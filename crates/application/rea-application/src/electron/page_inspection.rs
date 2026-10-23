//! Shared passive inspection of one local Electron file page.
//!
//! This workflow owns target authorization, CDP fact interpretation,
//! completeness, and output projection. The runtime adapter owns discovery,
//! socket/session lifecycle, and cancellation delivery to the transport.

use crate::electron::observation::{
    self, BrowserVersion, DiscoveredTarget, DomNode, DomSummary, ElectronFileAuthorizer, Frame,
    PageInspection, PageTarget, Resource, Script, Worker,
};
use rea_core::{
    cancellation::Cancellation,
    canonical_json,
    failure::{Detail, Failure},
};
use rea_host::cdp_transport::{CdpEvent, CdpEventBatch};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    time::{Duration, Instant},
};

pub const OPERATION: &str = observation::PAGE_OPERATION;

const DEFAULT_OBSERVATION_MS: u64 = 100;
const SOURCE_BYTE_LIMIT: usize = 32 * 1024 * 1024;
const SOURCE_DEADLINE: Duration = Duration::from_secs(20);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Parsed request values after strict validation and defaulting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InspectElectronPageInput {
    pub cdp_endpoint: String,
    pub target_id: String,
    pub observation_ms: u64,
    pub include_script_sources: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ElectronCdpFailureKind {
    Cancelled,
    Timeout,
    Protocol { code: Option<i64> },
    Transport,
}

/// Transport failure details retained until the operation maps them to REA's
/// tagged failure algebra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ElectronCdpFailure {
    pub kind: ElectronCdpFailureKind,
    pub message: String,
}

/// The workflow distinguishes browser-level inventory from page-scoped
/// commands so flattened target sessions cannot query the wrong target.
pub trait ElectronPageTransport {
    fn request_page(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, ElectronCdpFailure>;

    fn request_browser(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, ElectronCdpFailure>;

    fn drain_events(&mut self) -> CdpEventBatch;

    fn poll_events(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), ElectronCdpFailure>;
}

/// Validate an inspection request without changing caller-selected values.
pub fn validate_input(input: &Value) -> Result<InspectElectronPageInput, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("Electron page input must be an object."))?;
    reject_unknown_fields(
        object,
        &[
            "cdp_endpoint",
            "target_id",
            "observation_ms",
            "include_script_sources",
        ],
    )?;

    let endpoint = object
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid_input("cdp_endpoint must be a non-empty string."))?;
    let cdp_endpoint = observation::validate_endpoint(endpoint)?;

    let target_id = object
        .get("target_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_input("target_id must be a non-empty string."))?
        .to_owned();

    let observation_ms = match object.get("observation_ms") {
        None => DEFAULT_OBSERVATION_MS,
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| invalid_input("observation_ms must be a non-negative integer."))?,
        Some(_) => {
            return Err(invalid_input(
                "observation_ms must be a non-negative integer.",
            ));
        }
    };

    let include_script_sources = match object.get("include_script_sources") {
        None => false,
        Some(Value::Bool(value)) => *value,
        Some(_) => {
            return Err(invalid_input(
                "include_script_sources must be a boolean when supplied.",
            ));
        }
    };

    Ok(InspectElectronPageInput {
        cdp_endpoint,
        target_id,
        observation_ms,
        include_script_sources,
    })
}

/// Inspect one explicitly selected, authorized Electron file page.
pub fn inspect_with_cancellation(
    input: &Value,
    browser: BrowserVersion,
    discovered_target: &DiscoveredTarget,
    transport: &mut dyn ElectronPageTransport,
    started_at: &str,
    clock: &dyn Fn() -> String,
    cancellation: &Cancellation,
) -> Result<PageInspection, Failure> {
    let request = validate_input(input)?;
    ensure_active(cancellation)?;

    let mut file_authorizer = ElectronFileAuthorizer::default();
    let target = authorize_target(
        &request,
        discovered_target,
        &mut file_authorizer,
        cancellation,
    )?;
    let mut capture = CaptureState::default();

    request_page(
        transport,
        "Page.enable",
        json!({}),
        cancellation,
        &mut capture,
    )?;
    let initial_tree = request_page(
        transport,
        "Page.getFrameTree",
        json!({}),
        cancellation,
        &mut capture,
    )?;
    let main_frame_value = main_frame(&initial_tree)?;
    let main_file_path = authorize_frame_url(main_frame_value, &mut file_authorizer, cancellation)?
        .ok_or_else(target_not_allowed)?;
    capture.main_frame_id = string_field(main_frame_value, "id").map(str::to_owned);

    let frames = capture_frames(
        &initial_tree,
        &mut file_authorizer,
        cancellation,
        &mut capture.completeness,
    )?;
    if frames
        .first()
        .is_none_or(|frame| frame.file_path != main_file_path)
    {
        return Err(target_not_allowed());
    }

    request_page(
        transport,
        "Runtime.enable",
        json!({}),
        cancellation,
        &mut capture,
    )?;
    request_page(
        transport,
        "Debugger.enable",
        json!({}),
        cancellation,
        &mut capture,
    )?;

    capture_observation_window(
        transport,
        request.observation_ms,
        cancellation,
        &mut capture,
    )?;

    let resources = capture_resources(transport, &mut file_authorizer, cancellation, &mut capture)?;
    let dom = capture_dom(transport, &mut file_authorizer, cancellation, &mut capture)?;
    let scripts = capture_scripts(
        transport,
        &request,
        &frames,
        &mut file_authorizer,
        cancellation,
        &mut capture,
    )?;
    let workers = capture_workers(
        transport,
        &request,
        &frames,
        &mut file_authorizer,
        cancellation,
        &mut capture,
    )?;

    let final_tree = request_page(
        transport,
        "Page.getFrameTree",
        json!({}),
        cancellation,
        &mut capture,
    )?;
    let final_main_frame = main_frame(&final_tree)?;
    let final_path = authorize_frame_url(final_main_frame, &mut file_authorizer, cancellation)?;
    if capture.navigation_during_capture || final_path.as_deref() != Some(&main_file_path) {
        return Err(target_changed());
    }

    ensure_active(cancellation)?;
    let ended_at = clock();
    let mut limitations = vec![
        "Local file paths exposed by the selected CDP target are retained in the observation."
            .to_owned(),
        "REA does not evaluate renderer JavaScript, invoke Electron APIs, navigate, click, or close the page."
            .to_owned(),
        "Select include_script_sources to retain script contents.".to_owned(),
    ];
    if discovered_target.attached.is_none() {
        limitations.push(
            "CDP discovery omitted the target attachment state; attached is reported as unknown."
                .to_owned(),
        );
    }

    observation::project_page_inspection(
        browser,
        PageTarget {
            target_id: target.target_id,
            target_type: target.target_type,
            title: observation::sanitize_target_title(&target.title),
            file_path: main_file_path,
            attached: target.attached,
        },
        json!({
            "started_at": started_at,
            "ended_at": ended_at,
            "observation_ms": request.observation_ms,
        }),
        capture.completeness.value(),
        frames,
        dom,
        scripts,
        resources,
        workers,
        limitations,
    )
}

#[derive(Default)]
struct CaptureState {
    completeness: Completeness,
    scripts: Vec<ScriptDraft>,
    execution_context_frames: HashMap<String, String>,
    main_frame_id: Option<String>,
    navigation_during_capture: bool,
}

#[derive(Clone, Debug)]
struct ScriptDraft {
    script_id: String,
    raw_url: String,
    cdp_hash: Option<String>,
    length: Option<usize>,
    is_module: Option<bool>,
    language: Option<String>,
    frame_id: Option<String>,
}

#[derive(Default)]
struct Completeness {
    policy_filtered: BTreeSet<&'static str>,
    attach_limited: BTreeSet<&'static str>,
    truncated: BTreeSet<&'static str>,
    unavailable: BTreeSet<&'static str>,
    excluded: BTreeMap<(&'static str, &'static str), Option<u64>>,
    dropped_scripts: u64,
}

impl Completeness {
    fn exclude(&mut self, section: &'static str, reason: &'static str, count: Option<u64>) {
        if matches!(
            reason,
            "disallowed_origin"
                | "unsupported_url"
                | "unattributed_origin"
                | "not_approved"
                | "out_of_target_scope"
        ) {
            self.policy_filtered.insert(section);
        }
        if matches!(reason, "provider_unavailable" | "invalid_protocol_value") {
            self.unavailable.insert(section);
        }
        if reason == "resource_budget_exhausted" {
            self.truncated.insert(section);
        }

        let key = (section, reason);
        let existing = self.excluded.get(&key).copied();
        let combined = match (existing, count) {
            (Some(Some(left)), Some(right)) => Some(left.saturating_add(right)),
            (None, Some(right)) => Some(right),
            _ => None,
        };
        self.excluded.insert(key, combined);
    }

    fn unavailable(&mut self, section: &'static str) {
        self.attach_limited.insert(section);
        self.unavailable.insert(section);
        self.exclude(section, "provider_unavailable", None);
    }

    fn value(&self) -> Value {
        let policy_filtered_sections = strings(&self.policy_filtered);
        let attach_limited_sections = strings(&self.attach_limited);
        let truncated_sections = strings(&self.truncated);
        let unavailable_sections = strings(&self.unavailable);
        let policy_filtered = !policy_filtered_sections.is_empty();
        let attach_limited =
            !attach_limited_sections.is_empty() || !unavailable_sections.is_empty();
        let truncated = !truncated_sections.is_empty() || self.dropped_scripts > 0;

        let status = if truncated {
            "truncated"
        } else if policy_filtered {
            "policy_filtered"
        } else if attach_limited {
            "attach_limited"
        } else {
            "complete_within_window"
        };
        let mut conditions = Vec::new();
        if attach_limited {
            conditions.push("attach_limited");
        }
        if policy_filtered {
            conditions.push("policy_filtered");
        }
        if truncated {
            conditions.push("truncated");
        }
        if conditions.is_empty() {
            conditions.push("complete_within_window");
        }

        let excluded = self
            .excluded
            .iter()
            .map(|((section, reason), count)| {
                json!({"section":section,"reason":reason,"count":count})
            })
            .collect::<Vec<_>>();
        let dropped_total = self.dropped_scripts;

        json!({
            "status": status,
            "conditions": conditions,
            "policy_filtered_sections": policy_filtered_sections,
            "attach_limited_sections": attach_limited_sections,
            "truncated_sections": truncated_sections,
            "unavailable_sections": unavailable_sections,
            "excluded": excluded,
            "dropped_events": {
                "scripts": self.dropped_scripts,
                "network_requests": 0,
                "console_events": 0,
                "websocket_connections": 0,
                "websocket_frames": 0,
                "webmcp_tools": 0,
                "timeline_events": 0,
                "total": dropped_total,
            },
        })
    }
}

fn strings(values: &BTreeSet<&'static str>) -> Vec<&'static str> {
    values.iter().copied().collect()
}

fn authorize_target(
    request: &InspectElectronPageInput,
    discovered: &DiscoveredTarget,
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
) -> Result<PageTarget, Failure> {
    ensure_active(cancellation)?;
    if discovered.id != request.target_id {
        return Err(target_not_found());
    }
    if discovered.target_type != "page" {
        return Err(target_not_allowed());
    }
    if !discovered.has_validated_transport {
        return Err(transport_unavailable());
    }
    let Some(file_path) = authorizer
        .authorize(&discovered.url, cancellation)
        .map_err(|error| bind_operation(error, OPERATION))?
    else {
        return Err(target_not_allowed());
    };

    Ok(PageTarget {
        target_id: discovered.id.clone(),
        target_type: discovered.target_type.clone(),
        title: discovered.title.clone(),
        file_path,
        attached: discovered.attached,
    })
}

fn request_page(
    transport: &mut dyn ElectronPageTransport,
    method: &str,
    params: Value,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<Value, Failure> {
    let result = transport.request_page(method, params, cancellation);
    ingest_transport_events(capture, transport.drain_events());
    result.map_err(|error| map_cdp_failure(error, method))
}

fn request_browser(
    transport: &mut dyn ElectronPageTransport,
    method: &str,
    params: Value,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<Value, ElectronCdpFailure> {
    let result = transport.request_browser(method, params, cancellation);
    ingest_transport_events(capture, transport.drain_events());
    result
}

fn capture_observation_window(
    transport: &mut dyn ElectronPageTransport,
    observation_ms: u64,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<(), Failure> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(observation_ms))
        .ok_or_else(|| invalid_input("observation_ms exceeds the supported duration."))?;

    loop {
        ensure_active(cancellation)?;
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let wait = remaining.min(CANCELLATION_POLL_INTERVAL);
        transport
            .poll_events(wait, cancellation)
            .map_err(|error| map_cdp_failure(error, "Page observation window"))?;
        ingest_transport_events(capture, transport.drain_events());
    }
    ensure_active(cancellation)
}

fn capture_frames(
    tree: &Value,
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
    completeness: &mut Completeness,
) -> Result<Vec<Frame>, Failure> {
    let Some(root) = tree.get("frameTree").and_then(Value::as_object) else {
        return Err(protocol_failure("Page.getFrameTree omitted frameTree."));
    };
    let mut pending = vec![root];
    let mut frames = Vec::new();

    while let Some(frame_tree) = pending.pop() {
        ensure_active(cancellation)?;
        if let Some(children) = frame_tree.get("childFrames") {
            if let Some(children) = children.as_array() {
                for child in children.iter().rev() {
                    if let Some(child) = child.as_object() {
                        pending.push(child);
                    } else {
                        completeness.exclude("frames", "invalid_protocol_value", None);
                    }
                }
            } else {
                completeness.exclude("frames", "invalid_protocol_value", None);
            }
        }

        let Some(frame) = frame_tree.get("frame").and_then(Value::as_object) else {
            completeness.exclude("frames", "invalid_protocol_value", Some(1));
            continue;
        };
        let Some(frame_id) = string_field(frame, "id") else {
            completeness.exclude("frames", "invalid_protocol_value", Some(1));
            continue;
        };
        let Some(file_path) = authorize_frame_url(frame, authorizer, cancellation)? else {
            completeness.exclude("frames", "out_of_target_scope", Some(1));
            continue;
        };
        frames.push(Frame {
            frame_id: frame_id.to_owned(),
            parent_frame_id: string_field(frame, "parentId").map(str::to_owned),
            file_path,
        });
    }
    Ok(frames)
}

fn authorize_frame_url(
    frame: &Map<String, Value>,
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
) -> Result<Option<String>, Failure> {
    let url = string_field(frame, "url").unwrap_or_default();
    authorizer
        .authorize(url, cancellation)
        .map_err(|error| bind_operation(error, OPERATION))
}

fn capture_resources(
    transport: &mut dyn ElectronPageTransport,
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<Vec<Resource>, Failure> {
    let result = request_page(
        transport,
        "Page.getResourceTree",
        json!({}),
        cancellation,
        capture,
    )?;
    let Some(root) = result.get("frameTree").and_then(Value::as_object) else {
        return Err(protocol_failure("Page.getResourceTree omitted frameTree."));
    };

    let mut resources = Vec::new();
    let mut seen = HashSet::new();
    for frame_tree in walk_frame_trees(root, &mut capture.completeness, "resources") {
        ensure_active(cancellation)?;
        let Some(raw_resources) = frame_tree.get("resources") else {
            capture
                .completeness
                .exclude("resources", "invalid_protocol_value", None);
            continue;
        };
        let Some(raw_resources) = raw_resources.as_array() else {
            capture
                .completeness
                .exclude("resources", "invalid_protocol_value", None);
            continue;
        };
        for raw_resource in raw_resources {
            ensure_active(cancellation)?;
            let Some(resource) = raw_resource.as_object() else {
                capture
                    .completeness
                    .exclude("resources", "invalid_protocol_value", Some(1));
                continue;
            };
            let Some(file_path) = authorizer
                .authorize(
                    string_field(resource, "url").unwrap_or_default(),
                    cancellation,
                )
                .map_err(|error| bind_operation(error, OPERATION))?
            else {
                capture
                    .completeness
                    .exclude("resources", "out_of_target_scope", Some(1));
                continue;
            };
            let resource_type = string_field(resource, "type").unwrap_or("Other");
            let mime_type = string_field(resource, "mimeType").unwrap_or("");
            let content_size =
                parse_content_size(resource.get("contentSize"), &mut capture.completeness);
            let identity = json!({
                "file_path": file_path,
                "type": resource_type,
                "mime_type": mime_type,
                "content_size": content_size,
            });
            let resource_key = prefixed_digest("electron_resource", &identity)?;
            if !seen.insert(resource_key.clone()) {
                continue;
            }
            resources.push(Resource {
                resource_key,
                file_path,
                resource_type: resource_type.to_owned(),
                mime_type: mime_type.to_owned(),
                content_size,
            });
        }
    }
    resources.sort_by(|left, right| left.resource_key.cmp(&right.resource_key));
    Ok(resources)
}

fn capture_scripts(
    transport: &mut dyn ElectronPageTransport,
    request: &InspectElectronPageInput,
    frames: &[Frame],
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<Vec<Script>, Failure> {
    let frame_ids = frames
        .iter()
        .map(|frame| frame.frame_id.as_str())
        .collect::<HashSet<_>>();
    let mut seen = HashSet::new();
    let mut scripts = Vec::new();
    let mut retained_source_bytes = 0usize;
    let source_started_at = Instant::now();

    let script_drafts = capture.scripts.clone();
    for script in &script_drafts {
        ensure_active(cancellation)?;
        let Some(file_path) = authorizer
            .authorize(&script.raw_url, cancellation)
            .map_err(|error| bind_operation(error, OPERATION))?
        else {
            capture
                .completeness
                .exclude("scripts", "out_of_target_scope", Some(1));
            continue;
        };
        let frame_id = script
            .frame_id
            .as_deref()
            .filter(|frame_id| frame_ids.contains(frame_id))
            .map(str::to_owned);
        let identity = json!({
            "frame_id": frame_id,
            "file_path": file_path,
            "cdp_hash": script.cdp_hash,
            "length": script.length,
            "is_module": script.is_module,
            "language": script.language,
        });
        let script_key = prefixed_digest("electron_script", &identity)?;
        if !seen.insert(script_key.clone()) {
            continue;
        }

        let source = if !request.include_script_sources {
            json!({
                "included": false,
                "reason": "source capture was not selected",
            })
        } else if source_started_at.elapsed() >= SOURCE_DEADLINE {
            capture
                .completeness
                .exclude("script_sources", "resource_budget_exhausted", Some(1));
            source_omission_deadline()
        } else {
            match request_page(
                transport,
                "Debugger.getScriptSource",
                json!({"scriptId": script.script_id}),
                cancellation,
                capture,
            ) {
                Ok(value) => {
                    let Some(text) = value.get("scriptSource").and_then(Value::as_str) else {
                        return Err(protocol_failure(
                            "Debugger.getScriptSource omitted scriptSource text.",
                        ));
                    };
                    if source_started_at.elapsed() >= SOURCE_DEADLINE {
                        capture.completeness.exclude(
                            "script_sources",
                            "resource_budget_exhausted",
                            Some(1),
                        );
                        source_omission_deadline()
                    } else if text.len() > SOURCE_BYTE_LIMIT.saturating_sub(retained_source_bytes) {
                        capture.completeness.exclude(
                            "script_sources",
                            "resource_budget_exhausted",
                            Some(1),
                        );
                        source_omission_bytes()
                    } else {
                        retained_source_bytes += text.len();
                        source_artifact(text)
                    }
                }
                Err(error) if source_started_at.elapsed() >= SOURCE_DEADLINE => {
                    // Match the TypeScript budget: caller cancellation wins over
                    // deadline-based source omission, even when both are observed
                    // while handling the failed CDP request.
                    ensure_active(cancellation)?;
                    let _ = error;
                    capture.completeness.exclude(
                        "script_sources",
                        "resource_budget_exhausted",
                        Some(1),
                    );
                    source_omission_deadline()
                }
                Err(error) => return Err(error),
            }
        };

        scripts.push(Script {
            script_key,
            frame_id,
            file_path,
            cdp_hash: script.cdp_hash.clone(),
            length: script.length,
            is_module: script.is_module,
            language: script.language.clone(),
            source,
        });
    }

    if !request.include_script_sources {
        capture
            .completeness
            .exclude("script_sources", "not_approved", Some(scripts.len() as u64));
    }
    scripts.sort_by(|left, right| left.script_key.cmp(&right.script_key));
    Ok(scripts)
}

fn capture_workers(
    transport: &mut dyn ElectronPageTransport,
    request: &InspectElectronPageInput,
    frames: &[Frame],
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<Vec<Worker>, Failure> {
    let targets = match request_browser(
        transport,
        "Target.getTargets",
        json!({}),
        cancellation,
        capture,
    ) {
        Ok(targets) => targets,
        Err(error)
            if matches!(
                error.kind,
                ElectronCdpFailureKind::Protocol { code: Some(-32601) }
            ) =>
        {
            capture.completeness.unavailable("workers");
            return Ok(Vec::new());
        }
        Err(error) => return Err(map_cdp_failure(error, "Target.getTargets")),
    };

    let Some(target_infos) = targets.get("targetInfos").and_then(Value::as_array) else {
        capture
            .completeness
            .exclude("workers", "invalid_protocol_value", None);
        return Ok(Vec::new());
    };
    let frame_ids = frames
        .iter()
        .map(|frame| frame.frame_id.as_str())
        .collect::<HashSet<_>>();
    let mut workers = Vec::new();

    for entry in target_infos {
        ensure_active(cancellation)?;
        let Some(target) = entry.as_object() else {
            capture
                .completeness
                .exclude("workers", "invalid_protocol_value", Some(1));
            continue;
        };
        let worker_type = string_field(target, "type").unwrap_or_default();
        if !worker_type.contains("worker") {
            continue;
        }

        let opener_target_id = bounded_string(target.get("openerId"));
        let parent_frame_id = bounded_string(target.get("parentFrameId"));
        let belongs_to_page = opener_target_id.as_deref() == Some(request.target_id.as_str())
            || parent_frame_id
                .as_deref()
                .is_some_and(|frame_id| frame_ids.contains(frame_id));
        if !belongs_to_page {
            capture
                .completeness
                .exclude("workers", "out_of_target_scope", Some(1));
            continue;
        }

        let Some(file_path) = authorizer
            .authorize(
                string_field(target, "url").unwrap_or_default(),
                cancellation,
            )
            .map_err(|error| bind_operation(error, OPERATION))?
        else {
            capture
                .completeness
                .exclude("workers", "out_of_target_scope", Some(1));
            continue;
        };
        let Some(target_id) = bounded_string(target.get("targetId")) else {
            capture
                .completeness
                .exclude("workers", "invalid_protocol_value", Some(1));
            continue;
        };
        let Some(attached) = target.get("attached").and_then(Value::as_bool) else {
            capture
                .completeness
                .exclude("workers", "invalid_protocol_value", Some(1));
            continue;
        };
        workers.push(Worker {
            target_id,
            worker_type: worker_type.to_owned(),
            file_path,
            attached,
            opener_target_id,
            parent_frame_id,
        });
    }

    workers.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    Ok(workers)
}

fn walk_frame_trees<'a>(
    root: &'a Map<String, Value>,
    completeness: &mut Completeness,
    section: &'static str,
) -> Vec<&'a Map<String, Value>> {
    let mut pending = vec![root];
    let mut result = Vec::new();
    while let Some(frame_tree) = pending.pop() {
        if let Some(children) = frame_tree.get("childFrames") {
            if let Some(children) = children.as_array() {
                for child in children.iter().rev() {
                    if let Some(child) = child.as_object() {
                        pending.push(child);
                    } else {
                        completeness.exclude(section, "invalid_protocol_value", None);
                    }
                }
            } else {
                completeness.exclude(section, "invalid_protocol_value", None);
            }
        }
        result.push(frame_tree);
    }
    result
}

fn capture_dom(
    transport: &mut dyn ElectronPageTransport,
    authorizer: &mut ElectronFileAuthorizer,
    cancellation: &Cancellation,
    capture: &mut CaptureState,
) -> Result<DomSummary, Failure> {
    // DOMSnapshot can be large. The host transport applies the 64 MiB bound
    // before JSON parsing, while this projection retains only validated rows.
    let result = request_page(
        transport,
        "DOMSnapshot.captureSnapshot",
        json!({
            "computedStyles": [],
            "includePaintOrder": false,
            "includeDOMRects": false,
        }),
        cancellation,
        capture,
    )?;
    let completeness = &mut capture.completeness;
    let strings = string_table(result.get("strings"), completeness);
    let Some(documents) = result.get("documents").and_then(Value::as_array) else {
        completeness.exclude("dom", "invalid_protocol_value", None);
        return Ok(DomSummary {
            total_nodes: 0,
            nodes: Vec::new(),
        });
    };
    if documents.is_empty() {
        completeness.exclude("dom", "invalid_protocol_value", None);
        return Ok(DomSummary {
            total_nodes: 0,
            nodes: Vec::new(),
        });
    }

    let mut total_nodes = 0usize;
    let mut nodes = Vec::new();
    for document_value in documents {
        ensure_active(cancellation)?;
        let Some(document) = document_value.as_object() else {
            completeness.exclude("dom", "invalid_protocol_value", Some(1));
            continue;
        };
        let Some(document_url) = snapshot_string(&strings, document.get("documentURL")) else {
            completeness.exclude("dom", "invalid_protocol_value", Some(1));
            continue;
        };
        if authorizer
            .authorize(&document_url, cancellation)
            .map_err(|error| bind_operation(error, OPERATION))?
            .is_none()
        {
            completeness.exclude("dom", "out_of_target_scope", Some(1));
            continue;
        }

        let Some(snapshot_nodes) = parse_snapshot_nodes(document.get("nodes"), &strings) else {
            completeness.exclude("dom", "invalid_protocol_value", Some(1));
            continue;
        };
        if snapshot_nodes.excess_attributes > 0 {
            completeness.exclude(
                "dom",
                "invalid_protocol_value",
                Some(snapshot_nodes.excess_attributes as u64),
            );
        }
        let base_index = total_nodes;
        total_nodes = total_nodes.saturating_add(snapshot_nodes.node_types.len());
        for index in 0..snapshot_nodes.node_types.len() {
            let Some((node_type, node_name, node_value, parent_index, attributes)) =
                snapshot_nodes.node(index)
            else {
                completeness.exclude("dom", "invalid_protocol_value", Some(1));
                continue;
            };
            nodes.push(DomNode {
                index: base_index.saturating_add(index),
                parent_index: if parent_index < 0 {
                    -1
                } else {
                    (base_index as isize).saturating_add(parent_index)
                },
                node_type,
                node_name,
                node_value_length: node_value.len(),
                attribute_names: attributes,
            });
        }
    }

    Ok(DomSummary { total_nodes, nodes })
}

struct ParsedSnapshotNodes {
    node_types: Vec<Option<u32>>,
    node_names: Vec<Option<String>>,
    node_values: Vec<Option<String>>,
    parents: Vec<Option<isize>>,
    attributes: Vec<Option<Vec<String>>>,
    excess_attributes: usize,
}

impl ParsedSnapshotNodes {
    fn node(&self, index: usize) -> Option<(u32, String, String, isize, Vec<String>)> {
        Some((
            self.node_types.get(index).copied().flatten()?,
            self.node_names.get(index)?.clone()?,
            self.node_values.get(index)?.clone()?,
            self.parents.get(index).copied().flatten()?,
            self.attributes.get(index)?.clone()?,
        ))
    }
}

fn parse_snapshot_nodes(
    value: Option<&Value>,
    strings: &[Option<String>],
) -> Option<ParsedSnapshotNodes> {
    let nodes = value?.as_object()?;
    let node_types_raw = nodes.get("nodeType")?.as_array()?;
    let node_names_raw = nodes.get("nodeName")?.as_array()?;
    let node_values_raw = nodes.get("nodeValue")?.as_array()?;
    let parents_raw = nodes.get("parentIndex")?.as_array()?;
    let attributes_raw = nodes.get("attributes")?.as_array()?;
    let count = node_types_raw.len();
    if node_names_raw.len() != count || node_values_raw.len() != count || parents_raw.len() != count
    {
        return None;
    }

    let mut parents = parents_raw
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let parent = signed_integer(value)?;
            (parent >= -1 && parent < count as i64 && parent != index as i64)
                .then_some(parent as isize)
        })
        .collect::<Vec<_>>();
    invalidate_parent_cycles(&mut parents);

    let node_types = node_types_raw
        .iter()
        .map(|value| unsigned_integer(value).and_then(|value| u32::try_from(value).ok()))
        .collect();
    let node_names = node_names_raw
        .iter()
        .map(|value| snapshot_string(strings, Some(value)))
        .collect();
    let node_values = node_values_raw
        .iter()
        .map(|value| snapshot_value_string(strings, Some(value)))
        .collect();
    let attributes = attributes_raw
        .iter()
        .take(count)
        .map(|value| parse_snapshot_attributes(value, strings))
        .collect::<Vec<_>>();
    let mut attributes = attributes;
    attributes.resize_with(count, || None);

    Some(ParsedSnapshotNodes {
        node_types,
        node_names,
        node_values,
        parents,
        attributes,
        excess_attributes: attributes_raw.len().saturating_sub(count),
    })
}

fn parse_snapshot_attributes(value: &Value, strings: &[Option<String>]) -> Option<Vec<String>> {
    let values = value.as_array()?;
    if values.len() % 2 != 0 {
        return None;
    }
    let mut names = Vec::with_capacity(values.len() / 2);
    for pair in values.chunks_exact(2) {
        names.push(snapshot_string(strings, pair.first())?);
        snapshot_value_string(strings, pair.get(1))?;
    }
    Some(names)
}

fn invalidate_parent_cycles(parents: &mut [Option<isize>]) {
    let mut state = vec![0u8; parents.len()];
    for start in 0..parents.len() {
        if state[start] != 0 {
            continue;
        }
        let mut path = Vec::new();
        let mut cursor = start as isize;
        while cursor >= 0 && state[cursor as usize] == 0 {
            let index = cursor as usize;
            state[index] = 1;
            path.push(index);
            cursor = parents[index].unwrap_or(-1);
        }
        if cursor >= 0 && state[cursor as usize] == 1 {
            if let Some(cycle_start) = path.iter().position(|index| *index == cursor as usize) {
                for index in path.iter().skip(cycle_start) {
                    parents[*index] = None;
                }
            }
        }
        for index in path {
            state[index] = 2;
        }
    }
}

fn string_table(value: Option<&Value>, completeness: &mut Completeness) -> Vec<Option<String>> {
    let Some(values) = value.and_then(Value::as_array) else {
        completeness.exclude("dom", "invalid_protocol_value", None);
        return Vec::new();
    };
    values
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect()
}

fn snapshot_string(strings: &[Option<String>], index: Option<&Value>) -> Option<String> {
    let index = unsigned_integer(index?)?;
    strings.get(usize::try_from(index).ok()?)?.clone()
}

fn snapshot_value_string(strings: &[Option<String>], index: Option<&Value>) -> Option<String> {
    let index = signed_integer(index?)?;
    if index == -1 {
        return Some(String::new());
    }
    strings.get(usize::try_from(index).ok()?)?.clone()
}

fn parse_content_size(value: Option<&Value>, completeness: &mut Completeness) -> Option<f64> {
    match value {
        None => None,
        Some(value) => match value.as_f64() {
            Some(size) if size.is_finite() && size >= 0.0 => Some(size),
            _ => {
                completeness.exclude("resources", "invalid_protocol_value", Some(1));
                None
            }
        },
    }
}

fn ingest_transport_events(capture: &mut CaptureState, batch: CdpEventBatch) {
    if batch.dropped > 0 {
        capture.completeness.dropped_scripts = capture
            .completeness
            .dropped_scripts
            .saturating_add(batch.dropped);
        capture.completeness.truncated.insert("scripts");
    }
    for event in batch.items {
        ingest_event(capture, event);
    }
}

fn ingest_event(capture: &mut CaptureState, event: CdpEvent) {
    let Some(method) = event.value.get("method").and_then(Value::as_str) else {
        capture
            .completeness
            .exclude("scripts", "invalid_protocol_value", Some(1));
        return;
    };
    let params = event.value.get("params").and_then(Value::as_object);
    match method {
        "Runtime.executionContextsCleared" => capture.execution_context_frames.clear(),
        "Runtime.executionContextDestroyed" => {
            if let Some(key) =
                params.and_then(|params| safe_identifier(params.get("executionContextId")))
            {
                capture.execution_context_frames.remove(&key);
            }
        }
        "Runtime.executionContextCreated" => {
            let Some(context) = params
                .and_then(|params| params.get("context"))
                .and_then(Value::as_object)
            else {
                return;
            };
            let (Some(key), Some(frame_id)) = (
                safe_identifier(context.get("id")),
                context
                    .get("auxData")
                    .and_then(|aux| aux.get("frameId"))
                    .and_then(Value::as_str),
            ) else {
                return;
            };
            capture
                .execution_context_frames
                .insert(key, frame_id.to_owned());
        }
        "Debugger.scriptParsed" => {
            let Some(params) = params else {
                capture
                    .completeness
                    .exclude("scripts", "invalid_protocol_value", Some(1));
                return;
            };
            let Some(script_id) = params.get("scriptId").and_then(Value::as_str) else {
                capture
                    .completeness
                    .exclude("scripts", "invalid_protocol_value", Some(1));
                return;
            };
            let Some(raw_url) = params.get("url").and_then(Value::as_str) else {
                capture
                    .completeness
                    .exclude("scripts", "unattributed_origin", Some(1));
                return;
            };
            if raw_url.is_empty() {
                capture
                    .completeness
                    .exclude("scripts", "unattributed_origin", Some(1));
                return;
            }
            let context_key = safe_identifier(params.get("executionContextId"));
            capture.scripts.push(ScriptDraft {
                script_id: script_id.to_owned(),
                raw_url: raw_url.to_owned(),
                cdp_hash: params
                    .get("hash")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                length: params.get("length").and_then(safe_nonnegative_integer),
                is_module: params.get("isModule").and_then(Value::as_bool),
                language: params
                    .get("scriptLanguage")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                frame_id: context_key
                    .and_then(|key| capture.execution_context_frames.get(&key).cloned()),
            });
        }
        "Page.frameNavigated" => {
            let Some(frame_id) = params
                .and_then(|params| params.get("frame"))
                .and_then(|frame| frame.get("id"))
                .and_then(Value::as_str)
            else {
                return;
            };
            if capture.main_frame_id.as_deref() == Some(frame_id) {
                capture.navigation_during_capture = true;
            }
        }
        "Page.navigatedWithinDocument" => {
            if params
                .and_then(|params| params.get("frameId"))
                .and_then(Value::as_str)
                .is_some_and(|frame_id| capture.main_frame_id.as_deref() == Some(frame_id))
            {
                capture.navigation_during_capture = true;
            }
        }
        _ => {}
    }
}

fn safe_identifier(value: Option<&Value>) -> Option<String> {
    let value = safe_nonnegative_integer(value?)?;
    (value <= 9_007_199_254_740_991).then(|| value.to_string())
}

fn safe_nonnegative_integer(value: &Value) -> Option<usize> {
    let value = unsigned_integer(value)?;
    usize::try_from(value)
        .ok()
        .filter(|value| *value <= 9_007_199_254_740_991usize)
}

fn unsigned_integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value.as_f64().and_then(|number| {
            (number.is_finite() && number >= 0.0 && number.fract() == 0.0).then_some(number as u64)
        })
    })
}

fn signed_integer(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| {
        value.as_f64().and_then(|number| {
            (number.is_finite() && number.fract() == 0.0).then_some(number as i64)
        })
    })
}

fn main_frame(tree: &Value) -> Result<&Map<String, Value>, Failure> {
    tree.get("frameTree")
        .and_then(Value::as_object)
        .and_then(|tree| tree.get("frame"))
        .and_then(Value::as_object)
        .ok_or_else(|| protocol_failure("Page.getFrameTree omitted its main frame."))
}

fn string_field<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn bounded_string(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn source_artifact(text: &str) -> Value {
    let digest = Sha256::digest(text.as_bytes());
    let sha256 = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    json!({
        "included": true,
        "artifact": {
            "sha256": sha256,
            "bytes": text.len(),
            "media_type": "text/javascript",
            "charset": "utf-8",
            "text": text,
        },
    })
}

fn source_omission_deadline() -> Value {
    json!({
        "included": false,
        "reason": "script source was omitted because the 20-second source collection deadline elapsed",
    })
}

fn source_omission_bytes() -> Value {
    json!({
        "included": false,
        "reason": "script source was omitted because the aggregate 32 MiB source budget was exhausted",
    })
}

fn prefixed_digest(prefix: &str, value: &Value) -> Result<String, Failure> {
    canonical_json::digest(value)
        .map(|digest| format!("{prefix}_{digest}"))
        .map_err(|error| {
            invalid_output(&format!(
                "Unable to construct an Electron evidence key: {error}"
            ))
        })
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    if let Some(reason) = cancellation.reason() {
        return Err(cancelled_failure(reason));
    }
    Ok(())
}

fn map_cdp_failure(error: ElectronCdpFailure, method: &str) -> Failure {
    match error.kind {
        ElectronCdpFailureKind::Cancelled => cancelled_failure(&error.message),
        ElectronCdpFailureKind::Timeout => Failure::new(
            "timeout",
            "timeout",
            format!("Electron CDP command {method} exceeded its response deadline."),
            true,
            "Retry while the selected local Electron endpoint is responsive.".into(),
            operation_details(Some(("reason", error.message))),
        ),
        ElectronCdpFailureKind::Protocol { code } => Failure::new(
            "provider_error",
            "provider",
            format!("Electron CDP command {method} failed."),
            true,
            "Retry against a compatible Electron CDP endpoint.".into(),
            operation_details(Some(("reason", protocol_reason(code, &error.message)))),
        ),
        ElectronCdpFailureKind::Transport => Failure::new(
            "provider_unavailable",
            "provider_unavailable",
            format!("Unable to complete Electron CDP command {method}."),
            true,
            "Check that the selected local Electron endpoint remains available, then retry.".into(),
            operation_details(Some(("reason", error.message))),
        ),
    }
}

fn protocol_reason(code: Option<i64>, message: &str) -> String {
    match code {
        Some(code) => format!("CDP error {code}: {message}"),
        None => message.to_owned(),
    }
}

fn operation_details(reason: Option<(&str, String)>) -> BTreeMap<&'static str, Detail> {
    let mut details = BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]);
    if let Some(("reason", value)) = reason {
        details.insert("reason", Detail::Text(value));
    }
    details
}

fn bind_operation(mut failure: Failure, operation: &'static str) -> Failure {
    failure.detail("operation", Detail::Text(operation.into()));
    failure
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a local page target and a loopback Electron CDP endpoint.".into(),
        operation_details(None),
    )
}

fn invalid_output(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_output",
        reason.to_owned(),
        false,
        "Retry after confirming the selected Electron page and protocol response.".into(),
        operation_details(None),
    )
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.iter().any(|allowed| field == allowed))
    {
        return Err(invalid_input(&format!(
            "Electron page input does not accept {field}."
        )));
    }
    Ok(())
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "invalid_endpoint_response",
        "invalid_output",
        reason.to_owned(),
        false,
        "Retry against a compatible Electron CDP endpoint.".into(),
        operation_details(None),
    )
}

fn target_not_found() -> Failure {
    Failure::new(
        "target_not_found",
        "target_not_found",
        "The selected Electron target was not present in the latest endpoint discovery.".into(),
        false,
        "List Electron targets again and select an available target_id.".into(),
        operation_details(None),
    )
}

fn target_not_allowed() -> Failure {
    Failure::new(
        "target_not_allowed",
        "target_not_allowed",
        "The selected Electron target is not an authorized local file page.".into(),
        false,
        "Select a page target whose main document is a local file or regular ASAR member.".into(),
        operation_details(None),
    )
}

fn target_changed() -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        "The selected Electron page changed during inspection.".into(),
        false,
        "Retry after the selected page reaches a stable state.".into(),
        operation_details(None),
    )
}

fn transport_unavailable() -> Failure {
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        "The selected Electron target has no validated CDP transport.".into(),
        true,
        "List Electron targets again and retry while the selected endpoint is available.".into(),
        operation_details(None),
    )
}

fn cancelled_failure(reason: &str) -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        format!("Electron page inspection was cancelled: {reason}"),
        false,
        "Retry the passive page inspection if it is still needed.".into(),
        operation_details(None),
    )
}
