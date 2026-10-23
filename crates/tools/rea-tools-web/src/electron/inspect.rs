//! `inspect_electron_page`: passive structural inspection of one local
//! Electron file page.
//!
//! Compatibility owners: `src/browser/CdpElectronProvider.ts`
//! (`inspectPage`, `authorizeTarget`, `providerError`),
//! `src/browser/CdpElectronInspection.ts`, `CdpElectronScripts.ts`,
//! `CdpElectronScriptEvents.ts`, `CdpElectronWorkers.ts`,
//! `CdpSnapshotNodes.ts`, `CdpSnapshotStrings.ts`,
//! `CdpScriptSourceBudget.ts`, `src/domain/webContentArtifact.ts`
//! (`createWebTextArtifact`),
//! `src/application/javascript/ElectronObservationService.ts`
//! (`inspectElectronPage`) and `ElectronEvidence.ts`. The socket/session
//! lifecycle is the shared `browser::capture::connection` owner; every local
//! path is authorized by `cdp::file_scope`.
use crate::browser::capture::completeness::Completeness;
use crate::browser::capture::connection::{self, Connection, foreign};
use crate::browser::capture::iso_now;
use crate::browser::capture::values::{self, Event, Record, js_number};
use crate::cdp::discovery::{self, Discovery, Target};
use crate::cdp::target_session::Deadline;
use crate::cdp::{self, Endpoint, Refinement, file_scope, observation_error};
use crate::comparisons::digest::{compare_unicode_code_points, digest_canonical_value};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;

pub(super) const OPERATION: &str = "inspect_electron_page";
const PHASE: &str = "browser_observation";
/// `closeCdpTargetSession(..., ["Debugger", "Runtime", "Page"])`.
const CLEANUP_DOMAINS: [&str; 3] = ["Debugger", "Runtime", "Page"];
/// `WEB_RUNTIME_LIMITS.sourceBytes`.
const SOURCE_BYTES: usize = 32 * 1024 * 1024;
/// `WEB_RUNTIME_LIMITS.commandTimeoutMs` (the source collection deadline).
const SOURCE_DEADLINE: Duration = Duration::from_millis(20_000);
const BYTES_OMISSION: &str =
    "script source was omitted because the aggregate 32 MiB source budget was exhausted";
const DEADLINE_OMISSION: &str =
    "script source was omitted because the 20-second source collection deadline elapsed";
const NOT_SELECTED: &str = "source capture was not selected";
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Parsed `inspectElectronPageInputSchema` (after advertised defaults).
struct Input {
    endpoint: Endpoint,
    target_id: String,
    observation_ms: u64,
    include_script_sources: bool,
}

/// `String.prototype.trim`.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|character: char| {
        (character.is_whitespace() && character != '\u{85}') || character == '\u{FEFF}'
    })
}

/// The SDK's rendering of the two-branch strict union. An endpoint
/// transform failure aborts both branches (`Invalid input`); a trimmed-empty
/// `target_id` is a continuable check, so the one non-aborted branch reports
/// it directly.
fn parse_input(input: &Value) -> Result<Input, ToolOutput> {
    let endpoint = cdp::parse_http_endpoint(
        input
            .get("cdp_endpoint")
            .and_then(Value::as_str)
            .unwrap_or(""),
    );
    let Ok(endpoint) = endpoint else {
        return Err(cdp::refinement_failure(
            OPERATION,
            vec![Refinement::new(Vec::new(), "Invalid input")],
        ));
    };
    let target_id = js_trim(
        input
            .get("target_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .to_owned();
    if target_id.is_empty() {
        return Err(cdp::refinement_failure(
            OPERATION,
            vec![Refinement::new(
                vec![json!("target_id")],
                "Too small: expected string to have >=1 characters",
            )],
        ));
    }
    Ok(Input {
        endpoint,
        target_id,
        observation_ms: input
            .get("observation_ms")
            .and_then(Value::as_u64)
            .unwrap_or(100),
        include_script_sources: input
            .get("include_script_sources")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

/// `inspectElectronPage` (service) over the provider's `inspectPage`.
pub(super) fn run(context: &ToolContext<'_>, raw: &Value) -> ToolOutput {
    let input = match parse_input(raw) {
        Ok(input) => input,
        Err(failure) => return failure,
    };
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(OPERATION));
    }
    let discovery = match discovery::open(&input.endpoint, OPERATION, cancellation) {
        Ok(discovery) => discovery,
        Err(error) => return ToolOutput::Failure(error),
    };
    let target = match authorize_target(&discovery, &input.target_id, cancellation) {
        Ok(target) => target,
        Err(error) => return ToolOutput::Failure(error),
    };
    let outcome = connection::with_authorized_session(
        OPERATION,
        &discovery,
        target,
        &CLEANUP_DOMAINS,
        cancellation,
        |connection| inspect(connection, &discovery, target, &input, context),
    );
    let mut result = match outcome {
        Ok(result) => result,
        Err(error) => return ToolOutput::Failure(error),
    };
    if cancellation.reason().is_some() {
        // The provider's final cancellation retains the completed facts; REA
        // closed only its own transport.
        if let Some(limitations) = result.get_mut("limitations").and_then(Value::as_array_mut) {
            limitations.push(Value::String(
                "REA closed its CDP transport; this does not imply target shutdown.".to_owned(),
            ));
        }
        let error = AnalysisError::cancelled(OPERATION);
        return ToolOutput::Failure(match evidence(&input, result) {
            Ok(evidence) => error.retain_partial_observation(evidence.into_value()),
            Err(_) => error,
        });
    }
    match evidence(&input, result) {
        // `completeProviderEvidence`: a late cancellation keeps the facts.
        Ok(evidence) if cancellation.reason().is_some() => ToolOutput::Failure(
            AnalysisError::cancelled(OPERATION).retain_partial_observation(evidence.into_value()),
        ),
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(_) => ToolOutput::Failure(AnalysisError::output(
            OPERATION,
            "Electron provider returned a malformed page inspection.",
        )),
    }
}

/// `createElectronEvidence` for a page inspection.
fn evidence(input: &Input, result: Value) -> Result<Evidence, rea_core::canonical_json::Error> {
    let browser = &result["browser"];
    let environment = json!({
        "id": format!(
            "{}@{}",
            browser["product"].as_str().unwrap_or_default(),
            browser["revision"].as_str().unwrap_or_default()
        ),
        "platform": "unknown",
        "architecture": "unknown",
        "isolation": "none",
    });
    let mut limitations: Vec<String> = result["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    limitations.push("Browser host platform and architecture were not observed.".to_owned());
    let parameters = json!({
        "cdp_endpoint": input.endpoint.url,
        "target_id": input.target_id,
        "observation_ms": input.observation_ms,
        "include_script_sources": input.include_script_sources,
    });
    let mut observation = Observation::new(OPERATION, parameters, result);
    observation.predicate_type = Some("rea.electron-page-inspection".to_owned());
    observation.confidence = Some("observed".to_owned());
    observation.authority = Some("external-service".to_owned());
    observation.environment = Some(environment);
    observation.limitations = limitations;
    Evidence::create(None, &super::provider(), observation)
}

fn active(cancellation: &Cancellation) -> Result<(), AnalysisError> {
    match cancellation.reason() {
        Some(_) => Err(AnalysisError::cancelled(OPERATION)),
        None => Ok(()),
    }
}

/// `authorizeTarget`: producer failures are `inspect_web_page` errors that
/// `providerError` re-creates under this operation without detail.
fn authorize_target<'a>(
    discovery: &'a Discovery,
    target_id: &str,
    cancellation: &Cancellation,
) -> Result<&'a Target, AnalysisError> {
    active(cancellation)?;
    let Some(target) = discovery
        .targets
        .iter()
        .find(|candidate| candidate.id == target_id)
    else {
        return Err(foreign(OPERATION, "target_not_found"));
    };
    if target.kind != "page" {
        return Err(foreign(OPERATION, "target_not_allowed"));
    }
    let path = file_scope::authorized_file(&target.url, cancellation, OPERATION)?;
    active(cancellation)?;
    if path.is_none() {
        return Err(foreign(OPERATION, "target_not_allowed"));
    }
    Ok(target)
}

/// `ElectronScriptDraft`.
#[derive(Clone)]
struct ScriptDraft {
    script_id: String,
    raw_url: String,
    hash: Value,
    length: Value,
    is_module: Value,
    language: Value,
    frame_id: Option<String>,
}

/// `ElectronInspectionState` plus the listener's session filter.
struct State {
    session_id: Option<String>,
    completeness: Completeness,
    scripts: Vec<ScriptDraft>,
    execution_context_frames: HashMap<String, String>,
    limitations: Vec<String>,
    main_frame_id: Option<String>,
    navigation_during_capture: bool,
}

/// `executionContextKey`: a safe-integer identifier as `String(number)`.
fn execution_context_key(value: Option<&Value>) -> Option<String> {
    let number = values::number(value)?;
    (number.fract() == 0.0 && number.abs() <= MAX_SAFE_INTEGER)
        .then(|| format!("{}", number as i64))
}

impl State {
    /// The `connection.onEvent` listener.
    fn ingest(&mut self, event: &Event) {
        if event.session_id != self.session_id {
            return;
        }
        self.ingest_script_event(event);
        if let Some(main) = &self.main_frame_id
            && navigated_frame_id(event) == Some(main.as_str())
        {
            self.navigation_during_capture = true;
        }
    }

    /// `ingestElectronScriptEvent`.
    fn ingest_script_event(&mut self, event: &Event) {
        let params = event.params.as_object();
        match event.method.as_str() {
            "Runtime.executionContextsCleared" => self.execution_context_frames.clear(),
            "Runtime.executionContextDestroyed" => {
                if let Some(key) = execution_context_key(
                    params.and_then(|params| params.get("executionContextId")),
                ) {
                    self.execution_context_frames.remove(&key);
                }
            }
            "Runtime.executionContextCreated" => {
                let context = values::record(params.and_then(|params| params.get("context")));
                let key = execution_context_key(context.and_then(|context| context.get("id")));
                let frame_id = values::string(
                    values::record(context.and_then(|context| context.get("auxData")))
                        .and_then(|aux| aux.get("frameId")),
                );
                if let (Some(key), Some(frame_id)) = (key, frame_id) {
                    self.execution_context_frames
                        .insert(key, frame_id.to_owned());
                }
            }
            "Debugger.scriptParsed" => {
                let field = |name: &str| params.and_then(|params| params.get(name));
                let Some(script_id) = values::string(field("scriptId")) else {
                    self.completeness
                        .exclude("scripts", "invalid_protocol_value");
                    return;
                };
                let raw_url = match values::string(field("url")) {
                    Some(url) if !url.is_empty() => url,
                    _ => {
                        self.completeness.exclude("scripts", "unattributed_origin");
                        return;
                    }
                };
                // `scriptMetadataValues`.
                let length = values::number(field("length"))
                    .filter(|length| {
                        length.fract() == 0.0 && *length >= 0.0 && *length <= MAX_SAFE_INTEGER
                    })
                    .map_or(Value::Null, js_number);
                let frame_id = execution_context_key(field("executionContextId"))
                    .and_then(|key| self.execution_context_frames.get(&key).cloned());
                self.scripts.push(ScriptDraft {
                    script_id: script_id.to_owned(),
                    raw_url: raw_url.to_owned(),
                    hash: values::string(field("hash")).map_or(Value::Null, |hash| json!(hash)),
                    length,
                    is_module: field("isModule")
                        .and_then(Value::as_bool)
                        .map_or(Value::Null, Value::Bool),
                    language: values::string(field("scriptLanguage"))
                        .map_or(Value::Null, |language| json!(language)),
                    frame_id,
                });
            }
            _ => {}
        }
    }

    /// Deliver the events that arrived with the previous command.
    fn pump(&mut self, connection: &mut Connection<'_>) -> Result<(), AnalysisError> {
        for event in connection.drain()? {
            self.ingest(&event);
        }
        Ok(())
    }

    /// `connection.send` with the listener attached.
    fn send(
        &mut self,
        connection: &mut Connection<'_>,
        method: &str,
        params: Value,
    ) -> Result<Value, AnalysisError> {
        let value = connection.send(method, params)?;
        self.pump(connection)?;
        Ok(value)
    }
}

/// `navigatedFrameId`.
fn navigated_frame_id(event: &Event) -> Option<&str> {
    let params = event.params.as_object()?;
    match event.method.as_str() {
        "Page.frameNavigated" => {
            values::string(values::record(params.get("frame")).and_then(|frame| frame.get("id")))
        }
        "Page.navigatedWithinDocument" => values::string(params.get("frameId")),
        _ => None,
    }
}

/// `inspectCdpElectronPage` + `runElectronInspection`.
fn inspect(
    connection: &mut Connection<'_>,
    discovery: &Discovery,
    target: &Target,
    input: &Input,
    context: &ToolContext<'_>,
) -> Result<Value, AnalysisError> {
    let mut limitations = vec![
        "Local file paths exposed by the selected CDP target are retained in the observation.".to_owned(),
        "REA does not evaluate renderer JavaScript, invoke Electron APIs, navigate, click, or close the page.".to_owned(),
        "Select include_script_sources to retain script contents.".to_owned(),
    ];
    if target.attached.is_none() {
        limitations.push(
            "CDP discovery omitted the target attachment state; attached is reported as unknown."
                .to_owned(),
        );
    }
    let mut state = State {
        session_id: connection.session_id().map(str::to_owned),
        completeness: Completeness::default(),
        scripts: Vec::new(),
        execution_context_frames: HashMap::new(),
        limitations,
        main_frame_id: None,
        navigation_during_capture: false,
    };
    let started_at = iso_now();
    let cancellation = connection.cancellation.clone();

    // `authorizeInitialFrames`.
    context
        .progress
        .report(PHASE, "Authorizing Electron file frames");
    state.send(connection, "Page.enable", json!({}))?;
    let tree = state.send(connection, "Page.getFrameTree", json!({}))?;
    let frames = capture_frames(&tree, &mut state.completeness, &cancellation)?;
    let Some(main) = frames.first() else {
        return Err(foreign(OPERATION, "target_not_allowed"));
    };
    let main_path = main["file_path"].as_str().unwrap_or_default().to_owned();
    state.main_frame_id = main["frame_id"].as_str().map(str::to_owned);

    // `enableElectronCapture`.
    state.send(connection, "Runtime.enable", json!({}))?;
    state.send(connection, "Debugger.enable", json!({}))?;
    connection.wait(
        Duration::from_millis(input.observation_ms),
        |_, events, _| {
            for event in &events {
                state.ingest(event);
            }
            false
        },
    )?;

    // `captureElectronContent`.
    context
        .progress
        .report(PHASE, "Capturing Electron structure");
    let frame_ids: BTreeSet<String> = frames
        .iter()
        .filter_map(|frame| frame["frame_id"].as_str().map(str::to_owned))
        .collect();
    let resources = capture_resources(connection, &mut state, &cancellation)?;
    let dom = capture_dom(connection, &mut state, &cancellation)?;
    let scripts = capture_scripts(
        connection,
        &mut state,
        &frame_ids,
        input.include_script_sources,
        &cancellation,
    )?;
    let workers = capture_workers(connection, &mut state, target, &frame_ids, &cancellation)?;

    // `assertStableMainFrame`.
    let after = state.send(connection, "Page.getFrameTree", json!({}))?;
    let after_url = values::string(
        values::record(values::frame_tree_root(&after).and_then(|tree| tree.get("frame")))
            .and_then(|frame| frame.get("url")),
    )
    .unwrap_or("");
    let Some(after_path) = file_scope::authorized_file(after_url, &cancellation, OPERATION)? else {
        return Err(foreign(OPERATION, "target_not_allowed"));
    };
    if state.navigation_during_capture || after_path != main_path {
        return Err(foreign(OPERATION, "target_changed"));
    }
    context
        .progress
        .report(PHASE, "Electron inspection complete");
    let mut result = Map::new();
    result.insert("browser".into(), discovery.version.clone());
    result.insert(
        "target".into(),
        json!({
            "target_id": target.id,
            "type": target.kind,
            "title": target.title,
            "file_path": main_path,
            "attached": target.attached,
        }),
    );
    result.insert(
        "capture_window".into(),
        json!({ "started_at": started_at, "ended_at": iso_now(), "observation_ms": input.observation_ms }),
    );
    result.insert("completeness".into(), state.completeness.snapshot());
    result.insert("frames".into(), Value::Array(frames));
    result.insert("dom".into(), dom);
    result.insert("scripts".into(), scripts);
    result.insert("resources".into(), Value::Array(resources));
    result.insert("workers".into(), Value::Array(workers));
    result.insert("limitations".into(), json!(state.limitations));
    Ok(Value::Object(result))
}

/// `captureFrames`.
fn capture_frames(
    result: &Value,
    completeness: &mut Completeness,
    cancellation: &Cancellation,
) -> Result<Vec<Value>, AnalysisError> {
    let Some(root) = values::frame_tree_root(result) else {
        return Err(foreign(OPERATION, "protocol_error"));
    };
    let mut malformed = 0_u64;
    let trees = values::walk_frame_trees(root, &mut |_| malformed += 1);
    for _ in 0..malformed {
        completeness.exclude("frames", "invalid_protocol_value");
    }
    let mut frames = Vec::new();
    for tree in trees {
        active(cancellation)?;
        let frame = values::record(tree.get("frame"));
        let (Some(frame), Some(frame_id)) = (
            frame,
            values::string(frame.and_then(|frame| frame.get("id"))),
        ) else {
            completeness.exclude("frames", "invalid_protocol_value");
            continue;
        };
        let url = values::string(frame.get("url")).unwrap_or("");
        let Some(path) = file_scope::authorized_file(url, cancellation, OPERATION)? else {
            completeness.exclude("frames", "out_of_target_scope");
            continue;
        };
        frames.push(json!({
            "frame_id": frame_id,
            "parent_frame_id": values::string(frame.get("parentId")),
            "file_path": path,
        }));
    }
    Ok(frames)
}

/// `captureResources` with `frameTreeResources`.
fn capture_resources(
    connection: &mut Connection<'_>,
    state: &mut State,
    cancellation: &Cancellation,
) -> Result<Vec<Value>, AnalysisError> {
    let result = state.send(connection, "Page.getResourceTree", json!({}))?;
    let Some(root) = values::frame_tree_root(&result) else {
        return Err(foreign(OPERATION, "protocol_error"));
    };
    let completeness = &mut state.completeness;
    let mut omitted: Vec<Option<u64>> = Vec::new();
    let trees = values::walk_frame_trees(root, &mut |count| omitted.push(count));
    let mut records: Vec<&Record> = Vec::new();
    for tree in trees {
        let Some(entries) = tree.get("resources").and_then(Value::as_array) else {
            omitted.push(None);
            continue;
        };
        for entry in entries {
            match entry.as_object() {
                Some(resource) => records.push(resource),
                None => omitted.push(Some(1)),
            }
        }
    }
    for count in omitted {
        completeness.exclude_count("resources", "invalid_protocol_value", count);
    }
    let mut seen = BTreeSet::new();
    let mut resources = Vec::new();
    for resource in records {
        active(cancellation)?;
        let url = values::string(resource.get("url")).unwrap_or("");
        let Some(path) = file_scope::authorized_file(url, cancellation, OPERATION)? else {
            completeness.exclude("resources", "out_of_target_scope");
            continue;
        };
        // `resourceContentSize`: omitted is unknown; a supplied invalid size
        // is malformed.
        let content_size = match resource.get("contentSize") {
            None => Value::Null,
            Some(value) => match values::number(Some(value)).filter(|size| *size >= 0.0) {
                Some(size) => js_number(size),
                None => {
                    completeness.exclude("resources", "invalid_protocol_value");
                    Value::Null
                }
            },
        };
        let item = json!({
            "file_path": path,
            "type": values::string(resource.get("type")).unwrap_or("Other"),
            "mime_type": values::string(resource.get("mimeType")).unwrap_or(""),
            "content_size": content_size,
        });
        let key = format!("electron_resource_{}", digest_canonical_value(&item));
        if !seen.insert(key.clone()) {
            continue;
        }
        resources.push(json!({
            "resource_key": key,
            "file_path": item["file_path"],
            "type": item["type"],
            "mime_type": item["mime_type"],
            "content_size": item["content_size"],
        }));
    }
    resources.sort_by(|left, right| {
        compare_unicode_code_points(
            left["resource_key"].as_str().unwrap_or_default(),
            right["resource_key"].as_str().unwrap_or_default(),
        )
    });
    Ok(resources)
}

/// A finite safe-integer JSON number (`Number.isSafeInteger`).
fn safe_integer(value: Option<&Value>) -> Option<i64> {
    values::number(value)
        .filter(|number| number.fract() == 0.0 && number.abs() <= MAX_SAFE_INTEGER)
        .map(|number| number as i64)
}

/// `cdpSnapshotString`.
fn snapshot_string(strings: &[Option<String>], index: Option<&Value>) -> Option<String> {
    let index = safe_integer(index).filter(|index| *index >= 0)?;
    strings.get(usize::try_from(index).ok()?).cloned().flatten()
}

/// `cdpSnapshotValueString`: `-1` is the protocol's empty string.
fn snapshot_value_string(strings: &[Option<String>], index: Option<&Value>) -> Option<String> {
    if values::number(index) == Some(-1.0) {
        return Some(String::new());
    }
    snapshot_string(strings, index)
}

/// `SnapshotDocumentNodes` (backend node IDs are not consumed here).
struct DocumentNodes {
    node_types: Vec<Option<i64>>,
    node_names: Vec<Option<String>>,
    node_values: Vec<Option<String>>,
    parents: Vec<Option<i64>>,
    attributes: Vec<Option<Vec<String>>>,
    excess_attributes: u64,
}

/// `attributes`: even-length name/value pairs; only names are retained.
fn snapshot_attributes(value: &Value, strings: &[Option<String>]) -> Option<Vec<String>> {
    let items = value.as_array()?;
    if items.len() % 2 != 0 {
        return None;
    }
    let mut names = Vec::new();
    for pair in items.chunks(2) {
        let name = snapshot_string(strings, pair.first())?;
        snapshot_value_string(strings, pair.get(1))?;
        names.push(name);
    }
    Some(names)
}

/// `invalidateParentCycles`.
fn invalidate_parent_cycles(parents: &mut [Option<i64>]) {
    let mut state = vec![0_u8; parents.len()];
    let mut path: Vec<usize> = Vec::new();
    for start in 0..parents.len() {
        if state[start] != 0 {
            continue;
        }
        path.clear();
        let mut cursor = start as i64;
        while cursor >= 0 && state[cursor as usize] == 0 {
            state[cursor as usize] = 1;
            path.push(cursor as usize);
            cursor = parents[cursor as usize].unwrap_or(-1);
        }
        if cursor >= 0
            && state[cursor as usize] == 1
            && let Some(position) = path.iter().position(|index| *index == cursor as usize)
        {
            for index in &path[position..] {
                parents[*index] = None;
            }
        }
        for index in &path {
            state[*index] = 2;
        }
    }
}

/// `snapshotDocumentNodes`.
fn snapshot_document_nodes(
    value: Option<&Value>,
    strings: &[Option<String>],
) -> Option<DocumentNodes> {
    let raw = values::record(value)?;
    let column = |name: &str| raw.get(name).and_then(Value::as_array);
    let (node_type, node_name, node_value, parent_index, attributes) = (
        column("nodeType")?,
        column("nodeName")?,
        column("nodeValue")?,
        column("parentIndex")?,
        column("attributes")?,
    );
    let count = node_type.len();
    if node_name.len() != count || node_value.len() != count || parent_index.len() != count {
        return None;
    }
    let mut parents: Vec<Option<i64>> = parent_index
        .iter()
        .enumerate()
        .map(|(index, value)| {
            safe_integer(Some(value))
                .filter(|parent| *parent >= -1 && *parent < count as i64 && *parent != index as i64)
        })
        .collect();
    invalidate_parent_cycles(&mut parents);
    Some(DocumentNodes {
        node_types: node_type
            .iter()
            .map(|value| safe_integer(Some(value)).filter(|kind| *kind >= 0))
            .collect(),
        node_names: node_name
            .iter()
            .map(|value| snapshot_string(strings, Some(value)))
            .collect(),
        node_values: node_value
            .iter()
            .map(|value| snapshot_value_string(strings, Some(value)))
            .collect(),
        parents,
        attributes: attributes
            .iter()
            .take(count)
            .map(|value| snapshot_attributes(value, strings))
            .collect(),
        excess_attributes: attributes.len().saturating_sub(count) as u64,
    })
}

/// `captureDom`.
fn capture_dom(
    connection: &mut Connection<'_>,
    state: &mut State,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let result = state.send(
        connection,
        "DOMSnapshot.captureSnapshot",
        json!({ "computedStyles": [], "includePaintOrder": false, "includeDOMRects": false }),
    )?;
    let completeness = &mut state.completeness;
    let Some(strings) = result.get("strings").and_then(Value::as_array) else {
        completeness.exclude_count("dom", "invalid_protocol_value", None);
        return Ok(json!({ "total_nodes": 0, "nodes": [] }));
    };
    let strings: Vec<Option<String>> = strings
        .iter()
        .map(|value| value.as_str().map(str::to_owned))
        .collect();
    // `snapshotDocuments`.
    let documents: Vec<&Record> = match result.get("documents").and_then(Value::as_array) {
        Some(items) if !items.is_empty() => items
            .iter()
            .filter_map(|item| {
                let document = item.as_object();
                if document.is_none() {
                    completeness.exclude("dom", "invalid_protocol_value");
                }
                document
            })
            .collect(),
        _ => {
            completeness.exclude_count("dom", "invalid_protocol_value", None);
            Vec::new()
        }
    };
    let mut nodes = Vec::new();
    let mut total: i64 = 0;
    for document in documents {
        active(cancellation)?;
        let Some(document_url) = snapshot_string(&strings, document.get("documentURL")) else {
            completeness.exclude("dom", "invalid_protocol_value");
            continue;
        };
        if file_scope::authorized_file(&document_url, cancellation, OPERATION)?.is_none() {
            completeness.exclude("dom", "out_of_target_scope");
            continue;
        }
        let Some(document_nodes) = snapshot_document_nodes(document.get("nodes"), &strings) else {
            completeness.exclude("dom", "invalid_protocol_value");
            continue;
        };
        if document_nodes.excess_attributes > 0 {
            completeness.exclude_count(
                "dom",
                "invalid_protocol_value",
                Some(document_nodes.excess_attributes),
            );
        }
        let base = total;
        total += document_nodes.node_types.len() as i64;
        for index in 0..document_nodes.node_types.len() {
            // `snapshotNodeAt`.
            let (
                Some(node_type),
                Some(node_name),
                Some(node_value),
                Some(parent),
                Some(Some(attributes)),
            ) = (
                document_nodes.node_types[index],
                document_nodes.node_names[index].as_ref(),
                document_nodes.node_values[index].as_ref(),
                document_nodes.parents[index],
                document_nodes.attributes.get(index),
            )
            else {
                completeness.exclude("dom", "invalid_protocol_value");
                continue;
            };
            nodes.push(json!({
                "index": base + index as i64,
                "parent_index": if parent < 0 { -1 } else { base + parent },
                "node_type": node_type,
                "node_name": node_name,
                "node_value_length": node_value.len(),
                "attribute_names": attributes,
            }));
        }
    }
    Ok(json!({ "total_nodes": total, "nodes": nodes }))
}

/// `CdpScriptSourceBudget`.
struct SourceBudget {
    deadline: Deadline,
    retained: usize,
}

impl SourceBudget {
    fn timed_out(&self) -> bool {
        self.deadline.expired()
    }

    fn admit(&mut self, text: &str) -> bool {
        if text.len() > SOURCE_BYTES - self.retained {
            return false;
        }
        self.retained += text.len();
        true
    }
}

/// `createWebTextArtifact(text, "text/javascript")`.
fn text_artifact(text: &str) -> Value {
    let digest = Sha256::digest(text.as_bytes());
    let sha256: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    json!({
        "sha256": sha256,
        "bytes": text.len(),
        "media_type": "text/javascript",
        "charset": "utf-8",
        "text": text,
    })
}

fn omitted(reason: &str) -> Value {
    json!({ "included": false, "reason": reason })
}

/// `captureScriptSource`.
fn capture_source(
    connection: &mut Connection<'_>,
    state: &mut State,
    script_id: &str,
    budget: &mut SourceBudget,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let response = connection
        .send_rejectable(
            "Debugger.getScriptSource",
            json!({ "scriptId": script_id }),
            Some(budget.deadline.cancellation()),
        )
        .map_err(connection::Rejection::into_error)?;
    state.pump(connection)?;
    active(cancellation)?;
    // `requiredScriptSource`.
    let Some(text) = values::string(response.get("scriptSource")) else {
        return Err(observation_error(
            OPERATION,
            "protocol_error",
            Some("Debugger.getScriptSource returned malformed source text: scriptSource must be a string.".to_owned()),
        ));
    };
    if budget.timed_out() {
        state
            .completeness
            .exclude("script_sources", "resource_budget_exhausted");
        return Ok(omitted(DEADLINE_OMISSION));
    }
    if !budget.admit(text) {
        state
            .completeness
            .exclude("script_sources", "resource_budget_exhausted");
        return Ok(omitted(BYTES_OMISSION));
    }
    Ok(json!({ "included": true, "artifact": text_artifact(text) }))
}

/// `captureElectronScripts`. Scripts parsed while sources are read join the
/// live draft list, as with the TS array iteration.
fn capture_scripts(
    connection: &mut Connection<'_>,
    state: &mut State,
    frame_ids: &BTreeSet<String>,
    include_sources: bool,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let mut budget = (include_sources && !state.scripts.is_empty()).then(|| SourceBudget {
        deadline: Deadline::new(Some(cancellation), SOURCE_DEADLINE),
        retained: 0,
    });
    let mut total: u64 = 0;
    let mut items: Vec<Value> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut index = 0;
    while index < state.scripts.len() {
        let script = state.scripts[index].clone();
        index += 1;
        active(cancellation)?;
        let Some(path) = file_scope::authorized_file(&script.raw_url, cancellation, OPERATION)?
        else {
            state.completeness.exclude("scripts", "out_of_target_scope");
            continue;
        };
        let frame_id = script
            .frame_id
            .as_ref()
            .filter(|frame| frame_ids.contains(*frame))
            .map_or(Value::Null, |frame| json!(frame));
        let identity = json!({
            "frame_id": frame_id,
            "file_path": path,
            "cdp_hash": script.hash,
            "length": script.length,
            "is_module": script.is_module,
            "language": script.language,
        });
        let key = format!("electron_script_{}", digest_canonical_value(&identity));
        if !seen.insert(key.clone()) {
            continue;
        }
        total += 1;
        let mut source = omitted(if include_sources {
            DEADLINE_OMISSION
        } else {
            NOT_SELECTED
        });
        if let Some(budget) = budget.as_mut().filter(|_| include_sources) {
            if budget.timed_out() {
                state
                    .completeness
                    .exclude("script_sources", "resource_budget_exhausted");
            } else {
                match capture_source(connection, state, &script.script_id, budget, cancellation) {
                    Ok(captured) => source = captured,
                    Err(error) => {
                        active(cancellation)?;
                        if !budget.timed_out() {
                            return Err(error);
                        }
                        state
                            .completeness
                            .exclude("script_sources", "resource_budget_exhausted");
                    }
                }
            }
        }
        items.push(json!({
            "script_key": key,
            "frame_id": identity["frame_id"],
            "file_path": identity["file_path"],
            "cdp_hash": identity["cdp_hash"],
            "length": identity["length"],
            "is_module": identity["is_module"],
            "language": identity["language"],
            "source": source,
        }));
    }
    drop(budget);
    if !include_sources {
        state
            .completeness
            .exclude_count("script_sources", "not_approved", Some(total));
    }
    items.sort_by(|left, right| {
        compare_unicode_code_points(
            left["script_key"].as_str().unwrap_or_default(),
            right["script_key"].as_str().unwrap_or_default(),
        )
    });
    Ok(json!({ "total": total, "items": items }))
}

/// `boundedTargetField`.
fn bounded_target_field(value: Option<&Value>) -> Option<String> {
    values::string(value)
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
}

/// `captureElectronWorkers`: inventory worker targets without attaching.
fn capture_workers(
    connection: &mut Connection<'_>,
    state: &mut State,
    target: &Target,
    frame_ids: &BTreeSet<String>,
    cancellation: &Cancellation,
) -> Result<Vec<Value>, AnalysisError> {
    let result =
        connection.send_browser_optional("Target.getTargets", json!({}), &mut state.limitations)?;
    state.pump(connection)?;
    let Some(result) = result else {
        state.completeness.unavailable("workers");
        return Ok(Vec::new());
    };
    let Some(infos) = result.get("targetInfos").and_then(Value::as_array) else {
        state
            .completeness
            .exclude_count("workers", "invalid_protocol_value", None);
        return Ok(Vec::new());
    };
    let mut workers = Vec::new();
    for entry in infos {
        active(cancellation)?;
        let Some(info) = entry.as_object() else {
            state
                .completeness
                .exclude("workers", "invalid_protocol_value");
            continue;
        };
        let kind = values::string(info.get("type")).unwrap_or("");
        if !kind.contains("worker") {
            continue;
        }
        let opener = bounded_target_field(info.get("openerId"));
        let parent_frame = bounded_target_field(info.get("parentFrameId"));
        if opener.as_deref() != Some(target.id.as_str())
            && parent_frame
                .as_ref()
                .is_none_or(|frame| !frame_ids.contains(frame))
        {
            state.completeness.exclude("workers", "out_of_target_scope");
            continue;
        }
        let url = values::string(info.get("url")).unwrap_or("");
        let Some(path) = file_scope::authorized_file(url, cancellation, OPERATION)? else {
            state.completeness.exclude("workers", "out_of_target_scope");
            continue;
        };
        let Some(target_id) = bounded_target_field(info.get("targetId")) else {
            state
                .completeness
                .exclude("workers", "invalid_protocol_value");
            continue;
        };
        let Some(attached) = info.get("attached").and_then(Value::as_bool) else {
            state
                .completeness
                .exclude("workers", "invalid_protocol_value");
            continue;
        };
        workers.push(json!({
            "target_id": target_id,
            "type": kind,
            "file_path": path,
            "attached": attached,
            "opener_target_id": opener,
            "parent_frame_id": parent_frame,
        }));
    }
    workers.sort_by(|left, right| {
        compare_unicode_code_points(
            left["target_id"].as_str().unwrap_or_default(),
            right["target_id"].as_str().unwrap_or_default(),
        )
    });
    Ok(workers)
}
