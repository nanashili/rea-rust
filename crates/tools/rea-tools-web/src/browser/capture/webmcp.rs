//! `src/browser/CdpWebMcpDiscovery.ts` (`discoverWebMcp`): passive WebMCP
//! inventory from `WebMCP.enable` and `toolsAdded`/`toolsRemoved` events.
//! `WebMCP.invokeTool` is never sent.
use super::completeness::Completeness;
use super::connection::{Connection, TargetFacts, foreign};
use super::values::{self, Event, Record};
use crate::cdp::urls::SanitizedUrl;
use crate::comparisons::digest::{
    compare_unicode_code_points, composite_key, digest_canonical_value,
};
use rea_core::analysis_error::AnalysisError;
use rea_mcp::Progress;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::time::Duration;

pub(super) const OPERATION: &str = "discover_webmcp_tools";
const PHASE: &str = "browser_observation";
const SECTION: &str = "webmcp_tools";

struct ScopeFrame {
    url: String,
    origin: Option<String>,
    parent_frame_id: Option<String>,
    loader_id: Option<String>,
}

struct State<'a> {
    origins: &'a BTreeSet<String>,
    /// Insertion-ordered frames (`Map` iteration order matters for removal).
    frames: Vec<(String, ScopeFrame)>,
    /// Tools keyed by `tool_key`, in insertion order.
    tools: Vec<(String, Value)>,
    completeness: Completeness,
    transient: BTreeSet<String>,
    resolved_transient: BTreeSet<String>,
}

impl State<'_> {
    fn frame(&self, id: &str) -> Option<&ScopeFrame> {
        self.frames
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, frame)| frame)
    }

    fn set_frame(&mut self, id: &str, frame: ScopeFrame) {
        match self.frames.iter_mut().find(|(key, _)| key == id) {
            Some((_, existing)) => *existing = frame,
            None => self.frames.push((id.to_owned(), frame)),
        }
    }

    fn delete_frame(&mut self, id: &str) {
        self.frames.retain(|(key, _)| key != id);
    }

    fn remove_frame_tools(&mut self, frame_id: &str) {
        self.tools
            .retain(|(_, tool)| tool["frame_id"].as_str() != Some(frame_id));
    }

    fn set_tool(&mut self, key: String, tool: Value) {
        match self.tools.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, existing)) => *existing = tool,
            None => self.tools.push((key, tool)),
        }
    }

    /// `removeFrame`: the frame, its descendants and their tools.
    fn remove_frame(&mut self, frame_id: &str) {
        let mut pending = vec![frame_id.to_owned()];
        let mut removed = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if removed.contains(&current) {
                continue;
            }
            for (candidate, frame) in &self.frames {
                if frame.parent_frame_id.as_deref() == Some(current.as_str()) {
                    pending.push(candidate.clone());
                }
            }
            self.delete_frame(&current);
            removed.insert(current);
        }
        self.tools.retain(|(_, tool)| {
            !tool["frame_id"]
                .as_str()
                .is_some_and(|frame| removed.contains(frame))
        });
    }
}

pub(super) fn discover(
    connection: &mut Connection<'_>,
    facts: &TargetFacts<'_>,
    observation_ms: u64,
    progress: &Progress,
) -> Result<Value, AnalysisError> {
    let origins = &facts.origins;
    let mut limitations = vec![
        "Page-declared tool metadata is untrusted and is never registered or invoked by REA.".to_owned(),
        "Discovery uses only WebMCP.enable and toolsAdded/toolsRemoved; WebMCP.invokeTool is never called.".to_owned(),
    ];
    let mut completeness = Completeness::default();
    connection.send("Page.enable", json!({}))?;
    let frame_tree = connection.send("Page.getFrameTree", json!({}))?;
    connection.discard()?;
    let initial_url =
        values::main_frame_url(&frame_tree).map_err(|()| foreign(OPERATION, "protocol_error"))?;
    if values::allowed_sanitized_url(initial_url.as_deref(), origins).is_none() {
        return Err(foreign(OPERATION, "target_not_allowed"));
    }
    let frames = values::capture_frames(&frame_tree, origins, None, Some(&mut completeness));
    let mut state = State {
        origins,
        frames: frames
            .into_iter()
            .map(|frame| {
                (
                    frame.frame_id,
                    ScopeFrame {
                        url: frame.url,
                        origin: Some(frame.origin),
                        parent_frame_id: frame.parent_frame_id,
                        loader_id: None,
                    },
                )
            })
            .collect(),
        tools: Vec::new(),
        completeness,
        transient: BTreeSet::new(),
        resolved_transient: BTreeSet::new(),
    };
    initial_frame_scope(&frame_tree, &mut state);
    let session_id = connection.session_id().map(str::to_owned);
    progress.report(PHASE, "Enabling passive WebMCP discovery");
    let outcome = (|| {
        let enabled = connection.send_optional("WebMCP.enable", json!({}), &mut limitations);
        let enabled = enabled?;
        deliver(&mut state, connection.drain()?, session_id.as_deref());
        let available = enabled.is_some();
        if available {
            // CDP sends the enable response before the required toolsAdded replay.
            connection.wait(Duration::from_millis(observation_ms), |_, events, _| {
                deliver(&mut state, events, session_id.as_deref());
                false
            })?;
        } else {
            state.completeness.unavailable(SECTION);
        }
        // `assertStableAuthorizedFrame`.
        let final_tree = connection.send("Page.getFrameTree", json!({}))?;
        deliver(&mut state, connection.drain()?, session_id.as_deref());
        let final_url = values::main_frame_url(&final_tree)
            .map_err(|()| foreign(OPERATION, "protocol_error"))?;
        if values::allowed_sanitized_url(final_url.as_deref(), origins).is_none() {
            return Err(foreign(OPERATION, "target_not_allowed"));
        }
        if final_url != initial_url {
            return Err(foreign(OPERATION, "target_changed"));
        }
        if !state.transient.is_empty() {
            state.completeness.attach_limited(SECTION);
        }
        Ok(available)
    })();
    progress.report(PHASE, "WebMCP discovery complete");
    let available = outcome?;
    let target_url = initial_url.unwrap_or_else(|| facts.target.url.clone());
    let sanitized = values::allowed_sanitized_url(Some(&target_url), origins);
    let total = state.tools.len() as u64 + state.completeness.dropped_total();
    let mut items: Vec<(String, Value)> = std::mem::take(&mut state.tools);
    items.sort_by(|left, right| compare_unicode_code_points(&left.0, &right.0));
    let (url, origin) = match sanitized {
        Some(sanitized) => (sanitized.url, sanitized.origin.unwrap_or_default()),
        None => ("[unsupported-url]".to_owned(), String::new()),
    };
    Ok(json!({
        "browser": facts.discovery.version,
        "target": { "target_id": facts.target.id, "url": url, "origin": origin },
        "status": if available { "available" } else { "unavailable" },
        "tools": { "total": total, "items": items.into_iter().map(|(_, tool)| tool).collect::<Vec<_>>() },
        "completeness": state.completeness.snapshot(),
        "limitations": limitations,
    }))
}

fn deliver(state: &mut State<'_>, events: Vec<Event>, session_id: Option<&str>) {
    for event in events {
        if event.session_id.as_deref() != session_id {
            continue;
        }
        if ingest_frame_scope_event(&event, state) {
            continue;
        }
        ingest_webmcp_event(&event, state);
    }
}

/// `initialFrameScope`: record each admitted frame's loader.
fn initial_frame_scope(frame_tree: &Value, state: &mut State<'_>) {
    let Some(root) = values::frame_tree_root(frame_tree) else {
        return;
    };
    let mut malformed = 0;
    let trees = values::walk_frame_trees(root, &mut |_| malformed += 1);
    for _ in 0..malformed {
        state
            .completeness
            .exclude(SECTION, "invalid_protocol_value");
    }
    for tree in trees {
        let frame = values::record(tree.get("frame"));
        let Some(frame_id) = values::string(frame.and_then(|frame| frame.get("id"))) else {
            continue;
        };
        let loader =
            values::string(frame.and_then(|frame| frame.get("loaderId"))).map(str::to_owned);
        if let Some((_, prior)) = state.frames.iter_mut().find(|(key, _)| key == frame_id) {
            prior.loader_id = loader;
        }
    }
}

fn ingest_frame_scope_event(event: &Event, state: &mut State<'_>) -> bool {
    let Some(params) = event.params.as_object() else {
        return false;
    };
    match event.method.as_str() {
        "Page.frameDetached" => {
            let Some(frame_id) = values::string(params.get("frameId")) else {
                state
                    .completeness
                    .exclude(SECTION, "invalid_protocol_value");
                return true;
            };
            state.remove_frame(frame_id);
            state.transient.remove(frame_id);
            state.resolved_transient.remove(frame_id);
            true
        }
        "Page.frameNavigated" => {
            handle_frame_update(values::record(params.get("frame")), state, true)
        }
        "Page.navigatedWithinDocument" => handle_frame_update(Some(params), state, false),
        _ => false,
    }
}

fn handle_frame_update(
    frame: Option<&Record>,
    state: &mut State<'_>,
    document_committed: bool,
) -> bool {
    let Some(frame) = frame else {
        state
            .completeness
            .exclude(SECTION, "invalid_protocol_value");
        return true;
    };
    let Some(frame_id) =
        values::string(frame.get("id")).or_else(|| values::string(frame.get("frameId")))
    else {
        state
            .completeness
            .exclude(SECTION, "invalid_protocol_value");
        return true;
    };
    let raw_url = values::string(frame.get("url"));
    if matches!(raw_url, Some("" | "about:blank" | "about:srcdoc")) {
        if document_committed {
            state.remove_frame_tools(frame_id);
            state.transient.insert(frame_id.to_owned());
            state.resolved_transient.remove(frame_id);
        }
        return true;
    }
    update_frame_scope(frame, frame_id, state, document_committed);
    true
}

fn update_frame_scope(
    frame: &Record,
    frame_id: &str,
    state: &mut State<'_>,
    document_committed: bool,
) {
    let url = values::allowed_sanitized_url(values::string(frame.get("url")), state.origins);
    let Some(SanitizedUrl {
        url,
        origin: Some(origin),
    }) = url
    else {
        state.remove_frame_tools(frame_id);
        state.delete_frame(frame_id);
        state.completeness.exclude(SECTION, "out_of_target_scope");
        return;
    };
    let loader_id = values::string(frame.get("loaderId")).map(str::to_owned);
    let new_document = document_committed
        && state.frame(frame_id).is_some_and(|previous| {
            previous.url != url
                || matches!((&loader_id, &previous.loader_id), (Some(loader), Some(prior)) if loader != prior)
        });
    if new_document {
        state.remove_frame_tools(frame_id);
    }
    if document_committed && state.transient.contains(frame_id) {
        state.resolved_transient.insert(frame_id.to_owned());
    }
    let parent = values::string(frame.get("parentId"))
        .map(str::to_owned)
        .or_else(|| {
            state
                .frame(frame_id)
                .and_then(|prior| prior.parent_frame_id.clone())
        })
        .filter(|parent| !parent.is_empty());
    state.set_frame(
        frame_id,
        ScopeFrame {
            url,
            origin: Some(origin),
            parent_frame_id: parent,
            loader_id,
        },
    );
}

fn event_tools<'a>(value: Option<&'a Value>, completeness: &mut Completeness) -> Vec<&'a Record> {
    let Some(items) = value.and_then(Value::as_array) else {
        completeness.exclude(SECTION, "invalid_protocol_value");
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let record = item.as_object();
            if record.is_none() {
                completeness.exclude(SECTION, "invalid_protocol_value");
            }
            record
        })
        .collect()
}

fn ingest_webmcp_event(event: &Event, state: &mut State<'_>) {
    let removed = match event.method.as_str() {
        "WebMCP.toolsAdded" => false,
        "WebMCP.toolsRemoved" => true,
        _ => return,
    };
    let Some(params) = event.params.as_object() else {
        state
            .completeness
            .exclude(SECTION, "invalid_protocol_value");
        return;
    };
    let declared = event_tools(params.get("tools"), &mut state.completeness);
    if removed {
        for tool in declared {
            let (Some(name), Some(frame_id)) = (
                values::string(tool.get("name")),
                values::string(tool.get("frameId")),
            ) else {
                state
                    .completeness
                    .exclude(SECTION, "invalid_protocol_value");
                continue;
            };
            state.tools.retain(|(_, item)| {
                !(item["name"].as_str() == Some(name)
                    && item["frame_id"].as_str() == Some(frame_id))
            });
        }
        return;
    }
    for tool in declared {
        if let Some(frame_id) = values::string(tool.get("frameId")) {
            if state.transient.contains(frame_id) {
                if !state.resolved_transient.contains(frame_id) {
                    continue;
                }
                state.transient.remove(frame_id);
                state.resolved_transient.remove(frame_id);
            }
        }
        if let Some((key, normalized)) = normalize_tool(tool, state) {
            state.set_tool(key, normalized);
        }
    }
}

/// `normalizeTool`.
fn normalize_tool(value: &Record, state: &mut State<'_>) -> Option<(String, Value)> {
    let frame_id = values::string(value.get("frameId"));
    let name = values::string(value.get("name"));
    let (Some(frame_id), Some(name)) = (frame_id, name) else {
        state
            .completeness
            .exclude(SECTION, "invalid_protocol_value");
        return None;
    };
    let Some((frame_url, owner_origin)) = state.frame(frame_id).and_then(|frame| {
        frame
            .origin
            .clone()
            .map(|origin| (frame.url.clone(), origin))
    }) else {
        state.completeness.exclude(SECTION, "out_of_target_scope");
        return None;
    };
    let completeness = &mut state.completeness;
    let description = values::string(value.get("description")).unwrap_or_default();
    let annotations = values::record(value.get("annotations"));
    let malformed_annotations = value.contains_key("annotations") && annotations.is_none();
    if malformed_annotations {
        completeness.exclude(SECTION, "invalid_protocol_value");
    }
    let mut annotation = |key: &str| -> Value {
        let Some(hint) = annotations.and_then(|annotations| annotations.get(key)) else {
            return Value::Null;
        };
        if let Value::Bool(flag) = hint {
            return Value::Bool(*flag);
        }
        completeness.exclude(SECTION, "invalid_protocol_value");
        Value::Null
    };
    let consequential = annotation("consequential");
    let unknown_consequential = malformed_annotations
        || annotations
            .and_then(|annotations| annotations.get("consequential"))
            .is_some_and(|hint| !hint.is_boolean());
    let read_only = annotation("readOnly");
    let untrusted_content = annotation("untrustedContent");
    let autosubmit = annotation("autosubmit");
    let schema = value.get("inputSchema").map(values::js_json);
    if schema.is_none() {
        completeness.exclude(SECTION, "invalid_protocol_value");
    }
    let mut annotation_values = Map::new();
    annotation_values.insert("read_only".into(), read_only);
    annotation_values.insert("untrusted_content".into(), untrusted_content);
    if !unknown_consequential {
        annotation_values.insert("consequential".into(), consequential);
    }
    annotation_values.insert("autosubmit".into(), autosubmit);
    let key = tool_key(&frame_url, frame_id, name);
    let tool = json!({
        "tool_key": key,
        "name": name,
        "description": description,
        "frame_id": frame_id,
        "frame_url": frame_url,
        "owner_origin": owner_origin,
        "declaration_kind": if values::number(value.get("backendNodeId")).is_none() { "imperative" } else { "declarative" },
        "input_schema_sha256": schema.as_ref().map(digest_canonical_value),
        "input_schema": schema,
        "annotations": annotation_values,
        "registration_source": registration_source(values::record(value.get("stackTrace")), state.origins),
        "trust": "page-declared-untrusted",
    });
    Some((key, tool))
}

/// `registrationSource`: the first call-frame record.
fn registration_source(stack: Option<&Record>, origins: &BTreeSet<String>) -> Value {
    let frame = stack
        .and_then(|stack| stack.get("callFrames"))
        .and_then(Value::as_array)
        .and_then(|frames| frames.iter().find_map(Value::as_object));
    let Some(frame) = frame else {
        return Value::Null;
    };
    match values::allowed_sanitized_url(values::string(frame.get("url")), origins) {
        Some(url) => json!({
            "url": url.url,
            "line": values::integer_or_null(frame.get("lineNumber")),
            "column": values::integer_or_null(frame.get("columnNumber")),
        }),
        None => Value::Null,
    }
}

/// `toolKey`: `webmcp_` + SHA-256 of the composite `[frameUrl, frameId, name]`.
fn tool_key(frame_url: &str, frame_id: &str, name: &str) -> String {
    let composite = composite_key(&[json!(frame_url), json!(frame_id), json!(name)]);
    let digest = Sha256::digest(composite.as_bytes());
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("webmcp_{hex}")
}
