//! Contract boundary for passive web event-listener inspection.

use crate::browser;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::{CdpEventBatch, CdpTransportError, CdpWebSocketTransport};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_RUNTIME_EVENT_BYTES: usize = 8 * 1024 * 1024;
const MAX_RUNTIME_SOURCE_BYTES: usize = 32 * 1024 * 1024;
static NEXT_OBJECT_GROUP: AtomicU64 = AtomicU64::new(1);

pub const OPERATION: &str = "inspect_web_event_listeners";

/// Validate caller-supplied listener facts without opening a browser.
///
/// A complete authenticated Evidence record is returned byte-for-byte. A
/// plain captured report is returned after validating its public shape. The
/// operation never interprets a report as a live target or dispatches an
/// event, so callback execution remains explicitly unknown.
pub fn inspect_captured(input: &Value) -> Result<Value, Failure> {
    let capture = captured_value(input)?;
    if is_evidence_record(capture) {
        validate_evidence(capture)?;
        return Ok(input.clone());
    }

    validate_report(capture)?;
    Ok(input.clone())
}

/// CDP commands required by passive listener inspection.
pub trait CdpEventListenerTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpEventBatch::default()
    }

    fn close_connection(&mut self) -> Result<(), String> {
        Ok(())
    }
}

/// A connected, caller-selected page target for passive listener inspection.
pub struct ConnectedCdpEventListenerPort<T> {
    transport: T,
    target_id: String,
}

impl ConnectedCdpEventListenerPort<CdpWebSocketTransport> {
    pub fn connect(websocket_endpoint: &str, target_id: &str) -> Result<Self, CdpTransportError> {
        let transport = CdpWebSocketTransport::connect_for_target(websocket_endpoint, target_id)?;
        Ok(Self::from_transport(transport, target_id))
    }
}

impl<T> ConnectedCdpEventListenerPort<T> {
    pub fn from_transport(transport: T, target_id: &str) -> Self {
        Self {
            transport,
            target_id: target_id.to_owned(),
        }
    }

    pub fn inspect(
        &mut self,
        input: &Value,
        started_at: &str,
        ended_at: &str,
    ) -> Result<Value, Failure>
    where
        T: CdpEventListenerTransport,
    {
        self.inspect_with_cancellation(input, started_at, ended_at, &Cancellation::default())
    }

    pub fn inspect_with_cancellation(
        &mut self,
        input: &Value,
        started_at: &str,
        ended_at: &str,
        cancellation: &Cancellation,
    ) -> Result<Value, Failure>
    where
        T: CdpEventListenerTransport,
    {
        validate_input(input)?;
        let requested_target = input["target_id"].as_str().expect("validated target_id");
        if requested_target != self.target_id {
            return Err(target_mismatch());
        }

        let mut resources = InspectionResources::new();
        let mut source_inventory = RuntimeSourceInventory::default();
        let observation = inspect_connected_page(
            input,
            &mut self.transport,
            started_at,
            ended_at,
            cancellation,
            &mut resources,
            &mut source_inventory,
        );
        let cleanup = clean_up_inspection(&mut self.transport, &resources, &mut source_inventory);

        finish_inspection(observation, cleanup, cancellation)
    }
}

impl CdpEventListenerTransport for CdpWebSocketTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        CdpWebSocketTransport::request(self, method, params).map_err(|error| error.to_string())
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpWebSocketTransport::drain_events(self)
    }

    fn close_connection(&mut self) -> Result<(), String> {
        CdpWebSocketTransport::close_connection(self).map_err(|error| error.to_string())
    }
}

fn inspect_connected_page(
    input: &Value,
    transport: &mut dyn CdpEventListenerTransport,
    _started_at: &str,
    ended_at: &str,
    cancellation: &Cancellation,
    resources: &mut InspectionResources,
    sources: &mut RuntimeSourceInventory,
) -> Result<Value, Failure> {
    let origins = allowed_origins(input);
    enable_runtime_domains(transport, resources, sources, cancellation)?;

    let initial_target = current_main_frame(transport, &origins, cancellation, sources)?;
    let selected_node = inspect_selector_match(input, transport, cancellation, resources, sources)?;
    let browser = browser_version(transport, sources);
    let mut retained_sources = sources.read_for_listeners(
        transport,
        &selected_node.listeners,
        &initial_target.frame_id,
        cancellation,
    )?;
    let final_target = current_main_frame(transport, &origins, cancellation, sources)?;

    ensure_page_stayed_stable(&initial_target, &final_target)?;
    sources.revalidate_source_records(&mut retained_sources, &initial_target.frame_id);

    Ok(listener_report(
        input,
        &initial_target,
        selected_node,
        retained_sources,
        browser,
        sources,
        ended_at,
    ))
}

fn allowed_origins(input: &Value) -> Vec<&str> {
    input
        .get("allowed_origins")
        .and_then(Value::as_array)
        .map(|origins| origins.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default()
}

fn enable_runtime_domains(
    transport: &mut dyn CdpEventListenerTransport,
    resources: &mut InspectionResources,
    sources: &mut RuntimeSourceInventory,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    for domain in ["Page", "Runtime", "Debugger", "DOM"] {
        resources.enabled_domains.push(domain);
        request_cancellable(
            transport,
            &format!("{domain}.enable"),
            serde_json::json!({}),
            cancellation,
            sources,
        )?;
    }

    Ok(())
}

fn current_main_frame(
    transport: &mut dyn CdpEventListenerTransport,
    allowed_origins: &[&str],
    cancellation: &Cancellation,
    sources: &mut RuntimeSourceInventory,
) -> Result<MainFrame, Failure> {
    let frame_tree = request_cancellable(
        transport,
        "Page.getFrameTree",
        serde_json::json!({}),
        cancellation,
        sources,
    )?;

    main_frame(&frame_tree, allowed_origins)
}

fn inspect_selector_match(
    input: &Value,
    transport: &mut dyn CdpEventListenerTransport,
    cancellation: &Cancellation,
    resources: &InspectionResources,
    sources: &mut RuntimeSourceInventory,
) -> Result<SelectedNodeInspection, Failure> {
    let document = request_cancellable(
        transport,
        "DOM.getDocument",
        serde_json::json!({"depth": 0, "pierce": false}),
        cancellation,
        sources,
    )?;
    let root_node_id = required_u64(&document, "/root/nodeId", "DOM.getDocument root")?;
    let selector = input["selector"].as_str().expect("validated selector");
    let selected = request_cancellable(
        transport,
        "DOM.querySelector",
        serde_json::json!({"nodeId": root_node_id, "selector": selector}),
        cancellation,
        sources,
    )?;
    let node_id = required_u64(&selected, "/nodeId", "DOM.querySelector node")?;

    if node_id == 0 {
        return Ok(SelectedNodeInspection::not_found());
    }

    inspect_selected_node(
        transport,
        node_id,
        &resources.object_group,
        cancellation,
        sources,
    )
}

fn ensure_page_stayed_stable(
    initial_target: &MainFrame,
    final_target: &MainFrame,
) -> Result<(), Failure> {
    let frame_changed = initial_target.frame_id != final_target.frame_id;
    let loader_changed = initial_target.loader_id != final_target.loader_id;
    let url_changed_without_loader = initial_target.loader_id.is_none()
        && final_target.loader_id.is_none()
        && initial_target.url != final_target.url;

    if frame_changed || loader_changed || url_changed_without_loader {
        return Err(target_changed());
    }

    Ok(())
}

fn listener_report(
    input: &Value,
    target: &MainFrame,
    selected_node: SelectedNodeInspection,
    retained_sources: Vec<Value>,
    browser: Value,
    source_inventory: &mut RuntimeSourceInventory,
    ended_at: &str,
) -> Value {
    let selector = input["selector"].as_str().expect("validated selector");
    let listeners = selected_node
        .listeners
        .iter()
        .map(|listener| listener.to_value(source_inventory, &target.frame_id))
        .collect::<Vec<_>>();
    serde_json::json!({
        "browser": browser,
        "target": {
            "target_id": input["target_id"],
            "initial_url": target.url,
            "origin": target.origin,
            "frame_id": target.frame_id,
            "loader_id": target.loader_id,
        },
        "inspected_at": ended_at,
        "selected_node": {
            "selector": selector,
            "match": selected_node.match_state,
            "backend_node_id": selected_node.backend_node_id,
        },
        "listeners": listeners,
        "sources": retained_sources,
        "cleanup": "unknown",
        "limitations": [
            "Inspects listeners registered directly on the first native CSS match in the selected main document. Delegated ancestor listeners, descendants, closed shadow roots and framework registries are not enumerated.",
            "Native CDP listener descriptors report callback locations; registration time, dispatch history and UI causality remain unknown. REA does not dispatch an event, evaluate JavaScript or invoke a handler.",
            "Source identity uses this session's script ID and proven main-frame default-world metadata. Isolated or unknown worlds cannot establish website callback/source joins. A URL or sourceURL declaration never establishes identity or execution.",
            "Source text is retained inline with its independently computed UTF-8 digest; the producer hash is preserved separately. Missing source ownership or collected scripts remain explicit.",
            "REA releases its remote object group, disables enabled domains and closes its transport; the externally owned page remains open.",
        ],
    })
}

fn inspect_selected_node(
    transport: &mut dyn CdpEventListenerTransport,
    node_id: u64,
    object_group: &str,
    cancellation: &Cancellation,
    sources: &mut RuntimeSourceInventory,
) -> Result<SelectedNodeInspection, Failure> {
    let described = request_cancellable(
        transport,
        "DOM.describeNode",
        serde_json::json!({"nodeId": node_id}),
        cancellation,
        sources,
    )?;
    let backend_node_id = required_u64(
        &described,
        "/node/backendNodeId",
        "DOM.describeNode backend node",
    )?;
    let resolved = request_cancellable(
        transport,
        "DOM.resolveNode",
        serde_json::json!({"nodeId": node_id, "objectGroup": object_group}),
        cancellation,
        sources,
    )?;
    let object_id = resolved
        .pointer("/object/objectId")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| protocol_failure("DOM.resolveNode omitted objectId"))?;
    let listeners_result = request_cancellable(
        transport,
        "DOMDebugger.getEventListeners",
        serde_json::json!({"objectId": object_id, "depth": 0, "pierce": false}),
        cancellation,
        sources,
    );
    let listeners = match listeners_result {
        Ok(result) => parse_listeners(&result)?,
        Err(failure) => return Err(failure),
    };

    Ok(SelectedNodeInspection {
        match_state: "found",
        backend_node_id: Some(backend_node_id),
        listeners,
    })
}

fn parse_listeners(value: &Value) -> Result<Vec<ListenerDescriptor>, Failure> {
    let items = value
        .get("listeners")
        .and_then(Value::as_array)
        .ok_or_else(|| protocol_failure("DOMDebugger.getEventListeners omitted listeners"))?;
    let mut listeners = Vec::with_capacity(items.len());

    for (index, item) in items.iter().enumerate() {
        let field = |name: &str| format!("DOM listener {index} omitted {name}");
        listeners.push(ListenerDescriptor {
            listener_type: item
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| protocol_failure(&field("type")))?
                .to_owned(),
            use_capture: required_bool(item, "useCapture", index)?,
            passive: required_bool(item, "passive", index)?,
            once: required_bool(item, "once", index)?,
            script_id: item
                .get("scriptId")
                .and_then(Value::as_str)
                .ok_or_else(|| protocol_failure(&field("scriptId")))?
                .to_owned(),
            line_number: required_u64(item, "/lineNumber", "DOM listener line number")?,
            column_number: required_u64(item, "/columnNumber", "DOM listener column number")?,
        });
    }

    Ok(listeners)
}

fn required_bool(value: &Value, name: &str, index: usize) -> Result<bool, Failure> {
    value
        .get(name)
        .and_then(Value::as_bool)
        .ok_or_else(|| protocol_failure(&format!("DOM listener {index} omitted {name}")))
}

fn browser_version(
    transport: &mut dyn CdpEventListenerTransport,
    sources: &mut RuntimeSourceInventory,
) -> Value {
    request_and_collect(transport, "Browser.getVersion", serde_json::json!({}), sources)
        .ok()
        .map(|value| {
            serde_json::json!({
                "product": value.get("product").and_then(Value::as_str).unwrap_or("unknown"),
                "protocol_version": value.get("protocolVersion").and_then(Value::as_str).unwrap_or("unknown"),
                "revision": value.get("revision").and_then(Value::as_str).unwrap_or("unknown"),
                "user_agent": value.get("userAgent").and_then(Value::as_str).unwrap_or("unknown"),
                "js_version": value.get("jsVersion").and_then(Value::as_str).unwrap_or("unknown"),
            })
        })
        .unwrap_or_else(browser_version_unknown)
}

struct MainFrame {
    url: String,
    origin: String,
    frame_id: String,
    loader_id: Option<String>,
}

struct SelectedNodeInspection {
    match_state: &'static str,
    backend_node_id: Option<u64>,
    listeners: Vec<ListenerDescriptor>,
}

impl SelectedNodeInspection {
    fn not_found() -> Self {
        Self {
            match_state: "not_found",
            backend_node_id: None,
            listeners: Vec::new(),
        }
    }
}

#[derive(Debug, Clone)]
struct ListenerDescriptor {
    listener_type: String,
    use_capture: bool,
    passive: bool,
    once: bool,
    script_id: String,
    line_number: u64,
    column_number: u64,
}

impl ListenerDescriptor {
    fn to_value(&self, sources: &RuntimeSourceInventory, frame_id: &str) -> Value {
        let location = sources.location(self, frame_id);
        serde_json::json!({
            "type": self.listener_type,
            "use_capture": self.use_capture,
            "passive": self.passive,
            "once": self.once,
            "location": location,
            "execution": "unknown",
        })
    }
}

struct InspectionResources {
    object_group: String,
    enabled_domains: Vec<&'static str>,
}

impl InspectionResources {
    fn new() -> Self {
        let sequence = NEXT_OBJECT_GROUP.fetch_add(1, Ordering::Relaxed);
        Self {
            object_group: format!("rea-listeners-{}-{sequence}", std::process::id()),
            enabled_domains: Vec::new(),
        }
    }
}

struct CleanupOutcome {
    failures: Vec<String>,
}

impl CleanupOutcome {
    fn confirmed(&self) -> bool {
        self.failures.is_empty()
    }
}

fn clean_up_inspection(
    transport: &mut dyn CdpEventListenerTransport,
    resources: &InspectionResources,
    sources: &mut RuntimeSourceInventory,
) -> CleanupOutcome {
    let mut failures = Vec::new();

    cleanup_command(
        transport,
        sources,
        "Runtime.releaseObjectGroup",
        serde_json::json!({"objectGroup": resources.object_group}),
        &mut failures,
    );

    for domain in resources.enabled_domains.iter().rev() {
        cleanup_command(
            transport,
            sources,
            &format!("{domain}.disable"),
            serde_json::json!({}),
            &mut failures,
        );
    }

    if let Err(reason) = transport.close_connection() {
        failures.push(format!("CDP WebSocket close: {reason}"));
    }

    CleanupOutcome { failures }
}

fn cleanup_command(
    transport: &mut dyn CdpEventListenerTransport,
    sources: &mut RuntimeSourceInventory,
    method: &str,
    params: Value,
    failures: &mut Vec<String>,
) {
    if let Err(reason) = request_and_collect(transport, method, params, sources) {
        failures.push(format!("{method}: {reason}"));
    }
}

fn finish_inspection(
    observation: Result<Value, Failure>,
    cleanup: CleanupOutcome,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    match observation {
        Err(mut failure) => {
            attach_cleanup_failure(&mut failure, &cleanup);
            Err(failure)
        }
        Ok(mut report) => {
            if let Some(reason) = cancellation.reason() {
                report["cleanup"] = serde_json::json!(if cleanup.confirmed() {
                    "confirmed"
                } else {
                    "unknown"
                });
                let mut failure = cancelled_failure(reason);
                attach_cleanup_failure(&mut failure, &cleanup);
                retain_report(&mut failure, &report)?;
                return Err(failure);
            }

            if !cleanup.confirmed() {
                report["cleanup"] = serde_json::json!("unknown");
                let mut failure = protocol_failure("listener inspection cleanup is incomplete");
                attach_cleanup_failure(&mut failure, &cleanup);
                retain_report(&mut failure, &report)?;
                return Err(failure);
            }

            report["cleanup"] = serde_json::json!("confirmed");
            Ok(report)
        }
    }
}

fn attach_cleanup_failure(failure: &mut Failure, cleanup: &CleanupOutcome) {
    if cleanup.confirmed() {
        return;
    }

    failure.detail("cleanup", Detail::Text("unknown".into()));
    failure.detail("cleanup_failures", Detail::Texts(cleanup.failures.clone()));
}

fn retain_report(failure: &mut Failure, report: &Value) -> Result<(), Failure> {
    failure
        .retain(report)
        .map_err(|_| protocol_failure("completed listener report could not be retained"))
}

struct RuntimeSourceInventory {
    scripts: HashMap<String, Value>,
    contexts: HashMap<u64, Value>,
    changed_scripts: HashSet<String>,
    changed_contexts: HashSet<u64>,
    retained_event_bytes: usize,
    source_bytes: usize,
    metadata_complete: bool,
}

impl Default for RuntimeSourceInventory {
    fn default() -> Self {
        Self {
            scripts: HashMap::new(),
            contexts: HashMap::new(),
            changed_scripts: HashSet::new(),
            changed_contexts: HashSet::new(),
            retained_event_bytes: 0,
            source_bytes: 0,
            metadata_complete: true,
        }
    }
}

impl RuntimeSourceInventory {
    fn collect_pending_events(&mut self, transport: &mut dyn CdpEventListenerTransport) {
        let batch = transport.drain_events();
        if batch.dropped > 0 || batch.overflowed {
            self.metadata_complete = false;
        }

        for event in batch.items {
            self.ingest_event(&event.value);
        }
    }

    fn ingest_event(&mut self, event: &Value) {
        let Some(method) = event.get("method").and_then(Value::as_str) else {
            return;
        };
        if !matches!(
            method,
            "Runtime.executionContextCreated" | "Debugger.scriptParsed"
        ) {
            return;
        }

        let Some(params) = event.get("params") else {
            self.metadata_complete = false;
            return;
        };
        let event_bytes = serde_json::to_vec(params).map_or(usize::MAX, |bytes| bytes.len());
        let Some(total_bytes) = self.retained_event_bytes.checked_add(event_bytes) else {
            self.metadata_complete = false;
            return;
        };
        if total_bytes > MAX_RUNTIME_EVENT_BYTES {
            self.metadata_complete = false;
            return;
        }
        self.retained_event_bytes = total_bytes;

        match method {
            "Runtime.executionContextCreated" => self.ingest_context(params),
            "Debugger.scriptParsed" => self.ingest_script(params),
            _ => {}
        }
    }

    fn ingest_context(&mut self, params: &Value) {
        let Some(context) = params.get("context").filter(|value| value.is_object()) else {
            self.metadata_complete = false;
            return;
        };
        let Some(id) = context.get("id").and_then(Value::as_u64) else {
            self.metadata_complete = false;
            return;
        };

        if !valid_optional_string(context, "origin")
            || !valid_optional_string(context, "name")
            || !valid_optional_string(context, "uniqueId")
            || !valid_context_aux_data(context.get("auxData"))
        {
            self.metadata_complete = false;
            return;
        }

        if let Some(previous) = self.contexts.get(&id) {
            if previous != context {
                self.changed_contexts.insert(id);
            }
        }
        self.contexts.insert(id, context.clone());
    }

    fn ingest_script(&mut self, script: &Value) {
        let Some(id) = script
            .get("scriptId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            self.metadata_complete = false;
            return;
        };
        if script.get("url").and_then(Value::as_str).is_none()
            || script
                .get("executionContextId")
                .and_then(Value::as_u64)
                .is_none()
            || script.get("startLine").and_then(Value::as_u64).is_none()
            || script.get("startColumn").and_then(Value::as_u64).is_none()
            || script.get("endLine").and_then(Value::as_u64).is_none()
            || script.get("endColumn").and_then(Value::as_u64).is_none()
            || !valid_optional_string(script, "hash")
            || !valid_optional_string(script, "sourceMapURL")
            || !valid_optional_bool(script, "hasSourceURL")
            || !valid_optional_string(script, "scriptLanguage")
            || !valid_context_aux_data(script.get("executionContextAuxData"))
        {
            self.metadata_complete = false;
            return;
        }

        if let Some(previous) = self.scripts.get(id) {
            if previous != script {
                self.changed_scripts.insert(id.to_owned());
            }
        }
        self.scripts.insert(id.to_owned(), script.clone());
    }

    fn belongs_to_document(&self, script_id: &str, frame_id: &str) -> bool {
        if !self.metadata_complete || self.changed_scripts.contains(script_id) {
            return false;
        }
        let Some(script) = self.scripts.get(script_id) else {
            return false;
        };
        let Some(context_id) = script.get("executionContextId").and_then(Value::as_u64) else {
            return false;
        };
        if self.changed_contexts.contains(&context_id) {
            return false;
        }

        let script_aux = script.get("executionContextAuxData");
        let context_aux = self
            .contexts
            .get(&context_id)
            .and_then(|context| context.get("auxData"));
        let worlds = [script_aux, context_aux];
        if worlds.iter().any(|world| {
            world.is_some_and(|value| {
                value.get("isDefault").and_then(Value::as_bool) == Some(false)
                    || value
                        .get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|kind| kind != "default")
            })
        }) {
            return false;
        }

        let default_world_proven = worlds.iter().any(|world| {
            world.is_some_and(|value| {
                value.get("isDefault").and_then(Value::as_bool) == Some(true)
                    || value.get("type").and_then(Value::as_str) == Some("default")
            })
        });
        if !default_world_proven {
            return false;
        }

        let script_frame = script_aux
            .and_then(|value| value.get("frameId"))
            .and_then(Value::as_str);
        let context_frame = context_aux
            .and_then(|value| value.get("frameId"))
            .and_then(Value::as_str);
        if matches!((script_frame, context_frame), (Some(left), Some(right)) if left != right) {
            return false;
        }

        script_frame.or(context_frame) == Some(frame_id)
    }

    fn location(&self, listener: &ListenerDescriptor, frame_id: &str) -> Value {
        let script = self.scripts.get(&listener.script_id);
        let url = script
            .and_then(|value| value.get("url"))
            .and_then(Value::as_str)
            .map(|value| self.source_url(&listener.script_id, value));

        serde_json::json!({
            "script_id": listener.script_id,
            "url": url,
            "line_number": listener.line_number,
            "column_number": listener.column_number,
            "function_name": null,
            "source_association": if self.belongs_to_document(&listener.script_id, frame_id) { "script_id" } else { "unknown" },
        })
    }

    fn source_url(&self, script_id: &str, url: &str) -> String {
        let source_url_was_not_declared = self
            .scripts
            .get(script_id)
            .and_then(|script| script.get("hasSourceURL"))
            .and_then(Value::as_bool)
            == Some(false);
        if source_url_was_not_declared && !self.changed_scripts.contains(script_id) {
            strip_url_user_info(url)
        } else {
            url.to_owned()
        }
    }

    fn read_for_listeners(
        &mut self,
        transport: &mut dyn CdpEventListenerTransport,
        listeners: &[ListenerDescriptor],
        frame_id: &str,
        cancellation: &Cancellation,
    ) -> Result<Vec<Value>, Failure> {
        let mut seen = HashSet::new();
        let mut retained = Vec::new();

        for listener in listeners {
            let script_id = &listener.script_id;
            if script_id.is_empty() || !seen.insert(script_id.clone()) {
                continue;
            }
            check_cancelled(cancellation)?;

            let mut source = self.source_record(script_id, frame_id);
            if self.belongs_to_document(script_id, frame_id) {
                let language = self
                    .scripts
                    .get(script_id)
                    .and_then(|script| script.get("scriptLanguage"))
                    .and_then(Value::as_str);
                if language == Some("WebAssembly") {
                    source["source"] = serde_json::json!({
                        "state": "excluded",
                        "reason": "WebAssembly bytecode is outside this JavaScript source operation."
                    });
                } else {
                    source["source"] = self.capture_source(transport, script_id)?;
                }
            }

            if !self.belongs_to_document(script_id, frame_id) {
                source["frame_id"] = Value::Null;
                source["source"] = serde_json::json!({
                    "state": "excluded",
                    "reason": self.exclusion_reason(script_id)
                });
            }

            retained.push(source);
        }

        self.revalidate_source_records(&mut retained, frame_id);
        Ok(retained)
    }

    fn revalidate_source_records(&self, records: &mut [Value], frame_id: &str) {
        for record in records {
            let Some(script_id) = record
                .get("script_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
            else {
                continue;
            };
            if self.belongs_to_document(&script_id, frame_id) {
                continue;
            }

            record["frame_id"] = Value::Null;
            record["source"] = serde_json::json!({
                "state": "excluded",
                "reason": self.exclusion_reason(&script_id)
            });
        }
    }

    fn source_record(&self, script_id: &str, frame_id: &str) -> Value {
        let script = self.scripts.get(script_id);
        let context_id = script
            .and_then(|value| value.get("executionContextId"))
            .and_then(Value::as_u64);
        let context = context_id.and_then(|id| self.contexts.get(&id));
        let url = script
            .and_then(|value| value.get("url"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let owned = self.belongs_to_document(script_id, frame_id);

        serde_json::json!({
            "script_id": script_id,
            "url": self.source_url(script_id, url),
            "execution_context_id": context_id,
            "reported_execution_context": context,
            "reported_script_context_aux_data": script
                .and_then(|value| value.get("executionContextAuxData"))
                .filter(|value| value.is_object()),
            "frame_id": if owned { Value::String(frame_id.to_owned()) } else { Value::Null },
            "producer_hash": script.and_then(|value| value.get("hash")).and_then(Value::as_str),
            "source_map_url": script.and_then(|value| value.get("sourceMapURL")).and_then(Value::as_str),
            "has_source_url": script.and_then(|value| value.get("hasSourceURL")).and_then(Value::as_bool),
            "language": script.and_then(|value| value.get("scriptLanguage")).and_then(Value::as_str),
            "resource_start": script.map(|value| serde_json::json!({
                "line_number": value.get("startLine").and_then(Value::as_u64).unwrap_or(0),
                "column_number": value.get("startColumn").and_then(Value::as_u64).unwrap_or(0),
            })),
            "source": {
                "state": "excluded",
                "reason": self.exclusion_reason(script_id),
            }
        })
    }

    fn exclusion_reason(&self, script_id: &str) -> &'static str {
        if self.changed_scripts.contains(script_id) {
            "The script changed identity during observation; source attribution is unknown."
        } else if !self.metadata_complete {
            "CDP source identity events were incomplete; source ownership is unknown."
        } else {
            "Selected main-document default-world ownership was not established."
        }
    }

    fn capture_source(
        &mut self,
        transport: &mut dyn CdpEventListenerTransport,
        script_id: &str,
    ) -> Result<Value, Failure> {
        let response = request_and_collect(
            transport,
            "Debugger.getScriptSource",
            serde_json::json!({"scriptId": script_id}),
            self,
        );
        let response = match response {
            Ok(value) => value,
            Err(reason) => {
                return Ok(serde_json::json!({
                    "state": "unavailable",
                    "reason": reason,
                }));
            }
        };
        let source_text = response
            .get("scriptSource")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                protocol_failure("Debugger.getScriptSource returned malformed source text")
            })?;
        let source_bytes = source_text.len();
        let Some(total_bytes) = self.source_bytes.checked_add(source_bytes) else {
            return Err(source_limit_failure());
        };
        if total_bytes > MAX_RUNTIME_SOURCE_BYTES {
            return Err(source_limit_failure());
        }
        self.source_bytes = total_bytes;

        Ok(serde_json::json!({
            "state": "captured",
            "text": source_text,
            "sha256": sha256_hex(source_text.as_bytes()),
            "utf8_bytes": source_bytes,
            "utf16_units": source_text.encode_utf16().count(),
        }))
    }
}

fn valid_context_aux_data(value: Option<&Value>) -> bool {
    let Some(value) = value else {
        return true;
    };
    if !value.is_object() {
        return false;
    }

    value.get("frameId").is_none_or(Value::is_string)
        && value.get("isDefault").is_none_or(Value::is_boolean)
        && value.get("type").is_none_or(Value::is_string)
}

fn valid_optional_string(value: &Value, name: &str) -> bool {
    value.get(name).is_none_or(Value::is_string)
}

fn valid_optional_bool(value: &Value, name: &str) -> bool {
    value.get(name).is_none_or(Value::is_boolean)
}

fn strip_url_user_info(value: &str) -> String {
    let Some((scheme, remainder)) = value.split_once("://") else {
        return value.to_owned();
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let Some(user_info_end) = authority.rfind('@') else {
        return value.to_owned();
    };

    format!(
        "{scheme}://{}{}",
        &authority[user_info_end + 1..],
        &remainder[authority_end..]
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn source_limit_failure() -> Failure {
    Failure::new(
        "resource_limit",
        "resource_limit",
        "Complete runtime source evidence exceeds its 32 MiB budget.".into(),
        false,
        "Inspect a page with less retained script source.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn request_and_collect(
    transport: &mut dyn CdpEventListenerTransport,
    method: &str,
    params: Value,
    sources: &mut RuntimeSourceInventory,
) -> Result<Value, String> {
    let response = transport.request(method, params);
    sources.collect_pending_events(transport);
    response
}

fn request_required(
    transport: &mut dyn CdpEventListenerTransport,
    method: &str,
    params: Value,
    sources: &mut RuntimeSourceInventory,
) -> Result<Value, Failure> {
    request_and_collect(transport, method, params, sources)
        .map_err(|reason| protocol_failure(&format!("{method} failed: {reason}")))
}

fn request_cancellable(
    transport: &mut dyn CdpEventListenerTransport,
    method: &str,
    params: Value,
    cancellation: &Cancellation,
    sources: &mut RuntimeSourceInventory,
) -> Result<Value, Failure> {
    check_cancelled(cancellation)?;
    let response = request_required(transport, method, params, sources)?;
    check_cancelled(cancellation)?;
    Ok(response)
}

fn main_frame(tree: &Value, allowed_origins: &[&str]) -> Result<MainFrame, Failure> {
    let frame = tree
        .pointer("/frameTree/frame")
        .ok_or_else(|| protocol_failure("Page.getFrameTree omitted the main frame"))?;
    let url = frame
        .get("url")
        .and_then(Value::as_str)
        .filter(|value| value.starts_with("http://") || value.starts_with("https://"))
        .ok_or_else(|| unsupported_failure("selected page has no HTTP(S) URL"))?;
    let sanitized_url = strip_url_user_info(url);
    let origin =
        origin(&sanitized_url).ok_or_else(|| unsupported_failure("selected page has no origin"))?;
    if !allowed_origins.is_empty() && !allowed_origins.iter().any(|item| *item == origin) {
        return Err(Failure::new(
            "target_not_allowed",
            "policy",
            "The selected page origin is outside the caller's allowed origins.".into(),
            false,
            "Add the exact origin to allowed_origins or select another page.".into(),
            BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
        ));
    }
    let frame_id = frame
        .get("id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| protocol_failure("main frame omitted id"))?;
    Ok(MainFrame {
        url: sanitized_url,
        origin,
        frame_id: frame_id.to_owned(),
        loader_id: frame
            .get("loaderId")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn browser_version_unknown() -> Value {
    serde_json::json!({
        "product":"unknown",
        "protocol_version":"unknown",
        "revision":"unknown",
        "user_agent":"unknown",
        "js_version":"unknown"
    })
}

fn required_u64(value: &Value, pointer: &str, label: &str) -> Result<u64, Failure> {
    value
        .pointer(pointer)
        .and_then(Value::as_u64)
        .ok_or_else(|| protocol_failure(&format!("{label} omitted a non-negative integer")))
}

fn check_cancelled(cancellation: &Cancellation) -> Result<(), Failure> {
    match cancellation.reason() {
        Some(reason) => Err(cancelled_failure(reason)),
        None => Ok(()),
    }
}

fn cancelled_failure(reason: &str) -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "The caller cancelled web event-listener inspection.".into(),
        false,
        "Retry the passive inspection when the caller is ready.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.to_owned())),
        ]),
    )
}

fn origin(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    (!authority.is_empty()).then(|| format!("{scheme}://{authority}"))
}

fn target_mismatch() -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        "The inspection target differs from the connected target.".into(),
        false,
        "Retry after reconnecting to the caller-selected page target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn target_changed() -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        "The selected page navigated during listener inspection.".into(),
        false,
        "Retry after selecting a stable page target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "protocol_error",
        "provider",
        reason.into(),
        true,
        "Retry the bounded CDP listener inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn unsupported_failure(reason: &str) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        reason.into(),
        false,
        "Select a page with an HTTP(S) origin.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    browser::target_discovery::validate_scope(input, OPERATION)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web event-listener input must be an object"))?;
    non_empty(object.get("target_id"), "target_id")?;
    non_empty(object.get("selector"), "selector")?;
    Ok(())
}

fn captured_value(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_capture("captured listener input must be an object"))?;
    let mut capture = object
        .get("capture")
        .or_else(|| object.get("evidence"))
        .unwrap_or(input);
    if let Some(evidence) = capture.get("evidence") {
        capture = evidence;
    }
    if !capture.is_object() {
        return Err(invalid_capture("captured listener facts must be an object"));
    }
    Ok(capture)
}

fn is_evidence_record(value: &Value) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.contains_key("normalized_result"))
}

fn validate_evidence(value: &Value) -> Result<(), Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid_capture(&format!("listener Evidence is not JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| {
        invalid_capture(&format!("listener Evidence is not authenticated: {error}"))
    })?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid_capture(
            "listener Evidence operation must be inspect_web_event_listeners",
        ));
    }
    let normalized: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid_capture(&format!("listener Evidence result is not JSON: {error}"))
        })?;
    validate_report(&normalized)
}

fn validate_report(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_capture("listener capture must be an object"))?;
    validate_browser(object.get("browser"))?;
    validate_target(object.get("target"))?;
    iso_datetime(object.get("inspected_at"), "inspected_at")?;
    validate_selected_node(object.get("selected_node"))?;
    let listeners = array_capture(object.get("listeners"), "listeners")?;
    for listener in listeners {
        validate_listener(listener)?;
    }
    let sources = array_capture(object.get("sources"), "sources")?;
    for source in sources {
        validate_source(source)?;
    }
    if object.get("cleanup").and_then(Value::as_str) != Some("confirmed") {
        return Err(invalid_capture("cleanup must be confirmed"));
    }
    validate_text_array(object.get("limitations"), "limitations")
}

fn validate_browser(value: Option<&Value>) -> Result<(), Failure> {
    let object = object_capture(value, "browser")?;
    for field in [
        "product",
        "protocol_version",
        "revision",
        "user_agent",
        "js_version",
    ] {
        text_capture(object.get(field), &format!("browser.{field}"))?;
    }
    Ok(())
}

fn validate_target(value: Option<&Value>) -> Result<(), Failure> {
    let object = object_capture(value, "target")?;
    for field in ["target_id", "origin", "frame_id"] {
        non_empty_capture(object.get(field), &format!("target.{field}"))?;
    }
    text_capture(object.get("initial_url"), "target.initial_url")?;
    nullable_text(object.get("loader_id"), "target.loader_id")
}

fn validate_selected_node(value: Option<&Value>) -> Result<(), Failure> {
    let object = object_capture(value, "selected_node")?;
    text_capture(object.get("selector"), "selected_node.selector")?;
    if !matches!(
        object.get("match").and_then(Value::as_str),
        Some("found" | "not_found")
    ) {
        return Err(invalid_capture(
            "selected_node.match must be found or not_found",
        ));
    }
    nullable_positive_integer(
        object.get("backend_node_id"),
        "selected_node.backend_node_id",
    )
}

fn validate_listener(value: &Value) -> Result<(), Failure> {
    let object = object_capture(Some(value), "listener")?;
    text_capture(object.get("type"), "listener.type")?;
    for field in ["use_capture", "passive", "once"] {
        if object.get(field).and_then(Value::as_bool).is_none() {
            return Err(invalid_capture(&format!(
                "listener.{field} must be boolean"
            )));
        }
    }
    validate_location(object.get("location"))?;
    if object.get("execution").and_then(Value::as_str) != Some("unknown") {
        return Err(invalid_capture("listener.execution must be unknown"));
    }
    Ok(())
}

fn validate_location(value: Option<&Value>) -> Result<(), Failure> {
    let object = object_capture(value, "listener.location")?;
    text_capture(object.get("script_id"), "listener.location.script_id")?;
    nullable_text(object.get("url"), "listener.location.url")?;
    nonnegative_integer_capture(object.get("line_number"), "listener.location.line_number")?;
    nullable_nonnegative_integer(
        object.get("column_number"),
        "listener.location.column_number",
    )?;
    nullable_text(
        object.get("function_name"),
        "listener.location.function_name",
    )?;
    if !matches!(
        object.get("source_association").and_then(Value::as_str),
        Some("script_id" | "unknown")
    ) {
        return Err(invalid_capture(
            "listener.location.source_association is invalid",
        ));
    }
    Ok(())
}

fn validate_source(value: &Value) -> Result<(), Failure> {
    let object = object_capture(Some(value), "source")?;
    non_empty_capture(object.get("script_id"), "source.script_id")?;
    nullable_text(object.get("url"), "source.url")?;
    nullable_integer(
        object.get("execution_context_id"),
        "source.execution_context_id",
    )?;
    nullable_object(
        object.get("reported_execution_context"),
        "source.reported_execution_context",
    )?;
    nullable_object(
        object.get("reported_script_context_aux_data"),
        "source.reported_script_context_aux_data",
    )?;
    nullable_text(object.get("frame_id"), "source.frame_id")?;
    nullable_text(object.get("producer_hash"), "source.producer_hash")?;
    nullable_text(object.get("source_map_url"), "source.source_map_url")?;
    nullable_bool(object.get("has_source_url"), "source.has_source_url")?;
    nullable_text(object.get("language"), "source.language")?;
    validate_resource_start(object.get("resource_start"))?;
    validate_source_content(object.get("source"))
}

fn validate_resource_start(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Err(invalid_capture("source.resource_start is required"));
    };
    if value.is_null() {
        return Ok(());
    }
    let object = object_capture(Some(value), "source.resource_start")?;
    nonnegative_integer_capture(
        object.get("line_number"),
        "source.resource_start.line_number",
    )?;
    nonnegative_integer_capture(
        object.get("column_number"),
        "source.resource_start.column_number",
    )
    .map(|_| ())
}

fn validate_source_content(value: Option<&Value>) -> Result<(), Failure> {
    let object = object_capture(value, "source.source")?;
    match object.get("state").and_then(Value::as_str) {
        Some("captured") => {
            text_capture(object.get("text"), "source.source.text")?;
            let digest = non_empty_capture(object.get("sha256"), "source.source.sha256")?;
            if digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(invalid_capture(
                    "source.source.sha256 must be lowercase SHA-256",
                ));
            }
            nonnegative_integer_capture(object.get("utf8_bytes"), "source.source.utf8_bytes")?;
            nonnegative_integer_capture(object.get("utf16_units"), "source.source.utf16_units")?;
        }
        Some("unavailable" | "excluded") => {
            non_empty_capture(object.get("reason"), "source.source.reason")?;
        }
        _ => return Err(invalid_capture("source.source.state is invalid")),
    }
    Ok(())
}

fn object_capture<'a>(
    value: Option<&'a Value>,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, Failure> {
    value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_capture(&format!("{field} must be an object")))
}

fn array_capture<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a Vec<Value>, Failure> {
    value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_capture(&format!("{field} must be an array")))
}

fn validate_text_array(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    for item in array_capture(value, field)? {
        text_capture(Some(item), field)?;
    }
    Ok(())
}

fn non_empty_capture<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_capture(&format!("{field} must be a non-empty string")))
}

fn text_capture<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_capture(&format!("{field} must be a string")))
}

fn iso_datetime(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let text = text_capture(value, field)?;
    let valid_shape = text.len() >= 20
        && text.as_bytes().get(4) == Some(&b'-')
        && text.as_bytes().get(7) == Some(&b'-')
        && text.as_bytes().get(10) == Some(&b'T')
        && text.as_bytes().get(13) == Some(&b':')
        && text.as_bytes().get(16) == Some(&b':')
        && text.ends_with('Z');
    if !valid_shape {
        return Err(invalid_capture(&format!("{field} must be an ISO datetime")));
    }
    Ok(())
}

fn nullable_text(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid_capture(&format!("{field} is required")))?;
    if !value.is_null() && value.as_str().is_none() {
        return Err(invalid_capture(&format!("{field} must be text or null")));
    }
    Ok(())
}

fn nullable_bool(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid_capture(&format!("{field} is required")))?;
    if !value.is_null() && value.as_bool().is_none() {
        return Err(invalid_capture(&format!("{field} must be boolean or null")));
    }
    Ok(())
}

fn nullable_object(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid_capture(&format!("{field} is required")))?;
    if !value.is_null() && !value.is_object() {
        return Err(invalid_capture(&format!(
            "{field} must be an object or null"
        )));
    }
    Ok(())
}

fn nullable_positive_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid_capture(&format!("{field} is required")))?;
    if !value.is_null() && value.as_u64().is_none_or(|value| value == 0) {
        return Err(invalid_capture(&format!(
            "{field} must be positive or null"
        )));
    }
    Ok(())
}

fn nullable_nonnegative_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid_capture(&format!("{field} is required")))?;
    if !value.is_null() && value.as_u64().is_none() {
        return Err(invalid_capture(&format!(
            "{field} must be a non-negative integer or null"
        )));
    }
    Ok(())
}

fn nullable_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid_capture(&format!("{field} is required")))?;
    if !value.is_null() && value.as_i64().is_none() {
        return Err(invalid_capture(&format!(
            "{field} must be an integer or null"
        )));
    }
    Ok(())
}

fn nonnegative_integer_capture(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_capture(&format!("{field} must be a non-negative integer")))
}

fn invalid_capture(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a complete captured inspect_web_event_listeners report or authenticated Evidence."
            .into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            (
                "authority".into(),
                Detail::Text("offline_capture_only".into()),
            ),
        ]),
    )
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web event-listener result must be an object"));
    }
    Ok(result)
}

fn non_empty<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a caller-selected loopback CDP page and CSS selector for passive listener inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::cdp_transport::CdpEvent;

    const SOURCE_TEXT: &str = "const n = 'é😀';";

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": ["https://example.test"],
            "target_id": "TARGET_ID",
            "selector": "#submit"
        })
    }

    #[test]
    fn accepts_listener_inspection_request() {
        validate_input(&input()).expect("valid listener inspection input");
        assert!(retain_result(&input(), serde_json::json!({"listeners": []})).is_ok());
    }

    #[test]
    fn rejects_non_http_endpoint() {
        let mut invalid_input = input();
        invalid_input["cdp_endpoint"] = serde_json::json!("ws://127.0.0.1:9222");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_empty_selector() {
        let mut invalid_input = input();
        invalid_input["selector"] = serde_json::json!("");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_origin_filters_that_are_not_exact_origins() {
        let mut invalid_input = input();
        invalid_input["allowed_origins"] = serde_json::json!(["https://example.test/path"]);

        let failure = validate_input(&invalid_input).expect_err("origin must be exact");

        assert_eq!(failure.operation(), Some(OPERATION));
    }

    struct MockTransport {
        methods: Vec<String>,
        requests: Vec<(String, Value)>,
        responses: HashMap<String, Vec<Result<Value, String>>>,
        events_after_method: HashMap<String, Vec<Value>>,
        pending_events: Vec<CdpEvent>,
        event_sequence: u64,
        overflow_after_method: HashSet<String>,
        pending_overflow: bool,
        cancellation: Option<Cancellation>,
        cancel_after_method: Option<String>,
        close_error: Option<String>,
        closed: bool,
    }

    impl CdpEventListenerTransport for MockTransport {
        fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
            self.methods.push(method.to_owned());
            self.requests.push((method.to_owned(), params));
            if let Some(events) = self.events_after_method.remove(method) {
                for value in events {
                    self.event_sequence += 1;
                    self.pending_events.push(CdpEvent {
                        sequence: self.event_sequence,
                        value,
                    });
                }
            }
            if self.overflow_after_method.remove(method) {
                self.pending_overflow = true;
            }

            if self.cancel_after_method.as_deref() == Some(method) {
                if let Some(cancellation) = &self.cancellation {
                    cancellation.cancel("test cancellation");
                }
            }

            self.responses
                .get_mut(method)
                .and_then(|responses| {
                    if responses.is_empty() {
                        None
                    } else {
                        Some(responses.remove(0))
                    }
                })
                .unwrap_or_else(|| Err(format!("unexpected CDP method: {method}")))
        }

        fn drain_events(&mut self) -> CdpEventBatch {
            CdpEventBatch {
                items: std::mem::take(&mut self.pending_events),
                dropped: u64::from(self.pending_overflow),
                overflowed: std::mem::take(&mut self.pending_overflow),
            }
        }

        fn close_connection(&mut self) -> Result<(), String> {
            self.closed = true;
            match self.close_error.take() {
                Some(reason) => Err(reason),
                None => Ok(()),
            }
        }
    }

    fn mock_transport() -> MockTransport {
        let frame_tree = || {
            serde_json::json!({"frameTree":{"frame":{
                "id":"main-frame",
                "loaderId":"document-1",
                "url":"https://example.test/app"
            }}})
        };
        let mut responses = HashMap::new();
        responses.insert("Page.enable".into(), vec![Ok(serde_json::json!({}))]);
        responses.insert("Runtime.enable".into(), vec![Ok(serde_json::json!({}))]);
        responses.insert("Debugger.enable".into(), vec![Ok(serde_json::json!({}))]);
        responses.insert("DOM.enable".into(), vec![Ok(serde_json::json!({}))]);
        responses.insert(
            "Page.getFrameTree".into(),
            vec![Ok(frame_tree()), Ok(frame_tree())],
        );
        responses.insert(
            "DOM.getDocument".into(),
            vec![Ok(serde_json::json!({"root":{"nodeId":1}}))],
        );
        responses.insert(
            "DOM.querySelector".into(),
            vec![Ok(serde_json::json!({"nodeId":2}))],
        );
        responses.insert(
            "DOM.describeNode".into(),
            vec![Ok(serde_json::json!({"node":{"backendNodeId":22}}))],
        );
        responses.insert(
            "DOM.resolveNode".into(),
            vec![Ok(serde_json::json!({"object":{"objectId":"object-1"}}))],
        );
        responses.insert(
            "DOMDebugger.getEventListeners".into(),
            vec![Ok(serde_json::json!({"listeners":[{
                "type":"click",
                "useCapture":true,
                "passive":false,
                "once":true,
                "scriptId":"script-1",
                "lineNumber":4,
                "columnNumber":2
            }]}))],
        );
        responses.insert(
            "Debugger.getScriptSource".into(),
            vec![Ok(serde_json::json!({"scriptSource":SOURCE_TEXT}))],
        );
        responses.insert(
            "Browser.getVersion".into(),
            vec![Ok(serde_json::json!({"product":"MockChrome/1"}))],
        );
        responses.insert(
            "Runtime.releaseObjectGroup".into(),
            vec![Ok(serde_json::json!({}))],
        );
        for domain in ["DOM", "Debugger", "Runtime", "Page"] {
            responses.insert(format!("{domain}.disable"), vec![Ok(serde_json::json!({}))]);
        }

        MockTransport {
            methods: Vec::new(),
            requests: Vec::new(),
            responses,
            events_after_method: HashMap::from([
                ("Runtime.enable".into(), vec![context_event()]),
                ("Debugger.enable".into(), vec![script_event()]),
            ]),
            pending_events: Vec::new(),
            event_sequence: 0,
            overflow_after_method: HashSet::new(),
            pending_overflow: false,
            cancellation: None,
            cancel_after_method: None,
            close_error: None,
            closed: false,
        }
    }

    fn context_event() -> Value {
        serde_json::json!({
            "method":"Runtime.executionContextCreated",
            "params":{"context":{
                "id":7,
                "origin":"https://example.test",
                "name":"",
                "uniqueId":"context-unique",
                "auxData":{"frameId":"main-frame","isDefault":true,"type":"default"}
            }}
        })
    }

    fn script_event() -> Value {
        serde_json::json!({
            "method":"Debugger.scriptParsed",
            "params":{
                "scriptId":"script-1",
                "url":"https://user:pass@example.test/app.js",
                "executionContextId":7,
                "startLine":2,
                "startColumn":3,
                "endLine":8,
                "endColumn":1,
                "hash":"producer-hash",
                "sourceMapURL":"https://example.test/app.js.map",
                "hasSourceURL":false,
                "scriptLanguage":"JavaScript",
                "executionContextAuxData":{"frameId":"main-frame","isDefault":true,"type":"default"}
            }
        })
    }

    fn run_inspection(transport: MockTransport) -> Result<Value, Failure> {
        let mut port = ConnectedCdpEventListenerPort::from_transport(transport, "TARGET_ID");
        port.inspect(&input(), "started", "2026-10-21T00:00:00Z")
    }

    fn report_from_failure(failure: &Failure) -> Value {
        serde_json::to_value(failure).expect("failure serialization")
    }

    #[test]
    fn captures_source_with_proven_default_world_identity_and_owned_cleanup() {
        let mut port = ConnectedCdpEventListenerPort::from_transport(mock_transport(), "TARGET_ID");

        let result = port
            .inspect(&input(), "started", "2026-10-21T00:00:00Z")
            .expect("listener inspection should succeed");

        assert_eq!(result["selected_node"]["match"], "found");
        assert_eq!(result["selected_node"]["backend_node_id"], 22);
        assert_eq!(result["listeners"][0]["type"], "click");
        assert_eq!(
            result["listeners"][0]["location"]["source_association"],
            "script_id"
        );
        assert_eq!(
            result["listeners"][0]["location"]["url"],
            "https://example.test/app.js"
        );
        assert_eq!(result["sources"].as_array().map(Vec::len), Some(1));
        assert_eq!(result["sources"][0]["script_id"], "script-1");
        assert_eq!(result["sources"][0]["url"], "https://example.test/app.js");
        assert_eq!(result["sources"][0]["frame_id"], "main-frame");
        assert_eq!(result["sources"][0]["producer_hash"], "producer-hash");
        assert_eq!(result["sources"][0]["execution_context_id"], 7);
        assert_eq!(result["sources"][0]["source"]["state"], "captured");
        assert_eq!(result["sources"][0]["source"]["text"], SOURCE_TEXT);
        assert_eq!(
            result["sources"][0]["source"]["sha256"],
            "937622efdbac82d13ff690e291409fe5ecd9127f9fea1c61baed8d997cadab6d"
        );
        assert_eq!(result["sources"][0]["source"]["utf8_bytes"], 19);
        assert_eq!(result["sources"][0]["source"]["utf16_units"], 16);
        assert_eq!(result["cleanup"], "confirmed");
        assert!(port.transport.closed);

        let resolve = port
            .transport
            .requests
            .iter()
            .find(|(method, _)| method == "DOM.resolveNode")
            .expect("resolve request");
        let release = port
            .transport
            .requests
            .iter()
            .find(|(method, _)| method == "Runtime.releaseObjectGroup")
            .expect("group cleanup request");
        assert_eq!(resolve.1["objectGroup"], release.1["objectGroup"]);
        assert_eq!(
            port.transport
                .methods
                .iter()
                .filter(|method| method.ends_with(".enable"))
                .take(4)
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "Page.enable",
                "Runtime.enable",
                "Debugger.enable",
                "DOM.enable"
            ]
        );
        assert!(
            port.transport
                .methods
                .iter()
                .any(|method| method == "DOM.disable")
        );
        assert!(
            port.transport
                .methods
                .iter()
                .any(|method| method == "Debugger.disable")
        );
        assert!(
            port.transport
                .methods
                .iter()
                .any(|method| method == "Runtime.disable")
        );
        assert!(
            port.transport
                .methods
                .iter()
                .any(|method| method == "Page.disable")
        );
        assert!(
            !port
                .transport
                .methods
                .iter()
                .any(|method| method == "Runtime.evaluate")
        );
        assert!(
            !port
                .transport
                .methods
                .iter()
                .any(|method| method == "DOMDebugger.invoke_getEventListeners")
        );
    }

    #[test]
    fn isolated_world_and_missing_metadata_do_not_establish_source_ownership() {
        let mut isolated = mock_transport();
        isolated.events_after_method.insert(
            "Debugger.enable".into(),
            vec![{
                let mut event = script_event();
                event["params"]["executionContextAuxData"]["isDefault"] = serde_json::json!(false);
                event
            }],
        );
        let isolated_report = run_inspection(isolated).expect("isolated listener report");
        assert_eq!(
            isolated_report["listeners"][0]["location"]["source_association"],
            "unknown"
        );
        assert_eq!(isolated_report["sources"][0]["source"]["state"], "excluded");

        let mut missing = mock_transport();
        missing.events_after_method.clear();
        let missing_report = run_inspection(missing).expect("missing-metadata report");
        assert_eq!(missing_report["sources"][0]["frame_id"], Value::Null);
        assert_eq!(missing_report["sources"][0]["source"]["state"], "excluded");
    }

    #[test]
    fn event_buffer_overflow_keeps_source_identity_unknown() {
        let mut transport = mock_transport();
        transport
            .overflow_after_method
            .insert("Debugger.enable".into());

        let result = run_inspection(transport).expect("partial identity report");

        assert_eq!(
            result["listeners"][0]["location"]["source_association"],
            "unknown"
        );
        assert_eq!(result["sources"][0]["source"]["state"], "excluded");
        assert!(
            result["sources"][0]["source"]["reason"]
                .as_str()
                .unwrap()
                .contains("events were incomplete")
        );
    }

    #[test]
    fn changed_script_identity_during_source_read_excludes_captured_text() {
        let mut transport = mock_transport();
        let mut changed_script = script_event();
        changed_script["params"]["url"] = serde_json::json!("https://example.test/replaced.js");
        transport
            .events_after_method
            .insert("Debugger.getScriptSource".into(), vec![changed_script]);

        let result = run_inspection(transport).expect("changed identity report");

        assert_eq!(result["sources"][0]["frame_id"], Value::Null);
        assert_eq!(result["sources"][0]["source"]["state"], "excluded");
        assert_eq!(
            result["listeners"][0]["location"]["source_association"],
            "unknown"
        );
    }

    #[test]
    fn cancellation_after_node_resolution_releases_the_runtime_object_group() {
        let cancellation = Cancellation::default();
        let mut transport = mock_transport();
        transport.cancellation = Some(cancellation.clone());
        transport.cancel_after_method = Some("DOM.resolveNode".into());
        let mut port = ConnectedCdpEventListenerPort::from_transport(transport, "TARGET_ID");

        let failure = port
            .inspect_with_cancellation(&input(), "started", "ended", &cancellation)
            .expect_err("cancelled inspection must return a failure");

        assert_eq!(failure.code(), "cancelled");
        assert!(
            port.transport
                .methods
                .iter()
                .any(|method| method == "Runtime.releaseObjectGroup")
        );
        assert!(
            port.transport
                .methods
                .iter()
                .any(|method| method == "DOM.disable")
        );
        assert!(
            !port
                .transport
                .methods
                .iter()
                .any(|method| method == "DOMDebugger.getEventListeners")
        );
        assert!(port.transport.closed);
    }

    #[test]
    fn cancellation_during_final_cleanup_retains_the_completed_report() {
        let cancellation = Cancellation::default();
        let mut transport = mock_transport();
        transport.cancellation = Some(cancellation.clone());
        transport.cancel_after_method = Some("Runtime.releaseObjectGroup".into());
        let mut port = ConnectedCdpEventListenerPort::from_transport(transport, "TARGET_ID");

        let failure = port
            .inspect_with_cancellation(&input(), "started", "ended", &cancellation)
            .expect_err("cleanup cancellation must retain completed report");
        let serialized = report_from_failure(&failure);

        assert_eq!(failure.code(), "cancelled");
        assert_eq!(serialized["details"]["reason"], "test cancellation");
        assert_eq!(
            serialized["details"]["partial_observation"]["cleanup"],
            "confirmed"
        );
        assert_eq!(
            serialized["details"]["partial_observation"]["sources"][0]["source"]["state"],
            "captured"
        );
        assert!(port.transport.closed);
    }

    #[test]
    fn cleanup_failure_keeps_observation_and_never_claims_confirmation() {
        let mut transport = mock_transport();
        transport.responses.insert(
            "Debugger.disable".into(),
            vec![Err("debugger domain still active".into())],
        );
        let failure = run_inspection(transport).expect_err("incomplete cleanup must fail");
        let serialized = report_from_failure(&failure);

        assert_eq!(serialized["details"]["cleanup"], "unknown");
        assert_eq!(
            serialized["details"]["partial_observation"]["cleanup"],
            "unknown"
        );
        assert_eq!(
            serialized["details"]["partial_observation"]["listeners"][0]["type"],
            "click"
        );
        assert_eq!(
            serialized["details"]["cleanup_failures"][0],
            "Debugger.disable: debugger domain still active"
        );
        assert_eq!(
            serialized["details"]["cleanup_failures"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn source_budget_is_enforced_before_retaining_an_over_limit_source() {
        let mut transport = mock_transport();
        let mut inventory = RuntimeSourceInventory::default();
        inventory.source_bytes = MAX_RUNTIME_SOURCE_BYTES;

        let failure = inventory
            .capture_source(&mut transport, "script-1")
            .expect_err("over-budget source should fail");

        assert_eq!(failure.code(), "resource_limit");
        assert_eq!(inventory.source_bytes, MAX_RUNTIME_SOURCE_BYTES);
    }

    #[test]
    fn rejects_input_for_a_different_connected_target_before_transport_use() {
        let mut port = ConnectedCdpEventListenerPort::from_transport(mock_transport(), "TARGET_ID");

        let mut different = input();
        different["target_id"] = serde_json::json!("OTHER");
        let error = port
            .inspect(&different, "started", "ended")
            .expect_err("target mismatch must fail closed");

        assert_eq!(error.code(), "target_changed");
        assert!(port.transport.methods.is_empty());
    }

    #[test]
    fn malformed_listener_rows_are_not_silently_discarded() {
        let failure = parse_listeners(&serde_json::json!({"listeners":[{"type":"click"}]}))
            .expect_err("incomplete listener must be a protocol failure");

        assert_eq!(failure.code(), "protocol_error");
    }

    #[test]
    fn strips_only_user_information_from_script_urls() {
        assert_eq!(
            strip_url_user_info("https://user:pass@example.test/a?token=kept#fragment"),
            "https://example.test/a?token=kept#fragment"
        );
        assert_eq!(
            strip_url_user_info("https://example.test/a?token=kept"),
            "https://example.test/a?token=kept"
        );
    }
}
