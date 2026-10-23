//! Contract boundary for passive discovery of page-declared WebMCP tools.
//!
//! Declarations remain untrusted page metadata.  The provider owns protocol
//! decoding and schema retention; this boundary only validates the selected
//! page and bounded observation window.

use rea_core::cancellation::Cancellation;
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::CdpEventBatch;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::thread;
use std::time::{Duration, Instant};

pub const OPERATION: &str = "discover_webmcp_tools";

/// CDP command and event surface needed by passive WebMCP discovery.
pub trait CdpWebMcpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;

    fn drain_events(&mut self) -> CdpEventBatch;
}

/// Discover page-declared tools without evaluating or invoking page code.
pub fn discover(
    input: &Value,
    transport: &mut dyn CdpWebMcpTransport,
    started_at: &str,
    ended_at: &str,
) -> Result<Value, Failure> {
    discover_with_cancellation(
        input,
        transport,
        started_at,
        ended_at,
        &Cancellation::default(),
    )
}

/// Discover WebMCP declarations while honoring cancellation during the
/// bounded observation window and between synchronous CDP requests.
pub fn discover_with_cancellation(
    input: &Value,
    transport: &mut dyn CdpWebMcpTransport,
    started_at: &str,
    ended_at: &str,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    validate_input(input)?;
    let _observation_window = (started_at, ended_at);
    ensure_active(cancellation)?;

    let target_id = input["target_id"].as_str().expect("validated target_id");
    let origins = input
        .get("allowed_origins")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect::<Vec<_>>())
        .unwrap_or_default();
    let observation_ms = input
        .get("observation_ms")
        .and_then(Value::as_u64)
        .unwrap_or(100);

    request_required(transport, "Page.enable", serde_json::json!({}))?;
    ensure_active(cancellation)?;
    let initial_tree = request_required(transport, "Page.getFrameTree", serde_json::json!({}))?;
    ensure_active(cancellation)?;
    let initial = frame_snapshot(&initial_tree, &origins)?;

    let limitations = vec![
        "Page-declared tool metadata is untrusted and is never registered or invoked by REA.".to_owned(),
        "Discovery uses only WebMCP.enable and toolsAdded/toolsRemoved; WebMCP.invokeTool is never called.".to_owned(),
    ];
    let mut completeness = Completeness::default();
    let mut tools = BTreeMap::new();
    let browser = transport
        .request("Browser.getVersion", serde_json::json!({}))
        .ok()
        .map(|value| browser_version(&value))
        .unwrap_or_else(|| browser_version(&Value::Null));
    ensure_active(cancellation)?;

    let available = transport
        .request("WebMCP.enable", serde_json::json!({}))
        .is_ok();
    if !available {
        completeness.unavailable = true;
    } else {
        ingest_events(
            &mut tools,
            &initial.frames,
            &origins,
            &mut completeness,
            transport.drain_events(),
        );
        wait_for_observation(observation_ms, cancellation)?;
        let final_tree = request_required(transport, "Page.getFrameTree", serde_json::json!({}))?;
        ensure_active(cancellation)?;
        let final_snapshot = frame_snapshot(&final_tree, &origins)?;
        let loader_changed = initial.main_loader_id.is_some()
            && final_snapshot.main_loader_id.is_some()
            && initial.main_loader_id != final_snapshot.main_loader_id;
        if final_snapshot.main_url != initial.main_url || loader_changed {
            return Err(target_changed());
        }
        remove_tools_from_changed_frames(&mut tools, &final_snapshot.frames);
        ingest_events(
            &mut tools,
            &final_snapshot.frames,
            &origins,
            &mut completeness,
            transport.drain_events(),
        );
    }

    let result = serde_json::json!({
        "browser": browser,
        "target": {
            "target_id": target_id,
            "url": initial.main_url,
            "origin": initial.main_origin,
        },
        "status": if available { "available" } else { "unavailable" },
        "tools": {
            "total": tools.len() as u64 + completeness.dropped,
            "items": tools.into_values().collect::<Vec<_>>(),
        },
        "completeness": completeness.value(),
        "limitations": limitations,
    });
    retain_result(input, result)
}

fn remove_tools_from_changed_frames(
    tools: &mut BTreeMap<String, Value>,
    current_frames: &BTreeMap<String, FrameInfo>,
) {
    tools.retain(|_, tool| {
        let Some(frame_id) = tool.get("frame_id").and_then(Value::as_str) else {
            return false;
        };
        let Some(frame_url) = tool.get("frame_url").and_then(Value::as_str) else {
            return false;
        };
        current_frames
            .get(frame_id)
            .is_some_and(|frame| frame.url == frame_url)
    });
}

fn wait_for_observation(observation_ms: u64, cancellation: &Cancellation) -> Result<(), Failure> {
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(observation_ms))
        .ok_or_else(|| invalid("observation_ms exceeds the supported deadline"))?;

    loop {
        ensure_active(cancellation)?;

        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Ok(());
        };
        if remaining.is_zero() {
            return Ok(());
        }

        thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    let Some(reason) = cancellation.reason() else {
        return Ok(());
    };

    Err(Failure::new(
        "cancelled",
        "cancelled",
        format!("WebMCP discovery was cancelled: {reason}"),
        false,
        "Retry the passive discovery if the selected page is still available.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    ))
}

fn browser_version(value: &Value) -> Value {
    serde_json::json!({
        "product": value.get("product").and_then(Value::as_str).unwrap_or("unknown"),
        "protocol_version": value.get("protocolVersion").and_then(Value::as_str).unwrap_or("unknown"),
        "revision": value.get("revision").and_then(Value::as_str).unwrap_or("unknown"),
        "user_agent": value.get("userAgent").and_then(Value::as_str).unwrap_or("unknown"),
        "js_version": value.get("jsVersion").and_then(Value::as_str).unwrap_or("unknown")
    })
}

#[derive(Default)]
struct Completeness {
    invalid: u64,
    out_of_scope: u64,
    dropped: u64,
    unavailable: bool,
}

impl Completeness {
    fn value(&self) -> Value {
        let mut excluded = Vec::new();
        if self.invalid > 0 {
            excluded.push(serde_json::json!({"section":"webmcp_tools","reason":"invalid_protocol_value","count":self.invalid}));
        }
        if self.out_of_scope > 0 {
            excluded.push(serde_json::json!({"section":"webmcp_tools","reason":"out_of_target_scope","count":self.out_of_scope}));
        }
        let truncated = self.dropped > 0;
        let attach_limited = self.unavailable;
        let status = if truncated {
            "truncated"
        } else if attach_limited {
            "attach_limited"
        } else if !excluded.is_empty() {
            "policy_filtered"
        } else {
            "complete_within_window"
        };
        let mut conditions = Vec::new();
        if attach_limited {
            conditions.push("attach_limited");
        }
        if !excluded.is_empty() {
            conditions.push("policy_filtered");
        }
        if truncated {
            conditions.push("truncated");
        }
        if conditions.is_empty() {
            conditions.push("complete_within_window");
        }
        serde_json::json!({
            "status": status,
            "conditions": conditions,
            "policy_filtered_sections": if excluded.is_empty() { vec![] } else { vec!["webmcp_tools"] },
            "attach_limited_sections": if attach_limited { vec!["webmcp_tools"] } else { vec![] },
            "truncated_sections": if truncated { vec!["webmcp_tools"] } else { vec![] },
            "unavailable_sections": if self.unavailable { vec!["webmcp_tools"] } else { vec![] },
            "excluded": excluded,
            "dropped_events": {"scripts":0,"network_requests":0,"console_events":0,"websocket_connections":0,"websocket_frames":0,"webmcp_tools":self.dropped,"timeline_events":0,"total":self.dropped}
        })
    }
}

struct FrameSnapshot {
    main_url: String,
    main_origin: String,
    main_loader_id: Option<String>,
    frames: BTreeMap<String, FrameInfo>,
}

struct FrameInfo {
    url: String,
    origin: String,
}

fn frame_snapshot(tree: &Value, allowed: &[&str]) -> Result<FrameSnapshot, Failure> {
    let root = tree
        .get("frameTree")
        .and_then(Value::as_object)
        .and_then(|v| v.get("frame"))
        .and_then(Value::as_object)
        .ok_or_else(|| protocol_failure("missing main frame"))?;
    let main_url = http_url(root.get("url").and_then(Value::as_str).unwrap_or(""))?;
    let main_origin =
        origin(&main_url).ok_or_else(|| unsupported_failure("target URL has no HTTP(S) origin"))?;
    if !allowed.is_empty() && !allowed.iter().any(|value| *value == main_origin) {
        return Err(denied_failure());
    }
    let mut frames = BTreeMap::new();
    collect_frames(tree.get("frameTree"), allowed, &mut frames);
    Ok(FrameSnapshot {
        main_url,
        main_origin,
        main_loader_id: root
            .get("loaderId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        frames,
    })
}

fn collect_frames(
    value: Option<&Value>,
    allowed: &[&str],
    frames: &mut BTreeMap<String, FrameInfo>,
) {
    let Some(tree) = value.and_then(Value::as_object) else {
        return;
    };
    if let Some(frame) = tree.get("frame").and_then(Value::as_object) {
        if let (Some(id), Some(url)) = (
            frame.get("id").and_then(Value::as_str),
            frame.get("url").and_then(Value::as_str),
        ) {
            if let Ok(url) = http_url(url) {
                if let Some(origin) = origin(&url) {
                    if allowed.is_empty() || allowed.iter().any(|item| *item == origin) {
                        frames.insert(id.to_owned(), FrameInfo { url, origin });
                    }
                }
            }
        }
    }
    if let Some(children) = tree.get("childFrames").and_then(Value::as_array) {
        for child in children {
            collect_frames(Some(child), allowed, frames);
        }
    }
}

fn ingest_events(
    tools: &mut BTreeMap<String, Value>,
    frames: &BTreeMap<String, FrameInfo>,
    allowed: &[&str],
    completeness: &mut Completeness,
    batch: CdpEventBatch,
) {
    completeness.dropped = completeness.dropped.saturating_add(batch.dropped);
    for event in batch.items {
        let Some(method) = event.value.get("method").and_then(Value::as_str) else {
            continue;
        };
        let Some(params) = event.value.get("params").and_then(Value::as_object) else {
            if method == "WebMCP.toolsAdded" || method == "WebMCP.toolsRemoved" {
                completeness.invalid += 1;
            }
            continue;
        };
        let Some(items) = params.get("tools").and_then(Value::as_array) else {
            if method == "WebMCP.toolsAdded" || method == "WebMCP.toolsRemoved" {
                completeness.invalid += 1;
            }
            continue;
        };
        for item in items {
            let Some(tool) = item.as_object() else {
                completeness.invalid += 1;
                continue;
            };
            let Some(frame_id) = tool.get("frameId").and_then(Value::as_str) else {
                completeness.invalid += 1;
                continue;
            };
            let Some(name) = tool.get("name").and_then(Value::as_str) else {
                completeness.invalid += 1;
                continue;
            };
            if method == "WebMCP.toolsRemoved" {
                tools.retain(|_, value| {
                    value.get("name").and_then(Value::as_str) != Some(name)
                        || value.get("frame_id").and_then(Value::as_str) != Some(frame_id)
                });
                continue;
            }
            let Some(frame) = frames.get(frame_id) else {
                completeness.out_of_scope += 1;
                continue;
            };
            if !allowed.is_empty() && !allowed.iter().any(|origin| *origin == frame.origin) {
                completeness.out_of_scope += 1;
                continue;
            }
            let input_schema = tool
                .get("inputSchema")
                .filter(|value| {
                    value.is_object()
                        || value.is_array()
                        || value.is_string()
                        || value.is_number()
                        || value.is_boolean()
                        || value.is_null()
                })
                .cloned();
            let schema_digest = input_schema
                .as_ref()
                .and_then(|value| rea_core::canonical_json::digest(value).ok())
                .map(|digest| format!("{digest}"));
            let annotations = annotation_value(tool.get("annotations"), completeness);
            let source = registration_source(tool.get("stackTrace"), allowed, completeness);
            let key = tool_key(&frame.url, frame_id, name);
            tools.insert(key.clone(), serde_json::json!({
                "tool_key": key, "name": name,
                "description": tool.get("description").and_then(Value::as_str).unwrap_or(""),
                "frame_id": frame_id, "frame_url": frame.url, "owner_origin": frame.origin,
                "declaration_kind": if tool.get("backendNodeId").and_then(Value::as_u64).is_some() { "declarative" } else { "imperative" },
                "input_schema": input_schema,
                "input_schema_sha256": schema_digest,
                "annotations": annotations,
                "registration_source": source,
                "trust": "page-declared-untrusted"
            }));
        }
    }
}

fn annotation_value(value: Option<&Value>, completeness: &mut Completeness) -> Value {
    let Some(object) = value.and_then(Value::as_object) else {
        if value.is_some() {
            completeness.invalid += 1;
            return serde_json::json!({
                "read_only": null,
                "untrusted_content": null,
                "autosubmit": null
            });
        }
        return serde_json::json!({
            "read_only": null,
            "untrusted_content": null,
            "consequential": null,
            "autosubmit": null
        });
    };
    let read = |key: &str, completeness: &mut Completeness| -> Value {
        match object.get(key) {
            Some(Value::Bool(value)) => Value::Bool(*value),
            Some(_) => {
                completeness.invalid += 1;
                Value::Null
            }
            None => Value::Null,
        }
    };
    let consequential = object.get("consequential");
    let mut annotations = serde_json::Map::from_iter([
        ("read_only".to_owned(), read("readOnly", completeness)),
        (
            "untrusted_content".to_owned(),
            read("untrustedContent", completeness),
        ),
        ("autosubmit".to_owned(), read("autosubmit", completeness)),
    ]);
    if consequential.is_none() || consequential.is_some_and(Value::is_boolean) {
        annotations.insert(
            "consequential".to_owned(),
            read("consequential", completeness),
        );
    }
    Value::Object(annotations)
}

fn registration_source(
    value: Option<&Value>,
    allowed: &[&str],
    completeness: &mut Completeness,
) -> Value {
    let Some(frame) = value
        .and_then(|value| value.get("callFrames"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_object)
    else {
        return Value::Null;
    };
    let Some(raw_url) = frame.get("url").and_then(Value::as_str) else {
        completeness.invalid += 1;
        return Value::Null;
    };
    let Ok(url) = http_url(raw_url) else {
        completeness.out_of_scope += 1;
        return Value::Null;
    };
    let Some(origin) = origin(&url) else {
        return Value::Null;
    };
    if !allowed.is_empty() && !allowed.iter().any(|item| *item == origin) {
        return Value::Null;
    }
    serde_json::json!({"url":url,"line":nonnegative_integer(frame.get("lineNumber")),"column":nonnegative_integer(frame.get("columnNumber"))})
}

fn nonnegative_integer(value: Option<&Value>) -> Value {
    Value::Number(value.and_then(Value::as_i64).unwrap_or(0).max(0).into())
}

fn tool_key(url: &str, frame_id: &str, name: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(url.as_bytes());
    digest.update([0]);
    digest.update(frame_id.as_bytes());
    digest.update([0]);
    digest.update(name.as_bytes());
    format!("webmcp_{:x}", digest.finalize())
}

fn http_url(value: &str) -> Result<String, Failure> {
    if !(value.starts_with("http://") || value.starts_with("https://")) {
        return Err(unsupported_failure("target URL has no HTTP(S) origin"));
    }
    Ok(value.to_owned())
}

fn origin(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    (!authority.is_empty()).then(|| format!("{}://{}", url.split_once("://").unwrap().0, authority))
}

fn request_required(
    transport: &mut dyn CdpWebMcpTransport,
    method: &str,
    params: Value,
) -> Result<Value, Failure> {
    transport
        .request(method, params)
        .map_err(|reason| protocol_failure(&format!("{method} failed: {reason}")))
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "protocol_error",
        "provider",
        reason.into(),
        true,
        "Retry the bounded CDP WebMCP discovery.".into(),
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
fn denied_failure() -> Failure {
    Failure::new(
        "target_not_allowed",
        "policy",
        "The selected page origin is outside the caller's allowed origins.".into(),
        false,
        "Add the exact origin to allowed_origins or select another page.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn target_changed() -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        "The selected page navigated during WebMCP discovery.".into(),
        false,
        "Retry after selecting a stable page target.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("WebMCP discovery input must be an object"))?;
    let endpoint = non_empty(object.get("cdp_endpoint"), "cdp_endpoint")?;
    validate_endpoint(endpoint)?;
    non_empty(object.get("target_id"), "target_id")?;
    validate_origins(object.get("allowed_origins"))?;
    validate_duration(object.get("observation_ms"))?;
    Ok(())
}

fn validate_endpoint(endpoint: &str) -> Result<(), Failure> {
    if let Some(authority) = endpoint.strip_prefix("http://") {
        let authority = authority.strip_suffix('/').unwrap_or(authority);
        if authority.is_empty()
            || authority.contains('/')
            || authority.contains('?')
            || authority.contains('#')
        {
            return Err(invalid("cdp_endpoint must be a bare loopback HTTP origin"));
        }
        let address = authority
            .parse::<SocketAddr>()
            .map_err(|_| invalid("cdp_endpoint must include an explicit loopback port"))?;
        if !address.ip().is_loopback() {
            return Err(invalid("cdp_endpoint must resolve to a loopback host"));
        }
        return Ok(());
    }
    let remainder = endpoint.strip_prefix("ws://").ok_or_else(|| {
        invalid("cdp_endpoint must use loopback HTTP or browser WebSocket transport")
    })?;
    if remainder.contains('?') || remainder.contains('#') || remainder.contains('@') {
        return Err(invalid(
            "cdp_endpoint must not contain credentials, query, or fragment",
        ));
    }
    let (authority, path) = remainder
        .split_once('/')
        .ok_or_else(|| invalid("browser WebSocket endpoint must include a path"))?;
    let address = authority.parse::<SocketAddr>().map_err(|_| {
        invalid("browser WebSocket endpoint must include an explicit loopback port")
    })?;
    if !address.ip().is_loopback() || !path.starts_with("devtools/browser/") {
        return Err(invalid(
            "cdp_endpoint must be a loopback browser WebSocket endpoint",
        ));
    }
    let browser_id = &path["devtools/browser/".len()..];
    if browser_id.is_empty() || browser_id.contains('/') {
        return Err(invalid(
            "browser WebSocket endpoint must contain one browser identifier",
        ));
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("WebMCP discovery result must be an object"));
    }
    Ok(result)
}

fn validate_origins(value: Option<&Value>) -> Result<(), Failure> {
    let Some(origins) = value else {
        return Ok(());
    };
    let origins = origins
        .as_array()
        .ok_or_else(|| invalid("allowed_origins must be an array"))?;
    for origin in origins {
        let origin = non_empty(Some(origin), "allowed_origins[]")?;
        let remainder = origin
            .split_once("://")
            .map(|(_, remainder)| remainder)
            .unwrap_or_default();
        if !(origin.starts_with("http://") || origin.starts_with("https://"))
            || remainder.is_empty()
            || remainder.contains('/')
            || remainder.contains('?')
            || remainder.contains('#')
        {
            return Err(invalid(
                "allowed_origins must contain exact HTTP(S) origins",
            ));
        }
    }
    Ok(())
}

fn validate_duration(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let duration = value
        .as_u64()
        .ok_or_else(|| invalid("observation_ms must be a non-negative integer"))?;
    if duration > 2_147_483_647 {
        return Err(invalid("observation_ms exceeds the supported deadline"));
    }
    Ok(())
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
        "Provide a caller-selected CDP page, an optional exact-origin scope, and a bounded passive WebMCP discovery window.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::cdp_transport::CdpEvent;
    use std::{
        collections::VecDeque,
        sync::{Arc, Mutex},
        time::Duration,
    };

    struct CancellableTransport {
        methods: Arc<Mutex<Vec<String>>>,
    }

    impl CdpWebMcpTransport for CancellableTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            self.methods
                .lock()
                .expect("method lock")
                .push(method.to_owned());
            match method {
                "Page.getFrameTree" => Ok(serde_json::json!({
                    "frameTree":{"frame":{
                        "id":"frame-1",
                        "loaderId":"loader-1",
                        "url":"https://app.example.test/"
                    }}
                })),
                "Browser.getVersion" => Ok(serde_json::json!({
                    "product":"MockChrome/1",
                    "protocolVersion":"1.3",
                    "revision":"mock-revision",
                    "userAgent":"MockChrome",
                    "jsVersion":"mock-js"
                })),
                _ => Ok(serde_json::json!({})),
            }
        }

        fn drain_events(&mut self) -> CdpEventBatch {
            CdpEventBatch::default()
        }
    }

    struct EventTransport {
        frames: VecDeque<Value>,
        events: VecDeque<CdpEventBatch>,
    }

    impl CdpWebMcpTransport for EventTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            match method {
                "Page.getFrameTree" => self
                    .frames
                    .pop_front()
                    .ok_or_else(|| "frame tree exhausted".to_owned()),
                "Browser.getVersion" => Ok(serde_json::json!({"product":"MockChrome/1"})),
                _ => Ok(serde_json::json!({})),
            }
        }

        fn drain_events(&mut self) -> CdpEventBatch {
            self.events.pop_front().unwrap_or_default()
        }
    }

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": ["https://app.example.test"],
            "target_id": "page-1",
            "observation_ms": 100
        })
    }

    #[test]
    fn accepts_bounded_discovery() {
        validate_input(&input()).expect("valid WebMCP discovery input");
        assert!(retain_result(&input(), serde_json::json!({"tools": []})).is_ok());
    }

    #[test]
    fn rejects_missing_target() {
        let mut invalid_input = input();
        invalid_input["target_id"] = serde_json::json!("");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn accepts_browser_level_ipv4_websocket_endpoint() {
        let mut request = input();
        request["cdp_endpoint"] =
            serde_json::json!("ws://127.0.0.1:9222/devtools/browser/browser-id");
        validate_input(&request).expect("valid browser-level WebSocket endpoint");
    }

    #[test]
    fn accepts_browser_level_ipv6_websocket_endpoint() {
        let mut request = input();
        request["cdp_endpoint"] = serde_json::json!("ws://[::1]:9222/devtools/browser/browser-id");
        validate_input(&request).expect("valid IPv6 browser-level WebSocket endpoint");
    }

    #[test]
    fn rejects_browser_level_external_websocket_endpoint() {
        let mut request = input();
        request["cdp_endpoint"] =
            serde_json::json!("ws://192.0.2.1:9222/devtools/browser/browser-id");
        assert!(validate_input(&request).is_err());
    }

    #[test]
    fn rejects_unbounded_window() {
        let mut invalid_input = input();
        invalid_input["observation_ms"] = serde_json::json!(2_147_483_648_u64);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_non_object_result() {
        assert!(retain_result(&input(), serde_json::json!([])).is_err());
    }

    #[test]
    fn cancellation_interrupts_the_observation_window_before_final_revalidation() {
        let cancellation = Cancellation::default();
        let trigger = cancellation.clone();
        let cancel_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            trigger.cancel("test cancellation");
        });
        let methods = Arc::new(Mutex::new(Vec::new()));
        let mut transport = CancellableTransport {
            methods: methods.clone(),
        };
        let mut request = input();
        request["observation_ms"] = serde_json::json!(60_000);

        let result =
            discover_with_cancellation(&request, &mut transport, "started", "ended", &cancellation);
        cancel_thread.join().expect("cancellation thread");

        let failure = result.expect_err("cancelled observation");
        assert_eq!(failure.code(), "cancelled");
        let observed_frame_tree_requests = methods
            .lock()
            .expect("method lock")
            .iter()
            .filter(|method| method.as_str() == "Page.getFrameTree")
            .count();
        assert!(
            observed_frame_tree_requests < 2,
            "the final frame tree must not be requested after cancellation"
        );
    }

    #[test]
    fn discovers_added_tool_and_preserves_unknown_malformed_annotation() {
        let frame_tree = serde_json::json!({
            "frameTree":{"frame":{
                "id":"frame-1",
                "loaderId":"loader-1",
                "url":"https://app.example.test/"
            }}
        });
        let event = serde_json::json!({
            "method":"WebMCP.toolsAdded",
            "params":{"tools":[{
                "frameId":"frame-1",
                "name":"search",
                "description":"Search",
                "inputSchema":{"type":"object"},
                "annotations":{"consequential":"unknown"}
            }]}
        });
        let mut transport = EventTransport {
            frames: VecDeque::from([frame_tree.clone(), frame_tree]),
            events: VecDeque::from([
                CdpEventBatch::default(),
                CdpEventBatch {
                    items: vec![CdpEvent {
                        sequence: 1,
                        value: event,
                    }],
                    ..CdpEventBatch::default()
                },
            ]),
        };

        let result = discover(&input(), &mut transport, "started", "ended")
            .expect("WebMCP event should produce a retained tool");
        let tool = &result["tools"]["items"][0];
        assert_eq!(tool["name"], "search");
        assert!(tool["annotations"].get("consequential").is_none());
        assert_eq!(result["status"], "available");
    }
}
