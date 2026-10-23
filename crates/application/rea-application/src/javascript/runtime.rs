//! Boundary validation for passive Node/Electron V8 Inspector workflows.

use rea_core::cancellation::Cancellation;
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::CdpEventBatch;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::thread;
use std::time::{Duration, Instant};

pub const LIST_OPERATION: &str = "list_javascript_runtime_targets";
pub const OBSERVE_OPERATION: &str = "observe_javascript_runtime";

/// Transport boundary for a caller-selected V8 Inspector target.
///
/// Discovery and socket ownership stay in the runtime adapter. This trait
/// keeps event interpretation in the application layer and makes it possible
/// to retain partial observations when a bounded capture is cancelled.
pub trait InspectorTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String>;

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpEventBatch::default()
    }
}

/// Observe one already-authorized target without evaluating or pausing it.
pub fn observe_connected<T: InspectorTransport>(
    input: &Value,
    runtime: &Value,
    target: &Value,
    transport: &mut T,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    validate_observe_input(input)?;
    let target_id = input["target_id"].as_str().expect("validated target_id");
    if target.get("target_id").and_then(Value::as_str) != Some(target_id) {
        return Err(invalid(OBSERVE_OPERATION, "selected target changed"));
    }

    request(transport, "Runtime.enable", cancellation)?;
    request(transport, "Debugger.enable", cancellation)?;

    let observation_ms = input
        .get("observation_ms")
        .and_then(Value::as_u64)
        .unwrap_or(100);
    let started = Instant::now();
    let mut capture = Capture::default();
    while started.elapsed() < Duration::from_millis(observation_ms) {
        check_cancel(cancellation)?;
        let batch = transport.drain_events();
        capture.ingest(batch);
        thread::sleep(
            Duration::from_millis(10)
                .min(Duration::from_millis(observation_ms).saturating_sub(started.elapsed())),
        );
    }
    capture.ingest(transport.drain_events());
    check_cancel(cancellation)?;

    Ok(capture.project(input, runtime, target, observation_ms))
}

fn request<T: InspectorTransport>(
    transport: &mut T,
    method: &str,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    check_cancel(cancellation)?;
    transport
        .request(method, Value::Object(Map::new()))
        .map_err(|reason| invalid(OBSERVE_OPERATION, &format!("{method} failed: {reason}")))
}

fn check_cancel(cancellation: &Cancellation) -> Result<(), Failure> {
    cancellation.reason().map_or(Ok(()), |reason| {
        Err(Failure::new(
            "cancelled",
            "cancelled",
            reason.to_owned(),
            false,
            "Retry the bounded Inspector observation when the target is available.".into(),
            BTreeMap::from([("operation", Detail::Text(OBSERVE_OPERATION.into()))]),
        ))
    })
}

#[derive(Default)]
struct Capture {
    scripts: Vec<Value>,
    contexts: Vec<Value>,
    events_observed: u64,
    events_retained: u64,
    events_dropped: u64,
}

impl Capture {
    fn ingest(&mut self, batch: CdpEventBatch) {
        self.events_dropped = self.events_dropped.saturating_add(batch.dropped);
        for event in batch.items {
            let method = event.value.get("method").and_then(Value::as_str);
            let params = event.value.get("params").cloned().unwrap_or(Value::Null);
            if !matches!(
                method,
                Some("Debugger.scriptParsed")
                    | Some("Runtime.executionContextCreated")
                    | Some("Runtime.executionContextDestroyed")
                    | Some("Runtime.executionContextsCleared")
            ) {
                continue;
            }
            self.events_observed = self.events_observed.saturating_add(1);
            if method == Some("Debugger.scriptParsed") {
                self.scripts.push(params);
            } else {
                self.contexts.push(params);
            }
            self.events_retained = self.events_retained.saturating_add(1);
        }
    }

    fn project(
        &self,
        input: &Value,
        runtime: &Value,
        target: &Value,
        observation_ms: u64,
    ) -> Value {
        let scripts = self
            .scripts
            .iter()
            .filter_map(project_script)
            .collect::<Vec<_>>();
        let contexts = self
            .contexts
            .iter()
            .filter_map(project_context)
            .collect::<Vec<_>>();
        let runtime = runtime_projection(runtime);
        let target = target_projection(target, input);
        serde_json::json!({
            "runtime": runtime,
            "target": target,
            "capture": {
                "observation_ms": observation_ms,
                "events_observed": self.events_observed,
                "events_retained": self.events_retained,
                "events_dropped": self.events_dropped,
                "metadata_bytes_retained": 0,
                "truncated": self.events_dropped > 0,
                "truncation_reasons": if self.events_dropped > 0 { vec!["Inspector event buffer dropped events." ] } else { Vec::new() },
            },
            "scripts": {"items": scripts, "observed_total": self.scripts.len(), "excluded": {"unsupported_location": 0, "invalid_protocol_value": 0}},
            "execution_contexts": contexts,
            "directly_observed": ["Debugger.scriptParsed and Runtime execution-context events were observed without evaluating target code."],
            "unavailable_without_instrumentation": ["Require/import edges, EventEmitter activity, and Electron IPC remain unavailable."],
            "unknowns": ["Runtime host platform and architecture were not observed."],
            "limitations": ["REA never evaluates, pauses, resumes, or instruments the selected target."]
        })
    }
}

fn runtime_projection(runtime: &Value) -> Value {
    serde_json::json!({
        "product": runtime.get("product").and_then(Value::as_str).unwrap_or("unknown"),
        "protocol_version": runtime.get("protocol_version").and_then(Value::as_str).unwrap_or("unknown"),
        "v8_version": runtime.get("v8_version").cloned().unwrap_or(Value::Null),
    })
}

fn target_projection(target: &Value, input: &Value) -> Value {
    serde_json::json!({
        "target_id": target.get("target_id").and_then(Value::as_str).unwrap_or("unknown"),
        "protocol_type": target.get("protocol_type").and_then(Value::as_str).unwrap_or("unknown"),
        "attached": target.get("attached").cloned().unwrap_or(Value::Null),
        "location": target.get("location").cloned().unwrap_or_else(|| serde_json::json!({"kind":"unresolved", "reported_url":"", "reason":"location-authorization-not-attempted"})),
        "runtime_kind": input.get("runtime_kind").cloned().unwrap_or_else(|| Value::String("unknown".into())),
        "runtime_kind_authority": if input.get("runtime_kind").is_some() { "caller-declared-unverified" } else { "not-declared" },
    })
}

fn project_script(params: &Value) -> Option<Value> {
    let url = params.get("url").and_then(Value::as_str)?;
    let stable = serde_json::to_string(params).ok()?;
    let digest = format!("v8_script_{}", hex_digest(stable.as_bytes()));
    Some(serde_json::json!({
        "script_key": digest,
        "location": {"kind":"url", "origin": url, "sanitized_url": url},
        "execution_context_key": params.get("executionContextId").map(|v| v.to_string()),
        "cdp_hash": params.get("hash").and_then(Value::as_str),
        "length": params.get("length").and_then(Value::as_u64),
        "is_module": params.get("isLiveEdit").and_then(Value::as_bool),
        "status": "observed-loaded"
    }))
}

fn project_context(params: &Value) -> Option<Value> {
    let context = params.get("context")?;
    let id = context.get("id").and_then(Value::as_u64)?;
    Some(
        serde_json::json!({"context_key": format!("v8_context_{id}"), "state":"created", "name": context.get("name").and_then(Value::as_str), "origin": context.get("origin").and_then(Value::as_str)}),
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_endpoint(endpoint: &str, operation: &str) -> Result<(), Failure> {
    let Some((scheme, remainder)) = endpoint.split_once("://") else {
        return Err(invalid(operation, "Inspector endpoint must be an HTTP URL"));
    };
    if scheme != "http" || remainder.contains(['?', '#']) {
        return Err(invalid(
            operation,
            "Inspector endpoint must be an explicit-port loopback URL",
        ));
    }

    let authority = remainder.strip_suffix('/').unwrap_or(remainder);
    let Some((host, port)) = authority.rsplit_once(':') else {
        return Err(invalid(
            operation,
            "Inspector endpoint must include an explicit port",
        ));
    };
    if !matches!(host, "127.0.0.1" | "[::1]" | "::1")
        || port.is_empty()
        || port.parse::<u16>().is_err()
        || authority.contains('/')
    {
        return Err(invalid(
            operation,
            "Inspector endpoint must be an explicit-port loopback URL",
        ));
    }
    Ok(())
}

pub fn validate_list_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(LIST_OPERATION, "input must be an object"))?;
    reject_unknown_fields(object, &["inspector_endpoint"], LIST_OPERATION)?;
    let endpoint = object
        .get("inspector_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(LIST_OPERATION, "inspector_endpoint is required"))?;
    validate_endpoint(endpoint, LIST_OPERATION)
}

pub fn validate_observe_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(OBSERVE_OPERATION, "input must be an object"))?;
    reject_unknown_fields(
        object,
        &[
            "inspector_endpoint",
            "target_id",
            "runtime_kind",
            "observation_ms",
        ],
        OBSERVE_OPERATION,
    )?;
    let endpoint = object
        .get("inspector_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(OBSERVE_OPERATION, "inspector_endpoint is required"))?;
    validate_endpoint(endpoint, OBSERVE_OPERATION)?;

    let target = object
        .get("target_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid(OBSERVE_OPERATION, "target_id is required"))?;
    if target.contains('\0') {
        return Err(invalid(
            OBSERVE_OPERATION,
            "target_id must not contain NUL bytes",
        ));
    }
    if let Some(kind) = object.get("runtime_kind") {
        let kind = kind
            .as_str()
            .ok_or_else(|| invalid(OBSERVE_OPERATION, "runtime_kind is unsupported"))?;
        if !matches!(
            kind,
            "node" | "electron-main" | "electron-preload" | "electron-renderer"
        ) {
            return Err(invalid(OBSERVE_OPERATION, "runtime_kind is unsupported"));
        }
    }

    if let Some(observation_ms) = object.get("observation_ms") {
        let valid = observation_ms
            .as_f64()
            .is_some_and(|value| value.is_finite() && value >= 0.0 && value.fract() == 0.0);
        if !valid {
            return Err(invalid(
                OBSERVE_OPERATION,
                "observation_ms must be a non-negative integer",
            ));
        }
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    operation: &str,
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(operation, "input contains an unknown field"));
    }
    Ok(())
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Select an explicit-port loopback Inspector endpoint and target.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_loopback_listing_and_observation_inputs() {
        validate_list_input(&serde_json::json!({"inspector_endpoint": "http://127.0.0.1:9229"}))
            .expect("loopback endpoint is accepted");
        validate_observe_input(&serde_json::json!({
            "inspector_endpoint": "http://[::1]:9229",
            "target_id": "target",
            "runtime_kind": "electron-main",
            "observation_ms": 100
        }))
        .expect("runtime target is accepted");
    }

    #[test]
    fn rejects_non_loopback_and_unknown_runtime_kind() {
        assert!(
            validate_list_input(&serde_json::json!({
                "inspector_endpoint": "http://example.test:9229"
            }))
            .is_err()
        );
        assert!(
            validate_observe_input(&serde_json::json!({
                "inspector_endpoint": "http://127.0.0.1:9229",
                "target_id": "target",
                "runtime_kind": "browser"
            }))
            .is_err()
        );
    }

    #[test]
    fn accepts_normalized_endpoint_and_rejects_unknown_or_invalid_fields() {
        validate_list_input(&serde_json::json!({
            "inspector_endpoint": "http://127.0.0.1:9229/"
        }))
        .expect("URL parser accepts the canonical root path");
        assert!(
            validate_list_input(&serde_json::json!({
                "inspector_endpoint": "http://127.0.0.1:9229",
                "extra": true
            }))
            .is_err()
        );
        assert!(
            validate_observe_input(&serde_json::json!({
                "inspector_endpoint": "http://127.0.0.1:9229",
                "target_id": "target",
                "observation_ms": -1
            }))
            .is_err()
        );
    }
}
