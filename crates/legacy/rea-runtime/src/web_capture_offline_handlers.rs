//! Offline projections for retained browser observations.
//!
//! The live CDP producers remain the owners of capture, parsing, and browser
//! lifecycle. This module accepts only their completed JSON output or an
//! Evidence envelope and never opens a target, executes page code, or uses a
//! network transport. Screenshot capture is intentionally absent because its
//! producer still owns a live viewport.

use rea_application::web;
use rea_core::cancellation::Cancellation;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json, value::to_raw_value};
use std::collections::BTreeMap;

/// Run the live navigation observation producer for a caller-selected page.
///
/// Endpoint discovery remains an adapter concern. The caller passes the
/// already validated page WebSocket URL so this handler cannot silently select
/// another target or acquire browser-level authority.
pub fn observe_live(
    input: &Value,
    websocket_endpoint: &str,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    web::session_observation::validate_input(input)?;

    let target_id = input
        .get("target_id")
        .and_then(Value::as_str)
        .expect("validated target_id");
    let mut port = web::session_observation::ConnectedCdpWebSessionPort::connect(
        websocket_endpoint,
        target_id,
    )
    .map_err(|error| live_connection_failure(&error.to_string()))?;

    port.observe(input, cancellation)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    InspectPage,
    InspectEventListeners,
    ObserveExecution,
    ObserveSession,
    DiscoverWebMcpTools,
    CompareCaptures,
}

impl Operation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "inspect_web_page" => Ok(Self::InspectPage),
            "inspect_web_event_listeners" => Ok(Self::InspectEventListeners),
            "observe_web_execution" => Ok(Self::ObserveExecution),
            "observe_web_session" => Ok(Self::ObserveSession),
            "discover_webmcp_tools" => Ok(Self::DiscoverWebMcpTools),
            "compare_web_captures" => Ok(Self::CompareCaptures),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectPage => "inspect_web_page",
            Self::InspectEventListeners => "inspect_web_event_listeners",
            Self::ObserveExecution => "observe_web_execution",
            Self::ObserveSession => "observe_web_session",
            Self::DiscoverWebMcpTools => "discover_webmcp_tools",
            Self::CompareCaptures => "compare_web_captures",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputAuthority {
    Capture,
    Evidence,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Contract {
    pub operation: &'static str,
    pub authority: InputAuthority,
}

pub const CONTRACTS: [Contract; 6] = [
    Contract {
        operation: "inspect_web_page",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "inspect_web_event_listeners",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "observe_web_execution",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "observe_web_session",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "discover_webmcp_tools",
        authority: InputAuthority::Capture,
    },
    Contract {
        operation: "compare_web_captures",
        authority: InputAuthority::Capture,
    },
];

pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    dispatch_typed(Operation::parse(operation)?, &input)
}

pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Operation::CompareCaptures => compare_captures(input),
        _ => retain_capture(operation, input),
    }
}

fn retain_capture(operation: Operation, input: &Value) -> Result<Value, Failure> {
    let object = object_input(operation, input)?;
    require_only(object, &["capture"], operation)?;
    let capture = object_value(object, "capture", operation)?;
    validate_operation_provenance(operation, capture)?;
    Ok(capture.clone())
}

fn compare_captures(input: &Value) -> Result<Value, Failure> {
    let object = object_input(Operation::CompareCaptures, input)?;

    if object.contains_key("before_scenario") || object.contains_key("after_scenario") {
        require_scenario_fields(object)?;
        let result = web::capture_comparison::compare(input)?;
        return Ok(json!({ "result": result }));
    }

    require_only(object, &["before", "after"], Operation::CompareCaptures)?;
    let before = capture_result(object_value(object, "before", Operation::CompareCaptures)?)?;
    let after = capture_result(object_value(object, "after", Operation::CompareCaptures)?)?;
    let result = web::capture_comparison::compare(&json!({
        "before": before,
        "after": after,
    }))?;

    let mut output = Map::new();
    output.insert("result".into(), result);
    let mut provenance = Map::new();
    if let Some(id) = evidence_id(object.get("before").expect("validated before")) {
        provenance.insert("before_evidence_id".into(), Value::String(id));
    }
    if let Some(id) = evidence_id(object.get("after").expect("validated after")) {
        provenance.insert("after_evidence_id".into(), Value::String(id));
    }
    if !provenance.is_empty() {
        output.insert("provenance".into(), Value::Object(provenance));
    }
    Ok(Value::Object(output))
}

fn require_scenario_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "before_scenario" | "after_scenario" | "normalization"
        )
    }) {
        return Err(invalid_for(
            Operation::CompareCaptures,
            "scenario comparison accepts before_scenario, after_scenario, and normalization",
        ));
    }
    for field in ["before_scenario", "after_scenario"] {
        if !object.get(field).is_some_and(Value::is_object) {
            return Err(invalid_for(
                Operation::CompareCaptures,
                &format!("{field} must be an object"),
            ));
        }
    }
    Ok(())
}

fn capture_result(value: &Value) -> Result<Value, Failure> {
    let capture = if let Some(evidence) = value.get("evidence") {
        authenticated_capture(evidence)?
    } else if value.get("evidence_id").is_some() || value.get("operation").is_some() {
        authenticated_capture(value)?
    } else if let Some(normalized) = value.get("normalized_result") {
        normalized.clone()
    } else {
        value.clone()
    };
    if !capture.is_object() {
        return Err(invalid("capture result must be an object"));
    }
    Ok(capture)
}

fn authenticated_capture(value: &Value) -> Result<Value, Failure> {
    let raw = to_raw_value(value)
        .map_err(|error| invalid(&format!("capture Evidence is not canonical JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("capture Evidence authentication failed: {error}")))?;
    if !record.operation_matches("inspect_web_page") {
        return Err(invalid(
            "capture Evidence operation must be inspect_web_page",
        ));
    }
    serde_json::from_str(record.normalized_result().get()).map_err(|error| {
        invalid(&format!(
            "capture Evidence normalized_result is invalid: {error}"
        ))
    })
}

fn validate_operation_provenance(operation: Operation, capture: &Value) -> Result<(), Failure> {
    let expected = operation.name();
    let candidate = capture.get("operation").or_else(|| {
        capture
            .get("evidence")
            .and_then(|value| value.get("operation"))
    });
    if let Some(value) = candidate {
        if value.as_str() != Some(expected) {
            return Err(invalid(&format!("capture operation must be {expected}")));
        }
    }
    Ok(())
}

fn evidence_id(value: &Value) -> Option<String> {
    value
        .get("evidence_id")
        .or_else(|| {
            value
                .get("evidence")
                .and_then(|evidence| evidence.get("evidence_id"))
        })
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn object_input<'a>(
    operation: Operation,
    input: &'a Value,
) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid_for(operation, "offline input must be an object"))
}

fn require_only(
    object: &Map<String, Value>,
    fields: &[&str],
    operation: Operation,
) -> Result<(), Failure> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid_for(
            operation,
            "offline input contains unexpected or missing fields",
        ));
    }
    Ok(())
}

fn object_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    operation: Operation,
) -> Result<&'a Value, Failure> {
    object
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid_for(operation, &format!("{field} must be an object")))
}

fn unknown_operation(name: &str) -> Failure {
    invalid(&format!("unsupported offline web operation: {name}"))
}

fn invalid_for(operation: Operation, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide an explicit retained web capture; live CDP and screenshot capture are unsupported by this adapter.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.name().into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide an explicit retained web capture; live CDP and screenshot capture are unsupported by this adapter.".into(),
        BTreeMap::from([("authority", Detail::Text("offline_capture_only".into()))]),
    )
}

fn live_connection_failure(reason: &str) -> Failure {
    Failure::new(
        "connection_failed",
        "connection_failed",
        format!("observe_web_session could not connect to the selected page: {reason}"),
        false,
        "Retry with the caller-selected loopback CDP page target still available.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(web::session_observation::OPERATION.into()),
        )]),
    )
}
