//! Contract boundary for finite passive web execution observation.

use rea_core::canonical_json;
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "observe_web_execution";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web execution input must be an object"))?;
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "cdp_endpoint" | "allowed_origins" | "target_id" | "observation_ms"
        ) {
            return Err(invalid(&format!(
                "unknown web execution input field: {field}"
            )));
        }
    }
    let endpoint = object
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .filter(|endpoint| !endpoint.is_empty())
        .ok_or_else(|| invalid("cdp_endpoint must be a non-empty string"))?;
    validate_loopback_endpoint(endpoint)?;
    non_empty(object.get("target_id"), "target_id")?;

    if let Some(origins) = object.get("allowed_origins") {
        let origins = origins
            .as_array()
            .ok_or_else(|| invalid("allowed_origins must be an array"))?;
        for origin in origins {
            let origin = origin
                .as_str()
                .ok_or_else(|| invalid("allowed_origins entries must be strings"))?;
            validate_origin(origin)?;
        }
    }

    if let Some(duration) = object.get("observation_ms") {
        let duration = duration
            .as_u64()
            .ok_or_else(|| invalid("observation_ms must be a positive integer"))?;
        if duration == 0 || duration > 2_147_483_647 {
            return Err(invalid("observation_ms must be between 1 and 2147483647"));
        }
    }
    Ok(())
}

fn validate_loopback_endpoint(endpoint: &str) -> Result<(), Failure> {
    let authority = endpoint
        .strip_prefix("http://")
        .ok_or_else(|| invalid("cdp_endpoint must use HTTP"))?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
    {
        return Err(invalid(
            "cdp_endpoint must be an explicit-port loopback URL",
        ));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .ok_or_else(|| invalid("cdp_endpoint must include an explicit port"))?;
    let valid_host = host == "127.0.0.1" || host == "[::1]";
    if !valid_host || port.is_empty() || !port.chars().all(|character| character.is_ascii_digit()) {
        return Err(invalid(
            "cdp_endpoint must target 127.0.0.1 or ::1 with an explicit port",
        ));
    }
    Ok(())
}

fn validate_origin(origin: &str) -> Result<(), Failure> {
    let authority = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .ok_or_else(|| invalid("allowed_origins entries must use HTTP or HTTPS"))?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.contains('*')
    {
        return Err(invalid(
            "allowed_origins entries must be exact HTTP(S) origins",
        ));
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("web execution result must be an object"));
    }
    validate_selected_identity(input, &result)?;
    Ok(result)
}

/// Preserve the caller's selected target and bounded observation window when
/// a live or retained producer reports those facts.
///
/// Some derived projections intentionally omit the producer target and window;
/// omission remains unknown rather than being treated as a mismatch. Once a
/// producer supplies either fact, however, the application boundary owns the
/// comparison so individual adapters cannot silently substitute another page
/// or duration.
fn validate_selected_identity(input: &Value, result: &Value) -> Result<(), Failure> {
    if let Some(target_id) = result.pointer("/target/target_id") {
        if target_id.as_str() != input.get("target_id").and_then(Value::as_str) {
            return Err(target_mismatch());
        }
    }

    if let Some(requested_ms) = result.pointer("/window/requested_ms") {
        let requested_input_ms = input
            .get("observation_ms")
            .and_then(Value::as_u64)
            .unwrap_or(10_000);
        if requested_ms.as_u64() != Some(requested_input_ms) {
            return Err(window_mismatch());
        }
    }

    Ok(())
}

/// Project a retained, read-only browser capture into execution observations.
///
/// The capture producer owns browser event parsing. This projection only keeps
/// events that were actually supplied, attaches the exact source Evidence ID,
/// and reports causality as unknown unless the source explicitly observed it.
pub fn observe(input: &Value, source: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let source = Source::parse(source).map_err(|error| error.into_failure())?;
    project_source(&source).map_err(|reason| invalid(&reason))
}

/// Accept the adapter shape used by Evidence-consuming application workflows.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web execution projection input must be an object"))?;
    let source = object
        .get("browser_capture")
        .or_else(|| object.get("browser_evidence"))
        .or_else(|| object.get("capture"))
        .ok_or_else(|| invalid("web execution projection requires browser capture Evidence"))?;
    observe(
        &json!({
            "cdp_endpoint": "http://127.0.0.1:1",
            "target_id": "projection"
        }),
        source,
    )
}

/// Create unsigned derived Evidence linked to the exact browser source record.
pub fn project_evidence(input: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let result = project(input)?;
    let source = input
        .get("browser_capture")
        .or_else(|| input.get("browser_evidence"))
        .or_else(|| input.get("capture"))
        .expect("project validated source");
    let source_id = source
        .get("evidence_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("browser capture Evidence must include evidence_id"))?;
    let limitations = result
        .get("limitations")
        .cloned()
        .unwrap_or_else(|| json!([]));
    let unsigned = json!({
        "subject": null,
        "provider": {"id": "rea-web-execution", "name": "REA web execution projection", "version": "1"},
        "analysis_profile": null,
        "predicate_type": "rea.observe-web-execution",
        "operation": OPERATION,
        "parameters": {"source_evidence_id": source_id},
        "raw_result": null,
        "normalized_result": result,
        "confidence": "inferred",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": limitations,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": [source_id]
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| invalid(&format!("cannot encode projected Evidence: {error}")))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| invalid(&format!("cannot create projected Evidence: {error}")))?;
    Ok(
        serde_json::value::RawValue::from_string(evidence.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
}

struct Source<'a> {
    result: &'a Value,
    evidence_id: &'a str,
}

impl<'a> Source<'a> {
    fn parse(evidence: &'a Value) -> Result<Self, ProjectionError> {
        let object = evidence.as_object().ok_or_else(|| {
            ProjectionError::Invalid("browser capture Evidence must be an object".into())
        })?;
        let evidence_id = object
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                ProjectionError::Invalid("browser capture Evidence must include evidence_id".into())
            })?;
        let result = object
            .get("normalized_result")
            .or_else(|| object.get("result"))
            .ok_or_else(|| {
                ProjectionError::Invalid("browser capture Evidence has no normalized_result".into())
            })?;
        if !result.is_object() {
            return Err(ProjectionError::Invalid(
                "browser capture normalized_result must be an object".into(),
            ));
        }
        Ok(Self {
            result,
            evidence_id,
        })
    }
}

fn project_source(source: &Source<'_>) -> Result<Value, String> {
    let mut events = execution_events(source.result, source.evidence_id);
    let mut causality = Vec::with_capacity(events.len());
    for event in &mut events {
        let event_id = event
            .get("event_id")
            .or_else(|| event.get("request_id"))
            .cloned()
            .unwrap_or(Value::Null);
        let attribution = event
            .get("causal_attribution")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned();
        event["causal_attribution"] = Value::String(attribution.clone());
        causality.push(json!({
            "event_id": event_id,
            "status": if attribution == "unknown" { "unknown" } else { "reported" },
            "source_evidence_id": source.evidence_id
        }));
    }

    let partial = source
        .result
        .pointer("/events/dropped")
        .and_then(Value::as_u64)
        .is_some_and(|count| count > 0)
        || source
            .result
            .pointer("/completeness/truncated_sections")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty());
    let mut limitations = source
        .result
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    limitations.push("Execution events are projected from supplied browser capture Evidence; omitted event families remain unknown.".into());
    limitations.push(
        "Receipt order, timestamps, and reported initiators do not establish execution causality."
            .into(),
    );

    let projection_id = canonical_json::digest(
        &json!({"source_evidence_id": source.evidence_id, "events": events}),
    )
    .map_err(|error| error.to_string())?;
    Ok(json!({
        "projection_id": format!("wex_{projection_id}"),
        "source_evidence_ids": [source.evidence_id],
        "execution_events": events,
        "causality": causality,
        "coverage": {"status": if partial { "partial" } else { "complete-within-inputs" }, "unknown_dimensions": ["causality"]},
        "limitations": limitations,
        "evidence_links": [source.evidence_id]
    }))
}

fn execution_events(result: &Value, evidence_id: &str) -> Vec<Value> {
    let values = result
        .pointer("/events/items")
        .and_then(Value::as_array)
        .or_else(|| result.get("requests").and_then(Value::as_array))
        .cloned()
        .unwrap_or_default();
    values
        .into_iter()
        .map(|mut event| {
            if let Some(object) = event.as_object_mut() {
                object.insert(
                    "source_evidence_id".into(),
                    Value::String(evidence_id.to_owned()),
                );
            }
            event
        })
        .collect()
}

#[derive(Debug)]
enum ProjectionError {
    Invalid(String),
    EvidenceIntegrity(String),
}

impl ProjectionError {
    fn into_failure(self) -> Failure {
        match self {
            Self::Invalid(reason) => invalid(&reason),
            Self::EvidenceIntegrity(reason) => Failure::new(
                "evidence_integrity_mismatch",
                "integrity_mismatch",
                reason,
                false,
                "Supply unchanged authenticated browser capture Evidence.".into(),
                BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
            ),
        }
    }
}

impl From<EvidenceRecordError> for ProjectionError {
    fn from(error: EvidenceRecordError) -> Self {
        let reason = error.to_string();
        match error {
            EvidenceRecordError::SemanticIdMismatch => Self::EvidenceIntegrity(reason),
            _ => Self::Invalid(reason),
        }
    }
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
        "Provide a caller-selected CDP page and a bounded passive observation window.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn target_mismatch() -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        "the retained execution result differs from the caller-selected target".into(),
        false,
        "Supply a capture produced for the selected web target.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}

fn window_mismatch() -> Failure {
    Failure::new(
        "output_error",
        "output_error",
        "the retained execution result differs from the requested observation window".into(),
        false,
        "Supply a capture produced for the requested observation window.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "allowed_origins": [],
            "target_id": "TARGET_ID",
            "observation_ms": 10000
        })
    }

    #[test]
    fn accepts_bounded_observation_window() {
        validate_input(&input()).expect("valid web execution input");
        assert!(retain_result(&input(), serde_json::json!({"coverage": {}})).is_ok());
    }

    #[test]
    fn rejects_zero_duration() {
        let mut invalid_input = input();
        invalid_input["observation_ms"] = serde_json::json!(0);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_duration_above_i32_limit() {
        let mut invalid_input = input();
        invalid_input["observation_ms"] = serde_json::json!(2147483648_u64);
        assert!(validate_input(&invalid_input).is_err());
    }

    fn source_evidence() -> Value {
        serde_json::json!({
            "evidence_id": "ev_browser_capture",
            "operation": "capture_browser_scenario",
            "normalized_result": {
                "events": {
                    "items": [
                        {"event_id": "request-1", "kind": "network", "timestamp": 1.0}
                    ],
                    "dropped": 0
                },
                "limitations": []
            }
        })
    }

    #[test]
    fn projects_events_with_exact_source_reference_and_unknown_causality() {
        let result = observe(&input(), &source_evidence()).expect("projection succeeds");
        assert_eq!(
            result["source_evidence_ids"],
            serde_json::json!(["ev_browser_capture"])
        );
        assert_eq!(
            result["execution_events"][0]["source_evidence_id"],
            "ev_browser_capture"
        );
        assert_eq!(
            result["execution_events"][0]["causal_attribution"],
            "unknown"
        );
        assert_eq!(result["causality"][0]["status"], "unknown");
    }

    #[test]
    fn omitted_event_families_remain_unknown_when_capture_has_no_events() {
        let mut source = source_evidence();
        source["normalized_result"] = serde_json::json!({"limitations": []});
        let result = observe(&input(), &source).expect("empty projection succeeds");
        assert_eq!(result["execution_events"], serde_json::json!([]));
        assert_eq!(
            result["coverage"]["unknown_dimensions"],
            serde_json::json!(["causality"])
        );
    }

    #[test]
    fn rejects_capture_without_evidence_identity() {
        let mut source = source_evidence();
        source
            .as_object_mut()
            .expect("object")
            .remove("evidence_id");
        let error = observe(&input(), &source).expect_err("identity is required");
        assert_eq!(error.code(), "invalid_request");
    }
}
