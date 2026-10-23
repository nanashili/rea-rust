//! Offline projections for caller-supplied process evidence.
//!
//! This module deliberately has no process, procfs, ptrace, debugger, or
//! launcher authority.  Adapters pass observations that were captured by an
//! external owner; this boundary validates their envelope and preserves the
//! producer's facts, including generation identity and partial states.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OBSERVATION_OPERATION: &str = "inspect_process_observation";
pub const CMDLINE_OPERATION: &str = "inspect_process_cmdline";
pub const MEMORY_OPERATION: &str = "inspect_process_memory";
pub const CRASH_OPERATION: &str = "inspect_recorded_crash";
pub const CRASH_OFFLINE_OPERATION: &str = "inspect_recorded_crash_offline";
pub const COMPARISON_OPERATION: &str = "compare_process_captures";
pub const SCENARIO_OPERATION: &str = "capture_process_scenario";

const MAX_OBSERVATIONS: usize = 100_000;
const MAX_GENERATION_BYTES: usize = 4_096;

/// Project an already captured process observation set.
pub fn inspect_process_observation(input: &Value) -> Result<Value, Failure> {
    project_observations(input, OBSERVATION_OPERATION, "rea.process-observation")
}

/// Project already captured command-line records without reconstructing argv.
pub fn inspect_process_cmdline(input: &Value) -> Result<Value, Failure> {
    project_observations(input, CMDLINE_OPERATION, "rea.process-cmdline")
}

/// Project already captured memory ranges and bytes.
pub fn inspect_process_memory(input: &Value) -> Result<Value, Failure> {
    project_observations(input, MEMORY_OPERATION, "rea.process-memory")
}

/// Retain a supplied recorded-crash result without opening a path here.
pub fn inspect_recorded_crash(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, CRASH_OPERATION)?;
    let (metadata, result) = captured_crash_payload(object)?;

    Ok(evidence_projection(
        CRASH_OPERATION,
        "rea.recorded-crash",
        &metadata,
        Value::Object(result),
    ))
}

fn captured_crash_payload(
    input: &Map<String, Value>,
) -> Result<(Map<String, Value>, Map<String, Value>), Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid(CRASH_OPERATION, "captured crash Evidence is required"))?;
    let evidence_object = evidence
        .as_object()
        .ok_or_else(|| invalid(CRASH_OPERATION, "captured crash Evidence must be an object"))?;
    let raw = serde_json::value::to_raw_value(evidence).map_err(|error| {
        invalid(
            CRASH_OPERATION,
            &format!("captured crash Evidence is invalid: {error}"),
        )
    })?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| {
        invalid(
            CRASH_OPERATION,
            &format!("captured crash Evidence is not authenticated: {error}"),
        )
    })?;
    if !record.operation_matches(CRASH_OPERATION) {
        return Err(invalid(
            CRASH_OPERATION,
            "captured crash Evidence operation does not match",
        ));
    }
    let result: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(
                CRASH_OPERATION,
                &format!("captured crash result is invalid: {error}"),
            )
        })?;
    let result = result
        .as_object()
        .ok_or_else(|| invalid(CRASH_OPERATION, "captured crash result must be an object"))?;
    Ok((evidence_object.clone(), result.clone()))
}

/// Project a supplied crash observation through the uniquely named offline
/// adapter contract while retaining the underlying inspection operation.
pub fn inspect_recorded_crash_offline(input: &Value) -> Result<Value, Failure> {
    inspect_recorded_crash(input)
}

/// Compare two caller-supplied captures using the existing comparison owner.
/// The wrapper adds the offline boundary and checks generation provenance.
pub fn compare_process_captures(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, COMPARISON_OPERATION)?;
    for side in ["left", "right"] {
        let capture = object
            .get(side)
            .ok_or_else(|| invalid(COMPARISON_OPERATION, &format!("{side} capture is required")))?;
        validate_capture(capture, COMPARISON_OPERATION, side)?;
    }

    Ok(json!({
        "operation": COMPARISON_OPERATION,
        "left": object["left"].clone(),
        "right": object["right"].clone(),
        "max_capture_age_ms": object.get("max_capture_age_ms").cloned(),
        "trace_spec": object.get("trace_spec").cloned(),
        "limitations": [
            "comparison-consumes-caller-supplied-captures-only",
            "process-generation-identity-remains-capture-scoped",
            "partial-or-truncated-captures-must-remain-unknown"
        ]
    }))
}

/// Retain a caller-supplied scenario capture.  This never launches or controls
/// the scenario; a live capture adapter must own that authority separately.
pub fn capture_process_scenario(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, SCENARIO_OPERATION)?;
    let capture = object
        .get("capture")
        .or_else(|| object.get("scenario"))
        .ok_or_else(|| invalid(SCENARIO_OPERATION, "captured scenario is required"))?;
    validate_capture(capture, SCENARIO_OPERATION, "capture")?;

    Ok(evidence_projection(
        SCENARIO_OPERATION,
        "rea.process-capture",
        object,
        capture.clone(),
    ))
}

fn project_observations(
    input: &Value,
    operation: &'static str,
    predicate_type: &'static str,
) -> Result<Value, Failure> {
    let object = input_object(input, operation)?;
    let (metadata, captured) = captured_observation_payload(object, operation)?;
    let observations = captured
        .get("observations")
        .or_else(|| captured.get("capture"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(operation, "captured observations are required"))?;
    if observations.len() > MAX_OBSERVATIONS {
        return Err(invalid(
            operation,
            "captured observation count exceeds the limit",
        ));
    }

    let mut projected = Vec::with_capacity(observations.len());
    for (index, observation) in observations.iter().enumerate() {
        projected.push(validate_observation(observation, operation, index)?);
    }

    let normalized = json!({
        "source": captured
            .get("source")
            .cloned()
            .unwrap_or(Value::String("caller-supplied".into())),
        "observations": projected,
        "provenance": captured
            .get("provenance")
            .cloned()
            .unwrap_or_else(|| json!([])),
    });
    Ok(evidence_projection(
        operation,
        predicate_type,
        metadata,
        normalized,
    ))
}

/// Return the retained producer metadata and its normalized observation payload.
///
/// Callers may provide either adapter-shaped captured facts or an Evidence
/// envelope containing `normalized_result`.  In both forms the observation
/// owner remains responsible for identity, lifecycle, ownership, and unknown
/// state values; this adapter only validates the envelope and retains them.
fn captured_observation_payload<'a>(
    object: &'a Map<String, Value>,
    operation: &'static str,
) -> Result<(&'a Map<String, Value>, &'a Map<String, Value>), Failure> {
    if let Some(evidence) = object.get("evidence") {
        return evidence_payload(evidence, operation);
    }

    if object.get("normalized_result").is_some() || object.get("result").is_some() {
        let payload = object
            .get("normalized_result")
            .or_else(|| object.get("result"))
            .ok_or_else(|| invalid(operation, "captured Evidence result is required"))?;
        let payload = payload
            .as_object()
            .ok_or_else(|| invalid(operation, "captured Evidence result must be an object"))?;
        validate_evidence_operation(object, operation)?;
        return Ok((object, payload));
    }

    Ok((object, object))
}

fn evidence_payload<'a>(
    value: &'a Value,
    operation: &'static str,
) -> Result<(&'a Map<String, Value>, &'a Map<String, Value>), Failure> {
    let evidence = value
        .as_object()
        .ok_or_else(|| invalid(operation, "captured evidence must be an object"))?;
    validate_evidence_operation(evidence, operation)?;
    let payload = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid(operation, "captured Evidence result is required"))?;
    let payload = payload
        .as_object()
        .ok_or_else(|| invalid(operation, "captured Evidence result must be an object"))?;
    Ok((evidence, payload))
}

fn validate_evidence_operation(
    evidence: &Map<String, Value>,
    operation: &'static str,
) -> Result<(), Failure> {
    if let Some(candidate) = evidence.get("operation") {
        if candidate.as_str() != Some(operation) {
            return Err(invalid(
                operation,
                "captured Evidence operation does not match",
            ));
        }
    }
    Ok(())
}

fn validate_observation(
    value: &Value,
    operation: &'static str,
    index: usize,
) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(operation, &format!("observation {index} must be an object")))?;
    let pid = object
        .get("pid")
        .and_then(Value::as_u64)
        .filter(|pid| *pid > 0)
        .ok_or_else(|| {
            invalid(
                operation,
                &format!("observation {index} requires a positive pid"),
            )
        })?;

    let generation = object.get("generation").ok_or_else(|| {
        invalid(
            operation,
            &format!("observation {index} must preserve generation identity"),
        )
    })?;
    validate_generation(generation, operation)?;
    if !object.contains_key("state") {
        return Err(invalid(
            operation,
            &format!("observation {index} requires state"),
        ));
    }

    let mut result = object.clone();
    result.insert("pid".into(), Value::Number(pid.into()));
    Ok(Value::Object(result))
}

fn validate_capture(value: &Value, operation: &'static str, side: &str) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(operation, &format!("{side} capture must be an object")))?;
    let manifest = object
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(operation, &format!("{side} capture requires a manifest")))?;
    for field in ["full_scenario_sha256", "comparison_contract_sha256"] {
        if manifest.get(field).and_then(Value::as_str).is_none() {
            return Err(invalid(
                operation,
                &format!("{side}.manifest.{field} is required"),
            ));
        }
    }
    if let Some(samples) = object.get("process_samples").and_then(Value::as_array) {
        for (index, sample) in samples.iter().enumerate() {
            let sample_object = sample.as_object().ok_or_else(|| {
                invalid(
                    operation,
                    &format!("process sample {index} must be an object"),
                )
            })?;
            if sample_object
                .get("pid")
                .and_then(Value::as_u64)
                .is_none_or(|pid| pid == 0)
            {
                return Err(invalid(
                    operation,
                    &format!("process sample {index} requires a positive pid"),
                ));
            }
            if let Some(generation) = sample_object.get("generation") {
                validate_generation(generation, operation)?;
            }
        }
    }
    Ok(())
}

fn validate_generation(value: &Value, operation: &'static str) -> Result<(), Failure> {
    let valid = match value {
        Value::String(value) => !value.is_empty() && value.len() <= MAX_GENERATION_BYTES,
        Value::Object(value) => {
            !value.is_empty()
                && serde_json::to_vec(value)
                    .map(|bytes| bytes.len() <= MAX_GENERATION_BYTES)
                    .unwrap_or(false)
        }
        Value::Null => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(invalid(
            operation,
            "generation must be a bounded observed identity or explicit null",
        ))
    }
}

fn evidence_projection(
    operation: &'static str,
    predicate_type: &'static str,
    input: &Map<String, Value>,
    normalized: Value,
) -> Value {
    json!({
        "subject": Value::Null,
        "provider": input.get("provider").cloned().unwrap_or_else(|| json!({"id":"rea-process-offline","name":"REA offline process evidence","version":"1"})),
        "analysis_profile": Value::Null,
        "predicate_type": predicate_type,
        "operation": operation,
        "parameters": input.get("parameters").cloned().unwrap_or_else(|| json!({})),
        "raw_result": Value::Null,
        "normalized_result": normalized,
        "confidence": "observed",
        "authority": "historical-reference",
        "environment": Value::Null,
        "limitations": input.get("limitations").cloned().unwrap_or_else(|| json!(["caller-supplied-process-evidence-only","no-process-discovery-or-target-control"])),
        "relationship_coverage": Value::Null,
        "locations": [],
        "evidence_links": input.get("evidence_links").cloned().unwrap_or_else(|| json!([])),
        "provenance": input.get("provenance").cloned().unwrap_or_else(|| json!([])),
    })
}

fn input_object<'a>(
    input: &'a Value,
    operation: &'static str,
) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid(operation, "input must be an object"))
}

fn invalid(operation: &'static str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide a complete caller-supplied process evidence record.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
