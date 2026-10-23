//! Projection of caller-owned process-memory observations.
//!
//! This boundary has no process or ptrace authority.  It validates the
//! identity and lifecycle envelope, then carries provider-reported ranges and
//! bytes through without decoding bytes or inferring permissions.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_process_memory";
const MAX_OBSERVATIONS: usize = 100_000;
const MAX_RANGES_PER_PROCESS: usize = 1_000_000;
const MAX_GENERATION_BYTES: usize = 4096;

/// Project captured process-memory observations into the shared Evidence
/// result shape.  Input must contain `observations`; each observation retains
/// its `pid`, `generation`, `state`, and provider-reported range facts.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input)?;
    let source = object
        .get("source")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid("process-memory source must be a string"))
        })
        .transpose()?
        .unwrap_or("caller-supplied-process-memory");
    if source.is_empty() {
        return Err(invalid("process-memory source must not be empty"));
    }

    validate_optional_metadata(object)?;

    let observations = object
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("observations must be an array"))?;
    if observations.is_empty() {
        return Err(invalid("observations must contain at least one item"));
    }
    if observations.len() > MAX_OBSERVATIONS {
        return Err(resource(
            "process-memory observation count exceeds the limit",
        ));
    }

    let mut projected = Vec::with_capacity(observations.len());
    let mut pids = Vec::with_capacity(observations.len());
    for observation in observations {
        let item = observation
            .as_object()
            .ok_or_else(|| invalid("each process-memory observation must be an object"))?;
        let pid = item
            .get("pid")
            .and_then(Value::as_u64)
            .filter(|pid| *pid > 0)
            .ok_or_else(|| invalid("process-memory pid must be positive"))?;
        let generation = item
            .get("generation")
            .ok_or_else(|| invalid("process-memory generation is required"))?;
        validate_generation(generation)?;
        let state = item
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("process-memory state is required"))?;
        if !matches!(state, "readable" | "absent" | "unavailable") {
            return Err(invalid("process-memory state is unknown"));
        }
        if state == "readable" {
            if let Some(ranges) = item.get("ranges") {
                let ranges = ranges
                    .as_array()
                    .ok_or_else(|| invalid("process-memory ranges must be an array"))?;
                if ranges.len() > MAX_RANGES_PER_PROCESS {
                    return Err(resource("process-memory range count exceeds the limit"));
                }
                for range in ranges {
                    validate_range(range)?;
                }
            } else {
                validate_memory_metrics(item)?;
            }
        }
        if state != "readable" && item.get("ranges").is_some() {
            return Err(invalid(
                "non-readable process-memory observations cannot report ranges",
            ));
        }
        pids.push(pid);
        projected.push(Value::Object(item.clone()));
    }

    let normalized = json!({ "source": source, "observations": projected });
    Ok(json!({
        "subject": Value::Null,
        "provider": object.get("provider").cloned().unwrap_or(Value::String("process-observation".into())),
        "analysis_profile": Value::Null,
        "predicate_type": "rea.process-memory",
        "operation": OPERATION,
        "parameters": object.get("parameters").cloned().unwrap_or_else(|| json!({"pids": pids})),
        "raw_result": Value::Null,
        "normalized_result": normalized,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": Value::Null,
        "limitations": object.get("limitations").cloned().unwrap_or_else(|| json!([
            "caller-selected-pids-only",
            "generation-validated-process-memory-observation",
            "memory-bytes-and-permissions-remain-provider-reported",
            "identity-observation-does-not-grant-process-control-authority"
        ])),
        "relationship_coverage": Value::Null,
        "locations": [],
        "evidence_links": [],
        "provenance": object.get("provenance").cloned().unwrap_or_else(|| json!([])),
    }))
}

/// Validate the normalized observation payload of retained Evidence.
///
/// Evidence authentication establishes envelope identity, while this
/// operation-owned check establishes that the retained payload is usable by
/// the process-memory projection without interpreting bytes or permissions.
pub fn validate_normalized_result(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "normalized result must be an object".to_string())?;
    let observations = object
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| "normalized result observations must be an array".to_string())?;
    if observations.is_empty() {
        return Err("normalized result observations must contain at least one item".into());
    }
    if observations.len() > MAX_OBSERVATIONS {
        return Err("normalized result observation count exceeds the limit".into());
    }

    for observation in observations {
        let item = observation
            .as_object()
            .ok_or_else(|| "each normalized observation must be an object".to_string())?;
        item.get("pid")
            .and_then(Value::as_u64)
            .filter(|pid| *pid > 0)
            .ok_or_else(|| "normalized observation pid must be positive".to_string())?;
        let generation = item
            .get("generation")
            .ok_or_else(|| "normalized observation generation is required".to_string())?;
        validate_generation(generation)
            .map_err(|_| "normalized observation generation is invalid".to_string())?;
        let state = item
            .get("state")
            .and_then(Value::as_str)
            .ok_or_else(|| "normalized observation state is required".to_string())?;
        if !matches!(state, "readable" | "absent" | "unavailable") {
            return Err("normalized observation state is unknown".into());
        }

        if state == "readable" {
            if let Some(ranges) = item.get("ranges") {
                let ranges = ranges
                    .as_array()
                    .ok_or_else(|| "normalized observation ranges must be an array".to_string())?;
                if ranges.len() > MAX_RANGES_PER_PROCESS {
                    return Err("normalized observation range count exceeds the limit".into());
                }
                for range in ranges {
                    validate_range(range)
                        .map_err(|_| "normalized observation range is invalid".to_string())?;
                }
            } else {
                validate_memory_metrics(item)
                    .map_err(|_| "normalized memory metrics are invalid".to_string())?;
            }
        } else if item.get("ranges").is_some() {
            return Err("non-readable normalized observation cannot report ranges".into());
        }
    }

    Ok(())
}

fn validate_generation(value: &Value) -> Result<(), Failure> {
    match value {
        Value::String(value) if !value.is_empty() && value.len() <= MAX_GENERATION_BYTES => Ok(()),
        Value::Object(object)
            if !object.is_empty()
                && serde_json::to_vec(object)
                    .map(|bytes| bytes.len() <= MAX_GENERATION_BYTES)
                    .unwrap_or(false) =>
        {
            Ok(())
        }
        _ => Err(invalid(
            "process-memory generation must be a bounded observed identity",
        )),
    }
}

fn validate_range(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("process-memory range must be an object"))?;
    if object.get("start").is_none() || object.get("end").is_none() {
        return Err(invalid("process-memory range requires start and end"));
    }
    if let Some(bytes) = object.get("bytes_base64") {
        if !bytes
            .as_str()
            .map(|encoded| !encoded.is_empty())
            .unwrap_or(false)
        {
            return Err(invalid(
                "process-memory bytes_base64 must be a non-empty string when present",
            ));
        }
    }
    if let Some(complete) = object.get("complete") {
        if !complete.is_boolean() {
            return Err(invalid("process-memory completeness must be boolean"));
        }
    }
    if let Some(truncated) = object.get("truncated") {
        if !truncated.is_boolean() {
            return Err(invalid("process-memory truncation must be boolean"));
        }
    }
    Ok(())
}

fn validate_memory_metrics(object: &Map<String, Value>) -> Result<(), Failure> {
    let fields = [
        "virtual_pages",
        "resident_pages",
        "page_size_bytes",
        "virtual_bytes",
        "resident_bytes",
    ];
    if !fields.iter().any(|field| object.contains_key(*field)) {
        return Err(invalid(
            "readable process-memory observations require ranges or memory metrics",
        ));
    }
    for field in fields {
        if let Some(value) = object.get(field) {
            if value.as_u64().is_none() {
                return Err(invalid(
                    "process-memory metrics must be non-negative integers",
                ));
            }
        }
    }
    if let Some(source) = object.get("page_size_source") {
        if source.as_str().is_none() {
            return Err(invalid("process-memory page-size source must be a string"));
        }
    }
    Ok(())
}

fn validate_optional_metadata(object: &Map<String, Value>) -> Result<(), Failure> {
    if let Some(parameters) = object.get("parameters") {
        if !parameters.is_object() {
            return Err(invalid("process-memory parameters must be an object"));
        }
    }

    if let Some(limitations) = object.get("limitations") {
        let limitations = limitations
            .as_array()
            .ok_or_else(|| invalid("process-memory limitations must be an array"))?;
        if limitations.iter().any(|value| value.as_str().is_none()) {
            return Err(invalid(
                "process-memory limitations must contain only strings",
            ));
        }
    }

    for field in ["provenance", "evidence_links"] {
        if let Some(value) = object.get(field) {
            if !value.is_array() {
                return Err(invalid(format!("process-memory {field} must be an array")));
            }
        }
    }

    Ok(())
}

fn input_object(value: &Value) -> Result<&Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))
}
fn invalid(message: impl Into<String>) -> Failure {
    failure(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "provide a complete process-memory observation",
    )
}
fn resource(message: impl Into<String>) -> Failure {
    failure(
        "resource_limit",
        "resource",
        message.into(),
        false,
        "reduce the captured process-memory observation",
    )
}
fn failure(
    code: &'static str,
    category: &'static str,
    message: String,
    retryable: bool,
    action: &'static str,
) -> Failure {
    Failure::new(
        code,
        category,
        message,
        retryable,
        action.into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
