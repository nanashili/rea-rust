//! Projection of captured process command-line observations into Evidence.
//!
//! Process identity and command-line readers belong to the host observation
//! owner.  This module accepts their already-captured facts and performs no
//! PID lookup, procfs read, or platform API call.  In particular, an argv
//! vector is retained as the producer reported it and is never reconstructed
//! from a display command line.

use rea_core::{
    evidence::record::{EvidenceRecord, EvidenceRecordError},
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_process_cmdline";
const PREDICATE_TYPE: &str = "rea.process-cmdline";
const PROVIDER_ID: &str = "rea-process-observer";
const PROVIDER_NAME: &str = "REA process identity observer";
const LIMITATIONS: [&str; 3] = [
    "caller-selected-pids-only",
    "bounded-proc-cmdline-read",
    "identity-observation-does-not-grant-process-control-authority",
];

/// Project an adapter-shaped captured observation set without touching PIDs.
///
/// The accepted shape is `{ source, observations, provenance, evidence_links }`, where
/// each observation retains `pid`, optional `identity`/`generation`, and the
/// producer's flattened command-line state.  `capture` is accepted as an
/// alias for `observations` so adapters can keep transport metadata separate.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("process command-line input must be an object"))?;
    let source = object
        .get("source")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid("process command-line source must be a string"))
        })
        .transpose()?
        .unwrap_or("caller-supplied");
    if source.is_empty() {
        return Err(invalid("process command-line source must not be empty"));
    }
    let provenance = object
        .get("provenance")
        .cloned()
        .unwrap_or_else(|| json!([]));
    if !provenance.is_array() {
        return Err(invalid("process command-line provenance must be an array"));
    }
    let observations = object
        .get("observations")
        .or_else(|| object.get("capture"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("captured process command-line observations are required"))?;
    let projected = observations
        .iter()
        .map(project_observation)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(json!({
        "source": source,
        "observations": projected,
        "provenance": provenance,
    }))
}

/// Handle the captured `inspect_process_cmdline` operation.
///
/// This named entry point is intentionally a projection alias: the process
/// observation owner has already captured every fact, so dispatch cannot
/// perform a PID lookup or read `/proc` again.
pub fn inspect_process_cmdline(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Build the provider-neutral authenticated Evidence record for captured facts.
pub fn build_evidence(input: &Value) -> Result<EvidenceRecord, EvidenceRecordError> {
    let normalized =
        project(input).map_err(|error| EvidenceRecordError::Invalid(error.to_string()))?;
    let object = input.as_object().expect("project validates object input");
    let observations = normalized["observations"]
        .as_array()
        .expect("project validates observations");
    let pids = observations
        .iter()
        .filter_map(|observation| observation.get("pid").cloned())
        .collect::<Vec<_>>();
    let evidence_links = object
        .get("evidence_links")
        .cloned()
        .filter(Value::is_array)
        .unwrap_or_else(|| json!([]));
    let unsigned = json!({
        "subject": null,
        "provider": {
            "id": PROVIDER_ID,
            "name": PROVIDER_NAME,
            "version": null,
        },
        "analysis_profile": null,
        "predicate_type": PREDICATE_TYPE,
        "operation": OPERATION,
        "parameters": {
            "pids": pids,
            "source": normalized["source"],
        },
        "raw_result": null,
        "normalized_result": normalized,
        "confidence": "observed",
        "authority": "shipped-artifact",
        "environment": null,
        "limitations": LIMITATIONS,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": evidence_links,
    });
    let raw = serde_json::value::to_raw_value(&unsigned).map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

/// Adapter-friendly projection that returns the normalized JSON only.
pub fn project_value(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn project_observation(value: &Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("process command-line observation must be an object"))?;
    let pid = object
        .get("pid")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("process command-line observation pid must be nonnegative"))?;
    let mut result = object.clone();
    result.insert("pid".into(), Value::Number(pid.into()));

    if let Some(identity) = object.get("identity") {
        validate_identity(identity, "identity")?;
    }
    if let Some(generation) = object.get("generation") {
        validate_identity(generation, "generation")?;
    }

    let state = object
        .get("state")
        .ok_or_else(|| invalid("process command-line observation state is required"))?;
    let (state_name, nested_state) = match state {
        Value::String(name) => (name.as_str(), None),
        Value::Object(fields) => (
            fields
                .get("state")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("process command-line state name is required"))?,
            Some(fields),
        ),
        _ => return Err(invalid("process command-line observation state is invalid")),
    };
    let flattened_state = nested_state.unwrap_or(object);
    validate_state(state_name, flattened_state)?;
    result.insert("state".into(), Value::String(state_name.to_owned()));
    if let Some(fields) = nested_state {
        for (key, field) in fields {
            if key != "state" {
                result.insert(key.clone(), field.clone());
            }
        }
    }
    Ok(Value::Object(result))
}

fn validate_identity(value: &Value, field: &str) -> Result<(), Failure> {
    if !value.is_null() && value.as_str().is_none() {
        return Err(invalid(&format!(
            "process {field} must preserve a string identity"
        )));
    }
    Ok(())
}

fn validate_state(name: &str, state: &Map<String, Value>) -> Result<(), Failure> {
    match name {
        "readable" => {
            require_u64(state, "raw_len")?;
            require_bool(state, "nul_terminated")?;
            let arguments = state
                .get("arguments")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("readable command-line state requires arguments"))?;
            for argument in arguments {
                let argument = argument
                    .as_object()
                    .ok_or_else(|| invalid("command-line argument must be an object"))?;
                require_u64(argument, "start")?;
                require_u64(argument, "end")?;
                if argument.get("value").and_then(Value::as_str).is_none() {
                    return Err(invalid("command-line argument value must preserve text"));
                }
            }
        }
        "empty" => {}
        "malformed_utf8" => {
            require_u64(state, "raw_len")?;
        }
        "absent" | "unavailable" => {
            let reason = state
                .get("reason")
                .and_then(Value::as_str)
                .filter(|reason| !reason.is_empty())
                .ok_or_else(|| invalid("unavailable command-line state requires a reason"))?;
            let _ = reason;
        }
        _ => return Err(invalid("unknown process command-line observation state")),
    }
    Ok(())
}

fn require_u64(object: &Map<String, Value>, field: &str) -> Result<u64, Failure> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(&format!("command-line state requires nonnegative {field}")))
}

fn require_bool(object: &Map<String, Value>, field: &str) -> Result<bool, Failure> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(&format!("command-line state requires boolean {field}")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide captured process command-line observations with PID and generation provenance."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
