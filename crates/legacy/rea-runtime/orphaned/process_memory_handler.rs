//! Read-only runtime boundary for captured process-memory observations.
//!
//! This handler has no process, ptrace, debugger, or memory-read authority.
//! It delegates observation validation to the application projection and
//! accepts authenticated Evidence as an already captured result.

use rea_application::process;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_process_memory";

/// Project caller-supplied memory observations or retain matching Evidence.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    reject_unknown_fields(object)?;
    process::memory_projection::inspect(&input)
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    if value.is_null() {
        return Err(invalid("evidence must be an Evidence object"));
    }
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&format!("Evidence serialization failed: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is malformed: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity(
            "Evidence operation does not match inspect_process_memory",
        ));
    }

    let normalized = serde_json::from_str::<Value>(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence normalized result is invalid: {error}")))?;
    process::memory_projection::validate_normalized_result(&normalized)
        .map_err(|error| integrity(&format!("Evidence normalized result is invalid: {error}")))?;

    Ok(serde_json::from_str(record.raw().get()).map_err(|error| {
        integrity(&format!("Evidence could not be retained: {error}"))
    })?)
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "source"
                | "observations"
                | "provider"
                | "parameters"
                | "limitations"
                | "provenance"
                | "evidence_links"
        )
    }) {
        return Err(invalid("input contains an unsupported field"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide caller-supplied process-memory observations or matching Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide intact inspect_process_memory Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
