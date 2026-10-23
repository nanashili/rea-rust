//! Public adapter for the strict `inspect_pe_resources` result contract.
//!
//! The application PE reader retains additional decoded resource families for
//! native consumers.  This adapter owns the public contract boundary: it
//! preserves the reader's artifact identity and Evidence metadata while
//! projecting only the fields declared by the TypeScript contract.

use rea_application::{
    artifacts::inspection::Completion,
    inputs,
    binary::pe_resources::PeResourcesInspection,
};
use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_host::fs::unix_file::UnixFiles;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

pub const OPERATION: &str = "inspect_pe_resources";

/// Execute the read-only PE resource producer and project its public Evidence.
pub fn inspect(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input must be an object"))?;

    if object.contains_key("bytes_base64") || object.contains_key("evidence") {
        return rea_application::binary::pe_resources::inspect_captured(input);
    }

    let request = inputs::pe_resources(object)
        .map_err(|error| invalid_input(&error.to_string()))?;

    let mut inspection = PeResourcesInspection::new(Arc::new(UnixFiles));
    let result = inspection.inspect(request, cancellation, Completion::OneShot);
    let cleanup = inspection.close();
    let evidence = match (result, cleanup) {
        (Ok(evidence), Ok(())) => evidence,
        (Err(mut primary), Err(cleanup)) => {
            primary.detail(
                "cleanup_failure",
                Detail::Text(cleanup.code().to_owned()),
            );
            return Err(primary);
        }
        (Err(primary), Ok(())) => return Err(primary),
        (Ok(_evidence), Err(cleanup)) => return Err(cleanup),
    };

    project_evidence(evidence.as_ref())
}

fn project_evidence(evidence: &rea_core::evidence::ArtifactEvidence) -> Result<Value, Failure> {
    let mut value = serde_json::to_value(evidence)
        .map_err(|error| execution_failure(&error.to_string()))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| execution_failure("PE resource Evidence is not an object"))?;
    object.remove("evidence_id");
    let normalized = value
        .get_mut("normalized_result")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            execution_failure("PE resource Evidence has no normalized_result object")
        })?;
    retain_public_fields(normalized);

    let raw = serde_json::value::to_raw_value(&value)
        .map_err(|error| execution_failure(&error.to_string()))?;
    let record = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| execution_failure(&error.to_string()))?;
    serde_json::from_str(record.raw().get())
        .map_err(|error| execution_failure(&error.to_string()))
}

fn retain_public_fields(result: &mut Map<String, Value>) {
    result.retain(|field, _| {
        matches!(
            field.as_str(),
            "artifact"
                | "format"
                | "machine"
                | "directory"
                | "directories"
                | "resources"
                | "icon_groups"
                | "coverage"
                | "limitations"
        )
    });
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid.".into(),
        false,
        "Correct the request fields and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

fn execution_failure(reason: &str) -> Failure {
    Failure::new(
        "execution_failure",
        "analysis_output",
        "PE resource Evidence could not be serialized.".into(),
        false,
        "Review the PE resource Evidence output and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
