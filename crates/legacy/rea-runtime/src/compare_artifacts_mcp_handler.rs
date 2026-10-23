//! Isolated runtime handler for the public `compare_artifacts` contract.
//!
//! Session registration remains owned by the existing runtime composition
//! boundary. This module only validates the public request envelope and
//! delegates Evidence parsing, retained-record lookup, comparison, and typed
//! failures to the application producer.

use rea_application::{artifacts, ledger::artifact_records::ArtifactRecords};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use serde_json::Value;
use std::collections::BTreeMap;

/// The stable public MCP operation name.
pub const OPERATION: &str = "compare_artifacts";

/// Run the public contract against caller-supplied Evidence.
pub fn handle(
    input: &Value,
    records: Option<&ArtifactRecords>,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    validate_request(input)?;

    let raw = artifacts::compare::compare(input, records, cancellation)?;

    serde_json::from_str(raw.get()).map_err(|error| invalid_result(&error.to_string()))
}

fn validate_request(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("request must be an object"))?;

    let expected_fields = ["left", "right"];
    let has_exact_fields = object.len() == expected_fields.len()
        && expected_fields
            .iter()
            .all(|field| object.contains_key(*field));
    if !has_exact_fields {
        return Err(invalid_input(
            "request must contain exactly the left and right Evidence fields",
        ));
    }

    for field in expected_fields {
        if !object.get(field).is_some_and(Value::is_object) {
            return Err(invalid_input(&format!(
                "{field} must be an Evidence object"
            )));
        }
    }

    Ok(())
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Artifact comparison input is invalid.".into(),
        false,
        "Check the comparison inputs and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

fn invalid_result(reason: &str) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        "Artifact comparison returned invalid JSON.".into(),
        false,
        "Retry the comparison.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
