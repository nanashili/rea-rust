//! Isolated runtime adapter for `build_reconstruction_obligation_ledger`.
//!
//! The caller supplies the complete authenticated Evidence bundle, reviewed
//! obligations, and manifest. The application reducer owns ledger semantics;
//! this adapter only enforces the operation boundary and delegates to it. No
//! provider, target, filesystem, verifier, or project artifact is accessed.

use rea_application::reconstruction;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Dispatch the captured-Evidence ledger operation by its public name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != reconstruction::obligation_ledger::OPERATION {
        return Err(unknown_operation(operation));
    }

    dispatch_typed(&input)
}

/// Dispatch an already selected ledger operation without external access.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    reconstruction::obligation_ledger::build_ledger(input)
}

fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("ledger input must be an object"))?;
    require_exact_keys(object, &["evidence_bundle", "reviewed_obligations", "manifest"])?;

    let bundle = object
        .get("evidence_bundle")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_input("evidence_bundle must be an object"))?;
    require_exact_keys(
        bundle,
        &[
            "artifacts",
            "providers",
            "environments",
            "scenarios",
            "captures",
            "unknowns",
            "records",
        ],
    )?;

    let manifest = object
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_input("manifest must be an object"))?;
    require_exact_keys(manifest, &["bindings", "contradictions"])?;

    reconstruction::obligation_ledger::validate_input(input)
}

fn require_exact_keys(
    object: &serde_json::Map<String, Value>,
    expected: &[&str],
) -> Result<(), Failure> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid_input("input contains unknown or missing fields"));
    }
    Ok(())
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Reconstruction obligation ledger operation is unknown: {operation}"),
        false,
        "Select build_reconstruction_obligation_ledger and provide captured Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}

fn invalid_input(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        false,
        "Provide a complete captured Evidence bundle, reviewed obligations, and manifest."
            .into(),
        BTreeMap::from([(
            String::from("operation"),
            Detail::Text(reconstruction::obligation_ledger::OPERATION.into()),
        )]),
    )
}
