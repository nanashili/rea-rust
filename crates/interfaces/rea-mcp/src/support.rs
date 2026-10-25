//! Shared helpers for tool families.
#[cfg(unix)]
use rea_application::inputs::InputError;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use serde_json::{Map, Value};

/// Convert application input parsing issues into the shared input failure.
#[cfg(unix)]
pub fn input_error(operation: &str, error: InputError) -> AnalysisError {
    AnalysisError::input(
        operation,
        error
            .0
            .into_iter()
            .map(|issue| InputIssue {
                path: issue.path.into_iter().map(Value::String).collect(),
                reason: issue.reason,
                message: Some(issue.message),
                expected: issue
                    .expected
                    .map(|expected| Value::String(expected.into())),
                minimum: None,
                maximum: None,
            })
            .collect(),
    )
}

/// Arguments as an object map (validated input is always an object).
pub fn arguments(input: &Value) -> Map<String, Value> {
    input.as_object().cloned().unwrap_or_default()
}

/// Required string argument (schema validation already established presence).
pub fn string<'a>(input: &'a Value, key: &str) -> &'a str {
    input.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// Optional string argument.
pub fn optional_string<'a>(input: &'a Value, key: &str) -> Option<&'a str> {
    input.get(key).and_then(Value::as_str)
}

/// Optional unsigned integer argument.
pub fn optional_u64(input: &Value, key: &str) -> Option<u64> {
    input.get(key).and_then(Value::as_u64)
}

/// Optional boolean argument.
pub fn optional_bool(input: &Value, key: &str) -> Option<bool> {
    input.get(key).and_then(Value::as_bool)
}

/// Create Evidence, mapping canonicalization failures into the error algebra.
pub fn evidence(
    target: Option<&SubjectTarget>,
    provider: &EvidenceProvider,
    observation: Observation,
) -> Result<Evidence, AnalysisError> {
    Evidence::create(target, provider, observation)
        .map_err(|error| AnalysisError::output(String::new(), error.to_string()))
}

/// Adopt an already-built, authenticated Evidence value from an older owner.
pub fn adopt_evidence(value: Value) -> Result<Evidence, AnalysisError> {
    let id = value
        .get("evidence_id")
        .and_then(Value::as_str)
        .ok_or_else(|| AnalysisError::output("native", "Evidence is missing evidence_id"))?
        .to_owned();
    Ok(Evidence::from_authenticated(id, value))
}
