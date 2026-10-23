//! Typed failure constructors mirroring the original producer classes.
//!
//! Compatibility owners: `src/domain/providerAdapterError.ts`,
//! `src/domain/providerCleanupError.ts`, `src/domain/analysisErrorCleanup.ts`
//! and `src/domain/analysisErrorCore.ts`.
use crate::process::ProcessSnapshot;
use rea_core::analysis_error::{
    AnalysisError, CapturedOutput, CleanupObservation, ErrorKind, InputIssue,
};
use serde_json::{Map, Value, json};

/// `ProviderCleanupError.userMessage`.
pub const CLEANUP_MESSAGE: &str = "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target.";

/// Build an object map from ordered entries.
pub fn map(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    let mut object = Map::new();
    for (key, value) in entries {
        object.insert(key.to_owned(), value);
    }
    object
}

/// `new ProviderAdapterError(providerId, operation, { diagnostics, userMessage })`.
pub fn provider_adapter(
    provider_id: &str,
    operation: &str,
    diagnostics: Option<Map<String, Value>>,
    user_message: Option<String>,
) -> AnalysisError {
    let mut error = AnalysisError::from(ErrorKind::ProviderAdapter {
        provider_id: provider_id.to_owned(),
        operation: operation.to_owned(),
        user_message,
        remediation_action: None,
    });
    error.diagnostics = diagnostics;
    error
}

/// `new ProviderCleanupError(providerId, resources, diagnostics, { operation })`.
pub fn provider_cleanup(
    provider_id: &str,
    resources: Vec<String>,
    diagnostics: Map<String, Value>,
    operation: &str,
) -> AnalysisError {
    let mut error = provider_adapter(
        provider_id,
        operation,
        Some(diagnostics),
        Some(CLEANUP_MESSAGE.to_owned()),
    );
    error.cleanup_incomplete = Some(true);
    error.cleanup_resources = Some(resources);
    error
}

/// Provider identity of an adapter failure, `rea` otherwise.
fn provider_of(error: &AnalysisError) -> String {
    match &error.kind {
        ErrorKind::ProviderAdapter { provider_id, .. } => provider_id.clone(),
        _ => "rea".to_owned(),
    }
}

/// `analysisErrorWithCleanupFailure(primary, cleanup, operation)`.
pub fn with_cleanup_failure(
    primary: AnalysisError,
    cleanup: AnalysisError,
    operation: &str,
) -> AnalysisError {
    let projected = cleanup.project();
    let primary_projection = primary.project();
    let mut resources = Vec::new();
    if primary.is_cleanup_incomplete() {
        for resource in primary.unresolved_resources() {
            if !resources.contains(&resource) {
                resources.push(resource);
            }
        }
    }
    for resource in cleanup.unresolved_resources() {
        if !resources.contains(&resource) {
            resources.push(resource);
        }
    }
    let mut error = AnalysisError::from(ErrorKind::ProviderAdapter {
        provider_id: provider_of(&cleanup),
        operation: operation.to_owned(),
        user_message: primary_projection["message"].as_str().map(str::to_owned),
        remediation_action: projected["remediation"]["action"]
            .as_str()
            .map(str::to_owned),
    });
    error.captured_output = primary.captured_output.clone();
    error.partial_observation = primary.partial_observation.clone();
    error.cleanup = Some(CleanupObservation {
        reason: projected["message"].as_str().unwrap_or_default().to_owned(),
        resources,
    });
    error.diagnostics = Some(map([
        ("primary_error", primary_projection),
        ("cleanup_error", projected),
    ]));
    error.cleanup_primary = Some(Box::new(primary));
    error
}

/// `{ stdout, stderr, truncated, exit_code, signal }` from a process snapshot.
pub fn captured_from(snapshot: &ProcessSnapshot) -> CapturedOutput {
    CapturedOutput {
        stdout: snapshot.stdout.text.clone(),
        stderr: snapshot.stderr.text.clone(),
        truncated: snapshot.diagnostic_truncated,
        stdout_bytes: None,
        stderr_bytes: None,
        exit_code: Some(snapshot.exit_code),
        signal: Some(snapshot.signal.clone()),
    }
}

/// Attach captured output when present.
pub fn with_output(error: AnalysisError, output: Option<&CapturedOutput>) -> AnalysisError {
    match output {
        Some(output) => error.with_captured_output(output.clone()),
        None => error,
    }
}

/// `new AnalysisInputError(operation, _, [{ path, reason, message }])`.
pub fn input_issue(
    operation: &str,
    path: Vec<Value>,
    reason: &'static str,
    message: impl Into<String>,
) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue {
            path,
            reason,
            message: Some(message.into()),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}

/// Path segment helper for input issues.
pub fn segment(name: &str) -> Value {
    Value::String(name.to_owned())
}

/// `new AnalysisCapabilityUnavailableError(provider, operation, reason, { userMessage })`.
pub fn capability(
    provider_id: &str,
    operation: &str,
    reason: &str,
    user_message: Option<String>,
) -> AnalysisError {
    let error = AnalysisError::capability_unavailable(provider_id, operation, reason);
    match user_message {
        Some(message) => error.with_user_message(message),
        None => error,
    }
}

/// `new AnalysisResourceConstraintError(operation, resource, reason, limits)`.
pub fn resource(
    operation: &str,
    resource: &str,
    reason: &str,
    limits: Option<Value>,
) -> AnalysisError {
    AnalysisError::resource_constraint(operation, resource, reason, limits)
}

/// `{ key: value }` object literal shorthand.
pub fn object(entries: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(map(entries))
}

/// JSON `null`-or-string.
pub fn nullable(value: Option<&str>) -> Value {
    value.map_or(Value::Null, |text| json!(text))
}
