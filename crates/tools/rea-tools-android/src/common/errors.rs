//! Composition helpers over the shared typed error algebra.
//!
//! Compatibility owners: `src/domain/providerCleanupError.ts` and
//! `src/domain/analysisErrorCleanup.ts`. The projection itself stays in
//! `rea_core::analysis_error`; these helpers only set the same fields the
//! original constructors set.
use rea_core::analysis_error::{AnalysisError, CapturedOutput, CleanupObservation, ErrorKind};
use serde_json::{Map, Value, json};

/// `ProviderCleanupError.userMessage`.
pub const PROVIDER_CLEANUP_MESSAGE: &str = "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target.";

/// Convert a `json!({...})` object literal into a diagnostics map.
pub fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `new ProviderCleanupError(providerId, resources, diagnostics, { operation })`.
pub fn provider_cleanup(
    provider_id: &str,
    operation: &str,
    resources: Vec<String>,
    diagnostics: Map<String, Value>,
) -> AnalysisError {
    let mut error = AnalysisError::from(ErrorKind::ProviderAdapter {
        provider_id: provider_id.to_owned(),
        operation: operation.to_owned(),
        user_message: Some(PROVIDER_CLEANUP_MESSAGE.to_owned()),
        remediation_action: None,
    });
    error.diagnostics = Some(diagnostics);
    error.cleanup_incomplete = Some(true);
    error.cleanup_resources = Some(resources);
    error
}

/// `new ProviderAdapterError(providerId, operation, { userMessage, diagnostics })`.
pub fn provider_adapter(
    provider_id: &str,
    operation: &str,
    user_message: Option<String>,
    diagnostics: Option<Map<String, Value>>,
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

/// `new AnalysisCapabilityUnavailableError(provider, operation, reason, { userMessage, diagnostics })`.
pub fn capability_unavailable(
    provider_id: &str,
    operation: &str,
    reason: impl Into<String>,
    user_message: Option<String>,
    diagnostics: Option<Map<String, Value>>,
) -> AnalysisError {
    let mut error = AnalysisError::from(ErrorKind::CapabilityUnavailable {
        provider_id: provider_id.to_owned(),
        operation: operation.to_owned(),
        reason: reason.into(),
        user_message,
        remediation_action: None,
        retryable: false,
    });
    error.diagnostics = diagnostics;
    error
}

/// `analysisErrorWithCleanupFailure(primary, cleanup, operation)`.
///
/// The composed failure keeps the typed primary, the cleanup projection and
/// the union of unresolved resources, exactly as the original constructor.
pub fn with_cleanup_failure(
    primary: AnalysisError,
    cleanup: AnalysisError,
    operation: &str,
) -> AnalysisError {
    let projected = cleanup.project();
    let primary_projection = primary.project();
    let provider_id = match &cleanup.kind {
        ErrorKind::ProviderAdapter { provider_id, .. } => provider_id.clone(),
        _ => "rea".to_owned(),
    };
    let mut resources: Vec<String> = Vec::new();
    let mut push = |resource: String| {
        if !resources.contains(&resource) {
            resources.push(resource);
        }
    };
    if primary.is_cleanup_incomplete() {
        for resource in primary.unresolved_resources() {
            push(resource);
        }
    }
    for resource in cleanup.unresolved_resources() {
        push(resource);
    }
    let mut error = AnalysisError::from(ErrorKind::ProviderAdapter {
        provider_id,
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
    error.diagnostics = Some(object(json!({
        "primary_error": primary_projection,
        "cleanup_error": projected,
    })));
    error.cleanup_primary = Some(Box::new(primary));
    error
}

/// Error text of a failure value, as `cause instanceof Error ? cause.message : String(cause)`.
pub fn message_of(error: &dyn std::fmt::Display) -> String {
    error.to_string()
}

/// Build captured command output for a typed failure.
#[allow(clippy::too_many_arguments)]
pub fn captured_output(
    stdout: &[u8],
    stderr: &[u8],
    stdout_bytes: Option<u64>,
    stderr_bytes: Option<u64>,
    exit_code: Option<Option<i64>>,
    signal: Option<Option<String>>,
    truncated: bool,
) -> CapturedOutput {
    CapturedOutput {
        stdout: String::from_utf8_lossy(stdout).into_owned(),
        stderr: String::from_utf8_lossy(stderr).into_owned(),
        truncated,
        stdout_bytes,
        stderr_bytes,
        exit_code,
        signal,
    }
}
