//! Typed failures mirroring the TS producer classes for the two web-scripts
//! tools.
//!
//! Compatibility owners: `src/application/WebScriptExportService.ts`,
//! `src/domain/webScriptExportError.ts`, `src/domain/artifactOperationError.ts`,
//! `src/application/WebSourceLocationService.ts` and
//! `src/domain/analysisErrorCore.ts`.
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Value, json};

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

/// Path segment helper for input issue paths.
pub fn segment(name: &str) -> Value {
    Value::String(name.to_owned())
}

/// `new AnalysisOutputError(operation, message)`.
pub fn output(operation: &str, message: impl Into<String>) -> AnalysisError {
    AnalysisError::output(operation, message)
}

/// `new AnalysisCancelledError(operation)`.
pub fn cancelled(operation: &str) -> AnalysisError {
    AnalysisError::cancelled(operation)
}

/// `new AnalysisAccessDeniedError(operation, path, code)`.
pub fn access_denied(operation: &str, path: &str, code: &str) -> AnalysisError {
    AnalysisError::access_denied(operation, path, code)
}

/// `new AnalysisCapabilityUnavailableError(provider, operation, reason, { userMessage })`.
pub fn capability_unavailable(
    provider: &str,
    operation: &str,
    reason: &str,
    user_message: impl Into<String>,
) -> AnalysisError {
    AnalysisError::capability_unavailable(provider, operation, reason)
        .with_user_message(user_message)
}

/// `new WebScriptExportError(reason, target, diagnostic)` with no cleanup.
///
/// `WebScriptExportError` overrides `userMessage` to
/// `Script export failed for <target>: <diagnostic>` while leaving the
/// artifact `detail` unset, so the projection carries only
/// `details: { operation, reason }`. The generic `ArtifactOperation` message
/// algebra cannot reproduce that, so the exact projection is built here.
pub fn web_script_export(reason: &str, target: &str, diagnostic: &str) -> AnalysisError {
    projected_artifact_operation(
        "export_web_scripts",
        reason,
        &format!("Script export failed for {target}: {diagnostic}"),
    )
}

/// Build the exact projection the TS `ArtifactOperationError`/`WebScriptExportError`
/// subclasses produce: a caller-facing `userMessage` with artifact
/// `{ operation, reason }` details only.
pub fn projected_artifact_operation(operation: &str, reason: &str, message: &str) -> AnalysisError {
    let category = match reason {
        "integrity" => "integrity_mismatch",
        "limit" => "truncated",
        "cancelled" => "cancelled",
        "unavailable" => "unavailable",
        _ => "execution_failure",
    };
    let code = match reason {
        "limit" => "truncated",
        "cancelled" => "cancelled",
        _ => "artifact_operation_failed",
    };
    let retryable = reason == "cancelled";
    let mut details = serde_json::Map::new();
    details.insert("operation".into(), json!(operation));
    details.insert("reason".into(), json!(reason));
    if reason == "limit" {
        details.insert("truncated".into(), json!(true));
    }
    AnalysisError::from_projection(json!({
        "code": code,
        "category": category,
        "message": message,
        "retryable": retryable,
        "remediation": { "action": message },
        "details": Value::Object(details),
    }))
}
