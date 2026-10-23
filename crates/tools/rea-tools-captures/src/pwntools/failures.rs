//! Decoder failure classification shared by both pwntools adapters.
//!
//! Compatibility owner: `src/native/pwntools/PwntoolsFailures.ts`. Keeps read,
//! engine, output and owned-lifecycle failure reasons distinct and reproduces
//! the exact user-visible strings.
use crate::errors::{self, map};
use crate::process::{CommandFailure, FailureReason, ProcessSnapshot};
use crate::pwntools::release;
use crate::pwntools::resource_limits::{FailureEvidence, LimitReport};
use rea_core::analysis_error::{
    AnalysisError, CapturedOutput, ErrorKind, InputIssue, SelectionRejection,
};
use serde_json::{Value, json};

/// Operation identity supplied by each adapter sharing the pwntools boundary.
#[derive(Clone)]
pub struct Context {
    pub operation: String,
    pub provider_id: String,
    pub preceding_output: Option<CapturedOutput>,
    pub configuration_key: Option<String>,
}

impl Context {
    pub fn new(operation: &str, provider_id: &str) -> Self {
        Self {
            operation: operation.to_owned(),
            provider_id: provider_id.to_owned(),
            preceding_output: None,
            configuration_key: None,
        }
    }
}

/// `{ stdout, stderr, truncated }` of a bridge snapshot (`capturedPwntoolsOutput`).
pub fn captured(snapshot: &ProcessSnapshot) -> CapturedOutput {
    CapturedOutput {
        stdout: snapshot.stdout.text.clone(),
        stderr: snapshot.stderr.text.clone(),
        truncated: snapshot.diagnostic_truncated,
        stdout_bytes: None,
        stderr_bytes: None,
        exit_code: None,
        signal: None,
    }
}

/// Combine a preceding core-decoder output with the current debugger output.
fn combined_output(
    preceding: Option<&CapturedOutput>,
    current: Option<&CapturedOutput>,
) -> Option<CapturedOutput> {
    match (preceding, current) {
        (None, current) => current.cloned(),
        (Some(preceding), None) => Some(preceding.clone()),
        (Some(preceding), Some(current)) => Some(CapturedOutput {
            stdout: format!(
                "[core decoder]\n{}\n[debugger]\n{}",
                preceding.stdout, current.stdout
            ),
            stderr: format!(
                "[core decoder]\n{}\n[debugger]\n{}",
                preceding.stderr, current.stderr
            ),
            truncated: preceding.truncated || current.truncated,
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        }),
    }
}

/// Snapshot exit code as JSON (`null` when unavailable).
fn exit_code_value(snapshot: Option<&ProcessSnapshot>) -> Value {
    snapshot
        .and_then(|snapshot| snapshot.exit_code)
        .map_or(Value::Null, |code| json!(code))
}

fn signal_value(snapshot: Option<&ProcessSnapshot>) -> Value {
    snapshot
        .and_then(|snapshot| snapshot.signal.clone())
        .map_or(Value::Null, Value::String)
}

/// Captured-output diagnostic object copied verbatim like the original.
fn captured_object(output: &CapturedOutput) -> Value {
    json!({
        "stdout": output.stdout,
        "stderr": output.stderr,
        "truncated": output.truncated,
    })
}

/// Suffix appended to resource-constraint messages when a limit report is missing.
fn limit_suffix(report: Option<&LimitReport>) -> String {
    match report {
        None => String::new(),
        Some(report) => match &report.failure {
            None => String::new(),
            Some(failure) => format!(" Effective limit report unavailable: {failure}"),
        },
    }
}

fn reported_limits(report: Option<&LimitReport>) -> Option<Value> {
    report.and_then(|report| report.limits.clone())
}

/// `pwntoolsDecoderFailure`.
pub fn decoder_failure(
    cause: Cause,
    phase: &str,
    path: &str,
    executable_path: &str,
    evidence: &FailureEvidence,
    context: &Context,
) -> AnalysisError {
    match cause {
        Cause::Command(failure) => {
            command_failure(&failure, path, executable_path, evidence, context)
        }
        Cause::Spawn { code } => errors_unavailable(
            format!(
                "Selected Python could not launch ({code}): {executable_path}. Check the configured executable, its interpreter and host execute access."
            ),
            executable_path,
            Some(&code),
            None,
            context,
        ),
        Cause::Fs { code, message } => fs_failure(phase, path, code, &message, context),
    }
}

fn command_failure(
    failure: &CommandFailure,
    path: &str,
    _executable_path: &str,
    evidence: &FailureEvidence,
    context: &Context,
) -> AnalysisError {
    let current = failure.snapshot.as_ref().map(captured);
    let combined = combined_output(context.preceding_output.as_ref(), current.as_ref());
    let output = combined.as_ref();
    let limit_report = evidence.limits.as_ref();

    if let Some(reason) = &failure.cleanup_failure {
        let mut diagnostics = map([("reason", json!(reason))]);
        if let Some(output) = output {
            diagnostics.insert("captured_output".into(), captured_object(output));
        }
        diagnostics.insert(
            "previous_error".into(),
            json!({
                "failure_kind": failure_kind(failure.reason),
                "message": failure.message,
                "exit_code": exit_code_value(failure.snapshot.as_ref()),
                "signal": signal_value(failure.snapshot.as_ref()),
                "stdout": failure.snapshot.as_ref().map_or(Value::Null, |s| json!(s.stdout.text)),
                "stderr": failure.snapshot.as_ref().map_or(Value::Null, |s| json!(s.stderr.text)),
            }),
        );
        return errors::provider_cleanup(
            &context.provider_id,
            failure.resources.clone(),
            diagnostics,
            &context.operation,
        );
    }

    let signal = failure
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.signal.as_deref());
    let exit = failure
        .snapshot
        .as_ref()
        .and_then(|snapshot| snapshot.exit_code);

    match failure.reason {
        FailureReason::Cancelled => {
            errors::with_output(AnalysisError::cancelled(&context.operation), output)
        }
        FailureReason::Timeout => errors::with_output(
            AnalysisError::timeout(&context.operation, release::TIMEOUT_MS),
            output,
        ),
        FailureReason::OutputLimit => errors::with_output(
            AnalysisError::output(&context.operation, failure.message.clone()),
            output,
        ),
        FailureReason::Process => {
            let file_size_marker = evidence
                .marker
                .as_ref()
                .is_some_and(|marker| marker.resource.as_deref() == Some("file-size"))
                && exit == Some(release::FILE_SIZE_FAILURE_EXIT)
                && signal.is_none();
            if signal == Some("SIGXFSZ") || file_size_marker {
                let base = if signal == Some("SIGXFSZ") {
                    "Owned Python terminated with SIGXFSZ; the exact signal cause is unknown."
                } else {
                    "The owned Python bridge reported EFBIG while writing a file; the exact write failure cause is unknown."
                };
                return errors::with_output(
                    AnalysisError::resource_constraint(
                        &context.operation,
                        "file-size",
                        format!("{base}{}", limit_suffix(limit_report)),
                        reported_limits(limit_report),
                    ),
                    output,
                );
            }
            if signal == Some("SIGXCPU") {
                return errors::with_output(
                    AnalysisError::resource_constraint(
                        &context.operation,
                        "cpu",
                        format!(
                            "Owned Python terminated with SIGXCPU; the exact signal cause is unknown.{}",
                            limit_suffix(limit_report)
                        ),
                        reported_limits(limit_report),
                    ),
                    output,
                );
            }
            let memory_marker = evidence
                .marker
                .as_ref()
                .is_some_and(|marker| marker.resource.as_deref() == Some("memory"))
                && exit == Some(release::MEMORY_FAILURE_EXIT)
                && signal.is_none();
            if memory_marker {
                return errors::with_output(
                    AnalysisError::resource_constraint(
                        &context.operation,
                        "memory",
                        format!(
                            "The owned Python bridge reported a memory allocation failure without a structured reply; the exact allocation cause is unknown.{}",
                            limit_suffix(limit_report)
                        ),
                        reported_limits(limit_report),
                    ),
                    output,
                );
            }
            // Fall through to the generic provider adapter failure.
            generic_adapter(failure, path, context, output, evidence)
        }
    }
}

fn generic_adapter(
    failure: &CommandFailure,
    path: &str,
    context: &Context,
    output: Option<&CapturedOutput>,
    evidence: &FailureEvidence,
) -> AnalysisError {
    let mut diagnostics = map([("phase", json!("decoder")), ("path", json!(path))]);
    if let Some(preceding) = &context.preceding_output {
        diagnostics.insert("preceding_output".into(), captured_object(preceding));
    }
    diagnostics.insert("reason".into(), json!(failure.message));
    if let Some(marker) = &evidence.marker {
        diagnostics.insert(
            "resource_failure_marker".into(),
            json!({ "resource": marker.resource, "failure": marker.failure }),
        );
    }
    diagnostics.insert("failure_kind".into(), json!(failure_kind(failure.reason)));
    diagnostics.insert(
        "exit_code".into(),
        exit_code_value(failure.snapshot.as_ref()),
    );
    diagnostics.insert("signal".into(), signal_value(failure.snapshot.as_ref()));
    diagnostics.insert(
        "stdout".into(),
        failure
            .snapshot
            .as_ref()
            .map_or(Value::Null, |s| json!(s.stdout.text)),
    );
    diagnostics.insert(
        "stderr".into(),
        failure
            .snapshot
            .as_ref()
            .map_or(Value::Null, |s| json!(s.stderr.text)),
    );
    if let Some(output) = output {
        diagnostics.insert("captured_output".into(), captured_object(output));
    }
    errors::provider_adapter(
        &context.provider_id,
        &context.operation,
        Some(diagnostics),
        None,
    )
}

fn fs_failure(
    phase: &str,
    path: &str,
    code: Option<&'static str>,
    message: &str,
    context: &Context,
) -> AnalysisError {
    if phase == "configuration" {
        let code_text = code.unwrap_or("UNKNOWN");
        return errors_unavailable(
            format!(
                "Selected Python executable is unavailable ({code_text}): {path}. Check the caller-selected path and execute access."
            ),
            path,
            Some(code_text),
            None,
            context,
        );
    }
    if phase == "artifact-read" {
        if let Some(code @ ("EACCES" | "EPERM")) = code {
            return AnalysisError::access_denied(&context.operation, path, code);
        }
        if let Some(code @ ("ENOENT" | "ENOTDIR")) = code {
            return AnalysisError::input(
                &context.operation,
                vec![InputIssue {
                    path: vec![json!("path")],
                    reason: "invalid_value",
                    message: Some(format!(
                        "Selected object could not be read ({code}): {path}."
                    )),
                    expected: None,
                    minimum: None,
                    maximum: None,
                }],
            );
        }
    }
    errors::provider_adapter(
        &context.provider_id,
        &context.operation,
        Some(map([
            ("phase", json!(phase)),
            ("path", json!(path)),
            ("reason", json!(message)),
        ])),
        None,
    )
}

fn failure_kind(reason: FailureReason) -> &'static str {
    match reason {
        FailureReason::Cancelled => "cancelled",
        FailureReason::Timeout => "timeout",
        FailureReason::OutputLimit => "output-limit",
        FailureReason::Process => "process",
    }
}

/// `pwntoolsUnavailable`: a provider-selection failure with its configuration.
pub fn errors_unavailable(
    reason: impl Into<String>,
    path: &str,
    system_code: Option<&str>,
    captured_output: Option<CapturedOutput>,
    context: &Context,
) -> AnalysisError {
    let reason = reason.into();
    let configuration_key = context
        .configuration_key
        .clone()
        .unwrap_or_else(|| "REA_PWNTOOLS_PYTHON".to_owned());
    let mut diagnostics = map([
        ("configuration_key", json!(configuration_key)),
        ("executable_path", json!(path)),
    ]);
    if let Some(code) = system_code {
        diagnostics.insert("system_code".into(), json!(code));
    }
    let mut error = AnalysisError::from(ErrorKind::ProviderSelection {
        operation: context.operation.clone(),
        reason: "provider_unavailable".to_owned(),
        requested_provider_id: context.provider_id.clone(),
        candidate_ids: vec![context.provider_id.clone()],
        rejections: vec![SelectionRejection {
            provider_id: context.provider_id.clone(),
            code: "provider_unavailable".to_owned(),
            reason: reason.clone(),
            diagnostics: Value::Object(diagnostics),
        }],
        user_message: Some(reason),
    });
    if let Some(output) = captured_output {
        error = error.with_captured_output(output);
    }
    error
}

/// A classified decoder failure cause, mirroring the TS `cause` union.
pub enum Cause {
    /// An owned-command failure.
    Command(Box<CommandFailure>),
    /// The launcher could not spawn the interpreter.
    Spawn { code: String },
    /// A filesystem error at configuration/artifact-read time.
    Fs {
        code: Option<&'static str>,
        message: String,
    },
}

/// The Linux x64 host-requirement capability error (`HOST_REQUIREMENT`).
pub fn errors_unavailable_host(provider_id: &str, operation: &str) -> AnalysisError {
    AnalysisError::capability_unavailable(provider_id, operation, release::HOST_REQUIREMENT)
        .with_user_message(release::HOST_REQUIREMENT)
}

/// Attach captured output when present.
pub fn with_output_opt(error: AnalysisError, output: Option<CapturedOutput>) -> AnalysisError {
    match output {
        Some(output) => error.with_captured_output(output),
        None => error,
    }
}
