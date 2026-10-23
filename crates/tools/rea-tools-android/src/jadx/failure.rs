//! Freeze failure selection and present diagnostics after owned finalization.
//!
//! Compatibility owner: `src/android/JadxFailure.ts`. The native flow raises
//! `AnalysisError` for most failures already; this module maps the remaining
//! transport-observed physical/protocol/startup failures to their typed form
//! with the exact TS message strings, and retains the partial observation.

use super::release::JADX_PROVIDER_ID;
use super::transport::{JadxTransport, TransportFailure};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

/// Context for selecting a typed failure.
pub struct FailureContext<'a> {
    /// The primary cause (an `AnalysisError` when one was already raised).
    pub cause: FailureCause,
    pub operation: &'a str,
    pub timeout_ms: u64,
    /// Whether the whole-operation deadline elapsed.
    pub timed_out: bool,
    /// Whether the caller cancellation fired.
    pub cancelled: Option<String>,
    pub transport: Option<&'a JadxTransport>,
    /// Whether the session established the protocol (connected).
    pub initialized: bool,
    /// The launch command, for a startup failure message.
    pub command: String,
}

/// The primary cause of a provider failure.
pub enum FailureCause {
    /// An already-typed analysis error (configuration, input, output, ...).
    Analysis(AnalysisError),
    /// A transport/physical failure classified from its observed kind.
    Transport,
}

/// `captureJadxFailure(context)`: project the typed failure once and attach
/// the retained partial observation.
pub fn capture_jadx_failure(context: FailureContext<'_>, partial: Option<Value>) -> AnalysisError {
    let mut projected = observe(&context);
    if let Some(partial) = partial
        && partial.get("evidence_id").is_some()
    {
        projected = projected.retain_partial_observation(partial);
    }
    projected
}

fn observe(context: &FailureContext<'_>) -> AnalysisError {
    // A primary analysis error already classified by a lower layer wins.
    if let FailureCause::Analysis(error) = &context.cause {
        return error.clone();
    }

    let output = context.transport.and_then(JadxTransport::diagnostics);
    let observed = context.transport.and_then(JadxTransport::observed_failure);

    // An interruption boundary selected a cancellation/timeout reason.
    if let Some(TransportFailure::Interrupted { reason }) = observed {
        return interruption_failure(context, Some(reason.clone()));
    }

    if let Some(TransportFailure::Protocol { message }) = observed {
        return present_output(context, message.clone(), output);
    }
    if matches!(
        observed,
        Some(TransportFailure::Process { .. }) | Some(TransportFailure::Exit)
    ) {
        return physical_failure(context, output);
    }
    if let Some(reason) = &context.cancelled {
        return cancelled(context, Some(reason.clone()), output);
    }
    if context.timed_out {
        return timeout(context, output);
    }
    physical_failure(context, output)
}

fn interruption_failure(context: &FailureContext<'_>, reason: Option<String>) -> AnalysisError {
    let output = context.transport.and_then(JadxTransport::diagnostics);
    if context.timed_out {
        return timeout(context, output);
    }
    if context.cancelled.is_some() {
        return cancelled(context, reason, output);
    }
    physical_failure(context, output)
}

fn cancelled(
    context: &FailureContext<'_>,
    _reason: Option<String>,
    output: Option<rea_core::analysis_error::CapturedOutput>,
) -> AnalysisError {
    let mut error = AnalysisError::cancelled(context.operation);
    error.captured_output = output;
    error
}

fn timeout(
    context: &FailureContext<'_>,
    output: Option<rea_core::analysis_error::CapturedOutput>,
) -> AnalysisError {
    let mut error = AnalysisError::timeout(context.operation, context.timeout_ms);
    error.captured_output = output;
    error
}

fn present_output(
    context: &FailureContext<'_>,
    reason: String,
    output: Option<rea_core::analysis_error::CapturedOutput>,
) -> AnalysisError {
    let mut error = AnalysisError::output(context.operation, reason);
    error.captured_output = output;
    error
}

fn physical_failure(
    context: &FailureContext<'_>,
    output: Option<rea_core::analysis_error::CapturedOutput>,
) -> AnalysisError {
    if !context.initialized {
        return startup_failure(context, output);
    }
    let mut error = crate::common::errors::provider_adapter(
        JADX_PROVIDER_ID,
        context.operation,
        None,
        Some(crate::common::errors::object(json!({
            "reason": physical_reason(context),
        }))),
    );
    error.captured_output = output;
    error
}

fn physical_reason(context: &FailureContext<'_>) -> String {
    match context.transport.and_then(JadxTransport::observed_failure) {
        Some(TransportFailure::Process { message }) => message.clone(),
        Some(TransportFailure::Protocol { message }) => message.clone(),
        Some(TransportFailure::Interrupted { reason }) => reason.clone(),
        Some(TransportFailure::Exit) => "The JADX protocol process exited".to_owned(),
        None => "The JADX operation failed".to_owned(),
    }
}

fn startup_failure(
    context: &FailureContext<'_>,
    output: Option<rea_core::analysis_error::CapturedOutput>,
) -> AnalysisError {
    let launcher_stderr = output
        .as_ref()
        .map(|output| output.stderr.len())
        .unwrap_or(0);
    let truncated = output
        .as_ref()
        .map(|output| output.truncated)
        .unwrap_or(false);
    let cause = physical_reason(context);
    let stderr_note = if output.is_none() || launcher_stderr == 0 {
        "No launcher stderr was observed."
    } else {
        "Review the retained launcher diagnostics."
    };
    let truncated_note = if truncated {
        " Diagnostics are incomplete."
    } else {
        ""
    };
    let reason = format!(
        "Java could not start REA's Android bridge using {}: {cause}. {stderr_note}{truncated_note} Review the selected Java/JADX configuration; for a JVM memory limit, review REA_JADX_HEAP_MIB and inherited JVM options such as JAVA_TOOL_OPTIONS.",
        context.command
    );
    let mut error = crate::common::errors::capability_unavailable(
        JADX_PROVIDER_ID,
        context.operation,
        reason.clone(),
        Some(reason),
        None,
    );
    error.captured_output = output;
    error
}
