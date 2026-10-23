//! Native UI observation and scenario orchestration (`native-macos`).
//!
//! Compatibility owners: `src/native/NativeMacOSProvider.ts`
//! (`#observeNativeUi`, `#serializeNativeUi`, `#retryNativeUiCleanup`, the
//! `execute` admission order and `#nativeUiCleanupFailure`),
//! `src/native/NativeUiObservation.ts` (`observeNativeUi`,
//! `observeWithHelper`, `finishNativeUiObservation`),
//! `src/native/NativeUiCleanupError.ts`,
//! `src/native/NativeUiInterruptionControl.ts` and
//! `src/domain/native/nativeUiObservation.ts`.
//!
//! Admission order mirrors the provider `execute`: a closed client, then
//! caller cancellation, then the per-operation body. UI operations are
//! serialized per session; pending-runtime cleanup is retried before a new
//! operation and again at shutdown.
use super::budget::{
    NATIVE_UI_DEADLINE_MS, NATIVE_UI_OUTPUT_BUDGET_BYTES, NATIVE_UI_OUTPUT_WEIGHT,
};
use super::runtime::{HelperError, NativeUiHelperRuntime};
use super::snapshot::{self, SnapshotError};
use crate::common::{active_target, create_evidence, native_macos_provider, target_subject};
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::AnalysisError;
use rea_core::analysis_error::cleanup::{provider_cleanup_error, with_cleanup_failure};
use rea_core::cancellation::Cancellation;
use rea_mcp::{SessionResource, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// `native-macos` provider id.
const IDENTITY_ID: &str = "native-macos";

/// The two native UI operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    Observe,
    Scenario,
}

impl Operation {
    pub fn name(self) -> &'static str {
        match self {
            Self::Observe => "observe_native_ui",
            Self::Scenario => "capture_native_ui_scenario",
        }
    }
}

/// Per-session native UI state: the pending-runtime cleanup set and a
/// serialization lock. Owned once by the session so shutdown retries cleanup.
///
/// Mirrors the client-level `#pendingNativeUiRuntimes` set, `#nativeUiTail`
/// serialization and the `close()` cleanup retry on `NativeMacOSClient`.
#[derive(Default)]
pub struct NativeUiState {
    /// Serializes UI operations and their cleanup retries (`#serializeNativeUi`).
    serialize: Mutex<()>,
    inner: Mutex<StateInner>,
}

#[derive(Default)]
struct StateInner {
    /// Runtimes whose cleanup has not been confirmed (`#pendingNativeUiRuntimes`).
    pending: Vec<Arc<NativeUiHelperRuntime>>,
    /// Set once the session closed its native UI state.
    closed: bool,
}

impl SessionResource for NativeUiState {
    /// Shutdown cleanup retry (`NativeMacOSClient.close` native UI path): retry
    /// every pending runtime; a remaining failure keeps ownership for retry.
    fn close(&self) -> Result<(), AnalysisError> {
        let _serialized = self
            .serialize
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let failures = self.retry_cleanup();
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.closed = true;
        if failures.is_empty() {
            Ok(())
        } else {
            Err(cleanup_failure(&failures, "close_binary", None))
        }
    }
}

impl NativeUiState {
    /// Retry every pending runtime's cleanup; return the ones still failing.
    fn retry_cleanup(&self) -> Vec<CleanupFailure> {
        let pending = {
            let inner = self
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            inner.pending.clone()
        };
        let mut failures = Vec::new();
        let mut resolved = Vec::new();
        for runtime in pending {
            match runtime.close() {
                Ok(()) => resolved.push(Arc::as_ptr(&runtime)),
                Err(reason) => failures.push(CleanupFailure {
                    resources: runtime.resources(),
                    reason,
                    runtime,
                }),
            }
        }
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner
            .pending
            .retain(|runtime| !resolved.contains(&Arc::as_ptr(runtime)));
        failures
    }

    fn add_pending(&self, runtime: Arc<NativeUiHelperRuntime>) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .push(runtime);
    }

    fn remove_pending(&self, runtime: &Arc<NativeUiHelperRuntime>) {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pending
            .retain(|existing| !Arc::ptr_eq(existing, runtime));
    }

    fn is_closed(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .closed
    }
}

/// One unresolved runtime cleanup (`{ runtime, cause }`).
struct CleanupFailure {
    resources: Vec<String>,
    reason: String,
    runtime: Arc<NativeUiHelperRuntime>,
}

/// `new NativeUiCleanupError(failures, operation, partialObservation)`.
fn cleanup_failure(
    failures: &[CleanupFailure],
    operation: &str,
    partial: Option<Value>,
) -> AnalysisError {
    // Live resources are those of runtimes whose lease is not yet released.
    let resources: Vec<String> = failures
        .iter()
        .filter(|failure| !failure.runtime.released())
        .flat_map(|failure| failure.runtime.resources())
        .collect();
    let mut diagnostics = Map::new();
    diagnostics.insert(
        "reason".into(),
        json!("Native UI runtime cleanup remains incomplete"),
    );
    diagnostics.insert(
        "failures".into(),
        Value::Array(
            failures
                .iter()
                .map(|failure| {
                    json!({
                        "resources": failure.resources,
                        "reason": failure.reason,
                    })
                })
                .collect(),
        ),
    );
    let mut error =
        provider_cleanup_error(IDENTITY_ID, resources, diagnostics, Some(operation), None);
    if let Some(partial) = partial {
        error.partial_observation = Some(partial);
    }
    error
}

/// `#observeNativeUi(operation, parameters, signal)` inside `#serializeNativeUi`.
pub fn observe_native_ui(
    context: &ToolContext<'_>,
    operation: Operation,
    input: Value,
) -> ToolOutput {
    let name = operation.name();
    // `execute` admission order: a cancelled caller fails before admission.
    if context.cancellation.reason().is_some() {
        return AnalysisError::cancelled(name).into();
    }
    context.progress.report(name, "started");
    let state = context.session.state::<NativeUiState>();
    context.session.own_once(Arc::clone(&state));

    // `#serializeNativeUi`: one UI operation (and its cleanup retry) at a time.
    let _serialized = state
        .serialize
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let output = run_serialized(context, operation, &state, &input);
    context.progress.report(
        name,
        if matches!(output, ToolOutput::Failure(_)) {
            "failed"
        } else {
            "completed"
        },
    );
    output
}

fn run_serialized(
    context: &ToolContext<'_>,
    operation: Operation,
    state: &Arc<NativeUiState>,
    input: &Value,
) -> ToolOutput {
    let name = operation.name();
    if state.is_closed() {
        return AnalysisError::capability_unavailable(
            IDENTITY_ID,
            name,
            "Native provider client is closed",
        )
        .into();
    }
    // Retry earlier incomplete cleanup before admitting a new operation.
    let earlier = state.retry_cleanup();
    if !earlier.is_empty() {
        return cleanup_failure(&earlier, name, None).into();
    }
    // The admitted target, exactly as `active_target`/`NoBinaryOpenError`.
    let target = match active_target(context) {
        Ok(target) => target,
        Err(error) => return error.into(),
    };

    let runtime = Arc::new(NativeUiHelperRuntime::new(
        context.session.environment().clone(),
    ));
    state.add_pending(Arc::clone(&runtime));

    let started = Instant::now();
    let result = observe_with_helper(context, operation, &target, input, &runtime, started);

    // `runtime.close()` after the observation; a failure composes cleanup.
    match runtime.close() {
        Ok(()) => {
            state.remove_pending(&runtime);
            finish(result, operation, started, &context.cancellation)
                .and_then(|report| evidence_from_report(operation, &target, input.clone(), report))
                .into()
        }
        Err(reason) => {
            let result = finish(result, operation, started, &context.cancellation);
            let partial = match &result {
                Ok(report) => Some(report.clone()),
                Err(_) => None,
            };
            let failures = [CleanupFailure {
                resources: runtime.resources(),
                reason,
                runtime: Arc::clone(&runtime),
            }];
            let cleanup = cleanup_failure(&failures, name, partial);
            match result {
                Ok(_) => cleanup.into(),
                Err(primary) => with_cleanup_failure(primary, cleanup, name).into(),
            }
        }
    }
}

/// `finishNativeUiObservation`: a validated report survives cancellation
/// observed at the finalization boundary, but the deadline/caller interruption
/// replaces a success with a timeout/cancelled error.
fn finish(
    result: Result<Value, AnalysisError>,
    operation: Operation,
    started: Instant,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    let report = result?;
    match interruption(operation, started, cancellation) {
        Some(mut error) => {
            error = error.retain_partial_observation(report);
            Err(error)
        }
        None => Ok(report),
    }
}

/// The interruption class, if the deadline elapsed or the caller cancelled.
///
/// `NativeUiInterruptionControl.error`: the deadline is an `AnalysisTimeoutError`
/// and a caller abort is an `AnalysisCancelledError`. The deadline is checked
/// first only when the caller has not aborted, matching the "already aborted"
/// caller-priority ordering.
fn interruption(
    operation: Operation,
    started: Instant,
    cancellation: &Cancellation,
) -> Option<AnalysisError> {
    let name = operation.name();
    if cancellation.reason().is_some() {
        return Some(AnalysisError::cancelled(name));
    }
    if started.elapsed().as_millis() as u64 >= NATIVE_UI_DEADLINE_MS {
        return Some(AnalysisError::timeout(name, NATIVE_UI_DEADLINE_MS));
    }
    None
}

/// `observeWithHelper`: capture the initial snapshot, run each step, then
/// project the ordered before/after report with the fixed limitations.
fn observe_with_helper(
    context: &ToolContext<'_>,
    operation: Operation,
    target: &BinaryTarget,
    input: &Value,
    runtime: &NativeUiHelperRuntime,
    started: Instant,
) -> Result<Value, AnalysisError> {
    let name = operation.name();
    // `isMachOFormat`: native UI requires an active Mach-O executable/app.
    if target.kind != "executable" || !is_macho_format(&target.format) {
        return Err(AnalysisError::capability_unavailable(
            IDENTITY_ID,
            name,
            "Native UI observation requires an active Mach-O executable or app target",
        ));
    }
    let request = Request::from_input(input);
    if !request.screenshot && !request.accessibility {
        // `new AnalysisInputError(operation, { cause })`, no public issues.
        return Err(AnalysisError::input(name, Vec::new()));
    }

    let steps = match operation {
        Operation::Observe => Vec::new(),
        Operation::Scenario => input
            .get("steps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };

    let mut context_state = TakeState {
        launch_time: None,
        output_bytes: 0,
    };

    let initial = take(
        context,
        operation,
        target,
        &request,
        runtime,
        &mut context_state,
        None,
        started,
    )?;

    let mut results: Vec<Value> = Vec::new();
    let mut before = initial.clone();
    let mut terminal_failure: Option<AnalysisError> = None;
    for (index, step) in steps.iter().enumerate() {
        let kind = step.get("kind").and_then(Value::as_str).unwrap_or_default();
        if kind == "wait" {
            let milliseconds = step
                .get("milliseconds")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            wait_for_abortable_delay(milliseconds, &context.cancellation);
        }
        let action = if kind == "wait" {
            None
        } else {
            Some(step.clone())
        };
        match take(
            context,
            operation,
            target,
            &request,
            runtime,
            &mut context_state,
            action,
            started,
        ) {
            Ok(after) => {
                results.push(json!({
                    "index": index,
                    "kind": kind,
                    "before": before,
                    "after": after,
                    "outcome": "completed",
                    "reason": null,
                }));
                before = after;
            }
            Err(error) => {
                let outcome = if error.tag() == "AnalysisCancelledError" {
                    "cancelled"
                } else {
                    "failed"
                };
                results.push(json!({
                    "index": index,
                    "kind": kind,
                    "before": before,
                    "after": null,
                    "outcome": outcome,
                    "reason": error.message(),
                }));
                terminal_failure = Some(error);
                break;
            }
        }
    }

    let report = json!({
        "target_sha256": target.sha256,
        "initial": initial,
        "steps": results,
        "restore": "leave-as-is",
        "limitations": limitations(),
    });

    match terminal_failure {
        None => Ok(report),
        Some(error) => Err(error.retain_partial_observation(report)),
    }
}

/// Mutable accounting carried across captures within one observation.
struct TakeState {
    launch_time: Option<f64>,
    output_bytes: usize,
}

/// `take(action)`: one helper capture with window-identity and budget checks.
#[allow(clippy::too_many_arguments)]
fn take(
    context: &ToolContext<'_>,
    operation: Operation,
    target: &BinaryTarget,
    request: &Request,
    runtime: &NativeUiHelperRuntime,
    state: &mut TakeState,
    action: Option<Value>,
    started: Instant,
) -> Result<Value, AnalysisError> {
    let name = operation.name();
    // An interruption observed before the capture replaces it.
    if let Some(error) = interruption(operation, started, &context.cancellation) {
        return Err(error);
    }
    let mut parameters = Map::new();
    parameters.insert("pid".into(), json!(request.pid));
    parameters.insert("window_id".into(), json!(request.window_id));
    parameters.insert("executable".into(), json!(target.path));
    parameters.insert("sha256".into(), json!(target.sha256));
    if let Some(launch_time) = state.launch_time {
        parameters.insert("launch_time".into(), json!(launch_time));
    }
    parameters.insert("screenshot".into(), json!(request.screenshot));
    parameters.insert("accessibility".into(), json!(request.accessibility));
    parameters.insert("max_nodes".into(), json!(request.max_nodes));
    if let Some(action) = action {
        parameters.insert("action".into(), action);
    }

    let response = match runtime.invoke(&Value::Object(parameters), &context.cancellation) {
        Ok(response) => response,
        Err(error) => return Err(helper_error(operation, error)),
    };

    // `responseSchema.parse`: discriminated on `ok`.
    let validated = match snapshot::validate_response(&response) {
        Ok(validated) => validated,
        Err(error) => return Err(response_error(operation, error)),
    };
    let result = match validated {
        snapshot::Response::Ok(result) => result,
        snapshot::Response::Err { code, message } => {
            return Err(AnalysisError::capability_unavailable(
                IDENTITY_ID,
                name,
                format!("{code}: {message}"),
            ));
        }
    };

    // Helper window must match the selected target process/window.
    let window = result.get("window").cloned().unwrap_or(Value::Null);
    let window_pid = window.get("pid").and_then(Value::as_i64);
    let window_id = window.get("window_id").and_then(Value::as_i64);
    let window_executable = window.get("executable").and_then(Value::as_str);
    let window_launch = window.get("launch_time").and_then(Value::as_f64);
    let mismatch = window_pid != Some(request.pid)
        || window_id != Some(request.window_id)
        || window_executable != Some(target.path.as_str())
        || state
            .launch_time
            .is_some_and(|launch_time| window_launch != Some(launch_time));
    if mismatch {
        return Err(AnalysisError::capability_unavailable(
            IDENTITY_ID,
            name,
            "Native helper returned a different target process or window",
        ));
    }
    state.launch_time = window_launch;

    // Scenario output is charged at twice the encoded result size.
    let encoded = serde_json::to_string(&result)
        .map(|text| text.len())
        .unwrap_or(0);
    state.output_bytes += NATIVE_UI_OUTPUT_WEIGHT * encoded;
    if state.output_bytes > NATIVE_UI_OUTPUT_BUDGET_BYTES {
        return Err(AnalysisError::capability_unavailable(
            IDENTITY_ID,
            name,
            "Scenario captures exceeded the 64 MiB output budget",
        ));
    }
    Ok(result)
}

/// Map a helper runtime failure to the provider's typed failure.
fn helper_error(operation: Operation, error: HelperError) -> AnalysisError {
    let name = operation.name();
    match error {
        HelperError::Cancelled => AnalysisError::cancelled(name),
        HelperError::Timeout => AnalysisError::timeout(name, NATIVE_UI_DEADLINE_MS),
        HelperError::Adapter { reason } => provider_adapter_failure(name, reason),
    }
}

/// `responseSchema.parse` / snapshot validation failure → ProviderAdapterError
/// with the helper's diagnostics.
fn response_error(operation: Operation, error: SnapshotError) -> AnalysisError {
    provider_adapter_failure(operation.name(), error.into_reason())
}

/// `new ProviderAdapterError("native-macos", operation, { cause, diagnostics })`.
fn provider_adapter_failure(operation: &str, reason: String) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("helper_path".into(), json!(helper_path()));
    diagnostics.insert("reason".into(), json!(reason));
    diagnostics.insert(
        "remediation".into(),
        json!(
            "Native helper failed, timed out, or returned malformed capture data; install compatible Xcode command-line tools and inspect local OS permissions"
        ),
    );
    AnalysisError::provider_adapter(IDENTITY_ID, operation).with_diagnostics(diagnostics)
}

/// Deviation from the TypeScript `helper` constant (a repo path): the sources
/// are embedded, so this reports the embedded source's logical path.
fn helper_path() -> &'static str {
    "bridge/native/ReaNativeUI.swift"
}

/// `isMachOFormat`.
fn is_macho_format(format: &str) -> bool {
    format == "mach-o" || format == "mach-o-universal"
}

/// `waitForAbortableDelay(milliseconds, signal)`.
fn wait_for_abortable_delay(milliseconds: u64, cancellation: &Cancellation) {
    let deadline = Instant::now() + std::time::Duration::from_millis(milliseconds);
    while Instant::now() < deadline {
        if cancellation.reason().is_some() {
            return;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        std::thread::sleep(remaining.min(std::time::Duration::from_millis(10)));
    }
}

/// The exact native UI limitation strings.
fn limitations() -> Vec<String> {
    vec![
        "Only the explicitly selected already-running process/window is admitted. REA starts no target process and does not change permissions, foreground applications, or restore application data.".into(),
        "Click uses AXPress; scroll uses AXIncrement/AXDecrement; key-entry sets the selected element's AXValue. Unsupported elements fail without global event fallback.".into(),
        "Each completed action is followed immediately by capture; delayed UI changes require explicit wait steps. A failed after-capture can follow a completed action, so failure does not prove absence of application effects.".into(),
        "Scenarios can change app data, cause app network activity and persist changes. The caller explicitly chooses leave-as-is; automatic restoration is unsupported.".into(),
        "Window matching uses exact PID and window ID for screenshots and unique accessibility geometry. Accessibility paths can change as the UI changes; stale or ambiguous paths fail. Screenshots are scaled to at most 2048 pixels; scenario output is budgeted at 64 MiB and execution has a 180-second deadline.".into(),
    ]
}

/// The validated input fields shared by both operations.
struct Request {
    pid: i64,
    window_id: i64,
    screenshot: bool,
    accessibility: bool,
    max_nodes: i64,
}

impl Request {
    /// Read the framework-validated input (defaults already applied).
    fn from_input(input: &Value) -> Self {
        Self {
            pid: input.get("pid").and_then(Value::as_i64).unwrap_or_default(),
            window_id: input
                .get("window_id")
                .and_then(Value::as_i64)
                .unwrap_or_default(),
            screenshot: input
                .get("screenshot")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            accessibility: input
                .get("accessibility")
                .and_then(Value::as_bool)
                .unwrap_or(true),
            max_nodes: input
                .get("max_nodes")
                .and_then(Value::as_i64)
                .unwrap_or(500),
        }
    }
}

/// Build the provider Evidence for a successful observation.
pub fn evidence_from_report(
    operation: Operation,
    target: &BinaryTarget,
    evidence_parameters: Value,
    report: Value,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let limitations = report
        .get("limitations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let subject = target_subject(target);
    create_evidence(
        operation.name(),
        Some(&subject),
        &native_macos_provider(),
        evidence_parameters,
        report,
        limitations,
        Vec::new(),
    )
}
