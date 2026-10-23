//! Caller-selected reverse-engineering commands: GNU objdump and one-shot Rizin.
//!
//! Compatibility owners: `src/server/registerReverseEngineeringTools.ts`,
//! `src/application/reverse/ReverseEngineeringService.ts`,
//! `src/application/reverse/ReverseEngineeringCommandPort.ts`,
//! `src/composition/reverseEngineering.ts`, `src/objdump/ObjdumpCommand.ts`,
//! `src/rizin/RizinCommand.ts` and `src/domain/reverseEngineering.ts`.
//!
//! The binary-session admission hooks the server passes in the TypeScript
//! registration (`withAdmittedAnalysis`, `withAdmittedExternalMutation`,
//! `invalidateSnapshotForExternalMutation`) are owned by the binary-session
//! crate and are not available here. This module therefore implements the
//! non-session path the registration takes when those hooks are `undefined`:
//! both tools call the shared service directly, Rizin without external-mutation
//! admission or snapshot invalidation.
mod command;
mod digest;
mod schema;

use crate::errors;
use crate::process::{
    self, CommandError, CommandFailure, FailureReason, OwnedProcess, ProcessSnapshot, ProcessSpec,
    StreamSnapshot,
};
use command::ProviderCommand;
use digest::{DigestError, digest_file};
use rea_core::analysis_error::{AnalysisError, CapturedOutput, CleanupObservation, ErrorKind};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::{Registry, SessionResource, ToolContext};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

const OBJDUMP: &str = "inspect_with_objdump";
const RIZIN: &str = "execute_rizin_command";

const DEFAULT_TIMEOUT_MS: u64 = 120_000;
const MAX_COMBINED_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
/// Eight concurrent captures bound retained provider output to 128 MiB.
const MAX_CONCURRENT_REVERSE_ENGINEERING_OPERATIONS: usize = 8;

pub fn register(registry: &mut Registry) {
    registry.handle(OBJDUMP, |context, input| {
        inspect_with_objdump(context, &input).into()
    });
    registry.handle(RIZIN, |context, input| {
        execute_rizin_command(context, &input).into()
    });
}

// ---------------------------------------------------------------------------
// Session-owned service state
// ---------------------------------------------------------------------------

/// One retained provider owner whose cleanup could not be confirmed.
struct Retained {
    owner: OwnedProcess,
    reason: String,
    resources: Vec<String>,
    retry_failure: Option<AnalysisError>,
}

#[derive(Default)]
struct ServiceState {
    closing: bool,
    active_operations: usize,
    pending_cleanup: Vec<Retained>,
}

/// Shared reverse-engineering workflow state for one connection
/// (`ReverseEngineeringService`).
#[derive(Default)]
struct ReverseService {
    state: Mutex<ServiceState>,
}

impl ReverseService {
    fn lock(&self) -> std::sync::MutexGuard<'_, ServiceState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// `retryCleanup(operation)`: settle retained owners before admitting work.
    fn retry_cleanup(&self, operation: &str) -> Result<(), AnalysisError> {
        let mut state = self.lock();
        let mut failure: Option<AnalysisError> = None;
        let mut index = 0;
        while index < state.pending_cleanup.len() {
            let stopped = state.pending_cleanup[index].owner.stop();
            match stopped {
                process::StopResult::Stopped => {
                    state.pending_cleanup.remove(index);
                }
                process::StopResult::Incomplete { reason } => {
                    let retained = &mut state.pending_cleanup[index];
                    retained.reason = reason.clone();
                    // The first retry failure is retained and reported again
                    // by later retries, exactly like `retained.retryFailure`.
                    let error = retained
                        .retry_failure
                        .get_or_insert_with(|| {
                            AnalysisError::output(
                                operation,
                                "A previous provider process still requires cleanup.",
                            )
                            .with_cleanup(reason, retained.resources.clone())
                        })
                        .clone();
                    if failure.is_none() {
                        failure = Some(error);
                    }
                    index += 1;
                }
            }
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Retain an owner whose cleanup was reported incomplete.
    fn register_cleanup(&self, owner: OwnedProcess, reason: String, resources: Vec<String>) {
        self.lock().pending_cleanup.push(Retained {
            owner,
            reason,
            resources,
            retry_failure: None,
        });
    }
}

impl SessionResource for ReverseService {
    fn close(&self) -> Result<(), AnalysisError> {
        {
            let mut state = self.lock();
            state.closing = true;
        }
        // `#closeActiveOperationsAndCleanup`: active operations run on the
        // caller thread, so only retained cleanup can remain here.
        self.retry_cleanup("reverse_engineering_cleanup")
    }
}

fn service(context: &ToolContext<'_>) -> Arc<ReverseService> {
    let state = context.session.state::<ReverseService>();
    context.session.own_once::<ReverseService>(state.clone());
    state
}

// ---------------------------------------------------------------------------
// Tool entry points
// ---------------------------------------------------------------------------

fn inspect_with_objdump(
    context: &ToolContext<'_>,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    if !schema::objdump_parses(input) {
        return Err(AnalysisError::input(OBJDUMP, Vec::new()));
    }
    let environment = context.session.environment();
    let profile = command::objdump_command(input, environment);
    let architectures = input.get("operation").and_then(Value::as_str) == Some("architectures");
    let path = if architectures {
        None
    } else {
        input.get("path").and_then(Value::as_str).map(str::to_owned)
    };
    // `parameters`: the parsed input, dropping an omitted optional `symbol`.
    let parameters = objdump_parameters(input);
    observe(
        context,
        OBJDUMP,
        &profile,
        path.as_deref(),
        parameters,
        environment,
    )
}

fn execute_rizin_command(
    context: &ToolContext<'_>,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    if !schema::rizin_parses(input) {
        return Err(AnalysisError::input(RIZIN, Vec::new()));
    }
    let environment = context.session.environment();
    let profile = command::rizin_command(input, environment);
    let path = input.get("path").and_then(Value::as_str).map(str::to_owned);
    observe(
        context,
        RIZIN,
        &profile,
        path.as_deref(),
        input.clone(),
        environment,
    )
}

/// `parameters` for objdump: parsed input with an absent `symbol` omitted.
fn objdump_parameters(input: &Value) -> Value {
    let Some(object) = input.as_object() else {
        return input.clone();
    };
    let mut parameters = Map::new();
    for (key, value) in object {
        if key == "symbol" && value.is_null() {
            continue;
        }
        parameters.insert(key.clone(), value.clone());
    }
    Value::Object(parameters)
}

// ---------------------------------------------------------------------------
// Observation workflow (`#observe` / `#observeProvider`)
// ---------------------------------------------------------------------------

fn observe(
    context: &ToolContext<'_>,
    operation: &'static str,
    profile: &ProviderCommand,
    path: Option<&str>,
    parameters: Value,
    environment: &HashMap<String, String>,
) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    let service = service(context);

    // `#observe`: cancellation, closed and concurrency checks.
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    {
        let mut state = service.lock();
        if state.closing {
            return Err(AnalysisError::output(
                operation,
                "Reverse-engineering service is closed.",
            ));
        }
        if state.active_operations >= MAX_CONCURRENT_REVERSE_ENGINEERING_OPERATIONS {
            return Err(AnalysisError::resource_constraint(
                operation,
                "transport",
                "Concurrent reverse-engineering operation capacity reached.",
                Some(json!({
                    "max_concurrent_operations": MAX_CONCURRENT_REVERSE_ENGINEERING_OPERATIONS,
                    "active_operations": state.active_operations,
                })),
            ));
        }
        state.active_operations += 1;
    }
    struct ReleaseActive<'a>(&'a ReverseService);
    impl Drop for ReleaseActive<'_> {
        fn drop(&mut self) {
            self.0.lock().active_operations -= 1;
        }
    }
    let _release = ReleaseActive(&service);

    observe_provider(
        &service,
        operation,
        profile,
        path,
        &parameters,
        environment,
        cancellation,
    )
}

#[allow(clippy::too_many_lines)]
fn observe_provider(
    service: &ReverseService,
    operation: &'static str,
    profile: &ProviderCommand,
    path: Option<&str>,
    parameters: &Value,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    let command = profile.executable.clone();
    let args = profile.arguments.clone();
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    // `service.retryCleanup(operation)` before the provider call.
    service.retry_cleanup(operation)?;

    let absolute_path = path.map(command::absolute_caller_path);

    // Pre-run digest.
    let mut digest: Option<String> = None;
    if let Some(absolute) = &absolute_path {
        match digest_file(absolute, cancellation, DEFAULT_TIMEOUT_MS) {
            Ok(value) => digest = Some(value),
            Err(error) => {
                return Err(digest_failure(
                    operation,
                    &command,
                    absolute,
                    &error,
                    cancellation,
                ));
            }
        }
    }

    // Run the owned provider command and classify its outcome.
    let run = run_command(
        service,
        &command,
        &args,
        &profile.environment_overrides,
        environment,
        cancellation,
    );

    let mut stdout = String::new();
    let mut stderr = String::new();
    let mut stdout_bytes = 0usize;
    let mut stderr_bytes = 0usize;
    let mut exit_code: Value = json!(0);
    let mut signal_name: Option<String> = None;
    let mut output_truncated = false;
    let mut stdout_invalid_utf8 = false;
    let mut stderr_invalid_utf8 = false;
    let mut cleanup_incomplete = false;
    let mut cleanup_only_failure = false;
    let mut completion_status = "complete";
    let mut failure: Option<AnalysisError> = None;
    let mut early_failure: Option<AnalysisError> = None;

    match run {
        Ok(success) => {
            stdout = success.stdout.text;
            stderr = success.stderr.text;
            stdout_bytes = success.stdout.bytes;
            stderr_bytes = success.stderr.bytes;
            stdout_invalid_utf8 = success.stdout.invalid_utf8;
            stderr_invalid_utf8 = success.stderr.invalid_utf8;
        }
        Err(cause) => {
            let aborted = cancellation.reason().is_some();
            let code = cause.code.clone();
            let code_str = code.as_deref();

            // `E2BIG`: argument list exceeds the launch limit.
            if early_failure.is_none() && code_str == Some("E2BIG") {
                let argument_bytes: usize = args
                    .iter()
                    .enumerate()
                    .map(|(index, argument)| argument.len() + usize::from(index != 0))
                    .sum();
                early_failure = Some(with_cleanup(
                    AnalysisError::resource_constraint(
                        operation,
                        "transport",
                        "The host rejected the provider command because its argument list exceeds the process launch limit.",
                        Some(json!({ "argument_bytes": argument_bytes })),
                    ),
                    &cause,
                ));
            }

            // `capture === undefined || ENOENT || ERR_PROVIDER_LAUNCH`: no output.
            let no_capture = !cause.has_capture
                || code_str == Some("ENOENT")
                || code_str == Some("ERR_PROVIDER_LAUNCH");
            if early_failure.is_none() && no_capture {
                if aborted || code_str == Some("ABORT_ERR") {
                    early_failure = Some(with_cleanup(AnalysisError::cancelled(operation), &cause));
                } else if code_str == Some("ETIMEDOUT") {
                    early_failure = Some(with_cleanup(
                        AnalysisError::timeout(operation, DEFAULT_TIMEOUT_MS),
                        &cause,
                    ));
                } else if code_str == Some("EACCES") || code_str == Some("EPERM") {
                    early_failure = Some(with_cleanup(
                        AnalysisError::access_denied(operation, &command, code_str.unwrap_or("")),
                        &cause,
                    ));
                } else {
                    let provider = if operation == OBJDUMP {
                        "objdump"
                    } else {
                        "rizin"
                    };
                    let detail = code_str.unwrap_or("unknown error");
                    early_failure = Some(with_cleanup(
                        AnalysisError::capability_unavailable(
                            provider,
                            operation,
                            format!("Unable to run configured command ({detail})"),
                        ),
                        &cause,
                    ));
                }
            }

            if early_failure.is_none() && cause.has_capture {
                stdout = cause.stdout.clone();
                stderr = cause.stderr.clone();
                stdout_bytes = cause.stdout_bytes;
                stderr_bytes = cause.stderr_bytes;
                exit_code = code_to_value(&cause.code);
                signal_name = cause.signal.clone();
                output_truncated = cause.output_truncated;
                if cause.collection_failure {
                    exit_code = Value::Null;
                    completion_status = "unknown";
                }
                let captured = CapturedOutput {
                    stdout: stdout.clone(),
                    stderr: stderr.clone(),
                    truncated: output_truncated,
                    stdout_bytes: Some(stdout_bytes as u64),
                    stderr_bytes: Some(stderr_bytes as u64),
                    exit_code: Some(if !cause.collection_failure {
                        numeric_code(&cause.code)
                    } else {
                        None
                    }),
                    signal: Some(cause.signal.clone()),
                };

                if aborted || code_str == Some("ABORT_ERR") {
                    failure = Some(with_cleanup(
                        AnalysisError::cancelled(operation).with_captured_output(captured.clone()),
                        &cause,
                    ));
                } else if code_str == Some("ETIMEDOUT") {
                    failure = Some(with_cleanup(
                        AnalysisError::timeout(operation, DEFAULT_TIMEOUT_MS)
                            .with_captured_output(captured.clone()),
                        &cause,
                    ));
                } else if code_str == Some("EACCES") || code_str == Some("EPERM") {
                    failure = Some(with_cleanup(
                        AnalysisError::access_denied(operation, &command, code_str.unwrap_or(""))
                            .with_captured_output(captured.clone()),
                        &cause,
                    ));
                }

                if cause.cleanup.is_some() {
                    cleanup_incomplete = true;
                    if failure.is_none() {
                        cleanup_only_failure = !cause.collection_failure
                            && !cause.output_truncated
                            && !cause.killed()
                            && cause.signal.is_none()
                            && numeric_code(&cause.code).is_some()
                            && !aborted;
                        let mut error = AnalysisError::output(
                            operation,
                            "Provider process cleanup remains incomplete.",
                        )
                        .with_captured_output(captured.clone());
                        if let Some(cleanup) = &cause.cleanup {
                            error.cleanup = Some(cleanup.clone());
                        }
                        // `cleanupOnly` keeps the failure out of the limitation list.
                        error.cleanup_incomplete = Some(true);
                        failure = Some(error);
                    }
                }

                if failure.is_none() && cause.collection_failure {
                    failure = Some(
                        AnalysisError::output(operation, "Provider output collection failed.")
                            .with_captured_output(captured.clone()),
                    );
                }

                if cause.killed() || cause.signal.is_some() || numeric_code(&cause.code).is_none() {
                    exit_code = Value::Null;
                    completion_status = "unknown";
                }

                stdout_invalid_utf8 = cause.stdout_invalid_utf8;
                stderr_invalid_utf8 = cause.stderr_invalid_utf8;
            }

            if let Some(error) = early_failure {
                return Err(register_cleanup_failure(service, error, cause));
            }
            if failure.is_some() && cause.cleanup_owner.is_some() {
                failure = Some(register_cleanup_failure(
                    service,
                    failure.take().unwrap(),
                    cause,
                ));
            }
        }
    }

    // Post-run digest.
    let mut digest_after: Option<String> = None;
    if absolute_path.is_none() {
        digest_after = None;
    } else if cleanup_incomplete {
        if !cleanup_only_failure {
            completion_status = "unknown";
        }
    } else if let Some(absolute) = &absolute_path {
        if let Ok(value) = digest_file(absolute, cancellation, DEFAULT_TIMEOUT_MS) {
            digest_after = Some(value);
        }
    }

    // Late cancellation with no earlier failure.
    if cancellation.reason().is_some() && failure.is_none() {
        let captured = CapturedOutput {
            stdout: stdout.clone(),
            stderr: stderr.clone(),
            truncated: output_truncated,
            stdout_bytes: Some(stdout_bytes as u64),
            stderr_bytes: Some(stderr_bytes as u64),
            exit_code: Some(exit_code.as_i64()),
            signal: Some(signal_name.clone()),
        };
        failure = Some(AnalysisError::cancelled(operation).with_captured_output(captured));
        exit_code = Value::Null;
        completion_status = "unknown";
    }

    let artifact_changed: Option<bool> = match &absolute_path {
        None => None,
        Some(_) => match (&digest_after, &digest) {
            (Some(after), Some(before)) => Some(after != before),
            _ => None,
        },
    };

    let result = build_result(
        &stdout,
        &stderr,
        &exit_code,
        signal_name.as_deref(),
        output_truncated,
        completion_status,
        absolute_path.as_deref(),
        digest_after.as_deref(),
        artifact_changed,
    );

    let limitations = build_limitations(
        operation,
        absolute_path.as_deref(),
        parameters,
        stdout_invalid_utf8,
        stderr_invalid_utf8,
        output_truncated,
        signal_name.as_deref(),
        failure.as_ref(),
        artifact_changed,
        digest_after.as_deref(),
        cleanup_incomplete,
        cleanup_only_failure,
        cancellation,
    );

    let evidence = create_evidence(
        operation,
        &profile.identity,
        absolute_path.as_deref(),
        digest.as_deref(),
        parameters,
        &command,
        &args,
        &result,
        limitations,
    )?;

    match failure {
        None => Ok(evidence),
        Some(error) => Err(error.retain_partial_observation(evidence.value().clone())),
    }
}

/// `#registerCleanupFailure(failure, cleanupOwner)`.
fn register_cleanup_failure(
    service: &ReverseService,
    failure: AnalysisError,
    cause: OwnedOutputFailure,
) -> AnalysisError {
    if let (true, Some(owner)) = (failure.is_cleanup_incomplete(), cause.cleanup_owner) {
        let reason = cause
            .cleanup
            .as_ref()
            .map(|cleanup| cleanup.reason.clone())
            .unwrap_or_default();
        let resources = cause
            .cleanup
            .as_ref()
            .map(|cleanup| cleanup.resources.clone())
            .unwrap_or_default();
        service.register_cleanup(owner, reason, resources);
    }
    failure
}

/// `ownedCleanupOptions`: attach the retained cleanup observation when present.
fn with_cleanup(error: AnalysisError, cause: &OwnedOutputFailure) -> AnalysisError {
    match &cause.cleanup {
        Some(cleanup) => {
            let mut error = error;
            error.cleanup = Some(cleanup.clone());
            error
        }
        None => error,
    }
}

// ---------------------------------------------------------------------------
// Owned command execution (`runOwnedCommandOutput` + `OwnedOutputFailure`)
// ---------------------------------------------------------------------------

/// Successful owned-command output, exactly `ReverseEngineeringCommandRunner`.
struct OwnedOutput {
    stdout: StreamSnapshot,
    stderr: StreamSnapshot,
}

/// Owned-command failure carrying the fields `#observeProvider` inspects.
struct OwnedOutputFailure {
    stdout: String,
    stderr: String,
    /// `null` exit code or a libuv-style error name.
    code: Option<String>,
    signal: Option<String>,
    output_truncated: bool,
    stdout_invalid_utf8: bool,
    stderr_invalid_utf8: bool,
    stdout_bytes: usize,
    stderr_bytes: usize,
    collection_failure: bool,
    cleanup: Option<CleanupObservation>,
    cleanup_owner: Option<OwnedProcess>,
    /// Whether the snapshot was present (`capture !== undefined`).
    has_capture: bool,
}

impl OwnedOutputFailure {
    /// `capture.code` as a numeric exit code only; `null`/name → `None`.
    fn killed(&self) -> bool {
        // The owned command never reports an explicit `killed` flag; a
        // terminating signal is the observable equivalent the service uses.
        false
    }
}

fn run_command(
    service: &ReverseService,
    command: &str,
    args: &[String],
    overrides: &[(&'static str, String)],
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<OwnedOutput, OwnedOutputFailure> {
    // `runId: randomUUID()` without a provider prefix.
    let run_id = crate::node::random_uuid();
    let override_refs: Vec<(&str, &str)> = overrides
        .iter()
        .map(|(key, value)| (*key, value.as_str()))
        .collect();
    let spec = ProcessSpec::new(
        command.to_owned(),
        args.to_vec(),
        None,
        environment,
        &override_refs,
        run_id,
    );
    let limits = process::CommandLimits {
        timeout_ms: DEFAULT_TIMEOUT_MS,
        diagnostic_bytes: MAX_COMBINED_OUTPUT_BYTES,
        accept_nonzero_exit: true,
    };
    let _ = service;
    match process::run_owned_command(&spec, limits, cancellation, None) {
        Ok(snapshot) => complete_snapshot(snapshot),
        Err(CommandError::Launch(spawn)) => Err(from_launch(spawn)),
        Err(CommandError::Failed(failure)) => Err(from_failed(*failure)),
    }
}

/// Mirror the wrapper's signal / nonzero-exit throws around an `Ok(snapshot)`.
fn complete_snapshot(snapshot: ProcessSnapshot) -> Result<OwnedOutput, OwnedOutputFailure> {
    let code = exit_code_string(&snapshot.exit_code);
    if let Some(signal) = snapshot.signal.clone() {
        return Err(snapshot_failure(snapshot, code, Some(signal)));
    }
    if snapshot.exit_code != Some(0) {
        return Err(snapshot_failure(snapshot, code, None));
    }
    Ok(OwnedOutput {
        stdout: snapshot.stdout,
        stderr: snapshot.stderr,
    })
}
fn exit_code_string(code: &Option<i64>) -> Option<String> {
    code.map(|value| value.to_string())
}

fn snapshot_failure(
    snapshot: ProcessSnapshot,
    code: Option<String>,
    signal: Option<String>,
) -> OwnedOutputFailure {
    OwnedOutputFailure {
        stdout: snapshot.stdout.text,
        stderr: snapshot.stderr.text,
        code,
        signal,
        output_truncated: snapshot.diagnostic_truncated,
        stdout_invalid_utf8: snapshot.stdout.invalid_utf8,
        stderr_invalid_utf8: snapshot.stderr.invalid_utf8,
        stdout_bytes: snapshot.stdout.bytes,
        stderr_bytes: snapshot.stderr.bytes,
        collection_failure: false,
        cleanup: None,
        cleanup_owner: None,
        has_capture: true,
    }
}

/// A raw launch failure is rethrown unchanged by `runOwnedCommandOutput`
/// (it is not an `OwnedCommandFailure`): no capture, and `code` is the
/// spawn error's own code (`ENOENT`, `EACCES`, `E2BIG`, ...).
fn from_launch(spawn: process::SpawnFailure) -> OwnedOutputFailure {
    OwnedOutputFailure {
        stdout: String::new(),
        stderr: String::new(),
        code: spawn.code.map(str::to_owned),
        signal: None,
        output_truncated: false,
        stdout_invalid_utf8: false,
        stderr_invalid_utf8: false,
        stdout_bytes: 0,
        stderr_bytes: 0,
        collection_failure: false,
        cleanup: None,
        cleanup_owner: None,
        has_capture: false,
    }
}

/// Map `OwnedCommandFailure` into the wrapper's thrown `OwnedOutputFailure`.
fn from_failed(failure: CommandFailure) -> OwnedOutputFailure {
    let snapshot = failure.snapshot.clone();
    // Every `OwnedOutputFailure` carries string stdout/stderr, so
    // `execFileOutputFailure` always yields a capture for it.
    let has_capture = true;
    let output_limit = failure.reason == FailureReason::OutputLimit;
    let code = match failure.reason {
        FailureReason::Cancelled => Some("ABORT_ERR".to_owned()),
        FailureReason::Timeout => Some("ETIMEDOUT".to_owned()),
        FailureReason::OutputLimit => Some("ERR_CHILD_PROCESS_STDIO_MAXBUFFER".to_owned()),
        FailureReason::Process => match &snapshot {
            None => Some("ERR_PROVIDER_LAUNCH".to_owned()),
            Some(snapshot) => snapshot.exit_code.map(|value| value.to_string()),
        },
    };
    let cleanup = failure
        .cleanup_failure
        .as_ref()
        .map(|reason| CleanupObservation {
            reason: reason.clone(),
            resources: failure.resources.clone(),
        });
    OwnedOutputFailure {
        stdout: snapshot
            .as_ref()
            .map(|snapshot| snapshot.stdout.text.clone())
            .unwrap_or_default(),
        stderr: snapshot
            .as_ref()
            .map(|snapshot| snapshot.stderr.text.clone())
            .unwrap_or_default(),
        code,
        signal: snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.signal.clone()),
        // `outputTruncated || code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER"`.
        output_truncated: output_limit
            || snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.diagnostic_truncated),
        stdout_invalid_utf8: snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.stdout.invalid_utf8),
        stderr_invalid_utf8: snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot.stderr.invalid_utf8),
        stdout_bytes: snapshot
            .as_ref()
            .map(|snapshot| snapshot.stdout.bytes)
            .unwrap_or(0),
        stderr_bytes: snapshot
            .as_ref()
            .map(|snapshot| snapshot.stderr.bytes)
            .unwrap_or(0),
        collection_failure: failure.collection_failure,
        cleanup,
        cleanup_owner: failure.cleanup_owner,
        has_capture,
    }
}

/// `capture.code`: numeric exit code, or `None` for `null`/error-name codes.
fn numeric_code(code: &Option<String>) -> Option<i64> {
    code.as_ref().and_then(|value| value.parse::<i64>().ok())
}

/// `exitCode = capture.code` as a JSON value (`number | string | null`).
fn code_to_value(code: &Option<String>) -> Value {
    match code {
        None => Value::Null,
        Some(value) => match value.parse::<i64>() {
            Ok(number) => json!(number),
            Err(_) => json!(value),
        },
    }
}

// ---------------------------------------------------------------------------
// Digest-failure mapping (the pre-run digest catch block)
// ---------------------------------------------------------------------------

fn digest_failure(
    operation: &'static str,
    command: &str,
    absolute_path: &str,
    error: &DigestError,
    cancellation: &Cancellation,
) -> AnalysisError {
    if error.cancelled || cancellation.reason().is_some() {
        return AnalysisError::cancelled(operation);
    }
    match error.code {
        Some("EACCES") | Some("EPERM") => {
            AnalysisError::access_denied(operation, absolute_path, error.code.unwrap_or(""))
        }
        Some("ETIMEDOUT") => AnalysisError::timeout(operation, DEFAULT_TIMEOUT_MS),
        _ => {
            let _ = command;
            AnalysisError::input(operation, Vec::new())
        }
    }
}

// ---------------------------------------------------------------------------
// Result and limitations projection
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn build_result(
    stdout: &str,
    stderr: &str,
    exit_code: &Value,
    signal: Option<&str>,
    output_truncated: bool,
    completion_status: &str,
    absolute_path: Option<&str>,
    digest_after: Option<&str>,
    artifact_changed: Option<bool>,
) -> Value {
    let mut result = Map::new();
    result.insert("stdout".into(), json!(stdout));
    result.insert("stderr".into(), json!(stderr));
    result.insert("exit_code".into(), exit_code.clone());
    result.insert("signal".into(), errors::nullable(signal));
    result.insert("output_truncated".into(), json!(output_truncated));
    result.insert("completion_status".into(), json!(completion_status));
    result.insert(
        "artifact_sha256_after".into(),
        if absolute_path.is_none() {
            Value::Null
        } else {
            errors::nullable(digest_after)
        },
    );
    result.insert(
        "artifact_changed".into(),
        if absolute_path.is_none() {
            Value::Null
        } else {
            artifact_changed.map_or(Value::Null, Value::Bool)
        },
    );
    Value::Object(result)
}

#[allow(clippy::too_many_arguments)]
fn build_limitations(
    operation: &str,
    absolute_path: Option<&str>,
    parameters: &Value,
    stdout_invalid_utf8: bool,
    stderr_invalid_utf8: bool,
    output_truncated: bool,
    signal: Option<&str>,
    failure: Option<&AnalysisError>,
    artifact_changed: Option<bool>,
    digest_after: Option<&str>,
    cleanup_incomplete: bool,
    cleanup_only: bool,
    cancellation: &Cancellation,
) -> Vec<String> {
    let mut limitations: Vec<String> = Vec::new();
    if absolute_path.is_none() {
        limitations.push("The objdump version is not reported; the output lists BFD targets advertised by the installed tool and does not establish support for the selected artifact.".to_owned());
    } else {
        limitations.push("The executable version and supported formats are reported as unknown because no reliable version probe was performed.".to_owned());
    }
    limitations
        .push("A non-zero process exit is preserved as an observed command result.".to_owned());

    let symbol_selected =
        operation == OBJDUMP && parameters.get("symbol").and_then(Value::as_str).is_some();
    if symbol_selected {
        limitations.push("Disassembly is scoped to the caller-selected symbol using the provider's matching and symbol-boundary semantics; an empty match does not establish artifact-wide absence.".to_owned());
    }
    let follow_links = operation == OBJDUMP
        && parameters
            .get("follow_debug_links")
            .and_then(Value::as_bool)
            == Some(true);
    if follow_links {
        limitations.push("DWARF output may include local debug-link files whose identities are not bound to Evidence.".to_owned());
    }
    if operation == RIZIN {
        limitations.push("Rizin commands and retained plugins may read files or access network resources outside the selected artifact; those external inputs are not bound to Evidence.".to_owned());
    }
    if stdout_invalid_utf8 || stderr_invalid_utf8 {
        let mut streams: Vec<&str> = Vec::new();
        if stdout_invalid_utf8 {
            streams.push("stdout");
        }
        if stderr_invalid_utf8 {
            streams.push("stderr");
        }
        limitations.push(format!(
            "Captured {} bytes contain invalid or incomplete UTF-8; replacement characters in the text capture do not preserve the original bytes.",
            streams.join(" and ")
        ));
    }
    if output_truncated {
        limitations.push("The provider command ended before completion could be confirmed; captured output is partial.".to_owned());
    }
    if let Some(signal) = signal {
        limitations.push(format!(
            "The provider process terminated by signal {signal}; captured output may be partial and command completion is unknown."
        ));
    }
    // `failure === undefined || (AnalysisOutputError && cleanupOnly)` → no line.
    let suppress_failure_line = match failure {
        None => true,
        // `failure instanceof AnalysisOutputError && failure.cleanupOnly`.
        Some(error) => is_cleanup_only_output(error) && cleanup_only,
    };
    if !suppress_failure_line && let Some(error) = failure {
        limitations.push(format!(
            "Command completion is unknown because the operation failed with {}: {}",
            error.tag(),
            error.message()
        ));
    }
    if absolute_path.is_none() {
        limitations.push("This output lists BFD targets advertised by the installed objdump and is independent of the selected artifact.".to_owned());
    } else {
        limitations.push("When both are available, pre-run and post-run digests detect artifact changes across the provider call but cannot prove the exact bytes consumed during the call.".to_owned());
    }
    if artifact_changed == Some(true) {
        limitations.push("The provider command may have changed the artifact while analysis was running; pre-run and post-run digests are both reported.".to_owned());
    }
    if absolute_path.is_some() && digest_after.is_none() {
        let reason = if cleanup_incomplete {
            "The post-run artifact digest was not captured because owned provider cleanup was incomplete at observation time; artifact changes during the command remain unquantified."
        } else if cancellation.reason().is_some() {
            "The post-run artifact digest is unknown because cancellation interrupted the digest."
        } else {
            "The post-run artifact digest is unknown because the artifact could not be read after the provider call."
        };
        limitations.push(reason.to_owned());
    }
    limitations
}

/// `failure instanceof AnalysisOutputError && failure.cleanupOnly`.
fn is_cleanup_only_output(error: &AnalysisError) -> bool {
    matches!(error.kind, ErrorKind::Output { .. })
        && error.cleanup_incomplete == Some(true)
        && error.cleanup.is_some()
}

// ---------------------------------------------------------------------------
// Evidence construction (`createEvidence(...)`)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn create_evidence(
    operation: &str,
    identity: &EvidenceProvider,
    absolute_path: Option<&str>,
    digest: Option<&str>,
    parameters: &Value,
    command: &str,
    args: &[String],
    result: &Value,
    limitations: Vec<String>,
) -> Result<Evidence, AnalysisError> {
    // `parameters`: artifact runs keep the parsed parameters; pathless runs
    // substitute `{ operation: "architectures" }`.
    let mut evidence_parameters = Map::new();
    if absolute_path.is_none() {
        evidence_parameters.insert("operation".into(), json!("architectures"));
    } else if let Some(object) = parameters.as_object() {
        for (key, value) in object {
            evidence_parameters.insert(key.clone(), value.clone());
        }
    }
    evidence_parameters.insert("provider_executable".into(), json!(command));
    evidence_parameters.insert(
        "command_arguments".into(),
        Value::Array(args.iter().map(|argument| json!(argument)).collect()),
    );

    let subject = match (absolute_path, digest) {
        (Some(path), Some(sha256)) => Some(SubjectTarget {
            path: path.to_owned(),
            sha256: sha256.to_owned(),
            format: "unknown".to_owned(),
            architecture: None,
        }),
        _ => None,
    };

    let mut observation = Observation::new(
        operation,
        Value::Object(evidence_parameters),
        result.clone(),
    )
    .predicate("rea.reverse-engineering.command-observation")
    .raw(result.clone())
    .limitations(limitations);
    if let Some(path) = absolute_path {
        observation = observation.locations(vec![json!({ "kind": "artifact-path", "path": path })]);
    }

    rea_mcp::support::evidence(subject.as_ref(), identity, observation)
}
