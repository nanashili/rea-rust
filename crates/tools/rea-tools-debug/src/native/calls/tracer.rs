//! LLDB call tracer: one owned `lldb --batch` run of the REA LLDB bridge.
//!
//! Compatibility owner: `src/native/LldbCallTracer.ts` (`LldbCallTracer`
//! `#trace`, `#run`, `close`, `#retryPendingCleanup`, `tracerFailure`,
//! `partialNativeObservation`, `capturedOutput`, `readTracerOutput`,
//! `lldbCleanupFailure`, `lldbCleanupResources`, `releaseLldbRuntime`).
//!
//! Each trace owns a private runtime root (`rea-lldb-*`, mode 0700) holding
//! the bridge config, result, PID handshake, FIFOs and capture files. A run
//! whose LLDB group or target process could not be confirmed stopped is
//! retained and retried before the next trace and at session close.
#![cfg(unix)]

use rea_core::analysis_error::AnalysisError;
use rea_core::analysis_error::cleanup::{provider_cleanup_error, with_cleanup_failure};
use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::input::{MAX_OUTPUT_BYTES, ObservationInput};
use super::process::{
    LldbOutcome, TargetTermination, ensure_terminated, retry_stop, run_lldb,
    target_termination_reason,
};
use super::result::{
    CapturedOutput, NativeCallTrace, TargetFacts, TracerError, TracerOutput, project_partial,
};
use super::retained::{self, ReadFailure};

const OPERATION: &str = "observe_native_calls";
const PROVIDER: &str = "native-macos";
const LLDB_REQUIREMENT: &str = "LLDB from Xcode or the Command Line Tools is not available";
/// LLDB startup, symbol loading and teardown beyond the observation window.
const DEADLINE_GRACE_MS: u64 = 60_000;
/// `NATIVE_COMMAND_TIMEOUT_MS` for `xcrun --find`.
const XCRUN_TIMEOUT: Duration = Duration::from_millis(60_000);
/// Remediation for a target LLDB may not debug.
const ATTACH_REMEDIATION: &str = "Allow debugging for this user (Developer Tools access: `DevToolsSecurity -enable`, or membership in the _developer group). A hardened-runtime target is debuggable only with the com.apple.security.get-task-allow entitlement; inspect_signature reports hardened_runtime and entitlements.";
/// `bridge/native/rea_lldb_tracer.py`, materialized into each runtime root.
const BRIDGE: &[u8] = include_bytes!("../../../../../../bridge/native/rea_lldb_tracer.py");

/// One trace request (`NativeCallTracer.trace` request).
pub(crate) struct TraceRequest {
    pub executable: String,
    pub architecture: String,
    pub expected_sha256: String,
    pub input: ObservationInput,
}

impl TraceRequest {
    fn facts(&self) -> TargetFacts {
        TargetFacts {
            path: self.executable.clone(),
            sha256: self.expected_sha256.clone(),
            architecture: self.architecture.clone(),
        }
    }
}

/// `ResolvedTool`.
struct ResolvedTool {
    path: String,
    sha256: String,
}

/// `lldbRuntimePaths`.
struct Paths {
    bridge: PathBuf,
    config: PathBuf,
    result: PathBuf,
    pid: PathBuf,
    identity_ack: PathBuf,
    stdout: PathBuf,
    stderr: PathBuf,
    stdout_capture: PathBuf,
    stderr_capture: PathBuf,
    observations: PathBuf,
}

impl Paths {
    fn new(root: &Path) -> Self {
        Self {
            bridge: root.join("rea_lldb_tracer.py"),
            config: root.join("config.json"),
            result: root.join("result.json"),
            pid: root.join("pid"),
            identity_ack: root.join("identity.ack"),
            stdout: root.join("stdout"),
            stderr: root.join("stderr"),
            stdout_capture: root.join("stdout.capture"),
            stderr_capture: root.join("stderr.capture"),
            observations: root.join("observations.jsonl"),
        }
    }
}

/// `RetainedLldbResources`.
struct Retained {
    root: PathBuf,
    root_released: bool,
    process: Option<OwnedChildProcess>,
    pid_path: PathBuf,
    target_identity: Option<String>,
    target_pid: Option<u32>,
    process_stopped: bool,
    target_stopped: bool,
}

impl Retained {
    /// `lldbCleanupResources`.
    fn resources(&self) -> Vec<String> {
        let mut resources = Vec::new();
        if !self.process_stopped {
            resources.push("lldb-process-group".to_owned());
        }
        if !self.target_stopped {
            resources.push(format!(
                "native-target:{}",
                self.target_pid
                    .map_or_else(|| "unknown".to_owned(), |pid| pid.to_string())
            ));
        }
        if !self.root_released {
            resources.push(self.root.display().to_string());
        }
        resources
    }

    /// `releaseLldbRuntime`: the root is released only after every child
    /// resource confirmed completion.
    fn release(&mut self) -> Result<(), String> {
        if !self.process_stopped || !self.target_stopped {
            return Err("LLDB runtime still owns unresolved child resources".to_owned());
        }
        if self.root_released {
            return Ok(());
        }
        match std::fs::remove_dir_all(&self.root) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
        self.root_released = true;
        Ok(())
    }
}

/// `lldbCleanupFailure`.
fn lldb_cleanup_failure(owner: &Retained, reason: &str, partial: Option<Value>) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("reason".into(), json!(reason));
    let mut error = provider_cleanup_error(
        PROVIDER,
        owner.resources(),
        diagnostics,
        Some(OPERATION),
        None,
    );
    error.partial_observation = partial;
    error
}

/// The production tracer (`LldbCallTracer`), shared by one session.
#[derive(Default)]
pub(crate) struct CallTracer {
    /// `#serialize`: one trace or cleanup retry at a time.
    serialize: Mutex<()>,
    /// `#pendingCleanup`.
    pending: Mutex<Option<Retained>>,
}

impl CallTracer {
    fn take_pending(&self) -> Option<Retained> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn set_pending(&self, owner: Retained) {
        *self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(owner);
    }

    /// `close`: retry retained cleanup without abandoning its owner.
    pub(crate) fn close(&self) -> Result<(), AnalysisError> {
        let _serialized = self
            .serialize
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.retry_pending().map_or(Ok(()), Err)
    }

    /// `#retryPendingCleanup`.
    fn retry_pending(&self) -> Option<AnalysisError> {
        let mut owner = self.take_pending()?;
        let mut failures: Vec<String> = Vec::new();
        if !owner.process_stopped {
            match owner.process.as_mut() {
                None => failures.push("LLDB process cleanup ownership was unavailable".to_owned()),
                Some(process) => match retry_stop(process) {
                    Ok(()) => {
                        owner.process = None;
                        owner.process_stopped = true;
                    }
                    Err(reason) => failures.push(reason),
                },
            }
        }
        if owner.process_stopped && !owner.target_stopped {
            owner.target_pid = retained::read_target_pid(&owner.pid_path);
            match ensure_terminated(owner.target_pid, owner.target_identity.as_deref()) {
                TargetTermination::Terminated => owner.target_stopped = true,
                other => failures.push(target_termination_reason(other).to_owned()),
            }
        }
        if failures.is_empty() {
            match owner.release() {
                Ok(()) => return None,
                Err(reason) => failures.push(reason),
            }
        }
        let error = lldb_cleanup_failure(&owner, &failures.join("; "), None);
        self.set_pending(owner);
        Some(error)
    }

    /// `trace` (`#serialize(#trace)`).
    pub(crate) fn trace(
        &self,
        request: &TraceRequest,
        environment: &HashMap<String, String>,
        cancellation: &Cancellation,
    ) -> Result<NativeCallTrace, AnalysisError> {
        let _serialized = self
            .serialize
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(pending) = self.retry_pending() {
            return Err(pending);
        }
        let lldb = resolve_xcrun_tool("lldb", environment, cancellation).map_err(|cancelled| {
            if cancelled {
                AnalysisError::cancelled(OPERATION)
            } else {
                AnalysisError::capability_unavailable(PROVIDER, OPERATION, LLDB_REQUIREMENT)
                    .with_user_message(LLDB_REQUIREMENT)
            }
        })?;
        // A root allocation failure rejects the trace (`trace-result`).
        let root = create_root(environment).map_err(|error| {
            let mut diagnostics = Map::new();
            diagnostics.insert("phase".into(), json!("trace-result"));
            let _ = error;
            AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics)
        })?;
        let paths = Paths::new(&root);
        let mut owner = Retained {
            root,
            root_released: false,
            process: None,
            pid_path: paths.pid.clone(),
            target_identity: None,
            target_pid: None,
            process_stopped: true,
            target_stopped: true,
        };
        let mut result = match run(
            &lldb,
            &mut owner,
            &paths,
            request,
            environment,
            cancellation,
        ) {
            Ok(result) => result,
            Err(thrown) => {
                let partial = partial_native_observation(request, &paths, None, "tracer-failure");
                let pending = !owner.process_stopped || !owner.target_stopped;
                let mut diagnostics = Map::new();
                diagnostics.insert("reason".into(), json!(thrown));
                let mut failure = AnalysisError::provider_adapter(PROVIDER, OPERATION)
                    .with_diagnostics(diagnostics)
                    .retain_partial_observation(partial.observation);
                if pending {
                    failure = failure.with_cleanup(
                        "LLDB trace failed while owned resources remain",
                        owner.resources(),
                    );
                }
                Err(retain_partial_read_failures(
                    failure,
                    &partial.read_failures,
                ))
            }
        };
        let cancelled_success = |trace: &NativeCallTrace| {
            AnalysisError::cancelled(OPERATION).retain_partial_observation(project_partial(
                &request.facts(),
                &request.input,
                trace,
                "cancelled",
            ))
        };
        if let Ok(trace) = &result
            && cancellation.reason().is_some()
        {
            result = Err(cancelled_success(trace));
        }
        if !owner.process_stopped || !owner.target_stopped {
            // The primary already carries the live LLDB cleanup ownership.
            let outcome = match result {
                Err(error) if error.is_cleanup_incomplete() => Err(error),
                Err(error) => {
                    let cleanup = lldb_cleanup_failure(
                        &owner,
                        "LLDB readback descriptor cleanup remains incomplete",
                        None,
                    );
                    Err(with_cleanup_failure(error, cleanup, OPERATION))
                }
                Ok(trace) => Err(lldb_cleanup_failure(
                    &owner,
                    "LLDB readback descriptor cleanup remains incomplete",
                    Some(project_partial(
                        &request.facts(),
                        &request.input,
                        &trace,
                        "cleanup-failure",
                    )),
                )),
            };
            self.set_pending(owner);
            return outcome;
        }
        if let Err(reason) = owner.release() {
            let partial = result.as_ref().ok().map(|trace| {
                project_partial(&request.facts(), &request.input, trace, "cleanup-failure")
            });
            let cleanup = lldb_cleanup_failure(&owner, &reason, partial);
            self.set_pending(owner);
            return match result {
                Ok(_) => Err(cleanup),
                Err(error) => Err(with_cleanup_failure(error, cleanup, OPERATION)),
            };
        }
        if let Ok(trace) = &result
            && cancellation.reason().is_some()
        {
            return Err(cancelled_success(trace));
        }
        result
    }
}

/// `PrivateRuntimeRoot.create({ prefix: "rea-lldb-" })`: an owner-only
/// directory under `os.tmpdir()`.
fn create_root(environment: &HashMap<String, String>) -> std::io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    let lookup = |key: &str| {
        environment
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    let mut parent = lookup("TMPDIR")
        .or_else(|| lookup("TMP"))
        .or_else(|| lookup("TEMP"))
        .unwrap_or_else(|| "/tmp".to_owned());
    if parent.len() > 1 && parent.ends_with('/') {
        parent.pop();
    }
    loop {
        let suffix: String = uuid::Uuid::new_v4().simple().to_string()[..6].to_owned();
        let path = PathBuf::from(&parent).join(format!("rea-lldb-{suffix}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
}

/// `resolveXcrunTool`: `xcrun --find`, then the realpath and its digest.
/// `Err(true)` means the caller cancelled.
fn resolve_xcrun_tool(
    tool: &str,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<ResolvedTool, bool> {
    if cancellation.reason().is_some() {
        return Err(true);
    }
    let mut child_environment: Vec<(OsString, OsString)> = environment
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "LC_ALL" | "LANG" | "REA_PROCESS_RUN_ID"))
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    child_environment.push(("LC_ALL".into(), "C".into()));
    child_environment.push(("LANG".into(), "C".into()));
    child_environment.push((
        "REA_PROCESS_RUN_ID".into(),
        format!("rea-native-command-{}", uuid::Uuid::new_v4()).into(),
    ));
    let spec = ChildLaunchSpec {
        executable: "/usr/bin/xcrun".into(),
        arguments: ChildLaunchSpec::arguments(["--find", tool]),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let mut child = OwnedChildProcess::launch_with_environment(spec, &child_environment, 64 * 1024)
        .map_err(|_| false)?;
    let deadline = Instant::now() + XCRUN_TIMEOUT;
    let exit = loop {
        if let Ok(Some(_)) = child.try_wait() {
            break child.wait().ok();
        }
        if cancellation.reason().is_some() {
            let _ = child.cancel(1);
            return Err(true);
        }
        if Instant::now() >= deadline {
            let _ = child.cancel(1);
            return Err(false);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let output = child.drain_output().map_err(|_| false)?;
    if !exit.is_some_and(|exit| exit.code == 0 && exit.signal.is_none()) || output.output_incomplete
    {
        return Err(false);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let candidate = stdout.trim();
    if !candidate.starts_with('/') {
        return Err(false);
    }
    let resolve = || -> std::io::Result<ResolvedTool> {
        let path = std::fs::canonicalize(candidate)?;
        let mut file = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(ResolvedTool {
            path: path.to_string_lossy().into_owned(),
            sha256: hex(&hasher.finalize()),
        })
    };
    resolve().map_err(|_| cancellation.reason().is_some())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// LLDB command arguments are quoted; the bridge path is REA's own path.
fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// `PartialNativeObservationRead`.
struct PartialRead {
    observation: Value,
    read_failures: Vec<ReadFailure>,
}

/// `partialNativeObservation`.
fn partial_native_observation(
    request: &TraceRequest,
    paths: &Paths,
    version: Option<&str>,
    reason: &str,
) -> PartialRead {
    let journal = retained::read_journal(&paths.observations);
    let pid = retained::read_target_pid(&paths.pid);
    let stdout = retained::read_partial_capture(&paths.stdout_capture);
    let stderr = retained::read_partial_capture(&paths.stderr_capture);
    let mut read_failures = Vec::new();
    let (parsed, journal_limitations) = match journal {
        Ok((parsed, limitations, failure)) => {
            read_failures.extend(failure);
            (parsed, limitations)
        }
        Err(failure) => {
            let limitation = format!(
                "The observation journal could not be read: {}",
                failure.message
            );
            read_failures.push(failure);
            (retained::ParsedJournal::default(), vec![limitation])
        }
    };
    let mut limitations = Vec::new();
    let mut capture =
        |read: Result<(CapturedOutput, Vec<String>, Option<ReadFailure>), ReadFailure>,
         stream: &str| match read {
            Ok((capture, notes, failure)) => {
                limitations.extend(notes);
                read_failures.extend(failure);
                Some(capture)
            }
            Err(failure) => {
                limitations.push(format!(
                    "The target {stream} capture could not be read: {}",
                    failure.message
                ));
                read_failures.push(failure);
                None
            }
        };
    let stdout = capture(stdout, "stdout");
    let stderr = capture(stderr, "stderr");
    // Journal failures precede capture failures (`[journal, stdout, stderr]`).
    let observation = retained::project_partial(
        retained::target_object(
            &request.executable,
            &request.expected_sha256,
            &request.architecture,
            &request.input,
        ),
        pid,
        stdout.as_ref(),
        stderr.as_ref(),
        version,
        &parsed,
        &journal_limitations,
        &limitations,
        reason,
    );
    PartialRead {
        observation,
        read_failures,
    }
}

/// `retainPartialReadFailures`.
fn retain_partial_read_failures(
    mut failure: AnalysisError,
    read_failures: &[ReadFailure],
) -> AnalysisError {
    if read_failures.is_empty() {
        return failure;
    }
    let mut diagnostics = Map::new();
    diagnostics.insert(
        "reason".into(),
        json!("LLDB could not read all available partial observation data"),
    );
    diagnostics.insert(
        "read_failures".into(),
        Value::Array(
            read_failures
                .iter()
                .map(|failure| json!(failure.message))
                .collect(),
        ),
    );
    let readback =
        AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics);
    let mut merged = failure.diagnostics.take().unwrap_or_default();
    merged.insert("partial_readback_failure".into(), readback.project());
    failure.diagnostics = Some(merged);
    failure.secondary_failures.push(readback);
    failure
}

/// `tracerFailure`: preserve a decoded bridge failure's type.
fn tracer_failure(
    output: &TracerError,
    cleanup: Option<&(String, Vec<String>)>,
    partial: Value,
) -> AnalysisError {
    let message = output
        .error
        .clone()
        .unwrap_or_else(|| "no LLDB error text".to_owned());
    let mut diagnostics = Map::new();
    let error = match output.status.as_str() {
        "target-integrity-error" => AnalysisError::evidence_integrity(if message.is_empty() {
            "The launched native target did not match its session digest".to_owned()
        } else {
            message
        }),
        "target-identity-unavailable" => {
            diagnostics.insert("reason".into(), json!(message));
            diagnostics.insert(
                "constraint".into(),
                json!("target process start identity could not be verified"),
            );
            AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics)
        }
        "tracer-error" => {
            diagnostics.insert(
                "reason".into(),
                json!(format!("LLDB bridge failed: {message}")),
            );
            AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics)
        }
        "target-error" => AnalysisError::capability_unavailable(
            PROVIDER,
            OPERATION,
            format!("lldb-target-unloadable: {message}"),
        ),
        _ => {
            let lower = message.to_lowercase();
            if [
                "attach",
                "not allowed",
                "permission",
                "denied",
                "debugserver",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
            {
                AnalysisError::capability_unavailable(
                    PROVIDER,
                    OPERATION,
                    format!("debugger-attach-denied: {message}"),
                )
                .with_user_message(ATTACH_REMEDIATION)
            } else {
                AnalysisError::capability_unavailable(
                    PROVIDER,
                    OPERATION,
                    format!("launch-failed: {message}"),
                )
            }
        }
    };
    let error = match cleanup {
        Some((reason, resources)) => error.with_cleanup(reason.clone(), resources.clone()),
        None => error,
    };
    error.retain_partial_observation(partial)
}

/// `readTracerOutput`.
fn read_tracer_output(path: &Path) -> Result<TracerOutput, String> {
    let bytes = retained::read_all(path).map_err(|failure| failure.message)?;
    let text = String::from_utf8(bytes)
        .map_err(|_| "The encoded data was not valid for encoding utf-8".to_owned())?;
    TracerOutput::parse(&text)
}

/// `capturedOutput`: the bounded completed capture, or a readback failure
/// with its partial prefix.
fn captured_output(
    path: &Path,
    observed_bytes: u64,
    truncated: bool,
    complete: bool,
) -> Result<CapturedOutput, (ReadFailure, Option<CapturedOutput>)> {
    let read =
        retained::read_bounded_prefix(path, MAX_OUTPUT_BYTES).map_err(|failure| (failure, None))?;
    let failed = read.status == retained::PrefixStatus::ReadFailure;
    let capture = CapturedOutput {
        text: String::from_utf8_lossy(&read.bytes).into_owned(),
        bytes: observed_bytes,
        truncated: truncated || read.size > MAX_OUTPUT_BYTES || failed,
        complete: !failed
            && complete
            && read.bytes.len() as u64 >= observed_bytes.min(MAX_OUTPUT_BYTES),
    };
    match read.failure {
        Some(failure) => Err((failure, Some(capture))),
        None => Ok(capture),
    }
}

/// `#run`: write the config, supervise LLDB, confirm the target ended and
/// read the bridge result. `Err` is a thrown runtime failure.
fn run(
    lldb: &ResolvedTool,
    owner: &mut Retained,
    paths: &Paths,
    request: &TraceRequest,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<Result<NativeCallTrace, AnalysisError>, String> {
    let input = &request.input;
    let path = |path: &Path| path.display().to_string();
    std::fs::write(&paths.bridge, BRIDGE).map_err(|error| error.to_string())?;
    let config = input.bridge_config(
        &request.executable,
        &request.architecture,
        &request.expected_sha256,
        &path(&paths.stdout),
        &path(&paths.stderr),
        &path(&paths.stdout_capture),
        &path(&paths.stderr_capture),
        &path(&paths.result),
        &path(&paths.pid),
        &path(&paths.identity_ack),
        &path(&paths.observations),
    );
    retained::write_private(&paths.config, &config.to_string())
        .map_err(|error| error.to_string())?;
    owner.process_stopped = false;
    owner.target_stopped = false;
    let arguments = vec![
        "--batch".to_owned(),
        "--no-lldbinit".to_owned(),
        "--no-use-colors".to_owned(),
        "-o".to_owned(),
        format!("command script import {}", quote(&path(&paths.bridge))),
        "-o".to_owned(),
        format!("rea_trace {}", path(&paths.config)),
    ];
    let timeout_ms = input.duration_ms + DEADLINE_GRACE_MS;
    let exited = run_lldb(
        &lldb.path,
        &arguments,
        timeout_ms,
        &paths.pid,
        &paths.identity_ack,
        environment,
        cancellation,
    );
    owner.target_identity = exited.target_identity.clone();
    owner.process_stopped = exited.cleanup_owner.is_none() && exited.cleanup_failure.is_none();
    owner.process = exited.cleanup_owner;
    owner.target_stopped = !exited.target_launched;
    let readback = match exited.outcome {
        LldbOutcome::Exited { .. } => Some(read_tracer_output(&paths.result)),
        _ => None,
    };
    let output = readback.as_ref().and_then(|read| read.as_ref().ok());
    let failed_output = match output {
        Some(TracerOutput::Failed(failure)) => Some(failure),
        _ => None,
    };
    // An explicit bridge observation can prove no process was created or that
    // the created process exited. A missing PID alone remains ambiguous.
    let bridge_observed_exit =
        failed_output.is_some_and(|failure| failure.target_process_exit_observed == Some(true));
    owner.target_pid = retained::read_target_pid(&paths.pid);
    let mut termination = if exited.target_launched && !bridge_observed_exit {
        ensure_terminated(owner.target_pid, exited.target_identity.as_deref())
    } else {
        TargetTermination::Terminated
    };
    if failed_output.is_some_and(|failure| failure.target_process_created == Some(false))
        && owner.target_pid.is_none()
    {
        termination = TargetTermination::Terminated;
    }
    owner.target_stopped = termination == TargetTermination::Terminated;
    let terminated = owner.target_stopped;
    let mut cleanup_details: Vec<String> = exited.cleanup_failure.iter().cloned().collect();
    if !terminated {
        cleanup_details.push(target_termination_reason(termination).to_owned());
    }
    let lifecycle_cleanup =
        (!cleanup_details.is_empty()).then(|| (cleanup_details.join("; "), owner.resources()));
    let lifecycle_value = lifecycle_cleanup
        .as_ref()
        .map(|(reason, resources)| json!({ "reason": reason, "resources": resources }));
    let partial_reason = match exited.outcome {
        LldbOutcome::Cancelled => "cancelled",
        LldbOutcome::Timeout => "timeout",
        _ if exited.cleanup_failure.is_some() => "cleanup-failure",
        _ => "tracer-failure",
    };
    let version = match output {
        Some(TracerOutput::Traced(run)) => Some(run.version.as_str()),
        _ => None,
    };
    let with_partial = |create: &dyn Fn(Value) -> AnalysisError| {
        let partial = partial_native_observation(request, paths, version, partial_reason);
        Err(retain_partial_read_failures(
            create(partial.observation),
            &partial.read_failures,
        ))
    };
    let with_lifecycle = |error: AnalysisError| match &lifecycle_cleanup {
        Some((reason, resources)) => error.with_cleanup(reason.clone(), resources.clone()),
        None => error,
    };
    match &exited.outcome {
        LldbOutcome::Cancelled => {
            return Ok(with_partial(&|partial| {
                with_lifecycle(AnalysisError::cancelled(OPERATION))
                    .retain_partial_observation(partial)
            }));
        }
        LldbOutcome::Timeout => {
            return Ok(with_partial(&|partial| {
                with_lifecycle(AnalysisError::timeout(OPERATION, timeout_ms))
                    .retain_partial_observation(partial)
            }));
        }
        LldbOutcome::Exited { .. } => {}
    }
    if let Some(failure) = failed_output {
        return Ok(with_partial(&|partial| {
            tracer_failure(failure, lifecycle_cleanup.as_ref(), partial)
        }));
    }
    if let Some(process_failure) = &exited.cleanup_failure {
        return Ok(with_partial(&|partial| {
            let mut diagnostics = Map::new();
            diagnostics.insert(
                "reason".into(),
                json!("LLDB process-group cleanup could not be verified"),
            );
            diagnostics.insert("cleanup_failure".into(), json!(process_failure));
            if let Some(value) = &lifecycle_value {
                diagnostics.insert("target_cleanup".into(), value.clone());
            }
            let mut error = provider_cleanup_error(
                PROVIDER,
                owner.resources(),
                diagnostics,
                Some(OPERATION),
                None,
            );
            error.partial_observation = Some(partial);
            error
        }));
    }
    if !terminated {
        return Ok(with_partial(&|partial| {
            let mut diagnostics = Map::new();
            diagnostics.insert(
                "reason".into(),
                json!("LLDB target process termination could not be verified"),
            );
            if let Some(value) = &lifecycle_value {
                diagnostics.insert("target_cleanup".into(), value.clone());
            }
            let mut error = provider_cleanup_error(
                PROVIDER,
                owner.resources(),
                diagnostics,
                Some(OPERATION),
                None,
            );
            error.partial_observation = Some(partial);
            error
        }));
    }
    let Some(TracerOutput::Traced(run)) = output else {
        let (exit_code, lldb_output) = match &exited.outcome {
            LldbOutcome::Exited { exit_code, output } => (*exit_code, output.clone()),
            _ => (None, String::new()),
        };
        return Ok(with_partial(&|partial| {
            let mut diagnostics = Map::new();
            diagnostics.insert(
                "reason".into(),
                json!("LLDB exited without a usable tracer result"),
            );
            if let Some(Err(reason)) = &readback {
                diagnostics.insert("result_failure".into(), json!(reason));
            }
            diagnostics.insert("exit_code".into(), json!(exit_code));
            diagnostics.insert("lldb_output".into(), json!(lldb_output));
            if let Some(value) = &lifecycle_value {
                diagnostics.insert("target_cleanup".into(), value.clone());
            }
            with_lifecycle(
                AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics),
            )
            .retain_partial_observation(partial)
        }));
    };
    let counters = &run.target_output;
    let stdout = captured_output(
        &paths.stdout_capture,
        counters.stdout_bytes,
        counters.stdout_truncated,
        counters.stdout_complete,
    );
    let stderr = captured_output(
        &paths.stderr_capture,
        counters.stderr_bytes,
        counters.stderr_truncated,
        counters.stderr_complete,
    );
    let debugger_path = lldb.path.clone();
    let debugger_sha256 = lldb.sha256.clone();
    match (stdout, stderr) {
        (Ok(stdout), Ok(stderr)) => Ok(Ok(NativeCallTrace {
            debugger_path,
            debugger_sha256,
            run: run.clone(),
            stdout: Some(stdout),
            stderr: Some(stderr),
            terminated,
        })),
        (stdout, stderr) => {
            let mut diagnostics = Map::new();
            diagnostics.insert(
                "reason".into(),
                json!("LLDB target output capture could not be read"),
            );
            if let Err((failure, _)) = &stdout {
                diagnostics.insert("stdout_capture_error".into(), json!(failure.message));
            }
            if let Err((failure, _)) = &stderr {
                diagnostics.insert("stderr_capture_error".into(), json!(failure.message));
            }
            if let Some(value) = &lifecycle_value {
                diagnostics.insert("target_cleanup".into(), value.clone());
            }
            let pick =
                |read: Result<CapturedOutput, (ReadFailure, Option<CapturedOutput>)>| match read {
                    Ok(capture) => Some(capture),
                    Err((_, partial)) => partial,
                };
            let trace = NativeCallTrace {
                debugger_path,
                debugger_sha256,
                run: run.clone(),
                stdout: pick(stdout),
                stderr: pick(stderr),
                terminated,
            };
            let partial =
                project_partial(&request.facts(), &request.input, &trace, "capture-failure");
            Ok(Err(with_lifecycle(
                AnalysisError::provider_adapter(PROVIDER, OPERATION).with_diagnostics(diagnostics),
            )
            .retain_partial_observation(partial)))
        }
    }
}
