//! `RizinDebugSessionManager`: owned persistent Rizin debugger processes.
//!
//! Compatibility owner: `src/rizin/RizinDebugSessionManager.ts`. One manager
//! exists per MCP connection (`session.state`), registered once with
//! `own_once` so shutdown runs `close_all` like `createServer.ts`.

use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{SessionResource, ToolContext};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;

use super::frames::{
    CLEANUP_COMMAND_TIMEOUT_MS, Capture, Interruption, InterruptionKind, MAX_COMMAND_OUTPUT_BYTES,
    Shared, WaitError, truncate_utf8, wait_for_command_frames,
};
use crate::debugger::process::{DebuggerProcess, MAX_DIAGNOSTIC_BYTES};
use crate::debugger::{
    DebuggerSupervisor, DetachOutcome, OwnedDebuggerDetachResult, OwnedDebuggerProcess,
    OwnedDebuggerStopResult, OwnedInferiorIdentity, read_linux_process_start_time,
    stop_owned_debugger_process, verify_owned_inferiors_ended,
};

const MAX_SESSIONS: usize = 8;
const MAX_PENDING_COMMANDS: usize = 16;
const FRAME_TIMEOUT_MS: u64 = 120_000;
const STARTUP_TIMEOUT_MS: u64 = 30_000;
const DETACH_TIMEOUT_MS: u64 = 1_000;

const START: &str = "start_rizin_debug_session";
const COMMAND: &str = "rizin_debug_command";
const CLOSE: &str = "close_rizin_debug_session";
const DEBUGGER_NAME: &str = "Rizin debugger";

const LAUNCH_PROVENANCE_LIMITATION: &str = "Launch provenance records the original and resolved startup paths; it does not establish the current target after unrestricted debugger commands.";
const UNRESTRICTED_LIMITATION: &str = "The command is unrestricted and may access local files, the shell, network, or mutate the target.";

fn provider() -> EvidenceProvider {
    EvidenceProvider::new("rizin.debugger", "Rizin debugger", None)
}

#[derive(Clone, Debug)]
struct LaunchProvenance {
    caller_selected_path: String,
    resolved_path: String,
}

/// `RizinDebugCommandResult`.
#[derive(Clone, Debug)]
struct CommandResult {
    command: String,
    output: String,
    output_truncated: bool,
    output_invalid_utf8: bool,
    completion_status: &'static str,
    backend: Option<String>,
}

impl CommandResult {
    fn to_value(&self) -> Value {
        let mut value = json!({
            "command": self.command,
            "output": self.output,
            "output_scope": "command_and_interleaved_session_output",
            "output_truncated": self.output_truncated,
            "completion_status": self.completion_status,
            "backend": self.backend,
        });
        if self.output_invalid_utf8 {
            value["output_invalid_utf8"] = Value::Bool(true);
        }
        value
    }
}

/// Detach attempt shared across stop retries (`detachAttempts`).
type DetachSlot = Arc<(
    Mutex<Option<Result<OwnedDebuggerDetachResult, String>>>,
    Condvar,
)>;

/// Lifecycle bookkeeping outside the frame protocol state.
#[derive(Default)]
struct Lifecycle {
    cleanup_command_turn_held: bool,
    cleanup_failures: Vec<AnalysisError>,
    pending_command_count: usize,
    detach_outcome: Option<DetachOutcome>,
    detach_attempt: Option<DetachSlot>,
}

/// One owned Rizin debugger session (`RizinDebugSession`).
pub(super) struct RizinSession {
    id: String,
    process: Arc<DebuggerProcess>,
    shared: Arc<Shared>,
    backend: Option<String>,
    launch_provenance: LaunchProvenance,
    inferior_tty: String,
    inferior_tty_device: u64,
    inferior_tty_inode: u64,
    lifecycle: Mutex<Lifecycle>,
    /// Command turn (`commandTail`).
    turn: Mutex<bool>,
    turn_changed: Condvar,
    /// Serializes stop attempts (`stopAttempt`).
    stop_lock: Mutex<()>,
    weak_self: OnceLock<Weak<RizinSession>>,
}

fn relock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Releases the command turn on drop.
struct TurnGuard<'a>(&'a RizinSession);

impl Drop for TurnGuard<'_> {
    fn drop(&mut self) {
        *relock(&self.0.turn) = false;
        self.0.turn_changed.notify_all();
    }
}

impl RizinSession {
    fn lifecycle(&self) -> MutexGuard<'_, Lifecycle> {
        relock(&self.lifecycle)
    }

    /// `waitForTurn`; `None` when cancelled while queued.
    fn acquire_turn(&self, cancellation: Option<&Cancellation>) -> Option<TurnGuard<'_>> {
        let mut held = relock(&self.turn);
        loop {
            if cancellation.is_some_and(|c| c.reason().is_some()) {
                return None;
            }
            if !*held {
                *held = true;
                return Some(TurnGuard(self));
            }
            held = self
                .turn_changed
                .wait_timeout(held, Duration::from_millis(10))
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }

    fn command_evidence(
        &self,
        command: &str,
        result: &CommandResult,
        limitations: Vec<String>,
    ) -> Result<Evidence, AnalysisError> {
        let mut all = limitations;
        if result.completion_status == "unknown" {
            all.push("Interrupted output may include an incomplete completion-marker prefix; it is retained because it cannot be distinguished from command diagnostics.".to_owned());
        }
        if result.output_invalid_utf8 {
            all.push("Collected command frames contained invalid UTF-8 bytes; decoded text may contain replacement characters.".to_owned());
        }
        all.push(LAUNCH_PROVENANCE_LIMITATION.to_owned());
        let value = result.to_value();
        let observation = Observation::new(
            COMMAND,
            json!({
                "session_id": self.id,
                "command": command,
                "inferior_tty": self.inferior_tty,
                "launch_provenance": {
                    "caller_selected_path": self.launch_provenance.caller_selected_path,
                    "resolved_path": self.launch_provenance.resolved_path,
                },
            }),
            value.clone(),
        )
        .predicate("rea.debugger.command-observation")
        .raw(value)
        .subject_unavailable(
            "The current debugger target identity is not established by the Rizin session identifier.",
        )
        .limitations(all);
        Evidence::create(None, &provider(), observation)
            .map_err(|error| AnalysisError::output(COMMAND, error.to_string()))
    }

    /// `createRizinCommandTimeoutEvidence`.
    fn timeout_evidence(
        &self,
        command: &str,
        result: &CommandResult,
        cleanup_failure: Option<&str>,
    ) -> Result<Evidence, AnalysisError> {
        let mut limitations = vec!["The command timed out before its completion marker; retained output is partial and completion is unknown.".to_owned()];
        if result.output_invalid_utf8 {
            limitations.push("Collected command frame bytes did not form valid UTF-8; displayed output contains replacement characters.".to_owned());
        }
        limitations.push(match cleanup_failure {
            None => "The owned debugger session was stopped because output correlation could no longer be guaranteed.".to_owned(),
            Some(reason) => format!("The owned debugger session remains retained because cleanup could not be verified: {reason}"),
        });
        limitations.push(UNRESTRICTED_LIMITATION.to_owned());
        self.command_evidence(command, result, limitations)
    }

    /// `#retainCleanupFailure`.
    fn retain_cleanup_failure(
        &self,
        operation: &str,
        reason: &str,
        partial: Option<&Evidence>,
        captured: Option<CapturedOutput>,
    ) -> AnalysisError {
        let mut failure = AnalysisError::capability_unavailable(
            "rizin",
            operation,
            format!("The owned Rizin process could not be confirmed stopped: {reason}"),
        )
        .with_cleanup(reason, vec![self.id.clone()]);
        if let Some(evidence) = partial {
            failure = failure.retain_partial_observation(evidence.value().clone());
        }
        if let Some(captured) = captured {
            failure = failure.with_captured_output(captured);
        }
        self.lifecycle().cleanup_failures.push(failure.clone());
        failure
    }

    /// `#stopDebuggerOnly`.
    fn stop_debugger_only(&self, command_turn_held: bool) -> OwnedDebuggerStopResult {
        self.shared.lock().closing = true;
        let _stop = relock(&self.stop_lock);
        self.lifecycle().cleanup_command_turn_held = command_turn_held;
        let stopped = stop_owned_debugger_process(self, DEBUGGER_NAME);
        if !stopped.is_incomplete() {
            self.lifecycle().cleanup_failures.clear();
        }
        stopped
    }

    /// `#stopAfterProtocolFailure`.
    fn stop_after_protocol_failure(
        &self,
        command_turn_held: bool,
        partial: Option<&Evidence>,
    ) -> AnalysisError {
        match self.stop_debugger_only(command_turn_held) {
            OwnedDebuggerStopResult::Incomplete { reason } => {
                self.retain_cleanup_failure(COMMAND, &reason, partial, None)
            }
            _ => {
                let message = self
                    .shared
                    .lock()
                    .protocol_error
                    .clone()
                    .unwrap_or_default();
                let error = AnalysisError::capability_unavailable("rizin", COMMAND, message);
                match partial {
                    Some(evidence) => error.retain_partial_observation(evidence.value().clone()),
                    None => error,
                }
            }
        }
    }

    /// `#startupCapturedOutput`.
    fn startup_captured_output(&self) -> CapturedOutput {
        let diagnostics = self.process.diagnostics();
        let (protocol_output, history_truncated) = {
            let mut core = self.shared.lock();
            (core.protocol_output(), core.history_truncated)
        };
        let stdout = truncate_utf8(&protocol_output, MAX_DIAGNOSTIC_BYTES).to_owned();
        CapturedOutput {
            truncated: history_truncated
                || protocol_output.len() > stdout.len()
                || diagnostics.diagnostic_truncated
                || diagnostics.stderr_observed_bytes > diagnostics.stderr_bytes as u64,
            stdout,
            stderr: diagnostics.stderr_text,
            ..CapturedOutput::default()
        }
    }

    /// `#runInternalCommand`.
    fn run_internal_command(&self, command: &str) -> Result<String, String> {
        if self.shared.lock().has_unclaimed_frames() {
            return Err(
                "Unsolicited Rizin output prevents correlated cleanup readback.".to_owned(),
            );
        }
        let marker = format!("__REA_CLEANUP_COMPLETE_{}__", uuid::Uuid::new_v4().simple());
        if !self.process.stdin_writable() {
            return Err("Rizin stdin is unavailable during cleanup.".to_owned());
        }
        if let Err(cause) = self
            .process
            .write_stdin(format!("{command}\n!echo {marker}\n").as_bytes())
        {
            self.shared
                .lock()
                .fail_protocol(format!("Rizin stdin write failed: {cause}"));
            self.shared.notify();
        }
        let captured = wait_for_command_frames(
            &self.shared,
            &self.process,
            &marker,
            CLEANUP_COMMAND_TIMEOUT_MS,
            None,
            MAX_COMMAND_OUTPUT_BYTES,
        )
        .map_err(|interruption| interruption.cause)?;
        if captured.output_truncated {
            return Err("Rizin cleanup readback was truncated.".to_owned());
        }
        Ok(captured.output)
    }

    fn protocol_ambiguous(&self) -> bool {
        let mut core = self.shared.lock();
        Shared::observe_exit(&mut core, &self.process);
        core.exited || core.protocol_error.is_some()
    }

    /// `#detachInferior` (takes the command turn) or the unlocked variant.
    fn detach_inferior(&self) -> Result<OwnedDebuggerDetachResult, String> {
        if self.lifecycle().cleanup_command_turn_held {
            return self.detach_inferior_unlocked();
        }
        if self.protocol_ambiguous() {
            return Err(
                "Rizin protocol state is ambiguous; inferior detach is unverified.".to_owned(),
            );
        }
        let _turn = self.acquire_turn(None);
        self.detach_inferior_unlocked()
    }

    /// `#detachInferiorUnlocked`.
    fn detach_inferior_unlocked(&self) -> Result<OwnedDebuggerDetachResult, String> {
        if self.protocol_ambiguous() {
            return Err(
                "Rizin protocol state is ambiguous; inferior detach is unverified.".to_owned(),
            );
        }
        self.reset_inventory();
        let inferior = parse_rizin_ptrace_rows(&self.run_internal_command("olj")?)?;
        if inferior.is_empty() {
            let mut core = self.shared.lock();
            core.known_inferior_identities.clear();
            core.inferior_inventory_complete = true;
            return Ok(OwnedDebuggerDetachResult::NoInferior);
        }
        let mut identities: Vec<OwnedInferiorIdentity> = Vec::new();
        for (_, pid) in &inferior {
            if identities.iter().any(|identity| &identity.pid == pid) {
                continue;
            }
            let Some(start_time) = read_linux_process_start_time(pid)? else {
                self.shared.lock().known_inferior_identities = identities;
                return Err(format!(
                    "Inferior PID {pid} ended before its identity could be established."
                ));
            };
            identities.push(OwnedInferiorIdentity {
                pid: pid.clone(),
                start_time,
            });
        }
        {
            let mut core = self.shared.lock();
            core.known_inferior_identities = identities.clone();
            core.inferior_inventory_complete = true;
        }
        if inferior.len() != 1 {
            return Err("Rizin reported multiple or ambiguous ptrace inferiors.".to_owned());
        }
        let (fd, pid) = inferior[0].clone();
        let identity = identities
            .iter()
            .find(|identity| identity.pid == pid)
            .cloned()
            .ok_or_else(|| "Inferior identity was not recorded.".to_owned())?;
        assert_start_time_stable(&identity.start_time, read_linux_process_start_time(&pid)?)?;
        self.verify_debugger_exit_policy()?;
        self.verify_inferior_output_descriptors(&pid)?;
        self.run_internal_command(&format!("o- {fd}"))?;
        let after = parse_rizin_ptrace_rows(&self.run_internal_command("olj")?)?;
        if !after.is_empty() || after.iter().any(|(f, p)| *f == fd || *p == pid) {
            return Err(
                "Rizin did not confirm that the selected inferior FD was detached.".to_owned(),
            );
        }
        // Protocol readback must never be waived by proof that a process ended.
        self.verify_debugger_exit_policy()?;
        let readback = read_linux_process_start_time(&pid)
            .and_then(|after| assert_start_time_stable(&identity.start_time, after))
            .and_then(|()| self.verify_inferior_output_descriptors(&pid));
        if let Err(cause) = readback {
            // Detach resumes the inferior; only a previously identified
            // process can prove its end.
            if !verify_owned_inferiors_ended(std::iter::once(&identity))? {
                return Err(cause);
            }
            self.shared.lock().known_inferior_identities.clear();
            return Ok(OwnedDebuggerDetachResult::NoInferior);
        }
        Ok(OwnedDebuggerDetachResult::DetachedDurable)
    }

    fn reset_inventory(&self) {
        let mut core = self.shared.lock();
        core.inferior_inventory_complete = false;
        core.known_inferior_identities.clear();
    }

    /// `#verifyDebuggerExitPolicy`.
    fn verify_debugger_exit_policy(&self) -> Result<(), String> {
        if self.run_internal_command("e dbg.exitkills")?.trim() != "false" {
            return Err("Rizin dbg.exitkills readback did not confirm false.".to_owned());
        }
        Ok(())
    }

    /// `#verifyInferiorOutputDescriptors`.
    fn verify_inferior_output_descriptors(&self, pid: &str) -> Result<(), String> {
        tty::verify_descriptors(
            pid,
            &self.inferior_tty,
            self.inferior_tty_device,
            self.inferior_tty_inode,
        )
    }
}

impl DebuggerSupervisor for RizinSession {
    fn limit_additional_output_bytes(&self, max_bytes: usize) {
        self.process.limit_additional_output_bytes(max_bytes);
    }
    fn wait_for_output_close(&self, timeout: Duration) -> Result<bool, String> {
        Ok(self.process.wait_for_output_close(timeout))
    }
    fn unref_output_streams(&self) {
        self.process.unref_output_streams();
    }
    fn dispose(&self) {
        self.process.dispose();
    }
    fn term(&self) -> Result<(), String> {
        self.process.term_leader()
    }
    fn kill(&self) -> Result<(), String> {
        self.process.kill_leader()
    }
    fn wait_for_exit(&self, timeout: Duration) -> bool {
        let exited = self.process.wait_for_exit(timeout);
        if exited {
            let mut core = self.shared.lock();
            Shared::observe_exit(&mut core, &self.process);
            drop(core);
            self.shared.notify();
        }
        exited
    }
}

impl OwnedDebuggerProcess for RizinSession {
    fn id(&self) -> &str {
        &self.id
    }
    fn exited(&self) -> bool {
        let mut core = self.shared.lock();
        Shared::observe_exit(&mut core, &self.process);
        core.exited
    }
    fn supervisor(&self) -> &dyn DebuggerSupervisor {
        self
    }
    fn detach_outcome(&self) -> Option<DetachOutcome> {
        self.lifecycle().detach_outcome
    }
    fn set_detach_outcome(&self, outcome: DetachOutcome) {
        self.lifecycle().detach_outcome = Some(outcome);
    }
    fn detach_pending(&self) -> bool {
        self.lifecycle().detach_attempt.is_some()
    }
    fn inferior_state_unknown(&self) -> Option<bool> {
        Some(!self.shared.lock().inferior_inventory_complete)
    }
    fn verify_inferiors_ended_after_exit(&self) -> Option<Result<bool, String>> {
        let identities = {
            let core = self.shared.lock();
            if !core.inferior_inventory_complete {
                return Some(Ok(false));
            }
            core.known_inferior_identities.clone()
        };
        let ended = verify_owned_inferiors_ended(identities.iter());
        if matches!(ended, Ok(true)) {
            self.shared.lock().known_inferior_identities.clear();
        }
        Some(ended)
    }
    fn run_detach(&self) -> Result<Option<OwnedDebuggerDetachResult>, String> {
        let slot = {
            let mut lifecycle = self.lifecycle();
            if let Some(slot) = &lifecycle.detach_attempt {
                Arc::clone(slot)
            } else {
                let slot: DetachSlot = Arc::new((Mutex::new(None), Condvar::new()));
                lifecycle.detach_attempt = Some(Arc::clone(&slot));
                let session = self
                    .weak_self
                    .get()
                    .and_then(Weak::upgrade)
                    .ok_or_else(|| "Rizin session owner is unavailable.".to_owned())?;
                let worker_slot = Arc::clone(&slot);
                std::thread::spawn(move || {
                    let result = session.detach_inferior();
                    {
                        let mut lifecycle = session.lifecycle();
                        if lifecycle
                            .detach_attempt
                            .as_ref()
                            .is_some_and(|current| Arc::ptr_eq(current, &worker_slot))
                        {
                            lifecycle.detach_attempt = None;
                        }
                        lifecycle.detach_outcome = Some(match &result {
                            Ok(OwnedDebuggerDetachResult::NoInferior)
                            | Ok(OwnedDebuggerDetachResult::DetachedDurable) => {
                                DetachOutcome::Confirmed
                            }
                            Err(_) => DetachOutcome::Unconfirmed,
                        });
                    }
                    let (lock, cvar) = &*worker_slot;
                    *relock(lock) = Some(result);
                    cvar.notify_all();
                });
                slot
            }
        };
        let (lock, cvar) = &*slot;
        let guard = relock(lock);
        let (guard, _) = cvar
            .wait_timeout_while(guard, Duration::from_millis(DETACH_TIMEOUT_MS), |result| {
                result.is_none()
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match guard.clone() {
            None => Ok(None),
            Some(Ok(result)) => Ok(Some(result)),
            Some(Err(cause)) => Err(cause),
        }
    }
}

/// `parseRizinPtraceRows`: `(fd, pid)` for active ptrace descriptors.
fn parse_rizin_ptrace_rows(output: &str) -> Result<Vec<(String, String)>, String> {
    let parsed: Value = serde_json::from_str(output)
        .map_err(|_| "Rizin returned malformed JSON for `olj`.".to_owned())?;
    let Value::Array(rows) = parsed else {
        return Err("Rizin `olj` response is not an array.".to_owned());
    };
    let malformed = || "Rizin `olj` response contains a malformed descriptor row.".to_owned();
    let mut result = Vec::new();
    for row in rows {
        let Value::Object(row) = row else {
            return Err(malformed());
        };
        let fd = row
            .get("fd")
            .and_then(Value::as_number)
            .and_then(|number| {
                number.as_u64().or_else(|| {
                    number
                        .as_f64()
                        .filter(|value| {
                            value.fract() == 0.0
                                && *value >= 0.0
                                && *value <= 9_007_199_254_740_991.0
                        })
                        .map(|value| value as u64)
                })
            })
            .filter(|value| *value <= 9_007_199_254_740_991)
            .ok_or_else(malformed)?;
        let raised = row
            .get("raised")
            .and_then(Value::as_bool)
            .ok_or_else(malformed)?;
        let uri = row
            .get("uri")
            .and_then(Value::as_str)
            .ok_or_else(malformed)?;
        if let Some(pid) = uri.strip_prefix("ptrace://") {
            if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("Rizin `olj` returned a malformed ptrace URI.".to_owned());
            }
            if !raised {
                return Err("Rizin `olj` ptrace descriptor is not active.".to_owned());
            }
            result.push((fd.to_string(), pid.to_owned()));
        }
    }
    Ok(result)
}

/// `assertRizinProcessStartTimeStable`.
fn assert_start_time_stable(before: &str, after: Option<String>) -> Result<(), String> {
    if after.as_deref() != Some(before) {
        return Err(
            "The inferior PID disappeared or was reused during detach verification.".to_owned(),
        );
    }
    Ok(())
}

/// `absoluteCallerPath` (POSIX; persistent sessions run only on Linux).
fn absolute_caller_path(path: &str) -> String {
    if !path.starts_with('/') {
        let cwd = std::env::current_dir()
            .map(|dir| dir.to_string_lossy().into_owned())
            .unwrap_or_default();
        let base = if cwd.starts_with('/') {
            cwd
        } else {
            absolute_caller_path(&cwd)
        };
        return absolute_caller_path(&format!("{base}/{path}"));
    }
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let directory = (path.ends_with('/') || path.ends_with("/.")) && !segments.is_empty();
    format!(
        "/{}{}",
        segments.join("/"),
        if directory { "/" } else { "" }
    )
}

#[cfg(unix)]
mod tty {
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

    /// Validated inferior TTY identity.
    pub(super) struct TtyIdentity {
        pub(super) path: String,
        pub(super) device: u64,
        pub(super) inode: u64,
    }

    /// realpath + open(O_RDWR|O_NOCTTY|O_NONBLOCK) + isatty + S_IFCHR.
    pub(super) fn validate(input: &str) -> Result<TtyIdentity, String> {
        let path = std::fs::canonicalize(input)
            .map_err(|error| error.to_string())?
            .into_os_string()
            .into_string()
            .map_err(|_| "The selected inferior_tty path is not valid UTF-8.".to_owned())?;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open(&path)
            .map_err(|error| error.to_string())?;
        let metadata = file.metadata().map_err(|error| error.to_string())?;
        if !rustix::termios::isatty(&file) || !metadata.file_type().is_char_device() {
            return Err("The selected inferior_tty is not a character TTY.".to_owned());
        }
        Ok(TtyIdentity {
            path,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    pub(super) fn verify_descriptors(
        pid: &str,
        tty: &str,
        device: u64,
        inode: u64,
    ) -> Result<(), String> {
        for descriptor in ["1", "2"] {
            let descriptor_path = format!("/proc/{pid}/fd/{descriptor}");
            let destination =
                std::fs::read_link(&descriptor_path).map_err(|error| error.to_string())?;
            let metadata =
                std::fs::metadata(&descriptor_path).map_err(|error| error.to_string())?;
            let resolved =
                std::fs::canonicalize(&destination).map_err(|error| error.to_string())?;
            if metadata.dev() != device
                || metadata.ino() != inode
                || !metadata.file_type().is_char_device()
                || resolved.as_os_str() != std::ffi::OsStr::new(tty)
            {
                return Err(format!(
                    "Inferior descriptor {descriptor} is not routed to the selected TTY."
                ));
            }
        }
        Ok(())
    }
}

#[cfg(not(unix))]
mod tty {
    pub(super) struct TtyIdentity {
        pub(super) path: String,
        pub(super) device: u64,
        pub(super) inode: u64,
    }
    pub(super) fn validate(_input: &str) -> Result<TtyIdentity, String> {
        Err("Inferior TTY validation requires a POSIX host.".to_owned())
    }
    pub(super) fn verify_descriptors(_: &str, _: &str, _: u64, _: u64) -> Result<(), String> {
        Err("Inferior descriptor verification requires Linux /proc.".to_owned())
    }
}

#[derive(Default)]
struct ManagerInner {
    sessions: HashMap<String, Arc<RizinSession>>,
    active_starts: usize,
    session_reservations: usize,
    closing_all: bool,
}

/// Per-MCP-session manager (`RizinDebugSessionManager`).
#[derive(Default)]
pub(crate) struct RizinState {
    inner: Mutex<ManagerInner>,
    starts_drained: Condvar,
}

/// Start input (`start` argument).
pub(super) struct StartInput {
    pub(super) path: String,
    pub(super) inferior_tty: String,
    pub(super) backend: Option<String>,
}

/// Releases the start reservation and active-start count on drop.
struct StartGuard<'a> {
    state: &'a RizinState,
    reserved: bool,
}

impl StartGuard<'_> {
    fn release_reservation(&mut self) {
        if self.reserved {
            self.reserved = false;
            self.state.inner().session_reservations -= 1;
        }
    }
}

impl Drop for StartGuard<'_> {
    fn drop(&mut self) {
        self.release_reservation();
        let mut inner = self.state.inner();
        inner.active_starts -= 1;
        if inner.active_starts == 0 {
            self.state.starts_drained.notify_all();
        }
    }
}

impl RizinState {
    fn inner(&self) -> MutexGuard<'_, ManagerInner> {
        relock(&self.inner)
    }

    fn session(&self, id: &str) -> Option<Arc<RizinSession>> {
        self.inner().sessions.get(id).cloned()
    }

    fn remove_if_same(&self, session: &Arc<RizinSession>) {
        let mut inner = self.inner();
        if inner
            .sessions
            .get(&session.id)
            .is_some_and(|current| Arc::ptr_eq(current, session))
        {
            inner.sessions.remove(&session.id);
        }
    }

    /// `start`.
    pub(super) fn start(
        &self,
        context: &ToolContext<'_>,
        input: StartInput,
    ) -> Result<Value, AnalysisError> {
        {
            let mut inner = self.inner();
            if inner.closing_all {
                return Err(AnalysisError::input(START, Vec::new()));
            }
            let occupied = inner.sessions.len() + inner.session_reservations;
            if occupied >= MAX_SESSIONS {
                return Err(AnalysisError::resource_constraint(
                    START,
                    "memory",
                    "Rizin session capacity reached.",
                    Some(json!({
                        "max_sessions": MAX_SESSIONS,
                        "active_or_reserved_sessions": occupied,
                    })),
                ));
            }
            inner.active_starts += 1;
            inner.session_reservations += 1;
        }
        let mut guard = StartGuard {
            state: self,
            reserved: true,
        };
        self.start_reserved(context, input, &mut guard)
    }

    fn start_reserved(
        &self,
        context: &ToolContext<'_>,
        input: StartInput,
        guard: &mut StartGuard<'_>,
    ) -> Result<Value, AnalysisError> {
        let cancellation = &context.cancellation;
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(START));
        }
        if !cfg!(target_os = "linux") {
            return Err(AnalysisError::capability_unavailable(
                "rizin",
                START,
                "Persistent Rizin debugger sessions require Linux /proc descriptor readback to verify inferior detachment and output routing.",
            ));
        }
        if input.inferior_tty.is_empty() {
            return Err(AnalysisError::input(START, Vec::new()));
        }
        let tty = tty::validate(&input.inferior_tty)
            .map_err(|_| AnalysisError::input(START, Vec::new()))?;
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(START));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let resolved_path = absolute_caller_path(&input.path);
        let launch_provenance = LaunchProvenance {
            caller_selected_path: input.path.clone(),
            resolved_path: resolved_path.clone(),
        };
        let mut arguments = vec![
            "-N".to_owned(),
            "-0".to_owned(),
            "-d".to_owned(),
            "-R".to_owned(),
            format!("stdout={}", tty.path),
            "-R".to_owned(),
            format!("stderr={}", tty.path),
            "-e".to_owned(),
            "dbg.exitkills=false".to_owned(),
        ];
        if let Some(backend) = &input.backend {
            arguments.push("-D".to_owned());
            arguments.push(backend.clone());
        }
        arguments.push(resolved_path);

        let environment = context.session.environment();
        let command = environment
            .get("REA_RIZIN_COMMAND")
            .cloned()
            .unwrap_or_else(|| "rizin".to_owned());
        let shared = Arc::new(Shared::default());
        let reader = Arc::clone(&shared);
        let eof = Arc::clone(&shared);
        let process = match DebuggerProcess::spawn(
            &command,
            &arguments,
            environment,
            &id,
            move |chunk| reader.on_stdout(chunk),
            move || eof.notify(),
        ) {
            Ok(process) => process,
            Err(cause) => {
                if cancellation.reason().is_some() {
                    return Err(AnalysisError::cancelled(START));
                }
                return Err(AnalysisError::capability_unavailable("rizin", START, cause));
            }
        };
        let session = Arc::new(RizinSession {
            id: id.clone(),
            process,
            shared,
            backend: input.backend.clone(),
            launch_provenance,
            inferior_tty: tty.path,
            inferior_tty_device: tty.device,
            inferior_tty_inode: tty.inode,
            lifecycle: Mutex::new(Lifecycle::default()),
            turn: Mutex::new(false),
            turn_changed: Condvar::new(),
            stop_lock: Mutex::new(()),
            weak_self: OnceLock::new(),
        });
        let _ = session.weak_self.set(Arc::downgrade(&session));
        self.inner()
            .sessions
            .insert(id.clone(), Arc::clone(&session));
        guard.release_reservation();

        let startup = {
            let core = session.shared.lock();
            let (mut core, frame) = session.shared.wait_for_frame(
                core,
                &session.process,
                Duration::from_millis(STARTUP_TIMEOUT_MS),
                Some(cancellation),
            );
            match frame {
                Err(cause) => Err(cause),
                Ok(_) => {
                    // Observe lifecycle notifications queued with the frame.
                    Shared::observe_exit(&mut core, &session.process);
                    if cancellation.reason().is_some() {
                        Err(WaitError::Cancelled)
                    } else if core.exited {
                        Err(WaitError::Exited("Rizin exited during startup.".to_owned()))
                    } else if let Some(error) = core.protocol_error.clone() {
                        Err(WaitError::Failed(error))
                    } else {
                        core.ready = true;
                        Ok(())
                    }
                }
            }
        };
        let Err(cause) = startup else {
            return Ok(json!({ "session_id": id, "backend": input.backend }));
        };
        let stopped = session.stop_debugger_only(false);
        let captured = session.startup_captured_output();
        if let OwnedDebuggerStopResult::Incomplete { reason } = &stopped {
            return Err(session.retain_cleanup_failure(START, reason, None, Some(captured)));
        }
        self.remove_if_same(&session);
        if cancellation.reason().is_some() || matches!(cause, WaitError::Cancelled) {
            return Err(AnalysisError::cancelled(START).with_captured_output(captured));
        }
        if let Some(error) = session.shared.lock().protocol_error.clone() {
            return Err(AnalysisError::capability_unavailable("rizin", START, error)
                .with_captured_output(captured));
        }
        if let WaitError::Exited(message) = cause {
            return Err(
                AnalysisError::capability_unavailable("rizin", START, message)
                    .with_captured_output(captured),
            );
        }
        Err(AnalysisError::timeout(START, STARTUP_TIMEOUT_MS).with_captured_output(captured))
    }

    /// `execute`.
    pub(super) fn execute(
        &self,
        context: &ToolContext<'_>,
        session_id: &str,
        command: &str,
    ) -> Result<Evidence, AnalysisError> {
        let closing_all = self.inner().closing_all;
        let Some(session) = self.session(session_id) else {
            return Err(AnalysisError::input(COMMAND, Vec::new()));
        };
        {
            let mut core = session.shared.lock();
            Shared::observe_exit(&mut core, &session.process);
            if !core.ready
                || core.exited
                || core.protocol_error.is_some()
                || core.closing
                || closing_all
            {
                return Err(AnalysisError::input(COMMAND, Vec::new()));
            }
        }
        let cancellation = &context.cancellation;
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(COMMAND));
        }
        {
            let mut lifecycle = session.lifecycle();
            if lifecycle.pending_command_count >= MAX_PENDING_COMMANDS {
                return Err(AnalysisError::resource_constraint(
                    COMMAND,
                    "transport",
                    "Rizin command queue capacity reached.",
                    Some(json!({
                        "max_pending_commands": MAX_PENDING_COMMANDS,
                        "active_or_queued_commands": lifecycle.pending_command_count,
                    })),
                ));
            }
            lifecycle.pending_command_count += 1;
        }
        let result = match session.acquire_turn(Some(cancellation)) {
            None => Err(AnalysisError::cancelled(COMMAND)),
            Some(turn) => {
                let result = self.execute_turn(context, &session, command);
                session.shared.lock().command_capture_active = false;
                drop(turn);
                result
            }
        };
        session.lifecycle().pending_command_count -= 1;
        result
    }

    fn execute_turn(
        &self,
        context: &ToolContext<'_>,
        session: &RizinSession,
        command: &str,
    ) -> Result<Evidence, AnalysisError> {
        let cancellation = &context.cancellation;
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(COMMAND));
        }
        let closing_all = self.inner().closing_all;
        {
            let mut core = session.shared.lock();
            Shared::observe_exit(&mut core, &session.process);
            if !core.ready
                || core.exited
                || core.closing
                || closing_all
                || core.protocol_error.is_some()
            {
                return Err(AnalysisError::input(COMMAND, Vec::new()));
            }
            if core.has_unclaimed_frames() {
                core.fail_protocol("Unsolicited Rizin frames arrived before a command; command output can no longer be safely correlated.");
                drop(core);
                return Err(session.stop_after_protocol_failure(true, None));
            }
            // Arbitrary debugger commands can create or replace inferiors.
            core.inferior_inventory_complete = false;
            core.known_inferior_identities.clear();
            core.command_capture_active = true;
            core.command_output_dropped = false;
        }
        let marker = format!("__REA_COMMAND_COMPLETE_{}__", uuid::Uuid::new_v4().simple());
        if !session.process.stdin_writable() {
            session
                .shared
                .lock()
                .fail_protocol("Rizin stdin stream is closed.");
        } else if let Err(cause) = session
            .process
            .write_stdin(format!("{command}\n!echo {marker}\n").as_bytes())
        {
            session
                .shared
                .lock()
                .fail_protocol(format!("Rizin stdin write failed: {cause}"));
        }
        session.shared.notify();
        let received = wait_for_command_frames(
            &session.shared,
            &session.process,
            &marker,
            FRAME_TIMEOUT_MS,
            Some(cancellation),
            MAX_COMMAND_OUTPUT_BYTES,
        );
        let command_result = |capture: &Capture, completion: &'static str| CommandResult {
            command: command.to_owned(),
            output: capture.output.clone(),
            output_truncated: capture.output_truncated,
            output_invalid_utf8: capture.output_invalid_utf8,
            completion_status: completion,
            backend: session.backend.clone(),
        };
        let (capture, interruption) = match received {
            Ok(captured) if cancellation.reason().is_none() => {
                let mut cleanup_failure = None;
                if captured.output_truncated
                    && let OwnedDebuggerStopResult::Incomplete { reason } =
                        session.stop_debugger_only(true)
                {
                    cleanup_failure = Some(reason);
                }
                let result = command_result(
                    &captured,
                    if captured.output_truncated {
                        "unknown"
                    } else {
                        "complete"
                    },
                );
                let mut limitations = vec![
                    "Rizin commands and debugger effects depend on the loaded IO plugin and target.".to_owned(),
                    "Output contains all NUL frames through an explicit command-completion marker; backend output interleaved before that marker cannot be distinguished from command output.".to_owned(),
                ];
                if captured.output_truncated {
                    limitations.push(format!(
                        "The Rizin command exceeded the output or frame limit. Retained output is partial and command completion is unknown.{}",
                        match &cleanup_failure {
                            None => " The owned debugger session was stopped.".to_owned(),
                            Some(reason) => format!(" The owned debugger session remains retained because cleanup could not be verified: {reason}"),
                        }
                    ));
                }
                limitations.push(UNRESTRICTED_LIMITATION.to_owned());
                let evidence = session.command_evidence(command, &result, limitations)?;
                if let Some(reason) = cleanup_failure {
                    return Err(session.retain_cleanup_failure(
                        COMMAND,
                        &reason,
                        Some(&evidence),
                        None,
                    ));
                }
                return Ok(evidence);
            }
            Ok(captured) => (captured, None),
            Err(interruption) => (interruption.capture.clone(), Some(interruption)),
        };
        self.command_failure(
            context,
            session,
            command,
            &capture,
            interruption,
            &command_result,
        )
    }

    /// The `catch` branch of `execute`.
    fn command_failure(
        &self,
        context: &ToolContext<'_>,
        session: &RizinSession,
        command: &str,
        capture: &Capture,
        interruption: Option<Interruption>,
        command_result: &dyn Fn(&Capture, &'static str) -> CommandResult,
    ) -> Result<Evidence, AnalysisError> {
        let partial_result = command_result(capture, "unknown");
        let captured_output = CapturedOutput {
            stdout: capture.output.clone(),
            stderr: String::new(),
            truncated: capture.output_truncated,
            ..CapturedOutput::default()
        };
        let partial_evidence = |limitations: Vec<String>| {
            session.command_evidence(command, &partial_result, limitations)
        };
        let kind = interruption.as_ref().map(|interruption| interruption.kind);
        if context.cancellation.reason().is_some() || kind == Some(InterruptionKind::Cancelled) {
            let evidence = partial_evidence(vec![
                "The Rizin command was cancelled; collected frame output is partial and command completion is unknown.".to_owned(),
                "The owned debugger session was stopped because command output can no longer be correlated safely.".to_owned(),
                UNRESTRICTED_LIMITATION.to_owned(),
            ])?;
            session.shared.lock().protocol_error = Some("A Rizin command was cancelled; the owned session was stopped because command output can no longer be correlated safely.".to_owned());
            if let OwnedDebuggerStopResult::Incomplete { reason } = session.stop_debugger_only(true)
            {
                return Err(session.retain_cleanup_failure(
                    COMMAND,
                    &reason,
                    Some(&evidence),
                    None,
                ));
            }
            return Err(AnalysisError::cancelled(COMMAND)
                .with_captured_output(captured_output)
                .retain_partial_observation(evidence.into_value()));
        }
        if let Some(protocol_error) = session.shared.lock().protocol_error.clone() {
            let evidence = partial_evidence(vec![
                protocol_error,
                "The Rizin protocol failed; retained command output is partial and completion is unknown.".to_owned(),
                UNRESTRICTED_LIMITATION.to_owned(),
            ])?;
            return Err(session.stop_after_protocol_failure(true, Some(&evidence)));
        }
        if kind == Some(InterruptionKind::Timeout) {
            session.shared.lock().protocol_error = Some("Rizin command timed out before its completion marker; output correlation is no longer safe.".to_owned());
            let stopped = session.stop_debugger_only(true);
            let mut result = command_result(capture, "unknown");
            result.output_truncated = true;
            let reason = match &stopped {
                OwnedDebuggerStopResult::Incomplete { reason } => Some(reason.as_str()),
                _ => None,
            };
            let evidence = session.timeout_evidence(command, &result, reason)?;
            if let Some(reason) = reason {
                return Err(session.retain_cleanup_failure(COMMAND, reason, Some(&evidence), None));
            }
            return Ok(evidence);
        }
        if kind == Some(InterruptionKind::Exited) {
            let evidence = partial_evidence(vec![
                "Rizin exited before the command-completion marker; retained frame output is partial and command completion is unknown.".to_owned(),
                UNRESTRICTED_LIMITATION.to_owned(),
            ])?;
            if let OwnedDebuggerStopResult::Incomplete { reason } = session.stop_debugger_only(true)
            {
                return Err(session.retain_cleanup_failure(
                    COMMAND,
                    &reason,
                    Some(&evidence),
                    None,
                ));
            }
            return Ok(evidence);
        }
        let message = "Rizin did not return the current command-completion marker; the session was stopped to prevent late output from being attributed to a later command.";
        session.shared.lock().protocol_error = Some(message.to_owned());
        let evidence =
            partial_evidence(vec![message.to_owned(), UNRESTRICTED_LIMITATION.to_owned()])?;
        if let OwnedDebuggerStopResult::Incomplete { reason } = session.stop_debugger_only(true) {
            return Err(session.retain_cleanup_failure(COMMAND, &reason, Some(&evidence), None));
        }
        Err(AnalysisError::timeout(COMMAND, FRAME_TIMEOUT_MS)
            .retain_partial_observation(evidence.into_value()))
    }

    /// `status`; `None` for an unknown session.
    pub(super) fn status(&self, session_id: &str) -> Option<Value> {
        let session = self.session(session_id)?;
        let diagnostics_truncated = session.process.diagnostics().diagnostic_truncated;
        let mut core = session.shared.lock();
        Shared::observe_exit(&mut core, &session.process);
        let closed = core.exited || core.protocol_error.is_some() || core.closing || !core.ready;
        Some(json!({
            "session_id": session.id,
            "state": if closed { "closed" } else { "ready" },
            "inferior_tty": session.inferior_tty,
            "recent_output": core.history,
            "recent_output_truncated": core.history_truncated,
            "diagnostics_truncated": diagnostics_truncated,
            "output_invalid_utf8": core.invalid_utf8_observed,
        }))
    }

    /// `close`.
    pub(super) fn close(&self, session_id: &str) -> Result<Value, AnalysisError> {
        if self.inner().closing_all {
            return Err(AnalysisError::input(CLOSE, Vec::new()));
        }
        let Some(session) = self.session(session_id) else {
            return Err(AnalysisError::input(CLOSE, Vec::new()));
        };
        session.shared.lock().closing = true;
        if let OwnedDebuggerStopResult::Incomplete { reason } = session.stop_debugger_only(false) {
            return Err(session.retain_cleanup_failure(CLOSE, &reason, None, None));
        }
        self.remove_if_same(&session);
        Ok(json!({ "target_state": "unknown" }))
    }

    /// `retryCleanupFailures`.
    pub(super) fn retry_cleanup_failures(&self) -> Result<(), AnalysisError> {
        let sessions: Vec<Arc<RizinSession>> = self.inner().sessions.values().cloned().collect();
        for session in sessions {
            if session.lifecycle().cleanup_failures.is_empty() {
                continue;
            }
            if let OwnedDebuggerStopResult::Incomplete { reason } =
                session.stop_debugger_only(false)
            {
                let last = session.lifecycle().cleanup_failures.last().cloned();
                return Err(last.unwrap_or_else(|| {
                    session.retain_cleanup_failure(CLOSE, &reason, None, None)
                }));
            }
            self.remove_if_same(&session);
        }
        Ok(())
    }

    /// `closeAll` + `closeOwnedDebuggerSessions`.
    fn close_all(&self) -> Result<(), AnalysisError> {
        let sessions: Vec<Arc<RizinSession>> = {
            let mut inner = self.inner();
            inner.closing_all = true;
            while inner.active_starts > 0 {
                inner = self
                    .starts_drained
                    .wait(inner)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            inner.sessions.values().cloned().collect()
        };
        for session in &sessions {
            session.shared.lock().closing = true;
        }
        let results: Vec<(Arc<RizinSession>, OwnedDebuggerStopResult)> =
            std::thread::scope(|scope| {
                let handles: Vec<_> = sessions
                    .iter()
                    .map(|session| {
                        let session = Arc::clone(session);
                        scope.spawn(move || {
                            let stopped = session.stop_debugger_only(false);
                            (session, stopped)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .filter_map(|handle| handle.join().ok())
                    .collect()
            });
        let mut failures = Vec::new();
        let mut unresolved = Vec::new();
        for (session, stopped) in results {
            match stopped {
                OwnedDebuggerStopResult::Incomplete { reason } => {
                    failures.push(reason);
                    unresolved.push(session.id.clone());
                }
                _ => self.remove_if_same(&session),
            }
        }
        if failures.is_empty() {
            return Ok(());
        }
        let reason = format!(
            "One or more owned Rizin processes did not stop cleanly: {}",
            failures.join("; ")
        );
        Err(
            AnalysisError::capability_unavailable("rizin", CLOSE, reason.clone())
                .with_cleanup(reason, unresolved),
        )
    }
}

impl SessionResource for RizinState {
    fn close(&self) -> Result<(), AnalysisError> {
        self.close_all()
    }
}
