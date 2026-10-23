//! Owned persistent GDB/MI sessions (`GdbSessionManager`).
//!
//! Compatibility owner: `src/gdb/GdbSessionManager.ts` and its registration in
//! `src/server/registerGdbTools.ts`. Persistent sessions are available only on
//! Linux, where REA verifies live inferior output descriptors through `/proc`
//! before detaching; on every other platform `start_gdb_session` returns a
//! platform-specific `AnalysisCapabilityUnavailableError` after the input and
//! cancellation checks, in the exact TypeScript order.
//!
//! The TypeScript model is event-driven and asynchronous. This port owns each
//! GDB process through the shared `super::super::debugger` primitives (launched
//! with `rea_host::process::launcher::launch_protocol`, so stdout framing is
//! owned here) plus one bounded reader thread, and drives the identical
//! request/response lifecycle with a blocking per-session command queue and
//! a condvar-signalled MI framing loop. The mutable session data lives in a
//! shared [`Inner`] the reader thread references, so the reader, the command
//! callers and the shutdown path all synchronize through one mutex.
//!
//! The admission hooks the TS registration passes
//! (`withAdmittedExternalMutation`, `runOwnedCleanupWithExternalMutationAdmission`)
//! are owned by the binary-session crate and unreachable here; following the
//! `cutter` and `rea-tools-captures/src/reverse` precedent, this registration
//! takes the path the TS code takes when the admission hook is `undefined`
//! (call the manager directly, running `retry_cleanup_failures` first for
//! `gdb_console`). Reported as a requested shared change.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use rea_core::analysis_error::{AnalysisError, ErrorKind, InputIssue};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{SessionResource, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

use super::super::debugger::{
    DebuggerProcess, DebuggerSupervisor, DetachOutcome, OwnedDebuggerDetachResult,
    OwnedDebuggerProcess, OwnedDebuggerStopResult, OwnedInferiorIdentity,
    stop_owned_debugger_process, verify_owned_inferiors_ended,
};
use super::mi::{
    command_may_change_inferior_output, gdb_thread_group_count, gdb_thread_group_pids, mi_quote,
    mi_string_field, truncate_utf8_record_prefix,
};

const STARTUP_TIMEOUT_MS: u64 = 10_000;
const COMMAND_TIMEOUT_MS: u64 = 120_000;
const MAX_COMMAND_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_COMMAND_OUTPUT_RECORDS: usize = 16_384;
const MAX_MI_LINE_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECENT_MI_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_SESSIONS: usize = 8;
const MAX_PENDING_GDB_COMMANDS: usize = 16;

/// `GDB_PROVIDER_IDENTITY`.
fn gdb_provider() -> EvidenceProvider {
    EvidenceProvider::new("gnu.gdb", "GNU GDB", None)
}

/// One complete GDB/MI command result (`GdbCommandResult`).
#[derive(Clone, Debug, Default)]
struct GdbCommandResult {
    command: String,
    mi: String,
    records: Vec<String>,
    console: String,
    target: String,
    log: String,
    process_exit_observed: bool,
    process_exit_code: Option<i64>,
    process_exit_signal: Option<String>,
    output_truncated: bool,
    completion_status: CompletionStatus,
    output_invalid_utf8: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
enum CompletionStatus {
    Complete,
    #[default]
    Unknown,
}

impl CompletionStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Unknown => "unknown",
        }
    }
}

/// Build the MI-record projection object (shared by `result` and `rawResult`).
fn result_value(result: &GdbCommandResult) -> Value {
    let mut map = Map::new();
    map.insert("command".to_owned(), json!(result.command));
    map.insert("mi".to_owned(), json!(result.mi));
    map.insert(
        "records".to_owned(),
        Value::Array(result.records.iter().map(|r| json!(r)).collect()),
    );
    map.insert("console".to_owned(), json!(result.console));
    map.insert("target".to_owned(), json!(result.target));
    map.insert("log".to_owned(), json!(result.log));
    if result.process_exit_observed {
        map.insert("process_exit_observed".to_owned(), json!(true));
        map.insert(
            "process_exit_code".to_owned(),
            result.process_exit_code.map_or(Value::Null, |c| json!(c)),
        );
        map.insert(
            "process_exit_signal".to_owned(),
            result
                .process_exit_signal
                .clone()
                .map_or(Value::Null, Value::String),
        );
    }
    map.insert(
        "output_truncated".to_owned(),
        json!(result.output_truncated),
    );
    if result.output_invalid_utf8 {
        map.insert("output_invalid_utf8".to_owned(), json!(true));
    }
    map.insert(
        "completion_status".to_owned(),
        json!(result.completion_status.as_str()),
    );
    Value::Object(map)
}

fn stream_filter(records: &[String], prefix: char) -> String {
    records
        .iter()
        .filter(|line| line.starts_with(prefix))
        .cloned()
        .collect::<Vec<_>>()
        .join("\n")
}

/// Outcome stored for a blocked `request_internal` caller, keyed by token.
#[derive(Clone)]
enum CommandOutcome {
    Done(GdbCommandResult),
    ProcessExit(GdbCommandResult),
    Protocol {
        message: String,
        partial: GdbCommandResult,
    },
}

/// One in-flight MI command (`PendingCommand`).
struct Pending {
    command: String,
    evidence_command: String,
    lines: Vec<String>,
    output_bytes: usize,
    output_truncated: bool,
    output_invalid_utf8: bool,
    terminal_record: Option<String>,
    awaiting_inferior_stop: bool,
}

/// Mutable session data guarded by one mutex (`GdbSession` fields in TS).
struct SessionState {
    lines: Vec<String>,
    buffer: Vec<u8>,
    buffer_bytes: usize,
    invalid_utf8_observed: bool,
    prompt_tail: String,
    startup_prompt_seen: bool,
    ready: bool,
    exited: bool,
    exit_code: Option<i64>,
    exit_signal: Option<String>,
    next_token: u64,
    protocol_error: Option<String>,
    recent_records_truncated: bool,
    pending: HashMap<u64, Pending>,
    delivered: HashMap<u64, CommandOutcome>,
    inferior_tty_verified: bool,
    no_inferior_verified: bool,
    known_inferior_identities: HashMap<String, OwnedInferiorIdentity>,
}

impl SessionState {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            buffer: Vec::new(),
            buffer_bytes: 0,
            invalid_utf8_observed: false,
            prompt_tail: String::new(),
            startup_prompt_seen: false,
            ready: false,
            exited: false,
            exit_code: None,
            exit_signal: None,
            next_token: 1,
            protocol_error: None,
            recent_records_truncated: false,
            pending: HashMap::new(),
            delivered: HashMap::new(),
            // GDB is launched with --nx and receives no target-execution
            // command during startup, so no inferior can exist until execute().
            inferior_tty_verified: false,
            no_inferior_verified: true,
            known_inferior_identities: HashMap::new(),
        }
    }
}

/// Shared session core referenced by the reader thread and command callers.
struct Inner {
    id: String,
    mi_version: &'static str,
    inferior_tty: Option<String>,
    max_command_output_bytes: usize,
    command_timeout_ms: u64,
    state: Mutex<SessionState>,
    signal: Condvar,
    command_lock: Mutex<()>,
    pending_command_count: AtomicU64,
    process: Mutex<Option<Arc<DebuggerProcess>>>,
}

impl Inner {
    fn lock(&self) -> std::sync::MutexGuard<'_, SessionState> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn process(&self) -> Option<Arc<DebuggerProcess>> {
        self.process
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn set_process(&self, process: Arc<DebuggerProcess>) {
        *self.process.lock().unwrap_or_else(|p| p.into_inner()) = Some(process);
    }

    /// Ingest one stdout chunk (`#receive`).
    fn receive(&self, chunk: &[u8]) {
        let mut state = self.lock();
        if !state.startup_prompt_seen {
            let mut prompt = state.prompt_tail.clone();
            prompt.push_str(&String::from_utf8_lossy(chunk));
            if prompt.contains("(gdb)") {
                state.startup_prompt_seen = true;
            }
            let tail_start = prompt.len().saturating_sub(4);
            state.prompt_tail = prompt[tail_start..].to_owned();
        }

        let mut framed: Vec<(String, bool)> = Vec::new();
        let mut offset = 0usize;
        let mut protocol_broke = false;
        while offset < chunk.len() {
            let newline = chunk[offset..].iter().position(|&b| b == 0x0a);
            let end = newline.map_or(chunk.len(), |n| offset + n);
            let piece = &chunk[offset..end];
            state.buffer_bytes += piece.len();
            let trailing_cr = newline.is_some() && piece.last() == Some(&0x0d);
            let line_bytes = state.buffer_bytes - usize::from(trailing_cr);
            if line_bytes > MAX_MI_LINE_BYTES {
                protocol_broke = true;
                break;
            }
            state.buffer.extend_from_slice(piece);
            let Some(n) = newline else {
                break;
            };
            let _ = n;
            let mut record = std::mem::take(&mut state.buffer);
            state.buffer_bytes = 0;
            if record.last() == Some(&0x0d) {
                record.pop();
            }
            let invalid_utf8 = std::str::from_utf8(&record).is_err();
            let line = String::from_utf8_lossy(&record).into_owned();
            if invalid_utf8 {
                state.invalid_utf8_observed = true;
            }
            if !line.is_empty() {
                framed.push((line, invalid_utf8));
            }
            offset = end + 1;
        }

        if protocol_broke {
            fail_protocol_locked(
                &mut state,
                "GDB emitted an MI line exceeding the 16 MiB protocol limit.",
            );
        } else {
            for (line, _) in &framed {
                if line.len() > MAX_RECENT_MI_LINE_BYTES {
                    state.lines.push(truncate_utf8_record_prefix(line));
                    state.recent_records_truncated = true;
                } else {
                    state.lines.push(line.clone());
                }
            }
            if state.lines.len() > 256 {
                let excess = state.lines.len() - 256;
                state.lines.drain(0..excess);
                state.recent_records_truncated = true;
            }
            self.consume_lines_locked(&mut state, &framed);
        }
        drop(state);
        self.signal.notify_all();
    }

    /// Append freshly framed lines to every pending command and resolve those
    /// that terminate (`#receive` line loop).
    fn consume_lines_locked(&self, state: &mut SessionState, framed: &[(String, bool)]) {
        for (line, invalid_utf8) in framed {
            for pending in state.pending.values_mut() {
                let line_bytes = line.len() + 1;
                if pending.output_bytes + line_bytes <= self.max_command_output_bytes
                    && pending.output_bytes + line_bytes <= MAX_COMMAND_OUTPUT_BYTES
                    && pending.lines.len() < MAX_COMMAND_OUTPUT_RECORDS
                {
                    pending.lines.push(line.clone());
                    pending.output_bytes += line_bytes;
                    pending.output_invalid_utf8 |= *invalid_utf8;
                } else {
                    pending.output_truncated = true;
                }
            }

            if line.starts_with("*stopped") {
                let tokens: Vec<u64> = state
                    .pending
                    .iter()
                    .filter(|(_, p)| p.awaiting_inferior_stop)
                    .map(|(token, _)| *token)
                    .collect();
                for token in tokens {
                    if let Some(pending) = state.pending.remove(&token) {
                        let mi = pending.terminal_record.clone().unwrap_or_default();
                        let result = complete_result(&pending, mi);
                        state.delivered.insert(token, CommandOutcome::Done(result));
                    }
                }
                continue;
            }

            let Some((token, verb)) = parse_result_record(line) else {
                continue;
            };
            if !state.pending.contains_key(&token) {
                continue;
            }
            if verb == "running" {
                let pending = state.pending.get_mut(&token).expect("checked above");
                pending.terminal_record = Some(line.clone());
                pending.awaiting_inferior_stop = true;
                continue;
            }
            let pending = state.pending.remove(&token).expect("checked above");
            let result = complete_result(&pending, line.clone());
            state.delivered.insert(token, CommandOutcome::Done(result));
        }
    }

    /// Mark exited and settle every pending command (`#settleExitedCommands`).
    fn on_eof(&self) {
        let (code, signal) = match self.process() {
            Some(process) => {
                let diag = process.diagnostics();
                (diag.exit_code, diag.signal)
            }
            None => (None, None),
        };
        let mut state = self.lock();
        state.exited = true;
        state.exit_code = code;
        state.exit_signal = signal.clone();
        let tokens: Vec<u64> = state.pending.keys().copied().collect();
        for token in tokens {
            let pending = state.pending.remove(&token).expect("enumerated above");
            let mut partial = partial_result(&pending, CompletionStatus::Unknown);
            partial.process_exit_observed = true;
            partial.process_exit_code = code;
            partial.process_exit_signal = signal.clone();
            state
                .delivered
                .insert(token, CommandOutcome::ProcessExit(partial));
        }
        drop(state);
        self.signal.notify_all();
    }

    fn fail_protocol(&self, message: &str) {
        {
            let mut state = self.lock();
            fail_protocol_locked(&mut state, message);
        }
        self.signal.notify_all();
    }

    /// Submit one MI command and block for its correlated terminal record,
    /// honoring the command deadline (`#request`).
    fn request_internal(
        &self,
        command: &str,
        evidence_command: Option<&str>,
    ) -> Result<GdbCommandResult, AnalysisError> {
        let evidence_command = evidence_command.unwrap_or(command).to_owned();
        {
            let state = self.lock();
            if state.exited {
                return Err(AnalysisError::capability_unavailable(
                    "gdb",
                    "gdb_console",
                    format!(
                        "GDB MI process has exited (exit code {}, signal {}).",
                        state
                            .exit_code
                            .map_or_else(|| "null".to_owned(), |c| c.to_string()),
                        state
                            .exit_signal
                            .clone()
                            .unwrap_or_else(|| "null".to_owned()),
                    ),
                ));
            }
        }
        let writable = self
            .process()
            .is_some_and(|process| process.stdin_writable());
        if !writable {
            let message = "GDB MI input stream is closed".to_owned();
            self.fail_protocol(&message);
            return Err(AnalysisError::capability_unavailable(
                "gdb",
                "gdb_console",
                message,
            ));
        }

        let token = {
            let mut state = self.lock();
            let token = state.next_token;
            state.next_token += 1;
            state.pending.insert(
                token,
                Pending {
                    command: command.to_owned(),
                    evidence_command,
                    lines: Vec::new(),
                    output_bytes: 0,
                    output_truncated: false,
                    output_invalid_utf8: false,
                    terminal_record: None,
                    awaiting_inferior_stop: false,
                },
            );
            token
        };

        let line = format!("{token}{command}\n");
        if let Some(process) = self.process()
            && let Err(cause) = process.write_stdin(line.as_bytes())
        {
            self.fail_protocol(&format!("GDB stdin write failed: {cause}"));
        }

        self.wait_for_command(token, command)
    }

    fn wait_for_command(
        &self,
        token: u64,
        command: &str,
    ) -> Result<GdbCommandResult, AnalysisError> {
        let deadline = Instant::now() + Duration::from_millis(self.command_timeout_ms);
        let mut state = self.lock();
        loop {
            if let Some(outcome) = state.delivered.remove(&token) {
                return resolve_outcome(outcome, command);
            }
            if !state.pending.contains_key(&token) {
                return Err(AnalysisError::capability_unavailable(
                    "gdb",
                    "gdb_console",
                    "GDB MI command correlation was lost.",
                ));
            }
            let now = Instant::now();
            if now >= deadline {
                state.pending.remove(&token);
                state.protocol_error = Some(
                    "A GDB MI command timed out; untagged stream output can no longer be safely correlated with later commands.".to_owned(),
                );
                return Err(AnalysisError::timeout(
                    "gdb_console",
                    self.command_timeout_ms,
                ));
            }
            let timeout = (deadline - now).min(Duration::from_millis(20));
            let (next, _) = self
                .signal
                .wait_timeout(state, timeout)
                .unwrap_or_else(|p| p.into_inner());
            state = next;
        }
    }
}

/// `#failProtocol`: reject every pending command once with a partial.
fn fail_protocol_locked(state: &mut SessionState, message: &str) {
    if state.exited || state.protocol_error.is_some() {
        return;
    }
    state.protocol_error = Some(message.to_owned());
    let tokens: Vec<u64> = state.pending.keys().copied().collect();
    for token in tokens {
        let pending = state.pending.remove(&token).expect("enumerated above");
        state.delivered.insert(
            token,
            CommandOutcome::Protocol {
                message: message.to_owned(),
                partial: partial_result(&pending, CompletionStatus::Unknown),
            },
        );
    }
}

fn complete_result(pending: &Pending, mi: String) -> GdbCommandResult {
    let records = pending.lines.clone();
    GdbCommandResult {
        command: String::new(),
        mi,
        console: stream_filter(&records, '~'),
        target: stream_filter(&records, '@'),
        log: stream_filter(&records, '&'),
        records,
        process_exit_observed: false,
        process_exit_code: None,
        process_exit_signal: None,
        output_truncated: pending.output_truncated,
        completion_status: CompletionStatus::Complete,
        output_invalid_utf8: pending.output_invalid_utf8,
    }
}

fn partial_result(pending: &Pending, status: CompletionStatus) -> GdbCommandResult {
    let records = pending.lines.clone();
    GdbCommandResult {
        command: pending.command.clone(),
        mi: String::new(),
        console: stream_filter(&records, '~'),
        target: stream_filter(&records, '@'),
        log: stream_filter(&records, '&'),
        records,
        process_exit_observed: false,
        process_exit_code: None,
        process_exit_signal: None,
        output_truncated: pending.output_truncated,
        completion_status: status,
        output_invalid_utf8: pending.output_invalid_utf8,
    }
}

fn resolve_outcome(
    outcome: CommandOutcome,
    command: &str,
) -> Result<GdbCommandResult, AnalysisError> {
    match outcome {
        CommandOutcome::Done(mut result) => {
            result.command = command.to_owned();
            Ok(result)
        }
        CommandOutcome::ProcessExit(mut partial) => {
            partial.command = command.to_owned();
            Err(AnalysisError::capability_unavailable(
                "gdb",
                "gdb_console",
                format!(
                    "GDB exited before returning the active MI command result (exit code {}, signal {}).",
                    partial
                        .process_exit_code
                        .map_or_else(|| "null".to_owned(), |c| c.to_string()),
                    partial
                        .process_exit_signal
                        .clone()
                        .unwrap_or_else(|| "null".to_owned()),
                ),
            ))
        }
        CommandOutcome::Protocol { message, .. } => Err(AnalysisError::capability_unavailable(
            "gdb",
            "gdb_console",
            message,
        )),
    }
}

/// `/^(\d+)\^(done|running|connected|error|exit)(?:,|$)/`.
fn parse_result_record(line: &str) -> Option<(u64, &'static str)> {
    let caret = line.find('^')?;
    if caret == 0 || !line[..caret].bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let token: u64 = line[..caret].parse().ok()?;
    let rest = &line[caret + 1..];
    for verb in ["done", "running", "connected", "error", "exit"] {
        if let Some(after) = rest.strip_prefix(verb)
            && (after.is_empty() || after.starts_with(','))
        {
            return Some((token, verb));
        }
    }
    None
}

fn is_done_record(mi: &str) -> bool {
    match parse_result_record(mi) {
        Some((_, "done")) => true,
        _ => false,
    }
}

/// Supervisor adapter bridging [`DebuggerProcess`] to [`DebuggerSupervisor`].
struct SupervisorAdapter {
    process: Arc<DebuggerProcess>,
}

impl DebuggerSupervisor for SupervisorAdapter {
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
        self.process.wait_for_exit(timeout)
    }
}

/// One owned GDB/MI session (`GdbSession`).
pub(crate) struct GdbSession {
    inner: Arc<Inner>,
    process: Arc<DebuggerProcess>,
    supervisor: SupervisorAdapter,
    detach_outcome: Mutex<Option<DetachOutcome>>,
    detach_in_flight: AtomicBool,
    cleanup_failures: Mutex<Vec<AnalysisError>>,
}

impl OwnedDebuggerProcess for GdbSession {
    fn id(&self) -> &str {
        &self.inner.id
    }
    fn exited(&self) -> bool {
        self.inner.lock().exited || self.process.exit().is_some()
    }
    fn supervisor(&self) -> &dyn DebuggerSupervisor {
        &self.supervisor
    }
    fn detach_outcome(&self) -> Option<DetachOutcome> {
        *self
            .detach_outcome
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }
    fn set_detach_outcome(&self, outcome: DetachOutcome) {
        *self
            .detach_outcome
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(outcome);
    }
    fn detach_pending(&self) -> bool {
        self.detach_in_flight.load(Ordering::SeqCst)
    }
    fn inferior_state_unknown(&self) -> Option<bool> {
        Some(!self.inner.lock().no_inferior_verified)
    }
    fn verify_inferiors_ended_after_exit(&self) -> Option<Result<bool, String>> {
        let identities: Vec<OwnedInferiorIdentity> = self
            .inner
            .lock()
            .known_inferior_identities
            .values()
            .cloned()
            .collect();
        let ended = verify_owned_inferiors_ended(identities.iter());
        if matches!(ended, Ok(true)) {
            self.inner.lock().known_inferior_identities.clear();
        }
        Some(ended)
    }
    fn has_detach_capability(&self) -> bool {
        true
    }
    fn run_detach(&self) -> Result<Option<OwnedDebuggerDetachResult>, String> {
        if self.detach_in_flight.swap(true, Ordering::SeqCst) {
            return Ok(None);
        }
        let result = self.detach_inferior();
        self.detach_in_flight.store(false, Ordering::SeqCst);
        result.map(Some)
    }
}

impl GdbSession {
    fn new(inner: Arc<Inner>, process: Arc<DebuggerProcess>) -> Self {
        Self {
            inner,
            process: Arc::clone(&process),
            supervisor: SupervisorAdapter { process },
            detach_outcome: Mutex::new(None),
            detach_in_flight: AtomicBool::new(false),
            cleanup_failures: Mutex::new(Vec::new()),
        }
    }

    fn id(&self) -> &str {
        &self.inner.id
    }

    fn retain_cleanup_failure(&self, operation: &str, reason: &str) -> AnalysisError {
        let failure = AnalysisError::capability_unavailable(
            "gdb",
            operation,
            format!("The owned GDB process could not be confirmed stopped: {reason}"),
        )
        .with_cleanup(reason.to_owned(), vec![self.inner.id.clone()]);
        self.cleanup_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(failure.clone());
        failure
    }

    fn stop_debugger_only(&self) -> OwnedDebuggerStopResult {
        let stopped = stop_owned_debugger_process(self, "GDB");
        if !stopped.is_incomplete() {
            self.cleanup_failures
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clear();
        }
        stopped
    }

    fn has_cleanup_failures(&self) -> bool {
        !self
            .cleanup_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .is_empty()
    }

    fn last_cleanup_failure(&self) -> Option<AnalysisError> {
        self.cleanup_failures
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .last()
            .cloned()
    }

    /// `#serialize` capacity bound plus the per-session FIFO turn.
    fn acquire_turn<'a>(
        &'a self,
        operation: &str,
        check_cancel: Option<&ToolContext<'_>>,
    ) -> Result<TurnGuard<'a>, AnalysisError> {
        let count = self
            .inner
            .pending_command_count
            .fetch_add(1, Ordering::SeqCst);
        if count as usize >= MAX_PENDING_GDB_COMMANDS {
            self.inner
                .pending_command_count
                .fetch_sub(1, Ordering::SeqCst);
            return Err(AnalysisError::resource_constraint(
                operation,
                "transport",
                "GDB command queue capacity reached.",
                Some(json!({
                    "max_pending_commands": MAX_PENDING_GDB_COMMANDS,
                    "active_or_queued_commands": count,
                })),
            ));
        }
        if let Some(context) = check_cancel
            && context.cancellation.reason().is_some()
        {
            self.inner
                .pending_command_count
                .fetch_sub(1, Ordering::SeqCst);
            return Err(AnalysisError::cancelled(operation));
        }
        let guard = self
            .inner
            .command_lock
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        Ok(TurnGuard {
            inner: &self.inner,
            _guard: guard,
        })
    }

    /// `execute`: serialize, submit the console command, build Evidence.
    fn execute(
        &self,
        context: &ToolContext<'_>,
        session_id: &str,
        command: &str,
    ) -> Result<Evidence, AnalysisError> {
        let _turn = self.acquire_turn("gdb_console", Some(context))?;

        {
            let mut state = self.inner.lock();
            if state.exited || state.protocol_error.is_some() {
                return Err(AnalysisError::input("gdb_console", Vec::new()));
            }
            state.no_inferior_verified = false;
            state.known_inferior_identities.clear();
            if command_may_change_inferior_output(command) {
                state.inferior_tty_verified = false;
            }
        }

        let mut result = self.inner.request_internal(
            &format!("-interpreter-exec console {}", mi_quote(command)),
            Some(command),
        )?;
        result.command = command.to_owned();
        self.console_evidence(session_id, command, &result)
    }

    fn console_evidence(
        &self,
        session_id: &str,
        command: &str,
        result: &GdbCommandResult,
    ) -> Result<Evidence, AnalysisError> {
        let value = result_value(result);
        let mut limitations = vec![
            "MI records are returned as decoded text; their semantics depend on GDB version and target.".to_owned(),
        ];
        if result.output_invalid_utf8 {
            limitations.push(
                "MI stream bytes were not valid UTF-8; returned text contains replacement characters.".to_owned(),
            );
        }
        limitations.push(
            "The unrestricted GDB console can access local shell, filesystem, network, and target controls.".to_owned(),
        );
        let observation = Observation::new(
            "gdb_console",
            json!({ "session_id": session_id, "command": command }),
            value.clone(),
        )
        .predicate("rea.debugger.console-observation")
        .raw(value)
        .subject_unavailable(
            "The active GDB inferior identity is not established by the debugger session identifier.",
        )
        .limitations(limitations);
        Evidence::create(None, &gdb_provider(), observation)
            .map_err(|error| AnalysisError::output("gdb_console", error.to_string()))
    }

    /// `#detachInferior`: confirm the inferior disposition and any durable sink
    /// before process cleanup.
    fn detach_inferior(&self) -> Result<OwnedDebuggerDetachResult, String> {
        {
            let state = self.inner.lock();
            if state.no_inferior_verified {
                return Ok(OwnedDebuggerDetachResult::NoInferior);
            }
            if state.exited || self.process.exit().is_some() {
                return Err("GDB exited before inferior state could be verified.".to_owned());
            }
            if state.protocol_error.is_some()
                || !state.pending.is_empty()
                || self.inner.pending_command_count.load(Ordering::SeqCst) > 1
            {
                return Err(
                    "GDB MI state is not synchronized; inferior state is unknown.".to_owned(),
                );
            }
        }
        self.inner.lock().known_inferior_identities.clear();

        let groups = self
            .inner
            .request_internal("-list-thread-groups --recurse 1", None)
            .map_err(|error| error.message())?;
        if groups.completion_status != CompletionStatus::Complete
            || groups.output_truncated
            || !is_done_record(&groups.mi)
        {
            return Err("GDB could not confirm its inferior state.".to_owned());
        }
        let inferior_pids = gdb_thread_group_pids(&groups.mi);
        if inferior_pids.as_deref().map(<[String]>::len) == Some(0) {
            let mut state = self.inner.lock();
            state.known_inferior_identities.clear();
            state.no_inferior_verified = true;
            return Ok(OwnedDebuggerDetachResult::NoInferior);
        }
        self.inner.lock().no_inferior_verified = false;
        let pids = match &inferior_pids {
            Some(pids) if pids.len() == 1 => pids.clone(),
            Some(_) => {
                return Err(
                    "GDB reports multiple inferiors; automatic detach cannot be confirmed safely."
                        .to_owned(),
                );
            }
            None => return Err("GDB returned an unknown recursive inferior list.".to_owned()),
        };

        let (tty_verified, inferior_tty) = {
            let state = self.inner.lock();
            (state.inferior_tty_verified, self.inner.inferior_tty.clone())
        };
        if !tty_verified {
            return Err(
                "GDB cannot detach the live inferior because no durable output sink was verified at session startup."
                    .to_owned(),
            );
        }
        let inferior_tty = inferior_tty.unwrap_or_default();

        let observed_tty = self
            .inner
            .request_internal("-inferior-tty-show", None)
            .map_err(|error| error.message())?;
        if observed_tty.completion_status != CompletionStatus::Complete
            || observed_tty.output_truncated
            || !is_done_record(&observed_tty.mi)
            || mi_string_field(&observed_tty.mi, "inferior_tty_terminal").as_deref()
                != Some(inferior_tty.as_str())
        {
            return Err(
                "GDB no longer reports the caller-selected inferior TTY; detachment cannot be confirmed safely."
                    .to_owned(),
            );
        }

        verify_gdb_inferior_output_sink(&pids[0], &inferior_tty, |identity| {
            self.inner.lock().known_inferior_identities.insert(
                format!("{}:{}", identity.pid, identity.start_time),
                identity,
            );
        })?;

        let detached = self
            .inner
            .request_internal("-target-detach", None)
            .map_err(|error| error.message())?;
        if detached.completion_status != CompletionStatus::Complete
            || detached.output_truncated
            || !is_done_record(&detached.mi)
        {
            return Err("GDB did not confirm inferior detachment.".to_owned());
        }
        self.inner.lock().known_inferior_identities.clear();
        Ok(OwnedDebuggerDetachResult::DetachedDurable)
    }

    fn status_value(&self) -> Value {
        let diagnostics = self.process.diagnostics();
        let state = self.inner.lock();
        let status = if state.exited || state.protocol_error.is_some() || !state.ready {
            "closed"
        } else {
            "ready"
        };
        json!({
            "session_id": self.inner.id,
            "mi_version": self.inner.mi_version,
            "state": status,
            "recent_mi_records": state.lines.clone(),
            "recent_mi_records_truncated": state.recent_records_truncated,
            "mi_invalid_utf8": state.invalid_utf8_observed,
            "stderr": diagnostics.stderr_text,
            "stderr_observed_bytes": diagnostics.stderr_observed_bytes,
            "stderr_truncated": diagnostics.stderr_observed_bytes > diagnostics.stderr_bytes as u64,
            "stderr_invalid_utf8": diagnostics.stderr_invalid_utf8,
            "diagnostics_truncated": diagnostics.diagnostic_truncated,
            "inferior_tty": self.inner.inferior_tty.clone().map_or(Value::Null, Value::String),
            "inferior_tty_verified": state.inferior_tty_verified,
        })
    }

    /// `close`: confirm the inferior disposition, exit GDB, stop the process.
    fn close(&self, context: &ToolContext<'_>) -> Result<Value, AnalysisError> {
        if self.inner.lock().exited || self.process.exit().is_some() {
            let stopped = self.stop_debugger_only();
            if let OwnedDebuggerStopResult::Incomplete { reason } = stopped {
                return Err(self.retain_cleanup_failure("close_gdb_session", &reason));
            }
            return Ok(json!({ "target_state": "unknown" }));
        }

        let _turn = self.acquire_turn("close_gdb_session", None)?;
        let _ = context;

        if self.inner.lock().exited {
            let stopped = self.stop_debugger_only();
            if let OwnedDebuggerStopResult::Incomplete { reason } = stopped {
                return Err(self.retain_cleanup_failure("close_gdb_session", &reason));
            }
            return Ok(json!({ "target_state": "unknown" }));
        }

        let mut target_state = "unknown";
        if let Ok(groups) = self
            .inner
            .request_internal("-list-thread-groups --recurse 1", None)
            && groups.completion_status == CompletionStatus::Complete
            && !groups.output_truncated
            && is_done_record(&groups.mi)
        {
            match gdb_thread_group_count(&groups.mi) {
                None => {}
                Some(0) => {
                    self.inner.lock().no_inferior_verified = true;
                    target_state = "none_observed";
                    let _ = self.inner.request_internal("-gdb-exit", None);
                }
                Some(_) => {
                    if !self.inner.lock().inferior_tty_verified {
                        return Err(AnalysisError::from(ErrorKind::CapabilityUnavailable {
                            provider_id: "gnu.gdb".to_owned(),
                            operation: "close_gdb_session".to_owned(),
                            reason: "Live GDB inferiors require an explicit disposition because no durable inferior TTY is verified.".to_owned(),
                            user_message: Some(
                                "Close requires an explicit inferior disposition.".to_owned(),
                            ),
                            remediation_action: Some(
                                "Use gdb_console with this session_id to explicitly detach or terminate each remaining inferior, then retry close_gdb_session.".to_owned(),
                            ),
                            retryable: true,
                        }));
                    }
                    self.inner.lock().no_inferior_verified = false;
                    if let Ok(disposition) = self.detach_inferior() {
                        target_state = match disposition {
                            OwnedDebuggerDetachResult::NoInferior => "none_observed",
                            OwnedDebuggerDetachResult::DetachedDurable => "unknown",
                        };
                    }
                }
            }
        }

        let stopped = self.stop_debugger_only();
        if let OwnedDebuggerStopResult::Incomplete { reason } = stopped {
            return Err(self.retain_cleanup_failure("close_gdb_session", &reason));
        }
        Ok(json!({ "target_state": target_state }))
    }
}

struct TurnGuard<'a> {
    inner: &'a Inner,
    _guard: std::sync::MutexGuard<'a, ()>,
}

impl Drop for TurnGuard<'_> {
    fn drop(&mut self) {
        self.inner
            .pending_command_count
            .fetch_sub(1, Ordering::SeqCst);
    }
}

/// `verifyGdbInferiorOutputSink`: confirm the inferior's descriptors 1 and 2
/// still point to the selected character-device TTY. Linux `/proc` only.
#[cfg(target_os = "linux")]
fn verify_gdb_inferior_output_sink(
    pid: &str,
    selected_tty: &str,
    mut remember: impl FnMut(OwnedInferiorIdentity),
) -> Result<(), String> {
    use super::super::debugger::read_linux_process_start_time;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let before = read_linux_process_start_time(pid)?
        .ok_or_else(|| "GDB could not establish the live inferior identity.".to_owned())?;
    let tty_path = std::fs::canonicalize(selected_tty).map_err(|e| e.to_string())?;
    let tty_meta = std::fs::metadata(&tty_path).map_err(|e| e.to_string())?;
    if !tty_meta.file_type().is_char_device() {
        return Err("The selected GDB output sink is not a character device.".to_owned());
    }
    for descriptor in ["1", "2"] {
        let descriptor_path = format!("/proc/{pid}/fd/{descriptor}");
        let destination = std::fs::read_link(&descriptor_path).map_err(|e| e.to_string())?;
        let observed = std::fs::metadata(&descriptor_path).map_err(|e| e.to_string())?;
        let destination_real = std::fs::canonicalize(&destination).map_err(|e| e.to_string())?;
        if observed.dev() != tty_meta.dev()
            || observed.ino() != tty_meta.ino()
            || !observed.file_type().is_char_device()
            || destination_real != tty_path
        {
            return Err(format!(
                "GDB inferior descriptor {descriptor} no longer points to the selected TTY."
            ));
        }
    }
    let after = read_linux_process_start_time(pid)?
        .ok_or_else(|| "GDB could not establish the live inferior identity.".to_owned())?;
    if after != before {
        return Err("The GDB inferior identity changed during descriptor readback.".to_owned());
    }
    remember(OwnedInferiorIdentity {
        pid: pid.to_owned(),
        start_time: before,
    });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_gdb_inferior_output_sink(
    _pid: &str,
    _selected_tty: &str,
    _remember: impl FnMut(OwnedInferiorIdentity),
) -> Result<(), String> {
    Err("GDB cannot confirm live inferior output descriptors outside Linux /proc.".to_owned())
}

/// Per-MCP-session GDB manager (`GdbSessionManager`). Created on first use via
/// `context.session.state::<GdbState>()`.
pub(crate) struct GdbState {
    sessions: Mutex<HashMap<String, Arc<GdbSession>>>,
    reservations: AtomicU64,
    closing: AtomicBool,
}

impl Default for GdbState {
    fn default() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            reservations: AtomicU64::new(0),
            closing: AtomicBool::new(false),
        }
    }
}

impl GdbState {
    fn command_name(environment: &HashMap<String, String>) -> String {
        environment
            .get("REA_GDB_COMMAND")
            .cloned()
            .unwrap_or_else(|| "gdb".to_owned())
    }

    fn is_linux() -> bool {
        cfg!(target_os = "linux")
    }
}

impl SessionResource for GdbState {
    /// `closeAll`: stop every owned session; keep ownership of any that could
    /// not be confirmed stopped so a later retry can run again.
    fn close(&self) -> Result<(), AnalysisError> {
        self.closing.store(true, Ordering::SeqCst);
        let sessions: Vec<Arc<GdbSession>> = {
            let guard = self.sessions.lock().unwrap_or_else(|p| p.into_inner());
            guard.values().cloned().collect()
        };
        let mut failure: Option<AnalysisError> = None;
        for session in sessions {
            let stopped = stop_owned_debugger_process(session.as_ref(), "GDB");
            if let OwnedDebuggerStopResult::Incomplete { reason } = stopped {
                failure = Some(session.retain_cleanup_failure("close_gdb_session", &reason));
            } else {
                self.sessions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .remove(session.id());
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

/// `start_gdb_session` handler.
pub(crate) fn start_gdb_session(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let state = context.session.state::<GdbState>();
    context.session.own_once(state.clone());

    let inferior_tty = input
        .get("inferior_tty")
        .and_then(Value::as_str)
        .map(str::to_owned);

    // 1. Input validation (defensive; the frozen schema also enforces this).
    if let Some(tty) = &inferior_tty
        && (tty.is_empty() || tty.contains('\0'))
    {
        return ToolOutput::Failure(AnalysisError::input(
            "start_gdb_session",
            vec![InputIssue::new(
                &["inferior_tty"],
                "invalid_value",
                "The inferior TTY path must be non-empty and must not contain NUL.",
            )],
        ));
    }

    // 2. Closing or cancelled.
    if state.closing.load(Ordering::SeqCst) || context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled("start_gdb_session"));
    }

    // 3. Platform refusal (non-Linux).
    if !GdbState::is_linux() {
        let reason = if cfg!(target_os = "windows") {
            "Persistent Windows GDB sessions are unavailable because owned Job Object cleanup can terminate debugger inferiors."
        } else {
            "Persistent GDB sessions are available only on Linux because REA verifies live inferior output descriptors through /proc."
        };
        return ToolOutput::Failure(AnalysisError::capability_unavailable(
            "gdb",
            "start_gdb_session",
            reason,
        ));
    }

    match start_session_linux(context, &state, inferior_tty) {
        Ok(value) => ToolOutput::Value(value),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn start_session_linux(
    context: &ToolContext<'_>,
    state: &Arc<GdbState>,
    inferior_tty: Option<String>,
) -> Result<Value, AnalysisError> {
    let occupied = {
        let sessions = state.sessions.lock().unwrap_or_else(|p| p.into_inner());
        sessions.len() as u64 + state.reservations.load(Ordering::SeqCst)
    };
    if occupied as usize >= DEFAULT_MAX_SESSIONS {
        return Err(AnalysisError::resource_constraint(
            "start_gdb_session",
            "memory",
            "GDB session capacity reached.",
            Some(json!({
                "max_sessions": DEFAULT_MAX_SESSIONS,
                "active_or_reserved_sessions": occupied,
            })),
        ));
    }
    state.reservations.fetch_add(1, Ordering::SeqCst);
    let id = uuid::Uuid::new_v4().to_string();
    let result = start_protocol(context, state, &id, "mi3", inferior_tty.clone());
    let final_result = match &result {
        Ok(_) => result,
        Err(_)
            if context.cancellation.reason().is_some()
                || state
                    .sessions
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .contains_key(&id) =>
        {
            result
        }
        Err(_) => start_protocol(context, state, &id, "mi2", inferior_tty),
    };
    state.reservations.fetch_sub(1, Ordering::SeqCst);
    final_result
}

fn start_protocol(
    context: &ToolContext<'_>,
    state: &Arc<GdbState>,
    id: &str,
    mi_version: &'static str,
    inferior_tty: Option<String>,
) -> Result<Value, AnalysisError> {
    let environment = context.session.environment().clone();
    let command = GdbState::command_name(&environment);
    let arguments = vec![
        "--nx".to_owned(),
        "--quiet".to_owned(),
        format!("--interpreter={mi_version}"),
    ];
    let run_id = uuid::Uuid::new_v4().to_string();

    let inner = Arc::new(Inner {
        id: id.to_owned(),
        mi_version,
        inferior_tty: inferior_tty.clone(),
        max_command_output_bytes: MAX_COMMAND_OUTPUT_BYTES,
        command_timeout_ms: COMMAND_TIMEOUT_MS,
        state: Mutex::new(SessionState::new()),
        signal: Condvar::new(),
        command_lock: Mutex::new(()),
        pending_command_count: AtomicU64::new(0),
        process: Mutex::new(None),
    });

    let reader_inner = Arc::clone(&inner);
    let eof_inner = Arc::clone(&inner);
    let process = match DebuggerProcess::spawn(
        &command,
        &arguments,
        &environment,
        &run_id,
        move |chunk| reader_inner.receive(chunk),
        move || eof_inner.on_eof(),
    ) {
        Ok(process) => process,
        Err(cause) => {
            if context.cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled("start_gdb_session"));
            }
            return Err(AnalysisError::capability_unavailable(
                "gdb",
                "start_gdb_session",
                cause,
            ));
        }
    };
    inner.set_process(Arc::clone(&process));
    let session = Arc::new(GdbSession::new(Arc::clone(&inner), process));

    // Wait for the (gdb) startup prompt.
    let startup_deadline = Instant::now() + Duration::from_millis(STARTUP_TIMEOUT_MS);
    {
        let mut guard = inner.lock();
        while !guard.startup_prompt_seen && !guard.exited && guard.protocol_error.is_none() {
            let now = Instant::now();
            if now >= startup_deadline {
                drop(guard);
                let _ = session.stop_debugger_only();
                return Err(AnalysisError::timeout(
                    "start_gdb_session",
                    STARTUP_TIMEOUT_MS,
                ));
            }
            if context.cancellation.reason().is_some() {
                drop(guard);
                let _ = session.stop_debugger_only();
                return Err(AnalysisError::cancelled("start_gdb_session"));
            }
            let (next, _) = inner
                .signal
                .wait_timeout(guard, Duration::from_millis(50))
                .unwrap_or_else(|p| p.into_inner());
            guard = next;
        }
        if guard.exited || guard.protocol_error.is_some() {
            let message = guard
                .protocol_error
                .clone()
                .unwrap_or_else(|| "GDB exited during startup.".to_owned());
            drop(guard);
            let _ = session.stop_debugger_only();
            return Err(AnalysisError::capability_unavailable(
                "gdb",
                "start_gdb_session",
                message,
            ));
        }
        guard.ready = true;
    }

    let auto_load = session
        .inner
        .request_internal("-gdb-set auto-load off", None)
        .map_err(startup_capability)?;
    if !is_done_record(&auto_load.mi) {
        let _ = session.stop_debugger_only();
        return Err(AnalysisError::capability_unavailable(
            "gdb",
            "start_gdb_session",
            format!(
                "GDB rejected the required automatic-loading disable command ({}); the session was not started.",
                auto_load.mi
            ),
        ));
    }

    if let Some(tty) = &inferior_tty {
        let configured = session
            .inner
            .request_internal(&format!("-inferior-tty-set {}", mi_quote(tty)), None)
            .map_err(startup_capability)?;
        if configured.completion_status != CompletionStatus::Complete
            || configured.output_truncated
            || !is_done_record(&configured.mi)
        {
            let _ = session.stop_debugger_only();
            return Err(AnalysisError::capability_unavailable(
                "gdb",
                "start_gdb_session",
                "GDB did not confirm the inferior TTY configuration.",
            ));
        }
        let observed = session
            .inner
            .request_internal("-inferior-tty-show", None)
            .map_err(startup_capability)?;
        let reported = if observed.completion_status == CompletionStatus::Complete
            && !observed.output_truncated
        {
            mi_string_field(&observed.mi, "inferior_tty_terminal")
        } else {
            None
        };
        if !is_done_record(&observed.mi) || reported.as_deref() != Some(tty.as_str()) {
            let _ = session.stop_debugger_only();
            return Err(AnalysisError::capability_unavailable(
                "gdb",
                "start_gdb_session",
                "GDB did not report the exact caller-selected inferior TTY after configuration.",
            ));
        }
        session.inner.lock().inferior_tty_verified = true;
    }

    if session.inner.lock().exited || session.inner.lock().protocol_error.is_some() {
        let _ = session.stop_debugger_only();
        return Err(AnalysisError::capability_unavailable(
            "gdb",
            "start_gdb_session",
            "GDB exited during startup readiness.",
        ));
    }
    session.inner.lock().no_inferior_verified = false;
    state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(id.to_owned(), session);
    Ok(json!({ "session_id": id, "mi_version": mi_version }))
}

fn startup_capability(error: AnalysisError) -> AnalysisError {
    if matches!(
        error.kind,
        ErrorKind::Cancelled { .. } | ErrorKind::Timeout { .. }
    ) {
        return error;
    }
    AnalysisError::capability_unavailable("gdb", "start_gdb_session", error.message())
}

/// `gdb_console` handler.
pub(crate) fn gdb_console(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let state = context.session.state::<GdbState>();
    context.session.own_once(state.clone());

    // `runWithExternalMutationAdmission` with an undefined hook: run cleanup
    // recovery first, then the operation.
    if let Err(error) = retry_cleanup_failures(&state) {
        return ToolOutput::Failure(error);
    }

    let session_id = input
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let command = input.get("command").and_then(Value::as_str).unwrap_or("");

    let session = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(session_id)
        .cloned();
    let unavailable = match &session {
        None => true,
        Some(session) => {
            let s = session.inner.lock();
            !s.ready || s.exited || s.protocol_error.is_some()
        }
    };
    if unavailable {
        return ToolOutput::Failure(AnalysisError::input(
            "gdb_console",
            vec![InputIssue::new(
                &["session_id"],
                "invalid_value",
                "GDB session is unavailable or closed.",
            )],
        ));
    }
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled("gdb_console"));
    }
    let session = session.expect("checked above");

    match session.execute(context, session_id, command) {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `gdb_session_status` handler.
pub(crate) fn gdb_session_status(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let state = context.session.state::<GdbState>();
    context.session.own_once(state.clone());
    let session_id = input
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let session = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(session_id)
        .cloned();
    let Some(session) = session else {
        return ToolOutput::Failure(AnalysisError::input("gdb_session_status", Vec::new()));
    };
    ToolOutput::Value(session.status_value())
}

/// `close_gdb_session` handler.
pub(crate) fn close_gdb_session(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let state = context.session.state::<GdbState>();
    context.session.own_once(state.clone());
    if state.closing.load(Ordering::SeqCst) {
        return ToolOutput::Failure(AnalysisError::cancelled("close_gdb_session"));
    }
    let session_id = input
        .get("session_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    let session = state
        .sessions
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get(session_id)
        .cloned();
    let Some(session) = session else {
        return ToolOutput::Failure(AnalysisError::input("close_gdb_session", Vec::new()));
    };
    match session.close(context) {
        Ok(value) => {
            state
                .sessions
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(session_id);
            ToolOutput::Value(value)
        }
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `retryCleanupFailures`: re-run cleanup for sessions whose stop was
/// incomplete, releasing them once the owned process is confirmed stopped.
fn retry_cleanup_failures(state: &Arc<GdbState>) -> Result<(), AnalysisError> {
    let sessions: Vec<Arc<GdbSession>> = {
        let guard = state.sessions.lock().unwrap_or_else(|p| p.into_inner());
        guard.values().cloned().collect()
    };
    for session in sessions {
        if !session.has_cleanup_failures() {
            continue;
        }
        let stopped = session.stop_debugger_only();
        if let OwnedDebuggerStopResult::Incomplete { reason } = stopped {
            return Err(session
                .last_cleanup_failure()
                .unwrap_or_else(|| session.retain_cleanup_failure("close_gdb_session", &reason)));
        }
        state
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(session.id());
    }
    Ok(())
}
