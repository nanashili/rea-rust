//! One owned worker launch, its serial line-delimited JSON-RPC channel and
//! verified shutdown.
//!
//! Compatibility owners: `src/ghidra-rust/GhidraRustProcess.ts`,
//! `GhidraRustProcessOwner.ts`, `GhidraRustTransport.ts`,
//! `GhidraRustFrames.ts`, `GhidraRustProgress.ts`, `GhidraRustExitDrain.ts`,
//! `GhidraRustProcessCleanup.ts`, `GhidraRustCleanupFailures.ts` and
//! `GhidraRustMemorySupervisor.ts`.
//!
//! Any request failure poisons the channel: the worker is invalidated and
//! its process group stopped, exactly like the original transport. A failed
//! stop keeps the process owned so a later close can retry it.
use crate::configuration::{Configuration, MEMORY_SAMPLE_INTERVAL_MS, MIB, memory_policy};
use crate::identity::PROVIDER_ID;
use crate::protocol::{Frame, MAX_FRAME_BYTES, MAX_REQUEST_BYTES, WORKER_ARGUMENT, parse_frame};
use rea_analysis::ProgressFn;
use rea_core::analysis_error::cleanup::{provider_cleanup_error, with_cleanup_failure};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::ffi::OsString;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, SyncSender, TryRecvError};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

#[cfg(windows)]
use rea_host::process::launcher::OwnedInputWriter;
use rea_host::process::launcher::{ChildExit, ChildLaunchSpec, OwnedChildProcess};

/// Per-request output budget (`MAX_FRAME_BYTES * 4`).
const MAX_REQUEST_OUTPUT_BYTES: usize = MAX_FRAME_BYTES * 4;
/// Bounded stderr retained for diagnostics.
const MAX_DIAGNOSTIC_BYTES: usize = 256 * 1024;
/// Final buffered output allowed after an unexpected exit.
const EXIT_DRAIN: Duration = Duration::from_millis(1_000);
/// How long `close` waits for the acknowledged worker to exit.
const CLOSE_EXIT_WAIT: Duration = Duration::from_millis(1_000);
const POLL: Duration = Duration::from_millis(10);
#[cfg(unix)]
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// The first interruption source of one operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Interruption {
    Timeout,
    Cancelled,
    Closing,
}

/// `GhidraRustExecutionControl`: own the first interruption source
/// independently of later signal changes.
pub(crate) struct Control {
    cancellation: Cancellation,
    shutdown: Arc<AtomicBool>,
    deadline: Instant,
    timeout_ms: u64,
    source: Mutex<Option<Interruption>>,
    pub progress: Option<ProgressFn>,
    pub selector_from_provider: bool,
}

impl Control {
    pub(crate) fn new(
        cancellation: Cancellation,
        shutdown: Arc<AtomicBool>,
        timeout_ms: u64,
        progress: Option<ProgressFn>,
        selector_from_provider: bool,
    ) -> Self {
        let control = Self {
            cancellation,
            shutdown,
            deadline: Instant::now() + Duration::from_millis(timeout_ms),
            timeout_ms,
            source: Mutex::new(None),
            progress,
            selector_from_provider,
        };
        // A pre-aborted caller wins over a closing client.
        let _ = control.interruption();
        control
    }

    /// The retained first interruption, observing the sources once more.
    pub(crate) fn interruption(&self) -> Option<Interruption> {
        let mut source = self
            .source
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if source.is_none() {
            *source = if self.cancellation.reason().is_some() {
                Some(Interruption::Cancelled)
            } else if self.shutdown.load(Ordering::SeqCst) {
                Some(Interruption::Closing)
            } else if Instant::now() >= self.deadline {
                Some(Interruption::Timeout)
            } else {
                None
            };
        }
        *source
    }

    /// The caller-visible interruption failure for `operation`.
    pub(crate) fn error(
        &self,
        operation: &str,
        cause: Option<&AnalysisError>,
    ) -> Option<AnalysisError> {
        let partial = cause.and_then(|cause| cause.partial_observation.clone());
        let kind = |failure_kind: &str| {
            let mut diagnostics = Map::new();
            diagnostics.insert("failure_kind".into(), json!(failure_kind));
            diagnostics
        };
        let mut error = match self.interruption()? {
            Interruption::Timeout => {
                AnalysisError::timeout(operation, self.timeout_ms).with_diagnostics(kind("timeout"))
            }
            Interruption::Cancelled => {
                AnalysisError::cancelled(operation).with_diagnostics(kind("cancelled"))
            }
            Interruption::Closing => AnalysisError::capability_unavailable(
                PROVIDER_ID,
                operation,
                "The provider client is closing and cannot finish this operation.",
            )
            .with_diagnostics(kind("provider_closing")),
        };
        if let Some(partial) = partial {
            error = error.retain_partial_observation(partial);
        }
        Some(error)
    }

    /// Report one coalesced worker progress observation (best effort).
    fn report(&self, method: &str, label: &str, completed: u64, total: Option<u64>) {
        if let Some(progress) = &self.progress {
            let counts = match total {
                None => completed.to_string(),
                Some(total) => format!("{completed}/{total}"),
            };
            progress(
                &format!("ghidra-rust:{method}"),
                &format!("{label} ({counts})"),
            );
        }
    }
}

/// `GhidraRustProcess#error`: a process-level adapter failure.
pub(crate) fn process_error(message: impl Into<String>) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("failure_kind".into(), json!("process"));
    AnalysisError::provider_adapter(PROVIDER_ID, "worker")
        .with_user_message(message)
        .with_diagnostics(diagnostics)
}

/// `GhidraRustTransport#protocolError`.
fn protocol_error(message: impl Into<String>) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("failure_kind".into(), json!("protocol"));
    AnalysisError::provider_adapter(PROVIDER_ID, "worker")
        .with_user_message(message)
        .with_diagnostics(diagnostics)
}

/// `ghidraRustWorkerError`: corrupt durable state needs operator recovery.
pub(crate) fn worker_error(
    operation: &str,
    message: &str,
    code: &str,
    extra: Map<String, Value>,
) -> AnalysisError {
    let mut diagnostics = extra;
    diagnostics.insert(
        "failure_kind".into(),
        json!(if code == "CACHE_INTEGRITY_FAILED" {
            "cache_integrity"
        } else {
            "process"
        }),
    );
    diagnostics.insert("worker_error_code".into(), json!(code));
    if code == "CACHE_INTEGRITY_FAILED" {
        return AnalysisError::from(ErrorKind::Output {
            operation: operation.to_owned(),
            reason: "The saved Rust worker cache failed integrity validation.".to_owned(),
            user_message: Some(message.to_owned()),
            remediation_action: Some(
                "Preserve the existing cache for inspection. Configure REA_GHIDRA_RUST_CACHE_DIR to a new empty directory and reopen the target before retrying.".to_owned(),
            ),
        })
        .with_diagnostics(diagnostics);
    }
    AnalysisError::provider_adapter(PROVIDER_ID, operation)
        .with_user_message(message)
        .with_diagnostics(diagnostics)
}

/// `ghidraRustCacheIntegrityFailed`.
pub(crate) fn cache_integrity_failed(failure: &AnalysisError) -> bool {
    let root = rea_core::analysis_error::cleanup::cleanup_root(failure);
    root.diagnostics
        .as_ref()
        .and_then(|diagnostics| diagnostics.get("worker_error_code"))
        .and_then(Value::as_str)
        == Some("CACHE_INTEGRITY_FAILED")
}

/// One stdout observation from the reader thread.
enum ReaderEvent {
    /// Raw bytes received, counted before framing.
    Bytes(usize),
    /// One complete line decoded as JSON, or its decoding failure.
    Frame(Result<Value, String>),
    /// Stdout reached end of file; `trailing` reports an unterminated line.
    Closed { trailing: bool },
    /// The stream failed or exceeded its frame budget.
    Failed(String),
}

enum IdleObservation {
    Failure(AnalysisError),
    CheckProcess(Option<Arc<Mutex<OwnedChildProcess>>>),
}

/// `GhidraRustFrames`: one bounded line buffer per stream.
#[cfg(unix)]
fn spawn_reader(
    mut stdout: std::process::ChildStdout,
    sender: SyncSender<ReaderEvent>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("rea-ghidra-rust-reader".to_owned())
        .spawn(move || {
            use std::io::Read;
            let mut chunk = vec![0_u8; READ_CHUNK_BYTES];
            let mut line = Vec::new();
            loop {
                let count = match stdout.read(&mut chunk) {
                    Ok(0) => {
                        let _ = sender.send(ReaderEvent::Closed {
                            trailing: !line.is_empty(),
                        });
                        return;
                    }
                    Ok(count) => count,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        let _ = sender.send(ReaderEvent::Failed(error.to_string()));
                        return;
                    }
                };
                if sender.send(ReaderEvent::Bytes(count)).is_err() {
                    return;
                }
                let mut offset = 0;
                while offset < count {
                    let remaining = &chunk[offset..count];
                    let newline = remaining.iter().position(|byte| *byte == b'\n');
                    let end = newline.unwrap_or(remaining.len());
                    if line.len() + end + 1 > MAX_FRAME_BYTES {
                        let _ = sender.send(ReaderEvent::Failed(
                            "Rust worker output exceeds the 8 MiB frame budget.".into(),
                        ));
                        return;
                    }
                    line.extend_from_slice(&remaining[..end]);
                    let Some(newline) = newline else {
                        break;
                    };
                    let frame = std::str::from_utf8(&line)
                        .map_err(|error| {
                            format!("The encoded data was not valid for encoding utf-8: {error}")
                        })
                        .and_then(|text| {
                            serde_json::from_str::<Value>(text).map_err(|error| error.to_string())
                        });
                    line.clear();
                    if sender.send(ReaderEvent::Frame(frame)).is_err() {
                        return;
                    }
                    offset += newline + 1;
                }
            }
        })
        .map(|_| ())
}

/// Serial channel state while no request owns it.
struct Channel {
    events: Receiver<ReaderEvent>,
    next_id: u64,
    sequence: u64,
    closed_reply: bool,
    /// `GhidraRustExitDrain`: the exit observed before a close reply.
    exit_failure: Option<AnalysisError>,
    exit_observed_at: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MonitorState {
    NotStarted,
    Active,
    Exited,
    Stopped,
    LimitReached,
    Unavailable,
}

impl MonitorState {
    fn name(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Active => "active",
            Self::Exited => "exited",
            Self::Stopped => "stopped",
            Self::LimitReached => "limit_reached",
            Self::Unavailable => "unavailable",
        }
    }

    fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Stopped | Self::Exited | Self::LimitReached | Self::Unavailable
        )
    }
}

/// `GhidraRustMemorySupervisor` observations.
struct Memory {
    limit_mib: u64,
    state: MonitorState,
    last_bytes: Option<u64>,
    peak_bytes: Option<u64>,
    observed_at: Option<String>,
    samples: u64,
}

impl Memory {
    fn diagnostics(&self) -> Map<String, Value> {
        let mut diagnostics = memory_policy(Some(self.limit_mib));
        diagnostics.insert("memory_monitor_state".into(), json!(self.state.name()));
        diagnostics.insert("memory_rss_bytes".into(), json!(self.last_bytes));
        diagnostics.insert(
            "memory_peak_sampled_rss_bytes".into(),
            json!(self.peak_bytes),
        );
        diagnostics.insert("memory_last_observed_at".into(), json!(self.observed_at));
        diagnostics.insert("memory_samples".into(), json!(self.samples));
        diagnostics
    }
}

#[derive(Default)]
struct State {
    started: bool,
    closed: bool,
    closure_complete: bool,
    prepared: bool,
    checkpoint_acknowledged: bool,
    close_saved: Option<bool>,
    failure: Option<AnalysisError>,
    process: Option<Arc<Mutex<OwnedChildProcess>>>,
    #[cfg(windows)]
    input: Option<OwnedInputWriter>,
    pid: Option<u32>,
    channel: Option<Channel>,
    channel_busy: bool,
    exit_code: Option<i64>,
    stderr: String,
    stderr_truncated: bool,
    #[cfg(windows)]
    stderr_bytes: Vec<u8>,
    memory: Option<Memory>,
    lineage: Option<Value>,
}

#[cfg(windows)]
fn spawn_windows_reader(
    state: Arc<Mutex<State>>,
    sender: SyncSender<ReaderEvent>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("rea-ghidra-rust-reader".to_owned())
        .spawn(move || {
            let mut line = Vec::new();
            loop {
                let process = state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .process
                    .clone();
                let Some(process) = process else {
                    let _ = sender.send(ReaderEvent::Closed {
                        trailing: !line.is_empty(),
                    });
                    return;
                };
                let output = read_windows_output(&state, &process);
                let output = match output {
                    Ok(output) => output,
                    Err(error) => {
                        let _ = sender.send(ReaderEvent::Failed(error));
                        return;
                    }
                };
                if !emit_windows_stdout(&output.stdout, &mut line, &sender) {
                    return;
                }
                if output.stdout_closed {
                    let _ = sender.send(ReaderEvent::Closed {
                        trailing: !line.is_empty(),
                    });
                    return;
                }
                std::thread::sleep(POLL);
            }
        })
        .map(|_| ())
}

#[cfg(windows)]
fn read_windows_output(
    state: &Arc<Mutex<State>>,
    process_owner: &Arc<Mutex<OwnedChildProcess>>,
) -> Result<rea_host::process::launcher::ChildOutput, String> {
    let mut process = process_owner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let output = process
        .read_output()
        .map_err(|error| format!("Rust worker output read failed: {error}"))?;
    retain_windows_stderr(state, process_owner, &output.stderr);
    Ok(output)
}

#[cfg(windows)]
fn retain_windows_stderr(
    state: &Arc<Mutex<State>>,
    process: &Arc<Mutex<OwnedChildProcess>>,
    bytes: &[u8],
) {
    if bytes.is_empty() {
        return;
    }
    let mut guard = state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(current_process) = guard.process.as_ref() else {
        return;
    };
    if !Arc::ptr_eq(current_process, process) {
        return;
    }
    let available = MAX_DIAGNOSTIC_BYTES.saturating_sub(guard.stderr_bytes.len());
    let retained = bytes.len().min(available);
    guard.stderr_bytes.extend_from_slice(&bytes[..retained]);
    guard.stderr_truncated |= retained < bytes.len();
    let (stderr, _) = bounded_text(&guard.stderr_bytes);
    guard.stderr = stderr;
}

#[cfg(windows)]
fn emit_windows_stdout(
    stdout: &[u8],
    line: &mut Vec<u8>,
    sender: &SyncSender<ReaderEvent>,
) -> bool {
    if stdout.is_empty() {
        return true;
    }
    if sender.send(ReaderEvent::Bytes(stdout.len())).is_err() {
        return false;
    }
    let mut offset = 0;
    while offset < stdout.len() {
        let remaining = &stdout[offset..];
        let newline = remaining.iter().position(|byte| *byte == b'\n');
        let end = newline.unwrap_or(remaining.len());
        if line.len() + end + 1 > MAX_FRAME_BYTES {
            let _ = sender.send(ReaderEvent::Failed(
                "Rust worker output exceeds the 8 MiB frame budget.".into(),
            ));
            return false;
        }
        line.extend_from_slice(&remaining[..end]);
        let Some(newline) = newline else {
            break;
        };
        let frame = std::str::from_utf8(line)
            .map_err(|error| format!("The encoded data was not valid for encoding utf-8: {error}"))
            .and_then(|text| {
                serde_json::from_str::<Value>(text).map_err(|error| error.to_string())
            });
        line.clear();
        if sender.send(ReaderEvent::Frame(frame)).is_err() {
            return false;
        }
        offset += newline + 1;
    }
    true
}

/// One owned worker process and its serial channel.
pub(crate) struct Worker {
    configuration: Configuration,
    environment: Vec<(OsString, OsString)>,
    run_id: String,
    state: Arc<Mutex<State>>,
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn bounded_text(bytes: &[u8]) -> (String, bool) {
    if bytes.len() <= MAX_DIAGNOSTIC_BYTES {
        (String::from_utf8_lossy(bytes).into_owned(), false)
    } else {
        (
            String::from_utf8_lossy(&bytes[..MAX_DIAGNOSTIC_BYTES]).into_owned(),
            true,
        )
    }
}

fn exit_code(exit: &ChildExit) -> Option<i64> {
    if exit.signal.is_some() {
        None
    } else {
        Some(i64::from(exit.code))
    }
}

fn signal_name(exit: &ChildExit) -> Value {
    match exit.signal {
        None => Value::Null,
        Some(9) => json!("SIGKILL"),
        Some(15) => json!("SIGTERM"),
        Some(6) => json!("SIGABRT"),
        Some(11) => json!("SIGSEGV"),
        Some(10) if cfg!(target_os = "macos") => json!("SIGBUS"),
        Some(7) if cfg!(target_os = "linux") => json!("SIGBUS"),
        Some(signal) => json!(format!("SIG{signal}")),
    }
}

impl Worker {
    pub(crate) fn new(
        configuration: Configuration,
        environment: Vec<(OsString, OsString)>,
        run_id: String,
    ) -> Self {
        Self {
            configuration,
            environment,
            run_id,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub(crate) fn started(&self) -> bool {
        self.lock().started
    }

    /// The first retained worker failure, observing idle exits first.
    pub(crate) fn failure(&self) -> Option<AnalysisError> {
        self.observe_idle();
        self.lock().failure.clone()
    }

    pub(crate) fn record_prepared_target(&self) {
        self.lock().prepared = true;
    }

    pub(crate) fn acknowledge_validated_batch_checkpoint(&self) {
        self.lock().checkpoint_acknowledged = true;
    }

    /// Runtime lineage of the owned launch, if one started.
    pub(crate) fn lineage(&self) -> Option<Value> {
        self.lock().lineage.clone()
    }

    /// `GhidraRustProcess.diagnostics()`.
    pub(crate) fn diagnostics(&self) -> Map<String, Value> {
        self.observe_idle();
        #[cfg(unix)]
        {
            let process = self.lock().process.clone();
            if let Some(process) = process {
                let output = process
                    .lock()
                    .ok()
                    .and_then(|process| process.read_output().ok());
                if let Some(output) = output {
                    let mut state = self.lock();
                    let (stderr, truncated) = bounded_text(&output.stderr);
                    state.stderr = stderr;
                    state.stderr_truncated = truncated;
                }
            }
        }
        let state = self.lock();
        let mut diagnostics = memory_policy(self.configuration.memory_mib);
        diagnostics.insert("exit_code".into(), json!(state.exit_code));
        diagnostics.insert("stderr".into(), json!(state.stderr));
        diagnostics.insert("stderr_truncated".into(), json!(state.stderr_truncated));
        if let Some(memory) = &state.memory {
            for (key, value) in memory.diagnostics() {
                diagnostics.insert(key, value);
            }
        }
        diagnostics.insert("started".into(), json!(state.started));
        diagnostics.insert("prepared_target".into(), json!(state.prepared));
        diagnostics.insert(
            "checkpoint_acknowledged".into(),
            json!(state.checkpoint_acknowledged),
        );
        diagnostics.insert(
            "close_acknowledged".into(),
            json!(state.close_saved.is_some()),
        );
        diagnostics.insert("close_saved".into(), json!(state.close_saved));
        diagnostics
    }

    /// The exit code reported by `diagnostics()`.
    pub(crate) fn exit_code(&self) -> Option<i64> {
        self.lock().exit_code
    }

    /// Convert output or an exit observed while idle into the channel failure
    /// (the original transport observed both asynchronously).
    fn observe_idle(&self) {
        let observation = {
            let mut state = self.lock();
            if state.failure.is_some() || state.closed || state.channel_busy {
                return;
            }
            let Some(channel) = state.channel.as_mut() else {
                return;
            };
            match channel.events.try_recv() {
                Ok(ReaderEvent::Closed { .. }) | Err(TryRecvError::Disconnected) => {
                    IdleObservation::Failure(channel.exit_failure.clone().unwrap_or_else(|| {
                        protocol_error("Rust worker output closed before a close reply.")
                    }))
                }
                Ok(ReaderEvent::Failed(reason)) => IdleObservation::Failure(protocol_error(reason)),
                Ok(_) => {
                    IdleObservation::Failure(protocol_error("Unsolicited Rust worker output."))
                }
                Err(TryRecvError::Empty) => IdleObservation::CheckProcess(state.process.clone()),
            }
        };
        let failure = match observation {
            IdleObservation::Failure(failure) => Some(failure),
            IdleObservation::CheckProcess(process) => process.and_then(|process| {
                process
                    .lock()
                    .ok()
                    .and_then(|process| process.try_wait().ok().flatten())
                    .map(|exit| exit_failure(&exit))
            }),
        };
        if let Some(failure) = failure {
            let _ = self.invalidate(failure);
        }
    }

    /// `start`: launch once; a failed start invalidates the worker.
    pub(crate) fn start(&self, control: &Control) -> Result<(), AnalysisError> {
        {
            let mut state = self.lock();
            if state.closed {
                return Err(process_error("The Rust worker has been closed."));
            }
            if state.started {
                let failure = state.failure.clone();
                drop(state);
                return match failure {
                    None => Ok(()),
                    Some(failure) => Err(self.with_cleanup(failure)),
                };
            }
            state.started = true;
        }
        let startup = |interruption: Interruption| match interruption {
            Interruption::Timeout => {
                AnalysisError::timeout("worker:start", self.configuration.timeout_ms)
            }
            Interruption::Cancelled | Interruption::Closing => {
                AnalysisError::cancelled("worker:start")
            }
        };
        if let Some(interruption) = control.interruption() {
            return Err(self.invalidate(startup(interruption)));
        }
        if let Err(error) = self.launch() {
            return Err(self.invalidate(error));
        }
        if let Some(failure) = self.lock().failure.clone() {
            return Err(self.with_cleanup(failure));
        }
        if let Some(interruption) = control.interruption() {
            return Err(self.invalidate(startup(interruption)));
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn launch(&self) -> Result<(), AnalysisError> {
        Err(process_error(
            "The Rust worker is unavailable on this host.",
        ))
    }

    #[cfg(any(unix, windows))]
    fn launch(&self) -> Result<(), AnalysisError> {
        let spec = ChildLaunchSpec {
            executable: self.configuration.command.clone().into(),
            arguments: ChildLaunchSpec::arguments([WORKER_ARGUMENT]),
            working_directory: None,
            protocol_stdin: true,
            limits: rea_host::process::windows::job::WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        };
        #[cfg(unix)]
        let (process, stdout) = OwnedChildProcess::launch_protocol(spec, &self.environment)
            .map_err(|error| process_error(format!("Could not start the Rust worker: {error}")))?;
        #[cfg(windows)]
        let process = OwnedChildProcess::launch_with_environment(
            spec,
            &self.environment,
            MAX_REQUEST_OUTPUT_BYTES,
        )
        .map_err(|error| process_error(format!("Could not start the Rust worker: {error}")))?;
        #[cfg(windows)]
        let input = process.input_writer().ok_or_else(|| {
            process_error("The Rust worker did not provide a protocol input owner.")
        })?;
        let pid = process.id();
        let (sender, events) = std::sync::mpsc::sync_channel(16);
        #[cfg(unix)]
        let lineage = json!({
            "status": "unavailable",
            "observedAt": now_iso(),
            "runId": self.run_id,
            "launcherPid": pid,
            "processGroupId": pid,
            "reason": "The native runtime verifies the owned worker process group at launch but does not enumerate run-token descendants.",
        });
        #[cfg(windows)]
        let lineage = json!({
            "status": "unavailable",
            "observedAt": now_iso(),
            "runId": self.run_id,
            "launcherPid": pid,
            "jobObjectOwned": true,
            "reason": "The native runtime verifies the worker's owned Windows Job Object at launch but does not enumerate run-token descendants.",
        });
        {
            let mut state = self.lock();
            state.pid = Some(pid);
            state.process = Some(Arc::new(Mutex::new(process)));
            #[cfg(windows)]
            {
                state.input = Some(input);
            }
            state.channel = Some(Channel {
                events,
                next_id: 1,
                sequence: 0,
                closed_reply: false,
                exit_failure: None,
                exit_observed_at: None,
            });
            state.lineage = Some(lineage);
        }
        #[cfg(unix)]
        spawn_reader(stdout, sender)
            .map_err(|error| process_error(format!("Could not start the Rust worker: {error}")))?;
        #[cfg(windows)]
        spawn_windows_reader(Arc::clone(&self.state), sender)
            .map_err(|error| process_error(format!("Could not start the Rust worker: {error}")))?;
        #[cfg(any(unix, windows))]
        if let Some(limit_mib) = self.configuration.memory_mib {
            self.start_memory_supervision(limit_mib)?;
        }
        Ok(())
    }

    /// `GhidraRustMemorySupervisor.start`: one ready observation, then
    /// one-second samples until the worker stops.
    #[cfg(any(unix, windows))]
    fn start_memory_supervision(&self, limit_mib: u64) -> Result<(), AnalysisError> {
        self.lock().memory = Some(Memory {
            limit_mib,
            state: MonitorState::NotStarted,
            last_bytes: None,
            peak_bytes: None,
            observed_at: None,
            samples: 0,
        });
        if let Some(failure) = sample_memory(&self.state) {
            return Err(failure);
        }
        if self.lock().memory.as_ref().map(|memory| memory.state) != Some(MonitorState::Active) {
            return Err(process_error(
                "The worker exited before RSS supervision was ready.",
            ));
        }
        let weak = Arc::downgrade(&self.state);
        std::thread::Builder::new()
            .name("rea-ghidra-rust-memory".to_owned())
            .spawn(move || memory_loop(&weak))
            .map(|_| ())
            .map_err(|error| process_error(format!("RSS supervision could not start: {error}")))
    }

    /// `request`: one correlated worker request. Any failure invalidates the
    /// worker before it is returned.
    pub(crate) fn request(
        &self,
        method: &str,
        parameters: Value,
        control: Option<&Control>,
    ) -> Result<Value, AnalysisError> {
        {
            let state = self.lock();
            if let Some(failure) = state.failure.clone() {
                drop(state);
                return Err(self.with_cleanup(failure));
            }
            if state.closed || (state.channel.is_none() && !state.channel_busy) {
                return Err(process_error("No prepared worker channel is available."));
            }
        }
        if method == "batch_decompile" {
            self.lock().checkpoint_acknowledged = false;
        }
        self.transport(method, parameters, control)
    }

    /// `GhidraRustTransport.request`.
    fn transport(
        &self,
        method: &str,
        parameters: Value,
        control: Option<&Control>,
    ) -> Result<Value, AnalysisError> {
        let mut channel = {
            let mut state = self.lock();
            if let Some(failure) = state.failure.clone() {
                drop(state);
                return Err(self.with_cleanup(failure));
            }
            if state.channel_busy {
                drop(state);
                return Err(self.invalidate(protocol_error("The worker channel is busy.")));
            }
            let Some(channel) = state.channel.take() else {
                return Err(process_error("No prepared worker channel is available."));
            };
            state.channel_busy = true;
            channel
        };
        let outcome = self.exchange(&mut channel, method, parameters, control);
        let mut state = self.lock();
        state.channel_busy = false;
        match outcome {
            Ok(value) => {
                if state.failure.is_none() {
                    state.channel = Some(channel);
                }
                Ok(value)
            }
            Err(error) => {
                drop(state);
                // The exit observed before a close reply is the primary failure.
                let primary = channel.exit_failure.take().unwrap_or(error);
                Err(self.invalidate(primary))
            }
        }
    }

    fn exchange(
        &self,
        channel: &mut Channel,
        method: &str,
        parameters: Value,
        control: Option<&Control>,
    ) -> Result<Value, AnalysisError> {
        // Output between requests is unsolicited.
        match channel.events.try_recv() {
            Err(TryRecvError::Empty) => {}
            Ok(ReaderEvent::Closed { .. }) | Err(TryRecvError::Disconnected) => {
                return Err(channel.exit_failure.clone().unwrap_or_else(|| {
                    protocol_error("Rust worker output closed before a close reply.")
                }));
            }
            Ok(ReaderEvent::Failed(reason)) => return Err(protocol_error(reason)),
            Ok(_) => return Err(protocol_error("Unsolicited Rust worker output.")),
        }
        if let Some(failure) = channel.exit_failure.clone() {
            return Err(failure);
        }
        let id = channel.next_id;
        if id > 9_007_199_254_740_991 {
            return Err(protocol_error("Worker request IDs exhausted."));
        }
        channel.next_id += 1;
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": parameters });
        let mut frame =
            serde_json::to_vec(&request).map_err(|error| protocol_error(error.to_string()))?;
        frame.push(b'\n');
        if frame.len() > MAX_REQUEST_BYTES {
            return Err(protocol_error("Worker request exceeds 64 KiB."));
        }
        let timeout_ms = self.configuration.timeout_ms;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let interrupted = |control: Option<&Control>| -> Option<AnalysisError> {
            match control.and_then(|control| control.interruption()) {
                Some(Interruption::Timeout) => Some(AnalysisError::timeout(method, timeout_ms)),
                Some(Interruption::Cancelled | Interruption::Closing) => {
                    Some(AnalysisError::cancelled(method))
                }
                None => {
                    (Instant::now() >= deadline).then(|| AnalysisError::timeout(method, timeout_ms))
                }
            }
        };
        if let Some(error) = interrupted(control) {
            return Err(error);
        }
        let cancelled = || control.is_some_and(|control| control.interruption().is_some());
        if let Err(error) = self.write(&frame, Some(deadline), &cancelled) {
            return Err(interrupted(control).unwrap_or(error));
        }
        let mut bytes = 0_usize;
        loop {
            if let Some(error) = interrupted(control) {
                return Err(error);
            }
            if let Some(failure) = self.lock().failure.clone() {
                return Err(failure);
            }
            let event = match channel.events.recv_timeout(POLL) {
                Ok(event) => event,
                Err(RecvTimeoutError::Timeout) => {
                    if let Some(failure) = self.observe_exit(channel) {
                        return Err(failure);
                    }
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => ReaderEvent::Closed { trailing: false },
            };
            match event {
                ReaderEvent::Bytes(count) => {
                    bytes += count;
                    if bytes > MAX_REQUEST_OUTPUT_BYTES {
                        return Err(protocol_error(
                            "Rust worker output exceeds 32 MiB per request.",
                        ));
                    }
                }
                ReaderEvent::Failed(reason) => return Err(protocol_error(reason)),
                ReaderEvent::Closed { trailing } => {
                    if trailing {
                        return Err(protocol_error(
                            "Rust worker output ended without a newline.",
                        ));
                    }
                    // End of output usually precedes the reapable exit;
                    // attribute it to the exit when one follows promptly.
                    let attribution = Instant::now() + Duration::from_millis(250);
                    while channel.exit_failure.is_none() && Instant::now() < attribution {
                        let _ = self.observe_exit(channel);
                        if channel.exit_failure.is_none() {
                            std::thread::sleep(POLL);
                        }
                    }
                    return Err(channel.exit_failure.clone().unwrap_or_else(|| {
                        protocol_error("Rust worker output closed before a close reply.")
                    }));
                }
                ReaderEvent::Frame(Err(reason)) => return Err(protocol_error(reason)),
                ReaderEvent::Frame(Ok(value)) => {
                    match parse_frame(&value).map_err(protocol_error)? {
                        Frame::Progress {
                            label,
                            completed,
                            total,
                        } => {
                            if total.is_some_and(|total| completed > total) {
                                return Err(protocol_error("Invalid native progress counts."));
                            }
                            channel.sequence += 1;
                            if let Some(control) = control {
                                control.report(method, &label, completed, total);
                            }
                        }
                        Frame::Reply { id: reply, result } => {
                            if reply != id {
                                return Err(protocol_error("Uncorrelated Rust worker response."));
                            }
                            if method == "close" {
                                channel.closed_reply = true;
                                channel.exit_failure = None;
                            }
                            return Ok(result);
                        }
                        Frame::Error {
                            id: reply,
                            message,
                            error_code,
                        } => {
                            if reply != id {
                                return Err(protocol_error("Uncorrelated Rust worker response."));
                            }
                            return Err(worker_error(method, &message, &error_code, Map::new()));
                        }
                    }
                }
            }
        }
    }

    #[cfg(any(unix, windows))]
    fn write(
        &self,
        frame: &[u8],
        _deadline: Option<Instant>,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AnalysisError> {
        #[cfg(windows)]
        let input = self.lock().input.clone();
        #[cfg(windows)]
        let result = input
            .ok_or_else(|| protocol_error("The Rust worker has no input stream."))?
            .write_input_with_timeout_and_cancel(
                frame,
                _deadline
                    .map(|deadline| {
                        deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u32
                    })
                    .unwrap_or(1_000),
                _cancelled,
            );
        #[cfg(unix)]
        let process = self.lock().process.clone();
        #[cfg(unix)]
        let Some(process) = process else {
            return Err(protocol_error("The Rust worker has no input stream."));
        };
        #[cfg(unix)]
        let process = process
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        #[cfg(unix)]
        let result = process.write_input(frame);
        result
            .map(|_| ())
            .map_err(|error| protocol_error(error.to_string()))
    }

    #[cfg(not(any(unix, windows)))]
    fn write(
        &self,
        _frame: &[u8],
        _deadline: Option<Instant>,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<(), AnalysisError> {
        Err(protocol_error("The Rust worker has no input stream."))
    }

    /// `GhidraRustExitDrain.observe`: permit final buffered output for one
    /// second after an exit that preceded the close reply.
    fn observe_exit(&self, channel: &mut Channel) -> Option<AnalysisError> {
        if channel.closed_reply {
            return None;
        }
        if channel.exit_failure.is_none() {
            {
                let process = self.lock().process.clone();
                let exited = process.and_then(|process| {
                    process
                        .lock()
                        .ok()
                        .and_then(|process| process.try_wait().ok().flatten())
                });
                if let Some(exit) = exited {
                    channel.exit_failure = Some(exit_failure(&exit));
                    channel.exit_observed_at = Some(Instant::now());
                }
            }
            return None;
        }
        channel
            .exit_observed_at
            .filter(|observed| observed.elapsed() >= EXIT_DRAIN)
            .and_then(|_| channel.exit_failure.clone())
    }

    /// `invalidate`: retain the first failure, stop the owned process and
    /// return the failure with any incomplete cleanup composed.
    pub(crate) fn invalidate(&self, error: AnalysisError) -> AnalysisError {
        {
            let mut state = self.lock();
            if state.failure.is_none() {
                state.failure = Some(error.clone());
            }
            if !state.channel_busy {
                state.channel = None;
            }
        }
        self.with_cleanup(error)
    }

    /// `#withCleanup`.
    fn with_cleanup(&self, error: AnalysisError) -> AnalysisError {
        match self.release() {
            Ok(()) => error,
            Err(cleanup) => with_cleanup_failure(error, cleanup, "worker"),
        }
    }

    /// `GhidraRustProcessOwner.release`: stop the worker group, retaining
    /// ownership when cleanup is uncertain.
    #[cfg(any(unix, windows))]
    fn release(&self) -> Result<(), AnalysisError> {
        let mut guard = self.lock();
        let state = &mut *guard;
        if let Some(memory) = state.memory.as_mut()
            && matches!(
                memory.state,
                MonitorState::Active | MonitorState::NotStarted
            )
        {
            memory.state = MonitorState::Stopped;
        }
        let (pid, process, channel_busy) = (state.pid, state.process.clone(), state.channel_busy);
        drop(guard);
        let Some(process) = process else {
            let mut state = self.lock();
            if !channel_busy {
                state.channel = None;
            }
            return Ok(());
        };
        let process_owner = process;
        let mut process = process_owner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let stopped = match process.try_wait() {
            Ok(Some(_)) => process.wait().map(|_| ()),
            Ok(None) => process.cancel(1),
            Err(error) => Err(error),
        };
        if let Err(error) = stopped {
            let mut diagnostics = Map::new();
            let reason = format!("Worker stop failed: {error}");
            diagnostics.insert(
                "reasons".into(),
                json!([reason.chars().take(4_096).collect::<String>()]),
            );
            let resources = vec![format!(
                "Rust Ghidra worker {}",
                pid.map_or_else(|| "undefined".to_owned(), |pid| pid.to_string())
            )];
            return Err(provider_cleanup_error(
                PROVIDER_ID,
                resources,
                diagnostics,
                None,
                None,
            ));
        }
        let exit_code_observed = process
            .try_wait()
            .ok()
            .flatten()
            .and_then(|exit| exit_code(&exit));
        #[cfg(unix)]
        let drained_stderr = process.drain_output().ok().map(|output| {
            let (stderr, truncated) = bounded_text(&output.stderr);
            (stderr, truncated)
        });
        #[cfg(windows)]
        let drained_stderr = process.drain_output().ok().map(|output| output.stderr);

        #[cfg(windows)]
        retain_windows_stderr(
            &self.state,
            &process_owner,
            drained_stderr.as_deref().unwrap_or_default(),
        );
        drop(process);

        let mut state = self.lock();
        if let Some(exit_code) = exit_code_observed {
            state.exit_code = Some(exit_code);
        }
        #[cfg(unix)]
        if let Some((stderr, truncated)) = drained_stderr {
            state.stderr = stderr;
            state.stderr_truncated = truncated;
        }
        state.process = None;
        #[cfg(windows)]
        {
            state.input = None;
        }
        if !state.channel_busy {
            state.channel = None;
        }
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    fn release(&self) -> Result<(), AnalysisError> {
        Ok(())
    }

    /// `close`: acknowledge the close handshake, then release ownership.
    /// A failed close stays retryable.
    pub(crate) fn close(&self) -> Result<(), AnalysisError> {
        {
            let mut state = self.lock();
            state.closed = true;
            if state.closure_complete {
                return Ok(());
            }
        }
        let primary = self.acknowledge_close();
        let cleanup = self.release();
        let result = match (primary, cleanup) {
            (None, Ok(())) => Ok(()),
            (None, Err(cleanup)) => Err(cleanup),
            (Some(primary), Ok(())) => Err(primary),
            (Some(primary), Err(cleanup)) => Err(with_cleanup_failure(primary, cleanup, "worker")),
        };
        if result.is_ok() {
            self.lock().closure_complete = true;
        }
        result
    }

    /// `#acknowledgeClose`.
    fn acknowledge_close(&self) -> Option<AnalysisError> {
        {
            let state = self.lock();
            if state.channel.is_none() || state.failure.is_some() {
                return None;
            }
        }
        let reply = match self.transport("close", json!({}), None) {
            Ok(reply) => reply,
            Err(error) => return Some(error),
        };
        let saved = reply
            .as_object()
            .filter(|object| {
                object.len() == 2
                    && object.get("saved").is_some_and(Value::is_boolean)
                    && object.get("closed") == Some(&Value::Bool(true))
            })
            .and_then(|object| object["saved"].as_bool());
        let Some(saved) = saved else {
            return Some(process_error(
                "Malformed Rust worker close acknowledgement.",
            ));
        };
        let prepared = {
            let mut state = self.lock();
            state.close_saved = Some(saved);
            state.prepared
        };
        if saved != prepared {
            return Some(process_error(
                "The Rust worker did not acknowledge the expected saved target state.",
            ));
        }
        self.wait_for_exit(CLOSE_EXIT_WAIT);
        None
    }

    #[cfg(any(unix, windows))]
    fn wait_for_exit(&self, limit: Duration) {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            let process = self.lock().process.clone();
            let exited = process.is_none_or(|process| {
                process
                    .lock()
                    .ok()
                    .and_then(|process| process.try_wait().ok().flatten())
                    .is_some()
            });
            if exited {
                return;
            }
            std::thread::sleep(POLL);
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn wait_for_exit(&self, _limit: Duration) {}
}

/// The failure for a worker exit that preceded its close reply.
#[cfg(any(unix, windows))]
fn exit_failure(exit: &ChildExit) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("failure_kind".into(), json!("process"));
    diagnostics.insert("exit_code".into(), json!(exit_code(exit)));
    diagnostics.insert("signal".into(), signal_name(exit));
    AnalysisError::provider_adapter(PROVIDER_ID, "worker")
        .with_user_message("The Rust worker exited before acknowledging closure.")
        .with_diagnostics(diagnostics)
}

/// One RSS observation while the owned process lock prevents concurrent reap.
#[cfg(any(unix, windows))]
fn sample_memory(state: &Arc<Mutex<State>>) -> Option<AnalysisError> {
    #[cfg(unix)]
    use rea_host::process::linux::memory::{MemoryObservation, ProcessMemoryObserver};
    #[cfg(windows)]
    use rea_host::process::windows::memory::{MemoryObservation, ProcessMemoryObserver};

    let (process, pid) = {
        let guard = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let memory = guard.memory.as_ref()?;
        if memory.state.is_terminal() {
            return None;
        }
        (guard.process.clone(), guard.pid.unwrap_or_default())
    };

    let observation = {
        let Some(process) = process.as_ref() else {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(memory) = guard.memory.as_mut() {
                if memory.state.is_terminal() {
                    return None;
                }
                memory.state = MonitorState::Exited;
            }
            return None;
        };
        let process = process
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if process.try_wait().ok().flatten().is_some() {
            drop(process);
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(memory) = guard.memory.as_mut() {
                if memory.state.is_terminal() {
                    return None;
                }
                memory.state = MonitorState::Exited;
            }
            return None;
        }
        ProcessMemoryObserver.observe(u64::from(pid))
    };

    let failure = match observation {
        MemoryObservation::Readable { resident_bytes, .. } => {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(memory) = guard.memory.as_mut() else {
                return None;
            };
            if memory.state.is_terminal() {
                return None;
            }
            memory.last_bytes = Some(resident_bytes);
            memory.peak_bytes = Some(memory.peak_bytes.unwrap_or(0).max(resident_bytes));
            memory.observed_at = Some(now_iso());
            memory.samples += 1;
            memory.state = MonitorState::Active;
            if resident_bytes < memory.limit_mib.saturating_mul(MIB) {
                return None;
            }
            memory.state = MonitorState::LimitReached;
            let limits = Value::Object(memory.diagnostics());
            let mut error = AnalysisError::from(ErrorKind::ResourceConstraint {
                operation: "worker".to_owned(),
                resource: "memory".to_owned(),
                reason: "The sampled worker RSS reached the configured supervision threshold."
                    .to_owned(),
                reported_limits: Some(limits),
                remediation_action: None,
                retryable: Some(false),
            });
            let mut diagnostics = Map::new();
            diagnostics.insert("failure_kind".into(), json!("memory"));
            error = error.with_diagnostics(diagnostics);
            error
        }
        MemoryObservation::Absent { .. } => {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(memory) = guard.memory.as_mut() {
                if memory.state.is_terminal() {
                    return None;
                }
                memory.state = MonitorState::Exited;
            }
            return None;
        }
        MemoryObservation::Unavailable { reason } => {
            let mut guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let Some(memory) = guard.memory.as_mut() else {
                return None;
            };
            if memory.state.is_terminal() {
                return None;
            }
            memory.state = MonitorState::Unavailable;
            let mut diagnostics = memory.diagnostics();
            diagnostics.insert("failure_kind".into(), json!("memory_monitor"));
            diagnostics.insert("cause".into(), json!(reason));
            AnalysisError::capability_unavailable(
                PROVIDER_ID,
                "worker:memory_supervision",
                "RSS supervision is unavailable; the owned worker must stop before further analysis.",
            )
            .with_diagnostics(diagnostics)
        }
    };

    let process = {
        let mut guard = state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.failure.is_none() {
            guard.failure = Some(failure.clone());
        }
        guard.process.clone()
    };

    // The owner retains termination authority: stop the group now. The
    // regular release path remains responsible for reporting cleanup errors.
    if let Some(process) = process {
        if let Ok(mut process) = process.lock() {
            let _ = process.cancel(1);
        }
    }
    Some(failure)
}

#[cfg(any(unix, windows))]
fn memory_loop(state: &Weak<Mutex<State>>) {
    loop {
        std::thread::sleep(Duration::from_millis(MEMORY_SAMPLE_INTERVAL_MS));
        let Some(state) = state.upgrade() else {
            return;
        };
        let active = {
            let guard = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard
                .memory
                .as_ref()
                .is_some_and(|memory| memory.state == MonitorState::Active)
        };
        if !active || sample_memory(&state).is_some() {
            return;
        }
    }
}
