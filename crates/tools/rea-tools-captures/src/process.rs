//! Owned short-lived provider processes.
//!
//! Compatibility owners: `src/process/ProviderProcess.ts`
//! (`spawnOwnedProviderProcess`, `ProviderProcessSupervisor`) and
//! `src/process/OwnedCommand.ts` (`runOwnedCommand`). Every child runs in its
//! own process group (Windows: an owned Job Object), retains at most the
//! configured aggregate diagnostic bytes, and is stopped with verified group
//! cleanup. Cleanup that cannot be confirmed keeps the exact owner for retry.
//!
//! The shared `rea_host::process::launcher` cannot yet select the child
//! environment or report a terminating signal on POSIX, both of which these
//! producers depend on (private Wireshark profiles, `REA_PROCESS_RUN_ID`,
//! SIGXCPU/SIGXFSZ classification). POSIX launches therefore use this local
//! owner; Windows launches delegate to the shared Job Object launcher.
use crate::node;
use rea_core::cancellation::Cancellation;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Bound retention throughout termination and failed cleanup, including retries.
const MAX_LATE_OUTPUT_BYTES: usize = 64 * 1024;
/// Grace for inherited pipes to close after verified process exit.
const OUTPUT_CLOSE_GRACE: Duration = Duration::from_millis(1_000);
/// Grace for the group leader to exit after SIGKILL.
const KILL_GRACE: Duration = Duration::from_millis(1_000);
/// Grace for every other group member to disappear after SIGKILL.
const GROUP_SETTLE_GRACE: Duration = Duration::from_millis(1_000);

/// Spawn coordinates for one owned provider process.
#[derive(Clone, Debug)]
pub struct ProcessSpec {
    pub command: String,
    pub arguments: Vec<String>,
    pub cwd: Option<String>,
    /// Complete child environment (`{...host, ...env, REA_PROCESS_RUN_ID}`).
    pub environment: Vec<(String, String)>,
    pub run_id: String,
    /// Windows Job Object committed-memory limit; refused on other hosts.
    pub memory_limit_bytes: Option<u64>,
}

impl ProcessSpec {
    /// Build a spec whose environment is the host snapshot plus overrides and
    /// the run token, exactly like `spawnOwnedProviderProcess`.
    pub fn new(
        command: impl Into<String>,
        arguments: Vec<String>,
        cwd: Option<String>,
        host: &HashMap<String, String>,
        overrides: &[(&str, &str)],
        run_id: impl Into<String>,
    ) -> Self {
        let run_id = run_id.into();
        let mut environment = host.clone();
        for (key, value) in overrides {
            environment.insert((*key).to_owned(), (*value).to_owned());
        }
        environment.insert("REA_PROCESS_RUN_ID".to_owned(), run_id.clone());
        let mut environment = environment.into_iter().collect::<Vec<_>>();
        environment.sort();
        Self {
            command: command.into(),
            arguments,
            cwd,
            environment,
            run_id,
            memory_limit_bytes: None,
        }
    }
}

/// A launch failure observed before any owned process existed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpawnFailure {
    /// libuv error name (`ENOENT`, `EACCES`, ...), when known.
    pub code: Option<&'static str>,
    /// Node's error message, for example `spawn /usr/bin/prlimit ENOENT`.
    pub message: String,
}

/// One retained output stream.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StreamSnapshot {
    pub text: String,
    /// Bytes retained in `text`.
    pub bytes: usize,
    /// Every byte drained from the stream.
    pub observed_bytes: u64,
    pub invalid_utf8: bool,
}

/// Detached diagnostics captured for one supervised process.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessSnapshot {
    /// Retained diagnostics omit bytes because of the budget or output loss.
    pub diagnostic_truncated: bool,
    pub stdout: StreamSnapshot,
    pub stderr: StreamSnapshot,
    /// Exit observed (`exitCode`/`signal` are no longer undefined).
    pub exited: bool,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub memory_limit_reached: bool,
    pub output_incomplete: bool,
}

/// Exact disposition of one stop attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopResult {
    Stopped,
    Incomplete { reason: String },
}

#[derive(Default)]
struct Capture {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_observed: u64,
    stderr_observed: u64,
    max: Option<usize>,
    truncated: bool,
    stdout_closed: bool,
    stderr_closed: bool,
    stream_failure: Option<String>,
    output_incomplete: bool,
}

impl Capture {
    fn append(&mut self, stdout: bool, bytes: &[u8]) -> bool {
        if stdout {
            self.stdout_observed += bytes.len() as u64;
        } else {
            self.stderr_observed += bytes.len() as u64;
        }
        let remaining = match self.max {
            None => bytes.len(),
            Some(max) => max.saturating_sub(self.stdout.len() + self.stderr.len()),
        };
        let retained = bytes.len().min(remaining);
        let truncated = retained < bytes.len();
        if truncated {
            self.truncated = true;
        }
        let target = if stdout {
            &mut self.stdout
        } else {
            &mut self.stderr
        };
        target.extend_from_slice(&bytes[..retained]);
        truncated
    }

    fn limit_additional(&mut self, bytes: usize) {
        let requested = self.stdout.len() + self.stderr.len() + bytes;
        self.max = Some(self.max.map_or(requested, |max| max.min(requested)));
    }
}

fn stream_snapshot(bytes: &[u8], observed: u64) -> StreamSnapshot {
    let (text, invalid_utf8) = match std::str::from_utf8(bytes) {
        Ok(text) => (text.to_owned(), false),
        Err(_) => (String::from_utf8_lossy(bytes).into_owned(), true),
    };
    StreamSnapshot {
        text,
        bytes: bytes.len(),
        observed_bytes: observed,
        invalid_utf8,
    }
}

/// Node's signal name for a POSIX signal number (`signo_string`).
#[cfg(unix)]
pub fn signal_name(signal: i32) -> String {
    let name = match signal {
        libc::SIGHUP => "SIGHUP",
        libc::SIGINT => "SIGINT",
        libc::SIGQUIT => "SIGQUIT",
        libc::SIGILL => "SIGILL",
        libc::SIGTRAP => "SIGTRAP",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGFPE => "SIGFPE",
        libc::SIGKILL => "SIGKILL",
        libc::SIGUSR1 => "SIGUSR1",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGUSR2 => "SIGUSR2",
        libc::SIGPIPE => "SIGPIPE",
        libc::SIGALRM => "SIGALRM",
        libc::SIGTERM => "SIGTERM",
        libc::SIGCHLD => "SIGCHLD",
        libc::SIGCONT => "SIGCONT",
        libc::SIGSTOP => "SIGSTOP",
        libc::SIGTSTP => "SIGTSTP",
        libc::SIGTTIN => "SIGTTIN",
        libc::SIGTTOU => "SIGTTOU",
        libc::SIGURG => "SIGURG",
        libc::SIGXCPU => "SIGXCPU",
        libc::SIGXFSZ => "SIGXFSZ",
        libc::SIGVTALRM => "SIGVTALRM",
        libc::SIGPROF => "SIGPROF",
        libc::SIGWINCH => "SIGWINCH",
        libc::SIGSYS => "SIGSYS",
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::SIGPOLL => "SIGPOLL",
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        libc::SIGIO => "SIGIO",
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::SIGPWR => "SIGPWR",
        #[cfg(any(target_os = "linux", target_os = "android"))]
        libc::SIGSTKFLT => "SIGSTKFLT",
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        libc::SIGINFO => "SIGINFO",
        #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
        libc::SIGEMT => "SIGEMT",
        other => return format!("SIG{other}"),
    };
    name.to_owned()
}

/// One supervised owned process.
pub struct OwnedProcess {
    inner: platform::Child,
    capture: Arc<Mutex<Capture>>,
    exit: Option<(Option<i64>, Option<String>)>,
    run_id: String,
    pid: u32,
    released: bool,
    memory_limit_reached: bool,
}

impl std::fmt::Debug for OwnedProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OwnedProcess")
            .field("run_id", &self.run_id)
            .field("pid", &self.pid)
            .field("released", &self.released)
            .finish()
    }
}

impl OwnedProcess {
    /// Spawn one owned process with an aggregate retained-diagnostic budget.
    pub fn spawn(
        spec: &ProcessSpec,
        max_diagnostic_bytes: Option<usize>,
    ) -> Result<Self, SpawnFailure> {
        let capture = Arc::new(Mutex::new(Capture {
            max: max_diagnostic_bytes,
            ..Capture::default()
        }));
        let (inner, pid) = platform::spawn(spec, Arc::clone(&capture))?;
        Ok(Self {
            inner,
            capture,
            exit: None,
            run_id: spec.run_id.clone(),
            pid,
            released: false,
            memory_limit_reached: false,
        })
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Recorded launch identities (`ownedCommandResources`).
    pub fn resources(&self, directory: Option<&str>) -> Vec<String> {
        let mut resources = vec![self.run_id.clone()];
        if let Some(directory) = directory {
            resources.push(directory.to_owned());
        }
        resources.push(format!("pid:{}", self.pid));
        resources.push(format!("process-group:{}", self.pid));
        resources
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Capture> {
        self.capture
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn observe(&mut self) {
        if self.exit.is_none()
            && let Some(exit) = self.inner.observe_exit()
        {
            self.exit = Some(exit);
        }
        if self.inner.memory_limit_reached() {
            self.memory_limit_reached = true;
        }
    }

    /// Whether the exit and every output stream closure were observed.
    pub fn output_closed(&mut self) -> bool {
        self.inner.pump();
        self.observe();
        let capture = self.lock();
        self.exit.is_some() && capture.stdout_closed && capture.stderr_closed
    }

    /// Wait up to `timeout` for output closure.
    pub fn wait_for_output_close(&mut self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.output_closed() {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(5)));
        }
    }

    /// Whether retained diagnostics already omitted bytes.
    pub fn diagnostic_truncated(&self) -> bool {
        self.lock().truncated
    }

    /// First stream failure observed while draining output.
    pub fn stream_failure(&self) -> Option<String> {
        self.lock().stream_failure.clone()
    }

    /// Latest retained output and exit observation.
    pub fn snapshot(&mut self) -> ProcessSnapshot {
        self.inner.pump();
        self.observe();
        let capture = self.lock();
        let (exit_code, signal) = self.exit.clone().unwrap_or((None, None));
        let output_incomplete = capture.output_incomplete;
        ProcessSnapshot {
            diagnostic_truncated: capture.truncated || output_incomplete,
            stdout: stream_snapshot(&capture.stdout, capture.stdout_observed),
            stderr: stream_snapshot(&capture.stderr, capture.stderr_observed),
            exited: self.exit.is_some(),
            exit_code,
            signal,
            memory_limit_reached: self.memory_limit_reached,
            output_incomplete,
        }
    }

    /// Stop the owned process tree; incomplete cleanup keeps this owner for retry.
    pub fn stop(&mut self) -> StopResult {
        if self.released {
            return StopResult::Stopped;
        }
        self.lock().limit_additional(MAX_LATE_OUTPUT_BYTES);
        self.observe();
        match self.inner.cleanup() {
            Ok(exit) => {
                if self.exit.is_none() {
                    self.exit = exit;
                }
                self.released = true;
                // Exit proves process lifetime only; bound the final drain.
                if !self.wait_for_output_close(OUTPUT_CLOSE_GRACE) {
                    let mut capture = self.lock();
                    capture.output_incomplete = true;
                }
                StopResult::Stopped
            }
            Err(reason) => StopResult::Incomplete { reason },
        }
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.released {
            let _ = self.inner.cleanup();
        }
    }
}

fn spawn_reader<R>(mut reader: R, stdout: bool, capture: Arc<Mutex<Capture>>)
where
    R: std::io::Read + Send + 'static,
{
    std::thread::spawn(move || {
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(count) => {
                    let mut state = capture
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.append(stdout, &buffer[..count]);
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    let mut state = capture
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.output_incomplete = true;
                    let stream = if stdout { "stdout" } else { "stderr" };
                    state
                        .stream_failure
                        .get_or_insert_with(|| format!("{stream} stream failed: {error}"));
                    break;
                }
            }
        }
        let mut state = capture
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if stdout {
            state.stdout_closed = true;
        } else {
            state.stderr_closed = true;
        }
    });
}

#[cfg(unix)]
mod platform {
    use super::{
        Capture, GROUP_SETTLE_GRACE, KILL_GRACE, ProcessSpec, SpawnFailure, signal_name,
        spawn_reader,
    };
    use crate::node;
    use rustix::process::{Pid, Signal, WaitId, WaitIdOptions};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    pub(super) struct Child {
        child: std::process::Child,
        pid: Pid,
        exited: Option<(Option<i64>, Option<String>)>,
        reaped: bool,
    }

    pub(super) fn spawn(
        spec: &ProcessSpec,
        capture: Arc<Mutex<Capture>>,
    ) -> Result<(Child, u32), SpawnFailure> {
        if spec.memory_limit_bytes.is_some() {
            return Err(SpawnFailure {
                code: None,
                message: "Owned process memory limits require the Windows Job Object launcher; no limit can be enforced on this host.".into(),
            });
        }
        let mut command = Command::new(&spec.command);
        command
            .args(&spec.arguments)
            .env_clear()
            .envs(spec.environment.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().map_err(|error| {
            let (code, message) = node::spawn_message(&spec.command, &error);
            SpawnFailure { code, message }
        })?;
        let pid_number = child.id();
        let pid = Pid::from_child(&child);
        if let Some(stdout) = child.stdout.take() {
            spawn_reader(stdout, true, Arc::clone(&capture));
        } else {
            capture
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .stdout_closed = true;
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_reader(stderr, false, Arc::clone(&capture));
        } else {
            capture
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .stderr_closed = true;
        }
        Ok((
            Child {
                child,
                pid,
                exited: None,
                reaped: false,
            },
            pid_number,
        ))
    }

    impl Child {
        pub(super) fn pump(&mut self) {}

        pub(super) fn memory_limit_reached(&self) -> bool {
            false
        }

        /// Observe exit without reaping, so the leader keeps its group ID.
        pub(super) fn observe_exit(&mut self) -> Option<(Option<i64>, Option<String>)> {
            if self.exited.is_some() {
                return self.exited.clone();
            }
            let status = rustix::process::waitid(
                WaitId::Pid(self.pid),
                WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
            )
            .ok()
            .flatten()?;
            let observed = if let Some(code) = status.exit_status() {
                (Some(i64::from(code)), None)
            } else if let Some(signal) = status.terminating_signal() {
                (None, Some(signal_name(signal)))
            } else {
                return None;
            };
            self.exited = Some(observed.clone());
            Some(observed)
        }

        fn group_exists(&self) -> Result<bool, String> {
            match rustix::process::test_kill_process_group(self.pid) {
                Ok(()) => Ok(true),
                Err(rustix::io::Errno::SRCH) => Ok(false),
                Err(errno) => Err(format!(
                    "owned process group could not be inspected: {}",
                    std::io::Error::from(errno)
                )),
            }
        }

        /// Kill the owned group while the unreaped leader pins its ID, reap
        /// the leader, then confirm no group member remains.
        pub(super) fn cleanup(&mut self) -> Result<Option<(Option<i64>, Option<String>)>, String> {
            if !self.reaped {
                match rustix::process::kill_process_group(self.pid, Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                    Err(errno) => {
                        return Err(format!(
                            "owned process group signal failed: {}",
                            std::io::Error::from(errno)
                        ));
                    }
                }
                let deadline = Instant::now() + KILL_GRACE;
                while self.observe_exit().is_none() {
                    if Instant::now() >= deadline {
                        return Err(
                            "verified process-group cleanup did not stop the launcher".into()
                        );
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                match self.child.wait() {
                    Ok(_) => self.reaped = true,
                    Err(error) => {
                        return Err(format!(
                            "owned provider process could not be reaped: {error}"
                        ));
                    }
                }
            } else if self.group_exists()? {
                // Surviving members still pin the group ID, so it cannot name
                // another group; repeat the group signal for a retry.
                match rustix::process::kill_process_group(self.pid, Signal::KILL) {
                    Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                    Err(errno) => {
                        return Err(format!(
                            "owned process group signal failed: {}",
                            std::io::Error::from(errno)
                        ));
                    }
                }
            }
            let deadline = Instant::now() + GROUP_SETTLE_GRACE;
            while self.group_exists()? {
                if Instant::now() >= deadline {
                    return Err("owned process group remained active after cleanup deadline".into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(self.exited.clone())
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{Capture, ProcessSpec, SpawnFailure};
    use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
    use rea_host::process::windows::job::WindowsJobLimits;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    pub(super) struct Child {
        child: OwnedChildProcess,
        capture: Arc<Mutex<Capture>>,
        stdout_seen: usize,
        stderr_seen: usize,
        exited: Option<(Option<i64>, Option<String>)>,
        memory_limit_reached: bool,
    }

    pub(super) fn spawn(
        spec: &ProcessSpec,
        capture: Arc<Mutex<Capture>>,
    ) -> Result<(Child, u32), SpawnFailure> {
        // The shared Job Object launcher inherits the REA process environment;
        // per-launch environment overrides are a requested shared change.
        let child = OwnedChildProcess::launch(ChildLaunchSpec {
            executable: PathBuf::from(&spec.command),
            arguments: ChildLaunchSpec::arguments(spec.arguments.iter().cloned()),
            working_directory: spec.cwd.as_ref().map(PathBuf::from),
            protocol_stdin: false,
            limits: WindowsJobLimits {
                memory_bytes: spec.memory_limit_bytes,
                cpu_seconds: None,
            },
        })
        .map_err(|error| SpawnFailure {
            code: if error.message.contains("not found") || error.message.contains("(2)") {
                Some("ENOENT")
            } else {
                None
            },
            message: format!("spawn {} {}", spec.command, error),
        })?;
        Ok((
            Child {
                child,
                capture,
                stdout_seen: 0,
                stderr_seen: 0,
                exited: None,
                memory_limit_reached: false,
            },
            0,
        ))
    }

    impl Child {
        /// Drain newly available pipe bytes into the retained capture.
        pub(super) fn pump(&mut self) {
            let Ok(output) = self.child.read_output() else {
                return;
            };
            let mut capture = self.capture.lock().unwrap_or_else(|p| p.into_inner());
            if output.stdout.len() > self.stdout_seen {
                capture.append(true, &output.stdout[self.stdout_seen..]);
                self.stdout_seen = output.stdout.len();
            }
            if output.stderr.len() > self.stderr_seen {
                capture.append(false, &output.stderr[self.stderr_seen..]);
                self.stderr_seen = output.stderr.len();
            }
            capture.stdout_closed = output.stdout_closed;
            capture.stderr_closed = output.stderr_closed;
            if output.output_incomplete {
                capture.output_incomplete = true;
            }
        }

        pub(super) fn memory_limit_reached(&self) -> bool {
            self.memory_limit_reached
        }

        pub(super) fn observe_exit(&mut self) -> Option<(Option<i64>, Option<String>)> {
            if self.exited.is_some() {
                return self.exited.clone();
            }
            let exit = self.child.try_wait().ok().flatten()?;
            if let Ok(settlement) = self.child.settlement() {
                self.memory_limit_reached |= settlement.memory_limit_reached;
            }
            let observed = (Some(i64::from(exit.code)), None);
            self.exited = Some(observed.clone());
            Some(observed)
        }

        pub(super) fn cleanup(&mut self) -> Result<Option<(Option<i64>, Option<String>)>, String> {
            let result = if self.child.last_cleanup_failure().is_some() {
                self.child.retry_cleanup(1)
            } else {
                self.child.cancel(1)
            };
            result.map_err(|error| error.to_string())?;
            self.pump();
            Ok(self.observe_exit())
        }
    }
}

/// Why an owned command failed (`OwnedCommandFailure.reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    Cancelled,
    Timeout,
    OutputLimit,
    Process,
}

/// A short-lived command failed its lifecycle or complete-output contract.
#[derive(Debug)]
pub struct CommandFailure {
    pub reason: FailureReason,
    pub message: String,
    pub snapshot: Option<ProcessSnapshot>,
    /// Cleanup failure reason when the owned tree could not be confirmed stopped.
    pub cleanup_failure: Option<String>,
    pub resources: Vec<String>,
    /// The owner retained after incomplete cleanup.
    pub cleanup_owner: Option<OwnedProcess>,
    /// Output collection itself failed.
    pub collection_failure: bool,
}

impl CommandFailure {
    fn new(reason: FailureReason, message: &str, snapshot: Option<ProcessSnapshot>) -> Self {
        Self {
            reason,
            message: message.to_owned(),
            snapshot,
            cleanup_failure: None,
            resources: Vec::new(),
            cleanup_owner: None,
            collection_failure: false,
        }
    }
}

/// Failure of one owned command.
#[derive(Debug)]
pub enum CommandError {
    /// The process could not be created; the original raw error.
    Launch(SpawnFailure),
    /// The owned command failed (`OwnedCommandFailure`).
    Failed(Box<CommandFailure>),
}

/// Output handling for one owned command.
#[derive(Clone, Copy, Debug)]
pub struct CommandLimits {
    pub timeout_ms: u64,
    /// Retained stdout plus stderr bytes.
    pub diagnostic_bytes: usize,
    /// Accept an ordinary nonzero exit after output closes.
    pub accept_nonzero_exit: bool,
}

/// One absolute deadline shared with caller cancellation; the first wins.
pub struct Deadline<'a> {
    at: Instant,
    cancellation: &'a Cancellation,
    interruption: Option<FailureReason>,
}

impl<'a> Deadline<'a> {
    pub fn new(timeout_ms: u64, cancellation: &'a Cancellation) -> Self {
        let mut deadline = Self {
            at: Instant::now() + Duration::from_millis(timeout_ms),
            cancellation,
            interruption: None,
        };
        if cancellation.reason().is_some() {
            deadline.interruption = Some(FailureReason::Cancelled);
        }
        deadline
    }

    /// First control path that interrupted the command, if any.
    pub fn interruption(&mut self) -> Option<FailureReason> {
        if self.interruption.is_none() {
            if Instant::now() >= self.at {
                self.interruption = Some(FailureReason::Timeout);
            } else if self.cancellation.reason().is_some() {
                self.interruption = Some(FailureReason::Cancelled);
            }
        }
        self.interruption
    }

    /// Sleep at most `milliseconds`, waking early on interruption.
    pub fn wait(&mut self, milliseconds: u64) {
        let target = (Instant::now() + Duration::from_millis(milliseconds)).min(self.at);
        while Instant::now() < target {
            if self.cancellation.reason().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5).min(target - Instant::now()));
        }
    }
}

fn interruption_message(reason: FailureReason) -> &'static str {
    if reason == FailureReason::Cancelled {
        "Command cancelled."
    } else {
        "Command deadline elapsed."
    }
}

/// Callback accepting unresolved cleanup ownership (`retainCleanup`).
pub type RetainCleanup<'a> = &'a mut dyn FnMut(OwnedProcess, String);

/// Execute one owned process with independent cleanup and bounded diagnostic
/// retention (`runOwnedCommand`).
pub fn run_owned_command(
    spec: &ProcessSpec,
    limits: CommandLimits,
    cancellation: &Cancellation,
    retain_cleanup: Option<RetainCleanup<'_>>,
) -> Result<ProcessSnapshot, CommandError> {
    if cancellation.reason().is_some() {
        return Err(CommandError::Failed(Box::new(CommandFailure::new(
            FailureReason::Cancelled,
            "Command cancelled before launch.",
            None,
        ))));
    }
    let mut deadline = Deadline::new(limits.timeout_ms, cancellation);
    let mut process = match OwnedProcess::spawn(spec, Some(limits.diagnostic_bytes)) {
        Ok(process) => process,
        Err(failure) => {
            if let Some(interruption) = deadline.interruption() {
                return Err(CommandError::Failed(Box::new(CommandFailure::new(
                    interruption,
                    if interruption == FailureReason::Cancelled {
                        "Command cancelled during ownership preparation."
                    } else {
                        "Command deadline elapsed during ownership preparation."
                    },
                    None,
                ))));
            }
            return Err(CommandError::Launch(failure));
        }
    };
    let failure = collect(&mut process, limits, &mut deadline);
    let stopped = process.stop();
    let snapshot = process.snapshot();
    if let StopResult::Incomplete { reason } = stopped {
        match retain_cleanup {
            Some(retain) => retain(process, reason),
            None => {
                let resources = process.resources(spec.cwd.as_deref());
                let (failure_reason, message, collection_failure) = match &failure {
                    Some(failure) => (
                        failure.reason,
                        failure.message.clone(),
                        failure.collection_failure,
                    ),
                    None => (
                        FailureReason::Process,
                        "Command cleanup failed.".to_owned(),
                        false,
                    ),
                };
                return Err(CommandError::Failed(Box::new(CommandFailure {
                    reason: failure_reason,
                    message,
                    snapshot: Some(snapshot),
                    cleanup_failure: Some(reason),
                    resources,
                    cleanup_owner: Some(process),
                    collection_failure,
                })));
            }
        }
    }
    if let Some(failure) = failure {
        return Err(CommandError::Failed(Box::new(CommandFailure {
            snapshot: Some(snapshot),
            ..failure
        })));
    }
    if cancellation.reason().is_some() {
        return Err(CommandError::Failed(Box::new(CommandFailure::new(
            FailureReason::Cancelled,
            "Command cancelled.",
            Some(snapshot),
        ))));
    }
    Ok(snapshot)
}

fn collect(
    process: &mut OwnedProcess,
    limits: CommandLimits,
    deadline: &mut Deadline<'_>,
) -> Option<CommandFailure> {
    while !process.wait_for_output_close(Duration::from_millis(10)) {
        if let Some(interruption) = deadline.interruption() {
            return Some(CommandFailure::new(
                interruption,
                interruption_message(interruption),
                None,
            ));
        }
        if process.diagnostic_truncated() {
            return Some(CommandFailure::new(
                FailureReason::OutputLimit,
                "Command diagnostic output exceeded its complete-output budget.",
                None,
            ));
        }
        if let Some(message) = process.stream_failure() {
            let mut failure = CommandFailure::new(FailureReason::Process, &message, None);
            failure.collection_failure = true;
            return Some(failure);
        }
        deadline.wait(25);
    }
    let snapshot = process.snapshot();
    if let Some(interruption) = deadline.interruption() {
        return Some(CommandFailure::new(
            interruption,
            interruption_message(interruption),
            Some(snapshot),
        ));
    }
    if process.diagnostic_truncated() {
        return Some(CommandFailure::new(
            FailureReason::OutputLimit,
            "Command diagnostic output exceeded its complete-output budget.",
            Some(snapshot),
        ));
    }
    let stream_failure = process.stream_failure();
    let accepted_nonzero = limits.accept_nonzero_exit
        && snapshot.exit_code.is_some_and(|code| code != 0)
        && snapshot.signal.is_none();
    if stream_failure.is_some()
        || ((snapshot.exit_code != Some(0) || snapshot.signal.is_some()) && !accepted_nonzero)
    {
        let collection_failure = stream_failure.is_some();
        let mut failure = CommandFailure::new(
            FailureReason::Process,
            stream_failure
                .as_deref()
                .unwrap_or("Command failed; inspect its exit status and diagnostics."),
            Some(snapshot),
        );
        failure.collection_failure = collection_failure;
        return Some(failure);
    }
    None
}

/// A fresh run token with the selected prefix (`${prefix}${randomUUID()}`).
pub fn run_id(prefix: &str) -> String {
    format!("{prefix}{}", node::random_uuid())
}
