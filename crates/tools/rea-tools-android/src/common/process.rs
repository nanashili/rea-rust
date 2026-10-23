//! Owned external processes over the shared host launcher.
//!
//! Every child runs in an owned POSIX process group or Windows Job Object
//! (`rea_host::process::launcher`). This module adds the bounded collection,
//! deadline and cancellation semantics of the original `execFile` and
//! `runOwnedCommand` owners, and keeps any child whose cleanup could not be
//! proven so its owner can retry instead of forgetting it.
//!
//! Platform note: the launcher's POSIX snapshots are cumulative (bounded at
//! 8 MiB per stream), while Windows reads return only the bytes consumed by
//! that poll. [`Cursor`] presents both as increments.
use rea_core::analysis_error::CapturedOutput;
use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::{
    ChildLaunchSpec, ChildOutput, OwnedChildProcess, ProcessLaunchError,
};
use rea_host::process::windows::job::WindowsJobLimits;
use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// Bytes the POSIX launcher retains per stream before dropping output.
pub const LAUNCHER_STREAM_CAPTURE_BYTES: usize = 8 * 1024 * 1024;

/// One exact argv launch; arguments are never re-split or shell-interpreted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub working_directory: Option<PathBuf>,
}

impl CommandSpec {
    pub fn new<I, S>(program: impl Into<PathBuf>, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            program: program.into(),
            arguments: ChildLaunchSpec::arguments(arguments),
            working_directory: None,
        }
    }

    pub fn in_directory(mut self, directory: impl Into<PathBuf>) -> Self {
        self.working_directory = Some(directory.into());
        self
    }

    fn launch_spec(&self, protocol_stdin: bool) -> ChildLaunchSpec {
        ChildLaunchSpec {
            executable: self.program.clone(),
            arguments: self.arguments.clone(),
            working_directory: self.working_directory.clone(),
            protocol_stdin,
            limits: WindowsJobLimits {
                memory_bytes: None,
                cpu_seconds: None,
            },
        }
    }
}

/// Output observed since the previous poll.
#[derive(Debug, Default)]
pub struct Increment {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_closed: bool,
    pub stderr_closed: bool,
    /// The launcher dropped stdout bytes (POSIX per-stream capture bound).
    pub stdout_truncated: bool,
    /// The launcher dropped stderr bytes (POSIX per-stream capture bound).
    pub stderr_truncated: bool,
}

impl Increment {
    /// Whether the launcher dropped bytes on either stream.
    pub fn capture_truncated(&self) -> bool {
        self.stdout_truncated || self.stderr_truncated
    }
}

/// Uniform incremental reader over both launcher output semantics.
#[derive(Debug, Default)]
pub struct Cursor {
    stdout: usize,
    stderr: usize,
    stdout_closed: bool,
    stderr_closed: bool,
}

impl Cursor {
    /// Convert one launcher snapshot into the bytes not seen before.
    pub fn advance(
        &mut self,
        output: ChildOutput,
        drained: bool,
    ) -> Result<Increment, ProcessLaunchError> {
        #[cfg(not(windows))]
        let (stdout, stderr) = {
            if output.stdout.len() < self.stdout || output.stderr.len() < self.stderr {
                return Err(ProcessLaunchError {
                    operation: "read_output",
                    message: "owned process output regressed".into(),
                    cleanup: None,
                });
            }
            let stdout = output.stdout[self.stdout..].to_vec();
            let stderr = output.stderr[self.stderr..].to_vec();
            self.stdout = output.stdout.len();
            self.stderr = output.stderr.len();
            (stdout, stderr)
        };
        #[cfg(windows)]
        let (stdout, stderr) = {
            self.stdout += output.stdout.len();
            self.stderr += output.stderr.len();
            (output.stdout, output.stderr)
        };
        self.stdout_closed |= output.stdout_closed;
        self.stderr_closed |= output.stderr_closed;
        // POSIX snapshots flag dropped bytes once a stream reached its capture
        // bound; a drained snapshot also flags streams that did not close,
        // which is not truncation. Windows reads are unbounded increments.
        let flagged = if cfg!(windows) {
            false
        } else if drained {
            output.output_incomplete && output.stdout_closed && output.stderr_closed
        } else {
            output.output_incomplete
        };
        Ok(Increment {
            stdout,
            stderr,
            stdout_closed: self.stdout_closed,
            stderr_closed: self.stderr_closed,
            stdout_truncated: flagged && self.stdout >= LAUNCHER_STREAM_CAPTURE_BYTES,
            stderr_truncated: flagged && self.stderr >= LAUNCHER_STREAM_CAPTURE_BYTES,
        })
    }

    pub fn closed(&self) -> bool {
        self.stdout_closed && self.stderr_closed
    }
}

/// Retained output bound for one command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputBudget {
    /// Node `execFile` `maxBuffer`: each stream may hold at most this many bytes.
    PerStream(usize),
    /// Owned-command diagnostic budget across stdout and stderr together.
    Combined(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct CommandLimits {
    pub timeout: Duration,
    pub budget: OutputBudget,
}

/// Captured physical output of one command.
#[derive(Clone, Debug, Default)]
pub struct CommandOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Bytes observed on each stream, including bytes beyond the budget.
    pub stdout_observed: u64,
    pub stderr_observed: u64,
    /// Exit code once the child's exit was observed.
    pub exit_code: Option<i64>,
    /// Output was dropped (budget or launcher capture bound).
    pub truncated: bool,
    /// Both streams reached end of file.
    pub output_closed: bool,
}

impl CommandOutput {
    /// UTF-8 text with replacement, as `buffer.toString("utf8")`.
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }

    /// Captured output in the shared failure shape.
    pub fn captured(&self) -> CapturedOutput {
        CapturedOutput {
            stdout: self.stdout_text(),
            stderr: self.stderr_text(),
            truncated: self.truncated,
            stdout_bytes: Some(self.stdout.len() as u64),
            stderr_bytes: Some(self.stderr.len() as u64),
            exit_code: Some(self.exit_code),
            signal: Some(None),
        }
    }

    fn absorb(&mut self, increment: &Increment, budget: OutputBudget) -> bool {
        self.stdout_observed += increment.stdout.len() as u64;
        self.stderr_observed += increment.stderr.len() as u64;
        let mut exceeded = increment.capture_truncated();
        match budget {
            OutputBudget::PerStream(maximum) => {
                for (buffer, bytes) in [
                    (&mut self.stdout, &increment.stdout),
                    (&mut self.stderr, &increment.stderr),
                ] {
                    let room = maximum.saturating_sub(buffer.len());
                    let retained = room.min(bytes.len());
                    buffer.extend_from_slice(&bytes[..retained]);
                    exceeded |= retained < bytes.len();
                }
            }
            OutputBudget::Combined(maximum) => {
                for stream in 0..2 {
                    let room = maximum.saturating_sub(self.stdout.len() + self.stderr.len());
                    let (buffer, bytes) = if stream == 0 {
                        (&mut self.stdout, &increment.stdout)
                    } else {
                        (&mut self.stderr, &increment.stderr)
                    };
                    let retained = room.min(bytes.len());
                    buffer.extend_from_slice(&bytes[..retained]);
                    exceeded |= retained < bytes.len();
                }
            }
        }
        self.output_closed = increment.stdout_closed && increment.stderr_closed;
        self.truncated |= exceeded;
        exceeded
    }
}

/// Why a command did not complete successfully.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FailureKind {
    /// The owned child could not be created.
    Launch {
        message: String,
        /// Host error number, when the launcher reported one.
        os_code: Option<i32>,
    },
    /// The caller cancelled; the first reason is retained.
    Cancelled { reason: String },
    /// The command deadline elapsed and the owned child was stopped.
    Timeout,
    /// Output exceeded its budget and the owned child was stopped.
    OutputLimit,
    /// The command exited with a nonzero status.
    Exit,
    /// Supervision failed while collecting output or exit status.
    Collection { message: String },
    /// Output and exit completed, but the owned process group was not proven settled.
    Settlement,
}

impl FailureKind {
    /// Whether launch failed because the program does not exist.
    pub fn program_not_found(&self) -> bool {
        matches!(
            self,
            Self::Launch {
                os_code: Some(2),
                ..
            }
        ) || (cfg!(windows)
            && matches!(
                self,
                Self::Launch {
                    os_code: Some(3),
                    ..
                }
            ))
    }
}

/// A child whose cleanup could not be confirmed; ownership stays here.
#[derive(Debug)]
pub struct RetainedChild {
    child: OwnedChildProcess,
    /// Label naming the retained resource in cleanup reports.
    pub resource: String,
    /// Latest cleanup failure.
    pub reason: String,
}

impl RetainedChild {
    /// Retry the exact owned cleanup; on success the owner is released.
    pub fn retry(&mut self) -> Result<(), String> {
        match self.child.retry_cleanup(1) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.reason = error.to_string();
                Err(self.reason.clone())
            }
        }
    }
}

/// A command that did not complete, with its retained output and owner.
#[derive(Debug)]
pub struct CommandFailure {
    pub kind: FailureKind,
    pub output: CommandOutput,
    /// The child whose cleanup failed, retained for retry.
    pub retained: Option<RetainedChild>,
}

impl CommandFailure {
    fn new(kind: FailureKind, output: CommandOutput) -> Self {
        Self {
            kind,
            output,
            retained: None,
        }
    }

    /// Message of the underlying physical failure, as a diagnostic.
    pub fn describe(&self) -> String {
        match &self.kind {
            FailureKind::Launch { message, .. } | FailureKind::Collection { message } => {
                message.clone()
            }
            FailureKind::Cancelled { .. } => "The operation was aborted".into(),
            FailureKind::Timeout => "Command deadline elapsed.".into(),
            FailureKind::OutputLimit => {
                "Command output exceeded its complete-output budget.".into()
            }
            FailureKind::Exit => format!(
                "Command failed with exit code {}",
                self.output
                    .exit_code
                    .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
            ),
            FailureKind::Settlement => self.retained.as_ref().map_or_else(
                || "Command cleanup failed.".to_owned(),
                |child| child.reason.clone(),
            ),
        }
    }
}

/// Host error number embedded in a launcher message.
pub fn os_code(message: &str) -> Option<i32> {
    if let Some(start) = message.rfind("(os error ") {
        let digits = &message[start + 10..];
        let end = digits.find(')')?;
        return digits[..end].parse().ok();
    }
    message
        .strip_prefix("CreateProcessW failed: ")
        .and_then(|code| code.trim().parse().ok())
}

/// Stop and settle an owned child, distinguishing an already observed exit.
fn settle(child: &mut OwnedChildProcess, exit_observed: bool) -> Result<(), ProcessLaunchError> {
    if exit_observed && child.wait().is_ok() {
        return Ok(());
    }
    match child.cancel(1) {
        Ok(()) => Ok(()),
        Err(error) => match child.try_wait() {
            // The child exited between observation and termination; reap it
            // through the owner rather than by its numeric identity.
            Ok(Some(_)) => child
                .wait()
                .map(|_| ())
                .or_else(|_| child.cancel(1))
                .map_err(|_| error),
            _ => Err(error),
        },
    }
}

/// Poll quickly for short commands, then back off: POSIX snapshots copy the
/// cumulative capture, so long commands poll less often.
pub fn poll_interval(started: Instant) -> Duration {
    let elapsed = started.elapsed();
    if elapsed < Duration::from_millis(200) {
        Duration::from_millis(5)
    } else if elapsed < Duration::from_secs(2) {
        Duration::from_millis(20)
    } else {
        Duration::from_millis(50)
    }
}

/// Run one bounded command to completion.
///
/// The command succeeds only when both streams closed, its exit was observed
/// and (unless `accept_nonzero_exit`) the exit status was zero. Every failure
/// stops the owned child; a child whose stop could not be confirmed is
/// returned in [`CommandFailure::retained`].
pub fn run_command(
    spec: &CommandSpec,
    limits: CommandLimits,
    cancellation: &Cancellation,
    accept_nonzero_exit: bool,
) -> Result<CommandOutput, CommandFailure> {
    if let Some(reason) = cancellation.reason() {
        return Err(CommandFailure::new(
            FailureKind::Cancelled {
                reason: reason.to_owned(),
            },
            CommandOutput::default(),
        ));
    }
    let mut child = OwnedChildProcess::launch(spec.launch_spec(false)).map_err(|error| {
        CommandFailure::new(
            FailureKind::Launch {
                os_code: os_code(&error.message),
                message: error.message,
            },
            CommandOutput::default(),
        )
    })?;
    let started = Instant::now();
    let deadline = started + limits.timeout;
    let mut cursor = Cursor::default();
    let mut output = CommandOutput::default();
    let mut exit: Option<u32> = None;
    let outcome: Result<(), FailureKind> = loop {
        let snapshot = if exit.is_some() {
            child.drain_output_with(|| cancellation.reason().is_some())
        } else {
            child.read_output()
        };
        match snapshot.and_then(|snapshot| cursor.advance(snapshot, exit.is_some())) {
            Ok(increment) => {
                if output.absorb(&increment, limits.budget) {
                    break Err(FailureKind::OutputLimit);
                }
            }
            Err(error) => {
                break Err(FailureKind::Collection {
                    message: error.to_string(),
                });
            }
        }
        if exit.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit = Some(status.code);
                    output.exit_code = Some(i64::from(status.code));
                }
                Ok(None) => {}
                Err(error) => {
                    break Err(FailureKind::Collection {
                        message: error.to_string(),
                    });
                }
            }
        }
        if exit.is_some() && cursor.closed() {
            break Ok(());
        }
        if let Some(reason) = cancellation.reason() {
            break Err(FailureKind::Cancelled {
                reason: reason.to_owned(),
            });
        }
        if Instant::now() >= deadline {
            break Err(FailureKind::Timeout);
        }
        if exit.is_none() {
            std::thread::sleep(poll_interval(started));
        }
    };
    let settled = settle(&mut child, exit.is_some());
    let retained = |child: OwnedChildProcess, error: ProcessLaunchError| RetainedChild {
        child,
        resource: format!("process:{}", spec.program.display()),
        reason: error.to_string(),
    };
    match (outcome, settled) {
        (Ok(()), Ok(())) => {
            if exit != Some(0) && !accept_nonzero_exit {
                return Err(CommandFailure::new(FailureKind::Exit, output));
            }
            // A late cancellation keeps the completed output with the failure.
            if let Some(reason) = cancellation.reason() {
                return Err(CommandFailure::new(
                    FailureKind::Cancelled {
                        reason: reason.to_owned(),
                    },
                    output,
                ));
            }
            Ok(output)
        }
        (Ok(()), Err(error)) => Err(CommandFailure {
            kind: FailureKind::Settlement,
            output,
            retained: Some(retained(child, error)),
        }),
        (Err(kind), Ok(())) => Err(CommandFailure::new(kind, output)),
        (Err(kind), Err(error)) => Err(CommandFailure {
            kind,
            output,
            retained: Some(retained(child, error)),
        }),
    }
}

/// A long-lived child speaking a protocol over stdin/stdout.
///
/// Stderr is retained as bounded diagnostics; stdout is returned to the
/// protocol owner as it arrives. Lifetime byte counters let the owner retire
/// a child before the POSIX launcher's per-stream capture bound is reached.
#[derive(Debug)]
pub struct ProtocolChild {
    child: Option<OwnedChildProcess>,
    cursor: Cursor,
    exit: Option<u32>,
    stderr: Vec<u8>,
    stderr_limit: usize,
    stderr_truncated: bool,
    /// Per-request counters (reset by `reset_diagnostics`).
    stderr_observed: u64,
    stdout_observed: u64,
    /// Counters since launch.
    stdout_lifetime: u64,
    stderr_lifetime: u64,
    stdout_capture_truncated: bool,
    stderr_capture_truncated: bool,
    stopped: bool,
}

impl ProtocolChild {
    /// Launch with protocol stdin; stderr diagnostics keep at most `stderr_limit` bytes.
    pub fn launch(spec: &CommandSpec, stderr_limit: usize) -> Result<Self, ProcessLaunchError> {
        let child = OwnedChildProcess::launch(spec.launch_spec(true))?;
        Ok(Self {
            child: Some(child),
            cursor: Cursor::default(),
            exit: None,
            stderr: Vec::new(),
            stderr_limit,
            stderr_truncated: false,
            stderr_observed: 0,
            stdout_observed: 0,
            stdout_lifetime: 0,
            stderr_lifetime: 0,
            stdout_capture_truncated: false,
            stderr_capture_truncated: false,
            stopped: false,
        })
    }

    /// Write protocol bytes in full.
    pub fn write_all(&self, bytes: &[u8]) -> Result<(), ProcessLaunchError> {
        let Some(child) = self.child.as_ref() else {
            return Err(ProcessLaunchError {
                operation: "write_input",
                message: "owned protocol process was stopped".into(),
                cleanup: None,
            });
        };
        let mut written = 0;
        while written < bytes.len() {
            written += child.write_input(&bytes[written..])?;
        }
        Ok(())
    }

    fn absorb(&mut self, increment: &Increment) {
        self.stdout_observed += increment.stdout.len() as u64;
        self.stderr_observed += increment.stderr.len() as u64;
        self.stdout_lifetime += increment.stdout.len() as u64;
        self.stderr_lifetime += increment.stderr.len() as u64;
        self.stdout_capture_truncated |= increment.stdout_truncated;
        self.stderr_capture_truncated |= increment.stderr_truncated;
        let room = self.stderr_limit.saturating_sub(self.stderr.len());
        let retained = room.min(increment.stderr.len());
        self.stderr.extend_from_slice(&increment.stderr[..retained]);
        self.stderr_truncated |= retained < increment.stderr.len();
    }

    /// New output since the last poll (stdout for the protocol owner; stderr
    /// is also retained internally as diagnostics).
    pub fn poll(&mut self) -> Result<Increment, ProcessLaunchError> {
        let Some(child) = self.child.as_ref() else {
            return Ok(Increment {
                stdout_closed: true,
                stderr_closed: true,
                ..Increment::default()
            });
        };
        let snapshot = child.read_output()?;
        let increment = self.cursor.advance(snapshot, false)?;
        let exit = if self.exit.is_none() {
            child.try_wait()?.map(|status| status.code)
        } else {
            None
        };
        self.absorb(&increment);
        if exit.is_some() {
            self.exit = exit;
        }
        Ok(increment)
    }

    /// Exit code once observed by [`ProtocolChild::poll`].
    pub fn exit_code(&self) -> Option<u32> {
        self.exit
    }

    /// Bytes observed on stdout and stderr since the last reset.
    pub fn observed_bytes(&self) -> (u64, u64) {
        (self.stdout_observed, self.stderr_observed)
    }

    /// Bytes observed on stdout and stderr since launch.
    pub fn lifetime_bytes(&self) -> (u64, u64) {
        (self.stdout_lifetime, self.stderr_lifetime)
    }

    /// Whether the launcher dropped protocol (stdout) bytes.
    pub fn stdout_capture_truncated(&self) -> bool {
        self.stdout_capture_truncated
    }

    /// Retained stderr diagnostics, observed stderr bytes and whether the
    /// retained text is incomplete.
    pub fn diagnostics(&self) -> (String, u64, bool) {
        (
            String::from_utf8_lossy(&self.stderr).into_owned(),
            self.stderr_observed,
            self.stderr_truncated || self.stderr_capture_truncated,
        )
    }

    /// Scope diagnostics and byte accounting to the next request.
    pub fn reset_diagnostics(&mut self) {
        self.stderr.clear();
        self.stderr_truncated = false;
        self.stderr_observed = 0;
        self.stdout_observed = 0;
    }

    /// Whether both output streams reached end of file.
    pub fn output_closed(&self) -> bool {
        self.cursor.closed()
    }

    /// Close protocol input so a cooperative child may exit.
    pub fn close_input(&mut self) {
        if let Some(child) = self.child.as_mut() {
            child.close_input();
        }
    }

    /// Stop the owned child and prove its process group or job settled.
    /// A failed stop keeps ownership; calling again retries it.
    pub fn stop(&mut self) -> Result<(), ProcessLaunchError> {
        if self.stopped {
            return Ok(());
        }
        let Some(child) = self.child.as_mut() else {
            self.stopped = true;
            return Ok(());
        };
        let mut exit_observed = self.exit.is_some();
        if !exit_observed && let Ok(Some(status)) = child.try_wait() {
            self.exit = Some(status.code);
            exit_observed = true;
        }
        let result = if child.last_cleanup_failure().is_some() {
            child.retry_cleanup(1)
        } else {
            settle(child, exit_observed)
        };
        result?;
        // Retain diagnostics the child wrote before it stopped.
        let snapshot = child.read_output();
        if let Ok(snapshot) = snapshot
            && let Ok(increment) = self.cursor.advance(snapshot, false)
        {
            self.absorb(&increment);
        }
        self.child = None;
        self.stopped = true;
        Ok(())
    }

    /// Whether the owned child has been proven stopped.
    pub fn is_stopped(&self) -> bool {
        self.stopped
    }
}
