//! Shell-free command execution with a stop signal, timeout and output cap.
//!
//! Compatibility owner: `src/process/ExecFileOutput.ts` (`execFileBytes` /
//! `execFileOutput`). A command runs in its own owned process group with a
//! complete child environment, captures stdout/stderr up to `max_buffer`
//! bytes, and is stopped with the configured signal (then SIGKILL after the
//! grace) on abort, timeout or output overflow. The call settles only after
//! the process group exits, so the caller can remove files it writes.
//!
//! Process ownership, identity verification and settlement belong to
//! `rea_host::process::launcher`; this module only applies the
//! `execFileOutput` stop/timeout policy and failure classification.
use rea_core::cancellation::Cancellation;
use std::collections::HashMap;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;
/// How long a stopped process may take to exit before it is killed.
/// `STOP_GRACE_MS` in `ExecFileOutput.ts`.
#[cfg(unix)]
const STOP_GRACE: Duration = Duration::from_millis(5_000);
/// The control path that stopped a command.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stopped {
    Abort,
    Overflow,
    Timeout,
}
/// A command failure observed by the owner (`execFileOutput` rejection).
#[derive(Debug)]
pub struct ExecFailure {
    /// Classified failure path (`ETIMEDOUT`, `ABORT_ERR`, launch or runtime).
    pub code: ExecFailureCode,
    /// The failure message (`Command timed out ...`, `spawn ...`, ...).
    pub message: String,
    pub stdout: String,
    pub stderr: String,
}
/// Classified command failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecFailureCode {
    /// Caller/deadline abort observed by the stop signal (`ExecFileOutputCancelledError`).
    Cancelled,
    /// The command exceeded its own timeout (`ETIMEDOUT`, `killed: true`).
    Timeout,
    /// The process could not be spawned.
    Spawn,
    /// The command exited nonzero, was killed by another signal, or its
    /// owned process group could not be settled.
    Process,
    /// Captured output exceeded `max_buffer` (`ERR_CHILD_PROCESS_STDIO_MAXBUFFER`).
    OutputLimit,
}
/// Successful command output (`{ stdout, stderr }`).
#[derive(Clone, Debug)]
pub struct ExecOutput {
    pub stdout: String,
    pub stderr: String,
}
/// Options for one owned command run.
pub struct ExecOptions<'a> {
    pub timeout: Duration,
    pub max_buffer: usize,
    /// Signal sent on abort or timeout before the kill grace.
    pub stop_signal: i32,
    /// Complete child environment (the process inherits nothing else).
    pub environment: &'a HashMap<String, String>,
    pub cwd: Option<&'a str>,
}

fn failure(
    code: ExecFailureCode,
    message: impl Into<String>,
    stdout: String,
    stderr: String,
) -> ExecFailure {
    ExecFailure {
        code,
        message: message.into(),
        stdout,
        stderr,
    }
}

/// Run a shell-free command, capturing complete output within `max_buffer`.
#[cfg(unix)]
pub fn exec_file_output(
    command: &str,
    arguments: &[String],
    options: &ExecOptions<'_>,
    cancellation: &Cancellation,
) -> Result<ExecOutput, ExecFailure> {
    use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
    use rea_host::process::windows::job::WindowsJobLimits;
    use std::ffi::OsString;
    // A stoppable command whose caller already aborted rejects before spawn.
    if cancellation.reason().is_some() {
        return Err(failure(
            ExecFailureCode::Cancelled,
            "The operation was aborted",
            String::new(),
            String::new(),
        ));
    }
    let spec = ChildLaunchSpec {
        executable: command.into(),
        arguments: ChildLaunchSpec::arguments(arguments.iter().map(String::as_str)),
        working_directory: options.cwd.map(Into::into),
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let environment: Vec<(OsString, OsString)> = options
        .environment
        .iter()
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    let mut child =
        OwnedChildProcess::launch_with_environment(spec, &environment, options.max_buffer)
            .map_err(|error| {
                failure(
                    ExecFailureCode::Spawn,
                    format!("spawn {command} failed: {}", error.message),
                    String::new(),
                    String::new(),
                )
            })?;

    let deadline = Instant::now() + options.timeout;
    let mut stopped: Option<Stopped> = None;
    let mut kill_at: Option<Instant> = None;
    let mut settle_error: Option<String> = None;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(_)) => match child.wait() {
                Ok(exit) => break Some(exit),
                Err(error) => {
                    settle_error = Some(error.message);
                    break None;
                }
            },
            Ok(None) => {}
            Err(error) => {
                settle_error = Some(error.message);
                break None;
            }
        }
        if stopped.is_none() {
            let overflow = child
                .read_output()
                .is_ok_and(|output| output.output_incomplete);
            stopped = if overflow {
                Some(Stopped::Overflow)
            } else if cancellation.reason().is_some() {
                Some(Stopped::Abort)
            } else if options.timeout > Duration::ZERO && Instant::now() >= deadline {
                Some(Stopped::Timeout)
            } else {
                None
            };
            if stopped.is_some() {
                let _ = child.signal(options.stop_signal);
                kill_at = Some(Instant::now() + STOP_GRACE);
            }
        }
        if kill_at.is_some_and(|at| Instant::now() >= at) {
            // SIGKILL and settle through the launcher's verified cleanup.
            if let Err(error) = child.cancel(1) {
                settle_error = Some(error.message);
            }
            break None;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let output =
        child
            .drain_output()
            .unwrap_or_else(|_| rea_host::process::launcher::ChildOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdout_closed: false,
                stderr_closed: false,
                output_incomplete: false,
                cancellation_observed: false,
            });
    let overflowed = output.output_incomplete;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    // Classify in the TypeScript order: an explicit stop names the failure,
    // then output-limit, then any nonzero/killed exit.
    match stopped {
        Some(Stopped::Overflow) => Err(failure(
            ExecFailureCode::OutputLimit,
            "stdout maxBuffer length exceeded",
            stdout,
            stderr,
        )),
        Some(Stopped::Abort) => Err(failure(
            ExecFailureCode::Cancelled,
            "The operation was aborted",
            stdout,
            stderr,
        )),
        Some(Stopped::Timeout) => Err(failure(
            ExecFailureCode::Timeout,
            format!(
                "Command timed out after {} ms: {command}",
                options.timeout.as_millis()
            ),
            stdout,
            stderr,
        )),
        None if overflowed => Err(failure(
            ExecFailureCode::OutputLimit,
            "stdout maxBuffer length exceeded",
            stdout,
            stderr,
        )),
        None => match (exit, settle_error) {
            (Some(exit), None) if exit.code == 0 && exit.signal.is_none() => {
                Ok(ExecOutput { stdout, stderr })
            }
            (Some(_), _) => Err(failure(
                ExecFailureCode::Process,
                format!("Command failed: {command}"),
                stdout,
                stderr,
            )),
            (None, reason) => Err(failure(
                ExecFailureCode::Process,
                format!(
                    "Command exit could not be observed: {command}: {}",
                    reason.unwrap_or_default()
                ),
                stdout,
                stderr,
            )),
        },
    }
}

/// Native UI helpers are macOS-only; other platforms never launch them.
#[cfg(not(unix))]
pub fn exec_file_output(
    command: &str,
    _arguments: &[String],
    _options: &ExecOptions<'_>,
    _cancellation: &Cancellation,
) -> Result<ExecOutput, ExecFailure> {
    Err(failure(
        ExecFailureCode::Spawn,
        format!("spawn {command} failed: unsupported platform"),
        String::new(),
        String::new(),
    ))
}
