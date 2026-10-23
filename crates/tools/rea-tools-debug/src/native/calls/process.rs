//! Owned LLDB supervision and target-process termination.
//!
//! Compatibility owners: `src/native/LldbCallTracer.ts` (`runLldb`,
//! `ensureTerminated`, `targetTerminationReason`, `alive`) over
//! `src/process/ProviderProcess.ts` (`spawnOwnedProviderProcess`,
//! `ProviderProcessSupervisor`) and
//! `src/process/ProcessOwnershipObservation.ts`
//! (`observeProcessStartIdentity`, `signalProcessWithStartIdentity`).
//!
//! LLDB runs in its own owned process group through
//! `rea_host::process::launcher` with a complete explicit environment
//! (`{...host, REA_PROCESS_RUN_ID}`) and a bounded diagnostic capture. The
//! traced target is created by debugserver outside that group; it is only
//! signaled while its launch-time start identity still matches.
#![cfg(unix)]

use rea_core::cancellation::Cancellation;
use rea_core::linux_proc::stat::Lifecycle;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::linux::identity::{Observation, ProcessIdentityObserver};
use rea_host::process::windows::job::WindowsJobLimits;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::time::{Duration, Instant};

use super::retained as readback;

/// Retained LLDB stdout/stderr diagnostics (`DIAGNOSTIC_BYTES`).
pub(crate) const DIAGNOSTIC_BYTES: usize = 16 * 1024;
const POLL: Duration = Duration::from_millis(20);

/// How LLDB's supervision ended (`LldbOutcome`).
#[derive(Debug)]
pub(crate) enum LldbOutcome {
    Exited {
        exit_code: Option<i64>,
        output: String,
    },
    Cancelled,
    Timeout,
}

/// `LldbExit`: the outcome plus the ownership facts the tracer retains.
pub(crate) struct LldbExit {
    pub outcome: LldbOutcome,
    /// False proves LLDB never started and could not have created a target.
    pub target_launched: bool,
    pub target_identity: Option<String>,
    pub cleanup_failure: Option<String>,
    /// The LLDB process whose group cleanup could not be verified.
    pub cleanup_owner: Option<OwnedChildProcess>,
}

/// `ProviderStartupDeadline.interruption`: caller abort wins over the deadline.
fn interruption(deadline: Instant, cancellation: &Cancellation) -> Option<LldbOutcome> {
    if cancellation.reason().is_some() {
        Some(LldbOutcome::Cancelled)
    } else if Instant::now() >= deadline {
        Some(LldbOutcome::Timeout)
    } else {
        None
    }
}

/// `supervisor.stop()`: kill and settle the owned group. An exited leader is
/// reaped first so settlement does not re-verify a gone process.
fn stop(child: &mut OwnedChildProcess, exited: bool) -> Result<(), String> {
    if exited && child.wait().is_ok() {
        return Ok(());
    }
    child.cancel(1).map_err(|error| error.message)
}

/// `runLldb`: supervise LLDB while publishing the target identity ack.
pub(crate) fn run_lldb(
    executable: &str,
    arguments: &[String],
    deadline_ms: u64,
    pid_path: &Path,
    identity_ack_path: &Path,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> LldbExit {
    let not_launched = |outcome| LldbExit {
        outcome,
        target_launched: false,
        target_identity: None,
        cleanup_failure: None,
        cleanup_owner: None,
    };
    if cancellation.reason().is_some() {
        return not_launched(LldbOutcome::Cancelled);
    }
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let mut child_environment: Vec<(OsString, OsString)> = environment
        .iter()
        .filter(|(key, _)| key.as_str() != "REA_PROCESS_RUN_ID")
        .map(|(key, value)| (OsString::from(key), OsString::from(value)))
        .collect();
    child_environment.push((
        "REA_PROCESS_RUN_ID".into(),
        uuid::Uuid::new_v4().to_string().into(),
    ));
    let spec = ChildLaunchSpec {
        executable: executable.into(),
        arguments: ChildLaunchSpec::arguments(arguments.iter().map(String::as_str)),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let mut child = match OwnedChildProcess::launch_with_environment(
        spec,
        &child_environment,
        DIAGNOSTIC_BYTES,
    ) {
        Ok(child) => child,
        Err(error) => {
            let outcome = interruption(deadline, cancellation).unwrap_or(LldbOutcome::Exited {
                exit_code: None,
                output: error.message,
            });
            return not_launched(outcome);
        }
    };
    let mut target_identity = None;
    let mut identity_ack_written = false;
    let mut exit = None;
    let outcome = loop {
        if exit.is_none() {
            exit = child.try_wait().ok().flatten();
        }
        let closed = child
            .read_output()
            .is_ok_and(|output| output.stdout_closed && output.stderr_closed);
        if exit.is_some() && closed {
            break interruption(deadline, cancellation).unwrap_or_else(|| {
                let output = child.read_output().ok();
                let mut text = output
                    .as_ref()
                    .map(|output| {
                        let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
                        text.push_str(&String::from_utf8_lossy(&output.stderr));
                        text
                    })
                    .unwrap_or_default();
                let count = text.chars().count();
                if count > DIAGNOSTIC_BYTES {
                    text = text.chars().skip(count - DIAGNOSTIC_BYTES).collect();
                }
                let exit = exit.as_ref();
                LldbOutcome::Exited {
                    exit_code: exit
                        .filter(|exit| exit.signal.is_none())
                        .map(|exit| i64::from(exit.code)),
                    output: text,
                }
            });
        }
        if !identity_ack_written && let Some(pid) = readback::read_target_pid(pid_path) {
            let observation = start_identity(pid);
            let readable = matches!(observation, Some(Ok(_)));
            if let Some(Ok(identity)) = observation {
                target_identity = Some(identity);
            }
            // A failed ack write leaves the bridge to time out its handshake.
            let _ = readback::write_private(
                identity_ack_path,
                if readable { "readable" } else { "unavailable" },
            );
            identity_ack_written = true;
        }
        if let Some(outcome) = interruption(deadline, cancellation) {
            break outcome;
        }
        std::thread::sleep(POLL);
    };
    let stopped = stop(&mut child, exit.is_some());
    let outcome = interruption(deadline, cancellation).unwrap_or(outcome);
    match stopped {
        Ok(()) => LldbExit {
            outcome,
            target_launched: true,
            target_identity,
            cleanup_failure: None,
            cleanup_owner: None,
        },
        Err(reason) => LldbExit {
            outcome,
            target_launched: true,
            target_identity,
            cleanup_failure: Some(reason),
            cleanup_owner: Some(child),
        },
    }
}

/// Retry a retained LLDB group cleanup (`supervisor.stop()` on close).
pub(crate) fn retry_stop(child: &mut OwnedChildProcess) -> Result<(), String> {
    child.retry_cleanup(1).map_err(|error| error.message)
}

/// `observeProcessStartIdentity`: `None` when the PID is gone (or a zombie),
/// `Err` when its identity is unreadable.
fn start_identity(pid: u32) -> Option<Result<String, String>> {
    match ProcessIdentityObserver.observe(u64::from(pid), false) {
        Observation::Readable {
            lifecycle: Some(Lifecycle::Zombie),
            ..
        } => None,
        Observation::Readable { identity, .. } => Some(Ok(identity)),
        Observation::Absent { .. } => None,
        Observation::Unavailable { reason } => Some(Err(reason)),
    }
}

/// `TargetTermination`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TargetTermination {
    Terminated,
    IdentityUnavailable,
    IdentityChanged,
    SignalDidNotStop,
}

/// `targetTerminationReason`.
pub(crate) fn target_termination_reason(termination: TargetTermination) -> &'static str {
    match termination {
        TargetTermination::Terminated => "target process terminated",
        TargetTermination::IdentityUnavailable => {
            "target process start identity was unavailable; survivor was left untouched"
        }
        TargetTermination::IdentityChanged => {
            "target PID start identity changed; replacement process was left untouched"
        }
        TargetTermination::SignalDidNotStop => "verified target did not exit after SIGKILL",
    }
}

/// `alive`: `kill(pid, 0)` succeeds or fails with anything but ESRCH.
fn alive(pid: u32) -> bool {
    let Some(pid) = i32::try_from(pid)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    !matches!(
        rustix::process::test_kill_process(pid),
        Err(rustix::io::Errno::SRCH)
    )
}

/// `signalProcessWithStartIdentity(pid, identity, "SIGKILL")`.
fn signal_with_identity(pid: u32, expected: &str) -> TargetTermination {
    match start_identity(pid) {
        None => TargetTermination::Terminated,
        Some(Err(_)) => TargetTermination::IdentityUnavailable,
        Some(Ok(identity)) if identity != expected => TargetTermination::IdentityChanged,
        Some(Ok(_)) => {
            let signaled = i32::try_from(pid)
                .ok()
                .and_then(rustix::process::Pid::from_raw)
                .is_some_and(|pid| {
                    rustix::process::kill_process(pid, rustix::process::Signal::KILL).is_ok()
                });
            if signaled {
                TargetTermination::SignalDidNotStop
            } else {
                TargetTermination::IdentityUnavailable
            }
        }
    }
}

/// `ensureTerminated`: only signal a surviving target whose captured OS start
/// identity still matches.
pub(crate) fn ensure_terminated(pid: Option<u32>, identity: Option<&str>) -> TargetTermination {
    let Some(pid) = pid else {
        return TargetTermination::IdentityUnavailable;
    };
    let mut disposition = None;
    for attempt in 0..20 {
        if !alive(pid) {
            return TargetTermination::Terminated;
        }
        if attempt == 10 {
            match identity {
                None => disposition = Some(TargetTermination::IdentityUnavailable),
                Some(identity) => match signal_with_identity(pid, identity) {
                    TargetTermination::Terminated => return TargetTermination::Terminated,
                    other => disposition = Some(other),
                },
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !alive(pid) {
        TargetTermination::Terminated
    } else {
        disposition.unwrap_or(TargetTermination::IdentityUnavailable)
    }
}
