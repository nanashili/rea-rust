//! Owned-debugger stop/detach lifecycle shared by gdb and rizin.
//!
//! Compatibility owner: `src/process/ownedDebuggerSession.ts`. Each provider
//! session implements [`OwnedDebuggerProcess`]; `stop_owned_debugger_process`
//! drives the same ordered cleanup the TypeScript does: confirm no inferior or
//! detach one with a verified durable output sink, then terminate only the
//! directly owned process (never its group or inferiors) with SIGTERM then
//! SIGKILL, and finally confirm inherited output streams settled. Cleanup that
//! cannot be confirmed returns `Incomplete`, and the caller keeps ownership so
//! the retry path can run again.

#[cfg(target_os = "linux")]
use rea_core::linux_proc::stat;
use std::io::ErrorKind;
use std::time::Duration;

/// Settlement grace for a detach confirmation (`DETACH_TIMEOUT_MS`).
pub(crate) const DETACH_TIMEOUT_MS: u64 = 1_000;
/// Bound retained bytes after debugger shutdown (`MAX_LATE_DEBUGGER_OUTPUT_BYTES`).
pub(crate) const MAX_LATE_DEBUGGER_OUTPUT_BYTES: usize = 64 * 1024;

/// Result of terminating one owned debugger process (`OwnedDebuggerStopResult`).
#[derive(Clone, Debug)]
pub(crate) enum OwnedDebuggerStopResult {
    Stopped,
    AlreadyExited,
    Incomplete { reason: String },
}

impl OwnedDebuggerStopResult {
    pub(crate) fn is_incomplete(&self) -> bool {
        matches!(self, Self::Incomplete { .. })
    }
}

/// Verified inferior disposition (`OwnedDebuggerDetachResult`).
#[derive(Clone, Debug)]
pub(crate) enum OwnedDebuggerDetachResult {
    NoInferior,
    /// Detached only after a durable caller-selected output sink was verified.
    DetachedDurable,
}

impl OwnedDebuggerDetachResult {
    fn is_verified(&self) -> bool {
        matches!(self, Self::NoInferior | Self::DetachedDurable)
    }
}

/// One previously identified inferior process (`OwnedInferiorIdentity`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnedInferiorIdentity {
    pub(crate) pid: String,
    pub(crate) start_time: String,
}

/// Read one Linux process start time; absence is distinct from unreadable or
/// malformed data (`readLinuxProcessStartTime`).
///
/// `Ok(None)` is reported only for ENOENT (the PID no longer exists).
pub(crate) fn read_linux_process_start_time(pid: &str) -> Result<Option<String>, String> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err("Inferior process identity verification requires Linux /proc.".to_owned())
    }
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/stat");
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        let parsed = stat::parse(&text).ok();
        match parsed {
            Some(parsed) if pid.parse::<u64>().ok() == Some(parsed.pid) => {
                Ok(Some(parsed.start_time.to_owned()))
            }
            _ => Err(format!(
                "Inferior PID {pid} has an unreadable process identity."
            )),
        }
    }
}

/// Confirm only that every previously identified inferior process has ended
/// (`verifyOwnedInferiorsEnded`). Returns `false` when any identity still
/// resolves to the same start time, and `false` when the set is empty.
pub(crate) fn verify_owned_inferiors_ended<'a, I>(identities: I) -> Result<bool, String>
where
    I: IntoIterator<Item = &'a OwnedInferiorIdentity>,
{
    let mut found_identity = false;
    for identity in identities {
        found_identity = true;
        let observed = read_linux_process_start_time(&identity.pid)?;
        if observed.as_deref() == Some(identity.start_time.as_str()) {
            return Ok(false);
        }
    }
    Ok(found_identity)
}

/// Bounded output-close verification over an owned provider process.
pub(crate) trait DebuggerSupervisor {
    /// Cap retained bytes after shutdown while continuing to drain.
    fn limit_additional_output_bytes(&self, max_bytes: usize);
    /// Verify inherited output streams closed within the timeout.
    fn wait_for_output_close(&self, timeout: Duration) -> Result<bool, String>;
    /// Stop referencing output streams so they cannot hold the loop open.
    fn unref_output_streams(&self);
    /// Release retained supervisor resources after confirmed settlement.
    fn dispose(&self);
    /// Terminate only the directly owned process with SIGTERM.
    fn term(&self) -> Result<(), String>;
    /// Terminate only the directly owned process with SIGKILL.
    fn kill(&self) -> Result<(), String>;
    /// Wait for the owned process to exit within the timeout.
    fn wait_for_exit(&self, timeout: Duration) -> bool;
}

/// Per-session detach outcome (`detachOutcomes` WeakMap).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DetachOutcome {
    Confirmed,
    Unconfirmed,
    InferiorEnded,
}

/// One owned debugger process (`OwnedDebuggerProcess`).
///
/// Implementors own serialization of `detach_inferior` internally; the shared
/// lifecycle calls it at most once per in-flight attempt (the TypeScript
/// `detachAttempts` WeakMap) through [`OwnedDebuggerProcess::run_detach`].
pub(crate) trait OwnedDebuggerProcess {
    fn id(&self) -> &str;
    fn exited(&self) -> bool;
    fn supervisor(&self) -> &dyn DebuggerSupervisor;

    /// Stored detach outcome for this session.
    fn detach_outcome(&self) -> Option<DetachOutcome>;
    fn set_detach_outcome(&self, outcome: DetachOutcome);
    /// Whether a detach attempt is still pending (`detachAttempts.has`).
    fn detach_pending(&self) -> bool;

    /// `inferiorStateUnknown?.()` — present only for providers that infer it.
    fn inferior_state_unknown(&self) -> Option<bool> {
        None
    }
    /// `verifyInferiorsEndedAfterExit?.()` — present only for such providers.
    fn verify_inferiors_ended_after_exit(&self) -> Option<Result<bool, String>> {
        None
    }

    /// Whether this provider can verify detachment at all (`detachInferior`).
    fn has_detach_capability(&self) -> bool {
        true
    }

    /// Run the provider detach with the shared single-attempt + timeout race,
    /// returning `Ok(None)` when the attempt did not settle in time. The
    /// provider records `Confirmed`/`Unconfirmed` through this call.
    fn run_detach(&self) -> Result<Option<OwnedDebuggerDetachResult>, String>;
}

/// Finalize an exited owned session (`finishExitedDebuggerSession`).
fn finish_exited_debugger_session(
    session: &dyn OwnedDebuggerProcess,
    debugger_name: &str,
    status: OwnedDebuggerStopResult,
) -> OwnedDebuggerStopResult {
    let supervisor = session.supervisor();
    supervisor.limit_additional_output_bytes(MAX_LATE_DEBUGGER_OUTPUT_BYTES);
    match supervisor.wait_for_output_close(Duration::from_millis(1_000)) {
        Ok(true) => {}
        Ok(false) => {
            return OwnedDebuggerStopResult::Incomplete {
                reason: format!(
                    "Owned {debugger_name} process leader exited, but inherited output streams are still open or have not reported settlement."
                ),
            };
        }
        Err(cause) => {
            return OwnedDebuggerStopResult::Incomplete {
                reason: format!(
                    "Owned {debugger_name} inherited output stream settlement could not be verified: {cause}"
                ),
            };
        }
    }
    supervisor.unref_output_streams();
    supervisor.dispose();
    status
}

/// Stop only the directly owned debugger process, never its group or target
/// (`stopOwnedDebuggerProcess`, POSIX path; this port supports Linux only).
pub(crate) fn stop_owned_debugger_process(
    session: &dyn OwnedDebuggerProcess,
    debugger_name: &str,
) -> OwnedDebuggerStopResult {
    if session.exited() {
        if session.detach_pending() {
            return OwnedDebuggerStopResult::Incomplete {
                reason: format!(
                    "Owned {debugger_name} inferior detach is still pending after the process exited."
                ),
            };
        }
        let detach_outcome = session.detach_outcome();
        let needs_verify = detach_outcome == Some(DetachOutcome::Unconfirmed)
            || (detach_outcome.is_none() && session.inferior_state_unknown() == Some(true));
        if needs_verify {
            match session.verify_inferiors_ended_after_exit() {
                Some(Ok(true)) => session.set_detach_outcome(DetachOutcome::InferiorEnded),
                Some(Ok(false)) | None => {
                    return OwnedDebuggerStopResult::Incomplete {
                        reason: format!(
                            "Owned {debugger_name} inferior disposition was not verified before the debugger exited, and no owner proof confirms the identified inferior processes have ended."
                        ),
                    };
                }
                Some(Err(cause)) => {
                    return OwnedDebuggerStopResult::Incomplete {
                        reason: format!(
                            "Owned {debugger_name} inferior process identity could not be verified after debugger exit: {cause}"
                        ),
                    };
                }
            }
        }
        return finish_exited_debugger_session(
            session,
            debugger_name,
            OwnedDebuggerStopResult::AlreadyExited,
        );
    }

    if !session.has_detach_capability() {
        session.set_detach_outcome(DetachOutcome::Unconfirmed);
        return OwnedDebuggerStopResult::Incomplete {
            reason: format!(
                "Owned {debugger_name} inferior detach cannot be verified because the provider has no detach capability."
            ),
        };
    }

    match session.run_detach() {
        Ok(None) => {
            return OwnedDebuggerStopResult::Incomplete {
                reason: format!(
                    "Owned {debugger_name} inferior detach was not verified within {DETACH_TIMEOUT_MS} ms."
                ),
            };
        }
        Ok(Some(detached)) => {
            if !detached.is_verified() {
                session.set_detach_outcome(DetachOutcome::Unconfirmed);
                return OwnedDebuggerStopResult::Incomplete {
                    reason: format!(
                        "Owned {debugger_name} provider did not confirm no inferior or detachment with a durable output sink."
                    ),
                };
            }
            session.set_detach_outcome(DetachOutcome::Confirmed);
        }
        Err(cause) => {
            return OwnedDebuggerStopResult::Incomplete {
                reason: format!(
                    "Owned {debugger_name} inferior detach could not be verified: {cause}"
                ),
            };
        }
    }

    let supervisor = session.supervisor();
    if let Err(cause) = supervisor.term() {
        return OwnedDebuggerStopResult::Incomplete {
            reason: format!("Owned {debugger_name} process termination failed: {cause}"),
        };
    }
    if !supervisor.wait_for_exit(Duration::from_millis(300)) {
        if let Err(cause) = supervisor.kill() {
            return OwnedDebuggerStopResult::Incomplete {
                reason: format!("Owned {debugger_name} process termination failed: {cause}"),
            };
        }
        let exited_after_kill = supervisor.wait_for_exit(Duration::from_millis(1_000));
        if exited_after_kill {
            return finish_exited_debugger_session(
                session,
                debugger_name,
                OwnedDebuggerStopResult::Stopped,
            );
        }
        return OwnedDebuggerStopResult::Incomplete {
            reason: format!("Owned {debugger_name} process did not exit after direct termination."),
        };
    }
    finish_exited_debugger_session(session, debugger_name, OwnedDebuggerStopResult::Stopped)
}

/// Keep the ErrorKind import referenced on non-Linux builds.
#[cfg(not(target_os = "linux"))]
const _: fn() -> ErrorKind = || ErrorKind::NotFound;
