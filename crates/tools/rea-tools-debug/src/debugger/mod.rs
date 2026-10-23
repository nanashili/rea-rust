//! Shared owned-debugger lifecycle primitives (gdb, rizin).
//!
//! Compatibility owners: `src/process/ownedDebuggerSession.ts`
//! (`stopOwnedDebuggerProcess`, `closeOwnedDebuggerSessions`,
//! `verifyOwnedInferiorsEnded`, `readLinuxProcessStartTime`) and
//! `src/process/ProviderProcess.ts` (owned process + supervisor).
//! `src/process/LinuxProcessStat.ts` is already ported as
//! `rea_core::linux_proc::stat` and reused directly.
//!
//! The TypeScript model is event-driven and asynchronous; this port owns each
//! debugger process through `rea_host::process::launcher::OwnedChildProcess`
//! (launched with `launch_protocol` so stdout framing is owned by each
//! provider) plus one bounded reader thread, and drives the identical
//! lifecycle with blocking waits.
#![allow(dead_code)]

pub(crate) mod owned_session;
pub(crate) mod process;

pub(crate) use owned_session::{
    DebuggerSupervisor, DetachOutcome, OwnedDebuggerDetachResult, OwnedDebuggerProcess,
    OwnedDebuggerStopResult, OwnedInferiorIdentity, read_linux_process_start_time,
    stop_owned_debugger_process, verify_owned_inferiors_ended,
};
pub(crate) use process::DebuggerProcess;
