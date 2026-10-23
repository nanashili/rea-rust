//! Persistent GDB/MI sessions (`start_gdb_session`, `gdb_console`,
//! `gdb_session_status`, `close_gdb_session`).
//!
//! Compatibility owners: `src/gdb/GdbSessionManager.ts` and
//! `src/server/registerGdbTools.ts`. Persistent sessions are available only on
//! Linux, where REA can verify live inferior output descriptors through
//! `/proc` before detaching; on macOS and Windows `start_gdb_session` returns
//! a platform-specific `AnalysisCapabilityUnavailableError` after the input and
//! closing/cancel checks, exactly as the TypeScript order.
//!
//! The server composition registers one `GdbSessionManager` per connection
//! (`new GdbSessionManager({ environment: providerEnvironment })`) and closes
//! every session at shutdown with the TS close semantics (cleanup failure keeps
//! ownership for retry). This port stores the manager in
//! `context.session.state::<GdbState>()` and registers it once with
//! `context.session.own_once` so MCP shutdown runs `close_all`.
//!
//! The admission hooks the TS registration passes (`withAdmittedExternalMutation`,
//! `runOwnedCleanupWithExternalMutationAdmission`) are owned by the binary
//! session crate and unreachable here; following the
//! `rea-tools-captures/src/reverse` precedent, this registration takes the path
//! the TS code takes when the admission hook is `undefined` (call the manager
//! directly, running `retry_cleanup_failures` first for console). Reported as a
//! requested shared change.
#![allow(dead_code)]

mod manager;
mod mi;

use rea_mcp::Registry;

/// Bind the four persistent GDB tools to their catalog contracts.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("start_gdb_session", |context, input| {
        manager::start_gdb_session(context, input)
    });
    registry.handle("gdb_console", |context, input| {
        manager::gdb_console(context, input)
    });
    registry.handle("gdb_session_status", |context, input| {
        manager::gdb_session_status(context, input)
    });
    registry.handle("close_gdb_session", |context, input| {
        manager::close_gdb_session(context, input)
    });
}
