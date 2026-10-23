//! Persistent Rizin debugger sessions (`start_rizin_debug_session`,
//! `rizin_debug_command`, `rizin_debug_session_status`,
//! `close_rizin_debug_session`).
//!
//! Compatibility owners: `src/rizin/RizinDebugSessionManager.ts` and
//! `src/server/registerRizinDebugTools.ts`. Persistent sessions run only on
//! Linux, where REA can verify inferior output descriptors through `/proc`
//! before detaching; elsewhere `start_rizin_debug_session` returns the TS
//! `AnalysisCapabilityUnavailableError` after the closing, capacity and
//! cancellation checks, in the TS order.
//!
//! The manager lives in `context.session.state::<RizinState>()` and is owned
//! once with `own_once`, so MCP shutdown runs `closeAll` semantics (cleanup
//! failures keep ownership for retry).
//!
//! The TS registration wraps start/command/close in
//! `runWithExternalMutationAdmission` with the binary session's
//! `withAdmittedExternalMutation` hook. That hook is owned by
//! `rea-tools-binary` and unreachable here; like the cutter and gdb ports,
//! this registration takes the path TS takes when the hook is `undefined`:
//! start and command run `retryCleanupFailures` first, close runs directly.
//! Reported as a requested shared change.
mod frames;
mod manager;

use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::Value;
use std::sync::Arc;

use manager::{RizinState, StartInput};

fn state(context: &ToolContext<'_>) -> Arc<RizinState> {
    let state = context.session.state::<RizinState>();
    context.session.own_once(Arc::clone(&state));
    state
}

fn text(input: &Value, key: &str) -> Option<String> {
    input.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Bind the four persistent Rizin debugger tools to their catalog contracts.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("start_rizin_debug_session", |context, input| {
        let state = state(context);
        if let Err(error) = state.retry_cleanup_failures() {
            return ToolOutput::Failure(error);
        }
        let input = StartInput {
            path: text(&input, "path").unwrap_or_default(),
            inferior_tty: text(&input, "inferior_tty").unwrap_or_default(),
            backend: text(&input, "backend"),
        };
        match state.start(context, input) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => ToolOutput::Failure(error),
        }
    });
    registry.handle("rizin_debug_command", |context, input| {
        let state = state(context);
        if let Err(error) = state.retry_cleanup_failures() {
            return ToolOutput::Failure(error);
        }
        let session_id = text(&input, "session_id").unwrap_or_default();
        let command = text(&input, "command").unwrap_or_default();
        state.execute(context, &session_id, &command).into()
    });
    registry.handle("rizin_debug_session_status", |context, input| {
        let state = state(context);
        let session_id = text(&input, "session_id").unwrap_or_default();
        match state.status(&session_id) {
            Some(value) => ToolOutput::Value(value),
            None => ToolOutput::Failure(AnalysisError::input(
                "rizin_debug_session_status",
                Vec::new(),
            )),
        }
    });
    registry.handle("close_rizin_debug_session", |context, input| {
        let state = state(context);
        let session_id = text(&input, "session_id").unwrap_or_default();
        match state.close(&session_id) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => ToolOutput::Failure(error),
        }
    });
}
