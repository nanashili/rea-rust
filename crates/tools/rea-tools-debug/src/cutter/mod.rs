//! Cutter bridge discovery and arbitrary Rizin command tools.
//!
//! Port of the TypeScript oracle:
//! - `src/server/registerCutterTools.ts` (tool registration and delivery),
//! - `src/cutter/CutterBridgeService.ts` (shared workflows, Evidence,
//!   pending-cleanup bookkeeping),
//! - `src/cutter/CutterBridgeClient.ts` (descriptor discovery, directory
//!   security, the authenticated loopback transport and error mapping).
//!
//! The bridge wire protocol (`bridge/cutter/rea_bridge.py`) is the upstream
//! Cutter-side plugin; REA is only the client. Nothing here modifies it.
//!
//! `cutter_command` is an externally mutating command. In the TypeScript
//! registration it runs through `runWithExternalMutationAdmission` with the
//! binary session's `withAdmittedExternalMutation` hook. That admission hook
//! is owned by `rea-tools-binary` and is unreachable from this crate, so this
//! port takes the path the TS registration takes when the admission hook is
//! `undefined` (call the service directly, running cleanup recovery first),
//! exactly as the `rea-tools-captures` reverse module does. This is listed as
//! a requested shared change in the worker report.

use rea_mcp::{Registry, ToolOutput};
use std::sync::Arc;

mod client;
mod service;
mod transport;

use service::{CutterBridgeState, CutterServiceResource};

/// Bind this group's tools to their exact catalog contracts.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("list_cutter_sessions", |context, _input| {
        let state = context.session.state::<CutterBridgeState>();
        // Own the service once so a shutdown drives descriptor cleanup retry,
        // mirroring `CutterBridgeService.close()` in the provider close set.
        context
            .session
            .own_once(Arc::new(CutterServiceResource(state.clone())));
        match state.list_sessions(context) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("cutter_command", |context, input| {
        let state = context.session.state::<CutterBridgeState>();
        context
            .session
            .own_once(Arc::new(CutterServiceResource(state.clone())));
        state.execute(context, input)
    });
}
