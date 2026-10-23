//! Frida device discovery and instrumentation sessions (feature `frida`).
//!
//! Compatibility owners: `src/frida/FridaInstrumentationManager.ts` (provider),
//! `src/application/frida/FridaInstrumentationService.ts` (workflows/Evidence),
//! `src/application/frida/FridaInstrumentationPort.ts` and
//! `src/server/registerFridaTools.ts`.
//!
//! The nine tools run through the owned GLib-thread FFI wrapper (`ffi.rs`), the
//! `Manager`/`Service` port (`manager.rs`/`service.rs`) and the pure
//! capture/input layers (`capture.rs`/`input.rs`). The manager lives in
//! `context.session.state::<Manager>()` and is owned once with `own_once`, so
//! MCP shutdown runs `closeAll`. Cross-field `.refine` input failures render as
//! the SDK boundary's text-only `Input validation error: ...` via
//! `ToolOutput::Raw`; base-schema failures are rejected by the catalog schema
//! before a handler runs.
#![allow(unsafe_code)]
#![allow(dead_code)]

pub(crate) mod capture;
pub(crate) mod ffi;
pub(crate) mod input;
pub(crate) mod manager;
pub(crate) mod service;

use std::sync::Arc;

use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};

use manager::{Manager, Mode, Remote, ScriptSource, Selector, StartInput};
use service::InstrumentInput;

/// Build/link proof for the pinned frida-core devkit. Not wired into
/// `register`; retained as a devkit smoke symbol.
fn probe() -> u32 {
    // SAFETY: `frida_init` takes no arguments and is idempotent.
    unsafe {
        frida_sys::frida_init();
    }
    0
}

fn state(context: &ToolContext<'_>) -> Arc<Manager> {
    let state = context.session.state::<Manager>();
    context.session.own_once(Arc::clone(&state));
    state
}

fn text(input: &Value, key: &str) -> Option<String> {
    input.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn u32_field(input: &Value, key: &str) -> Option<u32> {
    input
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
}

fn remote(input: &Value) -> Option<Remote> {
    let remote = input.get("remote")?;
    Some(Remote {
        address: text(remote, "address").unwrap_or_default(),
        token: text(remote, "token"),
        certificate: text(remote, "certificate"),
        origin: text(remote, "origin"),
        keepalive_interval: remote.get("keepalive_interval").and_then(Value::as_i64),
    })
}

fn selector(input: &Value) -> Selector {
    Selector {
        device_id: text(input, "device_id"),
        remote: remote(input),
    }
}

fn mode(input: &Value) -> Mode {
    match text(input, "mode").as_deref() {
        Some("spawn") => Mode::Spawn,
        _ => Mode::Attach,
    }
}

fn argv(input: &Value) -> Option<Vec<String>> {
    input.get("argv").and_then(Value::as_array).map(|items| {
        items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn start_input(input: &Value) -> StartInput {
    StartInput {
        selector: selector(input),
        mode: mode(input),
        pid: u32_field(input, "pid"),
        program: text(input, "program"),
        argv: argv(input),
    }
}

fn script_source(input: &Value) -> Option<ScriptSource> {
    match text(input, "source_kind").as_deref() {
        Some("inline") => text(input, "source").map(ScriptSource::Inline),
        Some("file") => text(input, "path").map(ScriptSource::File),
        _ => None,
    }
}

/// A text-only SDK boundary failure (no structuredContent), matching the
/// MCP server's rendering of a cross-field `.refine` rejection.
fn refinement(text: String) -> ToolOutput {
    ToolOutput::Raw(json!({
        "content": [{ "type": "text", "text": text }],
        "isError": true,
    }))
}

/// Bind the nine Frida tools to their catalog contracts.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("list_frida_devices", |context, input| {
        if let Some(text) = input::remote_address_refinement("list_frida_devices", &input) {
            return refinement(text);
        }
        match service::list_devices(&state(context), remote(&input)) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("list_frida_processes", |context, input| {
        if let Some(text) = input::list_processes_refinement(&input) {
            return refinement(text);
        }
        match service::list_processes(&state(context), selector(&input)) {
            Ok(value) => ToolOutput::Value(value),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("start_frida_session", |context, input| {
        if let Some(text) = input::start_refinement(&input) {
            return refinement(text);
        }
        match state(context).start_session(start_input(&input)) {
            Ok(session) => ToolOutput::Value(service::session_output(&session)),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("load_frida_script", |context, input| {
        if let Some(text) = input::load_refinement(&input) {
            return refinement(text);
        }
        let session_id = text(&input, "session_id").unwrap_or_default();
        let Some(source) = script_source(&input) else {
            return ToolOutput::Failure(AnalysisError::input("load_frida_script", Vec::new()));
        };
        service::load_script(&state(context), &session_id, source).into()
    });

    registry.handle("resume_frida_session", |context, input| {
        let session_id = text(&input, "session_id").unwrap_or_default();
        match state(context).resume_session(&session_id) {
            Ok(()) => ToolOutput::Value(json!({ "state": "running" })),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("unload_frida_script", |context, input| {
        let session_id = text(&input, "session_id").unwrap_or_default();
        let script_id = text(&input, "script_id").unwrap_or_default();
        match state(context).unload_script(&session_id, &script_id) {
            Ok(()) => ToolOutput::Value(json!({ "unloaded": true })),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("frida_session_status", |context, input| {
        let session_id = text(&input, "session_id").unwrap_or_default();
        match service::status_evidence(&state(context), &session_id) {
            Some(Ok(evidence)) => ToolOutput::Evidence(evidence),
            Some(Err(error)) => ToolOutput::Failure(error),
            None => ToolOutput::Failure(manager::unknown_session_error(
                "frida_session_status",
                &session_id,
            )),
        }
    });

    registry.handle("close_frida_session", |context, input| {
        let session_id = text(&input, "session_id").unwrap_or_default();
        match state(context).close_session(&session_id) {
            Ok(_) => ToolOutput::Value(json!({ "target_state": "unknown" })),
            Err(error) => ToolOutput::Failure(error),
        }
    });

    registry.handle("instrument_with_frida", |context, input| {
        if let Some(text) = input::instrument_refinement(&input) {
            return refinement(text);
        }
        let Some(source) = script_source(&input) else {
            return ToolOutput::Failure(AnalysisError::input("instrument_with_frida", Vec::new()));
        };
        let duration_ms = input
            .get("duration_ms")
            .and_then(Value::as_u64)
            .unwrap_or(1_000);
        let instrument = InstrumentInput {
            start: start_input(&input),
            source,
            duration_ms,
        };
        service::instrument(&state(context), instrument).into()
    });
}
