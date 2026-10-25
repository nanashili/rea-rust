//! Bounded process scenario capture and comparison.
//!
//! `capture_process_scenario` runs one command on an owned PTY
//! (`rea_host::process::pty`) and renders frames with the native
//! xterm-compatible terminal (`rea_host::process::terminal`);
//! `compare_process_captures` compares two such captures.
mod capture;
mod compare_tool;
mod comparison;
mod input_failure;
mod json;
#[cfg(unix)]
mod run;
mod shape;

use rea_mcp::Registry;

/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    #[cfg(unix)]
    registry.handle(
        "capture_process_scenario",
        run::tool::capture_process_scenario,
    );
    registry.handle(
        "compare_process_captures",
        compare_tool::compare_process_captures,
    );
}
