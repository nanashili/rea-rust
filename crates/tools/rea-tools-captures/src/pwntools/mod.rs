//! pwntools ELF artifact adapters: `inspect_binary_layout` and
//! `inspect_recorded_crash`.
//!
//! Compatibility owners: `src/application/binaryDiagnostics/BinaryLayoutService.ts`,
//! `RecordedCrashService.ts`, `src/native/pwntools/*` and
//! `src/native/pwndbg/*`. Both tools run the unchanged upstream Python bridges
//! under `bridge/pwntools/` (and `bridge/pwndbg/`) exactly as the TypeScript
//! runtime does, and preserve provider identity, limitations and failure
//! strings.
use rea_mcp::Registry;

mod crash;
mod decoder;
mod failures;
mod layout;
mod pwndbg;
mod refine;
mod release;
mod resource_limits;

/// Bind this family's tools.
pub fn register(registry: &mut Registry) {
    layout::register_binary_layout(registry);
    crash::register_recorded_crash(registry);
}
