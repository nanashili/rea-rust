//! Apktool resource-decoding tools over a caller-selected launcher.
//!
//! Compatibility owners: `src/server/registerApktoolTools.ts`,
//! `src/application/apktool/*`, `src/domain/apktool/apktoolResourceAnalysis.ts`
//! and `src/apktool/*`. Apktool is bring-your-own: REA never installs it, and
//! decoding happens in a provider-owned workspace removed after projection.
//! Each MCP call serializes through one per-session provider (a turnstile), as
//! the single TypeScript provider instance does, and failed cleanup stays owned
//! for retry before the next call and on session close.

use rea_mcp::Registry;

mod config;
mod decode_output;
mod locale;
mod provider;
mod state;
mod string_tables;
mod strings_xml;
mod version;
mod workspace;

pub(crate) use provider::OPERATION_INSPECT;
pub use provider::availability;

/// Bind every Apktool tool to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    provider::register(registry);
}
