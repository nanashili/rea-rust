//! ADB device inspection and acquisition tools over a caller-selected adb
//! binary.
//!
//! Compatibility owners: `src/server/registerAdbTools.ts`,
//! `src/application/adb/*`, `src/domain/adb/adbDeviceAnalysis.ts` and
//! `src/adb/*`.
use rea_mcp::Registry;

pub mod command;
pub mod config;
pub mod device_output;
pub mod directory_listing;
pub mod files;
pub mod host_file_name;
pub mod provider;
pub mod provider_acquire;
pub mod provider_mutate;
pub mod provider_reads;
pub mod shell_output;
pub mod state;

pub use provider::availability;

/// Bind every ADB tool to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    provider::register(registry);
}
