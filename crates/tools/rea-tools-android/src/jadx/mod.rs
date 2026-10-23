//! Static Android (JADX) inspection tools over a caller-supplied
//! jadx-headless-mcp JAR and JDK, launched headless through REA's bridge.
//!
//! Compatibility owners: `src/server/registerAndroidTools.ts`,
//! `src/application/android/*`, `src/domain/android/*` and `src/android/*`.
use rea_mcp::Registry;

pub mod analysis;
pub mod archive;
pub mod configuration;
pub mod failure;
pub mod java_probe;
pub mod protocol;
pub mod provider;
pub mod release;
pub mod service;
pub mod session;
pub mod transport;

pub use provider::availability;

/// Bind every JADX tool to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    service::register(registry);
}
