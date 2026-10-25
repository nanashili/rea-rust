//! Rust Ghidra deep-analysis provider.
//!
//! The provider owns one `rea-ghidra-rust-worker` process per opened target
//! (`native/ghidra-rust-worker`, built on the `ghidra-decompiler` crate) and
//! speaks its line-delimited JSON-RPC protocol. It is the only Ghidra engine
//! of the native runtime; the Java Ghidra bridge is not part of this build.
//!
//! Compatibility owners: `src/ghidra-rust/*` and
//! `src/composition/localGhidraRustProvider.ts`.
mod analysis;
mod batch;
mod client;
mod configuration;
mod identity;
mod inventory;
mod native_instruction;
mod profile;
mod protocol;
mod provider;
mod selectors;
mod session;
mod static_routes;
mod worker;

pub use provider::GhidraRustProvider;

use rea_analysis::AnalysisProvider;
use std::collections::HashMap;
use std::sync::Arc;

/// The Ghidra providers composed for one session environment snapshot.
///
/// The Rust Ghidra candidate is always composed; its availability reports
/// why it cannot run (for example a missing worker executable) without
/// starting anything.
pub fn providers(environment: &HashMap<String, String>) -> Vec<Arc<dyn AnalysisProvider>> {
    vec![Arc::new(GhidraRustProvider::new(
        environment.clone(),
        std::env::current_exe().ok(),
    ))]
}
