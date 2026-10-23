//! Static artifact, Apple, PE, Rust, Go, IL2CPP, SQLite, WASM, EVM and Swift tools.
use rea_mcp::Registry;

#[allow(dead_code)]
mod artifact_reader;
mod common;
#[allow(dead_code)]
mod directory_reader;
#[allow(dead_code)]
mod lipo;
#[cfg(feature = "family-macos-readers")]
#[allow(dead_code)]
mod macos_readers;
mod native_command;

#[cfg(feature = "family-apple")]
mod apple;
#[cfg(feature = "family-artifacts")]
mod artifact_graph;
#[cfg(feature = "family-desktop")]
mod desktop;
#[cfg(feature = "family-evm")]
mod evm;
#[cfg(feature = "native-core")]
mod native_macos;
#[cfg(feature = "family-sqlite")]
mod sqlite;
#[cfg(feature = "family-static")]
mod static_binaries;
#[cfg(feature = "family-wasm")]
mod wasm;

/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    #[cfg(feature = "family-static")]
    static_binaries::register(registry);
    #[cfg(feature = "family-sqlite")]
    sqlite::register(registry);
    #[cfg(feature = "family-evm")]
    evm::register(registry);
    #[cfg(feature = "family-wasm")]
    wasm::register(registry);
    #[cfg(feature = "native-core")]
    native_macos::register(registry);
    #[cfg(feature = "family-artifacts")]
    artifact_graph::register(registry);
    #[cfg(feature = "family-desktop")]
    desktop::register(registry);
    #[cfg(feature = "family-apple")]
    apple::register(registry);
    let _ = registry;
}
