//! Host resource owners. Platform facts and cleanup receipts stay outside domain
//! semantics; a failed cleanup may retain the exact handle for explicit retry.

#[cfg(target_os = "macos")]
pub mod apple_asset_catalog;
pub mod cdp_transport;
#[cfg(unix)]
pub mod command_interrupts;
pub mod fs;
pub mod ghidra_rust;
pub mod process;
