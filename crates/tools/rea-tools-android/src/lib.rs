//! Android (JADX), Apktool, JEB and ADB device tools.
//!
//! Compatibility owners: `src/server/registerAndroidTools.ts`,
//! `src/server/registerApktoolTools.ts`, `src/server/registerJebTools.ts`
//! and `src/server/registerAdbTools.ts` with their application services and
//! provider adapters.
use rea_mcp::Registry;

pub mod adb;
pub mod apktool;
pub mod common;
pub mod jadx;
pub mod jeb;

/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    jadx::register(registry);
    apktool::register(registry);
    jeb::register(registry);
    adb::register(registry);
}
