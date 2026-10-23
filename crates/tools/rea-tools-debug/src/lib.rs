//! GDB, Rizin debugger, Cutter, Frida and native UI/call observation tools.
//!
//! Each tool group lives in its own feature-gated module; `register` binds
//! every group compiled into this build.
//!
//! Frida tools (`list_frida_devices`, `list_frida_processes`,
//! `start_frida_session`, `load_frida_script`, `resume_frida_session`,
//! `unload_frida_script`, `frida_session_status`, `close_frida_session`,
//! `instrument_with_frida`) are bound when the `frida` feature is compiled in;
//! they drive frida-core through the owned GLib-thread wrapper in
//! `frida/ffi.rs`. The feature links the pinned devkit and is off by default.
use rea_mcp::Registry;

mod common;
#[cfg(feature = "cutter")]
mod cutter;
#[cfg(feature = "debugger")]
mod debugger;
#[cfg(feature = "frida")]
mod frida;
#[cfg(feature = "gdb")]
mod gdb;
#[cfg(feature = "native")]
mod native;
#[cfg(feature = "rizin")]
mod rizin;

/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    #[cfg(feature = "cutter")]
    cutter::register(registry);
    #[cfg(feature = "gdb")]
    gdb::register(registry);
    #[cfg(feature = "native")]
    native::register(registry);
    #[cfg(feature = "rizin")]
    rizin::register(registry);
    #[cfg(feature = "frida")]
    frida::register(registry);
    let _ = registry;
}
