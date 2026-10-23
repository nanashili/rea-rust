//! Browser, Electron and JavaScript runtime observation tools over CDP.
//!
//! Each feature-gated group owns its tools' handlers. `cdp` is the shared
//! owner of loopback CDP endpoint discovery and the connection port used by
//! the live browser, Electron, module-resolver and V8 Inspector groups.
use rea_mcp::Registry;
#[cfg(feature = "browser")]
mod browser;
#[cfg(feature = "browser-scenario")]
mod browser_scenario;
#[cfg(feature = "cdp")]
pub(crate) mod cdp;
#[cfg(feature = "comparisons")]
mod comparisons;
#[cfg(feature = "electron")]
mod electron;
#[cfg(feature = "electron-fuses")]
mod electron_fuses;
#[cfg(feature = "javascript-recovery")]
mod javascript_recovery;
#[cfg(feature = "javascript-runtime")]
mod javascript_runtime;
#[cfg(feature = "network-capture")]
mod network_capture;
mod static_traces;
#[cfg(feature = "web-scripts")]
mod web_scripts;
/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    static_traces::register(registry);
    network_capture::register(registry);
    web_scripts::register(registry);
    comparisons::register(registry);
    javascript_recovery::register(registry);
    electron_fuses::register(registry);
    #[cfg(feature = "browser")]
    browser::register(registry);
    #[cfg(feature = "browser-scenario")]
    browser_scenario::register(registry);
    #[cfg(feature = "electron")]
    electron::register(registry);
    #[cfg(feature = "javascript-runtime")]
    javascript_runtime::register(registry);
    let _ = registry;
}
