//! macOS native observation tools (`native-macos` provider): native UI
//! observation and scenarios (`ui`) and LLDB call observation (`calls`).
use rea_mcp::Registry;

mod calls;
mod ui;

/// Bind the native observation tools.
pub(crate) fn register(registry: &mut Registry) {
    calls::register(registry);
    ui::register(registry);
}
