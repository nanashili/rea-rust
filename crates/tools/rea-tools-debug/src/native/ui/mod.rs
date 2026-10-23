//! Native UI observation and scenarios (`observe_native_ui`,
//! `capture_native_ui_scenario`).
use rea_mcp::Registry;
mod budget;
mod exec;
mod provider;
mod runtime;
mod snapshot;
use provider::{Operation, observe_native_ui};
/// Bind this group's tools.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("observe_native_ui", |context, input| {
        observe_native_ui(context, Operation::Observe, input)
    });
    registry.handle("capture_native_ui_scenario", |context, input| {
        observe_native_ui(context, Operation::Scenario, input)
    });
}
