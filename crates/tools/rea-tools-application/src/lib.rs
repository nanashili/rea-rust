//! JavaScript application analysis and application workflows.
//!
//! Compatibility owner: `src/server/registerApplicationTools.ts` and
//! `src/server/registerApplicationTools/**`.
mod bundle;
mod coverage;
mod javascript;
mod ledger;
mod ledger_sources;
mod mobile_graph;
mod rejection;
mod sdk_input;
mod support;

use rea_mcp::Registry;

/// Bind every tool owned by this family to its exact catalog contract.
pub fn register(registry: &mut Registry) {
    mobile_graph::register(registry);
    coverage::register(registry);
    ledger::register(registry);
    javascript::register(registry);
}
