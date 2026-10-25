//! JavaScript Application Graph workflows over authenticated Evidence.
//!
//! Compatibility owners: `src/server/registerApplicationTools/*.ts` and
//! `src/application/javascript/JavaScriptApplicationWorkflowService.ts`.
mod comparisons;
mod export_shapes;
mod feature_trace;
mod graph_evidence;
mod js;
mod reconstruction;
pub mod reconstruction_evidence;
mod runtime_reconciliation;
mod semantic_trace;
mod workflow_evidence;

use rea_mcp::Registry;

pub fn register(registry: &mut Registry) {
    reconstruction::register(registry);
    comparisons::register(registry);
    semantic_trace::register(registry);
    feature_trace::register(registry);
    export_shapes::register(registry);
    runtime_reconciliation::register(registry);
}
