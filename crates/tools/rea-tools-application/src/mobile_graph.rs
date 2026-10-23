//! Execution-free mobile application inventory projection tools.
//!
//! Compatibility owner:
//! `src/server/registerApplicationTools/projectMobileApplicationGraph.ts`.
use crate::projection::{InventoryProjection, project_inventory_evidence};
use crate::{android, apple, harmony, support};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::Value;

pub fn register(registry: &mut Registry) {
    registry.handle(android::OPERATION, |context, input| {
        handle(context, &input, &android::PROJECTION)
    });
    registry.handle(apple::OPERATION, |context, input| {
        handle(context, &input, &apple::PROJECTION)
    });
    registry.handle(harmony::OPERATION, |context, input| {
        handle(context, &input, &harmony::PROJECTION)
    });
}

/// Project, then record the caller's inventory sources before delivering
/// (and retaining) the derived Evidence.
fn handle(
    context: &ToolContext<'_>,
    input: &Value,
    projection: &InventoryProjection,
) -> ToolOutput {
    let evidence = project_inventory_evidence(projection, input);
    support::deliver(
        context.session,
        &inventory_evidence_sources(input),
        evidence,
    )
}

/// `inventoryEvidenceSources`: the caller-supplied inventory pages, in order.
fn inventory_evidence_sources(input: &Value) -> Vec<Value> {
    input
        .get("inventory_evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
