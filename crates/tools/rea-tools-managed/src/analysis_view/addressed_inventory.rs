//! Stable pages of retained native `list_procedures` / `list_strings` rows.
//!
//! Compatibility owner: `src/domain/analysisView/addressedInventoryView.ts`.
//! The parent inventory is the complete provider result; paging slices it in
//! original order and never reruns provider analysis.
use crate::common::view::{Parent, offset_limit, page, page_coverage, view_error};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

/// One inventory operation and the page collection it owns.
#[derive(Clone, Copy)]
pub(super) struct Inventory {
    pub operation: &'static str,
    pub collection: &'static str,
}

pub(super) const PROCEDURES: Inventory = Inventory {
    operation: "list_procedures",
    collection: "procedures",
};

pub(super) const STRINGS: Inventory = Inventory {
    operation: "list_strings",
    collection: "strings",
};

/// `isAddressedInventoryItem`: rows keep provider metadata beside the
/// required `address`/`value` strings.
fn is_addressed_item(value: &Value) -> bool {
    value.get("address").is_some_and(Value::is_string)
        && value.get("value").is_some_and(Value::is_string)
}

/// `getAddressedInventoryRows`: sealed parents are validated once per cache
/// lifetime; inline parents are validated on every request.
fn addressed_rows<'a>(parent: &Parent<'a>) -> Result<Option<&'a [Value]>, AnalysisError> {
    let Some(rows) = parent.normalized_result.as_array() else {
        return Ok(None);
    };
    let valid = parent.cached("addressed_inventory_rows", || {
        Ok(rows.iter().all(is_addressed_item))
    })?;
    Ok(valid.then_some(rows.as_slice()))
}

/// `projectAddressedInventoryView`.
pub(super) fn project(
    parent: &Parent<'_>,
    view: &Value,
    inventory: Inventory,
) -> Result<Value, AnalysisError> {
    let kind = view.get("kind").and_then(Value::as_str);
    let collection = view.get("collection").and_then(Value::as_str);
    if kind != Some("page") || collection != Some(inventory.collection) {
        return Err(view_error(
            &["view"],
            "invalid_value",
            format!(
                "{} Evidence supports stable pages of the {} collection.",
                inventory.operation, inventory.collection
            ),
        ));
    }
    let Some(rows) = addressed_rows(parent)? else {
        return Err(view_error(
            &["view"],
            "invalid_value",
            format!(
                "Parent Evidence result does not match the {} address/value inventory.",
                inventory.operation
            ),
        ));
    };
    let Some((path, sha256)) = parent.artifact() else {
        return Err(view_error(
            &["view"],
            "invalid_value",
            format!(
                "Parent {} Evidence has no authenticated artifact identity.",
                inventory.operation
            ),
        ));
    };
    let (offset, limit) = offset_limit(view);
    let items = page(rows, offset, limit);
    let examined = items.len();
    Ok(json!({
        "kind": "page",
        "view": view,
        "items": items,
        "parent_evidence_id": parent.evidence_id,
        "parent_operation": inventory.operation,
        "parent_digest": parent.digest(),
        "artifact": { "path": path, "sha256": sha256 },
        "coverage": page_coverage(offset, examined, rows.len()),
        "limitations": parent.limitations,
        "unknowns": [],
    }))
}
