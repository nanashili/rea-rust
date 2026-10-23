//! Shared coverage and message-budget helpers for retained analysis views.
//!
//! These helpers keep the representation of paging coverage and bounded
//! diagnostic fields consistent across view projections.  They do not inspect
//! or reinterpret a parent Evidence record.

use serde_json::{Value, json};
use std::collections::BTreeSet;

/// Maximum repeated serialized message budget for one analysis-view field.
pub const ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT: usize = 256 * 1024;

/// Coverage for a summary, facet, or single selected object.
pub fn complete_within_view_coverage(examined: usize, total: usize) -> Value {
    json!({
        "status": "complete-within-view",
        "examined": examined,
        "total": total,
        "next_offset": Value::Null,
        "exhausted": true,
    })
}

/// Coverage for a stable page, including an offset past the collection.
pub fn page_view_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    let next_offset = if exhausted {
        Value::Null
    } else {
        json!(offset + examined)
    };

    json!({
        "status": if examined == 0 { "empty" } else { "page" },
        "examined": examined,
        "total": total,
        "next_offset": next_offset,
        "exhausted": exhausted,
    })
}

/// Deduplicate and bound repeated view messages by their serialized size.
pub fn bounded_view_messages(
    values: &[String],
    parent_evidence_id: &str,
    field: &str,
    required: &[String],
) -> Vec<String> {
    let priority = unique_sorted(required);

    let mut all_values = priority.clone();
    all_values.extend(values.iter().cloned());
    let unique = unique_sorted(&all_values);

    let notice = |omitted: usize| {
        format!(
            "{omitted} additional {field} omitted from this view; consult source parent Evidence {parent_evidence_id} for the complete list (the caller-supplied record, or its retaining session)."
        )
    };

    let total_bytes = unique
        .iter()
        .map(|value| message_wire_bytes(value))
        .sum::<usize>();
    if total_bytes <= ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT {
        return unique;
    }

    // Reserve notice space only after proving the complete source set does not fit.
    let initial_notice = notice(unique.len());
    let mut remaining = ANALYSIS_VIEW_MESSAGE_BYTE_LIMIT
        .saturating_sub(message_wire_bytes(&initial_notice));
    let mut retained = BTreeSet::new();

    for value in priority.iter().chain(unique.iter()) {
        if retained.contains(value) {
            continue;
        }

        let bytes = message_wire_bytes(value);
        if bytes > remaining {
            continue;
        }

        retained.insert(value.clone());
        remaining -= bytes;
    }

    let omitted = unique.len().saturating_sub(retained.len());
    if omitted == 0 {
        return unique;
    }

    let mut bounded = retained.into_iter().collect::<Vec<_>>();
    bounded.push(notice(omitted));
    bounded
}

/// Approximate the repeated JSON/MCP wire cost without allocating copies.
fn message_wire_bytes(value: &str) -> usize {
    value
        .encode_utf16()
        .count()
        .saturating_mul(18)
        .saturating_add(6)
        .saturating_mul(3)
}

fn unique_sorted(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}
