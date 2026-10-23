//! Views over retained `inspect_artifact` and `inventory_artifact` Evidence.
//!
//! Compatibility owners: `src/domain/analysisView/artifactInventoryView.ts`,
//! `src/domain/artifactInventoryEvidence.ts`, `src/domain/artifactInspection.ts`
//! and the shared inventory graph schemas in `src/domain/artifactGraph.ts`.
mod inventory;

use crate::common::json::{self, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use inventory::{InventorySource, SourceFault};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

/// `projectArtifactInventoryView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let operation = parent.operation;
    if operation != "inventory_artifact" && operation != "inspect_artifact" {
        return Err(source_error(
            "Inventory views require inventory_artifact or inspect_artifact Evidence.",
        ));
    }
    let kind = view_kind(view);
    if kind != "summary" && kind != "inventory" {
        return Err(source_error(
            "Artifact Evidence supports summary and inventory views.",
        ));
    }

    let source = parse_source(parent)?;
    let InventorySource {
        inventory,
        evidence_ids,
        inspection,
    } = &*source;

    let inspection_limitations = inspection
        .as_ref()
        .map(|value| json::strings(value.get("limitations").unwrap_or(&Value::Null)))
        .unwrap_or_default();
    let limitations = unique_sorted(
        parent
            .limitations
            .iter()
            .cloned()
            .chain(json::strings(
                inventory.get("limitations").unwrap_or(&Value::Null),
            ))
            .chain(inspection_limitations),
    );

    let manifest = inventory.get("manifest").cloned().unwrap_or(Value::Null);
    let root_sha256 = manifest.get("root_sha256").cloned().unwrap_or(Value::Null);
    let complete = inventory
        .get("complete")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let artifact_path = parent
        .artifact()
        .map(|(path, _)| path.to_owned())
        .unwrap_or_default();

    let mut unknowns = vec![
        "Inventory does not establish application runtime behavior or complete format-specific analysis.".to_owned(),
    ];
    if !complete {
        unknowns.push(
            "Parent inventory is partial; counts and exhausted pages cover only available records. Missing matches do not establish absence.".to_owned(),
        );
    }

    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!(operation)),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({ "path": artifact_path, "sha256": root_sha256 }),
        ),
        ("limitations", json!(limitations)),
        ("unknowns", json!(unknowns)),
    ];

    let nodes = json::array_at(inventory, "nodes");
    let occurrences = json::array_at(inventory, "occurrences");
    let edges = json::array_at(inventory, "edges");
    let contradictions = json::array_at(inventory, "integrity_contradictions");

    if kind == "summary" {
        let mut counts = Map::new();
        for entry_kind in ["file", "directory", "symlink", "slice"] {
            counts.insert(entry_kind.into(), json!(0));
        }
        for occurrence in occurrences {
            if let Some(entry_kind) = occurrence.get("entry_kind").and_then(Value::as_str) {
                let current = counts.get(entry_kind).and_then(Value::as_u64).unwrap_or(0);
                counts.insert(entry_kind.into(), json!(current + 1));
            }
        }
        let examined = nodes.len() + occurrences.len() + edges.len();
        let inspection_value = match inspection {
            None => Value::Null,
            Some(value) => json!({
                "coverage": value.get("coverage").cloned().unwrap_or(Value::Null),
                "unexplored_branches": value.get("unexplored_branches").cloned().unwrap_or(Value::Null),
            }),
        };
        let summary = json!({
            "manifest": manifest,
            "available_counts": {
                "nodes": nodes.len(),
                "occurrences": occurrences.len(),
                "edges": edges.len(),
                "integrity_contradictions": contradictions.len(),
            },
            "observed_entry_kind_counts": Value::Object(counts),
            "source_complete": complete,
            "inventory_evidence_ids": evidence_ids.clone(),
            "inspection": inspection_value,
            "limitation_count": limitations.len(),
        });
        let mut out = Map::new();
        out.insert("kind".into(), json!("summary"));
        out.insert("view".into(), view.clone());
        out.insert("summary".into(), summary);
        out.insert("coverage".into(), complete_within_view(examined, examined));
        for (key, value) in shared {
            out.insert(key.into(), value);
        }
        return Ok(Value::Object(out));
    }

    // inventory page view.
    let collection = json::str_at(view, "collection").unwrap_or_default();
    let rows: Vec<Value> = match collection {
        "occurrences" => {
            // `view.logical_paths` filters occurrences when present.
            if let Some(paths) = view
                .get("logical_paths")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<std::collections::BTreeSet<_>>()
                })
            {
                occurrences
                    .iter()
                    .filter(|row| {
                        row.get("logical_path")
                            .and_then(Value::as_str)
                            .is_some_and(|path| paths.contains(path))
                    })
                    .cloned()
                    .collect()
            } else {
                occurrences.to_vec()
            }
        }
        "nodes" => nodes.to_vec(),
        "edges" => edges.to_vec(),
        // integrity_contradictions
        _ => contradictions.to_vec(),
    };
    let (offset, limit) = offset_limit(view);
    let items = page(&rows, offset, limit);
    let examined = items.len();

    let mut out = Map::new();
    out.insert("kind".into(), json!("inventory"));
    out.insert("view".into(), view.clone());
    out.insert("manifest".into(), manifest);
    out.insert("inventory_evidence_ids".into(), json!(evidence_ids.clone()));
    out.insert("source_complete".into(), json!(complete));
    out.insert("items".into(), Value::Array(items));
    out.insert(
        "coverage".into(),
        page_coverage(offset, examined, rows.len()),
    );
    for (key, value) in shared {
        out.insert(key.into(), value);
    }
    Ok(Value::Object(out))
}

/// `inputError`: one `["source"]` invalid_value issue.
fn source_error(message: impl Into<String>) -> AnalysisError {
    view_error(&["source"], "invalid_value", message)
}

/// `parseSource`: reuse the owning inventory parser for both carriers, caching
/// the validated facts of an immutable (sealed) parent.
fn parse_source(parent: &Parent<'_>) -> Result<std::sync::Arc<InventorySource>, AnalysisError> {
    parent.cached("artifact_inventory_source", || {
        inventory::parse_source(parent).map_err(|fault| match fault {
            // `parseSource` wraps a TypeError/ZodError message into a
            // `["source"]` invalid_value issue; other errors propagate verbatim.
            SourceFault::Input(message) => source_error(message),
            SourceFault::Fatal(error) => error,
        })
    })
}
