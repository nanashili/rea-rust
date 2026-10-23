//! `createJavaScriptRuntimeReconciliationResult`
//! (`javascriptRuntimeReconciliationResult.ts`). Nothing is omitted during
//! projection, so every omission count is zero and `outputTruncated` false.
use super::captures::Capture;
use super::layers::Layer;
use super::matching::MatchingProjection;
use super::runtime::RuntimeProjection;
use super::{Defect, digest, str_of};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

fn count(items: &[Value], key: &str, value: &str) -> usize {
    items.iter().filter(|item| item[key] == value).count()
}

pub fn create_result(
    layers: &[Layer],
    captures: &[Capture],
    runtime: &RuntimeProjection,
    matching: &MatchingProjection,
    load_states: &[Value],
    graph: Value,
) -> Result<Value, Defect> {
    let input_truncated = layers
        .iter()
        .any(|layer| layer.graph()["coverage"]["truncated"] == true)
        || captures.iter().any(Capture::condition_truncated);
    let input_partial = layers
        .iter()
        .any(|layer| layer.graph()["coverage"]["status"] != "complete")
        || captures
            .iter()
            .any(|capture| !capture.complete_within_window());
    let input_status = if input_truncated {
        "truncated"
    } else if input_partial {
        "partial"
    } else {
        "complete"
    };
    let static_layers: Vec<Value> = layers
        .iter()
        .map(|layer| {
            let result = layer.result();
            json!({
                "layer_id": layer.layer_id,
                "role": layer.role,
                "evidence_id": layer.evidence_id(),
                "graph_id": layer.graph()["graph_id"],
                "root_artifact_sha256": result["root_artifact_sha256"],
                "input_path": result["input_path"],
                "format": result["format"],
                "runtime_mappings": layer.runtime_mappings,
            })
        })
        .collect();
    let runtime_captures = captures
        .iter()
        .map(|capture| {
            let target_node = runtime.target_node(capture.evidence_id()).ok_or(Defect)?;
            let target = &capture.inspection.target;
            let location = if let Some(unresolved) = target.get("unresolved_location") {
                unresolved.clone()
            } else if let Some(url) = target.get("url") {
                url.clone()
            } else {
                target["file_path"].clone()
            };
            Ok(json!({
                "evidence_id": capture.evidence_id(),
                "capture_sha256": capture.capture_sha256,
                "kind": capture.kind,
                "target_node_id": target_node,
                "target_key": capture.target_id(),
                "target_location": location,
                "frames": capture.inspection.frames.len(),
                "scripts": capture.inspection.scripts.len(),
                "workers": capture.inspection.workers.len(),
                "scripts_complete_within_scope": capture.scripts_complete_within_scope,
            }))
        })
        .collect::<Result<Vec<_>, Defect>>()?;
    let entity_count = |kind: &str| {
        runtime
            .entities
            .iter()
            .filter(|entity| entity.kind == kind)
            .count()
    };
    let summary = json!({
        "runtime_targets": entity_count("target"),
        "runtime_frames": entity_count("frame"),
        "runtime_scripts": entity_count("script"),
        "runtime_workers": entity_count("worker"),
        "matched": count(&matching.items, "status", "matched"),
        "ambiguous": count(&matching.items, "status", "ambiguous"),
        "unmatched": count(&matching.items, "status", "unmatched"),
        "unknown": count(&matching.items, "status", "unknown"),
        "static_loaded": count(load_states, "status", "loaded"),
        "static_resident": count(load_states, "status", "resident-in-loaded-asset"),
        "static_not_observed": count(load_states, "status", "not-observed-in-capture"),
        "static_unknown": count(load_states, "status", "unknown"),
    });
    let declarations: usize = captures
        .iter()
        .filter(|capture| capture.kind == "browser")
        .map(|capture| {
            capture
                .inspection
                .scripts
                .iter()
                .filter(|script| !script.get("source_map_url").is_some_and(Value::is_null))
                .count()
        })
        .sum();
    let truncated = input_status == "truncated";
    let coverage = json!({
        "status": if truncated {
            "truncated"
        } else if input_status == "partial" {
            "partial"
        } else {
            "complete-within-inputs"
        },
        "truncated": truncated,
        "omitted_runtime_entities": 0,
        "omitted_reconciliation_items": 0,
        "omitted_static_load_states": 0,
        "omitted_graph_items": 0,
    });
    let links: BTreeSet<&str> = layers
        .iter()
        .map(Layer::evidence_id)
        .chain(captures.iter().map(Capture::evidence_id))
        .collect();
    let mut limitations: BTreeSet<&str> = [
        "Only caller-supplied, semantically verified Evidence records were reconciled.",
        "Digest equality establishes byte identity but not code reachability, module initialization, or feature execution.",
        "A static module resident in an observed bundle is not reported as executed.",
        "Not-observed means absent from the bounded captures in scope, never globally unloaded.",
        "Caller-declared file and URL mappings are inference inputs and do not expand CDP origin or filesystem-root authority.",
        "Source-map authority remains separate from passive runtime authority.",
    ]
    .into();
    if input_status != "complete" {
        limitations.insert("One or more static graphs or passive captures were incomplete.");
    }
    let semantic = json!({
        "static_layers": static_layers,
        "runtime_captures": runtime_captures,
        "graph": graph,
        "summary": summary,
        "reconciliations": matching.items,
        "static_load_states": load_states,
        "source_map_authority": {
            "used_for_primary_matching": false,
            "static_layer_count": layers.len(),
            "runtime_script_declarations": declarations,
            "limitation": "Source-map declarations and original-source content retain separate static authority and are not used as primary runtime byte matches.",
        },
        "coverage": coverage,
        "evidence_links": links,
        "limitations": limitations,
    });
    if links.len() < 2 || str_of(&semantic["graph"]["graph_id"]).is_empty() {
        return Err(Defect);
    }
    let id = format!("jrr_{}", digest(&semantic)?);
    let mut result = Map::new();
    result.insert("reconciliation_id".into(), json!(id));
    if let Value::Object(fields) = semantic {
        result.extend(fields);
    }
    Ok(Value::Object(result))
}
