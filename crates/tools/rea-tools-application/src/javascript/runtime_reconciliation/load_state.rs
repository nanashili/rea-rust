//! `classifyStaticLoadStates` (`javascriptRuntimeLoadState.ts`).
//!
//! Runtime entities and reconciliation items are never omitted, so
//! `reconciliationComplete` is always true and no state is omitted.
use super::candidates::{
    create_static_runtime_scope, mapped_runtime_paths, static_node_within_runtime_scope,
};
use super::captures::Capture;
use super::layers::Layer;
use super::runtime::Entity;
use super::str_of;
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};

pub fn classify_static_load_states(
    layers: &[Layer],
    captures: &[Capture],
    entities: &[Entity],
    matches: &[Value],
) -> Vec<Value> {
    layers
        .iter()
        .flat_map(|layer| classify_layer(layer, captures, entities, matches))
        .collect()
}

fn classify_layer(
    layer: &Layer,
    captures: &[Capture],
    entities: &[Entity],
    matches: &[Value],
) -> Vec<Value> {
    let mut direct: Vec<(String, Vec<String>)> = Vec::new();
    let mut ambiguous = HashSet::new();
    let mut incomplete = HashSet::new();
    for item in matches {
        let status = str_of(&item["status"]);
        if status == "matched"
            && item["static_layer_id"] == layer.layer_id.as_str()
            && item["static_node_id"].is_string()
        {
            let node = str_of(&item["static_node_id"]).to_owned();
            let runtime = str_of(&item["runtime_node_id"]).to_owned();
            match direct.iter_mut().find(|(id, _)| *id == node) {
                Some((_, values)) => values.push(runtime),
                None => direct.push((node, vec![runtime])),
            }
        } else if status == "ambiguous" || status == "unknown" {
            let uncertain = if status == "ambiguous" {
                &mut ambiguous
            } else {
                &mut incomplete
            };
            for candidate in item["candidate_static_nodes"]
                .as_array()
                .into_iter()
                .flatten()
            {
                if candidate["static_layer_id"] == layer.layer_id.as_str() {
                    uncertain.insert(str_of(&candidate["static_node_id"]).to_owned());
                }
            }
        }
    }
    let resident = resident_nodes(layer, &direct);
    let scope = create_static_runtime_scope(layer, entities);
    let scoped: Vec<&Entity> = entities
        .iter()
        .filter(|entity| !mapped_runtime_paths(layer, entity).is_empty())
        .collect();
    let layer_complete = layer.graph()["coverage"]["status"] == "complete"
        && !scoped.is_empty()
        && scoped
            .iter()
            .all(|entity| captures[entity.capture].scripts_complete_within_scope);
    layer
        .nodes()
        .iter()
        .filter(|node| {
            matches!(
                node["kind"].as_str(),
                Some("javascript-asset" | "javascript-chunk" | "javascript-module")
            )
        })
        .map(|node| {
            let id = str_of(&node["node_id"]);
            let runtime: BTreeSet<&str> = direct
                .iter()
                .find(|(node_id, _)| node_id == id)
                .into_iter()
                .flat_map(|(_, values)| values.iter().map(String::as_str))
                .collect();
            let (status, reason): (&str, &str) = if !runtime.is_empty() {
                ("loaded", "runtime-script-correspondence")
            } else if resident.contains(id) {
                ("resident-in-loaded-asset", "containing-asset-was-loaded")
            } else if incomplete.contains(id) {
                ("unknown", "static-or-runtime-coverage-incomplete")
            } else if ambiguous.contains(id) {
                ("unknown", "ambiguous-runtime-candidate")
            } else {
                let within = static_node_within_runtime_scope(node, &scope);
                if layer_complete && within {
                    ("not-observed-in-capture", "not-observed-in-bounded-capture")
                } else if !within {
                    ("unknown", "layer-outside-runtime-scope")
                } else {
                    ("unknown", "static-or-runtime-coverage-incomplete")
                }
            };
            json!({
                "static_layer_id": layer.layer_id,
                "static_node_id": id,
                "kind": node["kind"],
                "status": status,
                "runtime_node_ids": runtime,
                "reason": reason,
            })
        })
        .collect()
}

/// `residentNodes`.
fn resident_nodes(layer: &Layer, direct: &[(String, Vec<String>)]) -> HashSet<String> {
    let kinds: HashMap<&str, &str> = layer
        .nodes()
        .iter()
        .map(|node| (str_of(&node["node_id"]), str_of(&node["kind"])))
        .collect();
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for edge in layer.edges() {
        if edge["relation"] == "contains" {
            children
                .entry(str_of(&edge["source_node_id"]))
                .or_default()
                .push(str_of(&edge["target_node_id"]));
        }
    }
    let mut pending: Vec<String> = direct
        .iter()
        .map(|(id, _)| id.clone())
        .filter(|id| kinds.get(id.as_str()) == Some(&"javascript-asset"))
        .collect();
    let mut resident = HashSet::new();
    let mut index = 0;
    while index < pending.len() {
        let current = pending[index].clone();
        index += 1;
        for child in children.get(current.as_str()).into_iter().flatten() {
            if resident.insert((*child).to_owned()) {
                pending.push((*child).to_owned());
            }
        }
    }
    resident
}
