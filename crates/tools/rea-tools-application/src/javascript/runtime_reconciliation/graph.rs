//! `buildReconciledApplicationGraph` (`javascriptRuntimeReconciliationGraph.ts`).
//!
//! The projection never omits entities, items or observations, so
//! `outputTruncated` is always false and `omittedGraphItems` is zero.
use super::captures::Capture;
use super::layers::Layer;
use super::runtime::RuntimeProjection;
use super::{Defect, jag, str_of};
use serde_json::{Value, json};
use std::collections::HashSet;

pub fn build_reconciled_application_graph(
    layers: &[Layer],
    captures: &[Capture],
    runtime: &RuntimeProjection,
    reconciliation_edges: &[Value],
) -> Result<Value, Defect> {
    let all_nodes: Vec<&Value> = layers
        .iter()
        .flat_map(|layer| layer.nodes().iter())
        .chain(runtime.entities.iter().map(|entity| &entity.node))
        .collect();
    let nodes = merge_nodes(&all_nodes)?;
    let all_edges: Vec<&Value> = layers
        .iter()
        .flat_map(|layer| layer.edges().iter())
        .chain(runtime.edges.iter())
        .chain(reconciliation_edges.iter())
        .collect();
    let edges = unique_edges(&all_edges);
    let node_ids: HashSet<&str> = nodes.iter().map(|node| str_of(&node["node_id"])).collect();
    let edges: Vec<Value> = edges
        .into_iter()
        .filter(|edge| {
            node_ids.contains(str_of(&edge["source_node_id"]))
                && node_ids.contains(str_of(&edge["target_node_id"]))
        })
        .collect();
    let roots = preferred_root_ids(layers, runtime);

    let capture_truncated = captures.iter().any(Capture::condition_truncated);
    let capture_unknown_omissions = captures.iter().any(Capture::has_unavailable_sections);
    let input_truncated = layers
        .iter()
        .any(|layer| layer.graph()["coverage"]["truncated"] == true)
        || capture_truncated;
    let input_complete = layers
        .iter()
        .all(|layer| layer.graph()["coverage"]["status"] == "complete")
        && captures.iter().all(Capture::complete_within_window);
    let source_omissions: u64 = layers
        .iter()
        .map(|layer| {
            layer.graph()["coverage"]["omitted_count"]
                .as_u64()
                .unwrap_or(0)
        })
        .sum();
    let omissions_known = !capture_truncated
        && !capture_unknown_omissions
        && layers
            .iter()
            .all(|layer| !layer.graph()["coverage"]["omitted_count"].is_null());
    let input_status = if input_truncated {
        "truncated"
    } else if input_complete {
        "complete"
    } else {
        "partial"
    };
    let omitted = if omissions_known {
        json!(source_omissions)
    } else {
        Value::Null
    };
    let coverage = match input_status {
        "complete" => {
            json!({ "status": "complete", "truncated": false, "omitted_count": 0, "limits": [] })
        }
        "truncated" => json!({
            "status": "partial",
            "truncated": true,
            "omitted_count": omitted,
            "limits": [{
                "name": "runtime-reconciliation-input-coverage",
                "value": layers.len() + captures.len(),
                "unit": "items",
            }],
        }),
        _ => {
            json!({ "status": "partial", "truncated": false, "omitted_count": omitted, "limits": [] })
        }
    };
    let mut limitations: Vec<String> = layers
        .iter()
        .flat_map(|layer| {
            layer.graph()["limitations"]
                .as_array()
                .into_iter()
                .flatten()
        })
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    limitations.extend(
        [
            "Runtime presence is bounded to passive capture windows and does not prove feature execution.",
            "Cross-layer observed_as edges are inferences; digest equality proves byte identity only.",
            "Source-map relationships retain their original static authority and are not promoted into runtime matches.",
        ]
        .map(str::to_owned),
    );
    if input_status == "truncated" {
        limitations.push(
            "One or more source graphs or passive captures were incomplete or truncated.".into(),
        );
    }
    jag::create_graph(roots, nodes, edges, coverage, limitations)
}

fn preferred_root_ids(layers: &[Layer], runtime: &RuntimeProjection) -> Vec<String> {
    let roots = |application: bool| {
        layers
            .iter()
            .filter(move |layer| (layer.role == "application") == application)
            .flat_map(|layer| {
                layer.graph()["root_node_ids"]
                    .as_array()
                    .into_iter()
                    .flatten()
            })
            .filter_map(Value::as_str)
            .map(str::to_owned)
    };
    runtime
        .target_nodes
        .iter()
        .map(|(_, node)| node.clone())
        .chain(roots(true))
        .chain(roots(false))
        .collect()
}

/// `mergeNodes`.
fn merge_nodes(nodes: &[&Value]) -> Result<Vec<Value>, Defect> {
    let mut groups: Vec<(&str, Vec<&Value>)> = Vec::new();
    let mut positions: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for node in nodes {
        let id = str_of(&node["node_id"]);
        match positions.get(id) {
            Some(position) => groups[*position].1.push(*node),
            None => {
                positions.insert(id, groups.len());
                groups.push((id, vec![*node]));
            }
        }
    }
    groups
        .into_iter()
        .map(|(_, group)| {
            let first = group[0];
            if group
                .iter()
                .any(|node| node["kind"] != first["kind"] || node["identity"] != first["identity"])
            {
                return Err(Defect);
            }
            let mut observations: Vec<(String, Value)> = Vec::new();
            for observation in group
                .iter()
                .flat_map(|node| node["observations"].as_array().into_iter().flatten())
            {
                let id = str_of(&observation["observation_id"]).to_owned();
                match observations
                    .iter_mut()
                    .find(|(existing, _)| *existing == id)
                {
                    Some((_, value)) => *value = observation.clone(),
                    None => observations.push((id, observation.clone())),
                }
            }
            observations.sort_by(|left, right| left.0.cmp(&right.0));
            let stripped: Vec<Value> = observations
                .into_iter()
                .map(|(_, mut observation)| {
                    if let Some(object) = observation.as_object_mut() {
                        object.remove("observation_id");
                        object.remove("identifier_strategy");
                    }
                    observation
                })
                .collect();
            jag::create_node(str_of(&first["kind"]), &first["identity"], &stripped)
        })
        .collect()
}

/// `uniqueEdges`: last edge per identifier, at its first position.
fn unique_edges(edges: &[&Value]) -> Vec<Value> {
    let mut unique: Vec<Value> = Vec::new();
    let mut positions = std::collections::HashMap::new();
    for edge in edges {
        let id = str_of(&edge["edge_id"]).to_owned();
        match positions.get(&id) {
            Some(position) => unique[*position] = (*edge).clone(),
            None => {
                positions.insert(id, unique.len());
                unique.push((*edge).clone());
            }
        }
    }
    unique
}
