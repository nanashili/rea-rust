//! Merge source graphs and project inferred cross-version relationships.

use super::{
    graph::{ApplicationGraph, ApplicationNode},
    items::ClassifiedItem,
};
use rea_core::canonical_json;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn build(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    left_evidence_id: &str,
    right_evidence_id: &str,
    items: &[ClassifiedItem],
) -> Result<Value, super::Failure> {
    let nodes = merge_compared_nodes(left, right, items);
    let retained_node_ids = nodes
        .iter()
        .filter_map(|node| {
            node.get("node_id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>();
    let mut edges = retained_source_edges(left, right, &retained_node_ids);
    let node_by_id = merge_node_facts(left, right);

    for item in items {
        if let Some(edge) = changed_from_edge(
            item,
            left,
            right,
            left_evidence_id,
            right_evidence_id,
            &retained_node_ids,
            &node_by_id,
        )? {
            edges.push(edge);
        }
    }
    edges = unique_edges(edges);

    let roots = preferred_roots(left, right, &retained_node_ids);
    let roots = if roots.is_empty() {
        nodes
            .first()
            .and_then(|node| node.get("node_id"))
            .and_then(Value::as_str)
            .map(|node_id| vec![node_id.to_owned()])
            .unwrap_or_default()
    } else {
        roots
    };

    let mut graph = Map::new();
    graph.insert("schema".into(), json!("JavaScriptApplicationGraph"));
    graph.insert("root_node_ids".into(), json!(roots));
    graph.insert("nodes".into(), json!(nodes));
    graph.insert("edges".into(), json!(edges));
    graph.insert("coverage".into(), change_graph_coverage(left, right)?);
    graph.insert(
        "limitations".into(),
        json!(change_graph_limitations(left, right)),
    );

    let graph_id = committed_id("jag_", &Value::Object(graph.clone()), "graph")?;
    graph.insert("graph_id".into(), json!(graph_id));
    let graph = Value::Object(graph);
    super::graph::validate_graph(&graph, "change_graph")?;
    Ok(graph)
}

fn merge_compared_nodes(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    items: &[ClassifiedItem],
) -> Vec<Value> {
    let required = required_node_ids(left, right, items);
    let mut by_node_id = BTreeMap::<String, Vec<&ApplicationNode>>::new();

    for node in left.nodes.iter().chain(&right.nodes) {
        if required.contains(&node.node_id) {
            by_node_id
                .entry(node.node_id.clone())
                .or_default()
                .push(node);
        }
    }

    by_node_id
        .into_iter()
        .map(|(node_id, group)| merge_node(&node_id, &group))
        .collect()
}

fn merge_node(node_id: &str, group: &[&ApplicationNode]) -> Value {
    let first = group[0];
    let mut observations_by_id = BTreeMap::<String, Value>::new();
    for observation in group.iter().flat_map(|node| &node.observations) {
        observations_by_id
            .entry(observation.observation_id.clone())
            .or_insert_with(|| observation.raw.clone());
    }
    json!({
        "node_id": node_id,
        "kind": first.kind,
        "identity": first.identity,
        "observations": observations_by_id.into_values().collect::<Vec<_>>(),
    })
}

fn required_node_ids(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    items: &[ClassifiedItem],
) -> BTreeSet<String> {
    left.root_node_ids
        .iter()
        .chain(&right.root_node_ids)
        .cloned()
        .chain(items.iter().flat_map(|item| {
            item.left_node_id
                .iter()
                .chain(item.right_node_id.iter())
                .cloned()
        }))
        .collect()
}

fn merge_node_facts<'a>(
    left: &'a ApplicationGraph,
    right: &'a ApplicationGraph,
) -> BTreeMap<String, &'a ApplicationNode> {
    left.nodes
        .iter()
        .chain(&right.nodes)
        .map(|node| (node.node_id.clone(), node))
        .collect()
}

fn retained_source_edges(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    retained: &BTreeSet<String>,
) -> Vec<Value> {
    let mut by_id = BTreeMap::<String, Value>::new();
    for edge in left.edges.iter().chain(&right.edges) {
        if retained.contains(&edge.source_node_id) && retained.contains(&edge.target_node_id) {
            by_id
                .entry(edge.edge_id.clone())
                .or_insert_with(|| edge.raw.clone());
        }
    }
    by_id.into_values().collect()
}

fn changed_from_edge(
    item: &ClassifiedItem,
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    left_evidence_id: &str,
    right_evidence_id: &str,
    retained: &BTreeSet<String>,
    nodes: &BTreeMap<String, &ApplicationNode>,
) -> Result<Option<Value>, super::Failure> {
    if !is_meaningful_change(item) {
        return Ok(None);
    }
    let (Some(left_node_id), Some(right_node_id)) =
        (item.left_node_id.as_deref(), item.right_node_id.as_deref())
    else {
        return Ok(None);
    };
    if left_node_id == right_node_id
        || !retained.contains(left_node_id)
        || !retained.contains(right_node_id)
    {
        return Ok(None);
    }

    let source_observation = nodes
        .get(right_node_id)
        .or_else(|| nodes.get(left_node_id))
        .and_then(|node| node.observations.first());
    let complete = left.coverage.status == "complete" && right.coverage.status == "complete";
    let evidence = comparison_evidence(
        item,
        source_observation.map(|observation| &observation.evidence),
        left,
        right,
        left_evidence_id,
        right_evidence_id,
        complete,
    )?;
    let properties = json!({
        "comparison_item_id": item.item_id,
        "status": item.status,
        "match_basis": item.match_basis,
        "match_confidence": item.match_confidence,
        "dimensions": item.dimensions,
    });
    let semantic = json!({
        "source_node_id": right_node_id,
        "target_node_id": left_node_id,
        "relation": "changed_from",
        "properties": properties,
        "evidence": evidence,
        "identifier_strategy": "relationship-exact",
    });
    let edge_id = committed_id("jag_edge_", &semantic, "changed_from_edge")?;
    let mut edge = semantic
        .as_object()
        .cloned()
        .ok_or_else(|| super::graph::invalid("change_graph", "Edge must be an object"))?;
    edge.insert("edge_id".into(), json!(edge_id));
    Ok(Some(Value::Object(edge)))
}

fn is_meaningful_change(item: &ClassifiedItem) -> bool {
    if item.match_status != "matched" || item.status == "unchanged" {
        return false;
    }
    item.status != "unknown"
        || item
            .dimensions
            .iter()
            .any(|dimension| dimension != "location" && dimension != "coverage")
}

fn comparison_evidence(
    item: &ClassifiedItem,
    source: Option<&Value>,
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    left_evidence_id: &str,
    right_evidence_id: &str,
    complete: bool,
) -> Result<Value, super::Failure> {
    let unavailable_artifact = json!({
        "available": false,
        "reason": "unresolved",
        "detail": "Compared node has no artifact-backed observation.",
    });
    let unavailable_location = json!({
        "available": false,
        "reason": "unresolved",
        "detail": "Compared node has no actionable source location.",
    });
    let mut limitations = vec![
        "Cross-version pairing is inferred from the stated match basis; changed_from does not prove runtime reachability.".to_owned(),
    ];
    limitations.extend(item.limitations.iter().cloned());
    limitations.sort();
    limitations.dedup();

    let evidence_ids = vec![left_evidence_id.to_owned(), right_evidence_id.to_owned()];

    Ok(json!({
        "authority": "cross-version-comparison",
        "state": "inferred",
        "confidence": if item.match_confidence == "medium" { "medium" } else { "high" },
        "artifact": source.and_then(|evidence| evidence.get("artifact")).cloned().unwrap_or(unavailable_artifact),
        "location": source.and_then(|evidence| evidence.get("location")).cloned().unwrap_or(unavailable_location),
        "extractor": {
            "name": "rea-application-version-comparison",
            "version": "1",
            "operation": "compare_application_versions",
            "executable_sha256": null,
        },
        "coverage": change_edge_coverage(left, right, complete)?,
        "limitations": limitations,
        "evidence_ids": evidence_ids,
    }))
}

fn change_edge_coverage(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    complete: bool,
) -> Result<Value, super::Failure> {
    let limits = combined_limits(left, right)?;
    if complete {
        return Ok(json!({
            "status": "complete",
            "truncated": false,
            "omitted_count": 0,
            "limits": limits,
        }));
    }
    Ok(json!({
        "status": "partial",
        "truncated": left.coverage.truncated || right.coverage.truncated,
        "omitted_count": combine_omitted_counts(left.coverage.omitted_count, right.coverage.omitted_count)?,
        "limits": limits,
    }))
}

fn change_graph_coverage(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
) -> Result<Value, super::Failure> {
    let complete = left.coverage.status == "complete" && right.coverage.status == "complete";
    let status = if complete { "complete" } else { "partial" };
    Ok(json!({
        "status": status,
        "truncated": if complete { false } else { left.coverage.truncated || right.coverage.truncated },
        "omitted_count": if complete { Some(0) } else { combine_omitted_counts(left.coverage.omitted_count, right.coverage.omitted_count)? },
        "limits": combined_limits(left, right)?,
    }))
}

fn combined_limits(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
) -> Result<Vec<Value>, super::Failure> {
    let mut by_key = BTreeMap::<String, Value>::new();
    for limit in left.coverage.limits.iter().chain(&right.coverage.limits) {
        let key = super::graph::canonical_string(limit, "change_graph", "coverage limit")?;
        by_key.entry(key).or_insert_with(|| limit.clone());
    }
    let mut limits = by_key.into_values().collect::<Vec<_>>();
    limits.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    Ok(limits)
}

fn combine_omitted_counts(
    left: Option<u64>,
    right: Option<u64>,
) -> Result<Option<u64>, super::Failure> {
    let Some((left, right)) = left.zip(right) else {
        return Ok(None);
    };
    let combined = left
        .checked_add(right)
        .filter(|value| *value <= 9_007_199_254_740_991)
        .ok_or_else(|| {
            super::graph::invalid(
                "change_graph.coverage.omitted_count",
                "Combined omitted count exceeds the supported safe integer range",
            )
        })?;
    Ok(Some(combined))
}

fn change_graph_limitations(left: &ApplicationGraph, right: &ApplicationGraph) -> Vec<String> {
    let mut limitations = left
        .limitations
        .iter()
        .map(|limitation| format!("Left: {limitation}"))
        .chain(
            right
                .limitations
                .iter()
                .map(|limitation| format!("Right: {limitation}")),
        )
        .chain([
            "changed_from edges are cross-version inferences and never promote structural or semantic matches to exact identity.".to_owned(),
            "The change graph contains compared entities and their retained relationships; it is not an executable application.".to_owned(),
        ])
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    limitations.sort();
    limitations
}

fn preferred_roots(
    left: &ApplicationGraph,
    right: &ApplicationGraph,
    retained: &BTreeSet<String>,
) -> Vec<String> {
    right
        .root_node_ids
        .iter()
        .chain(&left.root_node_ids)
        .filter(|node_id| retained.contains(*node_id))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unique_edges(edges: Vec<Value>) -> Vec<Value> {
    let mut by_id = BTreeMap::<String, Value>::new();
    for edge in edges {
        if let Some(edge_id) = edge.get("edge_id").and_then(Value::as_str) {
            by_id.entry(edge_id.to_owned()).or_insert(edge);
        }
    }
    by_id.into_values().collect()
}

fn committed_id(prefix: &str, value: &Value, path: &str) -> Result<String, super::Failure> {
    canonical_json::digest(value)
        .map(|digest| format!("{prefix}{digest}"))
        .map_err(|error| super::graph::invalid(path, &error.to_string()))
}
