//! JavaScript Application Graph construction used by runtime reconciliation.
//!
//! Compatibility owner: `createJavaScriptApplicationNode`,
//! `createJavaScriptApplicationEdge` and `createJavaScriptApplicationGraph`
//! in `src/domain/javascript/javascriptApplicationGraph.ts`. The semantic
//! identifiers, normalization and ordering are derived exactly as the
//! original does (adapted from the managed graph builder in
//! `rea-tools-managed/src/workflows/graph_builder.rs`). The final graph
//! content schema refinements are not re-run: every input node and edge was
//! either revalidated at the Evidence boundary or built here.
use super::{Defect, digest};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

fn observation_identifier_strategy() -> Value {
    json!({ "strategy": "semantic-content-sha256", "stability": "observation-exact" })
}

fn edge_identifier_strategy() -> Value {
    json!({ "strategy": "semantic-content-sha256", "stability": "relationship-exact" })
}

/// `canonicalJson(value, "JavaScript Application Graph")`.
fn canonical_json(value: &Value) -> Result<String, Defect> {
    let raw = serde_json::value::to_raw_value(value).map_err(|_| Defect)?;
    let mut output = Vec::new();
    rea_core::canonical_json::write(&raw, &mut output).map_err(|_| Defect)?;
    String::from_utf8(output).map_err(|_| Defect)
}

/// `uniqueSorted` over the string members of a JSON array.
pub fn unique_sorted_value(value: &Value) -> Value {
    let set: BTreeSet<&str> = value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    Value::Array(set.into_iter().map(|item| json!(item)).collect())
}

/// `normalizeLimits`: dedupe by canonical JSON (last value wins) and sort.
fn normalize_limits(limits: &Value) -> Result<Value, Defect> {
    let mut by_key: Vec<(String, Value)> = Vec::new();
    for limit in limits.as_array().into_iter().flatten() {
        let key = canonical_json(limit)?;
        match by_key.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, value)) => *value = limit.clone(),
            None => by_key.push((key, limit.clone())),
        }
    }
    by_key.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(Value::Array(
        by_key.into_iter().map(|(_, value)| value).collect(),
    ))
}

/// `normalizeEvidence`.
fn normalize_evidence(evidence: &Value) -> Result<Value, Defect> {
    let mut object = evidence.as_object().cloned().ok_or(Defect)?;
    if let Some(Value::Object(coverage)) = object.get("coverage").cloned() {
        let mut coverage = coverage;
        let limits = coverage.get("limits").cloned().unwrap_or_else(|| json!([]));
        coverage.insert("limits".into(), normalize_limits(&limits)?);
        object.insert("coverage".into(), Value::Object(coverage));
    }
    let limitations = unique_sorted_value(object.get("limitations").unwrap_or(&Value::Null));
    object.insert("limitations".into(), limitations);
    let ids = unique_sorted_value(object.get("evidence_ids").unwrap_or(&Value::Null));
    object.insert("evidence_ids".into(), ids);
    Ok(Value::Object(object))
}

/// `normalizeIdentity`.
fn normalize_identity(identity: &Value) -> Value {
    if identity["strategy"] == "structural-fingerprint" {
        let mut object = identity.as_object().cloned().unwrap_or_default();
        if let Some(basis) = object.get("basis").cloned() {
            object.insert("basis".into(), unique_sorted_value(&basis));
        }
        return Value::Object(object);
    }
    identity.clone()
}

/// `createJavaScriptApplicationNode({ kind, identity, observations })`.
/// Each observation carries `label`, `properties`, `evidence` and an optional
/// `source_map_reference` (default null).
pub fn create_node(kind: &str, identity: &Value, observations: &[Value]) -> Result<Value, Defect> {
    if observations.is_empty() {
        return Err(Defect);
    }
    let identity = normalize_identity(identity);
    let node_id = format!(
        "jag_node_{}",
        digest(&json!({ "kind": kind, "identity": identity }))?
    );
    let mut built = Vec::with_capacity(observations.len());
    for observation in observations {
        let mut semantic = Map::new();
        semantic.insert(
            "label".into(),
            observation.get("label").cloned().unwrap_or(Value::Null),
        );
        semantic.insert(
            "source_map_reference".into(),
            observation
                .get("source_map_reference")
                .cloned()
                .unwrap_or(Value::Null),
        );
        semantic.insert(
            "properties".into(),
            observation.get("properties").cloned().ok_or(Defect)?,
        );
        semantic.insert(
            "evidence".into(),
            normalize_evidence(observation.get("evidence").ok_or(Defect)?)?,
        );
        semantic.insert(
            "identifier_strategy".into(),
            observation_identifier_strategy(),
        );
        let mut identified = Map::new();
        identified.insert("node_id".into(), json!(node_id));
        identified.extend(semantic.clone());
        let observation_id = format!("jag_observation_{}", digest(&Value::Object(identified))?);
        let strategy = semantic
            .remove("identifier_strategy")
            .unwrap_or(Value::Null);
        semantic.insert("observation_id".into(), json!(observation_id));
        semantic.insert("identifier_strategy".into(), strategy);
        built.push(Value::Object(semantic));
    }
    built.sort_by(|left, right| {
        left["observation_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["observation_id"].as_str().unwrap_or_default())
    });
    Ok(json!({
        "node_id": node_id,
        "kind": kind,
        "identity": identity,
        "observations": built,
    }))
}

/// `createJavaScriptApplicationEdge`.
pub fn create_edge(
    source_node_id: &str,
    target_node_id: &str,
    relation: &str,
    properties: Value,
    evidence: &Value,
) -> Result<Value, Defect> {
    let mut semantic = Map::new();
    semantic.insert("source_node_id".into(), json!(source_node_id));
    semantic.insert("target_node_id".into(), json!(target_node_id));
    semantic.insert("relation".into(), json!(relation));
    semantic.insert("properties".into(), properties);
    semantic.insert("evidence".into(), normalize_evidence(evidence)?);
    semantic.insert("identifier_strategy".into(), edge_identifier_strategy());
    let edge_id = format!("jag_edge_{}", digest(&Value::Object(semantic.clone()))?);
    let strategy = semantic
        .remove("identifier_strategy")
        .unwrap_or(Value::Null);
    semantic.insert("edge_id".into(), json!(edge_id));
    semantic.insert("identifier_strategy".into(), strategy);
    Ok(Value::Object(semantic))
}

/// `createJavaScriptApplicationGraph` with `normalizeGraphInput`.
pub fn create_graph(
    root_node_ids: Vec<String>,
    mut nodes: Vec<Value>,
    mut edges: Vec<Value>,
    coverage: Value,
    limitations: Vec<String>,
) -> Result<Value, Defect> {
    let roots: BTreeSet<String> = root_node_ids.into_iter().collect();
    nodes.sort_by(|left, right| {
        left["node_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["node_id"].as_str().unwrap_or_default())
    });
    edges.sort_by(|left, right| {
        left["edge_id"]
            .as_str()
            .unwrap_or_default()
            .cmp(right["edge_id"].as_str().unwrap_or_default())
    });
    let mut coverage = coverage.as_object().cloned().ok_or(Defect)?;
    let limits = coverage.get("limits").cloned().unwrap_or_else(|| json!([]));
    coverage.insert("limits".into(), normalize_limits(&limits)?);
    let limitations: BTreeSet<String> = limitations.into_iter().collect();
    let mut content = Map::new();
    content.insert("schema".into(), json!("JavaScriptApplicationGraph"));
    content.insert("root_node_ids".into(), json!(roots));
    content.insert("nodes".into(), Value::Array(nodes));
    content.insert("edges".into(), Value::Array(edges));
    content.insert("coverage".into(), Value::Object(coverage));
    content.insert("limitations".into(), json!(limitations));
    let graph_id = format!("jag_{}", digest(&Value::Object(content.clone()))?);
    content.insert("graph_id".into(), json!(graph_id));
    Ok(Value::Object(content))
}
