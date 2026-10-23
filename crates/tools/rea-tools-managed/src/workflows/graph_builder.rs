//! The JavaScript Application Graph builder shared by the managed graph
//! projection.
//!
//! Compatibility owner: `src/domain/javascript/javascriptApplicationGraph.ts`
//! (`createJavaScriptApplicationNode`, `createJavaScriptApplicationEdge`,
//! `createJavaScriptApplicationGraph`) together with its schemas
//! (`src/domain/javascript/javascriptApplicationGraphSchemas.ts` and
//! `javascriptApplicationEvidenceSchemas.ts`).
//!
//! No other Rust crate ports this builder, so the managed graph tool owns a
//! local copy. Only the node kinds, identity strategies, and evidence shapes
//! the managed projection produces are exercised; every semantic identifier,
//! normalization, and ordering is derived exactly as the TypeScript does, so
//! the stored graph and its `jag_*` digests match the oracle byte for byte.
use super::error::DomainError;
use crate::common::json;
use serde_json::{Map, Value, json};
use std::cmp::Ordering;

const DOMAIN_CONTEXT: &str = "JavaScript Application Graph";

/// `createJavaScriptApplicationNode`: normalize one node and derive every id.
///
/// `kind`, `identity`, and the observation list (`label`,
/// `source_map_reference`, `properties`, `evidence`) are supplied by the
/// caller; `source_map_reference` defaults to null.
pub struct NodeInput {
    pub kind: String,
    pub identity: Value,
    pub observations: Vec<ObservationInput>,
}

/// One node observation before its semantic identifier is derived.
pub struct ObservationInput {
    pub label: Value,
    pub properties: Value,
    pub evidence: Value,
}

/// One directed relationship before its semantic identifier is derived.
pub struct EdgeInput {
    pub source_node_id: String,
    pub target_node_id: String,
    pub relation: String,
    pub properties: Value,
    pub evidence: Value,
}

/// A built node: its stored value and the `node_id` the edges reference.
pub struct BuiltNode {
    pub node_id: String,
    pub value: Value,
}

fn observation_identifier_strategy() -> Value {
    json!({
        "strategy": "semantic-content-sha256",
        "stability": "observation-exact",
    })
}

fn edge_identifier_strategy() -> Value {
    json!({
        "strategy": "semantic-content-sha256",
        "stability": "relationship-exact",
    })
}

/// `compareUnicodeCodePoints`: Rust `str` ordering is UTF-8 byte order, which
/// equals Unicode code-point order.
fn cmp_code_points(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

/// `digestCanonicalValue(value, "JavaScript Application Graph")`.
fn digest(value: &Value) -> Result<String, DomainError> {
    rea_core::canonical_json::digest(value).map_err(|_| {
        DomainError::type_error(format!("{DOMAIN_CONTEXT} could not canonicalize data"))
    })
}

/// `canonicalJson(value, "JavaScript Application Graph")`: RFC 8785 text.
fn canonical_json(value: &Value) -> Result<String, DomainError> {
    let raw = serde_json::value::to_raw_value(value).map_err(|_| {
        DomainError::type_error(format!("{DOMAIN_CONTEXT} could not canonicalize data"))
    })?;
    let mut output: Vec<u8> = Vec::new();
    rea_core::canonical_json::write(&raw, &mut output).map_err(|_| {
        DomainError::type_error(format!("{DOMAIN_CONTEXT} could not canonicalize data"))
    })?;
    String::from_utf8(output).map_err(|_| {
        DomainError::type_error(format!("{DOMAIN_CONTEXT} could not canonicalize data"))
    })
}

/// `normalizeEvidence`: dedupe/sort coverage limits, limitations and ids.
fn normalize_evidence(evidence: &Value) -> Result<Value, DomainError> {
    let mut object = evidence.as_object().cloned().unwrap_or_default();
    if let Some(Value::Object(coverage)) = object.get("coverage").cloned().as_ref() {
        let mut coverage = coverage.clone();
        let limits = coverage.get("limits").cloned().unwrap_or_else(|| json!([]));
        coverage.insert("limits".into(), normalize_limits(&limits)?);
        object.insert("coverage".into(), Value::Object(coverage));
    }
    let limitations = object
        .get("limitations")
        .cloned()
        .unwrap_or_else(|| json!([]));
    object.insert(
        "limitations".into(),
        Value::Array(unique_sorted(&limitations)),
    );
    let evidence_ids = object
        .get("evidence_ids")
        .cloned()
        .unwrap_or_else(|| json!([]));
    object.insert(
        "evidence_ids".into(),
        Value::Array(unique_sorted(&evidence_ids)),
    );
    Ok(Value::Object(object))
}

/// `normalizeLimits`: last-writer-wins dedupe by canonical JSON, then sort.
fn normalize_limits(limits: &Value) -> Result<Value, DomainError> {
    let items = limits.as_array().cloned().unwrap_or_default();
    let mut by_key: Vec<(String, Value)> = Vec::new();
    for limit in &items {
        let key = canonical_json(limit)?;
        match by_key.iter_mut().find(|(existing, _)| existing == &key) {
            Some((_, value)) => *value = limit.clone(),
            None => by_key.push((key, limit.clone())),
        }
    }
    by_key.sort_by(|left, right| cmp_code_points(&left.0, &right.0));
    Ok(Value::Array(
        by_key.into_iter().map(|(_, value)| value).collect(),
    ))
}

/// `uniqueSorted`: dedupe strings and sort by Unicode code point.
fn unique_sorted(value: &Value) -> Vec<Value> {
    json::unique_sorted(json::strings(value))
        .into_iter()
        .map(Value::String)
        .collect()
}

/// `normalizeIdentity`: only structural fingerprints sort their basis; the
/// managed projection never uses that strategy, but keep the exact behavior.
fn normalize_identity(identity: &Value) -> Value {
    if identity.get("strategy").and_then(Value::as_str) == Some("structural-fingerprint") {
        let mut object = identity.as_object().cloned().unwrap_or_default();
        if let Some(basis) = object.get("basis").cloned() {
            object.insert("basis".into(), Value::Array(unique_sorted(&basis)));
        }
        return Value::Object(object);
    }
    identity.clone()
}

/// `nodeId`: `jag_node_${digest({ kind, identity })}`.
fn node_id(kind: &str, identity: &Value) -> Result<String, DomainError> {
    let semantic = json!({ "kind": kind, "identity": identity });
    Ok(format!("jag_node_{}", digest(&semantic)?))
}

/// `observationId`: `jag_observation_${digest({ node_id, ...semantic })}`.
fn observation_id(node_identifier: &str, semantic: &Value) -> Result<String, DomainError> {
    let mut object = Map::new();
    object.insert("node_id".into(), json!(node_identifier));
    if let Some(semantic) = semantic.as_object() {
        for (key, value) in semantic {
            object.insert(key.clone(), value.clone());
        }
    }
    Ok(format!(
        "jag_observation_{}",
        digest(&Value::Object(object))?
    ))
}

/// `edgeId`: `jag_edge_${digest(semantic)}`.
fn edge_id(semantic: &Value) -> Result<String, DomainError> {
    Ok(format!("jag_edge_{}", digest(semantic)?))
}

/// `createJavaScriptApplicationNode`.
pub fn create_node(input: NodeInput) -> Result<BuiltNode, DomainError> {
    let identity = normalize_identity(&input.identity);
    let identifier = node_id(&input.kind, &identity)?;
    let mut observations: Vec<Value> = Vec::with_capacity(input.observations.len());
    for observation in &input.observations {
        let evidence = normalize_evidence(&observation.evidence)?;
        // `semantic = { ...observation, evidence, identifier_strategy }`, the
        // observation base keys in schema order: label, source_map_reference,
        // properties, evidence, then the appended identifier_strategy.
        let mut semantic = Map::new();
        semantic.insert("label".into(), observation.label.clone());
        semantic.insert("source_map_reference".into(), Value::Null);
        semantic.insert("properties".into(), observation.properties.clone());
        semantic.insert("evidence".into(), evidence.clone());
        semantic.insert(
            "identifier_strategy".into(),
            observation_identifier_strategy(),
        );
        let semantic = Value::Object(semantic);
        let identifier_value = observation_id(&identifier, &semantic)?;
        // Stored observation in schema key order: base fields, then the two
        // extended fields (observation_id, identifier_strategy).
        let mut stored = Map::new();
        stored.insert("label".into(), observation.label.clone());
        stored.insert("source_map_reference".into(), Value::Null);
        stored.insert("properties".into(), observation.properties.clone());
        stored.insert("evidence".into(), evidence);
        stored.insert("observation_id".into(), json!(identifier_value));
        stored.insert(
            "identifier_strategy".into(),
            observation_identifier_strategy(),
        );
        observations.push(Value::Object(stored));
    }
    observations.sort_by(|left, right| {
        cmp_code_points(
            left.get("observation_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            right
                .get("observation_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
    });
    let mut node = Map::new();
    node.insert("node_id".into(), json!(identifier));
    node.insert("kind".into(), json!(input.kind));
    node.insert("identity".into(), identity);
    node.insert("observations".into(), Value::Array(observations));
    Ok(BuiltNode {
        node_id: identifier,
        value: Value::Object(node),
    })
}

/// `createJavaScriptApplicationEdge`.
pub fn create_edge(input: EdgeInput) -> Result<Value, DomainError> {
    let evidence = normalize_evidence(&input.evidence)?;
    // `semantic = { ...parsed, evidence, identifier_strategy }` in the edge
    // schema key order.
    let mut semantic = Map::new();
    semantic.insert("source_node_id".into(), json!(input.source_node_id));
    semantic.insert("target_node_id".into(), json!(input.target_node_id));
    semantic.insert("relation".into(), json!(input.relation));
    semantic.insert("properties".into(), input.properties.clone());
    semantic.insert("evidence".into(), evidence.clone());
    semantic.insert("identifier_strategy".into(), edge_identifier_strategy());
    let semantic = Value::Object(semantic);
    let identifier = edge_id(&semantic)?;
    // Stored edge: input fields, then the appended edge_id and
    // identifier_strategy.
    let mut stored = Map::new();
    stored.insert("source_node_id".into(), json!(input.source_node_id));
    stored.insert("target_node_id".into(), json!(input.target_node_id));
    stored.insert("relation".into(), json!(input.relation));
    stored.insert("properties".into(), input.properties);
    stored.insert("evidence".into(), evidence);
    stored.insert("edge_id".into(), json!(identifier));
    stored.insert("identifier_strategy".into(), edge_identifier_strategy());
    Ok(Value::Object(stored))
}

/// Complete graph content before the graph identifier is derived.
pub struct GraphInput {
    pub root_node_ids: Vec<String>,
    pub nodes: Vec<Value>,
    pub edges: Vec<Value>,
    pub coverage: Value,
    pub limitations: Vec<String>,
}

/// `createJavaScriptApplicationGraph`: normalize the graph and derive its id.
pub fn create_graph(input: GraphInput) -> Result<Value, DomainError> {
    // `normalizeGraphInput`.
    let root_node_ids: Vec<Value> = json::unique_sorted(input.root_node_ids)
        .into_iter()
        .map(Value::String)
        .collect();
    let mut nodes = input.nodes;
    nodes.sort_by(|left, right| {
        cmp_code_points(
            left.get("node_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            right
                .get("node_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
    });
    let mut edges = input.edges;
    edges.sort_by(|left, right| {
        cmp_code_points(
            left.get("edge_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            right
                .get("edge_id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
    });
    let mut coverage = input.coverage.as_object().cloned().unwrap_or_default();
    let limits = coverage.get("limits").cloned().unwrap_or_else(|| json!([]));
    coverage.insert("limits".into(), normalize_limits(&limits)?);
    let limitations: Vec<Value> = json::unique_sorted(input.limitations)
        .into_iter()
        .map(Value::String)
        .collect();
    // Content in the input schema key order: schema, root_node_ids, nodes,
    // edges, coverage, limitations.
    let mut content = Map::new();
    content.insert("schema".into(), json!("JavaScriptApplicationGraph"));
    content.insert("root_node_ids".into(), Value::Array(root_node_ids));
    content.insert("nodes".into(), Value::Array(nodes));
    content.insert("edges".into(), Value::Array(edges));
    content.insert("coverage".into(), Value::Object(coverage));
    content.insert("limitations".into(), Value::Array(limitations));
    let content = Value::Object(content);
    let graph_id = format!("jag_{}", digest(&content)?);
    // `{ ...content, graph_id }`: content keys keep their order, graph_id last.
    let mut graph = content.as_object().cloned().unwrap_or_default();
    graph.insert("graph_id".into(), json!(graph_id));
    Ok(Value::Object(graph))
}
