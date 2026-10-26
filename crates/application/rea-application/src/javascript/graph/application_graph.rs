//! Domain `javascriptApplicationGraph`: normalized nodes, edges and the sealed
//! graph with content-derived identifiers, plus the construction accumulator
//! (`JavaScriptArtifactGraphAccumulator`).
//!
//! Inputs here are producer-built and already satisfy the strict schemas, so
//! only the output-affecting parts of parsing are reproduced: the
//! `source_map_reference` default and identifier/order normalization.

use std::collections::HashMap;

use super::super::semantic::value_types::JsString;
use super::json::{Json, Obj, compare_code_points, unique_sorted, unique_sorted_js};

/// A live application node handle (`ApplicationNode` fields consumers read).
#[derive(Clone, Debug, PartialEq)]
pub struct AppNode {
    /// `jag_node_…` identifier.
    pub node_id: String,
    /// Node kind.
    pub kind: String,
    /// Normalized identity.
    pub identity: Json,
}

/// One observation before normalization.
pub struct ObservationInput {
    /// Display label (`""` becomes `null` in the accumulator).
    pub label: Option<JsString>,
    /// Source-map reference; defaults to `null`.
    pub source_map_reference: Json,
    /// Observation properties.
    pub properties: Obj,
    /// Observation evidence.
    pub evidence: Json,
}

impl ObservationInput {
    /// An observation without a source-map reference.
    pub fn new<L: Into<JsString>>(label: Option<L>, properties: Obj, evidence: Json) -> Self {
        Self {
            label: label.map(Into::into),
            source_map_reference: Json::Null,
            properties,
            evidence,
        }
    }

    /// An observation whose label is retained as the source's exact UTF-16 value.
    pub fn new_js(label: Option<JsString>, properties: Obj, evidence: Json) -> Self {
        Self {
            label,
            source_map_reference: Json::Null,
            properties,
            evidence,
        }
    }
}

/// One node before identifiers are derived.
pub struct NodeInput {
    /// Node kind.
    pub kind: String,
    /// Identity strategy object.
    pub identity: Json,
    /// One or more observations.
    pub observations: Vec<ObservationInput>,
}

fn limit_key(limit: &Json) -> String {
    limit.canonical()
}

/// `normalizeLimits`: deduplicate by canonical text, then sort by it.
pub fn normalize_limits(limits: &[Json]) -> Vec<Json> {
    let mut seen: Vec<(String, Json)> = Vec::new();
    for limit in limits {
        let key = limit_key(limit);
        if let Some(entry) = seen.iter_mut().find(|(existing, _)| *existing == key) {
            entry.1 = limit.clone();
        } else {
            seen.push((key, limit.clone()));
        }
    }
    seen.sort_by(|left, right| compare_code_points(&left.0, &right.0));
    seen.into_iter().map(|(_, limit)| limit).collect()
}

fn sorted_strings(value: &Json) -> Json {
    super::json::strings(unique_sorted_js(
        value.arr().iter().map(|item| item.text().clone()),
    ))
}

/// `normalizeEvidence` for application-graph facts.
pub fn normalize_evidence(evidence: &Json) -> Json {
    let mut object = evidence.obj();
    let mut coverage = evidence.at("coverage").obj();
    coverage.set(
        "limits",
        Json::array(normalize_limits(evidence.at("coverage").at("limits").arr())),
    );
    object.set("coverage", coverage);
    object.set("limitations", sorted_strings(evidence.at("limitations")));
    object.set("evidence_ids", sorted_strings(evidence.at("evidence_ids")));
    object.into()
}

fn normalize_identity(identity: &Json) -> Json {
    if identity.at("strategy").text() == "structural-fingerprint" {
        let mut object = identity.obj();
        object.set("basis", sorted_strings(identity.at("basis")));
        return object.into();
    }
    identity.clone()
}

/// `jag_node_` identifier for one kind and identity.
pub fn node_id(kind: &str, identity: &Json) -> String {
    let semantic = Obj::new()
        .with_static("kind", kind)
        .with_static("identity", identity.clone());
    format!("jag_node_{}", Json::from(semantic).digest())
}

fn observation_strategy() -> Json {
    Obj::new()
        .with_static("strategy", "semantic-content-sha256")
        .with_static("stability", "observation-exact")
        .into()
}

fn edge_strategy() -> Json {
    Obj::new()
        .with_static("strategy", "semantic-content-sha256")
        .with_static("stability", "relationship-exact")
        .into()
}

/// A created node: its handle plus ordered observations (each with `observation_id`).
pub struct CreatedNode {
    /// Handle.
    pub node: AppNode,
    /// Observations sorted by identifier, duplicates retained.
    pub observations: Vec<Json>,
}

/// `createJavaScriptApplicationNode`.
pub fn create_node(input: NodeInput) -> CreatedNode {
    let identity = normalize_identity(&input.identity);
    let identifier = node_id(&input.kind, &identity);
    let mut observations: Vec<Json> = input
        .observations
        .into_iter()
        .map(|observation| {
            let label = observation.label.map(Json::String).unwrap_or(Json::Null);
            let semantic = Obj::new()
                .with_static("label", label)
                .with_static("source_map_reference", observation.source_map_reference)
                .with_static("properties", observation.properties)
                .with_static("evidence", normalize_evidence(&observation.evidence))
                .with_static("identifier_strategy", observation_strategy());
            let mut hashed = Obj::new().with_static("node_id", identifier.as_str());
            hashed.extend_from(&semantic);
            let id = format!("jag_observation_{}", Json::from(hashed).digest());
            Json::from(semantic.with_static("observation_id", id))
        })
        .collect();
    observations.sort_by(|left, right| {
        compare_code_points(
            left.at("observation_id").str(),
            right.at("observation_id").str(),
        )
    });
    CreatedNode {
        node: AppNode {
            node_id: identifier,
            kind: input.kind,
            identity,
        },
        observations,
    }
}

/// One edge before its identifier is derived.
pub struct EdgeInput {
    /// Source node identifier.
    pub source: String,
    /// Target node identifier.
    pub target: String,
    /// Relation.
    pub relation: String,
    /// Properties.
    pub properties: Obj,
    /// Evidence.
    pub evidence: Json,
}

/// `createJavaScriptApplicationEdge`.
pub fn create_edge(input: EdgeInput) -> Json {
    let semantic = Obj::new()
        .with_static("source_node_id", input.source)
        .with_static("target_node_id", input.target)
        .with_static("relation", input.relation)
        .with_static("properties", input.properties)
        .with_static("evidence", normalize_evidence(&input.evidence))
        .with_static("identifier_strategy", edge_strategy());
    let id = format!("jag_edge_{}", Json::from(semantic.clone()).digest());
    semantic.with_static("edge_id", id).into()
}

struct AccumulatedNode {
    node: AppNode,
    observations: Vec<Json>,
    indices: HashMap<String, usize>,
    dirty: bool,
}

/// `JavaScriptArtifactGraphAccumulator`: live nodes with deduplicated observations.
#[derive(Default)]
pub struct Accumulator {
    order: Vec<String>,
    nodes: HashMap<String, AccumulatedNode>,
    edge_order: Vec<String>,
    edges: HashMap<String, Json>,
}

impl Accumulator {
    /// Merge observations into a stable live node.
    pub fn add_node(&mut self, mut input: NodeInput) -> AppNode {
        for observation in &mut input.observations {
            if observation.label.as_ref().is_some_and(JsString::is_empty) {
                observation.label = None;
            }
        }
        let created = create_node(input);
        let Some(existing) = self.nodes.get_mut(&created.node.node_id) else {
            let indices = created
                .observations
                .iter()
                .enumerate()
                .map(|(index, observation)| {
                    (observation.at("observation_id").str().to_owned(), index)
                })
                .collect();
            let node = created.node.clone();
            self.order.push(node.node_id.clone());
            self.nodes.insert(
                node.node_id.clone(),
                AccumulatedNode {
                    node: node.clone(),
                    observations: created.observations,
                    indices,
                    dirty: false,
                },
            );
            return node;
        };
        if existing.indices.len() != existing.observations.len() {
            let mut retained = Vec::with_capacity(existing.indices.len());
            for (index, observation) in existing.observations.iter().enumerate() {
                let id = observation.at("observation_id").str();
                if existing.indices.get(id) != Some(&index) {
                    continue;
                }
                retained.push(observation.clone());
            }
            existing.indices = retained
                .iter()
                .enumerate()
                .map(|(index, observation)| {
                    (observation.at("observation_id").str().to_owned(), index)
                })
                .collect();
            existing.observations = retained;
        }
        for observation in created.observations {
            let id = observation.at("observation_id").str().to_owned();
            if let Some(&index) = existing.indices.get(&id) {
                existing.observations[index] = observation;
            } else {
                existing.indices.insert(id, existing.observations.len());
                existing.observations.push(observation);
                existing.dirty = true;
            }
        }
        existing.node.clone()
    }

    /// Create or replace one canonical edge by semantic identifier.
    pub fn add_edge(&mut self, input: EdgeInput) {
        let edge = create_edge(input);
        let id = edge.at("edge_id").str().to_owned();
        if !self.edges.contains_key(&id) {
            self.edge_order.push(id.clone());
        }
        self.edges.insert(id, edge);
    }

    /// Finalize observation order and return canonical node records.
    pub fn nodes(&mut self) -> Vec<Json> {
        let mut records = Vec::with_capacity(self.order.len());
        for id in &self.order {
            let Some(entry) = self.nodes.get_mut(id) else {
                continue;
            };
            if entry.dirty {
                entry.observations.sort_by(|left, right| {
                    compare_code_points(
                        left.at("observation_id").str(),
                        right.at("observation_id").str(),
                    )
                });
                entry.dirty = false;
            }
            records.push(
                Obj::new()
                    .with_static("node_id", entry.node.node_id.as_str())
                    .with_static("kind", entry.node.kind.as_str())
                    .with_static("identity", entry.node.identity.clone())
                    .with_static("observations", Json::array(entry.observations.clone()))
                    .into(),
            );
        }
        records
    }

    /// All accumulated edges in first-insertion order.
    pub fn edges(&self) -> Vec<Json> {
        self.edge_order
            .iter()
            .filter_map(|id| self.edges.get(id).cloned())
            .collect()
    }
}

/// Graph content before sealing.
pub struct GraphInput {
    /// Root node identifiers.
    pub root_node_ids: Vec<String>,
    /// Node records.
    pub nodes: Vec<Json>,
    /// Edge records.
    pub edges: Vec<Json>,
    /// Graph coverage.
    pub coverage: Json,
    /// Graph limitations.
    pub limitations: Vec<String>,
}

/// `sealTransferredJavaScriptApplicationGraphSteps` output: normalized content
/// plus `graph_id`.
pub fn seal_graph(input: GraphInput) -> Json {
    let mut nodes = input.nodes;
    nodes.sort_by(|left, right| {
        compare_code_points(left.at("node_id").str(), right.at("node_id").str())
    });
    let mut edges = input.edges;
    edges.sort_by(|left, right| {
        compare_code_points(left.at("edge_id").str(), right.at("edge_id").str())
    });
    let mut coverage = input.coverage.obj();
    coverage.set(
        "limits",
        Json::array(normalize_limits(input.coverage.at("limits").arr())),
    );
    let content = Obj::new()
        .with_static("schema", "JavaScriptApplicationGraph")
        .with_static(
            "root_node_ids",
            super::json::strings(unique_sorted(input.root_node_ids)),
        )
        .with_static("nodes", Json::array(nodes))
        .with_static("edges", Json::array(edges))
        .with_static("coverage", coverage)
        .with_static(
            "limitations",
            super::json::strings(unique_sorted(input.limitations)),
        );
    let id = format!("jag_{}", Json::from(content.clone()).digest());
    content.with_static("graph_id", id).into()
}
