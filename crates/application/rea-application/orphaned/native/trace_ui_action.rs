//! Captured-Evidence-only tracing for compiled native UI actions.
//!
//! The adapter supplies a bounded, already joined graph. This module performs
//! deterministic graph traversal only; it never opens a UI archive, queries a
//! provider, or executes a target.

use rea_core::failure::{Detail, Failure};
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "trace_native_ui_action";
const MAX_DEPTH: usize = 32;
const MAX_NODES: usize = 2_000;
const MAX_EDGES: usize = 5_000;

#[derive(Clone, Debug)]
struct Graph {
    target_sha256: String,
    provider: Value,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    coverage: Vec<Value>,
    truncated: bool,
}

#[derive(Clone, Debug)]
struct Node {
    id: String,
    kind: String,
    name: String,
    value: Value,
}

#[derive(Clone, Debug)]
struct Edge {
    id: String,
    from: String,
    to: Option<String>,
    relation: String,
    resolution: String,
    value: Value,
}

struct CandidateSelection {
    start: Option<String>,
    candidates: Vec<String>,
    reason: &'static str,
}

#[derive(Clone, Copy)]
struct Limits {
    max_depth: usize,
    max_nodes: usize,
    max_edges: usize,
}

/// Project a captured graph into the public UI-action trace shape.
pub fn trace(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("trace_native_ui_action input must be an object"))?;
    let action = required_text(object, "action")?;
    let graph_value = object
        .get("graph")
        .or_else(|| object.get("evidence"))
        .ok_or_else(|| invalid("captured UI/native graph Evidence is required"))?;
    let graph = parse_graph(graph_value)?;
    let limits = Limits::from_input(object)?;

    let selection = select_candidates(&graph.nodes, &graph.edges, &action);
    let Some(start) = selection.start else {
        return unresolved_trace(&graph, &action, selection);
    };

    traverse(&graph, &action, &start, limits)
}

fn parse_graph(value: &Value) -> Result<Graph, Failure> {
    let graph = value
        .get("normalized_result")
        .or_else(|| value.get("result"))
        .unwrap_or(value)
        .as_object()
        .ok_or_else(|| invalid("captured UI/native graph must be an object"))?;

    let target_sha256 = required_text(graph, "target_sha256")?;
    if !is_sha256(&target_sha256) {
        return Err(invalid("target_sha256 must be a lowercase SHA-256 digest"));
    }
    let provider = graph
        .get("provider")
        .cloned()
        .ok_or_else(|| invalid("graph provider is required"))?;
    validate_provider(&provider)?;

    let nodes = parse_nodes(graph.get("nodes"))?;
    let edges = parse_edges(graph.get("edges"), &nodes)?;
    let coverage = parse_coverage(graph.get("coverage"))?;
    let truncated = graph
        .get("truncated")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("graph truncated must be a boolean"))?;

    Ok(Graph {
        target_sha256,
        provider,
        nodes,
        edges,
        coverage,
        truncated,
    })
}

fn parse_nodes(value: Option<&Value>) -> Result<Vec<Node>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("graph nodes must be an array"))?;
    if values.len() > MAX_NODES {
        return Err(invalid("graph nodes exceed the supported bound"));
    }

    let mut seen = BTreeSet::new();
    let mut nodes = Vec::with_capacity(values.len());
    for node in values {
        let object = node
            .as_object()
            .ok_or_else(|| invalid("graph node must be an object"))?;
        let id = required_text(object, "id")?;
        let name = required_text(object, "name")?;
        let kind = required_text(object, "kind")?;
        require_object(object, "attributes")?;
        require_array(object, "evidence")?;
        if !seen.insert(id.clone()) {
            return Err(invalid("graph node IDs must be unique"));
        }
        nodes.push(Node {
            id,
            kind,
            name,
            value: node.clone(),
        });
    }
    Ok(nodes)
}

fn parse_edges(value: Option<&Value>, nodes: &[Node]) -> Result<Vec<Edge>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("graph edges must be an array"))?;
    if values.len() > MAX_EDGES {
        return Err(invalid("graph edges exceed the supported bound"));
    }

    let node_ids = nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut edges = Vec::with_capacity(values.len());
    for edge in values {
        let object = edge
            .as_object()
            .ok_or_else(|| invalid("graph edge must be an object"))?;
        let id = required_text(object, "id")?;
        let from = required_text(object, "from")?;
        let relation = required_text(object, "relation")?;
        let resolution = required_text(object, "resolution")?;
        if !matches!(
            resolution.as_str(),
            "observed" | "inferred" | "resolved" | "ambiguous" | "unresolved"
        ) {
            return Err(invalid("graph edge resolution is invalid"));
        }
        require_array(object, "evidence")?;
        require_array(object, "limitations")?;
        if !node_ids.contains(from.as_str()) {
            return Err(invalid("graph edge source is absent from graph nodes"));
        }

        let to = match object.get("to") {
            Some(Value::String(value)) if !value.is_empty() => Some(value.clone()),
            Some(Value::Null) if resolution == "unresolved" => None,
            _ => return Err(invalid("graph edge destination is invalid")),
        };
        if let Some(destination) = to.as_ref() {
            if !node_ids.contains(destination.as_str()) {
                return Err(invalid("graph edge destination is absent from graph nodes"));
            }
        } else if resolution != "unresolved" {
            return Err(invalid("resolved graph edges require a destination"));
        }
        if resolution == "unresolved" {
            require_text(object, "reason")?;
        }
        if !seen.insert(id.clone()) {
            return Err(invalid("graph edge IDs must be unique"));
        }
        edges.push(Edge {
            id,
            from,
            to,
            relation,
            resolution,
            value: edge.clone(),
        });
    }
    Ok(edges)
}

fn parse_coverage(value: Option<&Value>) -> Result<Vec<Value>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("graph coverage must be an array"))?;
    for facet in values {
        let object = facet
            .as_object()
            .ok_or_else(|| invalid("graph coverage facet must be an object"))?;
        require_text(object, "facet")?;
        require_text(object, "status")?;
        require_nonnegative(object, "examined")?;
        require_nonnegative(object, "omitted")?;
        if !object.get("reason").is_some_and(Value::is_null)
            && object.get("reason").and_then(Value::as_str).is_none()
        {
            return Err(invalid("graph coverage reason must be text or null"));
        }
    }
    Ok(values.to_vec())
}

impl Limits {
    fn from_input(object: &Map<String, Value>) -> Result<Self, Failure> {
        Ok(Self {
            max_depth: bound(object, "max_depth", 8, MAX_DEPTH, false)?,
            max_nodes: bound(object, "max_nodes", 250, MAX_NODES, true)?,
            max_edges: bound(object, "max_edges", 500, MAX_EDGES, true)?,
        })
    }
}

fn select_candidates(nodes: &[Node], edges: &[Edge], action: &str) -> CandidateSelection {
    if let Some(node) = nodes
        .iter()
        .find(|node| node.id == action && node.kind == "action")
    {
        return CandidateSelection {
            start: Some(node.id.clone()),
            candidates: Vec::new(),
            reason: "",
        };
    }

    let actions = nodes
        .iter()
        .filter(|node| {
            node.kind == "action"
                && (node.name == action
                    || node
                        .value
                        .pointer("/attributes/selector")
                        .and_then(Value::as_str)
                        == Some(action))
        })
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    if actions.len() == 1 {
        return CandidateSelection {
            start: actions.first().cloned(),
            candidates: Vec::new(),
            reason: "",
        };
    }
    if actions.len() > 1 {
        return CandidateSelection {
            start: None,
            candidates: actions,
            reason: "action_selector_matches_multiple_ui_connections",
        };
    }

    let object_ids = nodes
        .iter()
        .filter(|node| {
            matches!(
                node.kind.as_str(),
                "control" | "view" | "view_controller" | "scene"
            ) && (node.id == action
                || node
                    .value
                    .pointer("/attributes/interface_builder_object_id")
                    .and_then(Value::as_str)
                    == Some(action))
        })
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    let action_ids = edges
        .iter()
        .filter_map(|edge| {
            let destination = edge.to.as_ref()?;
            if edge.resolution != "observed"
                || edge.relation != "target_action"
                || !object_ids.contains(edge.from.as_str())
            {
                return None;
            }
            nodes
                .iter()
                .find(|node| node.id == *destination && node.kind == "action")
                .map(|node| node.id.clone())
        })
        .collect::<BTreeSet<_>>();
    if action_ids.len() == 1 {
        return CandidateSelection {
            start: action_ids.iter().next().cloned(),
            candidates: Vec::new(),
            reason: "",
        };
    }
    if action_ids.len() > 1 {
        return CandidateSelection {
            start: None,
            candidates: action_ids.into_iter().collect(),
            reason: "interface_object_has_multiple_action_connections",
        };
    }

    CandidateSelection {
        start: None,
        candidates: Vec::new(),
        reason: "ui_action_or_object_not_found",
    }
}

fn unresolved_trace(
    graph: &Graph,
    action: &str,
    selection: CandidateSelection,
) -> Result<Value, Failure> {
    let nodes = graph
        .nodes
        .iter()
        .filter(|node| selection.candidates.contains(&node.id))
        .map(|node| node.value.clone())
        .collect::<Vec<_>>();

    Ok(json!({
        "target_sha256": graph.target_sha256,
        "provider": graph.provider,
        "start": action,
        "direction": "forward",
        "nodes": nodes,
        "edges": [],
        "unresolved": [],
        "reached_depth": 0,
        "truncated": graph.truncated,
        "reason": selection.reason,
        "coverage": graph.coverage,
        "limitations": [
            "The supplied graph did not identify one unique authored UI action or native function; no handler path was inferred."
        ]
    }))
}

fn traverse(graph: &Graph, action: &str, start: &str, limits: Limits) -> Result<Value, Failure> {
    let node_ids = graph
        .nodes
        .iter()
        .map(|node| node.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut adjacency: BTreeMap<String, Vec<&Edge>> = BTreeMap::new();
    for edge in &graph.edges {
        adjacency.entry(edge.from.clone()).or_default().push(edge);
    }

    let mut visited = vec![start.to_owned()];
    let mut visited_set = BTreeSet::from([start.to_owned()]);
    let mut queue = VecDeque::from([(start.to_owned(), 0usize)]);
    let mut selected_edges = Vec::new();
    let mut unresolved = Vec::new();
    let mut reached_depth = 0;
    let mut truncated = graph.truncated;
    let mut reason = None;

    while let Some((current, depth)) = queue.pop_front() {
        let adjacent = adjacency.get(&current).cloned().unwrap_or_default();
        for edge in adjacent {
            if selected_edges.len() + unresolved.len() >= limits.max_edges {
                truncated = true;
                reason = Some("max_edges_reached");
                break;
            }
            if edge.resolution == "unresolved" {
                unresolved.push(edge.value.clone());
                continue;
            }
            let Some(next) = edge.to.as_ref() else {
                continue;
            };
            if visited_set.contains(next) {
                selected_edges.push(edge.value.clone());
                continue;
            }
            if depth >= limits.max_depth {
                truncated = true;
                reason.get_or_insert("max_depth_reached");
                continue;
            }
            if visited.len() >= limits.max_nodes {
                truncated = true;
                reason = Some("max_nodes_reached");
                break;
            }
            if !node_ids.contains(next.as_str()) {
                truncated = true;
                reason.get_or_insert("edge_target_missing_from_graph");
                continue;
            }

            visited_set.insert(next.clone());
            visited.push(next.clone());
            reached_depth = reached_depth.max(depth + 1);
            selected_edges.push(edge.value.clone());
            queue.push_back((next.clone(), depth + 1));
        }
        if matches!(
            reason,
            Some("max_edges_reached") | Some("max_nodes_reached")
        ) {
            break;
        }
    }

    let trace_nodes = visited
        .iter()
        .filter_map(|id| graph.nodes.iter().find(|node| &node.id == id))
        .map(|node| node.value.clone())
        .collect::<Vec<_>>();
    let mut limitations = vec![
        "Static analysis does not prove that an authored UI action is reachable or executed at runtime.".to_owned(),
        "Provider call graphs may omit unresolved indirect dispatch.".to_owned(),
    ];
    if !unresolved.is_empty() {
        limitations
            .push("One or more traversed dispatch relationships remain unresolved.".to_owned());
    }

    Ok(json!({
        "target_sha256": graph.target_sha256,
        "provider": graph.provider,
        "start": action,
        "direction": "forward",
        "nodes": trace_nodes,
        "edges": selected_edges,
        "unresolved": unresolved,
        "reached_depth": reached_depth,
        "truncated": truncated,
        "reason": reason,
        "coverage": graph.coverage,
        "limitations": limitations,
    }))
}

fn validate_provider(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("graph provider must be an object"))?;
    require_text(object, "id")?;
    require_text(object, "tool_version")?;
    if !object.get("version").is_some_and(Value::is_null)
        && object.get("version").and_then(Value::as_str).is_none()
    {
        return Err(invalid("graph provider version must be text or null"));
    }
    Ok(())
}

fn bound(
    object: &Map<String, Value>,
    field: &str,
    default: usize,
    maximum: usize,
    positive: bool,
) -> Result<usize, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .unwrap_or(default as u64);
    let value = usize::try_from(value).map_err(|_| invalid(&format!("{field} is too large")))?;
    if value > maximum || (positive && value == 0) {
        return Err(invalid(&format!("{field} is outside the supported bound")));
    }
    Ok(value)
}

fn required_text(object: &Map<String, Value>, field: &str) -> Result<String, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn require_text(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    required_text(object, field).map(|_| ())
}

fn require_object(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_object).is_none() {
        return Err(invalid(&format!("{field} must be an object")));
    }
    Ok(())
}

fn require_array(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_array).is_none() {
        return Err(invalid(&format!("{field} must be an array")));
    }
    Ok(())
}

fn require_nonnegative(object: &Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_u64).is_none() {
        return Err(invalid(&format!("{field} must be a non-negative integer")));
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a bounded captured UI/native graph and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
