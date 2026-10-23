//! `traceNativeUiAction` (`application/native/NativeUiActionTrace.ts`) and its
//! dependencies: `NativeCallRoutes.ts`, `nativeInvestigationGraph.ts`
//! (`traceNativeInvestigationGraph`, `joinInterfaceBuilderDispatch`) and the
//! UI-action composition that joins decoded Interface Builder archives, native
//! dispatch metadata and static call routes into one bounded trace.
use super::schema::{
    interface_builder_analysis, investigation_graph, investigation_trace,
    native_call_routes_references,
};
use crate::analysis::{Analysis, is_cancellation, is_capability_unavailable, params};
use crate::enhanced::dispatch;
use crate::enhanced::graph::parse_related_addresses;
use rea_analysis::ProviderIdentity;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::HashSet;

const OP_INTERFACE_BUILDER: &str = "decode_interface_builder";
const OP_NATIVE_SEED: &str = "procedure_address";
const OP_REFERENCES: &str = "procedure_references";
const OP_CALLEES: &str = "procedure_callees";

// --- Ordered map preserving JS `Map` insertion order ----------------------

/// Insertion-ordered string-keyed map mirroring a JavaScript `Map`.
struct OrderedMap {
    order: Vec<String>,
    index: std::collections::HashMap<String, usize>,
    values: Vec<Value>,
}
impl OrderedMap {
    fn new() -> Self {
        Self {
            order: Vec::new(),
            index: std::collections::HashMap::new(),
            values: Vec::new(),
        }
    }
    fn contains(&self, key: &str) -> bool {
        self.index.contains_key(key)
    }
    fn get(&self, key: &str) -> Option<&Value> {
        self.index.get(key).map(|&i| &self.values[i])
    }
    fn len(&self) -> usize {
        self.order.len()
    }
    /// `map.set(key, value)` — replace in place, else append.
    fn set(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        if let Some(&i) = self.index.get(&key) {
            self.values[i] = value;
        } else {
            let i = self.values.len();
            self.index.insert(key.clone(), i);
            self.order.push(key);
            self.values.push(value);
        }
    }
    fn into_values(self) -> Vec<Value> {
        self.values
    }
    /// Snapshot of current values in insertion order (for `[...map.values()]`
    /// iteration while the map may still be mutated).
    fn values_snapshot(&self) -> Vec<Value> {
        self.values.clone()
    }
}

fn str_field(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn message_of(error: &AnalysisError) -> String {
    error
        .project()
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_default()
}

/// `traceNativeUiAction` over the validated tool input.
pub fn trace_native_ui_action(
    analysis: &Analysis<'_>,
    input: &Value,
) -> Result<Value, AnalysisError> {
    let action = str_field(input, "action");
    let max_depth = input["max_depth"].as_i64().unwrap_or(8);
    let max_nodes = input["max_nodes"].as_i64().unwrap_or(250);
    let max_edges = input["max_edges"].as_i64().unwrap_or(500);

    // `Promise.all([decode_interface_builder, inspectNativeDispatch])`. The
    // native port runs them sequentially; order has no observable effect since
    // each failure is inspected independently below.
    let ui_execution = analysis.execute(
        OP_INTERFACE_BUILDER,
        &params([
            ("max_documents", json!(64)),
            ("max_objects", json!(max_nodes)),
            ("max_connections", json!(max_edges)),
        ]),
        false,
    );
    let metadata_execution = dispatch::inspect(analysis, 20_000);

    if let Err(error) = &ui_execution {
        if is_cancellation(error) {
            return Err(ui_execution.err().expect("checked"));
        }
    }
    let metadata = match metadata_execution {
        Ok(value) => value,
        Err(error) => return Err(error),
    };

    let target_sha256 = match metadata.get("target_sha256").and_then(Value::as_str) {
        Some(sha) => sha.to_owned(),
        None => {
            return Err(AnalysisError::output(
                "inspect_native_dispatch_metadata",
                "Dispatch metadata lacks target identity",
            ));
        }
    };
    let metadata_provider = &metadata["provider"];
    let metadata_result = &metadata["result"];

    let mut graph = empty_graph(&target_sha256, metadata_provider)?;
    let mut coverage: Vec<Value> = Vec::new();

    match &ui_execution {
        Ok(execution) => {
            let decoded = interface_builder_analysis()
                .parse(&execution.result)
                .map_err(|_| {
                    AnalysisError::output(
                        OP_INTERFACE_BUILDER,
                        "artifact provider returned an invalid interface graph",
                    )
                })?;
            if str_field(&decoded, "target_sha256") != target_sha256 {
                return Err(AnalysisError::output(
                    OP_INTERFACE_BUILDER,
                    "UI and native provider results refer to different target SHA-256 values",
                ));
            }
            graph = join_interface_builder_dispatch(&decoded["graph"], metadata_result)?;

            let empty: Vec<Value> = Vec::new();
            let decoded_coverage = decoded["graph"]["coverage"].as_array().unwrap_or(&empty);
            let archive_decode = decoded_coverage
                .iter()
                .find(|facet| facet.get("facet").and_then(Value::as_str) == Some("archive_decode"));
            let documents_found = decoded["documents"]
                .as_array()
                .map(|docs| !docs.is_empty())
                .unwrap_or(false);
            let archive_status =
                archive_decode.and_then(|facet| facet.get("status").and_then(Value::as_str));
            let status = match archive_status {
                Some(status @ ("partial" | "complete" | "unsupported")) => status.to_owned(),
                _ => {
                    if documents_found {
                        "complete".to_owned()
                    } else {
                        "unsupported".to_owned()
                    }
                }
            };
            let reason = match archive_decode.and_then(|facet| facet.get("reason")) {
                Some(reason) if !reason.is_null() => reason.clone(),
                _ => {
                    if documents_found {
                        Value::Null
                    } else {
                        json!("no_compiled_interface_builder_archives_found")
                    }
                }
            };
            let documents_len = decoded["documents"].as_array().map(Vec::len).unwrap_or(0) as i64;
            let examined = archive_decode
                .and_then(|facet| facet.get("examined").and_then(Value::as_i64))
                .unwrap_or(documents_len);
            let omitted = archive_decode
                .and_then(|facet| facet.get("omitted").and_then(Value::as_i64))
                .unwrap_or(0);
            coverage.push(json!({
                "facet": "interface_builder_archives",
                "status": status,
                "reason": reason,
                "examined": examined,
                "omitted": omitted,
            }));

            let graph_nodes_len = decoded["graph"]["nodes"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0) as i64;
            let graph_edges_len = decoded["graph"]["edges"]
                .as_array()
                .map(Vec::len)
                .unwrap_or(0) as i64;
            let bounded = bound_ui_graph(&graph, max_nodes, max_edges)?;
            graph = bounded.graph;
            if bounded.truncated {
                coverage.push(json!({
                    "facet": "interface_builder_graph",
                    "status": "partial",
                    "reason": "native_trace_output_bounds_reached",
                    "examined": graph_nodes_len + graph_edges_len,
                    "omitted": bounded.omitted,
                }));
            }
        }
        Err(error) => {
            coverage.push(json!({
                "facet": "interface_builder_archives",
                "status": "unsupported",
                "reason": message_of(error),
                "examined": 0,
                "omitted": 0,
            }));
        }
    }

    let mut selected = resolve_ui_action(&graph, &action);
    if selected.node_id.is_none() && selected.candidates.is_empty() {
        let native = analysis.execute(
            OP_NATIVE_SEED,
            &params([("procedure", json!(action))]),
            false,
        );
        match &native {
            Err(error) if is_cancellation(error) => {
                return Err(native.err().expect("checked"));
            }
            Err(error) if !is_capability_unavailable(error) => {
                return Err(native.err().expect("checked"));
            }
            Err(_) => {}
            Ok(execution) => {
                let address = execution.result.as_str();
                let subject_sha = execution
                    .subject
                    .as_ref()
                    .map(|subject| subject.sha256.as_str());
                match (address, subject_sha) {
                    (Some(address), Some(sha)) if sha == target_sha256 => {
                        let id = format!("native:function:{address}");
                        push_graph_node(
                            &mut graph,
                            json!({
                                "id": id,
                                "kind": "function",
                                "name": action,
                                "location": { "address": address, "file_offset": Value::Null },
                                "attributes": { "resolved_by": execution.provider.id },
                                "evidence": [{
                                    "kind": "reference",
                                    "description": format!("Provider resolved the explicit native seed {action}"),
                                    "location": { "address": address, "file_offset": Value::Null },
                                    "artifact_path": Value::Null,
                                    "artifact_sha256": target_sha256,
                                }],
                            }),
                        );
                        selected = Selection {
                            node_id: Some(id),
                            candidates: Vec::new(),
                            reason: Value::Null,
                        };
                    }
                    _ => {
                        return Err(AnalysisError::output(
                            OP_NATIVE_SEED,
                            "Native seed lacks a validated address or matching target identity",
                        ));
                    }
                }
            }
        }
    }

    if selected.node_id.is_none() {
        for facet in graph["coverage"].as_array().cloned().unwrap_or_default() {
            coverage.push(facet);
        }
        let trace = json!({
            "target_sha256": graph["target_sha256"],
            "provider": graph["provider"],
            "start": action,
            "direction": "forward",
            "nodes": selected.candidates,
            "edges": [],
            "unresolved": [],
            "reached_depth": 0,
            "truncated": graph["truncated"],
            "reason": selected.reason,
            "coverage": coverage,
            "limitations": [
                "The query did not identify one unique authored UI action or native function; no handler path was inferred.",
            ],
        });
        return parse_trace(&trace);
    }

    let start = selected.node_id.clone().expect("checked");
    let initial =
        trace_native_investigation_graph(&graph, &start, max_depth, max_nodes, max_edges)?;
    let expanded = expand_native_calls(
        analysis,
        &graph,
        &initial,
        &action,
        &target_sha256,
        max_depth,
        max_nodes,
        max_edges,
    )?;

    coverage.push(json!({
        "facet": "static_native_calls",
        "status": "partial",
        "reason": "typed_direct_and_indirect_references_do_not_cover_all_runtime_dispatch; untyped_provider_callees_remain_inferred",
        "examined": expanded.examined,
        "omitted": expanded.omitted,
    }));
    coverage.push(json!({
        "facet": "cross_function_value_flow",
        "status": "unsupported",
        "reason": "call edges identify control-flow candidates but do not recover argument, return, or shared-memory value relationships",
        "examined": 0,
        "omitted": 0,
    }));

    let graph_truncated = graph["truncated"].as_bool().unwrap_or(false);
    let mut final_coverage = graph["coverage"].as_array().cloned().unwrap_or_default();
    final_coverage.extend(coverage.iter().cloned());
    let final_graph_input = json!({
        "target_sha256": graph["target_sha256"],
        "provider": graph["provider"],
        "nodes": expanded.nodes,
        "edges": expanded.edges,
        "coverage": final_coverage,
        "truncated": graph_truncated || expanded.truncated,
    });
    let final_graph = investigation_graph()
        .parse(&final_graph_input)
        .map_err(|issue| {
            AnalysisError::output(
                "trace_native_ui_action",
                format!("investigation graph does not satisfy its contract: {issue}"),
            )
        })?;

    let trace =
        trace_native_investigation_graph(&final_graph, &start, max_depth, max_nodes, max_edges)?;

    let trace_reason = trace["reason"].clone();
    let trace_truncated = trace["truncated"].as_bool().unwrap_or(false);
    let reason = if expanded.truncated && trace_reason.is_null() {
        json!("native_call_traversal_bound_reached")
    } else if graph_truncated && trace_reason.is_null() {
        json!("native_trace_output_bound_reached")
    } else {
        trace_reason
    };
    let mut limitations = trace["limitations"].as_array().cloned().unwrap_or_default();
    for line in render_source_limitations(&expanded.limitations) {
        limitations.push(json!(line));
    }

    let mut final_trace = trace.as_object().cloned().unwrap_or_default();
    final_trace.insert(
        "truncated".into(),
        json!(trace_truncated || expanded.truncated || graph_truncated),
    );
    final_trace.insert("reason".into(), reason);
    final_trace.insert("limitations".into(), Value::Array(limitations));

    parse_trace(&Value::Object(final_trace))
}

fn parse_trace(trace: &Value) -> Result<Value, AnalysisError> {
    investigation_trace().parse(trace).map_err(|issue| {
        AnalysisError::output(
            "trace_native_ui_action",
            format!("native investigation trace does not satisfy its contract: {issue}"),
        )
    })
}

/// `emptyGraph(targetSha256, provider)`.
fn empty_graph(target_sha256: &str, provider: &Value) -> Result<Value, AnalysisError> {
    let input = json!({
        "target_sha256": target_sha256,
        "provider": {
            "id": provider.get("id").cloned().unwrap_or(Value::Null),
            "version": provider.get("version").cloned().unwrap_or(Value::Null),
            "tool_version": "rea-native-ui-trace/1",
        },
        "nodes": [],
        "edges": [],
        "coverage": [],
        "truncated": false,
    });
    investigation_graph().parse(&input).map_err(|issue| {
        AnalysisError::output(
            "trace_native_ui_action",
            format!("empty graph does not satisfy its contract: {issue}"),
        )
    })
}

/// Append one node to a parsed graph value, mutating `nodes` in place.
fn push_graph_node(graph: &mut Value, node: Value) {
    if let Some(nodes) = graph.get_mut("nodes").and_then(Value::as_array_mut) {
        nodes.push(node);
    }
}

struct BoundedGraph {
    graph: Value,
    truncated: bool,
    omitted: i64,
}

/// `boundUiGraph(graph, maxNodes, maxEdges)`.
fn bound_ui_graph(
    graph: &Value,
    max_nodes: i64,
    max_edges: i64,
) -> Result<BoundedGraph, AnalysisError> {
    let empty: Vec<Value> = Vec::new();
    let all_nodes = graph["nodes"].as_array().unwrap_or(&empty);
    let all_edges = graph["edges"].as_array().unwrap_or(&empty);
    let nodes: Vec<Value> = all_nodes
        .iter()
        .take(max_nodes.max(0) as usize)
        .cloned()
        .collect();
    let node_ids: HashSet<String> = nodes.iter().map(|node| str_field(node, "id")).collect();
    let eligible: Vec<Value> = all_edges
        .iter()
        .filter(|edge| {
            let from = str_field(edge, "from");
            let to = &edge["to"];
            node_ids.contains(&from) && (to.is_null() || node_ids.contains(&str_field(edge, "to")))
        })
        .cloned()
        .collect();
    let edges: Vec<Value> = eligible
        .into_iter()
        .take(max_edges.max(0) as usize)
        .collect();
    let omitted =
        all_nodes.len() as i64 - nodes.len() as i64 + all_edges.len() as i64 - edges.len() as i64;
    let truncated = omitted > 0;
    let graph_truncated = graph["truncated"].as_bool().unwrap_or(false);
    let input = json!({
        "target_sha256": graph["target_sha256"],
        "provider": graph["provider"],
        "nodes": nodes,
        "edges": edges,
        "coverage": graph["coverage"],
        "truncated": graph_truncated || truncated,
    });
    let parsed = investigation_graph().parse(&input).map_err(|issue| {
        AnalysisError::output(
            "trace_native_ui_action",
            format!("bounded graph does not satisfy its contract: {issue}"),
        )
    })?;
    Ok(BoundedGraph {
        graph: parsed,
        truncated,
        omitted,
    })
}

struct Selection {
    node_id: Option<String>,
    candidates: Vec<Value>,
    reason: Value,
}

/// `resolveUiAction(graph, query)`.
fn resolve_ui_action(graph: &Value, query: &str) -> Selection {
    let empty: Vec<Value> = Vec::new();
    let nodes = graph["nodes"].as_array().unwrap_or(&empty);
    let edges = graph["edges"].as_array().unwrap_or(&empty);

    if let Some(exact) = nodes.iter().find(|node| str_field(node, "id") == query) {
        if node_kind(exact) == "action" {
            return Selection {
                node_id: Some(str_field(exact, "id")),
                candidates: Vec::new(),
                reason: Value::Null,
            };
        }
    }

    let actions: Vec<&Value> = nodes
        .iter()
        .filter(|node| {
            node_kind(node) == "action"
                && (str_field(node, "name") == query
                    || attr_str(node, "selector") == Some(query.to_owned()))
        })
        .collect();
    if actions.len() == 1 {
        return Selection {
            node_id: Some(str_field(actions[0], "id")),
            candidates: Vec::new(),
            reason: Value::Null,
        };
    }
    if actions.len() > 1 {
        return Selection {
            node_id: None,
            candidates: actions.into_iter().cloned().collect(),
            reason: json!("action_selector_matches_multiple_ui_connections"),
        };
    }

    let object_match_kinds = ["control", "view", "view_controller", "scene"];
    let object_matches: Vec<&Value> = nodes
        .iter()
        .filter(|node| {
            object_match_kinds.contains(&node_kind(node).as_str())
                && (str_field(node, "id") == query
                    || attr_str(node, "interface_builder_object_id") == Some(query.to_owned()))
        })
        .collect();

    // `actionIds` — insertion-ordered Set.
    let mut action_ids_order: Vec<String> = Vec::new();
    let mut action_ids_seen: HashSet<String> = HashSet::new();
    for edge in edges {
        let resolution = str_field(edge, "resolution");
        let relation = str_field(edge, "relation");
        if resolution != "observed" || relation != "target_action" {
            continue;
        }
        let from = str_field(edge, "from");
        let to = &edge["to"];
        if to.is_null() {
            continue;
        }
        let to_id = str_field(edge, "to");
        let from_matches = object_matches
            .iter()
            .any(|node| str_field(node, "id") == from);
        let to_is_action = nodes
            .iter()
            .any(|node| str_field(node, "id") == to_id && node_kind(node) == "action");
        if from_matches && to_is_action && action_ids_seen.insert(to_id.clone()) {
            action_ids_order.push(to_id);
        }
    }
    if action_ids_order.len() == 1 {
        return Selection {
            node_id: Some(action_ids_order[0].clone()),
            candidates: Vec::new(),
            reason: Value::Null,
        };
    }
    if action_ids_order.len() > 1 {
        let set: HashSet<&String> = action_ids_order.iter().collect();
        let candidates: Vec<Value> = nodes
            .iter()
            .filter(|node| set.contains(&str_field(node, "id")))
            .cloned()
            .collect();
        return Selection {
            node_id: None,
            candidates,
            reason: json!("interface_object_has_multiple_action_connections"),
        };
    }

    Selection {
        node_id: None,
        candidates: Vec::new(),
        reason: json!("ui_action_or_object_not_found"),
    }
}

fn node_kind(node: &Value) -> String {
    str_field(node, "kind")
}

fn attr_str(node: &Value, key: &str) -> Option<String> {
    node.get("attributes")
        .and_then(|attrs| attrs.get(key))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

// --- traceNativeInvestigationGraph -----------------------------------------

/// `traceNativeInvestigationGraph(graph, { start, direction: forward, limits })`.
fn trace_native_investigation_graph(
    graph: &Value,
    start_id: &str,
    max_depth: i64,
    max_nodes: i64,
    max_edges: i64,
) -> Result<Value, AnalysisError> {
    let empty: Vec<Value> = Vec::new();
    let nodes = graph["nodes"].as_array().unwrap_or(&empty);
    let edges = graph["edges"].as_array().unwrap_or(&empty);
    let coverage = graph["coverage"].clone();

    let start = nodes.iter().find(|node| str_field(node, "id") == start_id);
    if start.is_none() {
        let trace = json!({
            "target_sha256": graph["target_sha256"],
            "provider": graph["provider"],
            "start": start_id,
            "direction": "forward",
            "nodes": [],
            "edges": [],
            "unresolved": [],
            "reached_depth": 0,
            "truncated": false,
            "reason": "start_node_missing",
            "coverage": coverage,
            "limitations": ["The requested start node is absent from the supplied graph."],
        });
        return parse_trace(&trace);
    }
    let start = start.expect("checked");
    let start_id = str_field(start, "id");

    // nodeById lookup.
    let node_by_id: std::collections::HashMap<String, &Value> = nodes
        .iter()
        .map(|node| (str_field(node, "id"), node))
        .collect();

    // Forward adjacency keyed by `from`.
    let mut adjacency: std::collections::HashMap<String, Vec<&Value>> =
        std::collections::HashMap::new();
    for edge in edges {
        if edge["from"].is_null() {
            continue;
        }
        adjacency
            .entry(str_field(edge, "from"))
            .or_default()
            .push(edge);
    }

    let mut visited_order: Vec<String> = vec![start_id.clone()];
    let mut visited: HashSet<String> = HashSet::new();
    visited.insert(start_id.clone());
    let mut selected_edges = OrderedMap::new();
    let mut unresolved = OrderedMap::new();
    let mut queue: std::collections::VecDeque<(String, i64)> = std::collections::VecDeque::new();
    queue.push_back((start_id.clone(), 0));
    let mut reached_depth: i64 = 0;
    let mut truncated = false;
    let mut reason: Value = Value::Null;

    while let Some((current_id, current_depth)) = queue.pop_front() {
        let adjacent = adjacency.get(&current_id).cloned().unwrap_or_default();
        for edge in adjacent {
            if (selected_edges.len() + unresolved.len()) as i64 >= max_edges {
                truncated = true;
                reason = json!("max_edges_reached");
                break;
            }
            let edge_id = str_field(edge, "id");
            if str_field(edge, "resolution") == "unresolved" {
                unresolved.set(edge_id, edge.clone());
                continue;
            }
            let next_id = str_field(edge, "to");
            let already_visited = visited.contains(&next_id);
            if !already_visited && current_depth >= max_depth {
                truncated = true;
                if reason.is_null() {
                    reason = json!("max_depth_reached");
                }
                continue;
            }
            if !already_visited && visited.len() as i64 >= max_nodes {
                truncated = true;
                reason = json!("max_nodes_reached");
                break;
            }
            selected_edges.set(edge_id, edge.clone());
            if already_visited {
                continue;
            }
            if !node_by_id.contains_key(&next_id) {
                truncated = true;
                if reason.is_null() {
                    reason = json!("edge_target_missing_from_graph");
                }
                continue;
            }
            visited.insert(next_id.clone());
            visited_order.push(next_id.clone());
            reached_depth = reached_depth.max(current_depth + 1);
            queue.push_back((next_id, current_depth + 1));
        }
        let reason_str = reason.as_str();
        if reason_str == Some("max_edges_reached") || reason_str == Some("max_nodes_reached") {
            break;
        }
    }

    let trace_nodes: Vec<Value> = visited_order
        .iter()
        .filter_map(|id| node_by_id.get(id).map(|node| (*node).clone()))
        .collect();

    let trace = json!({
        "target_sha256": graph["target_sha256"],
        "provider": graph["provider"],
        "start": start_id,
        "direction": "forward",
        "nodes": trace_nodes,
        "edges": selected_edges.into_values(),
        "unresolved": unresolved.into_values(),
        "reached_depth": reached_depth,
        "truncated": truncated,
        "reason": reason,
        "coverage": coverage,
        "limitations": [
            "Static analysis does not prove that an authored UI action is reachable or executed at runtime.",
            "Provider call graphs may omit unresolved indirect dispatch.",
        ],
    });
    parse_trace(&trace)
}

// --- joinInterfaceBuilderDispatch ------------------------------------------

/// `joinInterfaceBuilderDispatch(graph, metadata)`.
fn join_interface_builder_dispatch(
    graph: &Value,
    metadata: &Value,
) -> Result<Value, AnalysisError> {
    let empty: Vec<Value> = Vec::new();
    let graph_nodes = graph["nodes"].as_array().unwrap_or(&empty);
    let graph_edges = graph["edges"].as_array().unwrap_or(&empty);

    let mut nodes = OrderedMap::new();
    for node in graph_nodes {
        nodes.set(str_field(node, "id"), node.clone());
    }
    let mut edges: Vec<Value> = graph_edges.to_vec();
    let mut existing_edge_ids: HashSet<String> =
        edges.iter().map(|edge| str_field(edge, "id")).collect();

    // selectorNodesByAction: action id -> objc_selector node id.
    let mut selector_nodes_by_action: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for edge in &edges {
        if str_field(edge, "resolution") == "observed"
            && str_field(edge, "relation") == "target_action"
        {
            let to_id = str_field(edge, "to");
            if nodes.get(&to_id).map(node_kind).as_deref() == Some("objc_selector") {
                selector_nodes_by_action.insert(str_field(edge, "from"), to_id);
            }
        }
    }

    let dispatch_impls = metadata["objc_dispatch_implementations"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    let mut examined: i64 = 0;
    let mut resolved: i64 = 0;
    let mut inferred_without_owner_class: i64 = 0;

    // Iterate over nodes.values() snapshot (actions only).
    let action_nodes: Vec<Value> = nodes
        .values_snapshot()
        .into_iter()
        .filter(|node| node_kind(node) == "action")
        .collect();

    for action in &action_nodes {
        let selector = attr_str(action, "selector");
        let selector = match selector {
            Some(selector) if !selector.is_empty() => selector,
            _ => continue,
        };
        let action_id = str_field(action, "id");
        let Some(selector_node_id) = selector_nodes_by_action.get(&action_id).cloned() else {
            continue;
        };
        // destinationEdge: observed target_action from this action to a
        // view_controller/placeholder/external_object.
        let dest_kinds = ["view_controller", "placeholder", "external_object"];
        let destination_edge = edges.iter().find(|edge| {
            str_field(edge, "resolution") == "observed"
                && str_field(edge, "relation") == "target_action"
                && str_field(edge, "from") == action_id
                && {
                    let to_id = str_field(edge, "to");
                    let kind = nodes.get(&to_id).map(node_kind).unwrap_or_default();
                    dest_kinds.contains(&kind.as_str())
                }
        });
        let Some(destination_edge) = destination_edge else {
            continue;
        };
        let owner_id = str_field(destination_edge, "to");
        let owner = nodes.get(&owner_id).cloned();
        examined += 1;
        let declared_class = owner
            .as_ref()
            .and_then(|owner| attr_str(owner, "class_name"));
        let owner_kind = owner.as_ref().map(node_kind).unwrap_or_default();
        let class_name: Option<String> = match declared_class {
            Some(name) if !name.is_empty() && owner_kind == "view_controller" => Some(name),
            _ => None,
        };

        let candidates: Vec<Value> = dispatch_impls
            .iter()
            .filter(|candidate| {
                str_field(candidate, "method_type") == "instance"
                    && str_field(candidate, "selector") == selector
                    && match &class_name {
                        None => true,
                        Some(class_name) => {
                            strip_category_suffix(&str_field(candidate, "class_name"))
                                == *class_name
                        }
                    }
            })
            .cloned()
            .collect();
        let implementation = if candidates.len() == 1 {
            Some(candidates[0].clone())
        } else {
            None
        };
        let class_label = class_name.clone().unwrap_or_else(|| owner_id.clone());
        let class_or_unknown = class_name.clone().unwrap_or_else(|| {
            owner
                .as_ref()
                .map(|owner| str_field(owner, "id"))
                .unwrap_or_else(|| "unknown".to_owned())
        });
        let edge_id = format!("dispatch:{selector_node_id}:{class_or_unknown}:{selector}");
        if existing_edge_ids.contains(&edge_id) {
            continue;
        }
        existing_edge_ids.insert(edge_id.clone());

        let action_evidence = action["evidence"].as_array().cloned().unwrap_or_default();

        let impl_address = implementation
            .as_ref()
            .and_then(|implementation| implementation.get("implementation_address"))
            .filter(|value| !value.is_null())
            .and_then(Value::as_str)
            .map(str::to_owned);

        if implementation.is_none() || impl_address.is_none() {
            let mut evidence = action_evidence.clone();
            for candidate in &candidates {
                if let Some(entries) = candidate["evidence"].as_array() {
                    evidence.extend(entries.iter().cloned());
                }
            }
            let reason = if candidates.len() > 1 {
                "selector_has_multiple_candidate_implementations"
            } else {
                "implementation_not_resolved_from_binary_metadata_or_provider_symbols"
            };
            edges.push(json!({
                "id": edge_id,
                "from": selector_node_id,
                "to": Value::Null,
                "relation": "objc_dispatch",
                "resolution": "unresolved",
                "reason": reason,
                "evidence": evidence,
                "limitations": [
                    "A missing or ambiguous symbol match does not prove that the runtime implementation is absent.",
                ],
            }));
            continue;
        }

        let implementation = implementation.expect("checked");
        let impl_address = impl_address.expect("checked");
        let function_id = format!("native:function:{impl_address}");
        if !nodes.contains(&function_id) {
            let impl_class = str_field(&implementation, "class_name");
            let file_offset = implementation["location"]
                .get("file_offset")
                .cloned()
                .unwrap_or(Value::Null);
            let method_type = str_field(&implementation, "method_type");
            nodes.set(
                function_id.clone(),
                json!({
                    "id": function_id,
                    "kind": "function",
                    "name": format!("{impl_class} {selector}"),
                    "location": { "address": impl_address, "file_offset": file_offset },
                    "attributes": {
                        "class_name": impl_class,
                        "selector": selector,
                        "method_type": method_type,
                    },
                    "evidence": implementation["evidence"].clone(),
                }),
            );
        }
        let decode_status = implementation["decode"]
            .get("status")
            .and_then(Value::as_str);
        let resolution = if class_name.is_some() && decode_status == Some("decoded") {
            "resolved"
        } else {
            "inferred"
        };
        let mut evidence = action_evidence.clone();
        if let Some(entries) = implementation["evidence"].as_array() {
            evidence.extend(entries.iter().cloned());
        }
        let limitations = if class_name.is_none() {
            vec![json!(
                "The selector uniquely matches a encoded or symbolized method, but the Interface Builder receiver is an unresolved placeholder; runtime dispatch was not observed."
            )]
        } else {
            vec![json!(
                "The Interface Builder target and encoded or symbolized method agree on class and selector; runtime dispatch and dynamically supplied targets were not observed."
            )]
        };
        let _ = class_label;
        edges.push(json!({
            "id": edge_id,
            "from": selector_node_id,
            "to": function_id,
            "relation": "objc_dispatch",
            "resolution": resolution,
            "evidence": evidence,
            "limitations": limitations,
        }));
        resolved += 1;
        if class_name.is_none() {
            inferred_without_owner_class += 1;
        }
    }

    let coverage_status = if examined == resolved && inferred_without_owner_class == 0 {
        "complete"
    } else {
        "partial"
    };
    let coverage_reason = if examined == resolved && inferred_without_owner_class == 0 {
        Value::Null
    } else if inferred_without_owner_class > 0 {
        json!("some_action_receivers_remain_placeholders")
    } else {
        json!("some_action_implementations_not_resolved")
    };
    let mut coverage = graph["coverage"].as_array().cloned().unwrap_or_default();
    coverage.push(json!({
        "facet": "ui_to_objc_dispatch",
        "status": coverage_status,
        "reason": coverage_reason,
        "examined": examined,
        "omitted": examined - resolved + inferred_without_owner_class,
    }));

    let input = json!({
        "target_sha256": graph["target_sha256"],
        "provider": {
            "id": "rea-native-investigation",
            "version": Value::Null,
            "tool_version": "rea-native-investigation/1",
        },
        "nodes": nodes.into_values(),
        "edges": edges,
        "coverage": coverage,
        "truncated": graph["truncated"],
    });
    investigation_graph().parse(&input).map_err(|issue| {
        AnalysisError::output(
            "trace_native_ui_action",
            format!("joined graph does not satisfy its contract: {issue}"),
        )
    })
}

/// `selector.replace(/\([^)]*\)$/u, "")` — strip one trailing `(...)` group.
fn strip_category_suffix(name: &str) -> String {
    let bytes = name.as_bytes();
    if bytes.last() != Some(&b')') {
        return name.to_owned();
    }
    // Find the matching '(' for the final ')', with no ')' between it and end.
    // JS regex `\([^)]*\)$`: an open paren, then zero or more non-`)` chars,
    // then `)` at end of string.
    if let Some(open) = name.rfind('(') {
        let inner = &name[open + 1..name.len() - 1];
        if !inner.contains(')') {
            return name[..open].to_owned();
        }
    }
    name.to_owned()
}

// --- NativeCallRoutes -------------------------------------------------------

/// One provider-owned caveat tied to the operation that reported it.
struct SourceLimitation {
    provider_id: String,
    provider_name: String,
    provider_version: Option<String>,
    operation: String,
    limitation: String,
}

/// One resolved call route (`NativeCallRoute`).
struct NativeCallRoute {
    address: String,
    site: String,
    relation: String,
    resolution: String,
    provider: ProviderIdentity,
    call_reference: Option<Value>,
}

/// One unresolved call retained with its producing provider.
struct NativeCallUnknown {
    address: String,
    reason: String,
    provider: ProviderIdentity,
}

/// Result of `readNativeCallRoutes`.
struct NativeCallRouteRead {
    routes: Vec<NativeCallRoute>,
    unknowns: Vec<NativeCallUnknown>,
    limitations: Vec<SourceLimitation>,
    /// `Ok(())` success; `Err(error)` an enumeration failure that still keeps
    /// obtained facts.
    outcome: Result<(), AnalysisError>,
}

fn limitations_from(
    operation: &str,
    provider: &ProviderIdentity,
    limitations: &[String],
) -> Vec<SourceLimitation> {
    limitations
        .iter()
        .map(|limitation| SourceLimitation {
            provider_id: provider.id.clone(),
            provider_name: provider.name.clone(),
            provider_version: provider.version.clone(),
            operation: operation.to_owned(),
            limitation: limitation.clone(),
        })
        .collect()
}

/// `observedCallRoutes(references, provider)`.
fn observed_call_routes(references: &[Value], provider: &ProviderIdentity) -> Vec<NativeCallRoute> {
    // calls = references.filter(kind.available ? kind.call : call !== undefined)
    let calls: Vec<&Value> = references
        .iter()
        .filter(|reference| {
            let kind = &reference["kind"];
            let available = kind
                .get("available")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if available {
                kind.get("call").and_then(Value::as_bool).unwrap_or(false)
            } else {
                reference.get("call").is_some()
            }
        })
        .collect();

    // countBySite: source_address -> set of target_address.
    let mut count_by_site: std::collections::HashMap<String, HashSet<String>> =
        std::collections::HashMap::new();
    for call in &calls {
        count_by_site
            .entry(str_field(call, "source_address"))
            .or_default()
            .insert(str_field(call, "target_address"));
    }

    calls
        .iter()
        .map(|call| {
            let kind = &call["kind"];
            let available = kind
                .get("available")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let computed = kind
                .get("computed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let indirect = kind
                .get("indirect")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let source_address = str_field(call, "source_address");
            let target_address = str_field(call, "target_address");
            let address = match call["target_procedure"]
                .get("address")
                .and_then(Value::as_str)
            {
                Some(address) => address.to_owned(),
                None => target_address.clone(),
            };
            let call_reference =
                call.get("call")
                    .filter(|value| !value.is_null())
                    .map(|classification| {
                        // { ...call.call, source_address, target_address }
                        let mut object = classification.as_object().cloned().unwrap_or_default();
                        object.insert("source_address".into(), json!(source_address));
                        object.insert("target_address".into(), json!(target_address));
                        Value::Object(object)
                    });
            let relation = if !available {
                "provider_call"
            } else if computed || indirect {
                "indirect_call"
            } else {
                "direct_call"
            };
            let resolution = if !available {
                "observed"
            } else if count_by_site
                .get(&source_address)
                .map(HashSet::len)
                .unwrap_or(0)
                > 1
            {
                "ambiguous"
            } else if computed || indirect {
                "resolved"
            } else {
                "observed"
            };
            NativeCallRoute {
                address,
                site: source_address,
                relation: relation.to_owned(),
                resolution: resolution.to_owned(),
                provider: provider.clone(),
                call_reference,
            }
        })
        .collect()
}

/// `readNativeCallRoutes(analysis, procedure, signal, "provider")`.
fn read_native_call_routes(analysis: &Analysis<'_>, procedure: &str) -> NativeCallRouteRead {
    let mut routes: Vec<NativeCallRoute> = Vec::new();
    let mut unknowns: Vec<NativeCallUnknown> = Vec::new();
    let mut limitations: Vec<SourceLimitation> = Vec::new();

    let references_params = params([
        ("procedure", json!(procedure)),
        ("direction", json!("outgoing")),
    ]);
    let execution = analysis.execute(OP_REFERENCES, &references_params, true);

    let mut fall_through = true;
    match &execution {
        Ok(execution) => {
            limitations.extend(limitations_from(
                OP_REFERENCES,
                &execution.provider,
                &execution.limitations,
            ));
            let parsed = match native_call_routes_references().parse(&execution.result) {
                Ok(parsed) => parsed,
                Err(_) => {
                    return NativeCallRouteRead {
                        routes,
                        unknowns,
                        limitations,
                        outcome: Err(AnalysisError::output(
                            OP_REFERENCES,
                            "Invalid typed call references",
                        )),
                    };
                }
            };
            if let Some(entries) = parsed["unresolved_calls"].as_array() {
                for call in entries {
                    unknowns.push(NativeCallUnknown {
                        address: str_field(call, "address"),
                        reason: str_field(call, "reason"),
                        provider: execution.provider.clone(),
                    });
                }
            }
            let references = parsed["references"].as_array().cloned().unwrap_or_default();
            routes.extend(observed_call_routes(&references, &execution.provider));
            let every_available = references.iter().all(|reference| {
                reference["kind"]
                    .get("available")
                    .and_then(Value::as_bool)
                    .unwrap_or(false)
            });
            let reference_kinds_available = parsed["reference_kinds_available"]
                .as_bool()
                .unwrap_or(false);
            if every_available && (reference_kinds_available || !references.is_empty()) {
                fall_through = false;
            }
        }
        Err(error) => {
            if !is_capability_unavailable(error) {
                return NativeCallRouteRead {
                    routes,
                    unknowns,
                    limitations,
                    outcome: Err(clone_error(error)),
                };
            }
        }
    }

    if !fall_through {
        return NativeCallRouteRead {
            routes,
            unknowns,
            limitations,
            outcome: Ok(()),
        };
    }

    let callees_params = params([("procedure", json!(procedure))]);
    let callees = match analysis.execute(OP_CALLEES, &callees_params, true) {
        Ok(callees) => callees,
        Err(error) => {
            return NativeCallRouteRead {
                routes,
                unknowns,
                limitations,
                outcome: Err(error),
            };
        }
    };
    limitations.extend(limitations_from(
        OP_CALLEES,
        &callees.provider,
        &callees.limitations,
    ));
    let parsed = match parse_related_addresses(&callees.result, "callees", OP_CALLEES) {
        Ok(parsed) => parsed,
        Err(error) => {
            return NativeCallRouteRead {
                routes,
                unknowns,
                limitations,
                outcome: Err(error),
            };
        }
    };
    let mut targets: HashSet<String> = routes.iter().map(|route| route.address.clone()).collect();
    for address in parsed {
        if targets.contains(&address) {
            continue;
        }
        targets.insert(address.clone());
        routes.push(NativeCallRoute {
            address,
            site: procedure.to_owned(),
            relation: "provider_call".to_owned(),
            resolution: "inferred".to_owned(),
            provider: callees.provider.clone(),
            call_reference: None,
        });
    }

    NativeCallRouteRead {
        routes,
        unknowns,
        limitations,
        outcome: Ok(()),
    }
}

/// Reproduce an [`AnalysisError`] value by projecting and re-adopting it.
fn clone_error(error: &AnalysisError) -> AnalysisError {
    // `readNativeCallRoutes` returns the original error through the outcome; a
    // borrowed error cannot be moved, so adopt its projection.
    AnalysisError::from_projection(error.project())
}

// --- expandNativeCalls ------------------------------------------------------

struct Expanded {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    examined: i64,
    omitted: i64,
    truncated: bool,
    limitations: Vec<SourceLimitation>,
}

struct QueueEntry {
    node: Value,
    address: String,
    depth: i64,
}

/// `expandNativeCalls({ analysis, graph, initial, input, targetSha256 })`.
#[allow(clippy::too_many_arguments)]
fn expand_native_calls(
    analysis: &Analysis<'_>,
    _graph: &Value,
    initial: &Value,
    _action: &str,
    target_sha256: &str,
    max_depth: i64,
    max_nodes: i64,
    max_edges: i64,
) -> Result<Expanded, AnalysisError> {
    let empty: Vec<Value> = Vec::new();
    let initial_nodes = initial["nodes"].as_array().unwrap_or(&empty);
    let initial_edges = initial["edges"].as_array().unwrap_or(&empty);
    let initial_unresolved = initial["unresolved"].as_array().unwrap_or(&empty);
    let reached_depth = initial["reached_depth"].as_i64().unwrap_or(0);
    let start_id = str_field(initial, "start");

    let mut nodes = OrderedMap::new();
    for node in initial_nodes {
        nodes.set(str_field(node, "id"), node.clone());
    }
    let mut edges = OrderedMap::new();
    for edge in initial_edges.iter().chain(initial_unresolved.iter()) {
        edges.set(str_field(edge, "id"), edge.clone());
    }

    let depth_by_node = graph_node_depths(&start_id, initial_nodes, initial_edges);

    // addressNames: address -> name for function nodes with an address.
    let mut address_names: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    for node in nodes.values_snapshot() {
        if node_kind(&node) == "function" {
            let address = node["location"].get("address");
            if let Some(address) = address
                .filter(|value| !value.is_null())
                .and_then(Value::as_str)
            {
                address_names.insert(address.to_owned(), str_field(&node, "name"));
            }
        }
    }

    // queue = initial.nodes.flatMap(function nodes with an address).
    let mut queue: Vec<QueueEntry> = Vec::new();
    for node in initial_nodes {
        if node_kind(node) == "function" {
            let address = node["location"].get("address");
            if let Some(address) = address
                .filter(|value| !value.is_null())
                .and_then(Value::as_str)
            {
                let node_id = str_field(node, "id");
                let depth = depth_by_node
                    .get(&node_id)
                    .copied()
                    .unwrap_or(reached_depth);
                queue.push(QueueEntry {
                    node: node.clone(),
                    address: address.to_owned(),
                    depth,
                });
            }
        }
    }

    let mut visited: HashSet<String> = HashSet::new();
    let mut queue_index = 0usize;
    let mut examined: i64 = 0;
    let mut omitted: i64 = 0;
    let mut truncated = false;
    let mut source_limitations: Vec<SourceLimitation> = Vec::new();

    while queue_index < queue.len() {
        let current_index = queue_index;
        queue_index += 1;
        let current_address = queue[current_index].address.clone();
        let current_depth = queue[current_index].depth;
        let current_node_id = str_field(&queue[current_index].node, "id");
        if visited.contains(&current_address) {
            continue;
        }
        visited.insert(current_address.clone());
        if current_depth >= max_depth {
            truncated = true;
            omitted += 1;
            continue;
        }
        if nodes.len() as i64 >= max_nodes {
            truncated = true;
            omitted += (queue.len() - queue_index + 1) as i64;
            break;
        }
        let execution = read_native_call_routes(analysis, &current_address);
        examined += 1;
        source_limitations.append(&mut take_limitations(&execution.limitations));

        if let Err(error) = &execution.outcome {
            if is_cancellation(error) {
                return Err(clone_error(error));
            }
        }

        // Unknown (unresolved) edges.
        let unknowns_len = execution.unknowns.len();
        for (index, unknown) in execution.unknowns.iter().enumerate() {
            if edges.len() as i64 >= max_edges {
                truncated = true;
                omitted += (unknowns_len - index) as i64;
                break;
            }
            let id = format!("unknown-dispatch:{}:{}", current_address, unknown.address);
            edges.set(
                id.clone(),
                json!({
                    "id": id,
                    "from": current_node_id,
                    "to": Value::Null,
                    "relation": "indirect_call",
                    "resolution": "unresolved",
                    "reason": unknown.reason,
                    "evidence": [{
                        "kind": "reference",
                        "provider": provider_json(&unknown.provider),
                        "description": format!("{} reported an unresolved call: {}", unknown.provider.name, unknown.reason),
                        "location": { "address": unknown.address, "file_offset": Value::Null },
                        "artifact_path": Value::Null,
                        "artifact_sha256": target_sha256,
                    }],
                    "limitations": [],
                }),
            );
        }

        // Routes.
        let routes_len = execution.routes.len();
        for (index, route) in execution.routes.iter().enumerate() {
            let address = route.address.clone();
            let target_id = format!("native:function:{address}");
            let target_omitted = !nodes.contains(&target_id) && nodes.len() as i64 >= max_nodes;
            let prefix = if target_omitted {
                "unknown-node-bound"
            } else {
                "call"
            };
            let edge_id = format!(
                "{prefix}:{}:{}:{}:{}",
                current_address, route.site, address, route.relation
            );
            if !edges.contains(&edge_id) && edges.len() as i64 >= max_edges {
                truncated = true;
                omitted += (routes_len - index) as i64;
                break;
            }
            // evidence = edges.get(edgeId)?.evidence ?? []
            let mut evidence = edges
                .get(&edge_id)
                .and_then(|edge| edge["evidence"].as_array().cloned())
                .unwrap_or_default();
            let mut evidence_entry = Map::new();
            evidence_entry.insert("kind".into(), json!("reference"));
            evidence_entry.insert("provider".into(), provider_json(&route.provider));
            evidence_entry.insert(
                "description".into(),
                json!(format!(
                    "{} reported {} from {} to {}",
                    route.provider.name, route.relation, current_address, address
                )),
            );
            evidence_entry.insert(
                "location".into(),
                json!({ "address": route.site, "file_offset": Value::Null }),
            );
            if let Some(call_reference) = &route.call_reference {
                evidence_entry.insert("call_reference".into(), call_reference.clone());
            }
            evidence_entry.insert("artifact_path".into(), Value::Null);
            evidence_entry.insert("artifact_sha256".into(), json!(target_sha256));
            evidence.push(Value::Object(evidence_entry));

            if target_omitted {
                truncated = true;
                omitted += 1;
                edges.set(
                    edge_id.clone(),
                    json!({
                        "id": edge_id,
                        "from": current_node_id,
                        "to": Value::Null,
                        "relation": route.relation,
                        "resolution": "unresolved",
                        "reason": "native_trace_node_bound_reached",
                        "evidence": evidence,
                        "limitations": [],
                    }),
                );
                continue;
            }
            if !nodes.contains(&target_id) {
                let name = address_names
                    .get(&address)
                    .cloned()
                    .unwrap_or_else(|| address.clone());
                let node = json!({
                    "id": target_id,
                    "kind": "function",
                    "name": name,
                    "location": { "address": address, "file_offset": Value::Null },
                    "attributes": { "resolved_by": route.provider.id },
                    "evidence": evidence,
                });
                nodes.set(target_id.clone(), node.clone());
                queue.push(QueueEntry {
                    node,
                    address: address.clone(),
                    depth: current_depth + 1,
                });
            }
            edges.set(
                edge_id.clone(),
                json!({
                    "id": edge_id,
                    "from": current_node_id,
                    "to": target_id,
                    "relation": route.relation,
                    "resolution": route.resolution,
                    "evidence": evidence,
                    "limitations": ["A resolved static call edge does not establish runtime reachability."],
                }),
            );
        }

        // Enumeration failure fallback edge.
        if let Err(error) = &execution.outcome {
            if edges.len() as i64 >= max_edges {
                truncated = true;
                omitted += 1;
                continue;
            }
            let id = format!("unknown-callees:{current_address}");
            edges.set(
                id.clone(),
                json!({
                    "id": id,
                    "from": current_node_id,
                    "to": Value::Null,
                    "relation": "provider_call",
                    "resolution": "unresolved",
                    "reason": message_of(error),
                    "evidence": [],
                    "limitations": ["The provider could not complete callee enumeration."],
                }),
            );
        }
    }

    Ok(Expanded {
        nodes: nodes.into_values(),
        edges: edges.into_values(),
        examined,
        omitted,
        truncated,
        limitations: source_limitations,
    })
}

/// Move the limitations out of a borrowed slice into owned copies.
fn take_limitations(source: &[SourceLimitation]) -> Vec<SourceLimitation> {
    source
        .iter()
        .map(|limitation| SourceLimitation {
            provider_id: limitation.provider_id.clone(),
            provider_name: limitation.provider_name.clone(),
            provider_version: limitation.provider_version.clone(),
            operation: limitation.operation.clone(),
            limitation: limitation.limitation.clone(),
        })
        .collect()
}

fn provider_json(provider: &ProviderIdentity) -> Value {
    json!({ "id": provider.id, "name": provider.name, "version": provider.version })
}

/// `graphNodeDepths(start, nodes, edges)`.
fn graph_node_depths(
    start: &str,
    nodes: &[Value],
    edges: &[Value],
) -> std::collections::HashMap<String, i64> {
    let known: HashSet<String> = nodes.iter().map(|node| str_field(node, "id")).collect();
    let mut depths: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    depths.insert(start.to_owned(), 0);
    let mut queue: Vec<String> = vec![start.to_owned()];
    let mut index = 0usize;
    while index < queue.len() {
        let current = queue[index].clone();
        index += 1;
        let depth = depths.get(&current).copied().unwrap_or(0);
        for edge in edges {
            if str_field(edge, "resolution") == "unresolved" {
                continue;
            }
            if str_field(edge, "from") != current {
                continue;
            }
            if edge["to"].is_null() {
                continue;
            }
            let to = str_field(edge, "to");
            if !known.contains(&to) || depths.contains_key(&to) {
                continue;
            }
            depths.insert(to.clone(), depth + 1);
            queue.push(to);
        }
    }
    depths
}

/// `renderSourceLimitations`.
fn render_source_limitations(limitations: &[SourceLimitation]) -> Vec<String> {
    struct Group {
        provider_id: String,
        provider_name: String,
        provider_version: Option<String>,
        limitation: String,
        operations: Vec<String>,
    }
    let mut groups: Vec<(String, Group)> = Vec::new();
    for fact in limitations {
        let key = serde_json::to_string(&json!([
            fact.provider_id,
            fact.provider_name,
            fact.provider_version,
            fact.limitation,
        ]))
        .unwrap_or_default();
        match groups.iter_mut().find(|(existing, _)| *existing == key) {
            Some((_, group)) => {
                if !group.operations.contains(&fact.operation) {
                    group.operations.push(fact.operation.clone());
                }
            }
            None => groups.push((
                key,
                Group {
                    provider_id: fact.provider_id.clone(),
                    provider_name: fact.provider_name.clone(),
                    provider_version: fact.provider_version.clone(),
                    limitation: fact.limitation.clone(),
                    operations: vec![fact.operation.clone()],
                },
            )),
        }
    }
    let mut rendered = groups
        .into_iter()
        .map(|(_, group)| {
            let version = group
                .provider_version
                .as_ref()
                .map_or_else(String::new, |version| format!(" {version}"));
            let mut operations = group.operations;
            operations.sort_by(|left, right| crate::js::compare_code_points(left, right));
            format!(
                "{} ({}{}) {}: {}",
                group.provider_name,
                group.provider_id,
                version,
                operations.join(", "),
                group.limitation
            )
        })
        .collect::<Vec<_>>();
    rendered.sort_by(|left, right| crate::js::compare_code_points(left, right));
    rendered
}
