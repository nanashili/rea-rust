//! Contract boundary for static JavaScript application feature tracing.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "trace_application_feature";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("application feature trace input must be an object"))?;

    evidence_id(object.get("application"), "application")?;

    if let Some(observations) = object.get("native_observations") {
        let observations = observations
            .as_array()
            .ok_or_else(|| invalid("native_observations must be an array"))?;
        validate_native_observation_ids(observations)?;
    }

    let seed = object
        .get("seed")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("seed must be an object"))?;
    let kind = seed
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| {
            matches!(
                *kind,
                "node-id" | "route" | "string" | "channel" | "module" | "native-export" | "api"
            )
        })
        .ok_or_else(|| invalid("seed.kind is unsupported"))?;
    let value = seed
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("seed.value must be a string"))?;
    let match_mode = seed.get("match").and_then(Value::as_str);
    if let Some(match_mode) = match_mode {
        if !matches!(match_mode, "exact" | "contains") {
            return Err(invalid("seed.match must be exact or contains"));
        }
    }
    if value.is_empty()
        && !matches!(kind, "route" | "string" | "channel" | "native-export")
        && !(matches!(kind, "api") && matches!(match_mode, Some("exact")))
    {
        return Err(invalid(
            "empty seed values require an explicit exact seed match",
        ));
    }
    if let Some(case_sensitive) = seed.get("case_sensitive") {
        if !case_sensitive.is_boolean() {
            return Err(invalid("seed.case_sensitive must be a boolean"));
        }
    }

    if let Some(direction) = object.get("direction") {
        let direction = direction
            .as_str()
            .ok_or_else(|| invalid("direction must be a string"))?;
        if !matches!(direction, "outgoing" | "incoming" | "both") {
            return Err(invalid("direction must be outgoing, incoming, or both"));
        }
    }

    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid(
            "application feature trace result must be an object",
        ));
    }
    Ok(result)
}

/// Derive a bounded feature trace from an authenticated application graph.
///
/// The graph producer owns parsing and node identity. This boundary only
/// selects matching nodes, traverses existing relationships, and carries the
/// original evidence IDs and source locations forward into the derived result.
pub fn trace_result(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let application = input
        .get("application")
        .ok_or_else(|| invalid("application Evidence is required"))?;
    let source_id = evidence_id(Some(application), "application")?.to_owned();
    let graph = application
        .get("normalized_result")
        .and_then(|result| result.get("graph"))
        .or_else(|| {
            application
                .get("result")
                .and_then(|result| result.get("graph"))
        })
        .ok_or_else(|| invalid("application Evidence must contain a JavaScript graph"))?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("application graph nodes must be an array"))?;
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("application graph edges must be an array"))?;
    let seed = input.get("seed").expect("validated seed");
    let matches = find_seed_matches(nodes, seed);
    let direction = input
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("both");
    let native = input.get("native_observations").and_then(Value::as_array);
    let mut result = if matches.is_empty() {
        no_match_result(&source_id, graph, seed, direction, native)
    } else {
        reachable_result(
            &source_id, graph, nodes, edges, &matches, seed, direction, native,
        )
    };
    result["evidence_links"] = Value::Array(evidence_links(
        &source_id,
        &result,
        input.get("native_observations").and_then(Value::as_array),
    ));
    Ok(result)
}

fn find_seed_matches(nodes: &[Value], seed: &Value) -> Vec<Value> {
    let kind = seed.get("kind").and_then(Value::as_str).unwrap_or_default();
    let query = seed
        .get("value")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let exact = seed.get("match").and_then(Value::as_str) != Some("contains")
        && !(seed.get("match").is_none() && kind == "string");
    let case_sensitive = seed
        .get("case_sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let normalized_query = normalize(query, case_sensitive);
    nodes.iter().filter_map(|node| {
        let node_kind = node.get("kind").and_then(Value::as_str).unwrap_or_default();
        if !kind_matches(kind, node_kind) { return None; }
        if kind == "route" && !node.get("observations").and_then(Value::as_array).is_some_and(|items| items.iter().any(|item| item.pointer("/properties/endpoint_kind").and_then(Value::as_str) == Some("route"))) { return None; }
        if kind == "api" && node_kind == "javascript-expression" && !node.get("observations").and_then(Value::as_array).is_some_and(|items| items.iter().any(|item| item.pointer("/properties/step_kind").and_then(Value::as_str) == Some("exposure"))) { return None; }
        if kind == "api" {
            if let Some(entry_path) = seed.get("entry_path").and_then(Value::as_array) {
                let matches_path = node.get("observations").and_then(Value::as_array).is_some_and(|items| items.iter().any(|item| item.pointer("/properties/entry_path").and_then(Value::as_array).is_some_and(|path| path == entry_path)));
                if !matches_path { return None; }
            }
        }
        let mut fields = Vec::new();
        if kind == "node-id" {
            fields.push(("node-id".to_owned(), "node_id".to_owned(), node.get("node_id").and_then(Value::as_str).unwrap_or_default().to_owned()));
        }
        if kind != "route" {
            append_identity_fields(node.get("identity"), &mut fields);
        }
        if let Some(observations) = node.get("observations").and_then(Value::as_array) {
            for (index, observation) in observations.iter().enumerate() {
                if kind != "route" {
                    if let Some(label) = observation.get("label").and_then(Value::as_str) {
                    fields.push(("label".into(), format!("observations[{index}].label"), label.into()));
                    }
                }
                let properties_path = format!("observations[{index}].properties");
                if kind == "route" {
                    for key in ["value", "path"] {
                        if let Some(value) = observation.pointer(&format!("/properties/{key}")).and_then(Value::as_str) {
                            fields.push(("property".into(), format!("{properties_path}.{key}"), value.into()));
                        }
                    }
                } else {
                    collect_strings(observation.get("properties"), &properties_path, &mut fields);
                }
                if let Some(source_map) = observation.get("source_map_reference") {
                    if source_map.pointer("/resolution/path").is_some()
                        && source_map.pointer("/resolution/kind").and_then(Value::as_str) != Some("unresolved")
                    {
                        if let Some(path) = source_map.pointer("/resolution/path").and_then(Value::as_str) {
                            fields.push(("property".into(), format!("observations[{index}].source_map_reference.resolution.path"), path.into()));
                        }
                    }
                }
            }
        }
        if kind != "string" {
            let allowed = match kind {
                "route" => &[".label", ".value", ".path"][..],
                "api" => &[".label", ".api_name", ".api_key", ".key", ".methods", ".members"][..],
                "channel" => &[".label", ".channel", ".key"][..],
                "module" => &[".label", ".module_key", ".path", ".source", ".original_source", ".source_root", ".exports"][..],
                "native-export" => &[".label", ".key", ".requested_members", ".members"][..],
                "node-id" => &["node_id"][..],
                _ => &[][..],
            };
            fields.retain(|(basis, field, _)| {
                basis == "identity" || allowed.iter().any(|suffix| field.ends_with(suffix))
            });
        }
        fields.into_iter().find(|(_, _, value)| {
            let value = normalize(value, case_sensitive);
            if exact { value == normalized_query } else { value.contains(&normalized_query) }
        }).map(|(basis, field, _)| serde_json::json!({"node_id":node.get("node_id"),"kind":node_kind,"basis":basis,"field":field}))
    }).collect()
}

fn reachable_result(
    source_id: &str,
    graph: &Value,
    nodes: &[Value],
    edges: &[Value],
    matches: &[Value],
    seed: &Value,
    direction: &str,
    native: Option<&Vec<Value>>,
) -> Value {
    let seeds: BTreeSet<String> = matches
        .iter()
        .filter_map(|m| m.get("node_id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let node_ids: BTreeSet<String> = nodes
        .iter()
        .filter_map(|n| n.get("node_id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let mut visited = seeds.clone();
    let mut queue: VecDeque<String> = seeds.iter().cloned().collect();
    let mut retained = BTreeMap::new();
    let mut predecessors: BTreeMap<String, (String, String)> = BTreeMap::new();
    while let Some(current) = queue.pop_front() {
        for edge in edges {
            let source = edge
                .get("source_node_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let target = edge
                .get("target_node_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let next = if direction != "incoming" && source == current {
                Some(target)
            } else if direction != "outgoing" && target == current {
                Some(source)
            } else {
                None
            };
            let Some(next) = next else { continue };
            retained.insert(
                edge.get("edge_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                edge.clone(),
            );
            if node_ids.contains(next) && visited.insert(next.to_owned()) {
                predecessors.insert(
                    next.to_owned(),
                    (
                        current.clone(),
                        edge.get("edge_id")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    ),
                );
                queue.push_back(next.to_owned());
            }
        }
    }
    let mut traced_nodes: Vec<Value> = nodes
        .iter()
        .filter(|node| {
            node.get("node_id")
                .and_then(Value::as_str)
                .is_some_and(|id| visited.contains(id))
        })
        .cloned()
        .collect();
    traced_nodes.sort_by(|left, right| {
        left.get("node_id")
            .and_then(Value::as_str)
            .cmp(&right.get("node_id").and_then(Value::as_str))
    });
    let traced_edges: Vec<Value> = retained.into_values().collect();
    let status = if graph
        .get("coverage")
        .and_then(|c| c.get("status"))
        .and_then(Value::as_str)
        == Some("complete")
    {
        "complete-within-source"
    } else {
        "partial"
    };
    json_result(
        source_id,
        graph,
        seed,
        direction,
        matches,
        traced_nodes,
        traced_edges,
        status,
        &predecessors,
        native,
    )
}

fn no_match_result(
    source_id: &str,
    graph: &Value,
    seed: &Value,
    direction: &str,
    native: Option<&Vec<Value>>,
) -> Value {
    json_result(
        source_id,
        graph,
        seed,
        direction,
        &[],
        Vec::new(),
        Vec::new(),
        "no-match",
        &BTreeMap::new(),
        native,
    )
}

fn json_result(
    source_id: &str,
    graph: &Value,
    seed: &Value,
    direction: &str,
    matches: &[Value],
    nodes: Vec<Value>,
    edges: Vec<Value>,
    status: &str,
    predecessors: &BTreeMap<String, (String, String)>,
    native: Option<&Vec<Value>>,
) -> Value {
    let graph_id = graph.get("graph_id").cloned().unwrap_or(Value::Null);
    let traced_node_values = nodes.clone();
    let traced_edge_values = edges.clone();
    let traced_graph = if nodes.is_empty() {
        Value::Null
    } else {
        let coverage = graph
            .get("coverage")
            .and_then(Value::as_object)
            .map(|coverage| {
                if coverage.get("status").and_then(Value::as_str) == Some("complete") {
                    json!({"status":"complete","truncated":false,"omitted_count":0,"limits":[]})
                } else {
                    Value::Object(coverage.clone())
                }
            })
            .unwrap_or_else(|| json!({"status":"unknown"}));
        let mut graph_limitations = graph
            .get("limitations")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        graph_limitations.push(json!("Trace edges retain their source authority; graph connectivity does not prove runtime execution or reachability."));
        serde_json::json!({"schema":"JavaScriptApplicationGraph","graph_id":graph_id.clone(),"root_node_ids":matches.iter().filter_map(|m|m.get("node_id")).collect::<Vec<_>>(),"nodes":traced_node_values,"edges":traced_edge_values,"coverage":coverage,"limitations":graph_limitations})
    };
    let source_status = graph
        .get("coverage")
        .and_then(|coverage| coverage.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let mut limitations = vec!["A trace reports graph relationships, not proof that code executed or that a feature is reachable in every state.".to_owned()];
    if source_status != "complete" {
        limitations.push("The source application graph is incomplete; unmatched seeds and frontiers remain unknown.".to_owned());
    }
    let native_handoffs = native_handoffs(&nodes, &edges, native);
    let paths = terminal_paths(&nodes, &edges, matches, predecessors);
    let facts = fact_summary(&nodes, &edges);
    let summary = serde_json::json!({"matched_seeds":matches.len(),"traced_nodes":nodes.len(),"traced_edges":edges.len(),"terminal_paths":paths.len(),"native_handoffs":native_handoffs.len(),"observed_facts":facts.0,"inferred_facts":facts.1,"unknown_facts":facts.2,"unavailable_facts":facts.3});
    let mut links = BTreeSet::from([source_id.to_owned()]);
    for handoff in &native_handoffs {
        collect_evidence_ids(handoff, &mut links);
    }
    limitations.push("Static, native, passive-runtime, inferred, and unknown facts retain their original authority in the returned graph.".to_owned());
    limitations.push("Native handoffs never open a binary or invoke a provider automatically; snapshot reuse remains provider/profile/target exact.".to_owned());
    let graph_limitations = graph
        .get("limitations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if source_status != "complete"
        || graph_limitations
            .iter()
            .any(|v| v.as_str() == Some("source truncated"))
    {
        limitations.push("The source application graph is incomplete; unmatched seeds and frontiers remain unknown.".to_owned());
    }
    limitations.sort_by(|left, right| left.cmp(right));
    limitations.dedup();
    let semantic = serde_json::json!({"source_evidence_id":source_id,"source_graph_id":graph_id.clone(),"seed":seed,"direction":direction,"seed_matches":matches,"graph":traced_graph,"paths":paths,"native_handoffs":native_handoffs,"summary":summary,"coverage":{"status":status,"source_graph_status":source_status,"total_seed_matches":matches.len()},"evidence_links":links.into_iter().map(Value::String).collect::<Vec<_>>(),"limitations":limitations});
    let digest = rea_core::canonical_json::digest(&semantic).unwrap_or_else(|_| "unknown".into());
    let mut output = semantic;
    output["trace_id"] = Value::String(format!("jatr_{digest}"));
    output
}

fn terminal_paths(
    nodes: &[Value],
    edges: &[Value],
    matches: &[Value],
    predecessors: &BTreeMap<String, (String, String)>,
) -> Vec<Value> {
    let seed_ids: BTreeSet<String> = matches
        .iter()
        .filter_map(|m| m.get("node_id").and_then(Value::as_str).map(str::to_owned))
        .collect();
    let edge_by_id: BTreeMap<String, &Value> = edges
        .iter()
        .filter_map(|edge| {
            edge.get("edge_id")
                .and_then(Value::as_str)
                .map(|id| (id.to_owned(), edge))
        })
        .collect();
    let mut paths = Vec::new();
    for node in nodes {
        let Some(node_id) = node.get("node_id").and_then(Value::as_str) else {
            continue;
        };
        let kind = node
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let terminal = matches!(
            kind,
            "endpoint" | "storage" | "native-addon" | "native-export" | "unknown"
        ) || (kind == "javascript-expression"
            && node
                .get("observations")
                .and_then(Value::as_array)
                .is_some_and(|observations| {
                    observations.iter().any(|o| {
                        o.pointer("/properties/step_kind").and_then(Value::as_str)
                            == Some("terminal")
                    })
                }));
        if !terminal || (seed_ids.contains(node_id) && nodes.len() != 1) {
            continue;
        }
        let mut node_ids = vec![node_id.to_owned()];
        let mut edge_ids = Vec::new();
        let mut current = node_id;
        while let Some((previous, edge_id)) = predecessors.get(current) {
            node_ids.push(previous.clone());
            edge_ids.push(edge_id.clone());
            current = previous;
        }
        node_ids.reverse();
        edge_ids.reverse();
        if edge_ids.iter().any(|id| !edge_by_id.contains_key(id)) {
            continue;
        }
        let authorities = edge_ids
            .iter()
            .filter_map(|id| edge_by_id.get(id))
            .filter_map(|edge| edge.pointer("/evidence/authority").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let contains_inference = edge_ids
            .iter()
            .filter_map(|id| edge_by_id.get(id))
            .any(|edge| {
                edge.pointer("/evidence/state").and_then(Value::as_str) == Some("inferred")
            });
        let semantic = json!({"start_node_id":node_ids.first().cloned().unwrap_or_else(|| node_id.to_owned()),"end_node_id":node_id,"end_kind":kind,"node_ids":node_ids,"edge_ids":edge_ids,"authorities":authorities,"contains_inference":contains_inference});
        let digest =
            rea_core::canonical_json::digest(&semantic).unwrap_or_else(|_| "unknown".into());
        let mut path = semantic;
        path["path_id"] = Value::String(format!("jatp_{digest}"));
        paths.push(path);
    }
    paths.sort_by(|left, right| {
        left.get("path_id")
            .and_then(Value::as_str)
            .cmp(&right.get("path_id").and_then(Value::as_str))
    });
    paths
}

fn native_handoffs(nodes: &[Value], edges: &[Value], native: Option<&Vec<Value>>) -> Vec<Value> {
    let native = native.cloned().unwrap_or_default();
    let mut output = Vec::new();
    for node in nodes
        .iter()
        .filter(|node| node.get("kind").and_then(Value::as_str) == Some("native-addon"))
    {
        let Some(node_id) = node.get("node_id").and_then(Value::as_str) else {
            continue;
        };
        let Some(digest) = node.pointer("/identity/sha256").and_then(Value::as_str) else {
            continue;
        };
        let linked = native
            .iter()
            .filter(|record| {
                record
                    .pointer("/subject/digest/sha256")
                    .and_then(Value::as_str)
                    == Some(digest)
            })
            .collect::<Vec<_>>();
        let export_ids = edges
            .iter()
            .filter_map(|edge| {
                let source = edge
                    .get("source_node_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let target = edge
                    .get("target_node_id")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let relation = edge
                    .get("relation")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let candidate = if source == node_id && matches!(relation, "contains" | "exposes") {
                    target
                } else if target == node_id && matches!(relation, "imports" | "loads") {
                    source
                } else {
                    return None;
                };
                nodes
                    .iter()
                    .find(|n| {
                        n.get("node_id").and_then(Value::as_str) == Some(candidate)
                            && n.get("kind").and_then(Value::as_str) == Some("native-export")
                    })
                    .and_then(|_| Some(candidate.to_owned()))
            })
            .collect::<BTreeSet<_>>();
        let mut requested = BTreeSet::new();
        for observation in nodes
            .iter()
            .filter(|n| {
                export_ids.contains(n.get("node_id").and_then(Value::as_str).unwrap_or_default())
            })
            .flat_map(|n| {
                n.get("observations")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
        {
            let has_structured_members = observation
                .pointer("/properties/requested_members")
                .is_some_and(Value::is_array);
            if !has_structured_members {
                if let Some(label) = observation.get("label").and_then(Value::as_str) {
                    requested.insert(label.to_owned());
                }
            }
            for key in ["requested_members", "members"] {
                if let Some(values) = observation
                    .pointer(&format!("/properties/{key}"))
                    .and_then(Value::as_array)
                {
                    requested.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
                }
            }
        }
        let evidence_ids = linked
            .iter()
            .filter_map(|r| r.get("evidence_id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<BTreeSet<_>>();
        let mut providers = linked
            .iter()
            .filter_map(|r| r.get("provider"))
            .cloned()
            .collect::<Vec<_>>();
        providers.sort_by_key(|provider| provider.to_string());
        providers.dedup();
        let artifact_path = node
            .get("observations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find_map(|observation| {
                observation
                    .pointer("/evidence/location/value/kind")
                    .and_then(Value::as_str)
                    .filter(|kind| *kind == "artifact-path")
                    .and_then(|_| observation.pointer("/evidence/location/value/path"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            });
        output.push(json!({"native_node_id":node_id,"artifact_sha256":digest,"artifact_path":artifact_path,"export_node_ids":export_ids,"requested_exports":requested,"status":if linked.is_empty(){"requires-provider-analysis"}else{"evidence-linked"},"providers":providers,"evidence_ids":evidence_ids,"recommended_tools":["open_binary","binary_overview","search_procedures","analyze_function","xrefs"]}));
    }
    output.sort_by(|left, right| {
        left.get("native_node_id")
            .and_then(Value::as_str)
            .cmp(&right.get("native_node_id").and_then(Value::as_str))
    });
    output
}

fn fact_summary(nodes: &[Value], edges: &[Value]) -> (usize, usize, usize, usize) {
    let mut counts = [0usize; 4];
    for evidence in nodes
        .iter()
        .flat_map(|node| node.get("observations"))
        .filter_map(Value::as_array)
        .flatten()
        .chain(edges.iter())
        .filter_map(|item| item.get("evidence"))
    {
        match evidence.get("state").and_then(Value::as_str) {
            Some("observed") => counts[0] += 1,
            Some("inferred") => counts[1] += 1,
            Some("unknown") => counts[2] += 1,
            Some("unavailable") => counts[3] += 1,
            _ => {}
        }
    }
    (counts[0], counts[1], counts[2], counts[3])
}

fn evidence_id<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_object)
        .and_then(|object| object.get("evidence_id"))
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must include evidence_id")))
}

fn validate_native_observation_ids(observations: &[Value]) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    for observation in observations {
        let id = evidence_id(Some(observation), "native observation")?;
        if !ids.insert(id) {
            return Err(invalid("native observation Evidence IDs must be unique"));
        }
    }
    Ok(())
}

fn kind_matches(seed: &str, node: &str) -> bool {
    match seed {
        "route" => node == "endpoint",
        "channel" => node == "ipc-channel",
        "module" => matches!(
            node,
            "javascript-asset" | "javascript-module" | "source-module"
        ),
        "api" => matches!(node, "context-bridge-api" | "javascript-expression"),
        "native-export" => node == "native-export",
        _ => true,
    }
}

fn normalize(value: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        value.to_owned()
    } else {
        value.to_lowercase()
    }
}

fn stringify_identity(identity: &Value) -> String {
    identity
        .as_object()
        .and_then(|object| object.values().find_map(Value::as_str))
        .map(str::to_owned)
        .unwrap_or_else(|| identity.to_string())
}

fn append_identity_fields(identity: Option<&Value>, fields: &mut Vec<(String, String, String)>) {
    let Some(identity) = identity.and_then(Value::as_object) else {
        return;
    };
    match identity.get("strategy").and_then(Value::as_str) {
        Some("content-digest") => {
            if let Some(value) = identity.get("sha256").and_then(Value::as_str) {
                fields.push(("identity".into(), "identity".into(), value.into()));
            }
        }
        Some("source-map-original") => {
            if let Some(value) = identity.get("original_source").and_then(Value::as_str) {
                fields.push((
                    "identity".into(),
                    "identity.original_source".into(),
                    value.into(),
                ));
            }
            if let Some(value) = identity.get("source_root").and_then(Value::as_str) {
                fields.push((
                    "identity".into(),
                    "identity.source_root".into(),
                    value.into(),
                ));
            }
        }
        Some("canonical-path") => {
            if let Some(value) = identity.get("path").and_then(Value::as_str) {
                fields.push(("identity".into(), "identity.path".into(), value.into()));
            }
        }
        Some("artifact-local-key") => {
            if let Some(value) = identity.get("key").and_then(Value::as_str) {
                fields.push(("identity".into(), "identity.key".into(), value.into()));
            }
        }
        Some("runtime-instance") => {
            if let Some(value) = identity.get("runtime_key").and_then(Value::as_str) {
                fields.push((
                    "identity".into(),
                    "identity.runtime_key".into(),
                    value.into(),
                ));
            }
        }
        _ => {
            fields.push((
                "identity".into(),
                "identity".into(),
                stringify_identity(&Value::Object(identity.clone())),
            ));
        }
    }
}

fn collect_strings(value: Option<&Value>, path: &str, fields: &mut Vec<(String, String, String)>) {
    match value {
        Some(Value::String(text)) => fields.push(("property".into(), path.into(), text.clone())),
        Some(Value::Array(values)) => values.iter().enumerate().for_each(|(index, value)| {
            collect_strings(Some(value), &format!("{path}[{index}]"), fields)
        }),
        Some(Value::Object(object)) => object.iter().for_each(|(key, value)| {
            collect_strings(Some(value), &format!("{path}.{key}"), fields)
        }),
        _ => {}
    }
}

fn evidence_links(source_id: &str, result: &Value, native: Option<&Vec<Value>>) -> Vec<Value> {
    let mut ids = BTreeSet::from([source_id.to_owned()]);
    for value in [result.get("graph"), result.get("paths")]
        .into_iter()
        .flatten()
    {
        collect_evidence_ids(value, &mut ids);
    }
    if let Some(native) = native {
        for observation in native {
            if let Some(id) = observation.get("evidence_id").and_then(Value::as_str) {
                ids.insert(id.to_owned());
            }
        }
    }
    ids.into_iter().map(Value::String).collect()
}

fn collect_evidence_ids(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(Value::Array(values)) = object.get("evidence_ids") {
                for id in values.iter().filter_map(Value::as_str) {
                    ids.insert(id.to_owned());
                }
            }
            object
                .values()
                .for_each(|value| collect_evidence_ids(value, ids));
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_evidence_ids(value, ids)),
        _ => {}
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide application Evidence, a typed feature seed, and an optional set of unique native observations.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "application": {"evidence_id": "ev_application"},
            "native_observations": [
                {"evidence_id": "ev_native"}
            ],
            "seed": {
                "kind": "route",
                "value": "/settings",
                "match": "exact",
                "case_sensitive": false
            },
            "direction": "both"
        })
    }

    #[test]
    fn accepts_typed_feature_trace_input() {
        validate_input(&input()).expect("valid feature trace input");
        assert!(retain_result(&input(), serde_json::json!({"paths": []})).is_ok());
    }

    #[test]
    fn rejects_duplicate_native_observation_identity() {
        let mut invalid_input = input();
        invalid_input["native_observations"] = serde_json::json!([
            {"evidence_id": "ev_native"},
            {"evidence_id": "ev_native"}
        ]);
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn accepts_explicit_empty_api_seed() {
        let mut invalid_input = input();
        invalid_input["seed"] = serde_json::json!({
            "kind": "api",
            "value": "",
            "match": "exact",
            "case_sensitive": false
        });
        assert!(validate_input(&invalid_input).is_ok());
    }

    #[test]
    fn rejects_unknown_trace_direction() {
        let mut invalid_input = input();
        invalid_input["direction"] = serde_json::json!("sideways");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn traces_matching_application_graph_and_links_native_evidence() {
        let input = serde_json::json!({
            "application": {
                "evidence_id": "ev_application",
                "normalized_result": {"graph": {
                    "graph_id": "jag_graph",
                    "nodes": [
                        {"node_id":"jag_route","kind":"endpoint","identity":{"path":"/settings"},"observations":[{"label":"settings","properties":{"path":"/settings"},"evidence":{"evidence_ids":["ev_source"]}}]},
                        {"node_id":"jag_store","kind":"storage","identity":{"key":"settings"},"observations":[{"label":"store","properties":{},"evidence":{"evidence_ids":["ev_store"]}}]}
                    ],
                    "edges": [{"edge_id":"jag_edge","source_node_id":"jag_route","target_node_id":"jag_store","relation":"persists_to","evidence":{"evidence_ids":["ev_edge"]}}],
                    "coverage":{"status":"complete"},"limitations":[]
                }}
            },
            "native_observations": [{"evidence_id":"ev_native"}],
            "seed":{"kind":"route","value":"/settings","match":"exact"},
            "direction":"outgoing"
        });
        let result = trace_result(&input).expect("trace succeeds");
        assert_eq!(result["coverage"]["status"], "complete-within-source");
        assert_eq!(result["summary"]["traced_nodes"], 2);
        assert_eq!(
            result["evidence_links"],
            serde_json::json!([
                "ev_application",
                "ev_edge",
                "ev_native",
                "ev_source",
                "ev_store"
            ])
        );
    }

    #[test]
    fn unresolved_seed_retains_uncertainty_and_source_link() {
        let mut input = input();
        input["application"] = serde_json::json!({
            "evidence_id": "ev_application",
            "normalized_result": {"graph": {
                "graph_id":"jag_graph", "nodes": [], "edges": [],
                "coverage":{"status":"partial"}, "limitations":["source truncated"]
            }}
        });
        let result = trace_result(&input).expect("unresolved trace succeeds");
        assert_eq!(result["coverage"]["status"], "no-match");
        assert!(result["graph"].is_null());
        assert_eq!(
            result["evidence_links"],
            serde_json::json!(["ev_application", "ev_native"])
        );
        assert!(
            result["limitations"][0]
                .as_str()
                .unwrap()
                .contains("not proof")
        );
    }
}
