//! Contract boundary for authenticated JavaScript semantic tracing.

use rea_core::canonical_json;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "trace_javascript_semantics";

const MAX_NODES: usize = 10_000;
const MAX_RELATIONS: usize = 20_000;

/// Execute a bounded query over the authenticated semantic graph carried by
/// an application Evidence record. Graph facts are returned verbatim so their
/// existing evidence references and unknown frontiers remain intact.
pub fn trace(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let application = input.get("application").expect("validated application");
    let evidence_id = application
        .get("evidence_id")
        .or_else(|| application.get("evidenceId"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("application Evidence must include evidence_id"))?;
    let graph = application
        .pointer("/normalized_result/semantic_graph")
        .or_else(|| application.pointer("/result/semantic_graph"))
        .ok_or_else(|| invalid("application Evidence has no semantic_graph"))?;
    let graph_id = graph
        .get("graph_id")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("semantic_graph.graph_id is required"))?;
    let query = input.get("query").expect("validated query");
    let seed = query.get("seed").expect("validated seed");
    let seed_ids = resolve_seeds(graph, seed)?;
    let direction = query["direction"].as_str().expect("validated direction");
    let allowed = query.get("allowed_relations").and_then(Value::as_array);
    let include_candidates = query
        .get("include_ambiguous_dynamic_edges")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let (node_ids, relation_ids, truncated) =
        traverse(graph, &seed_ids, direction, allowed, include_candidates);
    let nodes = values_by_ids(
        graph.get("nodes").and_then(Value::as_array),
        &node_ids,
        "node_id",
    );
    let relations = values_by_ids(
        graph.get("relations").and_then(Value::as_array),
        &relation_ids,
        "relation_id",
    );
    let unknowns = relevant_unknowns(graph, &node_ids, allowed, direction);
    let candidate_relations =
        relevant_candidate_relation_count(graph, &node_ids, allowed, direction);
    let contexts = retained_contexts(graph, &nodes, &relations, &unknowns);
    let expected_matches = expected_matches(query, &nodes, &relations);
    let query_id = format!(
        "jsrq_{}",
        canonical_json::digest(&json!({
            "source_graph_id": graph_id,
            "query": normalized_query_for_identity(query),
        }))
        .map_err(|error| invalid(&format!("cannot derive query identity: {error}")))?
    );
    let coverage_status = query_coverage_status(graph, &unknowns, candidate_relations, truncated);
    let status = query_status(
        graph,
        seed_ids.len(),
        !expected_matches.is_empty(),
        query.get("expected").is_some_and(|value| !value.is_null()),
        &unknowns,
        candidate_relations,
        truncated,
    );
    let limitations = query_limitations(graph, !unknowns.is_empty(), candidate_relations > 0);
    let (traversed_functions, traversed_modules) = owner_counts(&nodes);
    Ok(json!({
        "query_id": query_id,
        "source_graph_id": graph_id,
        "seed": seed,
        "direction": direction,
        "status": status,
        "seed_node_ids": seed_ids,
        "evidence_contexts": contexts,
        "nodes": nodes,
        "relations": relations,
        "unknowns": unknowns,
        "expected_match_node_ids": expected_matches,
        "summary": {
            "total_seed_matches": seed_ids.len(),
            "traversed_nodes": node_ids.len(),
            "traversed_relations": relation_ids.len(),
            "traversed_functions": traversed_functions,
            "traversed_modules": traversed_modules,
            "relevant_unknowns": unknowns.len()
        },
        "coverage": {"status": coverage_status},
        "limitations": limitations,
        "source_evidence_id": evidence_id,
        "evidence_links": [evidence_id]
    }))
}

fn query_status(
    graph: &Value,
    total_seeds: usize,
    has_expected_matches: bool,
    has_expectation: bool,
    unknowns: &[Value],
    candidate_relations: usize,
    truncated: bool,
) -> &'static str {
    if graph_coverage_status(graph) == "unavailable" {
        return "unsupported";
    }

    if candidate_relations > 0 {
        return "ambiguous";
    }

    if total_seeds == 0 || (has_expectation && !has_expected_matches) {
        return if query_is_uncertain(graph, unknowns, truncated) {
            "partial"
        } else {
            "no-match"
        };
    }

    if total_seeds > 1 {
        "ambiguous"
    } else {
        "found"
    }
}

fn query_coverage_status(
    graph: &Value,
    unknowns: &[Value],
    candidate_relations: usize,
    truncated: bool,
) -> &'static str {
    if graph_coverage_status(graph) == "unavailable" {
        return "unavailable";
    }

    if !unknowns.is_empty()
        || candidate_relations > 0
        || graph_coverage_status(graph) != "complete"
        || graph_coverage_truncated(graph)
        || truncated
    {
        "partial"
    } else {
        "complete"
    }
}

fn graph_coverage_status(graph: &Value) -> &str {
    graph
        .pointer("/coverage/status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
}

fn graph_coverage_truncated(graph: &Value) -> bool {
    graph
        .pointer("/coverage/truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn query_is_uncertain(graph: &Value, unknowns: &[Value], truncated: bool) -> bool {
    !unknowns.is_empty()
        || graph_coverage_status(graph) != "complete"
        || graph_coverage_truncated(graph)
        || truncated
}

fn query_limitations(graph: &Value, has_unknowns: bool, has_candidates: bool) -> Vec<String> {
    let mut limitations = BTreeSet::from([
        "Semantic graph reachability is a static inference and does not prove runtime execution."
            .to_owned(),
    ]);
    if let Some(graph_limitations) = graph.get("limitations").and_then(Value::as_array) {
        limitations.extend(
            graph_limitations
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }

    if has_unknowns {
        limitations.insert(
            "Relevant dynamic, unsupported, incomplete, or ambiguous semantics remain unknown."
                .to_owned(),
        );
    }

    if has_candidates {
        limitations.insert(
            "Candidate relations remain ambiguous and do not establish a resolved semantic path."
                .to_owned(),
        );
    }

    limitations.into_iter().collect()
}

fn owner_counts(nodes: &[Value]) -> (usize, usize) {
    let mut functions = BTreeSet::new();
    let mut modules = BTreeSet::new();

    for node in nodes {
        let function_id = if node["kind"] == "function" {
            node["node_id"].as_str()
        } else {
            node["function_node_id"].as_str()
        };
        if let Some(function_id) = function_id {
            functions.insert(function_id);
        }

        if let Some(module_path) = node
            .pointer("/identity/module_path")
            .and_then(Value::as_str)
        {
            modules.insert(module_path);
        }
    }

    (functions.len(), modules.len())
}

fn resolve_seeds(graph: &Value, seed: &Value) -> Result<Vec<String>, Failure> {
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .map_or(&[][..], |values| values);
    let kind = seed["kind"].as_str().unwrap_or_default();
    let mut matches = nodes
        .iter()
        .filter(|node| match kind {
            "semantic-node" => node["node_id"] == seed["node_id"],
            "application-node" => node["application_node_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id == &seed["node_id"])),
            "literal" => {
                node["kind"] == "literal" && property_matches(node, "value", &seed["value"])
            }
            "function" => {
                node["kind"] == "function"
                    && graph["fingerprints"].as_array().is_some_and(|fps| {
                        fps.iter().any(|fp| {
                            fp["function_node_id"] == node["node_id"]
                                && fp["fingerprint_sha256"] == seed["fingerprint_sha256"]
                        })
                    })
            }
            "property" => {
                node["kind"] == "property-slot" && property_matches(node, "name", &seed["name"])
            }
            "endpoint" => {
                matches!(node["kind"].as_str(), Some("request" | "response"))
                    && property_matches(node, "endpoint", &seed["value"])
            }
            "event" => {
                (node["kind"] == "event" || node["kind"] == "listener")
                    && property_matches(node, "event_name", &seed["name"])
            }
            "boundary-field" => {
                node["kind"] == "boundary" && property_matches(node, "field", &seed["field"])
            }
            _ => false,
        })
        .filter_map(|node| node["node_id"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    matches.sort();
    Ok(matches)
}

/// Reproduce the TypeScript query parser's defaults and canonical ordering
/// before deriving the graph-bound query identity. Omitting a defaulted field
/// must not create a second identity for the same semantic request, while
/// caller-selected relation and expected-class sets retain deterministic order.
fn normalized_query_for_identity(query: &Value) -> Value {
    let mut normalized = query.clone();
    let Some(object) = normalized.as_object_mut() else {
        return normalized;
    };

    if !object.contains_key("include_ambiguous_dynamic_edges") {
        object.insert("include_ambiguous_dynamic_edges".into(), json!(false));
    }
    if !object.contains_key("expected") {
        object.insert("expected".into(), Value::Null);
    }

    sort_string_array(object.get_mut("allowed_relations"));
    if let Some(expected) = object.get_mut("expected").and_then(Value::as_object_mut) {
        sort_string_array(expected.get_mut("classes"));
    }

    normalized
}

fn sort_string_array(value: Option<&mut Value>) {
    let Some(values) = value.and_then(Value::as_array_mut) else {
        return;
    };
    values.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
}

fn property_matches(node: &Value, key: &str, expected: &Value) -> bool {
    node["properties"]
        .get(key)
        .is_some_and(|value| value == expected)
}

fn traverse(
    graph: &Value,
    seeds: &[String],
    direction: &str,
    allowed: Option<&Vec<Value>>,
    include_candidates: bool,
) -> (BTreeSet<String>, BTreeSet<String>, bool) {
    let relations = graph
        .get("relations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut nodes = seeds.iter().cloned().collect::<BTreeSet<_>>();
    let mut relation_ids = BTreeSet::new();
    let mut queue = VecDeque::from(seeds.to_vec());
    let mut truncated = false;
    while let Some(current) = queue.pop_front() {
        for relation in &relations {
            if relation["resolution"] == "candidate" && !include_candidates {
                continue;
            }
            if !relation_allowed(relation, allowed) {
                continue;
            }
            let next = next_node(relation, &current, direction);
            let Some(next) = next else { continue };
            let relation_id = relation["relation_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            relation_ids.insert(relation_id);
            if relation_ids.len() > MAX_RELATIONS {
                truncated = true;
                break;
            }
            if nodes.insert(next.to_owned()) {
                queue.push_back(next.to_owned());
                if nodes.len() > MAX_NODES {
                    truncated = true;
                    break;
                }
            }
        }
        if truncated {
            break;
        }
    }
    (nodes, relation_ids, truncated)
}

fn relation_allowed(relation: &Value, allowed: Option<&Vec<Value>>) -> bool {
    allowed.is_none_or(|values| {
        values
            .iter()
            .any(|value| value.as_str() == relation["relation"].as_str())
    })
}

fn next_node<'a>(relation: &'a Value, current: &str, direction: &str) -> Option<&'a str> {
    let source = relation["source_node_id"].as_str()?;
    let target = relation["target_node_id"].as_str()?;
    match direction {
        "backward-provenance" if target == current => Some(source),
        "forward-influence" if source == current => Some(target),
        "callers" if relation["relation"] == "calls" && target == current => Some(source),
        "ownership"
            if relation["relation"]
                .as_str()
                .is_some_and(is_ownership_relation)
                && (source == current || target == current) =>
        {
            Some(if source == current { target } else { source })
        }
        _ => None,
    }
}

fn is_ownership_relation(relation: &str) -> bool {
    matches!(
        relation,
        "owns" | "captures" | "aggregates" | "creates-promise" | "returns-task" | "detaches-task"
    )
}

fn values_by_ids(values: Option<&Vec<Value>>, ids: &BTreeSet<String>, key: &str) -> Vec<Value> {
    values
        .map_or(&[][..], |values| values)
        .iter()
        .filter(|value| value[key].as_str().is_some_and(|id| ids.contains(id)))
        .cloned()
        .collect()
}

fn relevant_unknowns(
    graph: &Value,
    nodes: &BTreeSet<String>,
    allowed: Option<&Vec<Value>>,
    direction: &str,
) -> Vec<Value> {
    graph["unknowns"]
        .as_array()
        .map_or(&[][..], |values| values)
        .iter()
        .filter(|unknown| {
            (unknown["node_id"].is_null()
                || unknown["node_id"]
                    .as_str()
                    .is_some_and(|id| nodes.contains(id)))
                && unknown["relation_kinds"]
                    .as_array()
                    .is_some_and(|relations| {
                        relations.iter().any(|relation| {
                            relation.as_str().is_some_and(|relation| {
                                relation_name_allowed(relation, allowed)
                                    && direction_allows_relation(direction, relation)
                            })
                        })
                    })
        })
        .cloned()
        .collect()
}

fn relevant_candidate_relation_count(
    graph: &Value,
    nodes: &BTreeSet<String>,
    allowed: Option<&Vec<Value>>,
    direction: &str,
) -> usize {
    graph["relations"]
        .as_array()
        .map_or(&[][..], |relations| relations)
        .iter()
        .filter(|relation| {
            if relation["resolution"] != "candidate" || !relation_allowed(relation, allowed) {
                return false;
            }

            let source_is_relevant = relation["source_node_id"]
                .as_str()
                .is_some_and(|node_id| nodes.contains(node_id));
            let target_is_relevant = relation["target_node_id"]
                .as_str()
                .is_some_and(|node_id| nodes.contains(node_id));

            match direction {
                "callers" => relation["relation"] == "calls" && target_is_relevant,
                "ownership" => {
                    relation["relation"]
                        .as_str()
                        .is_some_and(is_ownership_relation)
                        && (source_is_relevant || target_is_relevant)
                }
                "backward-provenance" => target_is_relevant,
                "forward-influence" => source_is_relevant,
                _ => false,
            }
        })
        .count()
}

fn direction_allows_relation(direction: &str, relation: &str) -> bool {
    match direction {
        "callers" => relation == "calls",
        "ownership" => is_ownership_relation(relation),
        _ => true,
    }
}

fn relation_name_allowed(relation: &str, allowed: Option<&Vec<Value>>) -> bool {
    allowed.is_none_or(|values| values.iter().any(|value| value.as_str() == Some(relation)))
}

fn retained_contexts(
    graph: &Value,
    nodes: &[Value],
    relations: &[Value],
    unknowns: &[Value],
) -> Vec<Value> {
    let mut ids = BTreeSet::new();
    for fact in nodes.iter().chain(relations).chain(unknowns) {
        if let Some(id) = fact.pointer("/evidence/context_id").and_then(Value::as_str) {
            ids.insert(id);
        }
    }
    graph["evidence_contexts"]
        .as_array()
        .map_or(&[][..], |values| values)
        .iter()
        .filter(|context| {
            context["context_id"]
                .as_str()
                .is_some_and(|id| ids.contains(id))
        })
        .cloned()
        .collect()
}

fn expected_matches(query: &Value, nodes: &[Value], relations: &[Value]) -> Vec<String> {
    let Some(expected) = query.get("expected").filter(|value| !value.is_null()) else {
        return Vec::new();
    };
    let classes = expected["classes"]
        .as_array()
        .map_or(&[][..], |values| values);
    let connected = relations
        .iter()
        .filter_map(|relation| {
            if expected["role"] == "source" {
                relation["target_node_id"].as_str()
            } else {
                relation["source_node_id"].as_str()
            }
        })
        .collect::<BTreeSet<_>>();
    nodes
        .iter()
        .filter(|node| {
            classes.iter().any(|kind| kind == &node["kind"])
                && node["node_id"]
                    .as_str()
                    .is_some_and(|id| !connected.contains(id))
        })
        .filter_map(|node| node["node_id"].as_str().map(str::to_owned))
        .collect()
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("semantic trace input must be an object"))?;
    if object.get("application").is_none() {
        return Err(invalid("application Evidence is required"));
    }
    let query = object
        .get("query")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("query is required"))?;
    let seed = query
        .get("seed")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("query.seed is required"))?;
    let kind = seed
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("query.seed.kind is required"))?;
    if !matches!(
        kind,
        "semantic-node"
            | "application-node"
            | "literal"
            | "function"
            | "property"
            | "endpoint"
            | "event"
            | "boundary-field"
    ) {
        return Err(invalid("query.seed.kind is unsupported"));
    }
    let direction = query
        .get("direction")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("query.direction is required"))?;
    if !matches!(
        direction,
        "backward-provenance" | "forward-influence" | "callers" | "ownership"
    ) {
        return Err(invalid("query.direction is unsupported"));
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("semantic trace result must be an object"));
    }
    Ok(result)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated application Evidence and a bounded semantic query.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_authenticated_semantic_query() {
        let input = serde_json::json!({
            "application": {"evidence_id": "ev_application"},
            "query": {
                "seed": {"kind": "property", "name": "endpoint"},
                "direction": "backward-provenance"
            }
        });
        validate_input(&input).expect("query is valid");
        assert!(retain_result(&input, serde_json::json!({"status": "found"})).is_ok());
    }

    #[test]
    fn rejects_unknown_seed_and_direction() {
        let input = serde_json::json!({
            "application": {"evidence_id": "ev_application"},
            "query": {"seed": {"kind": "unknown"}, "direction": "execute"}
        });
        assert!(validate_input(&input).is_err());
    }

    fn graph_input() -> Value {
        let graph = serde_json::json!({
            "graph_id": "jsrg_graph",
            "nodes": [
                {
                    "node_id": "jsrg_node_source",
                    "kind": "request",
                    "identity": {"module_path": "main.js"},
                    "function_node_id": "jsrg_node_function",
                    "properties": {"url": "https://example.test"},
                    "evidence": {"context_id": "jsrg_evidence_source"}
                },
                {
                    "node_id": "jsrg_node_sink",
                    "kind": "boundary",
                    "identity": {"module_path": "main.js"},
                    "function_node_id": "jsrg_node_function",
                    "properties": {"field": "body"},
                    "evidence": {"context_id": "jsrg_evidence_sink"}
                },
                {
                    "node_id": "jsrg_node_function",
                    "kind": "function",
                    "identity": {"module_path": "main.js"},
                    "function_node_id": null,
                    "properties": {},
                    "evidence": {"context_id": "jsrg_evidence_function"}
                }
            ],
            "relations": [
                {
                    "relation_id": "jsrg_relation_link",
                    "source_node_id": "jsrg_node_source",
                    "target_node_id": "jsrg_node_sink",
                    "relation": "writes",
                    "resolution": "resolved",
                    "evidence": {"context_id": "jsrg_evidence_link"}
                }
            ],
            "unknowns": [
                {
                    "unknown_id": "jsrg_unknown_missing",
                    "node_id": "jsrg_node_sink",
                    "relation_kinds": ["calls"],
                    "evidence": {"context_id": "jsrg_evidence_unknown"}
                }
            ],
            "evidence_contexts": [
                {"context_id": "jsrg_evidence_source"},
                {"context_id": "jsrg_evidence_sink"},
                {"context_id": "jsrg_evidence_function"},
                {"context_id": "jsrg_evidence_link"},
                {"context_id": "jsrg_evidence_unknown"}
            ],
            "fingerprints": [],
            "coverage": {"status": "complete", "truncated": false},
            "limitations": []
        });
        serde_json::json!({
            "application": {"evidence_id": "ev_application", "normalized_result": {"semantic_graph": graph}},
            "query": {"seed":{"kind":"boundary-field","field":"body"},"direction":"backward-provenance"}
        })
    }

    #[test]
    fn traces_linked_facts_and_retains_provenance_contexts() {
        let result = trace(&graph_input()).expect("semantic trace");

        assert_eq!(result["status"], "found");
        assert_eq!(result["coverage"]["status"], "partial");
        assert_eq!(result["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(result["relations"][0]["relation"], "writes");
        assert_eq!(result["source_evidence_id"], "ev_application");
        assert_eq!(result["summary"]["traversed_functions"], 1);
        assert_eq!(result["summary"]["traversed_modules"], 1);
        assert_eq!(result["evidence_contexts"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn candidate_relation_makes_a_relevant_result_ambiguous() {
        let mut input = graph_input();
        input["application"]["normalized_result"]["semantic_graph"]["relations"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({
                "relation_id": "jsrg_relation_candidate",
                "source_node_id": "jsrg_node_source",
                "target_node_id": "jsrg_node_sink",
                "relation": "writes",
                "resolution": "candidate",
                "evidence": {"context_id": "jsrg_evidence_candidate"}
            }));

        let result = trace(&input).expect("semantic trace");

        assert_eq!(result["status"], "ambiguous");
        assert_eq!(result["coverage"]["status"], "partial");
        assert_eq!(result["summary"]["relevant_unknowns"], 1);
        assert_eq!(result["relations"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn unavailable_graph_coverage_remains_unsupported() {
        let mut input = graph_input();
        input["application"]["normalized_result"]["semantic_graph"]["coverage"]["status"] =
            serde_json::json!("unavailable");

        let result = trace(&input).expect("semantic trace");

        assert_eq!(result["status"], "unsupported");
        assert_eq!(result["coverage"]["status"], "unavailable");
    }

    #[test]
    fn reports_missing_seed_and_unresolved_frontier_without_inventing_facts() {
        let mut input = graph_input();
        input["query"]["seed"] = serde_json::json!({"kind":"property","name":"missing"});
        let result = trace(&input).expect("semantic trace");

        assert_eq!(result["status"], "no-match");
        assert!(result["nodes"].as_array().unwrap().is_empty());
        assert!(result["relations"].as_array().unwrap().is_empty());
        assert!(result["unknowns"].as_array().unwrap().is_empty());
    }
}
