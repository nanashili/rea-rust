//! `trace_javascript_semantics`.
//!
//! Compatibility owners: `src/server/registerApplicationTools/traceSemantics.ts`,
//! `src/application/javascript/JavaScriptSemanticTraceService.ts` and
//! `src/domain/javascript/javascriptSemanticQuery*.ts`.
use super::{graph_evidence, js, workflow_evidence};
use crate::support;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

pub const OPERATION: &str = "trace_javascript_semantics";

pub fn register(registry: &mut Registry) {
    registry.handle(OPERATION, handle);
}

fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let application = match graph_evidence::resolve_evidence_input(context, &input["application"]) {
        Ok(application) => application,
        Err(error) => return ToolOutput::Failure(error),
    };
    let evidence = trace(&application, &input["query"]);
    support::deliver(context.session, &[application], evidence)
}

fn trace(
    application: &Value,
    query: &Value,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let source =
        graph_evidence::parse_application_graph_evidence(application, &[json!("application")])
            .map_err(|issues| graph_evidence::input_error(OPERATION, issues))?;
    let Some(graph) = source.semantic_graph.as_ref() else {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![json!("application")],
                reason: "invalid_value",
                message: None,
                expected: Some(json!(
                    "inline Evidence from analyze_javascript_application with a semantic graph"
                )),
                minimum: None,
                maximum: None,
            }],
        ));
    };
    let query = normalize_query(query);
    let mut result = query_graph(graph, &query).map_err(|message| {
        AnalysisError::protocol(format!("JavaScript semantic trace failed: {message}"))
    })?;
    let evidence_id = source.evidence_id().to_owned();
    result.insert("source_evidence_id".into(), json!(evidence_id));
    result.insert("evidence_links".into(), json!([evidence_id]));
    let result = Value::Object(result);
    workflow_evidence::create(
        "rea.javascript-semantic-trace",
        OPERATION,
        json!({"application_evidence_id": evidence_id, "query": query}),
        result,
    )
}

/// `javaScriptSemanticQueryInputSchema.parse`: apply the declared defaults.
fn normalize_query(query: &Value) -> Value {
    let mut object = query.as_object().cloned().unwrap_or_default();
    object
        .entry("include_ambiguous_dynamic_edges")
        .or_insert(json!(false));
    object.entry("expected").or_insert(Value::Null);
    Value::Object(object)
}

fn str_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value[key].as_str().unwrap_or_default()
}

fn array(value: &Value) -> &[Value] {
    value.as_array().map(Vec::as_slice).unwrap_or_default()
}

const OWNERSHIP_RELATIONS: &[&str] = &[
    "acquires",
    "aggregates",
    "awaits",
    "chains",
    "connects-stdio",
    "creates-promise",
    "detaches-task",
    "owns",
    "releases",
    "returns-task",
    "spawns",
];

fn ownership(relation: &str) -> bool {
    OWNERSHIP_RELATIONS.contains(&relation)
}

/// `queryJavaScriptSemanticGraph`.
fn query_graph(graph: &Value, input: &Value) -> Result<Map<String, Value>, String> {
    let query_id = query_identifier(graph, input)?;
    let seeds = resolve_seeds(graph, input);
    let nodes: HashMap<&str, &Value> = array(&graph["nodes"])
        .iter()
        .map(|node| (str_of(node, "node_id"), node))
        .collect();
    let direction = str_of(input, "direction");
    let allowed: Option<HashSet<&str>> = input["allowed_relations"]
        .as_array()
        .map(|values| values.iter().filter_map(Value::as_str).collect());
    let include_candidates = input["include_ambiguous_dynamic_edges"].as_bool() == Some(true);
    // buildAdjacency
    let mut adjacency: HashMap<&str, Vec<(&Value, &str)>> = HashMap::new();
    for relation in array(&graph["relations"]) {
        let kind = str_of(relation, "relation");
        if allowed
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(kind))
        {
            continue;
        }
        if relation["resolution"] == "candidate" && !include_candidates {
            continue;
        }
        let source = str_of(relation, "source_node_id");
        let target = str_of(relation, "target_node_id");
        let mut add = |from, next| adjacency.entry(from).or_default().push((relation, next));
        match direction {
            "callers" => {
                if kind == "calls" {
                    add(target, source);
                }
            }
            "ownership" => {
                if ownership(kind) {
                    add(source, target);
                    add(target, source);
                }
            }
            "backward-provenance" => add(target, source),
            _ => add(source, target),
        }
    }
    // traverse
    let mut node_ids: Vec<&str> = Vec::new();
    let mut node_set: HashSet<&str> = HashSet::new();
    for seed in &seeds {
        if node_set.insert(seed.as_str()) {
            node_ids.push(seed.as_str());
        }
    }
    let mut relation_ids: HashSet<&str> = HashSet::new();
    let mut functions: HashSet<&str> = HashSet::new();
    let mut modules: HashSet<&str> = HashSet::new();
    fn owners<'a>(
        node: Option<&&'a Value>,
        functions: &mut HashSet<&'a str>,
        modules: &mut HashSet<&'a str>,
    ) {
        let Some(node) = node else { return };
        let function_id = if node["kind"] == "function" {
            node["node_id"].as_str()
        } else {
            node["function_node_id"].as_str()
        };
        if let Some(function_id) = function_id {
            functions.insert(function_id);
        }
        modules.insert(node["identity"]["module_path"].as_str().unwrap_or_default());
    }
    for id in &node_ids {
        owners(nodes.get(id), &mut functions, &mut modules);
    }
    let mut queue: Vec<&str> = node_ids.clone();
    let mut offset = 0;
    while offset < queue.len() {
        let current = queue[offset];
        offset += 1;
        let Some(entries) = adjacency.get(current) else {
            continue;
        };
        for (relation, next) in entries {
            relation_ids.insert(str_of(relation, "relation_id"));
            if node_set.contains(next) {
                continue;
            }
            let Some(node) = nodes.get(next) else {
                continue;
            };
            node_set.insert(next);
            owners(Some(node), &mut functions, &mut modules);
            queue.push(next);
        }
    }
    let retained_nodes: Vec<&Value> = array(&graph["nodes"])
        .iter()
        .filter(|node| node_set.contains(str_of(node, "node_id")))
        .collect();
    let retained_relations: Vec<&Value> = array(&graph["relations"])
        .iter()
        .filter(|relation| relation_ids.contains(str_of(relation, "relation_id")))
        .collect();
    let direction_allows = |relation: &str| match direction {
        "callers" => relation == "calls",
        "ownership" => ownership(relation),
        _ => true,
    };
    let unknowns: Vec<&Value> = array(&graph["unknowns"])
        .iter()
        .filter(|unknown| {
            (unknown["node_id"].is_null() || node_set.contains(str_of(unknown, "node_id")))
                && array(&unknown["relation_kinds"]).iter().any(|relation| {
                    let relation = relation.as_str().unwrap_or_default();
                    direction_allows(relation)
                        && allowed
                            .as_ref()
                            .is_none_or(|allowed| allowed.contains(relation))
                })
        })
        .collect();
    let candidate_relations = array(&graph["relations"])
        .iter()
        .filter(|relation| {
            let kind = str_of(relation, "relation");
            if relation["resolution"] != "candidate"
                || allowed
                    .as_ref()
                    .is_some_and(|allowed| !allowed.contains(kind))
            {
                return false;
            }
            let source = node_set.contains(str_of(relation, "source_node_id"));
            let target = node_set.contains(str_of(relation, "target_node_id"));
            (direction == "callers" && kind == "calls" && target)
                || (direction == "ownership" && ownership(kind) && (source || target))
                || (direction == "backward-provenance" && target)
                || (direction == "forward-influence" && source)
        })
        .count();
    let expected = &input["expected"];
    let expected_matches: Vec<&Value> = if expected.is_null() {
        Vec::new()
    } else {
        let classes: HashSet<&str> = array(&expected["classes"])
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let connected: HashSet<&str> = retained_relations
            .iter()
            .map(|relation| {
                if expected["role"] == "source" {
                    str_of(relation, "target_node_id")
                } else {
                    str_of(relation, "source_node_id")
                }
            })
            .collect();
        retained_nodes
            .iter()
            .copied()
            .filter(|node| {
                classes.contains(str_of(node, "kind"))
                    && !connected.contains(str_of(node, "node_id"))
            })
            .collect()
    };
    let contexts: HashSet<&str> = retained_nodes
        .iter()
        .chain(retained_relations.iter())
        .chain(unknowns.iter())
        .map(|fact| fact["evidence"]["context_id"].as_str().unwrap_or_default())
        .collect();
    // assessJavaScriptSemanticQuery
    let coverage_status = str_of(&graph["coverage"], "status");
    let truncated = graph["coverage"]["truncated"] == true;
    let uncertain = !unknowns.is_empty() || coverage_status != "complete" || truncated;
    let coverage = if coverage_status == "unavailable" {
        "unavailable"
    } else if uncertain || candidate_relations > 0 {
        "partial"
    } else {
        "complete"
    };
    let status = if coverage_status == "unavailable" {
        "unsupported"
    } else if candidate_relations > 0 {
        "ambiguous"
    } else if seeds.is_empty() || (!expected.is_null() && expected_matches.is_empty()) {
        if uncertain { "partial" } else { "no-match" }
    } else if seeds.len() > 1 {
        "ambiguous"
    } else {
        "found"
    };
    let mut limitations = vec![
        "Semantic graph reachability is a static inference and does not prove runtime execution."
            .to_owned(),
    ];
    limitations.extend(
        array(&graph["limitations"])
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned),
    );
    if !unknowns.is_empty() {
        limitations.push(
            "Relevant dynamic, unsupported, incomplete, or ambiguous semantics remain unknown."
                .into(),
        );
    }
    if candidate_relations > 0 {
        limitations.push(
            "Candidate relations remain ambiguous and do not establish a resolved semantic path."
                .into(),
        );
    }
    let mut result = Map::new();
    result.insert("query_id".into(), json!(query_id));
    result.insert("source_graph_id".into(), graph["graph_id"].clone());
    result.insert("seed".into(), input["seed"].clone());
    result.insert("direction".into(), json!(direction));
    result.insert("status".into(), json!(status));
    result.insert("seed_node_ids".into(), json!(seeds));
    result.insert(
        "evidence_contexts".into(),
        Value::Array(
            array(&graph["evidence_contexts"])
                .iter()
                .filter(|context| contexts.contains(str_of(context, "context_id")))
                .cloned()
                .collect(),
        ),
    );
    result.insert("nodes".into(), json!(retained_nodes));
    result.insert("relations".into(), json!(retained_relations));
    result.insert("unknowns".into(), json!(unknowns));
    result.insert(
        "expected_match_node_ids".into(),
        json!(
            expected_matches
                .iter()
                .map(|node| str_of(node, "node_id"))
                .collect::<Vec<_>>()
        ),
    );
    result.insert(
        "summary".into(),
        json!({
            "total_seed_matches": seeds.len(),
            "traversed_nodes": node_set.len(),
            "traversed_relations": relation_ids.len(),
            "traversed_functions": functions.len(),
            "traversed_modules": modules.len(),
            "relevant_unknowns": unknowns.len(),
        }),
    );
    result.insert("coverage".into(), json!({"status": coverage}));
    result.insert("limitations".into(), json!(js::unique_sorted(limitations)));
    Ok(result)
}

/// `javaScriptSemanticQueryIdentifier`.
fn query_identifier(graph: &Value, input: &Value) -> Result<String, String> {
    let mut semantic = Map::new();
    semantic.insert("source_graph_id".into(), graph["graph_id"].clone());
    for (key, value) in input.as_object().into_iter().flatten() {
        semantic.insert(key.clone(), value.clone());
    }
    if let Some(allowed) = input["allowed_relations"].as_array() {
        semantic.insert(
            "allowed_relations".into(),
            json!(js::unique_sorted_values(allowed)),
        );
    }
    if input["expected"].is_object() {
        let mut expected = input["expected"].as_object().cloned().unwrap_or_default();
        expected.insert(
            "classes".into(),
            json!(js::unique_sorted_values(array(
                &input["expected"]["classes"]
            ))),
        );
        semantic.insert("expected".into(), Value::Object(expected));
    }
    rea_core::canonical_json::digest(&Value::Object(semantic))
        .map(|digest| format!("jsrq_{digest}"))
        .map_err(|error| error.to_string())
}

/// `resolveJavaScriptSemanticQuerySeeds`.
fn resolve_seeds(graph: &Value, input: &Value) -> Vec<String> {
    let seed = &input["seed"];
    let kind = str_of(seed, "kind");
    let fingerprint_functions: HashSet<&str> = if kind == "function" {
        array(&graph["fingerprints"])
            .iter()
            .filter(|fingerprint| fingerprint["fingerprint_sha256"] == seed["fingerprint_sha256"])
            .map(|fingerprint| str_of(fingerprint, "function_node_id"))
            .collect()
    } else {
        HashSet::new()
    };
    let mut seeds: Vec<String> = array(&graph["nodes"])
        .iter()
        .filter(|node| {
            let node_kind = str_of(node, "kind");
            let properties = &node["properties"];
            match kind {
                "semantic-node" => node["node_id"] == seed["node_id"],
                "application-node" => {
                    array(&node["application_node_ids"]).contains(&seed["node_id"])
                }
                "function" => fingerprint_functions.contains(str_of(node, "node_id")),
                "literal" => {
                    node_kind == "literal"
                        && properties
                            .get("value")
                            .is_some_and(|value| js::strict_equals(value, &seed["value"]))
                }
                "property" => {
                    node_kind == "property-slot"
                        && properties
                            .get("name")
                            .is_some_and(|value| js::strict_equals(value, &seed["name"]))
                }
                "endpoint" => {
                    matches!(node_kind, "request" | "response")
                        && properties
                            .get("endpoint")
                            .is_some_and(|value| js::strict_equals(value, &seed["value"]))
                }
                "event" => {
                    matches!(node_kind, "event" | "listener")
                        && properties
                            .get("event_name")
                            .is_some_and(|value| js::strict_equals(value, &seed["name"]))
                }
                _ => {
                    node_kind == "boundary"
                        && properties
                            .get("field")
                            .is_some_and(|value| js::strict_equals(value, &seed["field"]))
                }
            }
        })
        .map(|node| str_of(node, "node_id").to_owned())
        .collect();
    seeds.sort();
    seeds
}
