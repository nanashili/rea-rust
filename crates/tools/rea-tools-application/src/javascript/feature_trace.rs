//! `trace_application_feature`.
//!
//! Compatibility owners: `src/server/registerApplicationTools/traceFeature.ts`,
//! `traceApplicationFeatureEvidenceValidated` and
//! `src/domain/javascript/javascriptFeature{Trace,Seed,Traversal}.ts`,
//! `javascriptNativeHandoff.ts`.
use super::js::{array, text, unique_sorted};
use super::{graph_evidence, js, workflow_evidence};
use crate::support;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use unicode_normalization::UnicodeNormalization;

pub const OPERATION: &str = "trace_application_feature";

pub fn register(registry: &mut Registry) {
    registry.handle(OPERATION, handle);
}

fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let application = match graph_evidence::resolve_evidence_input(context, &input["application"]) {
        Ok(application) => application,
        Err(error) => return ToolOutput::Failure(error),
    };
    let native = array(&input["native_observations"]).to_vec();
    let evidence = trace(&application, &native, &input);
    let mut sources = vec![application];
    sources.extend(native);
    support::deliver(context.session, &sources, evidence)
}

/// `validateApplicationTraceIdentities`.
pub fn unique_identities(
    values: &[Value],
    field: &str,
    message: &str,
) -> Result<(), AnalysisError> {
    let mut seen = HashSet::new();
    if values
        .iter()
        .all(|value| seen.insert(text(value, "evidence_id")))
    {
        return Ok(());
    }
    Err(AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![json!(field)],
            reason: "invalid_value",
            message: Some(message.into()),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    ))
}

fn trace(application: &Value, native: &[Value], input: &Value) -> Result<Evidence, AnalysisError> {
    unique_identities(
        native,
        "native_observations",
        "Native observations must be unique",
    )?;
    let source =
        graph_evidence::parse_application_graph_evidence(application, &[json!("application")])
            .map_err(|issues| graph_evidence::input_error(OPERATION, issues))?;
    let native =
        graph_evidence::parse_native_application_evidence(native, &[json!("native_observations")])
            .map_err(|issues| graph_evidence::input_error(OPERATION, issues))?;
    let seed = normalize_seed(&input["seed"]);
    let direction = input["direction"].as_str().unwrap_or("both").to_owned();
    let result = trace_feature(
        source.evidence_id(),
        &source.graph,
        &native,
        &seed,
        &direction,
    )
    .map_err(|message| {
        AnalysisError::protocol(format!(
            "JavaScript application workflow failed while producing {OPERATION}: {message}"
        ))
    })?;
    let native_ids: Vec<&str> = native
        .iter()
        .map(|evidence| text(evidence, "evidence_id"))
        .collect();
    workflow_evidence::create(
        "rea.application-feature-trace",
        OPERATION,
        json!({
            "application_evidence_id": source.evidence_id(),
            "native_evidence_ids": native_ids,
            "seed": seed,
            "direction": direction,
        }),
        result,
    )
}

/// `applicationFeatureSeedSchema.parse`: declared defaults.
fn normalize_seed(seed: &Value) -> Value {
    let mut object = seed.as_object().cloned().unwrap_or_default();
    object.entry("match").or_insert(Value::Null);
    object.entry("case_sensitive").or_insert(json!(false));
    Value::Object(object)
}

fn digest(value: &Value) -> Result<String, String> {
    rea_core::canonical_json::digest(value).map_err(|error| error.to_string())
}

fn trace_feature(
    source_evidence_id: &str,
    graph: &Value,
    native: &[Value],
    seed: &Value,
    direction: &str,
) -> Result<Value, String> {
    let seed_matches = find_seeds(array(&graph["nodes"]), seed);
    let source_status = graph["coverage"]["status"].clone();
    let complete = source_status == "complete";
    let source_limitations: Vec<String> = if complete {
        Vec::new()
    } else {
        vec!["The source application graph is incomplete; unmatched seeds and frontiers remain unknown.".into()]
    };
    let mut semantic = Map::new();
    semantic.insert("source_evidence_id".into(), json!(source_evidence_id));
    semantic.insert("source_graph_id".into(), graph["graph_id"].clone());
    semantic.insert("seed".into(), seed.clone());
    semantic.insert("direction".into(), json!(direction));
    if seed_matches.is_empty() {
        semantic.insert("seed_matches".into(), json!([]));
        semantic.insert("graph".into(), Value::Null);
        semantic.insert("paths".into(), json!([]));
        semantic.insert("native_handoffs".into(), json!([]));
        semantic.insert(
            "summary".into(),
            json!({
                "matched_seeds": 0, "traced_nodes": 0, "traced_edges": 0, "terminal_paths": 0,
                "native_handoffs": 0, "observed_facts": 0, "inferred_facts": 0,
                "unknown_facts": 0, "unavailable_facts": 0,
            }),
        );
        semantic.insert(
            "coverage".into(),
            json!({"status": "no-match", "source_graph_status": source_status, "total_seed_matches": 0}),
        );
        semantic.insert("evidence_links".into(), json!([source_evidence_id]));
        let mut limitations = vec![
            "No graph entity matched the literal seed; this is not evidence that the feature is absent."
                .to_owned(),
        ];
        limitations.extend(source_limitations);
        semantic.insert("limitations".into(), json!(unique_sorted(limitations)));
        return finish(semantic);
    }
    let seed_ids: Vec<&str> = seed_matches
        .iter()
        .map(|matched| text(matched, "node_id"))
        .collect();
    let traversal = traverse(graph, &seed_ids, direction);
    // traceGraph
    let mut graph_limitations: Vec<String> = array(&graph["limitations"])
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    graph_limitations.push(
        "Trace edges retain their source authority; graph connectivity does not prove runtime execution or reachability."
            .into(),
    );
    let coverage = if complete {
        json!({"status": "complete", "truncated": false, "omitted_count": 0, "limits": []})
    } else {
        graph["coverage"].clone()
    };
    let mut trace_graph = Map::new();
    trace_graph.insert("schema".into(), json!("JavaScriptApplicationGraph"));
    trace_graph.insert(
        "root_node_ids".into(),
        json!(unique_sorted(seed_ids.iter().map(|id| (*id).to_owned()))),
    );
    trace_graph.insert("nodes".into(), json!(traversal.nodes));
    trace_graph.insert("edges".into(), json!(traversal.edges));
    trace_graph.insert("coverage".into(), coverage);
    trace_graph.insert(
        "limitations".into(),
        json!(unique_sorted(graph_limitations)),
    );
    let graph_id = format!("jag_{}", digest(&Value::Object(trace_graph.clone()))?);
    trace_graph.insert("graph_id".into(), json!(graph_id));
    let paths = terminal_paths(&traversal, &seed_ids)?;
    let handoffs = native_handoffs(&traversal.nodes, &traversal.edges, native);
    let mut links = vec![source_evidence_id.to_owned()];
    for handoff in &handoffs {
        links.extend(
            array(&handoff["evidence_ids"])
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    let mut states: BTreeMap<&str, usize> = BTreeMap::new();
    for node in &traversal.nodes {
        for observation in array(&node["observations"]) {
            *states
                .entry(text(&observation["evidence"], "state"))
                .or_default() += 1;
        }
    }
    for edge in &traversal.edges {
        *states.entry(text(&edge["evidence"], "state")).or_default() += 1;
    }
    let count = |state: &str| states.get(state).copied().unwrap_or(0);
    semantic.insert("seed_matches".into(), json!(seed_matches));
    semantic.insert("graph".into(), Value::Object(trace_graph));
    semantic.insert(
        "summary".into(),
        json!({
            "matched_seeds": seed_matches.len(),
            "traced_nodes": traversal.nodes.len(),
            "traced_edges": traversal.edges.len(),
            "terminal_paths": paths.len(),
            "native_handoffs": handoffs.len(),
            "observed_facts": count("observed"),
            "inferred_facts": count("inferred"),
            "unknown_facts": count("unknown"),
            "unavailable_facts": count("unavailable"),
        }),
    );
    semantic.insert("paths".into(), json!(paths));
    semantic.insert("native_handoffs".into(), json!(handoffs));
    semantic.insert(
        "coverage".into(),
        json!({
            "status": if complete { "complete-within-source" } else { "partial" },
            "source_graph_status": source_status,
            "total_seed_matches": seed_matches.len(),
        }),
    );
    semantic.insert("evidence_links".into(), json!(unique_sorted(links)));
    let mut limitations: Vec<String> = vec![
        "A trace reports graph relationships, not proof that code executed or that a feature is reachable in every state.".into(),
        "Static, native, passive-runtime, inferred, and unknown facts retain their original authority in the returned graph.".into(),
        "Native handoffs never open a binary or invoke a provider automatically; snapshot reuse remains provider/profile/target exact.".into(),
    ];
    limitations.extend(source_limitations);
    semantic.insert("limitations".into(), json!(unique_sorted(limitations)));
    finish(semantic)
}

fn finish(mut semantic: Map<String, Value>) -> Result<Value, String> {
    let id = format!("jatr_{}", digest(&Value::Object(semantic.clone()))?);
    semantic.insert("trace_id".into(), json!(id));
    Ok(Value::Object(semantic))
}

struct Traversal<'a> {
    nodes: Vec<&'a Value>,
    edges: Vec<&'a Value>,
    predecessors: HashMap<&'a str, (&'a str, &'a str)>,
}

/// `traverseApplicationFeature`.
fn traverse<'a>(graph: &'a Value, seeds: &[&'a str], direction: &str) -> Traversal<'a> {
    let node_by_id: HashMap<&str, &Value> = array(&graph["nodes"])
        .iter()
        .map(|node| (text(node, "node_id"), node))
        .collect();
    let mut adjacency: HashMap<&str, Vec<(&Value, &str)>> = HashMap::new();
    for edge in array(&graph["edges"]) {
        let source = text(edge, "source_node_id");
        let target = text(edge, "target_node_id");
        if direction != "incoming" {
            adjacency.entry(source).or_default().push((edge, target));
        }
        if direction != "outgoing" {
            adjacency.entry(target).or_default().push((edge, source));
        }
    }
    for entries in adjacency.values_mut() {
        entries.sort_by(|(left, left_next), (right, right_next)| {
            (text(left, "edge_id"), *left_next).cmp(&(text(right, "edge_id"), *right_next))
        });
    }
    let mut visited: HashSet<&str> = HashSet::new();
    let mut order: Vec<&str> = Vec::new();
    for seed in seeds {
        if visited.insert(seed) {
            order.push(seed);
        }
    }
    let mut retained: BTreeMap<&str, &Value> = BTreeMap::new();
    let mut predecessors = HashMap::new();
    // The queue holds the seed list including duplicates, as the original.
    let mut queue: Vec<&str> = seeds.to_vec();
    let mut offset = 0;
    while offset < queue.len() {
        let current = queue[offset];
        offset += 1;
        let Some(entries) = adjacency.get(current) else {
            continue;
        };
        for (edge, next) in entries {
            retained.insert(text(edge, "edge_id"), edge);
            if visited.contains(next) || !node_by_id.contains_key(next) {
                continue;
            }
            visited.insert(next);
            predecessors.insert(*next, (current, text(edge, "edge_id")));
            queue.push(next);
        }
    }
    let mut nodes: Vec<&Value> = visited
        .iter()
        .filter_map(|id| node_by_id.get(id).copied())
        .collect();
    nodes.sort_by(|left, right| text(left, "node_id").cmp(text(right, "node_id")));
    Traversal {
        nodes,
        edges: retained.into_values().collect(),
        predecessors,
    }
}

fn is_terminal(node: &Value) -> bool {
    matches!(
        text(node, "kind"),
        "endpoint" | "storage" | "native-addon" | "native-export" | "unknown"
    ) || (text(node, "kind") == "javascript-expression"
        && array(&node["observations"])
            .iter()
            .any(|observation| observation["properties"]["step_kind"] == "terminal"))
}

fn terminal_paths(traversal: &Traversal<'_>, seeds: &[&str]) -> Result<Vec<Value>, String> {
    let seed_ids: HashSet<&str> = seeds.iter().copied().collect();
    let edge_by_id: HashMap<&str, &Value> = traversal
        .edges
        .iter()
        .map(|edge| (text(edge, "edge_id"), *edge))
        .collect();
    let mut paths = Vec::new();
    for node in &traversal.nodes {
        let id = text(node, "node_id");
        if !is_terminal(node) || (seed_ids.contains(id) && traversal.nodes.len() != 1) {
            continue;
        }
        let mut node_ids = vec![id];
        let mut edge_ids = Vec::new();
        let mut current = id;
        while let Some((previous, edge)) = traversal.predecessors.get(current) {
            node_ids.push(previous);
            edge_ids.push(*edge);
            current = previous;
        }
        node_ids.reverse();
        edge_ids.reverse();
        let edges: Vec<&Value> = edge_ids
            .iter()
            .filter_map(|id| edge_by_id.get(id).copied())
            .collect();
        if edges.len() != edge_ids.len() {
            continue;
        }
        let semantic = json!({
            "start_node_id": node_ids[0],
            "end_node_id": id,
            "end_kind": node["kind"],
            "node_ids": node_ids,
            "edge_ids": edge_ids,
            "authorities": unique_sorted(edges.iter().map(|edge| text(&edge["evidence"], "authority").to_owned())),
            "contains_inference": edges.iter().any(|edge| edge["evidence"]["state"] == "inferred"),
        });
        let mut path = semantic.as_object().cloned().unwrap_or_default();
        path.insert(
            "path_id".into(),
            json!(format!("jatp_{}", digest(&semantic)?)),
        );
        paths.push(Value::Object(path));
    }
    paths.sort_by(|left, right| text(left, "path_id").cmp(text(right, "path_id")));
    Ok(paths)
}

/// `buildJavaScriptNativeHandoffs`.
fn native_handoffs(nodes: &[&Value], edges: &[&Value], native: &[Value]) -> Vec<Value> {
    let node_by_id: HashMap<&str, &Value> = nodes
        .iter()
        .map(|node| (text(node, "node_id"), *node))
        .collect();
    let mut handoffs: Vec<Value> = nodes
        .iter()
        .filter(|node| node["kind"] == "native-addon" && node["identity"]["strategy"] == "content-digest")
        .map(|node| {
            let digest = text(&node["identity"], "sha256");
            let linked: Vec<&Value> =
                native.iter().filter(|evidence| evidence["subject"]["digest"]["sha256"] == digest).collect();
            let id = text(node, "node_id");
            let mut export_ids: Vec<&str> = Vec::new();
            for edge in edges {
                let relation = text(edge, "relation");
                let candidate = if text(edge, "source_node_id") == id && matches!(relation, "contains" | "exposes") {
                    text(edge, "target_node_id")
                } else if text(edge, "target_node_id") == id && matches!(relation, "imports" | "loads") {
                    text(edge, "source_node_id")
                } else {
                    continue;
                };
                if !export_ids.contains(&candidate) {
                    export_ids.push(candidate);
                }
            }
            let mut exports: Vec<&Value> = export_ids
                .iter()
                .filter_map(|id| node_by_id.get(id).copied())
                .filter(|node| node["kind"] == "native-export")
                .collect();
            exports.sort_by(|left, right| text(left, "node_id").cmp(text(right, "node_id")));
            let mut requested: BTreeSet<String> = BTreeSet::new();
            for export in &exports {
                for observation in array(&export["observations"]) {
                    let properties = &observation["properties"];
                    if let Some(label) = observation["label"].as_str()
                        && !properties["requested_members"].is_array()
                    {
                        requested.insert(label.to_owned());
                    }
                    for key in ["requested_members", "members"] {
                        requested.extend(array(&properties[key]).iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                }
            }
            let artifact_path = array(&node["observations"])
                .iter()
                .map(|observation| &observation["evidence"]["location"])
                .find(|location| location["available"] == true && location["value"]["kind"] == "artifact-path")
                .map_or(Value::Null, |location| location["value"]["path"].clone());
            let mut providers: BTreeMap<String, Value> = BTreeMap::new();
            for evidence in &linked {
                let provider = &evidence["provider"];
                let key = format!(
                    "{}\0{}\0{}",
                    text(provider, "id"),
                    text(provider, "name"),
                    provider["version"].as_str().unwrap_or_default()
                );
                providers.insert(key, provider.clone());
            }
            let mut evidence_ids: Vec<&str> = linked.iter().map(|evidence| text(evidence, "evidence_id")).collect();
            evidence_ids.sort();
            json!({
                "native_node_id": id,
                "artifact_sha256": digest,
                "artifact_path": artifact_path,
                "export_node_ids": exports.iter().map(|node| text(node, "node_id")).collect::<Vec<_>>(),
                "requested_exports": requested,
                "status": if linked.is_empty() { "requires-provider-analysis" } else { "evidence-linked" },
                "providers": providers.into_values().collect::<Vec<_>>(),
                "evidence_ids": evidence_ids,
                "recommended_tools": ["open_binary", "binary_overview", "search_procedures", "analyze_function", "xrefs"],
            })
        })
        .collect();
    handoffs.sort_by(|left, right| text(left, "native_node_id").cmp(text(right, "native_node_id")));
    handoffs
}

// ---------------------------------------------------------------------------
// Seeds (`javascriptFeatureSeed.ts`)
// ---------------------------------------------------------------------------

struct Candidate {
    basis: &'static str,
    field: String,
    selection_path: Option<String>,
    value: String,
}

fn normalize_text(value: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        value.nfc().collect()
    } else {
        value.nfkc().collect::<String>().to_lowercase()
    }
}

/// `findApplicationFeatureSeeds`.
fn find_seeds(nodes: &[Value], seed: &Value) -> Vec<Value> {
    let mut matches: Vec<Value> = nodes
        .iter()
        .filter_map(|node| seed_match(node, seed))
        .collect();
    matches.sort_by(|left, right| {
        (
            text(left, "node_id"),
            text(left, "basis"),
            text(left, "field"),
        )
            .cmp(&(
                text(right, "node_id"),
                text(right, "basis"),
                text(right, "field"),
            ))
    });
    matches
}

fn seed_match(node: &Value, seed: &Value) -> Option<Value> {
    let kind = text(seed, "kind");
    let mode = seed["match"].as_str().unwrap_or(if kind == "string" {
        "contains"
    } else {
        "exact"
    });
    let case_sensitive = seed["case_sensitive"] == true;
    let query = normalize_text(text(seed, "value"), case_sensitive);
    if !kind_matches(node, kind) {
        return None;
    }
    if kind == "api"
        && let Some(requested) = seed["entry_path"].as_array()
        && !array(&node["observations"]).iter().any(|observation| {
            observation["properties"]["entry_path"]
                .as_array()
                .is_some_and(|path| {
                    path.len() == requested.len()
                        && path
                            .iter()
                            .zip(requested)
                            .all(|(a, b)| js::strict_equals(a, b))
                })
        })
    {
        return None;
    }
    let matched = candidate_fields(node, kind).into_iter().find(|candidate| {
        let value = normalize_text(&candidate.value, case_sensitive);
        if mode == "exact" {
            value == query
        } else {
            value.contains(&query)
        }
    })?;
    Some(json!({
        "node_id": node["node_id"],
        "kind": node["kind"],
        "basis": matched.basis,
        "field": matched.field,
    }))
}

fn kind_matches(node: &Value, kind: &str) -> bool {
    let node_kind = text(node, "kind");
    let any_property = |key: &str, value: &str| {
        array(&node["observations"])
            .iter()
            .any(|observation| observation["properties"][key] == value)
    };
    match kind {
        "string" | "node-id" => true,
        "route" => node_kind == "endpoint" && any_property("endpoint_kind", "route"),
        "api" => {
            node_kind == "context-bridge-api"
                || (node_kind == "javascript-expression" && any_property("step_kind", "exposure"))
        }
        "channel" => node_kind == "ipc-channel",
        "module" => matches!(
            node_kind,
            "javascript-asset" | "javascript-module" | "source-module"
        ),
        _ => node_kind == "native-export",
    }
}

const MEMBER_FIELD_SUFFIXES: &[&str] = &[".members", ".methods", ".exports", ".requested_members"];

fn relevant_fields(kind: &str) -> &'static [&'static str] {
    match kind {
        "route" => &[".label", ".value", ".path"],
        "api" => &[
            ".label",
            ".api_name",
            ".api_key",
            ".key",
            ".methods",
            ".members",
        ],
        "channel" => &[".label", ".channel", ".key"],
        "module" => &[
            ".label",
            ".module_key",
            ".path",
            ".source",
            ".original_source",
            ".source_root",
            ".exports",
        ],
        _ => &[".label", ".key", ".requested_members", ".members"],
    }
}

fn candidate_fields(node: &Value, kind: &str) -> Vec<Candidate> {
    if kind == "node-id" {
        return vec![Candidate {
            basis: "node-id",
            field: "node_id".into(),
            selection_path: None,
            value: text(node, "node_id").into(),
        }];
    }
    let observations = array(&node["observations"]);
    if kind == "route" {
        let mut fields = Vec::new();
        for (index, observation) in observations.iter().enumerate() {
            for key in ["value", "path"] {
                if let Some(value) = observation["properties"][key].as_str() {
                    fields.push(Candidate {
                        basis: "property",
                        field: format!("observations[{index}].properties.{key}"),
                        selection_path: None,
                        value: value.into(),
                    });
                }
            }
        }
        return fields;
    }
    let mut fields = identity_fields(node);
    for (index, observation) in observations.iter().enumerate() {
        if let Some(label) = observation["label"].as_str() {
            fields.push(Candidate {
                basis: "label",
                field: format!("observations[{index}].label"),
                selection_path: None,
                value: label.into(),
            });
        }
        let reference = &observation["source_map_reference"];
        if !reference.is_null() && reference["resolution"]["kind"] != "unresolved" {
            fields.push(Candidate {
                basis: "property",
                field: format!("observations[{index}].source_map_reference.resolution.path"),
                selection_path: None,
                value: text(&reference["resolution"], "path").into(),
            });
        }
        property_fields(
            &observation["properties"],
            &format!("observations[{index}].properties"),
            &mut fields,
        );
    }
    if kind == "string" {
        return fields;
    }
    let names = relevant_fields(kind);
    fields
        .into_iter()
        .filter(|candidate| {
            names.iter().any(|name| {
                let path = if MEMBER_FIELD_SUFFIXES.contains(name) {
                    candidate
                        .selection_path
                        .as_deref()
                        .unwrap_or(&candidate.field)
                } else {
                    &candidate.field
                };
                path == "identity" || path.ends_with(name)
            })
        })
        .collect()
}

fn identity_fields(node: &Value) -> Vec<Candidate> {
    let identity = &node["identity"];
    let field = |field: &str, value: &Value| Candidate {
        basis: "identity",
        field: field.into(),
        selection_path: None,
        value: value.as_str().unwrap_or_default().into(),
    };
    match text(identity, "strategy") {
        "content-digest" => vec![field("identity", &identity["sha256"])],
        "source-map-original" => {
            let mut fields = vec![field(
                "identity.original_source",
                &identity["original_source"],
            )];
            if !identity["source_root"].is_null() {
                fields.push(field("identity.source_root", &identity["source_root"]));
            }
            fields
        }
        "canonical-path" => vec![field("identity.path", &identity["path"])],
        "artifact-local-key" => vec![field("identity.key", &identity["key"])],
        "runtime-instance" => vec![field("identity.runtime_key", &identity["runtime_key"])],
        _ => Vec::new(),
    }
}

/// `propertyFields`: depth-first, keys in code-point order, arrays in order.
fn property_fields(value: &Value, prefix: &str, output: &mut Vec<Candidate>) {
    let mut pending: Vec<(&Value, String, String)> =
        vec![(value, prefix.to_owned(), prefix.to_owned())];
    while let Some((current, path, selection)) = pending.pop() {
        match current {
            Value::String(value) => output.push(Candidate {
                basis: "property",
                field: path,
                selection_path: Some(selection),
                value: value.clone(),
            }),
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate().rev() {
                    pending.push((item, format!("{path}[{index}]"), selection.clone()));
                }
            }
            Value::Object(object) => {
                let mut keys: Vec<&String> = object.keys().collect();
                keys.sort();
                for key in keys.into_iter().rev() {
                    pending.push((
                        &object[key],
                        format!("{path}.{key}"),
                        format!("{selection}.{key}"),
                    ));
                }
            }
            _ => {}
        }
    }
}
