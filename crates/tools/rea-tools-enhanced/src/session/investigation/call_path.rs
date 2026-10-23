//! `buildCallPath` (`src/domain/callPath.ts`) and the function-dossier Evidence
//! and relationship-coverage helpers it consumes
//! (`functionDossierEvidence.ts`, `functionCallCoverage.ts`,
//! `relationshipCoverage.ts`).

use super::{is_canonical_native_address, parse_native_address, parse_native_address_value};
use crate::derived::{invalid_value, parse_evidence};
use crate::domain::dossier::function_dossier;
use crate::js::compare_code_points;
use crate::zod::Schema;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

const OPERATION: &str = "build_call_path";

/// A `FunctionSnapshot` parsed from one `analyze_function` Evidence record.
pub(crate) struct FunctionSnapshot {
    evidence_id: String,
    subject: Value,
    provider: Value,
    dossier: Value,
    procedure_address: String,
    procedure_name: Option<String>,
    callees: Vec<String>,
    relationship_coverage: Value,
    limitations: Vec<String>,
}

/// `relationshipCoverageLimitations(coverage)`.
pub(crate) fn relationship_coverage_limitations(coverage: &Value) -> Vec<String> {
    match coverage.get("status").and_then(Value::as_str) {
        None => match coverage {
            Value::Null => vec!["Provider did not report relationship coverage.".to_owned()],
            _ => Vec::new(),
        },
        Some("complete") => Vec::new(),
        Some("partial") => coverage
            .get("limitations")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        Some("unknown") => coverage
            .get("reason")
            .and_then(Value::as_str)
            .map(|reason| vec![reason.to_owned()])
            .unwrap_or_default(),
        Some(_) => Vec::new(),
    }
}

/// `isCallerOnlyIncompleteCoverage(coverage)`.
fn is_caller_only_incomplete_coverage(coverage: &Value) -> bool {
    match coverage.get("status").and_then(Value::as_str) {
        Some("complete") => false,
        _ => {
            if let Some(directions) = coverage.get("limited_directions").and_then(Value::as_array) {
                return !directions.iter().any(|d| d.as_str() == Some("callees"));
            }
            coverage.get("status").and_then(Value::as_str) == Some("unknown")
                && coverage
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| {
                        reason.starts_with("Callers: ") && !reason.contains("Callees: ")
                    })
        }
    }
}

/// `uniqueSorted` of strings (`compareUnicodeCodePoints`).
fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut unique: Vec<String> = values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    unique.sort_by(|left, right| compare_code_points(left, right));
    unique
}

fn dossier_schema() -> &'static Schema {
    function_dossier()
}

/// `assessFunctionCallCoverage(coverage, dossier)` -> (blockers, diagnostics).
fn assess_function_call_coverage(coverage: &Value, dossier: &Value) -> (Vec<String>, Vec<String>) {
    let mut blockers = relationship_coverage_limitations(coverage);
    if let Some(items) = dossier.get("unresolved_calls").and_then(Value::as_array) {
        for item in items {
            let address = item
                .get("address")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let reason = item
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default();
            blockers.push(format!("Unresolved call at {address}: {reason}"));
        }
    }
    let blockers = unique_sorted(blockers);
    let diagnostics = unique_sorted(
        coverage
            .get("diagnostics")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    );
    (blockers, diagnostics)
}

/// `parseFunctionEvidence(input)`.
fn parse_function_evidence(input: &Value) -> Result<FunctionSnapshot, AnalysisError> {
    let evidence =
        parse_evidence(input).map_err(|error| invalid_value(OPERATION, error.to_string()))?;
    let value = evidence.value().clone();
    if value.get("operation").and_then(Value::as_str) != Some("analyze_function") {
        return Err(invalid_value(
            OPERATION,
            "Function comparison requires analyze_function Evidence",
        ));
    }
    let subject = value.get("subject").cloned().unwrap_or(Value::Null);
    if subject.is_null() {
        return Err(invalid_value(
            OPERATION,
            "Function comparison requires artifact-bound Evidence",
        ));
    }
    let normalized = value
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    let dossier = dossier_schema()
        .parse(&normalized)
        .map_err(|issue| invalid_value(OPERATION, describe_issue(&issue)))?;
    let coverage = value
        .get("relationship_coverage")
        .cloned()
        .unwrap_or(Value::Null);
    let (_blockers, _diagnostics) = assess_function_call_coverage(&coverage, &dossier);
    let mut limitations: Vec<String> = Vec::new();
    if let Some(items) = value.get("limitations").and_then(Value::as_array) {
        limitations.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    if let Some(items) = dossier.get("limitations").and_then(Value::as_array) {
        limitations.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
    }
    let limitations = unique_sorted(limitations);
    let procedure = dossier.get("procedure").cloned().unwrap_or(Value::Null);
    let procedure_address = procedure
        .get("address")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let procedure_name = procedure
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut callees = Vec::new();
    if let Some(items) = dossier.get("callees").and_then(Value::as_array) {
        for callee in items {
            callees.push(
                callee
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
    }
    Ok(FunctionSnapshot {
        evidence_id: evidence.id().to_owned(),
        subject,
        provider: value.get("provider").cloned().unwrap_or(Value::Null),
        dossier,
        procedure_address,
        procedure_name,
        callees,
        relationship_coverage: coverage,
        limitations,
    })
}

fn describe_issue(issue: &crate::zod::Issue) -> String {
    let location = if issue.path.is_empty() {
        "the document root".to_owned()
    } else {
        issue.path.join(".")
    };
    format!("at {location}: {}", issue.message)
}

/// Minimal directed caller-to-callee adjacency for call-path search.
#[derive(Default)]
struct CallGraph {
    successors: HashMap<String, Vec<String>>,
    predecessors: HashMap<String, Vec<String>>,
    successor_sets: HashMap<String, HashSet<String>>,
    predecessor_sets: HashMap<String, HashSet<String>>,
}

impl CallGraph {
    fn merge_node(&mut self, node: &str) {
        self.successors.entry(node.to_owned()).or_default();
        self.predecessors.entry(node.to_owned()).or_default();
        self.successor_sets.entry(node.to_owned()).or_default();
        self.predecessor_sets.entry(node.to_owned()).or_default();
    }

    fn merge_directed_edge(&mut self, source: &str, target: &str) {
        self.merge_node(source);
        self.merge_node(target);
        if self
            .successor_sets
            .get_mut(source)
            .unwrap()
            .insert(target.to_owned())
        {
            self.successors
                .get_mut(source)
                .unwrap()
                .push(target.to_owned());
        }
        if self
            .predecessor_sets
            .get_mut(target)
            .unwrap()
            .insert(source.to_owned())
        {
            self.predecessors
                .get_mut(target)
                .unwrap()
                .push(source.to_owned());
        }
    }

    fn has_node(&self, node: &str) -> bool {
        self.successors.contains_key(node)
    }

    fn out_degree(&self, node: &str) -> usize {
        self.successor_sets.get(node).map_or(0, HashSet::len)
    }

    fn out_neighbors(&self, node: &str) -> Vec<String> {
        self.successors.get(node).cloned().unwrap_or_default()
    }

    fn in_neighbors(&self, node: &str) -> Vec<String> {
        self.predecessors.get(node).cloned().unwrap_or_default()
    }
}

/// Insertion-ordered snapshot map (`ReadonlyMap<string, FunctionSnapshot>`).
struct Snapshots {
    order: Vec<String>,
    by_address: HashMap<String, FunctionSnapshot>,
}

impl Snapshots {
    fn get(&self, address: &str) -> Option<&FunctionSnapshot> {
        self.by_address.get(address)
    }

    fn contains(&self, address: &str) -> bool {
        self.by_address.contains_key(address)
    }

    fn values(&self) -> impl Iterator<Item = &FunctionSnapshot> {
        self.order
            .iter()
            .map(move |address| &self.by_address[address])
    }
}

/// `distancesToGoal(graph, goal)`.
fn distances_to_goal(graph: &CallGraph, goal: &str) -> HashMap<String, usize> {
    if !graph.has_node(goal) {
        return HashMap::new();
    }
    let mut depth = HashMap::new();
    depth.insert(goal.to_owned(), 0usize);
    let mut queue = VecDeque::new();
    queue.push_back(goal.to_owned());
    while let Some(node) = queue.pop_front() {
        let next = depth.get(&node).copied().unwrap_or(0) + 1;
        for neighbor in graph.in_neighbors(&node) {
            if !depth.contains_key(&neighbor) {
                depth.insert(neighbor.clone(), next);
                queue.push_back(neighbor);
            }
        }
    }
    depth
}

struct SearchState {
    reached: Vec<(String, usize)>,
    exhaustive: bool,
    limitations: Vec<String>,
}

/// `inspectSearch`.
fn inspect_search(
    graph: &CallGraph,
    snapshots: &Snapshots,
    start: &str,
    goal: &str,
) -> SearchState {
    if !graph.has_node(start) {
        return SearchState {
            reached: Vec::new(),
            exhaustive: false,
            limitations: vec![format!(
                "No analyze_function Evidence was supplied for start {start}"
            )],
        };
    }
    let mut reached: Vec<(String, usize)> = vec![(start.to_owned(), 0)];
    let mut reached_index: HashMap<String, usize> = HashMap::new();
    reached_index.insert(start.to_owned(), 0);
    let mut queue: Vec<String> = vec![start.to_owned()];
    let mut limitations: Vec<String> = Vec::new();
    let mut incomplete = false;
    let mut index = 0;
    while index < queue.len() {
        let node = queue[index].clone();
        index += 1;
        let depth = *reached_index.get(&node).unwrap_or(&0);
        let snapshot = snapshots.get(&node);
        if let Some(snapshot) = snapshot {
            let coverage = &snapshot.relationship_coverage;
            for limitation in &snapshot.limitations {
                limitations.push(limitation.clone());
            }
            if !coverage.is_null() {
                for limitation in relationship_coverage_limitations(coverage) {
                    limitations.push(limitation);
                }
                if let Some(diagnostics) = coverage.get("diagnostics").and_then(Value::as_array) {
                    for diagnostic in diagnostics.iter().filter_map(Value::as_str) {
                        limitations.push(diagnostic.to_owned());
                    }
                }
            }
            if node == goal {
                continue;
            }
            let callees_facet = snapshot
                .dossier
                .get("facet_availability")
                .and_then(|facet| facet.get("callees"));
            if let Some(callees) = callees_facet
                && callees.get("available").and_then(Value::as_bool) == Some(false)
            {
                if let Some(reason) = callees.get("reason").and_then(Value::as_str) {
                    limitations.push(reason.to_owned());
                }
                incomplete = true;
            }
            let incomplete_here = if coverage.is_null() {
                !snapshot.limitations.is_empty()
            } else {
                coverage.get("status").and_then(Value::as_str) != Some("complete")
                    && !is_caller_only_incomplete_coverage(coverage)
            };
            if incomplete_here {
                incomplete = true;
            }
        } else if node == goal {
            continue;
        }
        if snapshot.is_none() {
            limitations.push(format!(
                "No analyze_function Evidence covers reachable function {node}"
            ));
            incomplete = true;
            continue;
        }
        let mut neighbors = graph.out_neighbors(&node);
        neighbors.sort_by(|left, right| compare_code_points(left, right));
        for neighbor in neighbors {
            if !reached_index.contains_key(&neighbor) {
                reached_index.insert(neighbor.clone(), depth + 1);
                reached.push((neighbor.clone(), depth + 1));
                queue.push(neighbor);
            }
        }
    }
    SearchState {
        reached,
        exhaustive: !incomplete,
        limitations,
    }
}

/// `summarizeSearch(graph, reached)`.
fn summarize_search(graph: &CallGraph, reached: &[(String, usize)]) -> Value {
    let nodes = reached.len();
    let edges: usize = reached
        .iter()
        .map(|(node, _)| {
            if graph.has_node(node) {
                graph.out_degree(node)
            } else {
                0
            }
        })
        .sum();
    let depth_reached = reached.iter().map(|(_, depth)| *depth).max().unwrap_or(0);
    json!({ "nodes": nodes, "edges": edges, "depth_reached": depth_reached })
}

/// `enumeratePaths` — all shortest paths, candidate neighbors sorted by code point.
fn enumerate_paths(
    graph: &CallGraph,
    start: &str,
    goal: &str,
    goal_distances: &HashMap<String, usize>,
) -> Vec<Vec<String>> {
    let mut output: Vec<Vec<String>> = Vec::new();
    let mut path: Vec<String> = vec![start.to_owned()];
    let mut neighbor_cache: HashMap<String, Vec<String>> = HashMap::new();

    let frame = |node: &str, cache: &mut HashMap<String, Vec<String>>| -> Vec<String> {
        if let Some(candidates) = cache.get(node) {
            return candidates.clone();
        }
        let distance = goal_distances.get(node).copied();
        let mut candidates: Vec<String> = graph
            .out_neighbors(node)
            .into_iter()
            .filter(|neighbor| {
                distance.is_some_and(|distance| {
                    goal_distances.get(neighbor).copied() == distance.checked_sub(1)
                })
            })
            .collect();
        candidates.sort_by(|left, right| compare_code_points(left, right));
        cache.insert(node.to_owned(), candidates.clone());
        candidates
    };

    struct Pending {
        neighbors: Vec<String>,
        next_index: usize,
    }

    let mut pending: Vec<Pending> = vec![Pending {
        neighbors: frame(start, &mut neighbor_cache),
        next_index: 0,
    }];

    while !pending.is_empty() {
        if path.last().map(String::as_str) == Some(goal) {
            output.push(path.clone());
            pending.pop();
            path.pop();
            continue;
        }
        let current = pending.last_mut().unwrap();
        let neighbor = current.neighbors.get(current.next_index).cloned();
        let Some(neighbor) = neighbor else {
            pending.pop();
            path.pop();
            continue;
        };
        current.next_index += 1;
        let next_frame = frame(&neighbor, &mut neighbor_cache);
        path.push(neighbor);
        pending.push(Pending {
            neighbors: next_frame,
            next_index: 0,
        });
    }
    output
}

/// `snapshotLinks(snapshot)`.
fn snapshot_links(snapshot: Option<&FunctionSnapshot>) -> Result<Vec<String>, AnalysisError> {
    match snapshot {
        None => Err(invalid_value(
            OPERATION,
            "Every call-path claim requires supporting Evidence",
        )),
        Some(snapshot) => Ok(vec![snapshot.evidence_id.clone()]),
    }
}

/// `citePath(addresses, snapshots)`.
fn cite_path(addresses: &[String], snapshots: &Snapshots) -> Result<Value, AnalysisError> {
    let mut edges = Vec::new();
    for (index, source) in addresses.iter().enumerate() {
        if index + 1 >= addresses.len() {
            break;
        }
        let target = &addresses[index + 1];
        let links = snapshot_links(snapshots.get(source))?;
        edges.push(json!({
            "source": source,
            "target": target,
            "evidence_links": links,
        }));
    }
    let mut nodes = Vec::new();
    for (index, address) in addresses.iter().enumerate() {
        let snapshot = snapshots.get(address);
        let supporting = match snapshot {
            Some(snapshot) => Some(snapshot),
            None => {
                if index > 0 {
                    snapshots.get(&addresses[index - 1])
                } else {
                    None
                }
            }
        };
        let name = snapshot.and_then(|s| s.procedure_name.clone());
        let links = snapshot_links(supporting)?;
        nodes.push(json!({
            "address": address,
            "name": name,
            "evidence_links": links,
        }));
    }
    // evidence_links: `[...new Set(edges.flatMap(links).concat(nodes.flatMap(links)))]`
    // preserving first-seen order (no sort).
    let mut seen = HashSet::new();
    let mut links: Vec<String> = Vec::new();
    for item in edges.iter().chain(nodes.iter()) {
        if let Some(list) = item.get("evidence_links").and_then(Value::as_array) {
            for link in list.iter().filter_map(Value::as_str) {
                if seen.insert(link.to_owned()) {
                    links.push(link.to_owned());
                }
            }
        }
    }
    Ok(json!({
        "hops": edges.len(),
        "nodes": nodes,
        "edges": edges,
        "evidence_links": links,
    }))
}

/// `buildCallPath(input)`.
pub(crate) fn build_call_path(input: &Value) -> Result<Value, AnalysisError> {
    // `callPathInputSchema.parse(input)` — strict object with
    // functions (>=1 evidence records), start.address, goal.address.
    let object = input.as_object().ok_or_else(|| {
        invalid_value(
            OPERATION,
            "at the document root: Invalid input: expected object",
        )
    })?;
    // The framework already validated the inputSchema; defaults applied.
    let functions = object
        .get("functions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_value(OPERATION, "at functions: Invalid input: expected array"))?;
    if functions.is_empty() {
        return Err(invalid_value(
            OPERATION,
            "at functions: Too small: expected array to have more items",
        ));
    }
    let start = parse_address_or_fail(object.get("start").and_then(|s| s.get("address")))?;
    let goal = parse_address_or_fail(object.get("goal").and_then(|g| g.get("address")))?;

    // prepareCallGraph: parse snapshots -> assertCompatible -> start present.
    let snapshots = parse_snapshots(functions)?;
    assert_compatible(&snapshots)?;
    if !snapshots.contains(&start) {
        return Err(invalid_value(
            OPERATION,
            format!("No analyze_function Evidence was supplied for start {start}"),
        ));
    }
    let graph = create_graph(&snapshots)?;

    let search = inspect_search(&graph, &snapshots, &start, &goal);
    let goal_distances = distances_to_goal(&graph, &goal);
    let shortest_depth = goal_distances.get(&start).copied();

    let mut paths: Vec<Value> = Vec::new();
    if shortest_depth.is_some() {
        for path in enumerate_paths(&graph, &start, &goal, &goal_distances) {
            paths.push(cite_path(&path, &snapshots)?);
        }
    }
    let shortest_hops = paths
        .first()
        .and_then(|path| path.get("hops"))
        .and_then(Value::as_u64);
    let found = shortest_hops.is_some();
    let exhaustive = search.exhaustive;

    // resultContext
    let evidence_links = unique_evidence(&snapshots)?;
    let limitations = unique_sorted(search.limitations.iter().cloned());
    let explored = summarize_search(&graph, &search.reached);

    let mut result = Map::new();
    result.insert("start".into(), json!(start));
    result.insert("goal".into(), json!(goal));
    result.insert("explored".into(), explored);
    result.insert("evidence_links".into(), json!(evidence_links));
    result.insert("limitations".into(), json!(limitations));
    if found {
        result.insert("status".into(), json!("found"));
        result.insert("shortest_hops".into(), json!(shortest_hops));
        result.insert("search_scope".into(), json!({ "exhaustive": exhaustive }));
        result.insert("paths".into(), Value::Array(paths));
    } else {
        result.insert(
            "status".into(),
            json!(if exhaustive { "not_found" } else { "unknown" }),
        );
        result.insert("shortest_hops".into(), Value::Null);
        result.insert("search_scope".into(), json!({ "exhaustive": exhaustive }));
        result.insert("paths".into(), Value::Array(Vec::new()));
    }

    // callPathResultSchema.parse: the union selects by status; its shape order
    // is resultContextShape (start, goal, explored, evidence_links, limitations)
    // then status, shortest_hops, search_scope, paths. Reorder to schema shape.
    Ok(reorder_result(result))
}

/// Order the result object to the union member shape order Zod emits.
fn reorder_result(result: Map<String, Value>) -> Value {
    let mut ordered = Map::new();
    for key in [
        "start",
        "goal",
        "explored",
        "evidence_links",
        "limitations",
        "status",
        "shortest_hops",
        "search_scope",
        "paths",
    ] {
        if let Some(value) = result.get(key) {
            ordered.insert(key.into(), value.clone());
        }
    }
    Value::Object(ordered)
}

fn parse_address_or_fail(value: Option<&Value>) -> Result<String, AnalysisError> {
    value.and_then(parse_native_address_value).ok_or_else(|| {
        invalid_value(
            OPERATION,
            "at start.address: Invalid string: must match pattern",
        )
    })
}

/// `parseSnapshots(groups)` building the insertion-ordered map.
fn parse_snapshots(groups: &[Value]) -> Result<Snapshots, AnalysisError> {
    let mut order: Vec<String> = Vec::new();
    let mut by_address: HashMap<String, FunctionSnapshot> = HashMap::new();
    for group in groups {
        let snapshot = parse_function_evidence(group)?;
        let address = parse_native_address(&snapshot.procedure_address).ok_or_else(|| {
            invalid_value(
                OPERATION,
                "Function procedure address is not a native address",
            )
        })?;
        for callee in &snapshot.callees {
            if parse_native_address(callee).is_none() {
                return Err(invalid_value(
                    OPERATION,
                    "Callee address is not a native address",
                ));
            }
        }
        if by_address.contains_key(&address) {
            return Err(invalid_value(
                OPERATION,
                format!("Duplicate function Evidence for {address}"),
            ));
        }
        order.push(address.clone());
        by_address.insert(address, snapshot);
    }
    Ok(Snapshots { order, by_address })
}

/// `assertCompatible(snapshots)`.
fn assert_compatible(snapshots: &Snapshots) -> Result<(), AnalysisError> {
    let mut values = snapshots.values();
    let Some(first) = values.next() else {
        return Ok(());
    };
    let first_sha = first.subject.pointer("/digest/sha256");
    let first_format = first.subject.get("format");
    let first_arch = first.subject.get("architecture");
    let first_provider_id = first.provider.get("id");
    let first_provider_name = first.provider.get("name");
    let first_provider_version = first.provider.get("version");
    for snapshot in snapshots.values() {
        if snapshot.subject.pointer("/digest/sha256") != first_sha
            || snapshot.subject.get("format") != first_format
            || snapshot.subject.get("architecture") != first_arch
        {
            return Err(invalid_value(
                OPERATION,
                "Call-path Evidence mixes artifact subjects",
            ));
        }
        if snapshot.provider.get("id") != first_provider_id
            || snapshot.provider.get("name") != first_provider_name
            || snapshot.provider.get("version") != first_provider_version
        {
            return Err(invalid_value(
                OPERATION,
                "Call-path Evidence mixes providers",
            ));
        }
    }
    Ok(())
}

/// `createGraph(snapshots)`.
fn create_graph(snapshots: &Snapshots) -> Result<CallGraph, AnalysisError> {
    let mut graph = CallGraph::default();
    for address in &snapshots.order {
        let snapshot = &snapshots.by_address[address];
        graph.merge_node(address);
        for callee in &snapshot.callees {
            let callee_address = parse_native_address(callee).ok_or_else(|| {
                invalid_value(OPERATION, "Callee address is not a native address")
            })?;
            graph.merge_node(&callee_address);
            graph.merge_directed_edge(address, &callee_address);
        }
    }
    Ok(graph)
}

/// `uniqueEvidence(snapshots.values())`.
fn unique_evidence(snapshots: &Snapshots) -> Result<Vec<String>, AnalysisError> {
    let mut all: Vec<String> = Vec::new();
    for snapshot in snapshots.values() {
        all.extend(snapshot_links(Some(snapshot))?);
    }
    Ok(unique_sorted(all))
}

/// Parameter projection `{ start, goal }` used by the handler.
pub(crate) fn handler_parameters(input: &Value) -> Value {
    let start = input
        .get("start")
        .and_then(|s| s.get("address"))
        .and_then(parse_native_address_value)
        .unwrap_or_default();
    let goal = input
        .get("goal")
        .and_then(|g| g.get("address"))
        .and_then(parse_native_address_value)
        .unwrap_or_default();
    json!({ "start": start, "goal": goal })
}

/// Whether the canonical native address predicate accepts `value` (used by the
/// result schema validation, kept for completeness).
#[allow(dead_code)]
pub(crate) fn is_canonical(value: &str) -> bool {
    is_canonical_native_address(value)
}
