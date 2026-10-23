//! Reconstructs shortest native call paths from supplied function Evidence.
//!
//! This module deliberately consumes authenticated `analyze_function` records only. It
//! does not resolve addresses, execute a target, or infer edges from names. Missing
//! function dossiers and incomplete callee coverage remain explicit in the result.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "build_call_path";

const MAX_FUNCTIONS: usize = 65_536;
const MAX_PATHS: usize = 65_536;

#[derive(Clone)]
struct Snapshot {
    evidence_id: String,
    address: String,
    name: Option<String>,
    callees: Vec<String>,
    limitations: Vec<String>,
    callee_limitation: Option<String>,
    coverage: Option<Value>,
    subject: Value,
    provider: Value,
}

#[derive(Default)]
struct Graph {
    successors: BTreeMap<String, BTreeSet<String>>,
    predecessors: BTreeMap<String, BTreeSet<String>>,
}

impl Graph {
    fn node(&mut self, address: &str) {
        self.successors.entry(address.to_owned()).or_default();
        self.predecessors.entry(address.to_owned()).or_default();
    }

    fn edge(&mut self, source: &str, target: &str) {
        self.node(source);
        self.node(target);
        self.successors
            .entry(source.to_owned())
            .or_default()
            .insert(target.to_owned());
        self.predecessors
            .entry(target.to_owned())
            .or_default()
            .insert(source.to_owned());
    }
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("call-path input must be an object"))?;
    let functions = object
        .get("functions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("functions must be a non-empty array"))?;
    if functions.is_empty() || functions.len() > MAX_FUNCTIONS {
        return Err(invalid("functions count is outside the supported bound"));
    }
    parse_address(
        object
            .get("start")
            .and_then(Value::as_object)
            .and_then(|start| start.get("address"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("start.address is required"))?,
    )?;
    parse_address(
        object
            .get("goal")
            .and_then(Value::as_object)
            .and_then(|goal| goal.get("address"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("goal.address is required"))?,
    )?;
    Ok(())
}

pub fn build(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let functions = input
        .get("functions")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("functions is required"))?;
    let start = parse_address(
        input
            .pointer("/start/address")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;
    let goal = parse_address(
        input
            .pointer("/goal/address")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )?;

    let snapshots = parse_snapshots(functions)?;
    assert_compatible(&snapshots)?;

    if !snapshots.contains_key(&start) {
        return Err(invalid(&format!(
            "No analyze_function Evidence was supplied for start {start}"
        )));
    }
    let graph = create_graph(&snapshots);
    let (reached, exhaustive, limitations) = inspect_search(&graph, &snapshots, &start, &goal);
    let distances = distances_to_goal(&graph, &goal);
    let shortest = distances.get(&start).copied();
    let mut paths = Vec::new();
    if shortest.is_some() {
        enumerate_paths(&graph, &snapshots, &start, &goal, &distances, &mut paths);
    }
    if paths.len() > MAX_PATHS {
        paths.truncate(MAX_PATHS);
    }

    let evidence_links = snapshots
        .values()
        .map(|snapshot| snapshot.evidence_id.clone())
        .collect::<BTreeSet<_>>();
    let explored_edges = reached
        .iter()
        .map(|(address, _)| graph.successors.get(address).map_or(0, BTreeSet::len))
        .sum::<usize>();
    let explored_depth = reached.values().copied().max().unwrap_or(0);
    let mut result = json!({
        "start": start,
        "goal": goal,
        "explored": {"nodes": reached.len(), "edges": explored_edges, "depth_reached": explored_depth},
        "evidence_links": evidence_links,
        "limitations": limitations,
        "shortest_hops": shortest,
        "search_scope": {"exhaustive": exhaustive},
        "paths": paths,
    });
    result["status"] = if shortest.is_some() {
        Value::String("found".into())
    } else if exhaustive {
        Value::String("not_found".into())
    } else {
        Value::String("unknown".into())
    };
    Ok(result)
}

fn parse_snapshots(functions: &[Value]) -> Result<BTreeMap<String, Snapshot>, Failure> {
    let mut snapshots = BTreeMap::new();
    for evidence in functions {
        if evidence.get("operation").and_then(Value::as_str) != Some("analyze_function") {
            return Err(invalid(
                "Call-path Evidence requires analyze_function records",
            ));
        }
        let evidence_id = evidence
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("Function Evidence must include evidence_id"))?;
        let subject = evidence
            .get("subject")
            .filter(|value| !value.is_null())
            .ok_or_else(|| invalid("Call-path Evidence must be artifact-bound"))?;
        let provider = evidence
            .get("provider")
            .ok_or_else(|| invalid("Function Evidence must include provider identity"))?;
        let provider = json!({
            "id": provider.get("id").cloned().unwrap_or(Value::Null),
            "name": provider.get("name").cloned().unwrap_or(Value::Null),
            "version": provider.get("version").cloned().unwrap_or(Value::Null),
        });
        let result = evidence
            .get("normalized_result")
            .or_else(|| evidence.get("result"))
            .ok_or_else(|| invalid("Function Evidence must include normalized_result"))?;
        let dossier = result.get("dossier").unwrap_or(result);
        let procedure = dossier
            .get("procedure")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("Function Evidence dossier must include procedure"))?;
        let address = parse_address(
            procedure
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Function procedure address is required"))?,
        )?;
        if snapshots.contains_key(&address) {
            return Err(invalid(&format!(
                "Duplicate function Evidence for {address}"
            )));
        }
        let mut callees = Vec::new();
        if let Some(items) = dossier.get("callees").and_then(Value::as_array) {
            for callee in items {
                let callee_address = parse_address(
                    callee
                        .get("address")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("Callee address is required"))?,
                )?;
                callees.push(callee_address);
            }
        }
        callees.sort();
        callees.dedup();
        let mut limitations = strings(evidence.get("limitations"));
        limitations.extend(strings(dossier.get("limitations")));
        limitations.sort();
        limitations.dedup();
        let callee_limitation = dossier
            .pointer("/facet_availability/callees")
            .and_then(Value::as_object)
            .and_then(|callees| {
                (callees.get("available").and_then(Value::as_bool) == Some(false)).then(|| {
                    callees
                        .get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("Callee relationships are unavailable.")
                        .to_owned()
                })
            });
        snapshots.insert(
            address.clone(),
            Snapshot {
                evidence_id: evidence_id.into(),
                address,
                name: procedure
                    .get("name")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                callees,
                limitations,
                callee_limitation,
                coverage: evidence.get("relationship_coverage").cloned(),
                subject: subject.clone(),
                provider: provider.clone(),
            },
        );
    }
    Ok(snapshots)
}

fn assert_compatible(snapshots: &BTreeMap<String, Snapshot>) -> Result<(), Failure> {
    let Some(first) = snapshots.values().next() else {
        return Ok(());
    };
    let first_digest = first.subject.pointer("/digest/sha256");
    let first_format = first.subject.get("format");
    let first_architecture = first.subject.get("architecture");
    for snapshot in snapshots.values().skip(1) {
        if snapshot.subject.pointer("/digest/sha256") != first_digest
            || snapshot.subject.get("format") != first_format
            || snapshot.subject.get("architecture") != first_architecture
        {
            return Err(invalid("Call-path Evidence mixes artifact subjects"));
        }
        if snapshot.provider != first.provider {
            return Err(invalid("Call-path Evidence mixes providers"));
        }
    }
    Ok(())
}

fn create_graph(snapshots: &BTreeMap<String, Snapshot>) -> Graph {
    let mut graph = Graph::default();
    for snapshot in snapshots.values() {
        graph.node(&snapshot.address);
        for callee in &snapshot.callees {
            graph.edge(&snapshot.address, callee);
        }
    }
    graph
}

fn inspect_search(
    graph: &Graph,
    snapshots: &BTreeMap<String, Snapshot>,
    start: &str,
    goal: &str,
) -> (BTreeMap<String, usize>, bool, Vec<String>) {
    let mut reached = BTreeMap::from([(start.to_owned(), 0)]);
    let mut queue = VecDeque::from([start.to_owned()]);
    let mut limitations = BTreeSet::new();
    let mut incomplete = false;
    while let Some(node) = queue.pop_front() {
        let depth = reached.get(&node).copied().unwrap_or(0);
        let Some(snapshot) = snapshots.get(&node) else {
            if node != goal {
                limitations.insert(format!(
                    "No analyze_function Evidence covers reachable function {node}"
                ));
                incomplete = true;
            }
            continue;
        };
        limitations.extend(snapshot.limitations.iter().cloned());
        if let Some(coverage) = &snapshot.coverage {
            match coverage.get("status").and_then(Value::as_str) {
                Some("partial") => {
                    if let Some(items) = coverage.get("limitations").and_then(Value::as_array) {
                        limitations
                            .extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
                    }
                }
                Some("unknown") => {
                    if let Some(reason) = coverage.get("reason").and_then(Value::as_str) {
                        limitations.insert(reason.to_owned());
                    }
                }
                _ => {}
            }
            if let Some(items) = coverage.get("diagnostics").and_then(Value::as_array) {
                limitations.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
            }
            let status = coverage.get("status").and_then(Value::as_str);
            let callee_limited = coverage
                .get("limited_directions")
                .and_then(Value::as_array)
                .is_some_and(|items| items.iter().any(|item| item.as_str() == Some("callees")));
            let caller_only_unknown = status == Some("unknown")
                && coverage.get("limited_directions").is_none()
                && coverage
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_some_and(|reason| {
                        reason.starts_with("Callers: ") && !reason.contains("Callees: ")
                    });
            if node != goal
                && status.is_some_and(|value| value != "complete")
                && (callee_limited
                    || (coverage.get("limited_directions").is_none() && !caller_only_unknown))
            {
                incomplete = true;
            }
        } else if node != goal && !snapshot.limitations.is_empty() {
            incomplete = true;
        }
        if node == goal {
            continue;
        }
        if let Some(reason) = &snapshot.callee_limitation {
            limitations.insert(reason.clone());
            incomplete = true;
        }
        for neighbor in graph.successors.get(&node).into_iter().flatten() {
            if !reached.contains_key(neighbor) {
                reached.insert(neighbor.clone(), depth + 1);
                queue.push_back(neighbor.clone());
            }
        }
    }
    (reached, !incomplete, limitations.into_iter().collect())
}

fn distances_to_goal(graph: &Graph, goal: &str) -> BTreeMap<String, usize> {
    if !graph.successors.contains_key(goal) {
        return BTreeMap::new();
    }
    let mut distances = BTreeMap::from([(goal.to_owned(), 0)]);
    let mut queue = VecDeque::from([goal.to_owned()]);
    while let Some(node) = queue.pop_front() {
        let next = distances[&node] + 1;
        for predecessor in graph.predecessors.get(&node).into_iter().flatten() {
            if !distances.contains_key(predecessor) {
                distances.insert(predecessor.clone(), next);
                queue.push_back(predecessor.clone());
            }
        }
    }
    distances
}

fn enumerate_paths(
    graph: &Graph,
    snapshots: &BTreeMap<String, Snapshot>,
    start: &str,
    goal: &str,
    distances: &BTreeMap<String, usize>,
    output: &mut Vec<Value>,
) {
    fn walk(
        graph: &Graph,
        snapshots: &BTreeMap<String, Snapshot>,
        node: &str,
        goal: &str,
        distances: &BTreeMap<String, usize>,
        path: &mut Vec<String>,
        output: &mut Vec<Value>,
    ) {
        if output.len() >= MAX_PATHS {
            return;
        }
        if node == goal {
            output.push(cite_path(path, snapshots));
            return;
        }
        let Some(distance) = distances.get(node) else {
            return;
        };
        if let Some(neighbors) = graph.successors.get(node) {
            for neighbor in neighbors {
                if distances.get(neighbor) == Some(&(distance - 1)) {
                    path.push(neighbor.clone());
                    walk(graph, snapshots, neighbor, goal, distances, path, output);
                    path.pop();
                }
            }
        }
    }
    let mut path = vec![start.to_owned()];
    walk(graph, snapshots, start, goal, distances, &mut path, output);
}

fn cite_path(path: &[String], snapshots: &BTreeMap<String, Snapshot>) -> Value {
    let nodes = path.iter().map(|address| {
        let snapshot = snapshots.get(address);
        let supporting = snapshot.or_else(|| {
            path.iter()
                .position(|item| item == address)
                .and_then(|index| index.checked_sub(1))
                .and_then(|index| path.get(index))
                .and_then(|previous| snapshots.get(previous))
        });
        json!({"address": address, "name": snapshot.and_then(|item| item.name.clone()), "evidence_links": supporting.map(|item| vec![item.evidence_id.clone()]).unwrap_or_default()})
    }).collect::<Vec<_>>();
    let edges = path.windows(2).map(|pair| {
        let source = &pair[0];
        json!({"source": source, "target": pair[1], "evidence_links": snapshots.get(source).map(|item| vec![item.evidence_id.clone()]).unwrap_or_default()})
    }).collect::<Vec<_>>();
    let mut links = BTreeSet::new();
    for node in &nodes {
        if let Some(items) = node.get("evidence_links").and_then(Value::as_array) {
            links.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
        }
    }
    json!({"hops": edges.len(), "nodes": nodes, "edges": edges, "evidence_links": links})
}

fn parse_address(value: &str) -> Result<String, Failure> {
    let separator = value.rfind(':').map(|index| index + 1).unwrap_or(0);
    let (space, raw) = value.split_at(separator);
    if !raw.starts_with("0x") && !raw.starts_with("0X") || raw.len() <= 2 {
        return Err(invalid("native address must be hexadecimal"));
    }
    let digits = &raw[2..];
    if !digits
        .chars()
        .all(|character| character.is_ascii_hexdigit())
    {
        return Err(invalid("native address must be hexadecimal"));
    }
    let number =
        u128::from_str_radix(digits, 16).map_err(|_| invalid("native address is out of range"))?;
    Ok(format!("{}0x{:x}", space, number))
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        true,
        "Correct the input and retry.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
