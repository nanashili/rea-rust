//! Direct caller/callee path tracing between resolved procedures.
//!
//! Compatibility owner: `traceCallPath` (`CallPathTracing.ts`).
use crate::analysis::{Analysis, is_cancellation, params};
use crate::enhanced::batch::resolve_procedure_address;
use crate::enhanced::graph::{parse_related_addresses, traversal};
use crate::js::{compare_utf16, from_entries};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::HashMap;

struct Visit {
    depth: usize,
    path: Vec<String>,
}

struct Edge {
    source_address: String,
    target_address: String,
    discovery_depth: usize,
}

/// Insertion-ordered set of strings (`Set<string>`).
#[derive(Default)]
struct OrderedSet(Vec<String>);

impl OrderedSet {
    fn add(&mut self, value: String) {
        if !self.0.contains(&value) {
            self.0.push(value);
        }
    }
}

struct TraceState {
    visited: Vec<(String, Visit)>,
    index: HashMap<String, usize>,
    queue: Vec<String>,
    edges: Vec<Edge>,
    edge_keys: std::collections::HashSet<(String, String)>,
    failures: Vec<Value>,
    residual: OrderedSet,
    limitations: OrderedSet,
    coverage: Vec<(String, Value)>,
    queue_index: usize,
    traversal_path: Vec<String>,
}

impl TraceState {
    fn new(start: &str, goal: Option<&str>) -> Self {
        Self {
            visited: vec![(
                start.to_owned(),
                Visit {
                    depth: 0,
                    path: vec![start.to_owned()],
                },
            )],
            index: HashMap::from([(start.to_owned(), 0)]),
            queue: vec![start.to_owned()],
            edges: Vec::new(),
            edge_keys: std::collections::HashSet::new(),
            failures: Vec::new(),
            residual: OrderedSet::default(),
            limitations: OrderedSet::default(),
            coverage: Vec::new(),
            queue_index: 0,
            traversal_path: if goal == Some(start) {
                vec![start.to_owned()]
            } else {
                Vec::new()
            },
        }
    }

    fn visit(&self, address: &str) -> Option<&Visit> {
        self.index.get(address).map(|index| &self.visited[*index].1)
    }

    fn set_coverage(&mut self, address: &str, coverage: Value) {
        match self
            .coverage
            .iter_mut()
            .find(|(existing, _)| existing == address)
        {
            Some((_, existing)) => *existing = coverage,
            None => self.coverage.push((address.to_owned(), coverage)),
        }
    }
}

fn record_edge(state: &mut TraceState, forward: bool, address: &str, related: &str, depth: usize) {
    let (source, target) = if forward {
        (address, related)
    } else {
        (related, address)
    };
    if state
        .edge_keys
        .insert((source.to_owned(), target.to_owned()))
    {
        state.edges.push(Edge {
            source_address: source.to_owned(),
            target_address: target.to_owned(),
            discovery_depth: depth,
        });
    }
}

/// `expandAddress`: `Ok(true)` when the goal was reached.
fn expand_address(
    analysis: &Analysis<'_>,
    state: &mut TraceState,
    goal: Option<&str>,
    direction: &str,
    address: &str,
) -> Result<bool, AnalysisError> {
    let (tool, relation) = traversal(direction);
    let (current_depth, current_path) = match state.visit(address) {
        Some(visit) => (visit.depth, visit.path.clone()),
        None => return Ok(false),
    };
    let result = analysis.observe(tool, &params([("procedure", json!(address))]), true);
    if let Err(error) = &result
        && (is_cancellation(error) || analysis.aborted())
    {
        return Err(error.clone());
    }
    if analysis.aborted() {
        return Err(AnalysisError::cancelled("trace_call_path"));
    }
    let execution = match result {
        Ok(execution) => execution,
        Err(error) => {
            state
                .failures
                .push(json!({ "address": address, "error": error.project() }));
            state.residual.add(format!(
                "Call relationships were unavailable for {address}."
            ));
            return Ok(false);
        }
    };
    let related = match parse_related_addresses(&execution.result, relation, tool) {
        Ok(related) => related,
        Err(error) => {
            state
                .failures
                .push(json!({ "address": address, "error": error.project() }));
            state
                .residual
                .add(format!("Call relationships were unreadable for {address}."));
            return Ok(false);
        }
    };
    for limitation in &execution.limitations {
        state.limitations.add(limitation.clone());
    }
    let coverage = execution.relationship_coverage.clone().unwrap_or_else(|| {
        json!({
            "status": "unknown",
            "reason": "Provider did not report relationship coverage.",
        })
    });
    state.set_coverage(address, coverage.clone());
    if let Some(diagnostics) = coverage.get("diagnostics").and_then(Value::as_array) {
        for diagnostic in diagnostics.iter().filter_map(Value::as_str) {
            state.limitations.add(diagnostic.to_owned());
        }
    }
    match coverage["status"].as_str() {
        Some("partial") => {
            for limitation in coverage["limitations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
            {
                state.residual.add(format!(
                    "Call relationships for {address} are limited: {limitation}"
                ));
            }
        }
        Some("unknown") => state.residual.add(format!(
            "Call relationship coverage is unknown for {address}: {}",
            coverage["reason"].as_str().unwrap_or("undefined")
        )),
        _ => {}
    }
    let mut sorted = related;
    sorted.sort_by(|left, right| compare_utf16(left, right));
    sorted.dedup();
    let forward = direction != "backward";
    for related_address in sorted {
        record_edge(state, forward, address, &related_address, current_depth + 1);
        let path = state.visit(&related_address).map_or_else(
            || {
                let mut path = current_path.clone();
                path.push(related_address.clone());
                path
            },
            |visit| visit.path.clone(),
        );
        if state.index.contains_key(&related_address) {
            if Some(related_address.as_str()) == goal {
                state.traversal_path = path;
                return Ok(true);
            }
            continue;
        }
        state
            .index
            .insert(related_address.clone(), state.visited.len());
        state.visited.push((
            related_address.clone(),
            Visit {
                depth: current_depth + 1,
                path: path.clone(),
            },
        ));
        if Some(related_address.as_str()) == goal {
            state.traversal_path = path;
            return Ok(true);
        }
        state.queue.push(related_address);
    }
    Ok(false)
}

/// `traceCallPath`.
pub fn trace_call_path(
    analysis: &Analysis<'_>,
    start: &str,
    goal: Option<&str>,
    direction: &str,
) -> Result<Value, AnalysisError> {
    let start = resolve_procedure_address(analysis, start)?;
    let goal = match goal {
        Some(goal) => Some(resolve_procedure_address(analysis, goal)?),
        None => None,
    };
    if analysis.aborted() {
        return Err(AnalysisError::cancelled("trace_call_path"));
    }
    let mut state = TraceState::new(&start, goal.as_deref());
    while state.queue_index < state.queue.len() && state.traversal_path.is_empty() {
        if analysis.aborted() {
            return Err(AnalysisError::cancelled("trace_call_path"));
        }
        let address = state.queue[state.queue_index].clone();
        state.queue_index += 1;
        if expand_address(analysis, &mut state, goal.as_deref(), direction, &address)? {
            break;
        }
    }
    if analysis.aborted() {
        return Err(AnalysisError::cancelled("trace_call_path"));
    }
    Ok(project_trace(&start, goal.as_deref(), direction, state))
}

fn project_trace(start: &str, goal: Option<&str>, direction: &str, state: TraceState) -> Value {
    let goal_status = match goal {
        None => "not_requested",
        Some(_) if !state.traversal_path.is_empty() => "reached",
        Some(_) if !state.residual.0.is_empty() => "unknown",
        Some(_) => "not_reached",
    };
    let mut nodes = state
        .visited
        .iter()
        .map(|(address, visit)| (address.clone(), visit.depth))
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then_with(|| compare_utf16(&left.0, &right.0))
    });
    let mut edges = state.edges;
    edges.sort_by(|left, right| {
        left.discovery_depth
            .cmp(&right.discovery_depth)
            .then_with(|| compare_utf16(&left.source_address, &right.source_address))
            .then_with(|| compare_utf16(&left.target_address, &right.target_address))
    });
    let mut coverage = state.coverage;
    coverage.sort_by(|left, right| compare_utf16(&left.0, &right.0));
    let mut limitations =
        vec!["Direct provider call relationships may omit unresolved indirect calls.".to_owned()];
    limitations.extend(state.limitations.0);
    json!({
        "start": start,
        "goal": goal,
        "direction": direction,
        "goal_status": goal_status,
        "nodes": nodes
            .into_iter()
            .map(|(address, depth)| json!({ "address": address, "depth": depth }))
            .collect::<Vec<_>>(),
        "edges": edges
            .into_iter()
            .map(|edge| json!({
                "source_address": edge.source_address,
                "target_address": edge.target_address,
                "discovery_depth": edge.discovery_depth,
            }))
            .collect::<Vec<_>>(),
        "traversal_path": state.traversal_path,
        "failures": state.failures,
        "traversal": { "nodes_visited": state.visited.len() },
        "relationship_coverage": from_entries(coverage),
        "truncated": !state.residual.0.is_empty(),
        "residual_unknowns": state.residual.0,
        "limitations": limitations,
    })
}
