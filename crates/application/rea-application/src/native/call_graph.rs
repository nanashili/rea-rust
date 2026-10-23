//! Provider-neutral call-graph projection over retained `analyze_function` Evidence.
//!
//! The provider owns address resolution and relationship discovery.  This module only
//! joins caller-supplied function dossiers into a bounded deterministic graph; it never
//! executes a target or asks an attached analysis database for more facts.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "get_call_graph";
const MAX_FUNCTIONS: usize = 65_536;
const MAX_NODES: usize = 65_536;

#[derive(Clone)]
struct Function {
    calls: Vec<String>,
    callers: Vec<String>,
    coverage: Option<Value>,
    limitations: Vec<String>,
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("call graph input must be an object"))?;
    let address = object.get("address");
    if address
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("address must be a non-empty string"));
    }
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("forward");
    if !matches!(direction, "forward" | "backward") {
        return Err(invalid("direction must be forward or backward"));
    }
    let functions = object.get("functions");
    if let Some(value) = functions {
        let entries = value
            .as_array()
            .ok_or_else(|| invalid("functions must be an array"))?;
        if entries.len() > MAX_FUNCTIONS {
            return Err(invalid("functions exceed the supported bound"));
        }
    }
    Ok(())
}

/// Build the same level-indexed graph shape as the application adapter.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input.as_object().expect("validated object");
    let start = object
        .get("address")
        .and_then(Value::as_str)
        .expect("validated address")
        .to_owned();
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("forward");
    let entries = object
        .get("functions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let functions = parse_functions(&entries)?;
    let mut limitations = BTreeSet::new();
    let mut graph: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();
    visited.insert(start.clone());
    queue.push_back((start, 0usize));

    while let Some((address, depth)) = queue.pop_front() {
        if visited.len() > MAX_NODES {
            return Err(invalid("call graph exceeds the supported node bound"));
        }
        let level = depth.to_string();
        let Some(function) = functions.get(&address) else {
            let reason =
                format!("No analyze_function Evidence covers reachable function {address}.");
            limitations.insert(reason.clone());
            graph.entry(level).or_default().push(json!({
                "address": address, "status": "error",
                "error": missing_evidence_error(&reason)
            }));
            continue;
        };

        limitations.extend(function.limitations.iter().cloned());
        let related = if direction == "forward" {
            &function.calls
        } else {
            &function.callers
        };
        let coverage = function
            .coverage
            .as_ref()
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(unknown_coverage);
        let mut node_limitations = relationship_limitations(&coverage);
        if function.coverage.as_ref().map_or(true, Value::is_null) {
            node_limitations.push("Provider did not report relationship coverage.".into());
        }
        node_limitations.sort();
        node_limitations.dedup();
        limitations.extend(node_limitations.iter().cloned());
        let mut node = json!({
            "address": address,
            "status": "ok",
            "calls": related,
            "relationship_coverage": coverage,
        });
        if !node_limitations.is_empty() {
            node["limitations"] = json!(node_limitations);
        }
        graph.entry(level).or_default().push(node);
        for next in related {
            if visited.insert(next.clone()) {
                queue.push_back((next.clone(), depth + 1));
            }
        }
    }

    Ok(json!({"graph": graph, "limitations": limitations.into_iter().collect::<Vec<_>>() }))
}

pub fn get_call_graph(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn parse_functions(entries: &[Value]) -> Result<BTreeMap<String, Function>, Failure> {
    let mut functions = BTreeMap::new();
    for entry in entries {
        if entry.get("operation").and_then(Value::as_str) != Some("analyze_function") {
            return Err(invalid(
                "call graph Evidence requires analyze_function records",
            ));
        }
        let _evidence_id = entry
            .get("evidence_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("function Evidence requires evidence_id"))?;
        let result = entry
            .get("normalized_result")
            .or_else(|| entry.get("result"))
            .ok_or_else(|| invalid("function Evidence requires normalized_result"))?;
        let dossier = result.get("dossier").unwrap_or(result);
        let procedure = dossier
            .get("procedure")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("function dossier requires procedure"))?;
        let address = procedure
            .get("address")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("function procedure requires address"))?
            .to_owned();
        if functions.contains_key(&address) {
            return Err(invalid("duplicate function Evidence address"));
        }
        let calls = addresses(dossier.get("callees"))?;
        let callers = addresses(dossier.get("callers"))?;
        let mut limitations = strings(entry.get("limitations"));
        limitations.extend(strings(dossier.get("limitations")));
        limitations.sort();
        limitations.dedup();
        functions.insert(
            address.clone(),
            Function {
                calls,
                callers,
                coverage: entry
                    .get("relationship_coverage")
                    .or_else(|| dossier.get("relationship_coverage"))
                    .cloned(),
                limitations,
            },
        );
    }
    Ok(functions)
}

fn addresses(value: Option<&Value>) -> Result<Vec<String>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid("function relationships must be arrays"))?;
    let mut result = Vec::with_capacity(values.len());
    for item in values {
        let address = item
            .get("address")
            .and_then(Value::as_str)
            .or_else(|| item.as_str())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("relationship entry requires address"))?;
        result.push(address.to_owned());
    }

    // Preserve the provider's relationship order and duplicate rows. The
    // TypeScript traversal emits the parsed relationship list verbatim while
    // deduplicating only the traversal queue, so collapsing rows here would
    // lose caller-visible source facts. The visited set in `project` still
    // prevents repeated expansion of the same destination.
    Ok(result)
}

fn relationship_limitations(coverage: &Value) -> Vec<String> {
    let mut values = Vec::new();
    match coverage.get("status").and_then(Value::as_str) {
        Some("partial") => values.extend(strings(coverage.get("limitations"))),
        Some("unknown") => {
            if let Some(reason) = coverage.get("reason").and_then(Value::as_str) {
                values.push(reason.to_owned());
            }
        }
        _ => {}
    }
    values.extend(strings(coverage.get("diagnostics")));
    values
}

fn unknown_coverage() -> Value {
    json!({
        "status": "unknown",
        "reason": "Provider did not report relationship coverage."
    })
}

fn missing_evidence_error(reason: &str) -> Value {
    json!({
        "code": "unreadable_output",
        "category": "execution_failure",
        "message": reason,
        "retryable": false,
        "remediation": {
            "action": "Provide analyze_function Evidence for every reachable function and retry."
        },
        "details": {
            "operation": OPERATION
        }
    })
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

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide bounded analyze_function Evidence and retry.".into(),
        BTreeMap::from([("operation".to_owned(), Detail::Text(OPERATION.into()))]),
    )
}
