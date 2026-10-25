//! Read-only call-relationship traversal over caller-supplied Evidence.
//!
//! The TypeScript adapter obtains one relationship result at a time from a
//! provider.  The native boundary receives those observations as input and
//! performs the same breadth-first traversal without executing a target.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const OPERATION: &str = "trace_call_path";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let start = object
        .get("start")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    if start.is_none() {
        return Err(invalid("start must be a non-empty string"));
    }
    if let Some(goal) = object.get("goal") {
        if !goal.is_null() && goal.as_str().is_none() {
            return Err(invalid("goal must be a string or null"));
        }
    }
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("forward");
    if !matches!(direction, "forward" | "backward") {
        return Err(invalid("direction must be forward or backward"));
    }
    let observations = object
        .get("observations")
        .or_else(|| object.get("evidence"));
    if let Some(value) = observations {
        if !value.is_array() {
            return Err(invalid("observations must be an array"));
        }
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("trace result must be an object"));
    }
    Ok(result)
}

/// Traverse the supplied relationship observations in deterministic BFS order.
pub fn trace(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input.as_object().expect("validated object");
    let start = object
        .get("start")
        .and_then(Value::as_str)
        .expect("validated start");
    let goal = object.get("goal").and_then(Value::as_str);
    let direction = object
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("forward");
    let records = object
        .get("observations")
        .or_else(|| object.get("evidence"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut adjacency: BTreeMap<String, Observation> = BTreeMap::new();
    let mut failures = Vec::new();
    let mut limitations = BTreeSet::new();
    for record in records {
        match parse_observation(&record, direction) {
            Ok(observation) => {
                adjacency
                    .entry(observation.address.clone())
                    .and_modify(|existing| {
                        existing.related.extend(observation.related.iter().cloned());
                        existing.related.sort();
                        existing.related.dedup();
                        existing
                            .evidence_ids
                            .extend(observation.evidence_ids.iter().cloned());
                        existing.evidence_ids.sort();
                        existing.evidence_ids.dedup();
                        existing
                            .limitations
                            .extend(observation.limitations.iter().cloned());
                        existing.limitations.sort();
                        existing.limitations.dedup();
                        if existing.coverage.is_none() {
                            existing.coverage = observation.coverage.clone();
                        }
                    })
                    .or_insert(observation);
            }
            Err(error) => {
                let address = record
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                failures.push(json!({"address": address, "error": error}));
            }
        }
    }

    let mut visited: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    let mut queue = VecDeque::new();
    visited.insert(start.to_owned(), (0, vec![start.to_owned()]));
    queue.push_back(start.to_owned());
    let mut edges = BTreeMap::<(String, String), usize>::new();
    let mut coverage = BTreeMap::new();
    let mut residual = Vec::new();
    let mut traversal_path = Vec::new();

    while let Some(address) = queue.pop_front() {
        let (depth, path) = visited.get(&address).cloned().expect("queued node exists");
        if goal == Some(address.as_str()) {
            traversal_path = path;
            break;
        }
        let Some(observation) = adjacency.get(&address) else {
            residual.push(format!(
                "Call relationships were unavailable for {address}."
            ));
            continue;
        };
        limitations.extend(observation.limitations.iter().cloned());
        let coverage_value = observation.coverage.clone().unwrap_or_else(|| {
            json!({"status":"unknown","reason":"Provider did not report relationship coverage."})
        });
        match coverage_value.get("status").and_then(Value::as_str) {
            Some("partial") => {
                let coverage_limitations = coverage_value
                    .get("limitations")
                    .and_then(Value::as_array)
                    .map(|values| {
                        values
                            .iter()
                            .filter_map(Value::as_str)
                            .filter(|value| !value.is_empty())
                            .map(str::to_owned)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if coverage_limitations.is_empty() {
                    residual.push(format!(
                        "Call relationships for {address} are limited: relationship coverage is partial"
                    ));
                } else {
                    residual.extend(coverage_limitations.into_iter().map(|limitation| {
                        format!("Call relationships for {address} are limited: {limitation}")
                    }));
                }
            }
            Some("unknown") | None => {
                let reason = coverage_value
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("Provider did not report relationship coverage.");
                residual.push(format!(
                    "Call relationship coverage is unknown for {address}: {reason}"
                ));
            }
            _ => {}
        }
        if let Some(diagnostics) = coverage_value.get("diagnostics").and_then(Value::as_array) {
            limitations.extend(
                diagnostics
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .map(str::to_owned),
            );
        }
        coverage.insert(address.clone(), coverage_value);
        for related in &observation.related {
            let (source, target) = if direction == "forward" {
                (address.clone(), related.clone())
            } else {
                (related.clone(), address.clone())
            };
            edges.entry((source, target)).or_insert(depth + 1);
            if visited.contains_key(related) {
                continue;
            }
            let next_path = path
                .iter()
                .cloned()
                .chain(std::iter::once(related.clone()))
                .collect::<Vec<_>>();
            visited.insert(related.clone(), (depth + 1, next_path.clone()));
            if goal == Some(related.as_str()) {
                traversal_path = next_path;
            }
            queue.push_back(related.clone());
            if !traversal_path.is_empty() {
                break;
            }
        }
        if !traversal_path.is_empty() {
            break;
        }
    }
    if goal.is_some() && traversal_path.is_empty() && residual.is_empty() {
        if adjacency
            .keys()
            .any(|address| !visited.contains_key(address))
        {
            residual.push("Supplied relationship observations contain unreachable records.".into());
        }
    }
    if !failures.is_empty() {
        residual.push("One or more call relationship observations were unreadable.".into());
    }
    let goal_status = match goal {
        None => "not_requested",
        Some(_) if !traversal_path.is_empty() => "reached",
        Some(_) if !residual.is_empty() => "unknown",
        Some(_) => "not_reached",
    };
    let mut node_values = visited
        .iter()
        .map(|(address, (depth, _))| (*depth, address.clone()))
        .collect::<Vec<_>>();
    node_values.sort_by(|left, right| left.cmp(right));
    let nodes = node_values
        .into_iter()
        .map(|(depth, address)| json!({"address":address,"depth":depth}))
        .collect::<Vec<_>>();
    let mut edge_values = edges
        .iter()
        .map(|((source, target), depth)| (*depth, source.clone(), target.clone()))
        .collect::<Vec<_>>();
    edge_values.sort();
    let edge_values = edge_values.into_iter().map(|(depth, source, target)| json!({"source_address":source,"target_address":target,"discovery_depth":depth})).collect::<Vec<_>>();
    limitations
        .insert("Direct provider call relationships may omit unresolved indirect calls.".into());
    Ok(json!({
        "start": start,
        "goal": goal,
        "direction": direction,
        "goal_status": goal_status,
        "nodes": nodes,
        "edges": edge_values,
        "traversal_path": traversal_path,
        "failures": failures,
        "relationship_coverage": coverage,
        "traversal": {"nodes_visited": visited.len()},
        "truncated": !residual.is_empty(),
        "residual_unknowns": residual,
        "limitations": limitations.into_iter().collect::<Vec<_>>(),
    }))
}

#[derive(Clone, Debug)]
struct Observation {
    address: String,
    related: Vec<String>,
    evidence_ids: Vec<String>,
    coverage: Option<Value>,
    limitations: Vec<String>,
}

fn parse_observation(record: &Value, direction: &str) -> Result<Observation, Value> {
    let source = record
        .get("normalized_result")
        .or_else(|| record.get("result"))
        .unwrap_or(record);
    let address = record.get("address").or_else(|| source.get("address")).and_then(Value::as_str)
        .ok_or_else(|| json!({"code":"invalid_input","message":"relationship observation requires address"}))?.to_owned();
    let related_value = record.get("related_addresses").or_else(|| record.get("related"))
        .or_else(|| source.get("related_addresses")).or_else(|| source.get("related"))
        .or_else(|| source.get(if direction == "forward" { "callees" } else { "callers" }))
        .and_then(Value::as_array).ok_or_else(|| json!({"code":"invalid_input","message":"relationship observation requires related addresses"}))?;
    let mut related = related_value
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    related.sort();
    related.dedup();
    let evidence_ids = record
        .get("evidence_id")
        .and_then(Value::as_str)
        .map(|id| vec![id.to_owned()])
        .unwrap_or_default();
    let coverage = record
        .get("relationship_coverage")
        .or_else(|| source.get("relationship_coverage"))
        .cloned();
    let limitations = record
        .get("limitations")
        .or_else(|| source.get("limitations"))
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    Ok(Observation {
        address,
        related,
        evidence_ids,
        coverage,
        limitations,
    })
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide bounded call relationship observations and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
