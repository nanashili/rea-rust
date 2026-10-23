//! Static projection for the provider-neutral `trace_feature` workflow.
//!
//! The original workflow performs two searches and then resolves xrefs through
//! a provider.  This module deliberately consumes those observations as
//! Evidence (or an application graph) so the application layer never opens a
//! binary or invents a native fact.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "trace_feature";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("trace_feature input must be an object"))?;
    let query = object
        .get("query")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("query must be a non-empty string"))?;
    if query.len() > 16 * 1024 {
        return Err(invalid("query exceeds the 16 KiB limit"));
    }
    if let Some(case_sensitive) = object.get("case_sensitive") {
        if !case_sensitive.is_boolean() {
            return Err(invalid("case_sensitive must be a boolean"));
        }
    }
    if let Some(observations) = object.get("observations") {
        let values = observations
            .as_array()
            .ok_or_else(|| invalid("observations must be an array"))?;
        if values.len() > 20_000 {
            return Err(invalid("observations exceed the 20,000 record limit"));
        }
        let mut ids = BTreeSet::new();
        for observation in values {
            let id = evidence_id(observation, "observation")?;
            if !ids.insert(id.to_owned()) {
                return Err(invalid("observation Evidence IDs must be unique"));
            }
        }
    }
    if object.get("application").is_some() {
        evidence_id(object.get("application").unwrap(), "application")?;
    }
    Ok(())
}

/// Project a literal trace from retained search/xref Evidence or an application graph.
pub fn trace(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let query = input["query"].as_str().unwrap_or_default();
    let case_sensitive = input
        .get("case_sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let normalized_query = normalize(query, case_sensitive);
    let mut matches = Vec::new();
    let mut match_keys = BTreeSet::new();
    let mut references = Vec::new();
    let mut residual = Vec::new();
    let mut evidence_links = BTreeSet::new();

    if let Some(application) = input.get("application") {
        evidence_links.insert(evidence_id(application, "application")?.to_owned());
        project_graph(
            application,
            &normalized_query,
            case_sensitive,
            &mut matches,
            &mut match_keys,
            &mut references,
            &mut residual,
            &mut evidence_links,
        )?;
    }
    if let Some(observations) = input.get("observations").and_then(Value::as_array) {
        for observation in observations {
            let id = evidence_id(observation, "observation")?;
            evidence_links.insert(id.to_owned());
            project_observation(
                observation,
                &normalized_query,
                case_sensitive,
                &mut matches,
                &mut match_keys,
                &mut references,
                &mut residual,
                &mut evidence_links,
            );
        }
    }

    matches.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    references.sort_by(|left, right| left.to_string().cmp(&right.to_string()));
    references.dedup_by(|left, right| left == right);
    residual.sort();
    residual.dedup();
    let semantic = json!({
        "query": query,
        "search_mode": "literal",
        "matches": matches,
        "references": references,
        "truncated": !residual.is_empty(),
        "residual_unknowns": residual,
    });
    let digest = rea_core::canonical_json::digest(&semantic)
        .map_err(|_| invalid("trace result could not be canonicalized"))?;
    let mut output = semantic;
    output["trace_id"] = Value::String(format!("ntr_{digest}"));
    output["evidence_links"] =
        Value::Array(evidence_links.into_iter().map(Value::String).collect());
    Ok(output)
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("trace_feature result must be an object"));
    }
    Ok(result)
}

fn project_observation(
    observation: &Value,
    query: &str,
    case_sensitive: bool,
    matches: &mut Vec<Value>,
    keys: &mut BTreeSet<String>,
    references: &mut Vec<Value>,
    residual: &mut Vec<String>,
    evidence_links: &mut BTreeSet<String>,
) {
    let operation = observation
        .get("operation")
        .or_else(|| observation.pointer("/normalized_result/operation"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let result = observation
        .get("result")
        .or_else(|| observation.get("normalized_result"))
        .unwrap_or(observation);
    collect_nested_evidence(result, evidence_links);
    if matches!(operation, "search_strings" | "search_procedures") {
        let kind = if operation == "search_strings" {
            "string"
        } else {
            "procedure"
        };
        let items = result
            .as_array()
            .or_else(|| result.get("items").and_then(Value::as_array));
        if let Some(items) = items {
            for item in items {
                let address = item
                    .get("address")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let value = item
                    .get("value")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if address.is_empty() || !contains(value, query, case_sensitive) {
                    continue;
                }
                let key = format!("{kind}\u{0}{address}");
                if keys.insert(key) {
                    matches.push(json!({"type": kind, "address": address, "value": value}));
                }
            }
        }
    }
    if operation == "xrefs" {
        let target_address = observation_address(observation);
        let references_truncated =
            result.get("references_truncated").and_then(Value::as_bool) == Some(true);
        if references_truncated {
            let message = target_address
                .map(|address| {
                    format!(
                        "References to {address} were truncated by the provider; additional references may exist."
                    )
                })
                .unwrap_or_else(|| {
                    "One or more xref providers truncated their reference list; additional references may exist."
                        .into()
                });
            residual.push(message);
        }
        if let Some(items) = result
            .as_array()
            .or_else(|| result.get("result").and_then(Value::as_array))
        {
            for item in items {
                if let Some(address) = item.as_str() {
                    let mut reference = json!({"source_address": address});
                    if let Some(target_address) = target_address {
                        reference["target_address"] = Value::String(target_address.to_owned());
                    }
                    references.push(reference);
                }
            }
        }
    }
}

fn project_graph(
    application: &Value,
    query: &str,
    case_sensitive: bool,
    matches: &mut Vec<Value>,
    keys: &mut BTreeSet<String>,
    references: &mut Vec<Value>,
    residual: &mut Vec<String>,
    evidence_links: &mut BTreeSet<String>,
) -> Result<(), Failure> {
    let graph = application
        .pointer("/normalized_result/graph")
        .or_else(|| application.pointer("/result/graph"))
        .ok_or_else(|| invalid("application Evidence must contain a graph"))?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("graph.nodes must be an array"))?;
    let edges = graph
        .get("edges")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("graph.edges must be an array"))?;
    for node in nodes {
        let kind = match node.get("kind").and_then(Value::as_str) {
            Some("javascript-string") | Some("string") => "string",
            Some("procedure") | Some("native-export") | Some("javascript-function") => "procedure",
            _ => continue,
        };
        let address = node
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let value = node.get("identity").map(stringify).unwrap_or_default();
        if address.is_empty() || !contains(&value, query, case_sensitive) {
            continue;
        }
        let key = format!("{kind}\u{0}{address}");
        if keys.insert(key) {
            matches.push(json!({"type":kind,"address":address,"value":value}));
        }
        collect_nested_evidence(node, evidence_links);
    }
    for edge in edges {
        let source = edge
            .get("source_node_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let target = edge
            .get("target_node_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !source.is_empty() && !target.is_empty() {
            references.push(json!({"source_address":source,"target_address":target}));
        }
        collect_nested_evidence(edge, evidence_links);
    }
    if graph.pointer("/coverage/status").and_then(Value::as_str) != Some("complete") {
        residual.push(
            "The source application graph is incomplete; additional matching references may exist."
                .into(),
        );
    }
    Ok(())
}

fn evidence_id<'a>(value: &'a Value, field: &str) -> Result<&'a str, Failure> {
    value
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must include evidence_id")))
}

fn collect_nested_evidence(value: &Value, ids: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(values) = object.get("evidence_ids").and_then(Value::as_array) {
                ids.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
            }
            object
                .values()
                .for_each(|value| collect_nested_evidence(value, ids));
        }
        Value::Array(values) => values
            .iter()
            .for_each(|value| collect_nested_evidence(value, ids)),
        _ => {}
    }
}

fn observation_address(observation: &Value) -> Option<&str> {
    observation
        .pointer("/parameters/address")
        .or_else(|| observation.pointer("/arguments/address"))
        .or_else(|| observation.get("address"))
        .and_then(Value::as_str)
        .filter(|address| !address.is_empty())
}

fn stringify(value: &Value) -> String {
    value
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| value.to_string())
}
fn normalize(value: &str, case_sensitive: bool) -> String {
    if case_sensitive {
        value.to_owned()
    } else {
        value.to_lowercase()
    }
}
fn contains(value: &str, query: &str, case_sensitive: bool) -> bool {
    normalize(value, case_sensitive).contains(query)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide bounded trace observations or application Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
