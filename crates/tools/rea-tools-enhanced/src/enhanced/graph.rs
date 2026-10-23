//! Breadth-first direct call graph.
//!
//! Compatibility owners: `#callGraph` (`EnhancedTools.ts`),
//! `CALL_RELATIONSHIP_TRAVERSALS` (`CallRelationshipTraversal.ts`) and
//! `parseRelatedAddresses` (`domain/hopperValues.ts`).
use crate::analysis::{Analysis, is_cancellation, params};
use crate::enhanced::overview::unwrap_property;
use crate::js::JsObject;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashSet, VecDeque};

/// The provider read and response relation for one traversal direction.
pub fn traversal(direction: &str) -> (&'static str, &'static str) {
    if direction == "backward" {
        ("procedure_callers", "callers")
    } else {
        ("procedure_callees", "callees")
    }
}

/// `parseRelatedAddresses`.
pub fn parse_related_addresses(
    value: &Value,
    relation: &str,
    operation: &str,
) -> Result<Vec<String>, AnalysisError> {
    let parsed = unwrap_property(value, relation)
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .map(|entry| entry.as_str().map(str::to_owned))
                .collect::<Option<Vec<_>>>()
        });
    parsed.ok_or_else(|| {
        AnalysisError::output(
            operation,
            format!("Provider returned an invalid {relation} list"),
        )
    })
}

/// The coverage-reported limitations of one relationship observation.
fn coverage_limitations(coverage: &Value) -> Vec<String> {
    let mut limitations = Vec::new();
    match coverage["status"].as_str() {
        Some("partial") => limitations.extend(
            coverage["limitations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        ),
        Some("unknown") => {
            if let Some(reason) = coverage["reason"].as_str() {
                limitations.push(reason.to_owned());
            }
        }
        _ => {}
    }
    if let Some(diagnostics) = coverage.get("diagnostics").and_then(Value::as_array) {
        limitations.extend(
            diagnostics
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    limitations
}

/// `#callGraph`.
pub fn call_graph(
    analysis: &Analysis<'_>,
    address: &str,
    direction: &str,
) -> Result<Value, AnalysisError> {
    let (tool, relation) = traversal(direction);
    let mut limitations = BTreeSet::new();
    let resolved = analysis.observe(
        "procedure_address",
        &params([("procedure", json!(address))]),
        false,
    )?;
    limitations.extend(resolved.limitations.iter().cloned());
    let start = match &resolved.result {
        Value::String(start) if !start.is_empty() => start.clone(),
        _ => {
            return Err(AnalysisError::output(
                "procedure_address",
                "provider returned no canonical procedure address",
            ));
        }
    };
    let mut discovered = HashSet::from([start.clone()]);
    let mut queue = VecDeque::from([(start, 0_usize)]);
    let mut graph = JsObject::new();
    while let Some((current, depth)) = queue.pop_front() {
        let level = depth.to_string();
        if !graph.contains_key(&level) {
            graph.insert(level.clone(), json!([]));
        }
        let observed = analysis.observe(tool, &params([("procedure", json!(current))]), true);
        let node = match observed {
            Err(error) if is_cancellation(&error) => return Err(error),
            Err(error) => {
                json!({ "address": current, "status": "error", "error": error.project() })
            }
            Ok(execution) => match parse_related_addresses(&execution.result, relation, tool) {
                Err(error) => {
                    json!({ "address": current, "status": "error", "error": error.project() })
                }
                Ok(related) => {
                    limitations.extend(execution.limitations.iter().cloned());
                    let (coverage, node_limitations) = match &execution.relationship_coverage {
                        None => {
                            let mut node = execution.limitations.clone();
                            node.push("Provider did not report relationship coverage.".to_owned());
                            (
                                json!({
                                    "status": "unknown",
                                    "reason": "Provider did not report relationship coverage.",
                                }),
                                node,
                            )
                        }
                        Some(reported) => (reported.clone(), coverage_limitations(reported)),
                    };
                    let node_limitations = node_limitations.into_iter().collect::<BTreeSet<_>>();
                    let mut node = Map::new();
                    node.insert("address".into(), json!(current));
                    node.insert("status".into(), json!("ok"));
                    node.insert("calls".into(), json!(related));
                    node.insert("relationship_coverage".into(), coverage);
                    if !node_limitations.is_empty() {
                        node.insert("limitations".into(), json!(node_limitations));
                    }
                    for address in related {
                        if discovered.insert(address.clone()) {
                            queue.push_back((address, depth + 1));
                        }
                    }
                    Value::Object(node)
                }
            },
        };
        if let Some(Value::Array(nodes)) = graph.get_mut(&level) {
            nodes.push(node);
        }
    }
    Ok(json!({ "graph": graph.into_value(), "limitations": limitations }))
}
