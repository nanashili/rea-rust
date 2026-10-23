//! Isolated runtime adapter for static JavaScript semantic tracing.
//!
//! This boundary accepts either an authenticated application Evidence envelope
//! or an explicitly identified caller-supplied semantic graph. It never parses
//! scripts, opens a browser, executes JavaScript, or contacts a provider.

use rea_application::javascript;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JavaScriptSemanticsOperation {
    Trace,
}

impl JavaScriptSemanticsOperation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            javascript::semantics::OPERATION => Ok(Self::Trace),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Trace => javascript::semantics::OPERATION,
        }
    }
}

/// Dispatch one static semantic trace without acquiring provider authority.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = JavaScriptSemanticsOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

pub fn dispatch_typed(
    operation: JavaScriptSemanticsOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        JavaScriptSemanticsOperation::Trace => {
            let normalized = normalize_input(input)?;
            let result = javascript::semantics::trace(&normalized)?;
            validate_output(&result)?;
            Ok(result)
        }
    }
}

fn normalize_input(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("semantic trace input must be an object"))?;
    let application = object
        .get("application")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("application static facts or Evidence are required"))?;

    if application.get("normalized_result").is_some()
        || application.get("result").is_some()
    {
        return Ok(input.clone());
    }

    let evidence_id = application
        .get("evidence_id")
        .or_else(|| application.get("evidenceId"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("static semantic facts must include evidence_id"))?;
    let graph = application
        .get("semantic_graph")
        .cloned()
        .ok_or_else(|| invalid("static semantic facts must include semantic_graph"))?;

    let mut normalized_application = application.clone();
    normalized_application.insert(
        "evidence_id".into(),
        Value::String(evidence_id.to_owned()),
    );
    normalized_application.insert(
        "normalized_result".into(),
        Value::Object(Map::from_iter([(String::from("semantic_graph"), graph)])),
    );

    let mut normalized_input = object.clone();
    normalized_input.insert(
        "application".into(),
        Value::Object(normalized_application),
    );
    Ok(Value::Object(normalized_input))
}

fn validate_output(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("semantic trace result must be an object"))?;
    for field in [
        "query_id",
        "source_graph_id",
        "seed",
        "direction",
        "status",
        "seed_node_ids",
        "evidence_contexts",
        "nodes",
        "relations",
        "unknowns",
        "expected_match_node_ids",
        "summary",
        "coverage",
        "limitations",
        "source_evidence_id",
        "evidence_links",
    ] {
        if !object.contains_key(field) {
            return Err(invalid(&format!("semantic trace result lacks {field}")));
        }
    }
    if !matches!(
        object.get("status").and_then(Value::as_str),
        Some("found" | "no-match" | "ambiguous" | "partial" | "unsupported")
    ) {
        return Err(invalid("semantic trace result has invalid status"));
    }
    if !matches!(
        object.pointer("/coverage/status").and_then(Value::as_str),
        Some("complete" | "partial" | "unavailable")
    ) {
        return Err(invalid("semantic trace result has invalid coverage status"));
    }
    for field in [
        "seed_node_ids",
        "evidence_contexts",
        "nodes",
        "relations",
        "unknowns",
        "expected_match_node_ids",
        "limitations",
        "evidence_links",
    ] {
        if !object.get(field).is_some_and(Value::is_array) {
            return Err(invalid(&format!("semantic trace result.{field} must be an array")));
        }
    }
    Ok(())
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("JavaScript semantics operation is unknown: {name}"),
        false,
        "Select trace_javascript_semantics and provide static semantic facts or Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide static JavaScript semantic facts or authenticated Evidence and retry.".into(),
        BTreeMap::from([(
            String::from("operation"),
            Detail::Text(javascript::semantics::OPERATION.into()),
        )]),
    )
}
