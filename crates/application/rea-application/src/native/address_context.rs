//! Provider-neutral address context projection.
//!
//! The native provider owns the volatile query operations.  This module only
//! combines their already retained results, preserving unavailable facets and
//! refusing to infer a bookmark or procedure from malformed provider data.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_address_context";

/// Validate the caller-owned address context input without contacting a
/// provider.  Results may be supplied under `observations`, `results`, or
/// `facets`; direct facet keys are accepted for adapter convenience.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("address context input must be an object"))?;
    required_text(object.get("address"), "address")?;
    if let Some(document) = object.get("document") {
        required_text(Some(document), "document")?;
    }
    if let Some(container) = source_container(object) {
        if !container.is_object() {
            return Err(invalid("address context observations must be an object"));
        }
    }
    Ok(())
}

/// Build the stable address context result from retained provider facts.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("address context input must be an object"))?;
    let address = required_text(object.get("address"), "address")?.to_owned();
    let document = object.get("document").cloned().unwrap_or(Value::Null);
    let source = source_container(object).unwrap_or(input);

    let name = facet_for(source, "address_name", "name")?;
    let procedure = facet_for(source, "resolve_containing_procedure", "procedure")?;
    let comment = facet_for(source, "comment", "comment")?;
    let inline_comment = facet_for(source, "inline_comment", "inline_comment")?;
    let procedure_address = procedure_address(&procedure, &address);
    let bookmarks = bookmarks_facet(
        facet_for(source, "list_bookmarks", "bookmarks")?,
        &procedure_address,
    );

    Ok(json!({
        "address": address,
        "document": document,
        "name": name,
        "procedure": procedure,
        "comment": comment,
        "inline_comment": inline_comment,
        "bookmarks": bookmarks,
    }))
}

fn source_container<'a>(object: &'a Map<String, Value>) -> Option<&'a Value> {
    ["observations", "results", "facets"]
        .iter()
        .find_map(|key| object.get(*key))
}

fn facet_for(source: &Value, operation: &str, short_name: &str) -> Result<Value, Failure> {
    let Some(object) = source.as_object() else {
        return Ok(unavailable(operation, "no retained provider result"));
    };
    let raw = object.get(operation).or_else(|| object.get(short_name));
    let Some(raw) = raw else {
        return Ok(unavailable(operation, "no retained provider result"));
    };
    parse_facet(raw, operation)
}

fn parse_facet(raw: &Value, operation: &str) -> Result<Value, Failure> {
    if let Some(object) = raw.as_object() {
        if let Some(state) = object.get("state").and_then(Value::as_str) {
            return match state {
                "available" => object
                    .get("value")
                    .cloned()
                    .map(|value| json!({"state":"available", "value":value}))
                    .ok_or_else(|| invalid(&format!("{operation} available facet lacks value"))),
                "unavailable" => {
                    let reason = required_text(object.get("reason"), "facet.reason")?;
                    let remediation = object
                        .get("remediation")
                        .and_then(Value::as_str)
                        .unwrap_or("Call the provider operation directly for diagnostics.");
                    Ok(json!({"state":"unavailable", "reason":reason, "remediation":remediation}))
                }
                _ => Err(invalid(&format!("{operation} facet has invalid state"))),
            };
        }
        if let Some(error) = object.get("error") {
            return Ok(unavailable(
                operation,
                error.as_str().unwrap_or("provider returned an error"),
            ));
        }
        if object.contains_key("normalized_result") || object.contains_key("result") {
            let value = object
                .get("normalized_result")
                .or_else(|| object.get("result"))
                .cloned()
                .unwrap_or(Value::Null);
            return Ok(json!({"state":"available", "value":value}));
        }
    }
    Ok(json!({"state":"available", "value":raw.clone()}))
}

fn bookmarks_facet(facet: Value, address: &str) -> Value {
    if facet.get("state").and_then(Value::as_str) != Some("available") {
        return facet;
    }
    let value = facet.get("value").cloned().unwrap_or(Value::Null);
    let Some(items) = value.as_array() else {
        return unavailable(
            "list_bookmarks",
            "list_bookmarks returned malformed output; expected an array.",
        );
    };
    let mut matches = Vec::new();
    for item in items {
        let Some(object) = item.as_object() else {
            return unavailable(
                "list_bookmarks",
                "list_bookmarks returned malformed entries; expected bookmark objects.",
            );
        };
        let Some(bookmark_address) = object.get("address").and_then(Value::as_str) else {
            return unavailable(
                "list_bookmarks",
                "list_bookmarks returned malformed entries; expected an address string.",
            );
        };
        let name = object.get("name").cloned().unwrap_or(Value::Null);
        if !name.is_null() && name.as_str().is_none() {
            return unavailable(
                "list_bookmarks",
                "list_bookmarks returned malformed entries; expected a string or null name.",
            );
        }
        if bookmark_address == address {
            matches.push(json!({"address":bookmark_address, "name":name}));
        }
    }
    json!({"state":"available", "value":matches})
}

fn procedure_address(procedure: &Value, fallback: &str) -> String {
    if procedure.get("state").and_then(Value::as_str) != Some("available") {
        return fallback.to_owned();
    }
    procedure
        .get("value")
        .and_then(|value| value.get("query_address"))
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn unavailable(operation: &str, reason: &str) -> Value {
    json!({
        "state": "unavailable",
        "reason": reason,
        "remediation": format!("Call {operation} directly to inspect provider availability and diagnostics."),
    })
}

fn required_text<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide an address and retained provider facet results.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
