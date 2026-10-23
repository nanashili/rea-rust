//! Bounded search over an already retained string inventory.
//!
//! Provider sessions own string discovery. This module accepts only an
//! inventory or retained Evidence and applies the shared search semantics at
//! the application boundary.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "search_strings";

const MAX_ITEMS: usize = 200_000;
const MAX_PATTERN_BYTES: usize = 16 * 1024;
const ROW_FIELDS: &[&str] = &["address", "decoding", "provider_value", "string", "value"];

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("search input must be an object"))?;

    reject_unknown_fields(object)?;
    validate_pattern(object)?;
    validate_options(object)?;

    if let Some(inventory) = object.get("strings").or_else(|| object.get("inventory")) {
        parse_inventory(inventory)?;
    }
    if let Some(evidence) = object.get("evidence") {
        parse_inventory(result_value(evidence)?)?;
    }

    Ok(())
}

/// Search supplied string facts, retaining the provider's item shape and order.
pub fn search(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;

    let object = input.as_object().expect("validated search input object");
    let rows = inventory(object)?;
    let pattern = object["pattern"]
        .as_str()
        .expect("validated search pattern");
    let case_sensitive = object
        .get("case_sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("literal");

    let matches = rows.into_iter().filter(|item| {
        let value = item
            .get("value")
            .and_then(Value::as_str)
            .expect("validated string row value");
        matches_pattern(value, pattern, mode, case_sensitive)
    });

    Ok(Value::Array(matches.collect()))
}

pub fn project(input: &Value) -> Result<Value, Failure> {
    search(input)
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: &[&str] = &[
        "pattern",
        "mode",
        "case_sensitive",
        "document",
        "strings",
        "inventory",
        "evidence",
    ];

    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown search_strings field: {field}")));
    }

    Ok(())
}

fn validate_pattern(object: &Map<String, Value>) -> Result<(), Failure> {
    let pattern = object
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("pattern must be a non-empty string"))?;
    if pattern.len() > MAX_PATTERN_BYTES {
        return Err(invalid("pattern exceeds the search limit"));
    }

    if object.get("mode").and_then(Value::as_str) == Some("regex") && !regex_is_well_formed(pattern)
    {
        return Err(invalid("pattern is not a valid regular expression"));
    }

    Ok(())
}

fn validate_options(object: &Map<String, Value>) -> Result<(), Failure> {
    if let Some(mode) = object.get("mode") {
        if !matches!(mode.as_str(), Some("literal") | Some("regex")) {
            return Err(invalid("mode must be literal or regex"));
        }
    }
    if let Some(case_sensitive) = object.get("case_sensitive") {
        if !case_sensitive.is_boolean() {
            return Err(invalid("case_sensitive must be a boolean"));
        }
    }
    if let Some(document) = object.get("document") {
        if document.as_str().is_none_or(str::is_empty) {
            return Err(invalid("document must be a non-empty string"));
        }
    }

    Ok(())
}

fn inventory(object: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    if let Some(value) = object.get("strings").or_else(|| object.get("inventory")) {
        return parse_inventory(value);
    }

    if let Some(evidence) = object.get("evidence") {
        if let Some(document) = object.get("document").and_then(Value::as_str) {
            if !evidence_matches_document(evidence, document) {
                return Ok(Vec::new());
            }
        }
        return parse_inventory(result_value(evidence)?);
    }

    Err(invalid("a retained string inventory is required"))
}

fn evidence_matches_document(evidence: &Value, requested: &str) -> bool {
    let Some(object) = evidence.as_object() else {
        return false;
    };

    object
        .get("document")
        .and_then(Value::as_str)
        .or_else(|| {
            object
                .get("parameters")
                .and_then(Value::as_object)
                .and_then(|parameters| parameters.get("document"))
                .and_then(Value::as_str)
        })
        .is_some_and(|document| document == requested)
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("Evidence must be an object"))?;

    object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .or_else(|| object.get("value"))
        .ok_or_else(|| invalid("Evidence has no normalized result"))
}

fn parse_inventory(value: &Value) -> Result<Vec<Value>, Failure> {
    let array = value
        .as_array()
        .or_else(|| value.get("items").and_then(Value::as_array))
        .or_else(|| value.get("value").and_then(Value::as_array))
        .ok_or_else(|| invalid("string inventory must be an array"))?;

    if array.len() > MAX_ITEMS {
        return Err(invalid("string inventory exceeds the item limit"));
    }

    for (index, item) in array.iter().enumerate() {
        validate_row(item, index)?;
    }

    Ok(array.to_vec())
}

fn validate_row(item: &Value, index: usize) -> Result<(), Failure> {
    let object = item
        .as_object()
        .ok_or_else(|| invalid(&format!("string inventory entry {index} must be an object")))?;

    if let Some(field) = object
        .keys()
        .find(|field| !ROW_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "string inventory entry contains unknown field: {field}"
        )));
    }
    if object
        .get("address")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "string inventory entries require a non-empty address",
        ));
    }
    if object.get("value").and_then(Value::as_str).is_none() {
        return Err(invalid("string inventory entries require a string value"));
    }

    Ok(())
}

fn matches_pattern(value: &str, pattern: &str, mode: &str, case_sensitive: bool) -> bool {
    if mode == "literal" {
        let haystack = if case_sensitive {
            value.to_owned()
        } else {
            value.to_lowercase()
        };
        let needle = if case_sensitive {
            pattern.to_owned()
        } else {
            pattern.to_lowercase()
        };
        return haystack.contains(&needle);
    }

    simple_regex_match(value, pattern, case_sensitive)
}

// The native crate intentionally has no regex dependency. This bounded matcher
// covers the constructs supported by the native search contract.
fn simple_regex_match(value: &str, pattern: &str, case_sensitive: bool) -> bool {
    let haystack = if case_sensitive {
        value.to_owned()
    } else {
        value.to_lowercase()
    };
    let needle = if case_sensitive {
        pattern.to_owned()
    } else {
        pattern.to_lowercase()
    };

    if needle == ".*" || needle.is_empty() {
        return true;
    }

    let anchored_start = needle.starts_with('^');
    let anchored_end = needle.ends_with('$') && !needle.ends_with("\\$");
    let core = needle.trim_start_matches('^').trim_end_matches('$');
    let parts: Vec<&str> = core.split(".*").collect();

    let mut offset = 0usize;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }

        let Some(found) = haystack[offset..].find(part) else {
            return false;
        };
        let start = offset + found;
        if index == 0 && anchored_start && start != 0 {
            return false;
        }
        offset = start + part.len();
    }

    if anchored_start && parts.first().is_some_and(|part| !part.is_empty()) {
        let first = parts[0];
        if !haystack.starts_with(first) {
            return false;
        }
    }

    if anchored_end {
        let last = parts.last().copied().unwrap_or_default();
        if !last.is_empty() && !haystack.ends_with(last) {
            return false;
        }
    }

    true
}

fn regex_is_well_formed(pattern: &str) -> bool {
    let mut escaped = false;
    let mut classes = 0usize;

    for character in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        match character {
            '\\' => escaped = true,
            '[' => classes += 1,
            ']' if classes > 0 => classes -= 1,
            ']' => return false,
            _ => {}
        }
    }

    !escaped && classes == 0
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Supply a bounded retained string inventory and a valid search pattern.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
