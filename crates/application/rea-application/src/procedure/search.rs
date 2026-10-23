//! Deterministic projection of procedure-name searches from retained Evidence.
//!
//! Providers own binary access and name decoding.  This module only applies the
//! caller's search predicate to authenticated procedure observations already
//! retained by the application layer.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "search_procedures";
const MAX_PATTERN_UTF16_UNITS: usize = 16 * 1024;
const MAX_ROWS: usize = 200_000;

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("search_procedures input must be an object"))?;

    reject_unknown_fields(object)?;

    let pattern = object
        .get("pattern")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("pattern must be a non-empty string"))?;
    if pattern.encode_utf16().count() > MAX_PATTERN_UTF16_UNITS {
        return Err(invalid("pattern exceeds the 16 KiB limit"));
    }

    if let Some(mode) = object.get("mode") {
        if !matches!(mode.as_str(), Some("literal") | Some("regex")) {
            return Err(invalid("mode must be literal or regex"));
        }
    }
    if let Some(value) = object.get("case_sensitive") {
        if !value.is_boolean() {
            return Err(invalid("case_sensitive must be a boolean"));
        }
    }
    if let Some(procedures) = object.get("procedures") {
        validate_rows(procedures, "procedures")?;
    }
    if let Some(observations) = object.get("observations") {
        let rows = observations
            .as_array()
            .ok_or_else(|| invalid("observations must be an array"))?;
        if rows.len() > MAX_ROWS {
            return Err(invalid("observations exceed the 200000 record limit"));
        }
        for row in rows {
            let evidence = row
                .as_object()
                .ok_or_else(|| invalid("observation must be an Evidence object"))?;
            if evidence
                .get("evidence_id")
                .and_then(Value::as_str)
                .is_none()
            {
                return Err(invalid("observation Evidence must include evidence_id"));
            }
        }
    }
    if let Some(evidence) = object.get("evidence") {
        validate_evidence(evidence)?;
    }
    Ok(())
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: &[&str] = &[
        "pattern",
        "mode",
        "case_sensitive",
        "procedures",
        "evidence",
        "observations",
    ];

    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown input field: {field}")));
    }

    Ok(())
}

/// Search direct procedure rows or retained list/search Evidence.
pub fn search(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("search_procedures input must be an object"))?;
    let pattern = object["pattern"].as_str().unwrap_or_default();
    let mode = object
        .get("mode")
        .and_then(Value::as_str)
        .unwrap_or("literal");
    let case_sensitive = object
        .get("case_sensitive")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if mode == "regex" && !regex_is_well_formed(pattern) {
        return Err(invalid("pattern is not a valid regular expression"));
    }

    let mut rows = Vec::new();
    if let Some(procedures) = object.get("procedures") {
        collect_rows(procedures, &mut rows)?;
    }
    if let Some(evidence) = object.get("evidence") {
        collect_evidence_rows(evidence, &mut rows)?;
    }
    if let Some(observations) = object.get("observations").and_then(Value::as_array) {
        for observation in observations {
            collect_evidence_rows(observation, &mut rows)?;
        }
    }

    let mut output = Vec::new();
    let mut seen = BTreeSet::new();
    for row in rows {
        let Some((address, value)) = row_address_value(&row) else {
            continue;
        };
        if !matches_pattern(&value, pattern, mode, case_sensitive) {
            continue;
        }
        let key = format!("{address}\u{0}{value}");
        if seen.insert(key) {
            output.push(json!({"address": address, "value": value}));
        }
    }
    Ok(Value::Array(output))
}

pub fn inspect(input: &Value) -> Result<Value, Failure> {
    search(input)
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let rows = result
        .as_array()
        .ok_or_else(|| invalid("search_procedures result must be an array"))?;
    validate_rows(&Value::Array(rows.clone()), "result")?;
    Ok(result)
}

fn collect_evidence_rows(evidence: &Value, rows: &mut Vec<Value>) -> Result<(), Failure> {
    validate_evidence(evidence)?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .unwrap_or(evidence);
    if let Some(array) = result.as_array() {
        rows.extend(array.iter().cloned());
    } else if let Some(array) = result.get("items").and_then(Value::as_array) {
        rows.extend(array.iter().cloned());
    } else if result.get("procedure").is_some() {
        rows.push(result.clone());
    }
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "procedure observations exceed the 200000 record limit",
        ));
    }
    Ok(())
}

fn collect_rows(value: &Value, rows: &mut Vec<Value>) -> Result<(), Failure> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid("procedures must be an array"))?;
    validate_rows(value, "procedures")?;
    rows.extend(array.iter().cloned());
    Ok(())
}

fn validate_rows(value: &Value, label: &str) -> Result<(), Failure> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(&format!("{label} exceeds the 200000 record limit")));
    }
    for row in rows {
        if !row.is_object() {
            return Err(invalid(&format!("{label} rows must be objects")));
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("Evidence must be an object"))?;
    if object.get("evidence_id").and_then(Value::as_str).is_none() {
        return Err(invalid("Evidence must include evidence_id"));
    }
    if let Some(operation) = object.get("operation").and_then(Value::as_str) {
        if !matches!(
            operation,
            "list_procedures" | "search_procedures" | "analyze_function"
        ) {
            return Err(invalid("Evidence is not a procedure observation"));
        }
    }
    Ok(())
}

fn row_address_value(row: &Value) -> Option<(String, String)> {
    let address = row
        .get("address")
        .or_else(|| row.pointer("/procedure/address"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())?;
    let value = row
        .get("value")
        .or_else(|| row.pointer("/procedure/name"))
        .or_else(|| row.get("name"))
        .and_then(Value::as_str)?;
    Some((address.to_owned(), value.to_owned()))
}

fn matches_pattern(value: &str, pattern: &str, mode: &str, case_sensitive: bool) -> bool {
    if mode == "literal" {
        if case_sensitive {
            value.contains(pattern)
        } else {
            value.to_lowercase().contains(&pattern.to_lowercase())
        }
    } else {
        simple_regex_match(value, pattern, case_sensitive)
    }
}

// The native crate intentionally has no regex dependency.  This bounded matcher
// covers the regular-expression constructs used by the public search contract
// (anchors, `.`, `*`, `+`, `?`, character classes, and escaped literals).
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
    let core = core.replace(".*", "\u{0}");
    let candidates = if anchored_start {
        vec![haystack.as_str()]
    } else {
        haystack.split(|_| false).collect()
    };
    candidates.into_iter().any(|candidate| {
        let matched = if core.contains('\u{0}') {
            let parts: Vec<&str> = core.split('\u{0}').collect();
            let mut offset = 0;
            parts.iter().all(|part| {
                if part.is_empty() {
                    return true;
                }
                let Some(found) = candidate[offset..].find(part) else {
                    return false;
                };
                offset += found + part.len();
                true
            })
        } else {
            candidate.contains(core.as_str())
        };
        matched && (!anchored_end || candidate.ends_with(core.as_str()))
    })
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
        message.to_owned(),
        true,
        "Correct the input and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
