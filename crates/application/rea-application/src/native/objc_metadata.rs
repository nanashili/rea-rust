//! Provider-neutral Objective-C symbol projections.
//!
//! The historical enhanced tools compose `list_names` and then classify the
//! retained name observations.  This module keeps that interpretation in one
//! native boundary.  It never opens an analysis database or attempts to
//! decode Objective-C metadata from bytes; a provider that has such facts can
//! feed its normalized name observations into this projection.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const CLASSES_OPERATION: &str = "get_objc_classes";
pub const PROTOCOLS_OPERATION: &str = "get_objc_protocols";
const MAX_NAMES: usize = 200_000;

/// Validate the small enhanced-tool input shared by both projections.
pub fn validate_input(input: &Value, operation: &str) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(operation, "Objective-C discovery input must be an object"))?;
    for key in object.keys() {
        if key != "pattern" && key != "names" && key != "evidence" {
            return Err(invalid(operation, &format!("unknown input field: {key}")));
        }
    }
    if let Some(pattern) = object.get("pattern")
        && !pattern.is_string()
    {
        return Err(invalid(operation, "pattern must be a string"));
    }
    if let Some(names) = object.get("names") {
        parse_names(names, operation)?;
    }
    Ok(())
}

/// Project Objective-C class labels from authenticated name observations.
pub fn classes(input: &Value) -> Result<Value, Failure> {
    let parsed = parse_input(input, CLASSES_OPERATION)?;
    let pattern = parsed.pattern.as_deref().unwrap_or("");
    let classes = unique_entries(
        parsed
            .names
            .into_iter()
            .filter(|entry| is_objc_class(&entry.name))
            .filter(|entry| pattern.is_empty() || entry.name.contains(pattern)),
    );
    Ok(json!({ "count": classes.len(), "classes": classes }))
}

/// Project Objective-C and Swift protocol labels from authenticated names.
pub fn protocols(input: &Value) -> Result<Value, Failure> {
    let parsed = parse_input(input, PROTOCOLS_OPERATION)?;
    let protocols = unique_entries(
        parsed
            .names
            .into_iter()
            .filter(|entry| is_objc_protocol(&entry.name)),
    );
    Ok(json!({ "count": protocols.len(), "protocols": protocols }))
}

/// Validate a result retained by a runtime adapter before Evidence wrapping.
pub fn retain_result(input: &Value, result: Value, operation: &str) -> Result<Value, Failure> {
    validate_input(input, operation)?;
    let object = result
        .as_object()
        .ok_or_else(|| invalid(operation, "symbol discovery result must be an object"))?;
    let property = if operation == CLASSES_OPERATION {
        "classes"
    } else {
        "protocols"
    };
    let entries = object
        .get(property)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(operation, &format!("result.{property} must be an array")))?;
    if entries.len() > MAX_NAMES {
        return Err(invalid(
            operation,
            "symbol discovery result exceeds the record limit",
        ));
    }
    for entry in entries {
        parse_entry(entry, operation)?;
    }
    let count = object.get("count").and_then(Value::as_u64).ok_or_else(|| {
        invalid(
            operation,
            "symbol discovery result.count must be an integer",
        )
    })?;
    if count as usize != entries.len() {
        return Err(invalid(
            operation,
            "symbol discovery result.count does not match its entries",
        ));
    }
    Ok(result)
}

#[derive(Clone)]
struct NameEntry {
    address: String,
    name: String,
}

struct ParsedInput {
    names: Vec<NameEntry>,
    pattern: Option<String>,
}

fn parse_input(input: &Value, operation: &str) -> Result<ParsedInput, Failure> {
    validate_input(input, operation)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid(operation, "Objective-C discovery input must be an object"))?;
    let names = if let Some(value) = object.get("names") {
        parse_names(value, operation)?
    } else if let Some(evidence) = object.get("evidence") {
        parse_evidence_names(evidence, operation)?
    } else {
        return Err(invalid(operation, "names or evidence is required"));
    };
    Ok(ParsedInput {
        names,
        pattern: object
            .get("pattern")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

fn parse_names(value: &Value, operation: &str) -> Result<Vec<NameEntry>, Failure> {
    let records = value
        .as_array()
        .ok_or_else(|| invalid(operation, "names must be an array"))?;
    if records.len() > MAX_NAMES {
        return Err(invalid(operation, "names exceeds the 200000 record limit"));
    }
    records
        .iter()
        .map(|record| parse_entry(record, operation))
        .collect()
}

fn parse_evidence_names(value: &Value, operation: &str) -> Result<Vec<NameEntry>, Failure> {
    let evidence = value
        .as_object()
        .ok_or_else(|| invalid(operation, "evidence must be an object"))?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .unwrap_or(value);
    let names = result
        .get("names")
        .or_else(|| result.get("items"))
        .or_else(|| result.get("value"))
        .unwrap_or(result);
    parse_names(names, operation)
}

fn parse_entry(value: &Value, operation: &str) -> Result<NameEntry, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(operation, "name entry must be an object"))?;
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(operation, "name entry requires a non-empty address"))?;
    let name = object
        .get("name")
        .or_else(|| object.get("value"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(operation, "name entry requires a non-empty name"))?;
    Ok(NameEntry {
        address: address.to_owned(),
        name: name.to_owned(),
    })
}

fn unique_entries(entries: impl IntoIterator<Item = NameEntry>) -> Vec<Value> {
    let mut seen = BTreeMap::new();
    let mut output = Vec::new();
    for entry in entries {
        if seen.contains_key(&entry.name) {
            continue;
        }
        seen.insert(entry.name.clone(), ());
        output.push(json!({ "address": entry.address, "name": entry.name }));
    }
    output
}

fn is_objc_class(name: &str) -> bool {
    name.contains("OBJC_CLASS_$_")
        || (name.starts_with("l_OBJC_CLASS_")
            && name.len() > "l_OBJC_CLASS_".len()
            && !is_legacy_class_name(name))
}

fn is_legacy_class_name(name: &str) -> bool {
    let prefix = "l_OBJC_CLASS_NAME_";
    if !name.starts_with(prefix) {
        return false;
    }
    name[prefix.len()..].is_empty()
        || name[prefix.len()..]
            .trim_start_matches('.')
            .chars()
            .all(|c| c.is_ascii_digit())
}

fn is_objc_protocol(name: &str) -> bool {
    name.contains("OBJC_PROTOCOL_$_")
        || name.contains("_TtP")
        || (name.ends_with("Mp") && swift_protocol_mangling(name))
}

fn swift_protocol_mangling(name: &str) -> bool {
    let prefix = ["__T0", "_$s", "_$S", "$s", "$S", "_T0"]
        .iter()
        .find(|prefix| name.starts_with(**prefix));
    let Some(prefix) = prefix else {
        return false;
    };
    let mangling = &name[prefix.len()..];
    let Some(mut offset) = identifier_end(mangling, 0) else {
        return false;
    };
    let mut category = None;
    loop {
        let Some(identifier_end) = identifier_end(mangling, offset) else {
            break;
        };
        let Some(kind) = mangling.as_bytes().get(identifier_end).copied() else {
            break;
        };
        match kind {
            b'C' | b'V' | b'O' | b'P' => {
                category = Some(kind);
                offset = identifier_end + 1;
            }
            b'E' if category.is_some() => {
                category = Some(b'E');
                break;
            }
            _ if mangling.get(identifier_end..) == Some("Mp") => {
                category = Some(b'P');
                break;
            }
            _ => break,
        }
    }
    category == Some(b'P')
}

fn identifier_end(mangling: &str, offset: usize) -> Option<usize> {
    let bytes = mangling.as_bytes();
    let mut cursor = offset;
    if !bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_digit() && *byte != b'0')
    {
        return None;
    }
    while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
        cursor += 1;
    }
    let length = mangling.get(offset..cursor)?.parse::<usize>().ok()?;
    let end = cursor.checked_add(length)?;
    let identifier = mangling.get(cursor..end)?;
    if identifier.is_empty()
        || !identifier.chars().enumerate().all(|(index, character)| {
            if index == 0 {
                character.is_ascii_alphabetic() || character == '_'
            } else {
                character.is_ascii_alphanumeric() || character == '_'
            }
        })
    {
        return None;
    }
    Some(end)
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated Objective-C name observations and a supported discovery input."
            .into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
