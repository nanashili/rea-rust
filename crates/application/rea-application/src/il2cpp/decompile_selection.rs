//! Select safe native decompilation selectors from retained IL2CPP facts.
//!
//! This boundary joins two already-produced projections. It never opens an
//! artifact and never turns an unresolved or ambiguous method into an address.
//! Every selected row retains the source method and the source Evidence IDs so
//! a host workflow can carry provenance into its Ghidra request.

use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::Failure;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "select_il2cpp_decompilation_targets";
const MAX_ROWS: usize = 200_000;

/// Select only uniquely mapped, executable method pointers.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = required_source(root, &["metadata", "metadata_evidence"], "metadata")?;
    let mapping = required_source(
        root,
        &["method_addresses", "method_address_mapping", "mapping"],
        "method_addresses",
    )?;
    let metadata_source = source_identity(metadata, "metadata")?;
    let mapping_source = source_identity(mapping, "method_addresses")?;
    let metadata_result = normalized_result(metadata, "metadata")?;
    let mapping_result = normalized_result(mapping, "method_addresses")?;
    let methods = rows(&metadata_result, &["methods", "method_definitions"])?
        .ok_or_else(|| invalid("metadata.normalized_result", "Metadata methods are missing"))?;
    let mapped_items = rows(&mapping_result, &["items", "mappings"])?.ok_or_else(|| {
        invalid(
            "method_addresses.normalized_result",
            "Mapping items are missing",
        )
    })?;
    if methods.len() > MAX_ROWS || mapped_items.len() > MAX_ROWS {
        return Err(resource("IL2CPP selection exceeds the supported row limit"));
    }

    let requested_selectors = requested_selectors(root)?;

    let mut items = Vec::with_capacity(mapped_items.len());
    let mut selected = 0usize;
    let mut unresolved = 0usize;
    let mut ambiguous = 0usize;
    let mut address_counts = BTreeMap::new();
    for mapping_item in mapped_items {
        if let Some(address) = mapping_item
            .as_object()
            .and_then(|item| item.get("method_pointer"))
            .and_then(pointer_address)
        {
            *address_counts
                .entry(address_identity_key(&address))
                .or_insert(0usize) += 1;
        }
    }

    let selection_rows = selection_rows(mapped_items, requested_selectors.as_deref());
    for (index, (mapping_item, requested_selector, forced_status)) in
        selection_rows.into_iter().enumerate()
    {
        let object = mapping_item.as_ref().and_then(Value::as_object);
        if mapping_item.is_some() && object.is_none() {
            return Err(invalid_row(index, "Mapping item must be an object"));
        }
        let (method_index, method_index_ambiguous) =
            object.map(mapping_method_index).unwrap_or((None, false));
        let method = if method_index_ambiguous {
            None
        } else {
            method_index
                .and_then(|value| methods.get(value))
                .cloned()
                .or_else(|| object.and_then(|object| object.get("method").cloned()))
        };
        let resolution = object
            .and_then(|object| object.get("resolution"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let pointer = object.and_then(|object| object.get("method_pointer"));
        let address = pointer.and_then(pointer_address);
        let status = if let Some(forced_status) = forced_status {
            if forced_status == "ambiguous" {
                ambiguous += 1;
            } else {
                unresolved += 1;
            }
            forced_status
        } else if resolution == "ambiguous" {
            ambiguous += 1;
            "ambiguous"
        } else if method_index_ambiguous {
            ambiguous += 1;
            "ambiguous"
        } else if resolution != "mapped" || method.is_none() || address.is_none() {
            unresolved += 1;
            "unresolved"
        } else if address
            .as_ref()
            .map(|value| address_identity_key(value))
            .and_then(|value| address_counts.get(&value))
            .is_some_and(|count| *count > 1)
        {
            ambiguous += 1;
            "ambiguous"
        } else {
            selected += 1;
            "selected"
        };
        let mut item = Map::new();
        item.insert(
            "mapping".into(),
            mapping_item.clone().unwrap_or(Value::Null),
        );
        item.insert("method".into(), method.unwrap_or(Value::Null));
        item.insert("status".into(), Value::String(status.into()));
        item.insert(
            "selector".into(),
            requested_selector
                .or(address)
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        item.insert("metadata_source_evidence".into(), metadata_source.clone());
        item.insert("mapping_source_evidence".into(), mapping_source.clone());
        items.push(Value::Object(item));
    }

    let selectors = items
        .iter()
        .filter_map(|item| {
            (item.get("status").and_then(Value::as_str) == Some("selected"))
                .then(|| item.get("selector").cloned().unwrap_or(Value::Null))
        })
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "operation": OPERATION,
        "status": if unresolved > 0 || ambiguous > 0 { "partial" } else { "complete" },
        "items": items,
        "selectors": selectors,
        "coverage": { "methods": methods.len(), "mapped": selected, "unresolved": unresolved, "ambiguous": ambiguous }
    }))
}

fn requested_selectors(root: &Map<String, Value>) -> Result<Option<Vec<String>>, Failure> {
    let Some(value) = root.get("selectors") else {
        return Ok(None);
    };
    let selectors = value
        .as_array()
        .ok_or_else(|| invalid("selectors", "Selectors must be an array"))?;
    if selectors.len() > MAX_ROWS {
        return Err(resource(
            "IL2CPP selector count exceeds the supported row limit",
        ));
    }
    selectors
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|selector| !selector.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| {
                    invalid(
                        &format!("selectors[{index}]"),
                        "Selector must be non-empty text",
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

fn selection_rows(
    mapped_items: &[Value],
    requested_selectors: Option<&[String]>,
) -> Vec<(Option<Value>, Option<String>, Option<&'static str>)> {
    let Some(requested_selectors) = requested_selectors else {
        return mapped_items
            .iter()
            .cloned()
            .map(|item| (Some(item), None, None))
            .collect();
    };

    requested_selectors
        .iter()
        .map(|selector| {
            let matches = mapped_items
                .iter()
                .filter(|item| {
                    item.as_object()
                        .and_then(|object| object.get("method_pointer"))
                        .and_then(pointer_address)
                        .is_some_and(|address| selector_matches(selector, &address))
                })
                .collect::<Vec<_>>();
            match matches.as_slice() {
                [] => (None, Some(selector.clone()), Some("unresolved")),
                [item] => (Some((*item).clone()), Some(selector.clone()), None),
                [first, ..] => (
                    Some((*first).clone()),
                    Some(selector.clone()),
                    Some("ambiguous"),
                ),
            }
        })
        .collect()
}

fn selector_matches(left: &str, right: &str) -> bool {
    left == right
        || match (parse_address_text(left), parse_address_text(right)) {
            (Some(left), Some(right)) => left == right,
            _ => false,
        }
}

fn address_identity_key(address: &str) -> String {
    parse_address_text(address)
        .map(|address| format!("0x{address:x}"))
        .unwrap_or_else(|| address.to_owned())
}

fn parse_address_text(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn mapping_method_index(object: &Map<String, Value>) -> (Option<usize>, bool) {
    let mut selected = None;
    let mut ambiguous = false;

    for name in ["method_index", "index"] {
        let Some(value) = object.get(name) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let Some(value) = value
            .as_u64()
            .or_else(|| value.as_str().and_then(parse_address_text))
        else {
            ambiguous = true;
            continue;
        };
        let Some(value) = usize::try_from(value).ok() else {
            ambiguous = true;
            continue;
        };
        if selected.is_some_and(|existing| existing != value) {
            ambiguous = true;
        } else if selected.is_none() {
            selected = Some(value);
        }
    }

    (selected, ambiguous)
}

fn required_source<'a>(
    root: &'a Map<String, Value>,
    names: &[&str],
    field: &str,
) -> Result<&'a Value, Failure> {
    let mut selected = None;
    for name in names {
        let Some(value) = root.get(*name) else {
            continue;
        };
        if let Some(existing) = selected {
            if existing != value {
                return Err(invalid(
                    field,
                    "Source aliases disagree; caller-selected evidence is ambiguous",
                ));
            }
        } else {
            selected = Some(value);
        }
    }
    selected.ok_or_else(|| invalid(field, "A retained source projection is required"))
}

fn normalized_result(value: &Value, _field: &str) -> Result<Value, Failure> {
    if let Some(object) = value.as_object() {
        if let Some(result) = object.get("normalized_result") {
            return Ok(result.clone());
        }
    }
    Ok(value.clone())
}

fn source_identity(value: &Value, field: &str) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(field, "Source must be an object"))?;
    if object.get("evidence_id").is_none() {
        return Err(invalid(field, "Source must retain evidence_id"));
    }
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(field, &error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(field, &error.to_string()))?;
    let operation = serde_json::from_str::<String>(record.operation().get())
        .map_err(|error| invalid(field, &error.to_string()))?;
    Ok(serde_json::json!({
        "evidence_id": record.evidence_id(),
        "operation": operation
    }))
}

fn rows<'a>(result: &'a Value, names: &[&str]) -> Result<Option<&'a Vec<Value>>, Failure> {
    let mut selected = None;
    for name in names {
        let Some(value) = result.get(*name) else {
            continue;
        };
        let rows = value
            .as_array()
            .ok_or_else(|| invalid("normalized_result", "Collection alias must be an array"))?;
        if let Some(existing) = selected {
            if existing != rows {
                return Err(invalid(
                    "normalized_result",
                    "Collection aliases disagree; method selection is ambiguous",
                ));
            }
        } else {
            selected = Some(rows);
        }
    }
    Ok(selected)
}

fn pointer_address(pointer: &Value) -> Option<String> {
    let Some(object) = pointer.as_object() else {
        return pointer
            .as_str()
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .or_else(|| pointer.as_u64().map(|number| format!("0x{number:x}")));
    };

    let mut selected = None;
    for field in [
        "address",
        "target_virtual_address",
        "virtual_address",
        "pointer",
    ] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let candidate = value
            .as_str()
            .filter(|text| !text.is_empty())
            .map(str::to_owned)
            .or_else(|| value.as_u64().map(|number| format!("0x{number:x}")))?;
        if selected
            .as_deref()
            .is_some_and(|existing| !selector_matches(existing, &candidate))
        {
            return None;
        }
        selected = Some(candidate);
    }
    selected
}

fn invalid(field: &str, message: &str) -> Failure {
    let text = format!("{field}: {message}");
    Failure::new(
        "invalid_request",
        "invalid_input",
        text.clone(),
        false,
        "Correct the retained IL2CPP projections and retry.".into(),
        BTreeMap::from([
            (
                "operation",
                rea_core::failure::Detail::Text(OPERATION.into()),
            ),
            ("reason", rea_core::failure::Detail::Text(text)),
        ]),
    )
}
fn invalid_row(index: usize, message: &str) -> Failure {
    invalid(&format!("method_addresses.items[{index}]"), message)
}
fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_limit",
        "resource_exhausted",
        message.into(),
        false,
        "Reduce the retained IL2CPP projection and retry.".into(),
        BTreeMap::from([(
            "operation",
            rea_core::failure::Detail::Text(OPERATION.into()),
        )]),
    )
}
