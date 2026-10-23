//! Symbol-only Objective-C and Swift dispatch metadata projection.
//!
//! The binary provider can supply richer metadata, but a name inventory is a
//! useful read-only fallback. This module only interprets names already
//! authenticated by the caller; it never opens or mutates a binary database.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_native_dispatch_metadata";
pub const DEFAULT_MAX_RECORDS: usize = 5_000;
pub const MAX_RECORDS: usize = 20_000;

/// Project a caller-owned name inventory into the normalized metadata shape.
pub fn inspect_names(names: &[Value], max_records: usize) -> Result<Value, Failure> {
    let limit = bounded_limit(max_records)?;
    let mut classes = BTreeSet::new();
    let mut implementations = BTreeMap::<String, Value>::new();
    let mut swift_symbols = Vec::new();
    let examined = names.len().min(limit);

    for entry in names.iter().take(examined) {
        let (address, name) = parse_name_entry(entry)?;
        let location_address = non_empty_address(&address);
        let location = json!({"address": location_address.clone(), "file_offset": Value::Null});
        let evidence = symbol_evidence(&name, &address);

        if let Some(class_name) = objc_class_name(&name) {
            classes.insert(class_name);
        }

        if let Some((method_type, class_name, selector)) = objc_method_name(&name) {
            classes.insert(class_name.clone());
            let key = format!("{class_name}\u{1f}{selector}\u{1f}{method_type}");
            implementations.insert(
                key,
                json!({
                    "class_name": class_name,
                    "selector": selector,
                    "method_type": method_type,
                    "implementation_address": location_address.clone(),
                    "location": location,
                    "decode": {"status": "partial", "reason": "symbol_name_only"},
                    "evidence": evidence,
                }),
            );
        }

        if is_swift_symbol(&name) {
            swift_symbols.push(json!({
                "mangled_name": name,
                "address": location_address,
                "decode": {"status": "partial", "reason": "mangled_symbol_not_demangled"},
                "evidence": evidence,
            }));
        }
    }

    let implementation_values: Vec<Value> = implementations.into_values().collect();
    let mut class_values = Vec::with_capacity(classes.len());
    for name in classes {
        let methods = implementation_values
            .iter()
            .filter(|record| record.get("class_name").and_then(Value::as_str) == Some(name.as_str()))
            .map(|record| {
                json!({
                    "selector": record.get("selector").cloned().unwrap_or(Value::Null),
                    "method_type": record.get("method_type").cloned().unwrap_or(Value::Null),
                    "address": parse_metadata_address(record.get("implementation_address").and_then(Value::as_str)),
                    "is_required": Value::Null,
                    "is_optional": Value::Null,
                })
            })
            .collect::<Vec<_>>();
        class_values.push(json!({
            "name": name,
            "super_class": Value::Null,
            "is_meta_class": Value::Null,
            "is_root_class": Value::Null,
            "methods": methods,
            "properties": [],
            "protocols": [],
            "ivar_count": Value::Null,
            "instance_size": Value::Null,
        }));
    }

    let has_swift = !swift_symbols.is_empty();
    let truncated = names.len() > examined;
    let class_count = class_values.len();
    let implementation_count = implementation_values.len();
    let swift_count = swift_symbols.len();
    Ok(json!({
        "objc_classes": class_values,
        "objc_dispatch_implementations": implementation_values,
        "swift_symbols": swift_symbols,
        "coverage": coverage(examined, class_count, implementation_count, swift_count, truncated, has_swift),
        "db_save_result": Value::Null,
    }))
}

/// Parse the application boundary, accepting either `names` or a selected
/// symbol Evidence record whose normalized result is an array.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let max_records = object
        .get("max_records")
        .and_then(Value::as_u64)
        .unwrap_or(DEFAULT_MAX_RECORDS as u64) as usize;
    let names = object
        .get("names")
        .or_else(|| object.get("symbols"))
        .or_else(|| {
            object
                .get("evidence")
                .and_then(|e| e.get("normalized_result"))
        })
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("names must be an array of provider symbol records"))?;
    inspect_names(names, max_records)
}

fn parse_name_entry(entry: &Value) -> Result<(Value, String), Failure> {
    let object = entry
        .as_object()
        .ok_or_else(|| invalid("symbol record must be an object"))?;
    let address = match object.get("address") {
        Some(value) if value.is_string() => value.clone(),
        Some(_) => return Err(invalid("symbol address must be a string")),
        None => Value::String(String::new()),
    };
    let name = object
        .get("name")
        .or_else(|| object.get("value"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("symbol record must contain a non-empty name"))?;
    Ok((address, name.to_owned()))
}

fn symbol_evidence(name: &str, address: &Value) -> Value {
    let address_text = non_empty_address(address);
    let has_location = !address_text.is_null();
    let mut evidence = json!({
        "kind": "symbol",
        "description": format!("Provider symbol {name}"),
        "location": {"address": address_text, "file_offset": Value::Null},
        "artifact_path": Value::Null,
        "artifact_sha256": Value::Null,
    });
    if !has_location {
        evidence["reported_address"] = address.clone();
    }
    evidence
}

fn objc_class_name(name: &str) -> Option<String> {
    ["OBJC_CLASS_$_", "OBJC_METACLASS_$_"]
        .iter()
        .find_map(|prefix| name.strip_prefix(prefix).map(ToOwned::to_owned))
        .filter(|value: &String| !value.is_empty())
}

fn objc_method_name(name: &str) -> Option<(String, String, String)> {
    let (method_type, rest) = match name.strip_prefix("+-") {
        Some(_) => return None,
        None => match name.strip_prefix('+') {
            Some(rest) => ("class", rest),
            None => ("instance", name.strip_prefix('-')?),
        },
    };
    let rest = rest.strip_prefix('[')?.strip_suffix(']')?;
    let separator = rest.find(char::is_whitespace)?;
    let (class_name, selector) = rest.split_at(separator);
    let selector = selector.trim();
    if class_name.is_empty() || selector.is_empty() || selector.contains(']') {
        return None;
    }
    Some((
        method_type.to_owned(),
        class_name.to_owned(),
        selector.to_owned(),
    ))
}

fn is_swift_symbol(name: &str) -> bool {
    name.starts_with("$s")
        || name.starts_with("$S")
        || name.starts_with("_$s")
        || name.starts_with("_Tt")
}

fn non_empty_address(address: &Value) -> Value {
    address
        .as_str()
        .filter(|value| !value.is_empty())
        .map(|value| Value::String(value.to_owned()))
        .unwrap_or(Value::Null)
}

fn parse_metadata_address(address: Option<&str>) -> Value {
    let Some(address) = address else {
        return Value::Null;
    };
    let Some(hex) = address.rsplit_once("0x").map(|(_, value)| value) else {
        return Value::Null;
    };
    u64::from_str_radix(hex, 16)
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
        .map(|value| Value::Number(value.into()))
        .unwrap_or(Value::Null)
}

fn coverage(
    examined: usize,
    classes: usize,
    methods: usize,
    swift: usize,
    truncated: bool,
    has_swift: bool,
) -> Vec<Value> {
    vec![
        json!({"facet":"objc_class_symbols","status":"partial","reason": if truncated {"record_limit_reached_and_symbol_names_are_not_runtime_class_metadata"} else {"symbol_names_do_not_recover_all_runtime_class_metadata"},"examined":examined,"decoded":classes}),
        json!({"facet":"objc_dispatch_implementations","status": if methods > 0 {"partial"} else {"unsupported"},"reason": if truncated {"record_limit_reached_and_only_symbolized_methods_are_resolved"} else if methods > 0 {"only_symbolized_methods_are_resolved"} else {"provider_name_inventory_has_no_objc_method_symbols"},"examined":examined,"decoded":methods}),
        json!({"facet":"objc_ivar_layouts","status":"unsupported","reason":"symbol_inventory_does_not_expose_runtime_ivar_layouts","examined":0,"decoded":0}),
        json!({"facet":"swift_declarations","status": if has_swift {"partial"} else {"unsupported"},"reason": if has_swift {"symbols_are_not_demangled_declarations"} else {"no_swift_symbols_observed"},"examined":swift,"decoded":0}),
        json!({"facet":"swift_dispatch_tables","status":"unsupported","reason":"provider_name_inventory_does_not_decode_witness_or_class_vtables","examined":0,"decoded":0}),
        json!({"facet":"relative_pointers","status":"unsupported","reason":"provider_name_inventory_does_not_decode_binary_relative_pointers","examined":0,"decoded":0}),
    ]
}

fn bounded_limit(value: usize) -> Result<usize, Failure> {
    if value == 0 || value > MAX_RECORDS {
        return Err(invalid("max_records must be between 1 and 20,000"));
    }
    Ok(value)
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide a valid native symbol inventory.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}
