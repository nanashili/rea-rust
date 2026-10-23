//! Join IL2CPP method metadata to captured native method-pointer facts.
//!
//! This module consumes normalized rows from the metadata and image/codegen
//! readers. It deliberately requires an explicit identity (or an explicit
//! pointer-table slot) on both sides of a join. Display names and array
//! position are retained as evidence, but never establish ownership.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "link_il2cpp_methods_to_native";
const MAX_ROWS: usize = 200_000;

/// Correlate method rows with native pointer/codegen rows while preserving
/// unresolved and ambiguous candidates for downstream investigation.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let native = root
        .get("native")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let methods = rows(
        metadata,
        &["methods", "method_definitions", "metadata_methods"],
        "methods",
    )?;
    let native_rows = native_rows(native)?;
    let candidates = index_candidates(&native_rows)?;

    let mut items = Vec::with_capacity(methods.len());
    let mut counts = BTreeMap::from([
        ("mapped", 0usize),
        ("unknown", 0usize),
        ("ambiguous", 0usize),
        ("unmapped", 0usize),
    ]);

    for (index, method) in methods.iter().enumerate() {
        let method_object = method
            .as_object()
            .ok_or_else(|| invalid_row("methods", index, "Expected an object"))?;
        let identity = explicit_identity(method_object, "methods", index)?;
        let slot = explicit_slot(method_object, "methods", index)?;
        let matches = matching_candidates(&candidates, identity.as_ref(), slot);
        let resolution = resolution_for(&matches);
        *counts
            .get_mut(resolution)
            .expect("resolution is a closed set") += 1;

        let candidate_identities = matches
            .iter()
            .map(|candidate| candidate.identity.clone())
            .collect::<Vec<_>>();
        let native_value = if matches.len() == 1 && resolution == "mapped" {
            matches[0].row.clone()
        } else {
            Value::Null
        };
        let source = matches
            .iter()
            .map(|candidate| candidate.source.clone())
            .collect::<Vec<_>>();

        items.push(serde_json::json!({
            "input_index": index,
            "method": method,
            "method_identity": identity,
            "method_pointer_slot": slot,
            "native": native_value,
            "native_candidates": candidate_identities,
            "native_sources": source,
            "resolution": resolution,
        }));
    }

    let complete = counts["unknown"] == 0
        && counts["ambiguous"] == 0
        && counts["unmapped"] == 0;
    Ok(serde_json::json!({
        "operation": OPERATION,
        "status": if complete { "complete" } else { "partial" },
        "items": items,
        "coverage": {
            "methods": methods.len(),
            "native_candidates": candidates.len(),
            "mapped": counts["mapped"],
            "unknown": counts["unknown"],
            "ambiguous": counts["ambiguous"],
            "unmapped": counts["unmapped"],
        },
    }))
}

#[derive(Clone, Debug)]
struct Candidate {
    row: Value,
    identity: Value,
    source: Value,
    identity_key: Option<String>,
    slot: Option<u64>,
    address_ambiguous: bool,
}

fn native_rows(native: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    let row_aliases = ["method_pointers", "method_pointer_rows", "native_methods"];
    if let Some(rows) = collection_alias(native, &row_aliases, "native")? {
        bounded_rows(rows, "native")?;
        return Ok(rows
            .iter()
            .enumerate()
            .map(|(position, value)| add_positional_slot(value, position))
            .collect());
    }

    let module_aliases = ["codegen_modules", "modules", "method_pointer_modules"];
    let modules = collection_alias(native, &module_aliases, "native")?.ok_or_else(|| {
        invalid("native", "Expected native method rows or codegen modules")
    })?;
    if modules.len() > MAX_ROWS {
        return Err(invalid("native", "Collection exceeds the IL2CPP row limit"));
    }

    let mut flattened = Vec::new();
    for (module_index, module) in modules.iter().enumerate() {
        let object = module
            .as_object()
            .ok_or_else(|| {
                invalid_row("codegen_modules", module_index, "Expected an object")
            })?;
        let pointer_aliases = ["method_pointers", "method_pointer_rows"];
        let pointers = collection_alias(object, &pointer_aliases, "codegen_modules")?
            .ok_or_else(|| {
                invalid_row(
                    "codegen_modules",
                    module_index,
                    "method_pointers must be an array",
                )
            })?;
        let module_identity = identity_value(object);
        for (position, pointer) in pointers.iter().enumerate() {
            let mut row = pointer.clone();
            if let Some(row_object) = row.as_object_mut() {
                if !row_object.contains_key("module_identity") {
                    row_object.insert("module_identity".into(), module_identity.clone());
                }
                if !row_object.contains_key("slot") && !row_object.contains_key("index") {
                    row_object.insert("slot".into(), Value::from(position as u64));
                }
            }
            flattened.push(row);
            if flattened.len() > MAX_ROWS {
                return Err(invalid("native", "Collection exceeds the IL2CPP row limit"));
            }
        }
    }
    Ok(flattened)
}

fn add_positional_slot(value: &Value, position: usize) -> Value {
    let Some(object) = value.as_object() else {
        return serde_json::json!({
            "slot": position,
            "pointer": value,
            "source": value,
        });
    };
    if object.contains_key("slot")
        || object.contains_key("index")
        || object.contains_key("method_pointer_slot")
        || object.contains_key("pointer_slot")
    {
        return value.clone();
    }
    let mut enriched = object.clone();
    enriched.insert("slot".into(), Value::from(position as u64));
    Value::Object(enriched)
}

fn index_candidates(rows: &[Value]) -> Result<Vec<Candidate>, Failure> {
    let mut candidates = Vec::with_capacity(rows.len());
    for (index, row) in rows.iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| invalid_row("native", index, "Expected an object"))?;
        let identity = explicit_identity(object, "native", index)?.unwrap_or_else(|| {
            identity_value(object)
        });
        let identity_key = identity_key(&identity)?;
        let slot = explicit_slot(object, "native", index)?;
        let address_ambiguous = conflicting_address_claims(object);
        let source = object
            .get("source")
            .or_else(|| object.get("provenance"))
            .cloned()
            .unwrap_or_else(|| row.clone());
        candidates.push(Candidate {
            row: row.clone(),
            identity,
            source,
            identity_key,
            slot,
            address_ambiguous,
        });
    }
    Ok(candidates)
}

fn matching_candidates<'a>(
    candidates: &'a [Candidate],
    identity: Option<&Value>,
    slot: Option<u64>,
) -> Vec<&'a Candidate> {
    let key = identity.and_then(identity_key_text);
    candidates
        .iter()
        .filter(|candidate| {
            let identity_matches = key
                .as_ref()
                .zip(candidate.identity_key.as_ref())
                .is_some_and(|(left, right)| left == right);
            let slot_matches = slot
                .zip(candidate.slot)
                .is_some_and(|(left, right)| left == right);
            match (key.is_some(), slot.is_some()) {
                (true, true) => identity_matches && slot_matches,
                (true, false) => identity_matches,
                (false, true) => slot_matches,
                (false, false) => false,
            }
        })
        .collect()
}

fn identity_key_text(value: &Value) -> Option<String> {
    let normalized = match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut normalized = Map::new();
            for (key, child) in entries {
                normalized.insert(key.clone(), normalized_identity(child));
            }
            Value::Object(normalized)
        }
        _ => value.clone(),
    };
    serde_json::to_string(&normalized).ok()
}

fn normalized_identity(value: &Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut entries = object.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let mut normalized = Map::new();
            for (key, child) in entries {
                normalized.insert(key.clone(), normalized_identity(child));
            }
            Value::Object(normalized)
        }
        Value::Array(values) => Value::Array(values.iter().map(normalized_identity).collect()),
        _ => value.clone(),
    }
}

fn resolution_for(matches: &[&Candidate]) -> &'static str {
    if matches.iter().any(|candidate| candidate.address_ambiguous) {
        return "ambiguous";
    }
    match matches.len() {
        0 => "unmapped",
        1 => "mapped",
        _ => "ambiguous",
    }
}

fn explicit_identity(
    object: &Map<String, Value>,
    field: &str,
    row: usize,
) -> Result<Option<Value>, Failure> {
    if conflicting_identity_claims(object) {
        return Err(invalid_row(field, row, "identity aliases disagree"));
    }
    let structured = ["method_identity", "metadata_identity", "identity"];
    let structured_values = structured
        .iter()
        .filter_map(|alias| object.get(*alias).map(|value| (*alias, value.clone())))
        .collect::<Vec<_>>();
    if let Some((_, value)) = structured_values.first() {
        if structured_values
            .iter()
            .skip(1)
            .any(|(_, other)| other != value)
        {
            return Err(invalid_row(field, row, "identity aliases disagree"));
        }
        return Ok(Some(value.clone()));
    }

    let aliases = ["method_index", "metadata_index", "token"];
    let mut values = Vec::new();
    for alias in aliases {
        if let Some(value) = object.get(alias) {
            values.push((alias, value.clone()));
        }
    }
    if values.is_empty() {
        let identity = identity_value(object);
        return Ok((!identity.is_null()).then_some(identity));
    }
    let first = values[0].1.clone();
    if values.iter().skip(1).any(|(_, value)| *value != first) {
        return Err(invalid_row(field, row, "identity aliases disagree"));
    }
    Ok(Some(first))
}

fn conflicting_identity_claims(object: &Map<String, Value>) -> bool {
    let structured = ["method_identity", "metadata_identity", "identity"];
    let structured_values = structured
        .iter()
        .filter_map(|alias| object.get(*alias))
        .collect::<Vec<_>>();
    if structured_values
        .windows(2)
        .any(|values| values[0] != values[1])
    {
        return true;
    }

    let identity_values = ["method_index", "metadata_index", "token"]
        .iter()
        .filter_map(|alias| object.get(*alias))
        .collect::<Vec<_>>();
    if identity_values
        .windows(2)
        .any(|values| values[0] != values[1])
    {
        return true;
    }

    ["source", "provenance", "procedure"]
        .iter()
        .filter_map(|wrapper| object.get(*wrapper).and_then(Value::as_object))
        .any(conflicting_identity_claims)
}

fn conflicting_address_claims(object: &Map<String, Value>) -> bool {
    let aliases = [
        "address",
        "native_address",
        "method_address",
        "pointer",
        "method_pointer",
    ];
    let values = aliases
        .iter()
        .filter_map(|alias| object.get(*alias))
        .filter(|value| !value.is_null())
        .collect::<Vec<_>>();
    if values.len() > 1 && values.windows(2).any(|pair| pair[0] != pair[1]) {
        return true;
    }

    ["source", "provenance", "procedure"]
        .iter()
        .filter_map(|wrapper| object.get(*wrapper).and_then(Value::as_object))
        .any(conflicting_address_claims)
}

fn identity_value(object: &Map<String, Value>) -> Value {
    for key in [
        "method_identity",
        "metadata_identity",
        "identity",
        "module_identity",
        "method_index",
        "metadata_index",
        "token",
    ] {
        if let Some(value) = object.get(key) {
            return value.clone();
        }
    }

    let mut module_identity = Map::new();
    for key in [
        "image_index",
        "image_id",
        "image_name",
        "assembly_name",
        "image",
        "module_name",
        "module",
    ] {
        if let Some(value) = object.get(key) {
            module_identity.insert(key.to_owned(), value.clone());
        }
    }
    if !module_identity.is_empty() {
        return Value::Object(module_identity);
    }

    for wrapper in ["source", "provenance", "procedure"] {
        let Some(value) = object.get(wrapper).and_then(Value::as_object) else {
            continue;
        };
        let identity = identity_value(value);
        if !identity.is_null() {
            return identity;
        }
    }

    Value::Null
}

fn identity_key(value: &Value) -> Result<Option<String>, Failure> {
    if value.is_null() {
        return Ok(None);
    }
    identity_key_text(value)
        .ok_or_else(|| invalid("native", "identity is not serializable"))
        .map(Some)
}

fn explicit_slot(
    object: &Map<String, Value>,
    field: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let aliases = [
        "method_pointer_slot",
        "pointer_slot",
        "slot",
        "method_pointer_index",
        "pointer_index",
        "index",
    ];
    let mut selected = None;
    for alias in aliases {
        let Some(value) = object.get(alias) else {
            continue;
        };
        let parsed = value
            .as_u64()
            .or_else(|| {
                value.as_str().and_then(|text| {
                    text.strip_prefix("0x")
                        .or_else(|| text.strip_prefix("0X"))
                        .map_or_else(
                            || text.parse().ok(),
                            |digits| u64::from_str_radix(digits, 16).ok(),
                        )
                })
            })
            .ok_or_else(|| {
                invalid_row(
                    field,
                    row,
                    "pointer slot must be a non-negative integer",
                )
            })?;
        if selected.is_some_and(|existing| existing != parsed) {
            return Err(invalid_row(field, row, "pointer slot aliases disagree"));
        }
        selected = Some(parsed);
    }
    Ok(selected)
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let values = collection_alias(object, aliases, field)?
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    bounded_rows(values, field)
}

fn collection_alias<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a [Value]>, Failure> {
    let present = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();
    let arrays = present
        .iter()
        .filter_map(|(alias, value)| value.as_array().map(|rows| (*alias, rows)))
        .collect::<Vec<_>>();

    if present.iter().any(|(_, value)| !value.is_array()) {
        return Err(invalid(field, "Collection aliases must be arrays"));
    }
    if arrays.len() > 1 && arrays.windows(2).any(|pair| pair[0].1 != pair[1].1) {
        return Err(invalid(field, "Collection aliases disagree"));
    }

    Ok(arrays.first().map(|(_, rows)| *rows))
}

fn bounded_rows(values: &[Value], field: &str) -> Result<&[Value], Failure> {
    if values.is_empty() {
        return Err(invalid(field, "Collection must contain at least one row"));
    }
    if values.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the IL2CPP row limit"));
    }
    Ok(values)
}

fn invalid_row(field: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{field}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP native method link input is invalid.".into(),
        false,
        "Supply normalized method identities and native pointer rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
