//! Projection of IL2CPP virtual-slot and interface-offset metadata.
//!
//! This module joins already decoded rows.  It never treats a slot number as a
//! method address and never chooses between overlapping or duplicate owners.
//! Such cases remain explicit in the returned coverage and resolution fields.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "map_il2cpp_vtables";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Project type vtable ranges and interface-offset rows onto method metadata.
///
/// Direct arrays or `metadata`/`binary` wrappers are accepted.  The metadata
/// side may contain `types` and `methods`; the binary side contains
/// `vtable_methods` and `interface_offsets` (camel-case aliases are accepted
/// for captures produced by different providers).
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    validate_input_shape(root)?;

    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let types = rows(metadata, &["types", "type_definitions"], "types")?;
    let methods = rows(metadata, &["methods", "method_definitions"], "methods")?;
    let slots = rows(
        binary,
        &["vtable_methods", "vtableMethods", "vtable_method_rows"],
        "vtable_methods",
    )?;
    let interfaces = rows(
        binary,
        &[
            "interface_offsets",
            "interfaceOffsets",
            "interface_offset_rows",
        ],
        "interface_offsets",
    )?;

    let method_index = index_methods(methods)?;
    let mut owners: BTreeMap<u64, Vec<(usize, u64)>> = BTreeMap::new();
    let mut type_items = Vec::with_capacity(types.len());
    let mut invalid_ranges = Vec::new();
    let mut covered_slots = BTreeSet::new();

    for (row, value) in types.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
        let type_identity = type_identity(object, &["metadata_index", "type_index", "index"]);
        let type_index = type_identity
            .value
            .ok_or_else(|| invalid_row("types", row, "metadata_index or type_index is required"))?;
        let start = optional_u64(object, &["vtable_start", "vtableStart"])?;
        let count = optional_u64(object, &["vtable_count", "vtableCount"])?;
        let mut slots_for_type = Vec::new();
        let mut range_invalid = type_identity.ambiguous;
        match (start, count, type_identity.ambiguous) {
            (_, _, true) => {
                invalid_ranges.push(Value::from(type_index));
            }
            (Some(start), Some(count), false) => {
                let end = start
                    .checked_add(count)
                    .ok_or_else(|| invalid_row("types", row, "vtable range overflows"))?;
                if end > slots.len() as u64 {
                    invalid_ranges.push(Value::from(type_index));
                    range_invalid = true;
                } else {
                    for slot_index in start..end {
                        covered_slots.insert(slot_index);
                        owners
                            .entry(slot_index)
                            .or_default()
                            .push((row, type_index));
                        slots_for_type.push(slot_projection(
                            slot_index,
                            type_index,
                            slots,
                            &method_index,
                        ));
                    }
                }
            }
            (None, None, false) => {}
            _ => {
                invalid_ranges.push(Value::from(type_index));
                range_invalid = true;
            }
        }
        type_items.push(serde_json::json!({
            "type": value,
            "type_index": type_index,
            "vtable": slots_for_type,
            "resolution": if range_invalid { "invalid" } else { "projected" }
        }));
    }

    let mut projected_slots = Vec::with_capacity(slots.len());
    let mut unresolved_slots = 0usize;
    let mut ambiguous_slots = 0usize;
    for (slot_index, slot) in slots.iter().enumerate() {
        let owner_rows = owners
            .get(&(slot_index as u64))
            .cloned()
            .unwrap_or_default();
        let slot_lookup = lookup_method(slot, &method_index);
        if slot_lookup.method.is_none() {
            unresolved_slots += 1;
        }
        if owner_rows.len() > 1 || slot_lookup.ambiguous {
            ambiguous_slots += 1;
        }
        let slot_resolution = if owner_rows.len() > 1 || slot_lookup.ambiguous {
            "ambiguous"
        } else if owner_rows.is_empty() || slot_lookup.method.is_none() {
            "unowned"
        } else {
            "owned"
        };
        projected_slots.push(serde_json::json!({
            "slot_index": slot_index,
            "slot": slot,
            "owners": owner_rows.iter().map(|(_, index)| Value::from(*index)).collect::<Vec<_>>(),
            "resolution": slot_resolution,
            "method": slot_lookup.method
        }));
    }

    let interface_projection = project_interfaces(interfaces, types, &method_index)?;
    Ok(serde_json::json!({
        "status": if invalid_ranges.is_empty() && ambiguous_slots == 0 && unresolved_slots == 0 { "complete" } else { "partial" },
        "types": type_items,
        "slots": projected_slots,
        "interface_offsets": interface_projection.rows,
        "coverage": {
            "types": types.len(), "slots": slots.len(), "covered_slots": covered_slots.len(),
            "unresolved_slots": unresolved_slots, "ambiguous_slots": ambiguous_slots,
            "invalid_type_ranges": invalid_ranges.len(), "invalid_type_indices": invalid_ranges,
            "interface_offsets": interfaces.len(), "interface_ambiguous": interface_projection.ambiguous,
            "interface_unresolved": interface_projection.unresolved
        }
    }))
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    let wrapped = root.contains_key("metadata") || root.contains_key("binary");

    if wrapped {
        reject_unknown_fields(root, &["metadata", "binary"], "input")?;

        let metadata = root
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        let binary = root
            .get("binary")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("binary", "Expected an object"))?;

        reject_unknown_fields(
            metadata,
            &["types", "type_definitions", "methods", "method_definitions"],
            "metadata",
        )?;
        reject_unknown_fields(
            binary,
            &[
                "vtable_methods",
                "vtableMethods",
                "vtable_method_rows",
                "interface_offsets",
                "interfaceOffsets",
                "interface_offset_rows",
            ],
            "binary",
        )?;
    } else {
        reject_unknown_fields(
            root,
            &[
                "types",
                "type_definitions",
                "methods",
                "method_definitions",
                "vtable_methods",
                "vtableMethods",
                "vtable_method_rows",
                "interface_offsets",
                "interfaceOffsets",
                "interface_offset_rows",
            ],
            "input",
        )?;
    }

    Ok(())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(unknown) = object
        .keys()
        .find(|key| !allowed.iter().any(|candidate| candidate == key))
    {
        return Err(invalid(
            &format!("{field}.{unknown}"),
            "Unknown field is not permitted",
        ));
    }

    Ok(())
}

struct InterfaceProjection {
    rows: Vec<Value>,
    ambiguous: usize,
    unresolved: usize,
}

fn project_interfaces(
    rows: &[Value],
    types: &[Value],
    methods: &MethodIndexes<'_>,
) -> Result<InterfaceProjection, Failure> {
    let mut output = Vec::with_capacity(rows.len());
    let mut ambiguous = 0;
    let mut unresolved = 0;
    let mut occurrences = BTreeMap::<(u64, u64), usize>::new();
    let mut parsed = Vec::with_capacity(rows.len());

    // Count duplicate keys before projecting rows.  Marking only the later
    // duplicate as ambiguous would leave the first row looking authoritative
    // even though the captured source is contradictory.
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("interface_offsets", row, "Expected an object"))?;
        let type_identity =
            type_identity(object, &["type_index", "metadata_index", "interface_type"]);
        let type_index = type_identity.value;
        let offset = required_u64(
            object,
            &["offset", "vtable_offset"],
            "interface_offsets",
            row,
        )?;
        let key = (type_index.unwrap_or(u64::MAX), offset);
        *occurrences.entry(key).or_default() += 1;
        parsed.push((
            value,
            object,
            type_index,
            type_identity.ambiguous,
            offset,
            key,
        ));
    }

    let mut type_occurrences = BTreeMap::<u64, usize>::new();
    for (row, value) in types.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
        let identity = type_identity(object, &["metadata_index", "type_index", "index"]);
        if let Some(type_index) = identity.value.filter(|_| !identity.ambiguous) {
            *type_occurrences.entry(type_index).or_default() += 1;
        }
    }

    for (row, (value, object, type_index, type_identity_ambiguous, offset, key)) in
        parsed.into_iter().enumerate()
    {
        let duplicate = occurrences.get(&key).copied().unwrap_or_default() > 1;
        let type_valid = type_index.is_some_and(|index| type_occurrences.contains_key(&index));
        let type_ambiguous = type_index
            .and_then(|index| type_occurrences.get(&index))
            .is_some_and(|count| *count > 1);
        let method_lookup = lookup_method(value, methods);
        let method = method_lookup.method;
        let resolution = if duplicate || type_identity_ambiguous || type_ambiguous {
            ambiguous += 1;
            "ambiguous"
        } else if method_lookup.ambiguous {
            ambiguous += 1;
            "ambiguous"
        } else if !type_valid || method_lookup.specified && method.is_none() {
            unresolved += 1;
            "unresolved"
        } else {
            "resolved"
        };
        output.push(serde_json::json!({ "row": row, "source": value, "type_index": type_index, "offset": offset, "method": method, "resolution": resolution }));
    }
    Ok(InterfaceProjection {
        rows: output,
        ambiguous,
        unresolved,
    })
}

fn slot_projection(
    index: u64,
    type_index: u64,
    slots: &[Value],
    methods: &MethodIndexes<'_>,
) -> Value {
    let slot = slots.get(index as usize).cloned().unwrap_or(Value::Null);
    let lookup = lookup_method(&slot, methods);
    let resolution = if lookup.ambiguous {
        "ambiguous"
    } else if lookup.method.is_some() {
        "owned"
    } else {
        "unowned"
    };
    serde_json::json!({
        "slot_index": index,
        "slot": slot,
        "owners": [type_index],
        "resolution": resolution,
        "method": lookup.method,
    })
}

struct MethodLookup {
    method: Option<Value>,
    ambiguous: bool,
    specified: bool,
}

struct TypeIdentity {
    value: Option<u64>,
    ambiguous: bool,
}

fn type_identity(object: &Map<String, Value>, names: &[&str]) -> TypeIdentity {
    let mut value = None;
    let mut ambiguous = false;

    for name in names {
        let Some(raw) = object.get(*name) else {
            continue;
        };
        let Some(candidate) = parse_u64(raw) else {
            ambiguous = true;
            continue;
        };
        if value.is_some_and(|selected| selected != candidate) {
            ambiguous = true;
        } else if value.is_none() {
            value = Some(candidate);
        }
    }

    TypeIdentity { value, ambiguous }
}

#[derive(Clone, Copy)]
enum MethodNamespace {
    Index,
    Token,
}

struct MethodIdentity {
    namespace: Option<MethodNamespace>,
    value: Option<u64>,
    ambiguous: bool,
    specified: bool,
}

struct MethodIndexes<'a> {
    indices: BTreeMap<u64, Vec<(usize, &'a Value)>>,
    tokens: BTreeMap<u64, Vec<(usize, &'a Value)>>,
}

fn lookup_method(source: &Value, methods: &MethodIndexes<'_>) -> MethodLookup {
    let Some(object) = source.as_object() else {
        return MethodLookup {
            method: None,
            ambiguous: false,
            specified: false,
        };
    };
    let identity = method_identity(object);
    let (Some(namespace), Some(value)) = (identity.namespace, identity.value) else {
        return MethodLookup {
            method: None,
            ambiguous: identity.ambiguous,
            specified: identity.specified,
        };
    };
    if identity.ambiguous {
        return MethodLookup {
            method: None,
            ambiguous: true,
            specified: true,
        };
    }
    let candidates = match namespace {
        MethodNamespace::Index => methods.indices.get(&value),
        MethodNamespace::Token => methods.tokens.get(&value),
    }
    .map(Vec::as_slice)
    .unwrap_or_default();
    let candidate_identity_conflict = candidates.iter().any(|(_, candidate)| {
        candidate
            .as_object()
            .is_some_and(|object| method_identity(object).ambiguous)
    });
    MethodLookup {
        method: (candidates.len() == 1 && !candidate_identity_conflict)
            .then(|| candidates[0].1.clone()),
        ambiguous: candidates.len() > 1 || candidate_identity_conflict,
        specified: true,
    }
}

fn method_identity(object: &Map<String, Value>) -> MethodIdentity {
    // A method index and a method token are separate lookup namespaces.  A
    // row may carry both, so only aliases within the selected namespace may
    // make its identity ambiguous.
    let mut specified = false;
    let mut primary = None;
    let mut primary_ambiguous = false;

    for name in ["method_index", "metadata_index", "index"] {
        let Some(value) = object.get(name) else {
            continue;
        };
        specified = true;
        let Some(index) = parse_u64(value) else {
            primary_ambiguous = true;
            continue;
        };
        if primary.is_some_and(|selected| selected != index) {
            primary_ambiguous = true;
        } else if primary.is_none() {
            primary = Some(index);
        }
    }

    if primary.is_some() || primary_ambiguous {
        return MethodIdentity {
            namespace: Some(MethodNamespace::Index),
            value: primary,
            ambiguous: primary_ambiguous,
            specified,
        };
    }

    let mut token = None;
    let mut token_ambiguous = false;
    for name in ["method_token", "token"] {
        let Some(value) = object.get(name) else {
            continue;
        };
        specified = true;
        let Some(index) = parse_u64(value) else {
            token_ambiguous = true;
            continue;
        };
        if token.is_some_and(|selected| selected != index) {
            token_ambiguous = true;
        } else if token.is_none() {
            token = Some(index);
        }
    }

    MethodIdentity {
        namespace: token.is_some().then_some(MethodNamespace::Token),
        value: token,
        ambiguous: token_ambiguous,
        specified,
    }
}

fn index_methods<'a>(rows: &'a [Value]) -> Result<MethodIndexes<'a>, Failure> {
    let mut indices = BTreeMap::new();
    let mut tokens = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let Some(object) = value.as_object() else {
            // Keep malformed method rows outside the lookup indexes so any
            // slot referring to them remains unresolved evidence.
            continue;
        };
        // A malformed method identity must not make the complete projection
        // fail.  The slot projection can still retain the source row and mark
        // references to it unresolved.  This also keeps conflicting aliases
        // from being silently treated as one authoritative method index.
        let Some(method_index) = index(object, &["metadata_index", "method_index", "index"]) else {
            continue;
        };
        indices
            .entry(method_index)
            .or_insert_with(Vec::new)
            .push((row, value));

        if let Some(token) = index(object, &["method_token", "token"]) {
            tokens
                .entry(token)
                .or_insert_with(Vec::new)
                .push((row, value));
        }
    }
    Ok(MethodIndexes { indices, tokens })
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let present = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();
    if present.len() > 1 {
        return Err(invalid(
            field,
            "Multiple aliases were supplied for the same collection",
        ));
    }
    let value = present
        .first()
        .map(|(_, value)| *value)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the IL2CPP row limit"));
    }
    Ok(rows)
}

fn index(object: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    let mut selected = None;
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let Some(candidate) = parse_u64(value) else {
            continue;
        };
        if selected.is_some_and(|existing| existing != candidate) {
            return None;
        }
        selected = Some(candidate);
    }
    selected
}

fn parse_u64(value: &Value) -> Option<u64> {
    let parsed = match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => {
            let digits = text.trim();
            let (radix, digits) = digits
                .strip_prefix("0x")
                .or_else(|| digits.strip_prefix("0X"))
                .map_or((10, digits), |digits| (16, digits));
            (!digits.is_empty())
                .then(|| u64::from_str_radix(digits, radix).ok())
                .flatten()
        }
        _ => None,
    }?;
    (parsed <= MAX_SAFE_INTEGER).then_some(parsed)
}

fn optional_u64(object: &Map<String, Value>, names: &[&str]) -> Result<Option<u64>, Failure> {
    let mut selected = None;
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let candidate = parse_u64(value)
            .ok_or_else(|| invalid("range", "Range values must be non-negative integers"))?;
        if selected.is_some_and(|existing| existing != candidate) {
            return Err(invalid(
                "range",
                "Conflicting range aliases cannot establish one vtable range",
            ));
        }
        selected = Some(candidate);
    }
    Ok(selected)
}
fn required_u64(
    object: &Map<String, Value>,
    names: &[&str],
    collection: &str,
    row: usize,
) -> Result<u64, Failure> {
    let value = optional_u64(object, names)?;
    value.ok_or_else(|| invalid_row(collection, row, "A non-negative offset is required"))
}
fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP vtable input is invalid.".into(),
        false,
        "Supply normalized IL2CPP vtable and interface rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
