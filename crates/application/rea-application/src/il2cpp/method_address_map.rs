//! Correlation of IL2CPP method tokens with native CodeGenModule slots.
//!
//! Metadata and binary readers own format decoding. This module only joins
//! their normalized facts. A method slot is identified by the method token RID
//! within its exact owning image/module; a global metadata row number is never
//! used as a native pointer-table key.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "map_il2cpp_method_addresses";
const METHOD_TOKEN_KIND: u32 = 0x06;
const TOKEN_RID_MASK: u32 = 0x00ff_ffff;
const MAX_ROWS: usize = 200_000;
const MAX_TOKEN_TEXT_LENGTH: usize = 32;

/// Join metadata methods with already-discovered CodeGenModule records.
///
/// A module may provide `method_pointers` as an array of pointer rows or raw
/// pointer values. Pointer rows can carry an explicit `slot` or discovery
/// `index`; when omitted, their array position is used. Modules must carry an
/// exact image/module identity; facts from another image are never considered
/// a match. The selected pointer row is retained as `method_pointer_source`
/// for downstream decompilation and evidence joins.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let methods = rows_from_aliases(
        metadata,
        &["methods", "method_definitions", "metadata_methods"],
        "methods",
    )?;
    let modules = rows_from_aliases(
        binary,
        &["codegen_modules", "modules", "method_pointer_modules"],
        "codegen_modules",
    )?;
    let module_records = index_modules(modules)?;

    let mut items = Vec::with_capacity(methods.len());
    let mut mapped = 0usize;
    let mut unknown = 0usize;
    let mut unmapped = Vec::new();
    let mut ambiguous = 0usize;

    for (row, method) in methods.iter().enumerate() {
        let object = method
            .as_object()
            .ok_or_else(|| invalid_row("methods", row, "Expected an object"))?;
        let (token, raw_token) = required_token(object, "methods", row)?;
        let rid = method_token_rid(token).map_err(|reason| invalid_row("methods", row, reason))?;
        let pointer_slot = method_pointer_slot(object, row)?;
        let identity = method_identity(object, metadata, row)?;
        let (pointer, resolution, module) =
            resolve(&module_records, identity.as_ref(), rid, pointer_slot);
        match resolution {
            "mapped" => mapped += 1,
            "unknown" => unknown += 1,
            "unmapped" => unmapped.push(raw_token.clone()),
            "ambiguous" => ambiguous += 1,
            _ => unreachable!("resolution is a closed set"),
        }
        let pointer_source = method_pointer_source(&pointer);
        let mut item = Map::new();
        item.insert("method".into(), method.clone());
        item.insert("method_token".into(), raw_token);
        item.insert("method_token_rid".into(), Value::from(rid));
        item.insert("method_pointer".into(), pointer);
        item.insert("method_pointer_source".into(), pointer_source);
        item.insert("codegen_module".into(), module);
        item.insert("resolution".into(), Value::from(resolution));
        items.push(Value::Object(item));
    }

    Ok(serde_json::json!({
        "status": if unknown > 0 || ambiguous > 0 || !unmapped.is_empty() { "partial" } else { "complete" },
        "items": items,
        "coverage": {
            "methods": methods.len(),
            "mapped": mapped,
            "unknown": unknown,
            "ambiguous": ambiguous,
            "unmapped": unmapped.len(),
            "unmapped_method_tokens": unmapped,
            "codegen_modules": modules.len()
        }
    }))
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ModuleIdentity {
    image_index: Option<u64>,
    image_name: Option<String>,
    module_name: Option<String>,
    ambiguous: bool,
}

#[derive(Clone, Debug)]
struct ModuleRecord {
    identity: ModuleIdentity,
    pointers: BTreeMap<usize, Value>,
    duplicate_slots: BTreeSet<usize>,
    slot_count: usize,
    valid: bool,
    source: Value,
}

fn index_modules(rows: &[Value]) -> Result<Vec<ModuleRecord>, Failure> {
    let mut records = Vec::with_capacity(rows.len());
    for (row, value) in rows.iter().enumerate() {
        let module = value
            .as_object()
            .ok_or_else(|| invalid_row("codegen_modules", row, "Expected an object"))?;
        let identity = exact_identity(module).ok_or_else(|| {
            invalid_row(
                "codegen_modules",
                row,
                "Exact image/module identity is required",
            )
        })?;
        let pointers = module
            .get("method_pointers")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_row("codegen_modules", row, "method_pointers must be an array")
            })?;
        if pointers.len() > MAX_ROWS {
            return Err(invalid_row(
                "codegen_modules",
                row,
                "method_pointers exceeds the IL2CPP method row limit",
            ));
        }
        let declared_count = module.get("method_pointer_count").and_then(Value::as_u64);
        if declared_count.is_some_and(|count| count > MAX_ROWS as u64) {
            return Err(invalid_row(
                "codegen_modules",
                row,
                "method_pointer_count exceeds the IL2CPP method row limit",
            ));
        }
        let (pointers, duplicate_slots, highest_slot) = index_pointer_rows(pointers, row)?;
        let inferred_count = match highest_slot {
            None => pointers.len(),
            Some(slot) => slot.checked_add(1).ok_or_else(|| {
                invalid_row(
                    "codegen_modules",
                    row,
                    "method pointer slot exceeds host index range",
                )
            })?,
        };
        let count_matches = declared_count.is_none_or(|count| count as usize >= inferred_count);
        let slot_count = declared_count
            .map_or(inferred_count, |count| count as usize)
            .max(inferred_count);
        records.push(ModuleRecord {
            identity,
            pointers,
            duplicate_slots,
            slot_count,
            valid: count_matches,
            source: value.clone(),
        });
    }
    Ok(records)
}

fn index_pointer_rows(
    rows: &[Value],
    module_row: usize,
) -> Result<(BTreeMap<usize, Value>, BTreeSet<usize>, Option<usize>), Failure> {
    let mut pointers = BTreeMap::new();
    let mut duplicate_slots = BTreeSet::new();
    let mut highest_slot: Option<usize> = None;

    for (position, pointer) in rows.iter().enumerate() {
        let slot = pointer_slot(pointer, module_row, position)?.unwrap_or(position);
        highest_slot = Some(highest_slot.map_or(slot, |current: usize| current.max(slot)));
        if pointers.insert(slot, pointer_value(pointer)).is_some() {
            duplicate_slots.insert(slot);
        }
    }

    Ok((pointers, duplicate_slots, highest_slot))
}

fn pointer_slot(
    pointer: &Value,
    module_row: usize,
    pointer_row: usize,
) -> Result<Option<usize>, Failure> {
    let Some(object) = pointer.as_object() else {
        return Ok(None);
    };

    let aliases = ["slot", "index", "method_pointer_slot", "pointer_slot"];
    let mut selected = None;
    for alias in aliases {
        let Some(value) = object.get(alias) else {
            continue;
        };
        let parsed = parse_slot(value, module_row, pointer_row)?;
        if selected.is_some_and(|existing| existing != parsed) {
            return Err(invalid_row(
                "codegen_modules",
                module_row,
                &format!("method_pointers[{pointer_row}] slot aliases disagree"),
            ));
        }
        selected = Some(parsed);
    }
    Ok(selected)
}

fn parse_slot(value: &Value, module_row: usize, pointer_row: usize) -> Result<usize, Failure> {
    let parsed = value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_slot_text))
        .ok_or_else(|| {
            invalid_row(
                "codegen_modules",
                module_row,
                &format!("method_pointers[{pointer_row}].slot must be a non-negative integer"),
            )
        })?;
    usize::try_from(parsed).map_err(|_| {
        invalid_row(
            "codegen_modules",
            module_row,
            &format!("method_pointers[{pointer_row}].slot exceeds host index range"),
        )
    })
}

fn parse_slot_text(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn resolve(
    records: &[ModuleRecord],
    identity: Option<&ModuleIdentity>,
    rid: u32,
    pointer_slot: Option<usize>,
) -> (Value, &'static str, Value) {
    let Some(identity) = identity else {
        return (Value::Null, "unmapped", Value::Null);
    };
    if identity.ambiguous {
        return (Value::Null, "ambiguous", Value::Null);
    }

    let matches = records
        .iter()
        .filter(|record| identity_matches(identity, &record.identity))
        .collect::<Vec<_>>();
    if matches.is_empty() {
        return (Value::Null, "unmapped", Value::Null);
    }
    if matches.len() > 1 {
        return (Value::Null, "ambiguous", ambiguous_module_source(&matches));
    }

    let record = matches[0];
    let slot = pointer_slot
        .unwrap_or_else(|| usize::try_from(rid - 1).expect("validated token RID fits usize"));
    let slot_is_present = slot < record.slot_count;
    if !slot_is_present {
        // Keep the matched module evidence even when its table is too short.
        // The caller can distinguish an identified-but-unmapped method from
        // one whose image/module identity was never established.
        return (Value::Null, "unmapped", record.source.clone());
    }

    if record.duplicate_slots.contains(&slot) {
        return (Value::Null, "ambiguous", record.source.clone());
    }

    if !record.valid {
        return (Value::Null, "unknown", record.source.clone());
    }
    match record.pointers.get(&slot) {
        Some(pointer) => (
            pointer.clone(),
            pointer_resolution(pointer),
            record.source.clone(),
        ),
        None => (Value::Null, "unknown", record.source.clone()),
    }
}

/// A captured producer may expose the native pointer-table slot separately
/// from the MethodDef RID. Preserve that explicit identity when available;
/// otherwise the historical RID-minus-one mapping remains the fallback.
fn method_pointer_slot(object: &Map<String, Value>, row: usize) -> Result<Option<usize>, Failure> {
    let aliases = [
        "method_pointer_slot",
        "method_pointer_index",
        "pointer_index",
        "pointer_slot",
    ];
    let mut selected = None;
    for alias in aliases {
        let Some(value) = object.get(alias) else {
            continue;
        };
        let parsed = parse_slot(value, row, 0).map_err(|_| {
            invalid_row(
                "methods",
                row,
                "method pointer slot must be a non-negative integer",
            )
        })?;
        if selected.is_some_and(|existing| existing != parsed) {
            return Err(invalid_row(
                "methods",
                row,
                "method pointer slot aliases disagree",
            ));
        }
        selected = Some(parsed);
    }
    Ok(selected)
}

fn identity_matches(method: &ModuleIdentity, module: &ModuleIdentity) -> bool {
    if method.ambiguous || module.ambiguous {
        return false;
    }

    let mut compared = false;
    if let (Some(left), Some(right)) = (method.image_index, module.image_index) {
        compared = true;
        if left != right {
            return false;
        }
    }
    if let (Some(left), Some(right)) = (&method.image_name, &module.image_name) {
        compared = true;
        if left != right {
            return false;
        }
    }
    if let (Some(left), Some(right)) = (&method.module_name, &module.module_name) {
        compared = true;
        if left != right {
            return false;
        }
    }
    compared
}

/// Keep the matched module evidence available when identity matching produces
/// more than one candidate. The first candidate retains the historical module
/// shape, while the complete candidate set makes the ambiguity explicit and
/// reviewable by downstream consumers.
fn ambiguous_module_source(matches: &[&ModuleRecord]) -> Value {
    let candidates = matches
        .iter()
        .map(|record| record.source.clone())
        .collect::<Vec<_>>();
    let Some(first) = candidates.first().and_then(Value::as_object) else {
        return serde_json::json!({
            "ambiguous": true,
            "ambiguous_candidates": candidates,
        });
    };

    let mut source = first.clone();
    source.insert("ambiguous".into(), Value::Bool(true));
    source.insert("ambiguous_candidates".into(), Value::Array(candidates));
    Value::Object(source)
}

fn pointer_value(value: &Value) -> Value {
    value.clone()
}

fn pointer_resolution(pointer: &Value) -> &'static str {
    if let Some(resolution) = pointer
        .as_object()
        .and_then(|object| object.get("resolution").and_then(Value::as_str))
    {
        return match resolution {
            "mapped" | "valid" => "mapped",
            "ambiguous" | "ambiguous_mapping" => "ambiguous",
            "unknown" | "unmapped" | "null" | "zero_filled" | "non_executable"
            | "outside_image" => "unknown",
            _ => return pointer_disposition_resolution(pointer),
        };
    }

    pointer_disposition_resolution(pointer)
}

fn pointer_disposition_resolution(pointer: &Value) -> &'static str {
    if let Some(disposition) = pointer
        .as_object()
        .and_then(|object| object.get("disposition").and_then(Value::as_str))
    {
        match disposition {
            "valid" => return "mapped",
            "ambiguous" | "ambiguous_mapping" => return "ambiguous",
            "null" | "unmapped" | "outside_image" | "non_executable" => return "unknown",
            _ => {}
        }
    }

    let Some(address) = pointer_virtual_address(pointer) else {
        // A file offset identifies storage in the captured image, but does not
        // establish a native method address without a virtual-address mapping.
        return "unknown";
    };

    match parse_address_value(address) {
        Some(0) | None => "unknown",
        Some(_) => "mapped",
    }
}

fn method_pointer_source(pointer: &Value) -> Value {
    pointer
        .as_object()
        .and_then(|object| object.get("source"))
        .cloned()
        .unwrap_or_else(|| pointer.clone())
}

fn pointer_virtual_address(pointer: &Value) -> Option<&Value> {
    if let Some(object) = pointer.as_object() {
        return [
            "address",
            "target_virtual_address",
            "virtual_address",
            "pointer",
        ]
        .iter()
        .find_map(|key| object.get(*key));
    }

    pointer
        .is_number()
        .then_some(pointer)
        .or_else(|| pointer.as_str().map(|_| pointer))
        .or_else(|| pointer.is_null().then_some(pointer))
}

/// Treat zero, empty, and non-numeric addresses as unresolved native pointers.
/// A file offset alone does not establish a virtual method address.
fn parse_address_value(address: &Value) -> Option<u64> {
    if let Some(value) = address.as_u64() {
        return Some(value);
    }

    let text = address.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn method_token_rid(token: u32) -> Result<u32, &'static str> {
    if token >> 24 != METHOD_TOKEN_KIND {
        return Err("token must use the MethodDef table kind 0x06");
    }
    let rid = token & TOKEN_RID_MASK;
    if rid == 0 {
        return Err("method token RID must be non-zero");
    }
    Ok(rid)
}

fn required_token(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<(u32, Value), Failure> {
    let value = object
        .get("token")
        .ok_or_else(|| invalid_row(collection, row, "token is required"))?;
    let token = value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_token_text))
        .ok_or_else(|| {
            invalid_row(
                collection,
                row,
                "token must be a non-negative integer or hexadecimal token",
            )
        })?;
    Ok((
        u32::try_from(token).map_err(|_| invalid_row(collection, row, "token exceeds u32"))?,
        value.clone(),
    ))
}

fn parse_token_text(value: &str) -> Option<u64> {
    if value.is_empty() || value.len() > MAX_TOKEN_TEXT_LENGTH {
        return None;
    }

    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn exact_identity(object: &Map<String, Value>) -> Option<ModuleIdentity> {
    let (image_index, image_index_ambiguous) = identity_index(object, &["image_index", "image_id"]);
    let (image_name, image_name_ambiguous) =
        identity_text(object, &["image_name", "assembly_name", "image"]);
    let (module_name, module_name_ambiguous) = identity_text(object, &["module_name", "module"]);
    let ambiguous = image_index_ambiguous || image_name_ambiguous || module_name_ambiguous;
    (image_index.is_some() || image_name.is_some() || module_name.is_some() || ambiguous).then_some(
        ModuleIdentity {
            image_index,
            image_name,
            module_name,
            ambiguous,
        },
    )
}

fn identity_index(object: &Map<String, Value>, aliases: &[&str]) -> (Option<u64>, bool) {
    let mut selected = None;
    let mut ambiguous = false;
    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let Some(value) = parse_identity_index(value) else {
            ambiguous = true;
            continue;
        };
        if selected.is_some_and(|previous| previous != value) {
            ambiguous = true;
        } else if selected.is_none() {
            selected = Some(value);
        }
    }
    (selected, ambiguous)
}

fn identity_text(object: &Map<String, Value>, aliases: &[&str]) -> (Option<String>, bool) {
    let mut selected = None;
    let mut ambiguous = false;
    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        if value.is_null() {
            continue;
        }
        let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
            ambiguous = true;
            continue;
        };
        if selected
            .as_deref()
            .is_some_and(|previous| previous != value)
        {
            ambiguous = true;
        } else if selected.is_none() {
            selected = Some(value.to_owned());
        }
    }
    (selected, ambiguous)
}

/// Captured JSON producers use both numeric indices and decimal/hexadecimal
/// strings. Preserve the source representation elsewhere, but normalize the
/// identity key before matching modules to methods.
fn parse_identity_index(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let text = value.as_str()?.trim();
        text.strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .map_or_else(
                || text.parse().ok(),
                |digits| u64::from_str_radix(digits, 16).ok(),
            )
    })
}

fn method_identity(
    object: &Map<String, Value>,
    metadata: &Map<String, Value>,
    row: usize,
) -> Result<Option<ModuleIdentity>, Failure> {
    if let Some(identity) = exact_identity(object) {
        return Ok(Some(identity));
    }
    let Some(owner) = object.get("declaring_type").and_then(Value::as_i64) else {
        return Ok(None);
    };
    if owner < 0 {
        return Err(invalid_row(
            "methods",
            row,
            "Method has no declaring type or owning image identity",
        ));
    }
    let Some(types) = metadata.get("types").and_then(Value::as_array) else {
        return Ok(None);
    };
    let owner = u64::try_from(owner)
        .map_err(|_| invalid_row("methods", row, "declaring_type exceeds host index range"))?;
    if !types
        .iter()
        .enumerate()
        .any(|(position, value)| type_identity(value, position) == Some(owner))
    {
        return Err(invalid_row(
            "methods",
            row,
            "declaring_type is outside decoded metadata types",
        ));
    }
    let Some(images) = metadata.get("images").and_then(Value::as_array) else {
        return Ok(None);
    };
    let image_index = images
        .iter()
        .enumerate()
        .find_map(|(index, image)| {
            let image = image.as_object()?;
            let start = image.get("type_start").and_then(Value::as_i64)?;
            let count = image.get("type_count").and_then(Value::as_u64)?;
            let start = usize::try_from(start).ok()?;
            let count = usize::try_from(count).ok()?;
            let end = start.checked_add(count)?;
            (owner >= start as u64 && owner < end as u64).then_some(index as u64)
        })
        .ok_or_else(|| {
            invalid_row(
                "methods",
                row,
                "declaring_type is not owned by a decoded image",
            )
        })?;
    let image_name = images
        .get(image_index as usize)
        .and_then(Value::as_object)
        .and_then(|image| text(image, "name"));
    Ok(Some(ModuleIdentity {
        image_index: Some(image_index),
        image_name,
        module_name: None,
        ambiguous: false,
    }))
}

fn type_identity(value: &Value, position: usize) -> Option<u64> {
    let object = value.as_object()?;
    object
        .get("metadata_index")
        .or_else(|| object.get("type_index"))
        .or_else(|| object.get("index"))
        .and_then(Value::as_u64)
        .or_else(|| u64::try_from(position).ok())
}

fn text(object: &Map<String, Value>, field: &str) -> Option<String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn rows_from_aliases<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let rows = aliases
        .iter()
        .find_map(|alias| object.get(*alias))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP method row limit",
        ));
    }
    if rows.is_empty() {
        return Err(invalid(field, "Collection must contain at least one row"));
    }
    Ok(rows)
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP method-address mapping input is invalid.".into(),
        false,
        "Supply normalized IL2CPP method tokens and exact CodeGenModule facts and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
