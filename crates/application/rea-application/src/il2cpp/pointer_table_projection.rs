//! Validation and projection for normalized IL2CPP method-pointer tables.
//!
//! This boundary consumes facts that were already decoded by an image or
//! CodeGenModule adapter. It deliberately treats a table slot as a slot: it
//! never turns a global metadata row number into a native pointer index.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_pointer_tables";
const MAX_MODULES: usize = 200_000;
const MAX_POINTERS: usize = 200_000;
const MAX_RANGES: usize = 200_000;

/// Validate and project normalized CodeGenModule pointer tables.
///
/// The accepted input is an object containing `modules` (or the equivalent
/// `codegen_modules`/`method_pointer_modules` alias) and optional
/// `executable_ranges`. A pointer array is positional unless a pointer object
/// supplies an explicit `slot`; no metadata index is consulted.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let modules = rows(
        root,
        &["modules", "codegen_modules", "method_pointer_modules"],
        "modules",
    )?;
    if modules.len() > MAX_MODULES {
        return Err(invalid("modules", "Module collection exceeds the limit"));
    }

    let executable_ranges = parse_ranges(root)?;
    let identities = collect_identities(modules)?;
    let mut projected = Vec::with_capacity(modules.len());
    let mut complete = 0usize;
    let mut partial = 0usize;
    let mut ambiguous_modules = 0usize;
    let mut ambiguous_slots = 0usize;
    let mut unknown_slots = 0usize;
    let mut mapped_slots = 0usize;
    let mut non_executable_slots = 0usize;
    let mut normalized_slots = 0u64;
    let mut missing_slots = 0usize;
    let mut modules_with_missing_slots = 0usize;

    for (module_row, module) in modules.iter().enumerate() {
        let object = module
            .as_object()
            .ok_or_else(|| invalid_row("modules", module_row, "Expected an object"))?;
        let identity = parse_identity(object, module_row)?;
        let pointers = object
            .get("method_pointers")
            .or_else(|| object.get("method_pointer_rows"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                invalid_row("modules", module_row, "method_pointers must be an array")
            })?;
        if pointers.len() > MAX_POINTERS {
            return Err(invalid_row(
                "modules",
                module_row,
                "method_pointers exceeds the limit",
            ));
        }

        let declared_count = parse_optional_count(object, module_row)?;
        let rows = project_pointers(
            pointers,
            &executable_ranges,
            identity.get("address_space").and_then(Value::as_str),
            module_row,
        )?;
        let coverage = derive_slot_coverage(&rows, declared_count, module_row)?;
        normalized_slots += coverage.slot_count;
        missing_slots += coverage.missing_slots.len();
        if !coverage.missing_slots.is_empty() {
            modules_with_missing_slots += 1;
        }
        let duplicate_slots = duplicate_slots(&rows);
        let identity_key = serde_json::to_string(&identity)
            .map_err(|_| invalid_row("modules", module_row, "Identity serialization failed"))?;
        let duplicate_identity = identities.get(&identity_key).copied().unwrap_or(0) > 1;
        let module_ambiguous = duplicate_identity || !duplicate_slots.is_empty();
        let module_complete = coverage.count_matches
            && coverage.missing_slots.is_empty()
            && !module_ambiguous
            && rows
                .iter()
                .all(|row| row.get("resolution").and_then(Value::as_str) == Some("mapped"));
        if module_ambiguous {
            ambiguous_modules += 1;
        }
        if module_complete {
            complete += 1;
        } else {
            partial += 1;
        }

        let mut module_rows = Vec::with_capacity(rows.len());
        for mut row in rows {
            row["module_identity"] = identity.clone();
            let duplicate_slot = row
                .get("slot")
                .and_then(Value::as_u64)
                .is_some_and(|slot| duplicate_slots.binary_search(&slot).is_ok());
            if duplicate_identity || duplicate_slot {
                row["resolution"] = Value::from("ambiguous");
            }
            match row.get("resolution").and_then(Value::as_str) {
                Some("mapped") => mapped_slots += 1,
                Some("unknown") => unknown_slots += 1,
                Some("non_executable") => non_executable_slots += 1,
                Some("ambiguous") => ambiguous_slots += 1,
                _ => {}
            }
            module_rows.push(row);
        }

        projected.push(serde_json::json!({
            "module": module,
            "identity": identity,
            "method_pointer_count": declared_count,
            "available_pointer_count": pointers.len(),
            "slot_count": coverage.slot_count,
            "observed_slot_count": coverage.observed_slot_count,
            "missing_slots": coverage.missing_slots,
            "count_match": coverage.count_matches,
            "duplicate_slots": duplicate_slots,
            "resolution": if module_complete { "complete" } else if module_ambiguous { "ambiguous" } else { "partial" },
            "method_pointers": module_rows,
        }));
    }

    Ok(serde_json::json!({
        "operation": OPERATION,
        "modules": projected,
        "executable_ranges": executable_ranges,
        "coverage": {
            "modules": modules.len(),
            "complete_modules": complete,
            "partial_modules": partial,
            "ambiguous_modules": ambiguous_modules,
            "method_pointer_slots": mapped_slots + unknown_slots + non_executable_slots + ambiguous_slots,
            "normalized_slots": normalized_slots,
            "missing_slots": missing_slots,
            "modules_with_missing_slots": modules_with_missing_slots,
            "mapped_slots": mapped_slots,
            "unknown_slots": unknown_slots,
            "non_executable_slots": non_executable_slots,
            "ambiguous_slots": ambiguous_slots,
        },
    }))
}

struct SlotCoverage {
    slot_count: u64,
    observed_slot_count: usize,
    missing_slots: Vec<u64>,
    count_matches: bool,
}

fn derive_slot_coverage(
    rows: &[Value],
    declared_count: Option<u64>,
    module_row: usize,
) -> Result<SlotCoverage, Failure> {
    let slots = rows
        .iter()
        .filter_map(|row| row.get("slot").and_then(Value::as_u64))
        .collect::<BTreeSet<_>>();
    let inferred_count = slots
        .last()
        .copied()
        .map_or(0, |slot| slot.saturating_add(1));
    let slot_count = declared_count.map_or(inferred_count, |count| count.max(inferred_count));
    if slot_count > MAX_POINTERS as u64 {
        return Err(invalid_row(
            "modules",
            module_row,
            "Normalized method-pointer slot range exceeds the limit",
        ));
    }

    let missing_slots = (0..slot_count)
        .filter(|slot| !slots.contains(slot))
        .collect::<Vec<_>>();
    Ok(SlotCoverage {
        slot_count,
        observed_slot_count: slots.len(),
        missing_slots,
        count_matches: declared_count.is_none_or(|count| count >= inferred_count),
    })
}

fn project_pointers(
    pointers: &[Value],
    ranges: &[Value],
    module_address_space: Option<&str>,
    module_row: usize,
) -> Result<Vec<Value>, Failure> {
    let mut rows = Vec::with_capacity(pointers.len());
    for (position, source) in pointers.iter().enumerate() {
        let object = source.as_object();
        let slot = object
            .and_then(|value| value.get("slot"))
            .map(|value| parse_u64(value, "slot"))
            .transpose()
            .map_err(|reason| invalid_row("modules", module_row, reason))?
            .unwrap_or(position as u64);
        if slot >= MAX_POINTERS as u64 {
            return Err(invalid_row(
                "modules",
                module_row,
                "method-pointer slot exceeds the limit",
            ));
        }
        let address = match object {
            Some(value) => parse_address_aliases(value),
            None => parse_address(source),
        }
        .map_err(|reason| invalid_row("modules", module_row, reason))?;
        let pointer_address_space = object
            .and_then(|value| text(value, &["address_space", "addressSpace", "space"]))
            .or_else(|| module_address_space.map(str::to_owned));
        let classification = address
            .filter(|value| !address_is_null(*value))
            .map(|value| membership(value, pointer_address_space.as_deref(), ranges));
        let executable = classification.as_ref().map(|value| value.status);
        let resolution = match (address, executable) {
            (None, _) | (Some(0), _) => "unknown",
            (Some(_), Some("ambiguous")) => "ambiguous",
            (Some(_), Some("non_executable")) => "non_executable",
            (Some(_), None) => "unknown",
            (Some(_), _) => "mapped",
        };
        rows.push(serde_json::json!({
            "slot": slot,
            "source": source,
            "address": address,
            "executable": executable,
            "address_space": pointer_address_space,
            "source_offset": object
                .map(|value| parse_optional_offset(value, &["source_offset", "sourceOffset", "offset"], "source_offset"))
                .transpose()
                .map_err(|reason| invalid_row("modules", module_row, reason))?
                .flatten(),
            "file_offset": object
                .map(|value| parse_optional_offset(value, &["file_offset", "fileOffset", "target_file_offset", "targetFileOffset"], "file_offset"))
                .transpose()
                .map_err(|reason| invalid_row("modules", module_row, reason))?
                .flatten(),
            "executable_range_matches": classification
                .as_ref()
                .map(|value| value.matches.clone())
                .unwrap_or_default(),
            "resolution": resolution,
        }));
    }
    Ok(rows)
}

fn duplicate_slots(rows: &[Value]) -> Vec<u64> {
    let mut seen = BTreeSet::new();
    let mut duplicate = BTreeSet::new();
    for row in rows {
        if let Some(slot) = row.get("slot").and_then(Value::as_u64) {
            if !seen.insert(slot) {
                duplicate.insert(slot);
            }
        }
    }
    duplicate.into_iter().collect()
}

struct AddressClassification {
    status: &'static str,
    matches: Vec<Value>,
}

fn membership(
    address: u64,
    address_space: Option<&str>,
    ranges: &[Value],
) -> AddressClassification {
    if ranges.is_empty() {
        return AddressClassification {
            status: "unknown",
            matches: Vec::new(),
        };
    }
    let matches = ranges
        .iter()
        .enumerate()
        .filter_map(|(index, range)| {
            let object = range.as_object();
            let start = object
                .and_then(|value| value.get("start"))
                .and_then(parse_integer_value);
            let end = object
                .and_then(|value| value.get("end"))
                .and_then(parse_integer_value);
            let range_address_space =
                object.and_then(|value| text(value, &["address_space", "addressSpace", "space"]));
            let address_space_matches = range_address_space
                .as_deref()
                .is_none_or(|range_space| address_space == Some(range_space));
            start
                .is_some_and(|start| {
                    end.is_some_and(|end| {
                        address_space_matches && address >= start && address < end
                    })
                })
                .then(|| {
                    serde_json::json!({
                        "index": index,
                        "range": range,
                        "address_space": range_address_space,
                    })
                })
        })
        .collect::<Vec<_>>();
    let status = match matches.len() {
        0 => "non_executable",
        1 => "executable",
        _ => "ambiguous",
    };
    AddressClassification { status, matches }
}

fn parse_ranges(root: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    let Some(value) = root
        .get("executable_ranges")
        .or_else(|| root.get("executableRanges"))
    else {
        return Ok(Vec::new());
    };
    let ranges = value
        .as_array()
        .ok_or_else(|| invalid("executable_ranges", "Expected an array"))?;
    if ranges.len() > MAX_RANGES {
        return Err(invalid(
            "executable_ranges",
            "Range collection exceeds the limit",
        ));
    }
    for (index, range) in ranges.iter().enumerate() {
        let object = range
            .as_object()
            .ok_or_else(|| invalid_row("executable_ranges", index, "Expected an object"))?;
        let start = parse_u64(
            object
                .get("start")
                .ok_or_else(|| invalid_row("executable_ranges", index, "start is required"))?,
            "start",
        )
        .map_err(|reason| invalid_row("executable_ranges", index, reason))?;
        let end = parse_u64(
            object
                .get("end")
                .ok_or_else(|| invalid_row("executable_ranges", index, "end is required"))?,
            "end",
        )
        .map_err(|reason| invalid_row("executable_ranges", index, reason))?;
        if start >= end {
            return Err(invalid_row(
                "executable_ranges",
                index,
                "start must be below end",
            ));
        }
    }
    Ok(ranges.to_vec())
}

fn collect_identities(rows: &[Value]) -> Result<BTreeMap<String, usize>, Failure> {
    let mut counts = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| invalid_row("modules", index, "Expected an object"))?;
        let identity = parse_identity(object, index)?;
        let key = serde_json::to_string(&identity)
            .map_err(|_| invalid_row("modules", index, "Identity serialization failed"))?;
        *counts.entry(key).or_insert(0) += 1;
    }
    Ok(counts)
}

fn parse_identity(object: &Map<String, Value>, row: usize) -> Result<Value, Failure> {
    let nested = object.get("identity").and_then(Value::as_object);
    let sources = [Some(object), nested];
    let module_name =
        checked_text_from_sources(&sources, &["module_name", "module"], "module_name")
            .map_err(|reason| invalid_row("modules", row, reason))?;
    let image_index = checked_integer_from_sources(&sources, &["image_index", "image_id"])
        .map_err(|reason| invalid_row("modules", row, reason))?;
    let image_name = checked_text_from_sources(
        &sources,
        &["image_name", "assembly_name", "image"],
        "image_name",
    )
    .map_err(|reason| invalid_row("modules", row, reason))?;
    let binary_sha256 = checked_text_from_sources(
        &sources,
        &["binary_sha256", "binary_digest", "sha256"],
        "binary_sha256",
    )
    .map_err(|reason| invalid_row("modules", row, reason))?;
    let address_space = checked_text_from_sources(
        &sources,
        &["address_space", "addressSpace"],
        "address_space",
    )
    .map_err(|reason| invalid_row("modules", row, reason))?;
    if module_name.is_none() || (image_index.is_none() && image_name.is_none()) {
        return Err(invalid_row(
            "modules",
            row,
            "Exact module and image identity are required",
        ));
    }
    Ok(serde_json::json!({
        "module_name": module_name,
        "image_index": image_index,
        "image_name": image_name,
        "binary_sha256": binary_sha256,
        "address_space": address_space,
    }))
}

fn first_value<'a>(
    sources: &[Option<&'a Map<String, Value>>],
    fields: &[&str],
) -> Option<&'a Value> {
    sources
        .iter()
        .flatten()
        .find_map(|source| fields.iter().find_map(|field| source.get(*field)))
}

fn checked_text_from_sources(
    sources: &[Option<&Map<String, Value>>],
    fields: &[&str],
    field: &'static str,
) -> Result<Option<String>, &'static str> {
    let mut selected = None;
    for source in sources.iter().flatten() {
        for alias in fields {
            let Some(value) = source.get(*alias) else {
                continue;
            };
            if value.is_null() {
                continue;
            }
            let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
                return Err(field);
            };
            if selected
                .as_deref()
                .is_some_and(|existing| existing != value)
            {
                return Err(field);
            }
            selected = Some(value.to_owned());
        }
    }
    Ok(selected)
}

fn checked_integer_from_sources(
    sources: &[Option<&Map<String, Value>>],
    fields: &[&str],
) -> Result<Option<u64>, &'static str> {
    let mut selected = None;
    for source in sources.iter().flatten() {
        for alias in fields {
            let Some(value) = source.get(*alias) else {
                continue;
            };
            if value.is_null() {
                continue;
            }
            let parsed = parse_u64(value, "image_index")?;
            if selected.is_some_and(|existing| existing != parsed) {
                return Err("image_index");
            }
            selected = Some(parsed);
        }
    }
    Ok(selected)
}

fn parse_optional_count(object: &Map<String, Value>, row: usize) -> Result<Option<u64>, Failure> {
    let canonical = object.get("method_pointer_count");
    let alias = object.get("methodPointerCount");
    let Some(value) = canonical.or(alias) else {
        return Ok(None);
    };
    let count = parse_u64(value, "method_pointer_count")
        .map_err(|reason| invalid_row("modules", row, reason))?;

    if let (Some(_), Some(alias)) = (canonical, alias) {
        let alias_count = parse_u64(alias, "method_pointer_count")
            .map_err(|reason| invalid_row("modules", row, reason))?;
        if count != alias_count {
            return Err(invalid_row(
                "modules",
                row,
                "method_pointer_count aliases contain conflicting values",
            ));
        }
    }

    if count > MAX_POINTERS as u64 {
        return Err(invalid_row(
            "modules",
            row,
            "method_pointer_count exceeds the limit",
        ));
    }
    Ok(Some(count))
}

fn parse_address(value: &Value) -> Result<Option<u64>, &'static str> {
    if value.is_null() {
        return Ok(None);
    }
    parse_u64(value, "address").map(Some)
}

fn parse_address_aliases(object: &Map<String, Value>) -> Result<Option<u64>, &'static str> {
    let mut selected = None;
    let mut found = false;

    for field in ["address", "target_virtual_address", "virtual_address"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let address = parse_address(value)?;
        if found && selected != address {
            return Err("address aliases contain conflicting values");
        }
        selected = address;
        found = true;
    }

    if found { Ok(selected) } else { Ok(None) }
}

fn address_is_null(address: u64) -> bool {
    address == 0
}

fn parse_optional_offset(
    object: &Map<String, Value>,
    fields: &[&str],
    field: &'static str,
) -> Result<Option<u64>, &'static str> {
    let Some(value) = first_value(&[Some(object)], fields) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    parse_u64(value, field).map(Some)
}

fn parse_u64(value: &Value, field: &'static str) -> Result<u64, &'static str> {
    parse_integer_value(value).ok_or(field)
}

fn parse_integer_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_integer))
}

fn parse_integer(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn text(object: &Map<String, Value>, fields: &[&str]) -> Option<String> {
    fields
        .iter()
        .find_map(|field| object.get(*field))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    aliases
        .iter()
        .find_map(|alias| root.get(*alias))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(field, "Expected an array"))
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP pointer-table input is invalid.".into(),
        false,
        "Supply normalized CodeGenModule pointer tables and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
