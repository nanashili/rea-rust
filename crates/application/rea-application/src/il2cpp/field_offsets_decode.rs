//! Decode caller-supplied IL2CPP field-offset tables.
//!
//! The table layout is intentionally explicit.  Unity versions and generated
//! binaries do not provide enough information at this boundary to justify
//! guessing a pointer width, byte order, or table origin.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "decode_il2cpp_field_offsets";
const MAX_TYPES: usize = 200_000;
const MAX_SLOTS: u64 = 2_000_000;
const MAX_BYTES: usize = 256 * 1024 * 1024;

/// Decode a bounded field-offset table from an explicit layout description.
///
/// Input fields are `metadata_version`, `layout`, `type_records`, and
/// `bytes_base64`. `layout` requires `pointer_width`, `endianness`,
/// `offset_encoding`, `table_offset`, and `table_count`. Each type record
/// supplies `type_index`, `field_start`, and `field_count`.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let version = object
        .get("metadata_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("metadata_version", "Metadata version is required"))?;
    if !matches!(version, 29 | 31 | 39) {
        return Err(invalid("metadata_version", "Unsupported metadata version"));
    }

    let layout = object
        .get("layout")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout", "Explicit table layout is required"))?;
    let width = layout
        .get("pointer_width")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("layout.pointer_width", "Pointer width is required"))?;
    if !matches!(width, 4 | 8) {
        return Err(invalid("layout.pointer_width", "Width must be 4 or 8"));
    }
    let offset_width = width;
    let endianness = match layout.get("endianness").and_then(Value::as_str) {
        Some("little") => "little",
        Some("big") => "big",
        _ => {
            return Err(invalid(
                "layout.endianness",
                "Endianness must be little or big",
            ));
        }
    };
    let encoding = match layout.get("offset_encoding").and_then(Value::as_str) {
        Some("signed") => "signed",
        Some("unsigned") => "unsigned",
        _ => {
            return Err(invalid(
                "layout.offset_encoding",
                "Encoding must be signed or unsigned",
            ));
        }
    };
    let table_offset = layout
        .get("table_offset")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("layout.table_offset", "Table offset is required"))?;
    let table_count = layout
        .get("table_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("layout.table_count", "Table count is required"))?;
    if table_count > MAX_SLOTS {
        return Err(invalid(
            "layout.table_count",
            "Table count exceeds the limit",
        ));
    }
    let address_base = layout
        .get("address_base")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let sentinels = parse_sentinels(layout)?;

    let bytes_text = object
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("bytes_base64", "Base64 table bytes are required"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(bytes_text)
        .map_err(|_| invalid("bytes_base64", "Table bytes are not valid base64"))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("bytes_base64", "Table bytes exceed the limit"));
    }
    let byte_count = table_count
        .checked_mul(offset_width)
        .ok_or_else(|| invalid("layout", "Table byte size overflows"))?;
    let table_end = table_offset
        .checked_add(byte_count)
        .ok_or_else(|| invalid("layout", "Table range overflows"))?;
    if table_end > bytes.len() as u64 {
        return Err(invalid("layout", "Table range exceeds supplied bytes"));
    }

    let records = object
        .get("type_records")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("type_records", "Type records are required"))?;
    if records.len() > MAX_TYPES {
        return Err(invalid(
            "type_records",
            "Type record count exceeds the limit",
        ));
    }

    let (metadata_bindings, has_metadata_bindings) = collect_metadata_bindings(object, records)?;
    let type_identity_counts = type_identity_counts(records)?;

    let mut items = Vec::new();
    let mut mapped = 0_u64;
    let mut unknown = 0_u64;
    let mut invalid_count = 0_u64;
    let mut decoded_slots = 0_u64;
    let mut claimed_ranges: Vec<(u64, u64, usize)> = Vec::new();
    for (record_index, record) in records.iter().enumerate() {
        let type_object = record
            .as_object()
            .ok_or_else(|| invalid_row(record_index, "Type record must be an object"))?;
        let type_index = type_object
            .get("type_index")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_row(record_index, "type_index is required"))?;
        let type_identity_ambiguous = type_identity_counts
            .get(&type_index)
            .is_some_and(|count| *count > 1);
        let start = type_object
            .get("field_start")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_row(record_index, "field_start is required"))?;
        let count = type_object
            .get("field_count")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_row(record_index, "field_count is required"))?;
        let end = start
            .checked_add(count)
            .ok_or_else(|| invalid_row(record_index, "field range overflows"))?;
        let mut fields = Vec::new();
        let overlap_records = claimed_ranges
            .iter()
            .filter_map(|(claimed_start, claimed_end, claimed_record)| {
                (start < *claimed_end && *claimed_start < end).then_some(*claimed_record)
            })
            .collect::<Vec<_>>();
        let overlaps_existing = !overlap_records.is_empty();
        let resolution = if end > table_count {
            invalid_count += 1;
            "invalid"
        } else {
            claimed_ranges.push((start, end, record_index));
            if overlaps_existing {
                invalid_count += 1;
            }
            decoded_slots = decoded_slots
                .checked_add(count)
                .ok_or_else(|| invalid_row(record_index, "decoded field count overflows"))?;
            if decoded_slots > MAX_SLOTS {
                return Err(invalid_row(
                    record_index,
                    "decoded field slots exceed the bounded limit",
                ));
            }
            let mut type_unknown = false;
            for slot in start..end {
                let byte_start =
                    table_offset
                        .checked_add(slot.checked_mul(offset_width).ok_or_else(|| {
                            invalid_row(record_index, "field slot offset overflows")
                        })?)
                        .ok_or_else(|| invalid_row(record_index, "field slot offset overflows"))?;
                let at = usize::try_from(byte_start)
                    .map_err(|_| invalid_row(record_index, "field slot is not addressable"))?;
                let span_length = usize::try_from(offset_width)
                    .map_err(|_| invalid_row(record_index, "field width is not addressable"))?;
                let span_end = at
                    .checked_add(span_length)
                    .ok_or_else(|| invalid_row(record_index, "field span overflows"))?;
                let raw_bytes = &bytes[at..span_end];
                let raw = read_value(raw_bytes, endianness);
                let is_sentinel = sentinels.contains(&raw);
                let decoded = decode_offset(raw, offset_width, encoding);
                let status = if type_identity_ambiguous
                    || overlaps_existing
                    || is_sentinel
                    || decoded.is_none()
                {
                    unknown += 1;
                    type_unknown = true;
                    "unknown"
                } else {
                    mapped += 1;
                    "mapped"
                };
                let offset = decoded.map(Value::from).unwrap_or(Value::Null);
                let source_address = address_base
                    .checked_add(byte_start)
                    .map(Value::from)
                    .unwrap_or(Value::Null);
                let mut field = json!({
                    "slot": slot,
                    "member_index": slot,
                    "raw": raw,
                    "raw_base64": base64::engine::general_purpose::STANDARD.encode(raw_bytes),
                    "byte_span": { "offset": byte_start, "length": offset_width },
                    "source_offset": byte_start,
                    "encoding": encoding,
                    "decoded": decoded_value(raw, offset_width, encoding),
                    "offset": offset,
                    "source_address": source_address,
                    "resolution": status,
                    "sentinel": is_sentinel,
                    "overlap": overlaps_existing,
                    "overlap_with": overlap_records,
                    "type_identity_ambiguous": type_identity_ambiguous
                });
                if has_metadata_bindings {
                    add_metadata_identity(&mut field, type_index, metadata_bindings.get(&slot));
                }
                fields.push(field);
            }
            if type_unknown || type_identity_ambiguous {
                "partial"
            } else {
                "mapped"
            }
        };
        items.push(json!({
            "type_index": type_index,
            "record_index": record_index,
            "source": record,
            "field_start": start,
            "field_count": count,
            "resolution": resolution,
            "overlap": overlaps_existing,
            "overlap_with": overlap_records,
            "fields": fields
        }));
    }

    Ok(json!({
        "metadata_version": version,
        "layout": layout,
        "source": { "bytes_base64": bytes_text, "byte_count": bytes.len() },
        "items": items,
        "coverage": {
            "types": records.len(),
            "table_slots": table_count,
            "mapped": mapped,
            "unknown": unknown,
            "invalid": invalid_count,
            "status": if invalid_count == 0 && unknown == 0 { "complete" } else { "partial" }
        }
    }))
}

fn type_identity_counts(records: &[Value]) -> Result<BTreeMap<u64, usize>, Failure> {
    let mut counts = BTreeMap::new();
    for (record_index, record) in records.iter().enumerate() {
        let type_index = record
            .as_object()
            .and_then(|object| object.get("type_index"))
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid_row(record_index, "type_index is required"))?;
        *counts.entry(type_index).or_insert(0) += 1;
    }
    Ok(counts)
}

#[derive(Clone)]
struct MetadataBinding {
    field_index: Option<u64>,
    source_offset: Option<u64>,
    storage_kind: Option<Value>,
    source: Value,
    type_index: Option<u64>,
    slot_ambiguous: bool,
    field_ambiguous: bool,
    source_offset_ambiguous: bool,
    storage_ambiguous: bool,
    type_ambiguous: bool,
    ambiguous: bool,
}

fn collect_metadata_bindings(
    root: &serde_json::Map<String, Value>,
    records: &[Value],
) -> Result<(BTreeMap<u64, MetadataBinding>, bool), Failure> {
    let mut rows = Vec::new();
    let mut has_metadata_bindings = false;
    for container in metadata_containers(root) {
        for key in ["field_metadata", "field_records", "fields"] {
            if let Some(values) = container.get(key) {
                has_metadata_bindings = true;
                let values = values.as_array().ok_or_else(|| {
                    invalid(
                        &format!("{key}"),
                        "Metadata field bindings must be an array",
                    )
                })?;
                rows.extend(values.iter().map(|value| (value, None)));
            }
        }
    }
    for record in records {
        let Some(record_object) = record.as_object() else {
            continue;
        };
        let type_index = record_object.get("type_index").and_then(Value::as_u64);
        for key in ["field_metadata", "field_records", "fields"] {
            if let Some(values) = record_object.get(key) {
                has_metadata_bindings = true;
                let values = values.as_array().ok_or_else(|| {
                    invalid(
                        &format!("type_records[].{key}"),
                        "Metadata field bindings must be an array",
                    )
                })?;
                rows.extend(values.iter().map(|value| (value, type_index)));
            }
        }
    }

    let mut bindings: BTreeMap<u64, MetadataBinding> = BTreeMap::new();
    for (row, declared_type_index) in rows {
        let object = row
            .as_object()
            .ok_or_else(|| invalid("field_metadata", "Metadata field bindings must be objects"))?;
        // A malformed alias is an observed but unusable identity claim. Do
        // not let a valid sibling alias win by being encountered first; leave
        // the slot unjoined so the decoded field remains explicitly unknown.
        if has_invalid_integer_alias(
            object,
            &[
                "slot",
                "table_slot",
                "field_slot",
                "offset_slot",
                "type_index",
                "declaring_type",
                "declaring_type_index",
                "field_index",
                "metadata_index",
                "index",
                "source_offset",
                "metadata_source_offset",
                "row_source_offset",
            ],
        ) || object
            .get("source")
            .and_then(Value::as_object)
            .is_some_and(|source| {
                has_invalid_integer_alias(source, &["source_offset", "offset", "byte_offset"])
            })
        {
            continue;
        }
        let slot_values =
            integer_alias_values(object, &["slot", "table_slot", "field_slot", "offset_slot"]);
        if slot_values.is_empty() {
            // A metadata row without an explicit table slot cannot be joined
            // safely. In particular, its array position is not an identity.
            continue;
        }
        let slot_ambiguous = slot_values.windows(2).any(|values| values[0] != values[1]);
        let type_values = integer_alias_values(
            object,
            &["type_index", "declaring_type", "declaring_type_index"],
        );
        let type_index = type_values.first().copied().or(declared_type_index);
        let type_ambiguous = type_values.windows(2).any(|values| values[0] != values[1]);
        let field_values =
            integer_alias_values(object, &["field_index", "metadata_index", "index"]);
        let field_index = field_values.first().copied();
        let field_ambiguous = field_values.windows(2).any(|values| values[0] != values[1]);
        let mut source_offset_values = integer_alias_values(
            object,
            &[
                "source_offset",
                "metadata_source_offset",
                "row_source_offset",
            ],
        );
        if let Some(source) = object.get("source").and_then(Value::as_object) {
            source_offset_values.extend(integer_alias_values(
                source,
                &["source_offset", "offset", "byte_offset"],
            ));
        }
        let source_offset = source_offset_values.first().copied();
        let source_offset_ambiguous = source_offset_values
            .windows(2)
            .any(|values| values[0] != values[1]);
        let storage_values = value_alias_values(object, &["storage_kind", "storageKind", "kind"]);
        let storage_kind = storage_values.first().cloned();
        let storage_ambiguous = storage_values
            .windows(2)
            .any(|values| values[0] != values[1]);
        let binding = MetadataBinding {
            field_index,
            source_offset,
            storage_kind,
            source: row.clone(),
            type_index,
            slot_ambiguous,
            field_ambiguous,
            source_offset_ambiguous,
            storage_ambiguous,
            type_ambiguous,
            ambiguous: field_ambiguous
                || slot_ambiguous
                || source_offset_ambiguous
                || storage_ambiguous
                || type_ambiguous,
        };
        for slot in slot_values {
            match bindings.get_mut(&slot) {
                Some(existing) => {
                    existing.ambiguous = true;
                }
                None => {
                    bindings.insert(slot, binding.clone());
                }
            }
        }
    }
    Ok((bindings, has_metadata_bindings))
}

fn has_invalid_integer_alias(object: &Map<String, Value>, aliases: &[&str]) -> bool {
    aliases.iter().any(|alias| {
        object
            .get(*alias)
            .is_some_and(|value| value.as_u64().is_none())
    })
}

fn metadata_containers(
    root: &serde_json::Map<String, Value>,
) -> Vec<&serde_json::Map<String, Value>> {
    let mut containers = vec![root];
    if let Some(metadata) = root.get("metadata").and_then(Value::as_object) {
        containers.push(metadata);
    }
    containers
}

fn integer_alias_values(object: &Map<String, Value>, aliases: &[&str]) -> Vec<u64> {
    aliases
        .iter()
        .filter_map(|alias| object.get(*alias).and_then(Value::as_u64))
        .collect()
}

fn value_alias_values(object: &Map<String, Value>, aliases: &[&str]) -> Vec<Value> {
    aliases
        .iter()
        .filter_map(|alias| object.get(*alias).cloned())
        .collect()
}

fn add_metadata_identity(field: &mut Value, type_index: u64, binding: Option<&MetadataBinding>) {
    let Some(field_object) = field.as_object_mut() else {
        return;
    };
    let Some(binding) = binding else {
        // Without an explicit metadata join, the table slot is the only
        // stable member identity available to downstream layout correlation.
        let member_index = field_object.get("slot").cloned().unwrap_or(Value::Null);
        field_object.insert("member_index".into(), member_index);
        field_object.insert("field_index".into(), Value::Null);
        field_object.insert("metadata_source_offset".into(), Value::Null);
        field_object.insert("storage_kind".into(), Value::Null);
        field_object.insert(
            "metadata_identity_resolution".into(),
            Value::from("unknown"),
        );
        return;
    };
    let type_matches = binding.type_index.map_or(true, |value| value == type_index);
    let resolved = !binding.ambiguous && type_matches && binding.field_index.is_some();
    let member_index = binding.field_index.map_or_else(
        || field_object.get("slot").cloned().unwrap_or(Value::Null),
        Value::from,
    );
    field_object.insert("member_index".into(), member_index);
    field_object.insert(
        "field_index".into(),
        binding.field_index.map_or(Value::Null, Value::from),
    );
    field_object.insert(
        "metadata_source_offset".into(),
        binding.source_offset.map_or(Value::Null, Value::from),
    );
    field_object.insert(
        "storage_kind".into(),
        binding.storage_kind.clone().unwrap_or(Value::Null),
    );
    field_object.insert(
        "metadata_identity_resolution".into(),
        Value::from(if resolved { "mapped" } else { "unknown" }),
    );
    field_object.insert("metadata_source".into(), binding.source.clone());
    if binding.slot_ambiguous {
        field_object.insert(
            "metadata_ambiguity".into(),
            Value::from("conflicting_slot_aliases"),
        );
    } else if binding.field_ambiguous {
        field_object.insert(
            "metadata_ambiguity".into(),
            Value::from("conflicting_field_aliases"),
        );
    } else if binding.source_offset_ambiguous {
        field_object.insert(
            "metadata_ambiguity".into(),
            Value::from("conflicting_source_offsets"),
        );
    } else if binding.storage_ambiguous {
        field_object.insert(
            "metadata_ambiguity".into(),
            Value::from("conflicting_storage_aliases"),
        );
    } else if binding.type_ambiguous {
        field_object.insert(
            "metadata_ambiguity".into(),
            Value::from("conflicting_type_aliases"),
        );
    } else if binding.ambiguous {
        field_object.insert("metadata_ambiguity".into(), Value::from("duplicate_slot"));
    } else if !type_matches {
        field_object.insert("metadata_ambiguity".into(), Value::from("type_mismatch"));
    }
}

fn read_value(bytes: &[u8], endianness: &str) -> u64 {
    let mut value = 0_u64;
    if endianness == "little" {
        for (index, byte) in bytes.iter().enumerate() {
            value |= u64::from(*byte) << (index * 8);
        }
    } else {
        for byte in bytes {
            value = (value << 8) | u64::from(*byte);
        }
    }
    value
}

fn decode_offset(raw: u64, width: u64, encoding: &str) -> Option<i64> {
    if encoding == "unsigned" {
        return i64::try_from(raw).ok();
    }
    let value = if width == 4 {
        i64::from(i32::from_ne_bytes((raw as u32).to_ne_bytes()))
    } else {
        i64::from_ne_bytes(raw.to_ne_bytes())
    };
    (value >= 0).then_some(value)
}

fn parse_sentinels(layout: &serde_json::Map<String, Value>) -> Result<Vec<u64>, Failure> {
    let Some(values) = layout.get("sentinels") else {
        return Ok(Vec::new());
    };
    let values = values
        .as_array()
        .ok_or_else(|| invalid("layout.sentinels", "Sentinels must be an array"))?;
    if values.len() > MAX_SLOTS as usize {
        return Err(invalid(
            "layout.sentinels",
            "Sentinel count exceeds the limit",
        ));
    }
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value.as_u64().ok_or_else(|| {
                invalid(
                    &format!("layout.sentinels[{index}]"),
                    "Sentinel must be an unsigned integer",
                )
            })
        })
        .collect()
}

fn decoded_value(raw: u64, width: u64, encoding: &str) -> Value {
    if encoding == "unsigned" {
        return Value::from(raw);
    }

    if width == 4 {
        return Value::from(i64::from(i32::from_ne_bytes((raw as u32).to_ne_bytes())));
    }

    Value::from(i64::from_ne_bytes(raw.to_ne_bytes()))
}

fn invalid_row(index: usize, reason: &str) -> Failure {
    invalid(&format!("type_records[{index}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP field-offset table input is invalid.".into(),
        false,
        "Provide an explicit bounded field-offset table layout and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
