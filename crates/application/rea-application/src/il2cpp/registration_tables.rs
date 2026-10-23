//! Projection of caller-supplied IL2CPP registration-table facts.
//!
//! Registration layouts change between Unity versions and generated builds.
//! This module therefore requires the caller to provide an explicit layout
//! descriptor. It validates facts against that descriptor, but never guesses
//! field offsets or selects one candidate root from several plausible roots.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_registration_tables";
const MAX_CANDIDATES: usize = 4_096;
const MAX_FIELDS: usize = 128;
const MAX_METHOD_POINTER_ROWS: usize = 200_000;
const MAX_EVIDENCE: usize = 128;
const MAX_NAME_LENGTH: usize = 256;
const MAX_EVIDENCE_LENGTH: usize = 2_048;
const MAX_COUNT: u64 = 16 * 1024 * 1024;
const MAX_POINTER_WIDTH: u64 = 8;
const MAX_SCHEMA_INTEGER: u64 = 9_007_199_254_740_991;

/// Validate and project explicit registration layout and candidate facts.
///
/// The input is intentionally data-only. A layout has a metadata version,
/// pointer width, byte order, and named fields with explicit offsets. Each
/// candidate supplies the observed field values, optional method-pointer rows,
/// and optional source identity. The output retains every candidate, field,
/// and pointer source row, including unresolved and ambiguous observations.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    reject_unknown(root, &["metadata_version", "layout", "candidates"])?;

    let version = required_u64(root, "metadata_version")?;
    if !matches!(version, 29 | 31 | 39) {
        return Err(invalid(
            "metadata_version",
            "Supported versions are 29, 31 and 39",
        ));
    }

    let layout = root
        .get("layout")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout", "An explicit layout descriptor is required"))?;
    let descriptor = parse_layout(layout, version)?;

    let candidates = root
        .get("candidates")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("candidates", "Candidates must be an array"))?;
    if candidates.len() > MAX_CANDIDATES {
        return Err(invalid(
            "candidates",
            "Candidate count exceeds the safety limit",
        ));
    }

    let mut projected = Vec::with_capacity(candidates.len());
    let mut states = BTreeSet::new();
    for (row, candidate) in candidates.iter().enumerate() {
        let value = project_candidate(candidate, row, &descriptor)?;
        if let Some(state) = value.get("state").and_then(Value::as_str) {
            states.insert(state.to_owned());
        }
        projected.push(value);
    }

    let status = if states.contains("ambiguous") || candidates.is_empty() || candidates.len() > 1 {
        "ambiguous"
    } else if states.contains("rejected") || states.contains("unknown") {
        "partial"
    } else {
        "complete"
    };

    Ok(serde_json::json!({
        "operation": OPERATION,
        "metadata_version": version,
        "layout": descriptor,
        "status": status,
        "candidates": projected,
        "coverage": {
            "candidate_count": candidates.len(),
            "candidate_selection": if candidates.len() == 1 { "unique_input" } else { "ambiguous_input" },
            "states": states.into_iter().collect::<Vec<_>>()
        },
        "limitations": [
            "The layout descriptor and candidate facts are caller-supplied observations.",
            "This projection does not discover registration roots or prove runtime ownership.",
            "Multiple candidates remain ambiguous and are never collapsed."
        ]
    }))
}

fn parse_layout(layout: &Map<String, Value>, version: u64) -> Result<Value, Failure> {
    reject_unknown(
        layout,
        &["metadata_version", "pointer_width", "endianness", "fields"],
    )?;
    if let Some(layout_version_value) = layout.get("metadata_version") {
        let layout_version = layout_version_value.as_u64().ok_or_else(|| {
            invalid(
                "layout.metadata_version",
                "Layout metadata version must be a non-negative integer",
            )
        })?;
        if layout_version != version {
            return Err(invalid(
                "layout.metadata_version",
                "Layout version does not match input",
            ));
        }
    }
    let pointer_width = required_u64(layout, "pointer_width")?;
    if pointer_width != 4 && pointer_width != MAX_POINTER_WIDTH {
        return Err(invalid(
            "layout.pointer_width",
            "Pointer width must be 4 or 8",
        ));
    }
    let endianness = layout
        .get("endianness")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("layout.endianness", "Endianness is required"))?;
    if !matches!(endianness, "little" | "big") {
        return Err(invalid(
            "layout.endianness",
            "Endianness must be little or big",
        ));
    }
    let fields = layout
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("layout.fields", "Layout fields are required"))?;
    if fields.is_empty() || fields.len() > MAX_FIELDS {
        return Err(invalid(
            "layout.fields",
            "Layout field count is out of bounds",
        ));
    }

    let mut seen_names = BTreeSet::new();
    let mut seen_indices = BTreeSet::new();
    let mut occupied_ranges = Vec::new();
    let mut normalized = Vec::with_capacity(fields.len());
    for (row, field) in fields.iter().enumerate() {
        let object = field
            .as_object()
            .ok_or_else(|| invalid_row("layout.fields", row, "Field must be an object"))?;
        reject_unknown(
            object,
            &[
                "name",
                "index",
                "count_offset",
                "pointer_offset",
                "element_width",
            ],
        )?;
        let name = object
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_row("layout.fields", row, "Field name is required"))?;
        if name.chars().count() > MAX_NAME_LENGTH {
            return Err(invalid_row(
                "layout.fields",
                row,
                "Field name exceeds the safety limit",
            ));
        }
        if !seen_names.insert(name.to_owned()) {
            return Err(invalid_row(
                "layout.fields",
                row,
                "Field names must be unique",
            ));
        }
        let index = required_u64_at(object, "index", "layout.fields", row)?;
        ensure_schema_integer(index, "layout.fields", row, "index")?;
        if !seen_indices.insert(index) {
            return Err(invalid_row(
                "layout.fields",
                row,
                "Field indices must be unique",
            ));
        }
        let count_offset = required_u64_at(object, "count_offset", "layout.fields", row)?;
        ensure_schema_integer(count_offset, "layout.fields", row, "count_offset")?;
        let pointer_offset = required_u64_at(object, "pointer_offset", "layout.fields", row)?;
        ensure_schema_integer(pointer_offset, "layout.fields", row, "pointer_offset")?;
        let element_width = required_u64_at(object, "element_width", "layout.fields", row)?;
        if element_width == 0 || element_width > 64 || !element_width.is_power_of_two() {
            return Err(invalid_row(
                "layout.fields",
                row,
                "Element width must be a power of two between 1 and 64",
            ));
        }
        let count_end = count_offset
            .checked_add(4)
            .ok_or_else(|| invalid_row("layout.fields", row, "Count offset overflows"))?;
        let pointer_end = pointer_offset
            .checked_add(pointer_width)
            .ok_or_else(|| invalid_row("layout.fields", row, "Pointer offset overflows"))?;

        validate_layout_range(
            &mut occupied_ranges,
            name,
            "count",
            count_offset,
            count_end,
            row,
        )?;
        validate_layout_range(
            &mut occupied_ranges,
            name,
            "pointer",
            pointer_offset,
            pointer_end,
            row,
        )?;

        normalized.push(serde_json::json!({
            "name": name,
            "index": index,
            "count_offset": count_offset,
            "pointer_offset": pointer_offset,
            "element_width": element_width
        }));
    }
    Ok(serde_json::json!({
        "metadata_version": version,
        "pointer_width": pointer_width,
        "endianness": endianness,
        "fields": normalized
    }))
}

fn project_candidate(candidate: &Value, row: usize, descriptor: &Value) -> Result<Value, Failure> {
    let object = candidate
        .as_object()
        .ok_or_else(|| invalid_row("candidates", row, "Candidate must be an object"))?;
    reject_unknown(
        object,
        &[
            "root_file_offset",
            "root_address",
            "state",
            "fields",
            "method_pointers",
            "method_pointer_count",
            "evidence",
        ],
    )?;
    let fields = object
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_row("candidates", row, "Candidate fields are required"))?;
    if fields.len() > MAX_FIELDS {
        return Err(invalid_row(
            "candidates",
            row,
            "Candidate field count exceeds the safety limit",
        ));
    }
    let method_pointers = parse_method_pointer_rows(object, row)?;
    let method_pointer_count = parse_method_pointer_count(object, row)?;
    let projected_method_pointers = method_pointers
        .as_ref()
        .map(|rows| project_method_pointer_rows(rows, row))
        .transpose()?;
    let method_pointer_count_match = method_pointer_count
        .zip(method_pointers.as_ref())
        .map(|(count, rows)| rows.len() as u64 == count);
    let method_pointer_slots_complete = method_pointer_count
        .zip(projected_method_pointers.as_ref())
        .map(|(count, rows)| method_pointer_slots_cover_count(rows, count));
    let descriptor_fields = descriptor["fields"].as_array().expect("normalized layout");

    if let Some(root_file_offset) = object.get("root_file_offset") {
        if !root_file_offset.is_u64() {
            return Err(invalid_row(
                "candidates.root_file_offset",
                row,
                "Root file offset must be a non-negative integer",
            ));
        }
        ensure_schema_integer(
            root_file_offset
                .as_u64()
                .expect("validated root file offset"),
            "candidates.root_file_offset",
            row,
            "root_file_offset",
        )?;
    }
    if let Some(root_address) = object.get("root_address") {
        if !root_address.is_u64() {
            return Err(invalid_row(
                "candidates.root_address",
                row,
                "Root address must be a non-negative integer",
            ));
        }
    }
    if let Some(state) = object.get("state") {
        if !state.is_string() {
            return Err(invalid_row(
                "candidates.state",
                row,
                "Candidate state must be a string",
            ));
        }
    }
    if let Some(evidence) = object.get("evidence") {
        validate_evidence(evidence, "candidates.evidence", row)?;
    }

    let mut seen_field_indices = BTreeSet::new();
    let mut projected_fields = Vec::with_capacity(fields.len());
    for (field_row, field) in fields.iter().enumerate() {
        let value = project_field(field, field_row, descriptor_fields)?;
        let index = value["index"].as_u64().expect("validated field index");
        if !seen_field_indices.insert(index) {
            return Err(invalid_row(
                "candidates",
                row,
                "Duplicate field indices are ambiguous",
            ));
        }
        projected_fields.push(value);
    }

    let supplied_state = object.get("state").and_then(Value::as_str);
    let valid_states = ["validated", "ambiguous", "rejected", "unknown"];
    if let Some(state) = supplied_state {
        if !valid_states.contains(&state) {
            return Err(invalid_row(
                "candidates.state",
                row,
                "Unknown candidate state",
            ));
        }
    }
    let invalid_fields = projected_fields
        .iter()
        .filter(|field| field["valid"] == false)
        .count();
    let unresolved_fields = projected_fields
        .iter()
        .filter(|field| field["resolution"] == "unknown")
        .count();
    let state = derive_candidate_state(
        supplied_state,
        object.get("root_address").is_some(),
        invalid_fields,
        unresolved_fields,
        method_pointer_count_match,
        method_pointer_count,
        method_pointer_slots_complete,
        projected_method_pointers.as_deref(),
    );
    let evidence = object
        .get("evidence")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    validate_evidence(&evidence, "candidates.evidence", row)?;

    let mut output = Map::new();
    for key in ["root_file_offset", "root_address"] {
        if let Some(value) = object.get(key) {
            output.insert(key.to_owned(), value.clone());
        }
    }
    if let Some(count) = method_pointer_count {
        output.insert("method_pointer_count".into(), Value::from(count));
    }
    if let Some(count_match) = method_pointer_count_match {
        output.insert(
            "method_pointer_count_match".into(),
            Value::from(count_match),
        );
    }
    if let Some(rows) = projected_method_pointers {
        output.insert("method_pointers".into(), Value::Array(rows));
    }
    output.insert("state".into(), Value::from(state));
    output.insert("fields".into(), Value::Array(projected_fields));
    output.insert("evidence".into(), evidence);
    Ok(Value::Object(output))
}

fn derive_candidate_state(
    supplied_state: Option<&str>,
    has_root_address: bool,
    invalid_field_count: usize,
    unresolved_field_count: usize,
    method_pointer_count_match: Option<bool>,
    method_pointer_count: Option<u64>,
    method_pointer_slots_complete: Option<bool>,
    method_pointers: Option<&[Value]>,
) -> &'static str {
    match supplied_state {
        Some("ambiguous") => return "ambiguous",
        Some("rejected") => return "rejected",
        Some("unknown") => return "unknown",
        Some("validated") | None => {}
        Some(_) => unreachable!("candidate state is validated before derivation"),
    }

    if invalid_field_count > 0 || method_pointer_count_match == Some(false) {
        return "rejected";
    }
    if unresolved_field_count > 0 {
        return "unknown";
    }
    if !has_root_address {
        return "ambiguous";
    }

    let Some(rows) = method_pointers else {
        if method_pointer_count.is_some_and(|count| count > 0) {
            return "unknown";
        }
        return "validated";
    };
    if rows
        .iter()
        .any(|row| row.get("resolution").and_then(Value::as_str) == Some("ambiguous"))
    {
        return "ambiguous";
    }
    if rows
        .iter()
        .any(|row| row.get("resolution").and_then(Value::as_str) == Some("unknown"))
    {
        return "unknown";
    }
    if method_pointer_count.is_none() {
        return "unknown";
    }
    if method_pointer_slots_complete == Some(false) {
        return "unknown";
    }

    "validated"
}

fn method_pointer_slots_cover_count(rows: &[Value], count: u64) -> bool {
    let slots = rows
        .iter()
        .filter_map(|row| row.get("slot").and_then(Value::as_u64))
        .collect::<BTreeSet<_>>();

    slots.len() == rows.len() && slots.iter().copied().eq(0..count)
}

fn parse_method_pointer_count(
    object: &Map<String, Value>,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let Some(value) = object.get("method_pointer_count") else {
        return Ok(None);
    };
    let count = value.as_u64().ok_or_else(|| {
        invalid_row(
            "candidates.method_pointer_count",
            row,
            "Method pointer count must be a non-negative integer",
        )
    })?;
    if count > MAX_METHOD_POINTER_ROWS as u64 {
        return Err(invalid_row(
            "candidates.method_pointer_count",
            row,
            "Method pointer count exceeds the safety limit",
        ));
    }
    Ok(Some(count))
}

fn parse_method_pointer_rows(
    object: &Map<String, Value>,
    row: usize,
) -> Result<Option<Vec<Value>>, Failure> {
    let Some(value) = object.get("method_pointers") else {
        return Ok(None);
    };
    let rows = value.as_array().ok_or_else(|| {
        invalid_row(
            "candidates.method_pointers",
            row,
            "Method pointers must be an array",
        )
    })?;
    if rows.len() > MAX_METHOD_POINTER_ROWS {
        return Err(invalid_row(
            "candidates.method_pointers",
            row,
            "Method pointer rows exceed the safety limit",
        ));
    }
    Ok(Some(rows.clone()))
}

fn project_method_pointer_rows(
    rows: &[Value],
    candidate_row: usize,
) -> Result<Vec<Value>, Failure> {
    let mut seen_slots = BTreeSet::new();
    let mut duplicate_slots = BTreeSet::new();
    let mut projected = Vec::with_capacity(rows.len());

    for (position, source) in rows.iter().enumerate() {
        let slot = source
            .as_object()
            .and_then(|object| object.get("slot"))
            .map(|value| {
                parse_method_pointer_integer(value).ok_or_else(|| {
                    invalid_row(
                        "candidates.method_pointers",
                        candidate_row,
                        "Method pointer slot must be a non-negative integer",
                    )
                })
            })
            .transpose()?
            .unwrap_or(position as u64);
        if !seen_slots.insert(slot) {
            duplicate_slots.insert(slot);
        }
        projected.push(method_pointer_row(source, slot));
    }

    for row in &mut projected {
        let slot = row["slot"].as_u64().expect("projected slot");
        if duplicate_slots.contains(&slot) {
            row["resolution"] = Value::from("ambiguous");
        }
    }
    Ok(projected)
}

fn parse_method_pointer_integer(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        value.as_str().and_then(|text| {
            text.strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .map_or_else(
                    || text.parse().ok(),
                    |digits| u64::from_str_radix(digits, 16).ok(),
                )
        })
    })
}

fn method_pointer_row(source: &Value, slot: u64) -> Value {
    let pointer = parse_method_pointer_integer(source).or_else(|| {
        source.as_object().and_then(|object| {
            [
                "pointer",
                "address",
                "method_pointer",
                "target_virtual_address",
                "virtual_address",
            ]
            .iter()
            .find_map(|key| object.get(*key).and_then(parse_method_pointer_integer))
        })
    });
    let resolution = match pointer {
        Some(0) | None => "unknown",
        Some(_) => "mapped",
    };
    serde_json::json!({
        "slot": slot,
        "source": source,
        "pointer": pointer,
        "resolution": resolution,
    })
}

fn project_field(field: &Value, row: usize, descriptor_fields: &[Value]) -> Result<Value, Failure> {
    let object = field
        .as_object()
        .ok_or_else(|| invalid_row("candidates.fields", row, "Field fact must be an object"))?;
    reject_unknown(
        object,
        &[
            "index",
            "name",
            "count",
            "pointer",
            "source_address",
            "available_bytes",
            "valid",
            "evidence",
        ],
    )?;
    let index = required_u64_at(object, "index", "candidates.fields", row)?;
    ensure_schema_integer(index, "candidates.fields", row, "index")?;
    let descriptor = descriptor_fields
        .iter()
        .find(|value| value["index"] == index);
    let descriptor = descriptor.ok_or_else(|| {
        invalid_row(
            "candidates.fields",
            row,
            "Field index is absent from explicit layout",
        )
    })?;
    let count = required_u64_at(object, "count", "candidates.fields", row)?;
    if count > MAX_COUNT {
        return Err(invalid_row(
            "candidates.fields",
            row,
            "Count exceeds the safety limit",
        ));
    }
    let pointer = required_u64_at(object, "pointer", "candidates.fields", row)?;
    let width = descriptor["element_width"]
        .as_u64()
        .expect("validated descriptor");
    let required_bytes = count
        .checked_mul(width)
        .ok_or_else(|| invalid_row("candidates.fields", row, "Required table bytes overflow"))?;
    let available = object.get("available_bytes").and_then(Value::as_u64);
    if let Some(available_bytes) = object.get("available_bytes") {
        if !available_bytes.is_u64() {
            return Err(invalid_row(
                "candidates.fields",
                row,
                "available_bytes must be a non-negative integer",
            ));
        }
        ensure_schema_integer(
            available_bytes
                .as_u64()
                .expect("validated available byte count"),
            "candidates.fields",
            row,
            "available_bytes",
        )?;
    }
    if let Some(source_address) = object.get("source_address") {
        if !source_address.is_u64() {
            return Err(invalid_row(
                "candidates.fields",
                row,
                "source_address must be a non-negative integer",
            ));
        }
    }
    if let Some(valid) = object.get("valid") {
        if !valid.is_boolean() {
            return Err(invalid_row(
                "candidates.fields",
                row,
                "valid must be a boolean",
            ));
        }
    }
    if let Some(name) = object.get("name") {
        let name = name
            .as_str()
            .ok_or_else(|| invalid_row("candidates.fields", row, "name must be a string"))?;
        if name.chars().count() > MAX_NAME_LENGTH {
            return Err(invalid_row(
                "candidates.fields",
                row,
                "name exceeds the safety limit",
            ));
        }
    }
    if let Some(evidence) = object.get("evidence") {
        validate_evidence(evidence, "candidates.fields.evidence", row)?;
    }
    if let Some(source_address) = object.get("source_address").and_then(Value::as_u64) {
        let end = source_address
            .checked_add(required_bytes)
            .ok_or_else(|| invalid_row("candidates.fields", row, "Source table range overflows"))?;
        let _ = end;
    }

    // A short capture is a meaningful partial observation. Preserve its span
    // and let the derived validity remain unknown instead of rejecting it.
    let claimed_valid = object
        .get("valid")
        .and_then(Value::as_bool)
        .unwrap_or_else(|| {
            count == 0 || (pointer != 0 && available.is_some_and(|size| size >= required_bytes))
        });
    let structurally_available =
        count == 0 || (pointer != 0 && available.is_some_and(|size| size >= required_bytes));
    let valid = claimed_valid;
    let mut output = object.clone();
    output.insert("layout_name".into(), descriptor["name"].clone());
    output.insert("required_bytes".into(), Value::from(required_bytes));
    output.insert("valid".into(), Value::from(valid));
    output.insert(
        "resolution".into(),
        Value::from(if valid && structurally_available {
            "validated"
        } else {
            "unknown"
        }),
    );
    let source_span = match (
        object.get("source_address").and_then(Value::as_u64),
        available,
    ) {
        (Some(source_address), Some(available_bytes)) => {
            let end = source_address.checked_add(required_bytes).ok_or_else(|| {
                invalid_row("candidates.fields", row, "Source table range overflows")
            })?;
            serde_json::json!({
                "start": source_address,
                "end": end,
                "length": required_bytes,
                "available_bytes": available_bytes
            })
        }
        _ => Value::Null,
    };
    output.insert("source_span".into(), source_span);
    Ok(Value::Object(output))
}

fn validate_layout_range(
    occupied_ranges: &mut Vec<(String, String, u64, u64)>,
    name: &str,
    kind: &str,
    start: u64,
    end: u64,
    row: usize,
) -> Result<(), Failure> {
    if let Some((previous_name, previous_kind, _, _)) = occupied_ranges
        .iter()
        .find(|(_, _, previous_start, previous_end)| start < *previous_end && *previous_start < end)
    {
        return Err(invalid_row(
            "layout.fields",
            row,
            &format!("{kind} range for {name} overlaps {previous_kind} range for {previous_name}"),
        ));
    }

    occupied_ranges.push((name.to_owned(), kind.to_owned(), start, end));
    Ok(())
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("input", &format!("Unexpected field {key}")));
    }
    Ok(())
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, Failure> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(key, "Expected a non-negative integer"))
}

fn required_u64_at(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
    row: usize,
) -> Result<u64, Failure> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_row(field, row, &format!("{key} must be a non-negative integer")))
}

fn ensure_schema_integer(value: u64, field: &str, row: usize, name: &str) -> Result<(), Failure> {
    if value > MAX_SCHEMA_INTEGER {
        return Err(invalid_row(
            field,
            row,
            &format!("{name} exceeds the JSON-safe integer limit"),
        ));
    }
    Ok(())
}

fn validate_evidence(value: &Value, field: &str, row: usize) -> Result<(), Failure> {
    let items = value
        .as_array()
        .ok_or_else(|| invalid_row(field, row, "Evidence must be an array of strings"))?;
    if items.len() > MAX_EVIDENCE {
        return Err(invalid_row(
            field,
            row,
            "Evidence count exceeds the safety limit",
        ));
    }
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| invalid_row(field, row, "Evidence must be an array of strings"))?;
        if text.chars().count() > MAX_EVIDENCE_LENGTH {
            return Err(invalid_row(
                field,
                row,
                "Evidence item exceeds the safety limit",
            ));
        }
    }
    Ok(())
}

fn invalid_row(field: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{field}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP registration-table input is invalid.".into(),
        false,
        "Supply an explicit versioned layout and captured candidate facts and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
