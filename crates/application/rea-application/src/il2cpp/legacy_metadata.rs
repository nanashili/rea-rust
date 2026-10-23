//! Bounded inspection of legacy Unity IL2CPP metadata headers.
//!
//! IL2CPP metadata versions 24.x through 28 do not share one stable serialized
//! row layout.  This module therefore decodes only the common magic/version
//! prefix and an explicitly described sequence of offset/size pairs.  It does
//! not infer record widths, section meanings, or relationships from a version
//! number.  Callers must provide those facts separately when they have a
//! version-specific capture.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_il2cpp_legacy_metadata";
const MAGIC: u32 = 0xfab1_1baf;
const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_PAIRS: usize = 128;
const MAX_OWNERSHIP_COLLECTIONS: usize = 128;
const MAX_OWNERSHIP_ROWS: usize = 200_000;
const MAX_TABLES: usize = 64;
const MAX_TABLE_ROWS: usize = 200_000;

/// Decode a captured legacy metadata header using an explicit pair count.
///
/// Required input fields are `metadata_version`, `bytes_base64`, and
/// `layout.header_pair_count`.  `layout.header_size` must equal the encoded
/// pair count's header size.  Optional `section_names` labels are retained,
/// but never used to select or reinterpret a pair.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "metadata_version" | "bytes_base64" | "layout" | "artifact" | "ownership"
        ) {
            return Err(invalid(key, "Unknown input field"));
        }
    }

    let version = object
        .get("metadata_version")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("metadata_version", "Legacy metadata version is required"))?;
    if !(24..=28).contains(&version) {
        return Err(invalid(
            "metadata_version",
            "Only legacy metadata versions 24 through 28 are supported",
        ));
    }

    let encoded = object
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("bytes_base64", "Captured metadata bytes are required"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid("bytes_base64", "Metadata bytes are not valid base64"))?;
    if bytes.len() > MAX_BYTES {
        return Err(invalid("bytes_base64", "Metadata bytes exceed the limit"));
    }

    let layout = object
        .get("layout")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout", "An explicit legacy header layout is required"))?;
    reject_unknown(
        layout,
        &[
            "header_pair_count",
            "header_size",
            "section_names",
            "tables",
            "strings",
        ],
    )?;
    let pair_count = layout
        .get("header_pair_count")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("layout.header_pair_count", "Header pair count is required"))?;
    let pair_count = usize::try_from(pair_count)
        .map_err(|_| invalid("layout.header_pair_count", "Header pair count is too large"))?;
    if pair_count == 0 || pair_count > MAX_PAIRS {
        return Err(invalid(
            "layout.header_pair_count",
            "Header pair count is out of bounds",
        ));
    }
    let header_size = layout
        .get("header_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("layout.header_size", "Header size is required"))?;
    let expected_header_size = 8_u64
        .checked_add((pair_count as u64).saturating_mul(8))
        .ok_or_else(|| invalid("layout.header_size", "Header size overflows"))?;
    if header_size != expected_header_size {
        return Err(invalid(
            "layout.header_size",
            "Header size does not match the explicit pair count",
        ));
    }
    if header_size > bytes.len() as u64 {
        return Err(invalid(
            "bytes_base64",
            "Captured bytes are shorter than the header",
        ));
    }

    let magic = read_u32(&bytes, 0)?;
    let encoded_version = read_u32(&bytes, 4)?;
    if magic != MAGIC {
        return Err(invalid("magic", "Metadata magic is invalid"));
    }
    if encoded_version != version as u32 {
        return Err(invalid(
            "metadata_version",
            "Input version disagrees with the captured header",
        ));
    }

    let names = layout.get("section_names").and_then(Value::as_array);
    if let Some(names) = names {
        if names.len() != pair_count
            || !names.iter().all(|value| {
                value
                    .as_str()
                    .is_some_and(|name| !name.is_empty() && name.chars().count() <= 256)
            })
        {
            return Err(invalid(
                "layout.section_names",
                "Section names must match the pair count and be non-empty strings of at most 256 characters",
            ));
        }
    }

    let mut sections = Vec::with_capacity(pair_count);
    let mut raw_header_pairs = Vec::with_capacity(pair_count);
    let mut ranges = Vec::new();
    for index in 0..pair_count {
        let position = 8 + index * 8;
        let offset = read_u32(&bytes, position)? as u64;
        let size = read_u32(&bytes, position + 4)? as u64;
        if index == 0 && offset != header_size {
            return Err(invalid(
                "sections",
                "The first section must begin immediately after the header",
            ));
        }
        let end = offset
            .checked_add(size)
            .ok_or_else(|| invalid("sections", "Section range overflows"))?;
        if size > 0 && offset < header_size {
            return Err(invalid(
                "sections",
                "Non-empty section begins inside the header",
            ));
        }
        if end > bytes.len() as u64 {
            return Err(invalid("sections", "Section extends beyond captured bytes"));
        }
        if size > 0 {
            for (other_start, other_end) in &ranges {
                if offset < *other_end && *other_start < end {
                    return Err(invalid("sections", "Section ranges overlap"));
                }
            }
            ranges.push((offset, end));
        }
        raw_header_pairs.push(json!({
            "index": index,
            "source_offset": position,
            "offset": offset,
            "size": size,
        }));
        let name = names
            .and_then(|values| values.get(index))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("section_{index}"));
        sections.push(json!({
            "index": index,
            "name": name,
            "offset": offset,
            "size": size,
            "count": Value::Null,
            "record_layout": Value::Null,
        }));
    }

    let tables = parse_tables(layout.get("tables"), &sections, &bytes)?;
    apply_table_descriptors(&mut sections, &tables);
    let rows = project_tables(&tables, layout.get("strings"), &sections, &bytes)?;
    let rows_coverage = if tables.is_empty()
        || tables
            .iter()
            .any(|table| table.section_resolution != "resolved" || table.uncovered_bytes > 0)
    {
        "unknown"
    } else {
        "complete"
    };

    let mut result = json!({
        "operation": OPERATION,
        "metadata_version": version,
        "magic": magic,
        "header": {
            "size": header_size,
            "pair_count": pair_count,
            "layout_source": "caller-supplied",
        },
        "artifact": {
            "bytes": bytes.len(),
        },
        "source": {
            "byte_count": bytes.len(),
            "header_bytes_base64": base64::engine::general_purpose::STANDARD
                .encode(&bytes[..header_size as usize]),
            "raw_header_pairs": raw_header_pairs,
        },
        "sections": sections,
        "rows": rows,
        "ownership": Value::Null,
        "coverage": {
            "header": "complete",
            "sections": "complete",
            "captured_byte_bounds_validated": true,
            "rows": rows_coverage,
        },
        "limitations": [
            "Legacy 24.x-28 row layouts vary across Unity releases and are not inferred from the version number.",
            "Section counts, names, records, and relationships remain unknown unless supplied by a separate version-specific capture.",
            "No native code addresses or decompilation facts are recovered by this header projection.",
        ],
    });
    if let Some(artifact) = object.get("artifact") {
        let artifact_object = artifact
            .as_object()
            .ok_or_else(|| invalid("artifact", "Artifact must be an object"))?;
        reject_unknown(artifact_object, &["path", "sha256", "id"])?;
        result["artifact"]["identity"] = artifact.clone();
    }
    if let Some(ownership) = object.get("ownership") {
        result["ownership"] = project_ownership(ownership, &sections)?;
    }
    Ok(result)
}

#[derive(Debug)]
struct TableDescriptor {
    name: String,
    section: String,
    offset: usize,
    size: usize,
    record_size: usize,
    count: usize,
    uncovered_bytes: usize,
    section_resolution: &'static str,
    fields: Vec<(String, usize)>,
}

fn parse_tables(
    value: Option<&Value>,
    sections: &[Value],
    bytes: &[u8],
) -> Result<Vec<TableDescriptor>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid("layout.tables", "Tables must be an object"))?;
    if object.len() > MAX_TABLES {
        return Err(invalid("layout.tables", "Too many explicit tables"));
    }
    let mut tables = Vec::with_capacity(object.len());
    for (name, descriptor) in object {
        if name.is_empty() || name.chars().count() > 128 {
            return Err(invalid(
                "layout.tables",
                "Table names are bounded non-empty strings",
            ));
        }
        let descriptor = descriptor
            .as_object()
            .ok_or_else(|| invalid("layout.tables", "Table descriptors must be objects"))?;
        reject_unknown(descriptor, &["section", "record_size", "count", "fields"])?;
        let section = descriptor
            .get("section")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("layout.tables", "Table section is required"))?;
        let matching_sections = sections
            .iter()
            .filter(|entry| entry.get("name").and_then(Value::as_str) == Some(section))
            .collect::<Vec<_>>();
        let section_value = matching_sections
            .first()
            .copied()
            .ok_or_else(|| invalid("layout.tables", "Table section is not present"))?;
        let section_resolution = if matching_sections.len() == 1 {
            "resolved"
        } else {
            "ambiguous"
        };
        let offset = usize::try_from(section_value["offset"].as_u64().unwrap_or(0))
            .map_err(|_| invalid("layout.tables", "Table offset exceeds platform bounds"))?;
        let size = usize::try_from(section_value["size"].as_u64().unwrap_or(0))
            .map_err(|_| invalid("layout.tables", "Table size exceeds platform bounds"))?;
        let record_size = descriptor
            .get("record_size")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("layout.tables", "Table record_size is required"))?;
        let record_size = usize::try_from(record_size)
            .map_err(|_| invalid("layout.tables", "Table record_size is too large"))?;
        if record_size == 0 || record_size % 4 != 0 {
            return Err(invalid(
                "layout.tables",
                "Table record_size must be a non-zero multiple of four",
            ));
        }
        let count = if section_resolution == "ambiguous" {
            0
        } else {
            match descriptor.get("count").and_then(Value::as_u64) {
                Some(count) => usize::try_from(count)
                    .map_err(|_| invalid("layout.tables", "Table count is too large"))?,
                None => size / record_size,
            }
        };
        if section_resolution == "resolved"
            && (count > MAX_TABLE_ROWS
                || count
                    .checked_mul(record_size)
                    .is_none_or(|span| span > size))
        {
            return Err(invalid(
                "layout.tables",
                "Table rows exceed the section bounds",
            ));
        }
        let covered_bytes = count
            .checked_mul(record_size)
            .ok_or_else(|| invalid("layout.tables", "Table row span overflows"))?;
        let fields = parse_table_fields(descriptor.get("fields"), record_size)?;
        if section_resolution == "resolved"
            && offset.checked_add(size).is_none_or(|end| end > bytes.len())
        {
            return Err(invalid(
                "layout.tables",
                "Table section exceeds captured bytes",
            ));
        }
        tables.push(TableDescriptor {
            name: name.clone(),
            section: section.to_owned(),
            offset,
            size,
            record_size,
            count,
            uncovered_bytes: size - covered_bytes,
            section_resolution,
            fields,
        });
    }
    Ok(tables)
}

fn parse_table_fields(
    value: Option<&Value>,
    record_size: usize,
) -> Result<Vec<(String, usize)>, Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout.tables.fields", "Table fields are required"))?;
    if object.len() > 32 {
        return Err(invalid("layout.tables.fields", "Too many table fields"));
    }
    let mut fields = Vec::with_capacity(object.len());
    for (name, offset) in object {
        let offset =
            usize::try_from(offset.as_u64().ok_or_else(|| {
                invalid("layout.tables.fields", "Field offsets must be integers")
            })?)
            .map_err(|_| invalid("layout.tables.fields", "Field offset is too large"))?;
        if offset % 4 != 0 || offset.checked_add(4).is_none_or(|end| end > record_size) {
            return Err(invalid(
                "layout.tables.fields",
                "Field offset leaves the record",
            ));
        }
        fields.push((name.clone(), offset));
    }
    Ok(fields)
}

fn apply_table_descriptors(sections: &mut [Value], tables: &[TableDescriptor]) {
    for table in tables {
        for section in sections.iter_mut().filter(|entry| {
            entry.get("name").and_then(Value::as_str) == Some(table.section.as_str())
        }) {
            section["count"] = json!(table.count);
            section["record_layout"] = json!({
                "record_size": table.record_size,
                "uncovered_bytes": table.uncovered_bytes,
                "section_resolution": table.section_resolution,
                "fields": table.fields.iter().map(|(name, offset)| json!({ "name": name, "offset": offset })).collect::<Vec<_>>()
            });
        }
    }
}

fn project_tables(
    tables: &[TableDescriptor],
    strings: Option<&Value>,
    sections: &[Value],
    bytes: &[u8],
) -> Result<Value, Failure> {
    if tables.is_empty() {
        return Ok(Value::Null);
    }
    let string_table = parse_string_table(strings, sections, bytes)?;
    let mut output = Map::new();
    for table in tables {
        if table.section_resolution != "resolved" {
            output.insert(table.name.clone(), Value::Null);
            continue;
        }
        let mut rows = Vec::with_capacity(table.count);
        for index in 0..table.count {
            let source_offset = table.offset + index * table.record_size;
            let mut row = json!({ "metadata_index": index, "source_offset": source_offset });
            for (field, field_offset) in &table.fields {
                let value = read_u32(bytes, source_offset + field_offset)?;
                row[field] = json!(value);
                if field.ends_with("name_index") || field == "name" {
                    if let Some(name) = string_table
                        .as_ref()
                        .and_then(|table| table.resolve(value as usize))
                    {
                        row[format!("{field}_value")] = json!(name);
                    }
                }
            }
            rows.push(row);
        }
        output.insert(table.name.clone(), Value::Array(rows));
    }
    Ok(Value::Object(output))
}

struct StringTable<'a> {
    offset: usize,
    size: usize,
    bytes: &'a [u8],
}

impl StringTable<'_> {
    fn resolve(&self, index: usize) -> Option<String> {
        if index >= self.size {
            return None;
        }
        let start = self.offset + index;
        let end = self.bytes[start..self.offset + self.size]
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| start + length)
            .unwrap_or(self.offset + self.size);
        std::str::from_utf8(&self.bytes[start..end])
            .ok()
            .map(str::to_owned)
    }
}

fn parse_string_table<'a>(
    value: Option<&Value>,
    sections: &[Value],
    bytes: &'a [u8],
) -> Result<Option<StringTable<'a>>, Failure> {
    let Some(value) = value else {
        return Ok(None);
    };
    let object = value
        .as_object()
        .ok_or_else(|| invalid("layout.strings", "Strings must be an object"))?;
    reject_unknown(object, &["section"])?;
    let section = object
        .get("section")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("layout.strings", "String section is required"))?;
    let matching_sections = sections
        .iter()
        .filter(|entry| entry.get("name").and_then(Value::as_str) == Some(section))
        .collect::<Vec<_>>();
    let Some(entry) = matching_sections.first().copied() else {
        return Err(invalid("layout.strings", "String section is not present"));
    };
    if matching_sections.len() > 1 {
        return Ok(None);
    }
    let offset = usize::try_from(entry["offset"].as_u64().unwrap_or(0))
        .map_err(|_| invalid("layout.strings", "String offset is too large"))?;
    let size = usize::try_from(entry["size"].as_u64().unwrap_or(0))
        .map_err(|_| invalid("layout.strings", "String size is too large"))?;
    if offset.checked_add(size).is_none_or(|end| end > bytes.len()) {
        return Err(invalid(
            "layout.strings",
            "String section exceeds captured bytes",
        ));
    }
    Ok(Some(StringTable {
        offset,
        size,
        bytes,
    }))
}

/// Project caller-supplied captured bytes using the explicit legacy layout.
///
/// This named entry point mirrors the captured projection APIs for newer
/// metadata versions. It intentionally delegates to [`project`], which owns
/// all byte bounds and version/layout validation and performs no I/O.
pub fn project_captured(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Alias for callers that use operation-oriented capture terminology.
pub fn capture(input: &Value) -> Result<Value, Failure> {
    project_captured(input)
}

/// Retain caller-supplied ownership ranges without interpreting legacy row
/// records.  The conventional collections are `methods`, `parameters`, and
/// `fields`; other collection names are retained so a version-specific
/// producer can add a distinct table without changing this boundary. A range
/// is useful only when its section name and bounds are explicit; malformed
/// entries remain visible with a diagnostic status.
fn project_ownership(ownership: &Value, sections: &[Value]) -> Result<Value, Failure> {
    let object = ownership
        .as_object()
        .ok_or_else(|| invalid("ownership", "Ownership must be an object"))?;
    if object.len() > MAX_OWNERSHIP_COLLECTIONS {
        return Err(invalid(
            "ownership",
            "Ownership contains more collections than the bounded limit",
        ));
    }
    let mut output = serde_json::Map::new();
    for (collection, value) in object {
        let rows = value
            .as_array()
            .ok_or_else(|| invalid("ownership", "Ownership collections must be arrays"))?;
        if rows.len() > MAX_OWNERSHIP_ROWS {
            return Err(invalid(
                "ownership",
                "Ownership collection exceeds the bounded row limit",
            ));
        }
        let mut projected = Vec::with_capacity(rows.len());
        for (row_index, row) in rows.iter().enumerate() {
            let Some(row_object) = row.as_object() else {
                projected.push(json!({
                    "index": row_index,
                    "raw": row,
                    "status": "malformed",
                    "diagnostic": "Ownership row must be an object",
                }));
                continue;
            };
            let owner = row_object.get("owner").cloned().unwrap_or(Value::Null);
            let section = row_object
                .get("section")
                .and_then(Value::as_str)
                .map(str::to_owned);
            let start = row_object.get("start").and_then(Value::as_u64);
            let count = row_object.get("count").and_then(Value::as_u64);
            let record_size = row_object.get("record_size").and_then(Value::as_u64);
            let mut projected_row = json!({
                "index": row_index,
                "raw": row,
                "owner": owner,
                "section": section,
                "start": start,
                "count": count,
                "record_size": record_size,
            });
            let diagnostic =
                ownership_diagnostic(section.as_deref(), start, count, record_size, sections);
            if let Some(message) = diagnostic {
                projected_row["status"] = Value::String("unknown".into());
                projected_row["diagnostic"] = Value::String(message.into());
            } else {
                projected_row["status"] = Value::String("range".into());
            }
            projected.push(projected_row);
        }
        output.insert(collection.clone(), Value::Array(projected));
    }
    Ok(Value::Object(output))
}

fn ownership_diagnostic(
    section: Option<&str>,
    start: Option<u64>,
    count: Option<u64>,
    record_size: Option<u64>,
    sections: &[Value],
) -> Option<&'static str> {
    let Some(section) = section else {
        return Some("Ownership section is missing");
    };
    let Some(start) = start else {
        return Some("Ownership start is missing or not an unsigned integer");
    };
    let Some(count) = count else {
        return Some("Ownership count is missing or not an unsigned integer");
    };
    let matching_sections = sections
        .iter()
        .filter(|value| value.get("name").and_then(Value::as_str) == Some(section))
        .collect::<Vec<_>>();
    let Some(section_value) = matching_sections.first().copied() else {
        return Some("Ownership section is not present in the captured header");
    };
    if matching_sections.len() > 1 {
        return Some("Ownership section name is ambiguous in the captured header");
    }
    if count > 0 && record_size == Some(0) {
        return Some("Ownership record size is zero for a non-empty range");
    }
    let Some(record_size) = record_size else {
        return Some("Ownership record size is missing; range span is unknown");
    };
    let section_bytes = section_value
        .get("size")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let span = match count.checked_mul(record_size) {
        Some(span) => span,
        None => return Some("Ownership count and record size overflow"),
    };
    if span > section_bytes {
        return Some("Ownership span exceeds the captured section byte size");
    }
    if start > section_bytes.saturating_sub(span) {
        return Some("Ownership range exceeds the captured section byte size");
    }
    None
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Failure> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid("bytes_base64", "Header offset overflows"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| invalid("bytes_base64", "Captured bytes are shorter than the header"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(key, "Unknown input field"));
        }
    }
    Ok(())
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "Legacy IL2CPP metadata capture is invalid.".into(),
        false,
        "Provide bounded bytes and an explicit version-specific header layout.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
