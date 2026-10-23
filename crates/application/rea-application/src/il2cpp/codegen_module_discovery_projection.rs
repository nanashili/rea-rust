//! JSON boundary for static IL2CPP CodeGenModule discovery.
//!
//! The discovery engine operates on typed slices so that address mapping and
//! candidate semantics stay explicit. This adapter owns only conversion from
//! bounded caller-captured JSON; it never opens an image or consults a live
//! process.

use crate::il2cpp::codegen_module_discovery::{
    self, AddressMapping, AddressRange, CandidateDisposition, DiscoveryInput, Endianness,
    PointerWidth,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "discover_il2cpp_codegen_modules";
const MAX_IMAGE_BYTES: usize = 256 * 1024 * 1024;
const MAX_RANGES: usize = 65_536;
const MAX_BASE64_CHARS: usize = 357_913_944;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_CAPTURE_RECORD_BYTES: usize = 4096;
const MAX_CAPTURE_NAME_BYTES: usize = 4096;
const MAX_CAPTURE_POINTER_BYTES: usize = 4 * 1024 * 1024;
const MAX_CAPTURE_POINTERS: u64 = 200_000;

/// Discover every plausible CodeGenModule record in a caller-supplied image.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    reject_unknown(
        root,
        &[
            "bytes_base64",
            "image_base64",
            "pointer_width",
            "endianness",
            "mappings",
            "address_mappings",
            "executable_ranges",
        ],
    )?;

    let encoded = one_text(root, &["bytes_base64", "image_base64"], "bytes_base64")?
        .ok_or_else(|| invalid("bytes_base64", "Captured image bytes are required"))?;
    if encoded.is_empty() || encoded.len() > MAX_BASE64_CHARS {
        return Err(invalid(
            "bytes_base64",
            "Captured image encoding exceeds the safety bound",
        ));
    }
    let image = STANDARD
        .decode(encoded)
        .map_err(|_| invalid("bytes_base64", "Captured image bytes are not valid base64"))?;
    if image.len() > MAX_IMAGE_BYTES {
        return Err(invalid(
            "bytes_base64",
            "Captured image exceeds the safety bound",
        ));
    }

    let pointer_width = match required_u64(root, "pointer_width")? {
        32 => PointerWidth::Bits32,
        64 => PointerWidth::Bits64,
        _ => return Err(invalid("pointer_width", "Pointer width must be 32 or 64")),
    };
    let endianness = match root
        .get("endianness")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("endianness", "Endianness is required"))?
    {
        "little" | "le" => Endianness::Little,
        "big" | "be" => Endianness::Big,
        _ => return Err(invalid("endianness", "Endianness must be little or big")),
    };

    let mappings_value = selected_value(root, &["mappings", "address_mappings"], "mappings")?
        .ok_or_else(|| invalid("mappings", "Address mappings are required"))?;
    let mappings = parse_mappings(mappings_value)?;
    let executable_ranges = parse_ranges(
        root.get("executable_ranges")
            .ok_or_else(|| invalid("executable_ranges", "Executable ranges are required"))?,
    )?;

    let report = codegen_module_discovery::discover(DiscoveryInput {
        image: &image,
        pointer_width,
        endianness,
        mappings: &mappings,
        executable_ranges: &executable_ranges,
    })
    .map_err(|error| invalid("discovery", &error.to_string()))?;

    let candidates = report
        .candidates
        .into_iter()
        .map(|candidate| candidate_value(&candidate, &image, pointer_width, endianness, &mappings))
        .collect::<Vec<_>>();
    Ok(serde_json::json!({
        "operation": OPERATION,
        "candidates": candidates,
        "scanned_offsets": report.scanned_offsets,
        "truncated": report.truncated,
        "limitations": report.limitations,
    }))
}

fn parse_mappings(value: &Value) -> Result<Vec<AddressMapping>, Failure> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("mappings", "Mappings must be an array"))?;
    if rows.len() > MAX_RANGES {
        return Err(invalid(
            "mappings",
            "Mapping count exceeds the safety bound",
        ));
    }
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let row = value
                .as_object()
                .ok_or_else(|| invalid_row("mappings", index, "Mapping must be an object"))?;
            reject_unknown(
                row,
                &["virtual_start", "virtual_end", "file_start", "file_end"],
            )?;
            Ok(AddressMapping::new(
                required_u64_at(row, "virtual_start", "mappings", index)?,
                required_u64_at(row, "virtual_end", "mappings", index)?,
                required_u64_at(row, "file_start", "mappings", index)?,
                required_u64_at(row, "file_end", "mappings", index)?,
            ))
        })
        .collect()
}

fn parse_ranges(value: &Value) -> Result<Vec<AddressRange>, Failure> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("executable_ranges", "Executable ranges must be an array"))?;
    if rows.len() > MAX_RANGES {
        return Err(invalid(
            "executable_ranges",
            "Range count exceeds the safety bound",
        ));
    }
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let row = value.as_object().ok_or_else(|| {
                invalid_row("executable_ranges", index, "Range must be an object")
            })?;
            reject_unknown(row, &["start", "end"])?;
            Ok(AddressRange::new(
                required_u64_at(row, "start", "executable_ranges", index)?,
                required_u64_at(row, "end", "executable_ranges", index)?,
            ))
        })
        .collect()
}

fn candidate_value(
    candidate: &codegen_module_discovery::CodeGenModuleCandidate,
    image: &[u8],
    pointer_width: PointerWidth,
    endianness: Endianness,
    mappings: &[AddressMapping],
) -> Value {
    let disposition = candidate_disposition_value(candidate.disposition);

    serde_json::json!({
        "record_file_offset": candidate.record_file_offset,
        "record_byte_length": candidate.record_byte_length,
        "record_virtual_address": candidate.record_virtual_address,
        "module_name": candidate.module_name,
        "module_name_file_offset": candidate.module_name_file_offset,
        "module_name_virtual_address": candidate.module_name_virtual_address,
        "method_pointer_count": candidate.method_pointer_count,
        "method_pointer_table": candidate.method_pointer_table,
        "method_pointer_table_file_offset": candidate.method_pointer_table_file_offset,
        "method_pointer_table_byte_length": candidate.method_pointer_table_byte_length,
        "method_pointers": candidate
            .method_pointers
            .iter()
            .map(method_pointer_value)
            .collect::<Vec<_>>(),
        "disposition": disposition,
        "issues": candidate.issues.iter().map(|issue| serde_json::json!({
            "field": issue.field,
            "reason": issue.reason,
        })).collect::<Vec<_>>(),
        "capture": capture_value(candidate, image, pointer_width, endianness, mappings),
    })
}

/// Build an exact request for the capture decoder only when every required
/// span is uniquely mapped and within the decoder's independent limits.
/// Candidates that cannot satisfy those conditions retain a reason instead of
/// silently turning a discovery guess into a capture.
fn capture_value(
    candidate: &codegen_module_discovery::CodeGenModuleCandidate,
    image: &[u8],
    pointer_width: PointerWidth,
    endianness: Endianness,
    mappings: &[AddressMapping],
) -> Value {
    let unavailable = |reason: &str| {
        serde_json::json!({
            "status": "unavailable",
            "reason": reason,
            "request": Value::Null,
            "spans": Value::Null,
        })
    };

    if candidate.disposition != CandidateDisposition::Valid {
        return unavailable("candidate_is_not_unique_and_valid");
    }
    let width = pointer_width.bytes();
    let Some(record_end) = candidate
        .record_file_offset
        .checked_add(candidate.record_byte_length)
    else {
        return unavailable("record_span_overflow");
    };
    if candidate.record_byte_length > MAX_CAPTURE_RECORD_BYTES
        || record_end > image.len()
        || !span_has_one_mapping(mappings, candidate.record_file_offset, record_end)
    {
        return unavailable("record_span_is_unbounded_or_not_uniquely_mapped");
    }

    let Some(name_offset) = candidate.module_name_file_offset else {
        return unavailable("module_name_span_is_unresolved");
    };
    let Some(name_end) = nul_terminated_end(image, name_offset, MAX_CAPTURE_NAME_BYTES) else {
        return unavailable("module_name_span_is_unbounded");
    };
    if !span_has_one_mapping(mappings, name_offset, name_end) {
        return unavailable("module_name_span_is_not_uniquely_mapped");
    }

    let Some(count) = candidate.method_pointer_count else {
        return unavailable("method_pointer_count_is_unresolved");
    };
    if u64::from(count) > MAX_CAPTURE_POINTERS {
        return unavailable("method_pointer_count_exceeds_capture_limit");
    }
    let pointer_bytes = (count as usize)
        .checked_mul(width)
        .filter(|bytes| *bytes <= MAX_CAPTURE_POINTER_BYTES);
    let Some(pointer_bytes) = pointer_bytes else {
        return unavailable("method_pointer_span_exceeds_capture_limit");
    };
    let pointer_offset = if pointer_bytes == 0 {
        candidate.method_pointer_table_file_offset
    } else {
        let Some(pointer_offset) = candidate.method_pointer_table_file_offset else {
            return unavailable("method_pointer_table_span_is_unresolved");
        };
        Some(pointer_offset)
    };
    let pointer_offset_for_capture = pointer_offset.unwrap_or(0);
    let Some(pointer_end) = pointer_offset_for_capture.checked_add(pointer_bytes) else {
        return unavailable("method_pointer_span_overflow");
    };
    if pointer_end > image.len()
        || (pointer_bytes > 0
            && !span_has_one_mapping(mappings, pointer_offset_for_capture, pointer_end))
    {
        return unavailable("method_pointer_span_is_not_uniquely_mapped");
    }

    let record_virtual = unique_virtual_for_file(mappings, candidate.record_file_offset);
    let name_virtual = unique_virtual_for_file(mappings, name_offset);
    let pointer_virtual =
        pointer_offset.and_then(|offset| unique_virtual_for_file(mappings, offset));
    let Some(record_virtual) = record_virtual else {
        return unavailable("record_virtual_address_is_ambiguous");
    };
    let Some(name_virtual) = name_virtual else {
        return unavailable("module_name_virtual_address_is_ambiguous");
    };
    if pointer_bytes > 0 && pointer_virtual.is_none() {
        return unavailable("method_pointer_virtual_address_is_ambiguous");
    }

    let count_offset = align(width, width);
    let table_offset = align(count_offset + 4, width);
    let request = serde_json::json!({
        "layout": {
            "version": 1,
            "pointer_width": pointer_width.bytes(),
            "endianness": endianness_value(endianness),
            "name_pointer_offset": 0,
            "method_pointer_count_offset": count_offset,
            "method_pointers_offset": table_offset,
        },
        "record_bytes_base64": STANDARD.encode(&image[candidate.record_file_offset..record_end]),
        "name_bytes_base64": STANDARD.encode(&image[name_offset..name_end]),
        "method_pointers_bytes_base64":
            STANDARD.encode(&image[pointer_offset_for_capture..pointer_end]),
        "module_name": candidate.module_name,
    });
    serde_json::json!({
        "status": "ready",
        "reason": Value::Null,
        "request": request,
        "spans": {
            "record": { "file_offset": candidate.record_file_offset, "virtual_address": record_virtual, "byte_length": candidate.record_byte_length },
            "module_name": { "file_offset": name_offset, "virtual_address": name_virtual, "byte_length": name_end - name_offset },
            "method_pointers": { "file_offset": pointer_offset, "virtual_address": pointer_virtual, "byte_length": pointer_bytes },
        },
    })
}

fn align(value: usize, alignment: usize) -> usize {
    let remainder = value % alignment;
    if remainder == 0 {
        value
    } else {
        value + alignment - remainder
    }
}

fn nul_terminated_end(image: &[u8], offset: usize, maximum: usize) -> Option<usize> {
    let end = image.len().min(offset.checked_add(maximum)?);
    let relative = image.get(offset..end)?.iter().position(|byte| *byte == 0)?;
    Some(offset + relative + 1)
}

fn span_has_one_mapping(mappings: &[AddressMapping], start: usize, end: usize) -> bool {
    if start >= end {
        return true;
    }
    let Ok(start) = u64::try_from(start) else {
        return false;
    };
    let Ok(end) = u64::try_from(end) else {
        return false;
    };
    mappings
        .iter()
        .filter(|mapping| mapping.file_start <= start && end <= mapping.file_end)
        .count()
        == 1
}

fn unique_virtual_for_file(mappings: &[AddressMapping], offset: usize) -> Option<u64> {
    let offset = u64::try_from(offset).ok()?;
    let mut result = None;
    for mapping in mappings
        .iter()
        .copied()
        .filter(|mapping| mapping.file_start <= offset && offset < mapping.file_end)
    {
        let address = mapping
            .virtual_start
            .checked_add(offset - mapping.file_start)?;
        if result.is_some() && result != Some(address) {
            return None;
        }
        result = Some(address);
    }
    result
}

fn candidate_disposition_value(disposition: CandidateDisposition) -> &'static str {
    match disposition {
        CandidateDisposition::Valid => "valid",
        CandidateDisposition::Ambiguous => "ambiguous",
        CandidateDisposition::Rejected => "rejected",
    }
}

fn method_pointer_value(observation: &codegen_module_discovery::MethodPointerObservation) -> Value {
    serde_json::json!({
        "index": observation.index,
        "target_virtual_address": observation.target_virtual_address,
        "target_file_offset": observation.target_file_offset,
        "mapping_count": observation.mapping_count,
        "executable_range_matches": observation
            .executable_range_matches
            .iter()
            .copied()
            .map(address_range_value)
            .collect::<Vec<_>>(),
        "disposition": method_pointer_disposition_value(observation.disposition),
    })
}

fn endianness_value(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

fn address_range_value(range: AddressRange) -> Value {
    serde_json::json!({
        "start": range.start,
        "end": range.end,
    })
}

fn method_pointer_disposition_value(
    disposition: codegen_module_discovery::MethodPointerDisposition,
) -> &'static str {
    match disposition {
        codegen_module_discovery::MethodPointerDisposition::Valid => "valid",
        codegen_module_discovery::MethodPointerDisposition::Null => "null",
        codegen_module_discovery::MethodPointerDisposition::Unmapped => "unmapped",
        codegen_module_discovery::MethodPointerDisposition::AmbiguousMapping => "ambiguous_mapping",
        codegen_module_discovery::MethodPointerDisposition::OutsideImage => "outside_image",
        codegen_module_discovery::MethodPointerDisposition::NonExecutable => "non_executable",
    }
}

fn one_text<'a>(
    root: &'a Map<String, Value>,
    keys: &[&str],
    field: &str,
) -> Result<Option<&'a str>, Failure> {
    let mut selected = None;
    for key in keys {
        if let Some(value) = root.get(*key) {
            let text = value
                .as_str()
                .ok_or_else(|| invalid(field, "Expected text"))?;
            if let Some(existing) = selected {
                if existing != text {
                    return Err(invalid(field, "Aliases disagree"));
                }
            } else {
                selected = Some(text);
            }
        }
    }
    Ok(selected)
}

fn selected_value<'a>(
    root: &'a Map<String, Value>,
    keys: &[&str],
    field: &str,
) -> Result<Option<&'a Value>, Failure> {
    let mut selected = None;
    for key in keys {
        if let Some(value) = root.get(*key) {
            if let Some(existing) = selected {
                if existing != value {
                    return Err(invalid(field, "Aliases disagree"));
                }
            } else {
                selected = Some(value);
            }
        }
    }
    Ok(selected)
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("input", &format!("Unexpected field {key}")));
    }
    Ok(())
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, Failure> {
    let value = object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(key, "Expected a non-negative integer"))?;
    if value > MAX_SAFE_INTEGER {
        return Err(invalid(key, "Integer exceeds the safe JSON bound"));
    }
    Ok(value)
}

fn required_u64_at(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
    row: usize,
) -> Result<u64, Failure> {
    let value = object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_row(field, row, &format!("{key} must be a non-negative integer")))?;
    if value > MAX_SAFE_INTEGER {
        return Err(invalid_row(
            field,
            row,
            &format!("{key} exceeds the safe JSON bound"),
        ));
    }
    Ok(value)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("{field}: {reason}"),
        false,
        "Provide bounded image bytes and explicit address evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_row(field: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{field}[{row}]"), reason)
}
