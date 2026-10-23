//! Projection of a bounded, caller-captured IL2CPP registration scan.
//!
//! This boundary owns neither a file nor a process.  The caller supplies the
//! captured bytes and the address mappings that explain where those bytes came
//! from.  The scanner reports every plausible root; this projection preserves
//! that ambiguity and adds the source mapping facts needed to interpret each
//! field.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

use crate::il2cpp::registration_scan::{
    self, AddressMapping, Endianness, MAX_INPUT_BYTES, PointerWidth, ScanError, ScanReport,
};

pub const OPERATION: &str = "scan_il2cpp_registration_candidates";
const MAX_MAPPINGS: usize = 65_536;

#[derive(Clone, Copy, Debug)]
struct Mapping {
    address: u64,
    file_offset: usize,
    available_bytes: usize,
}

/// Scan caller-supplied IL2CPP bytes and project the complete report as JSON.
///
/// `bytes_base64`, `metadata_version`, `pointer_width`, `endianness`, and
/// `address_mappings` are all required.  Address mappings are source facts,
/// not discovered file or process mappings, and are only used when the whole
/// requested pointer table fits within one supplied mapping.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    reject_unknown(
        root,
        &[
            "bytes_base64",
            "metadata_version",
            "pointer_width",
            "endianness",
            "address_mappings",
        ],
    )?;

    let metadata_version = required_u64(root, "metadata_version")?;
    let metadata_version = u32::try_from(metadata_version)
        .map_err(|_| invalid("metadata_version", "Metadata version is out of range"))?;
    if !matches!(metadata_version, 29 | 31 | 39) {
        return Err(invalid(
            "metadata_version",
            "Supported versions are 29, 31 and 39",
        ));
    }

    let pointer_width_value = required_u64(root, "pointer_width")?;
    let pointer_width = match pointer_width_value {
        4 => PointerWidth::Bits32,
        8 => PointerWidth::Bits64,
        _ => {
            return Err(invalid(
                "pointer_width",
                "Pointer width must be 4 or 8 bytes",
            ));
        }
    };

    let endianness = root
        .get("endianness")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("endianness", "Endianness is required"))?;
    let endianness_value = match endianness {
        "little" => Endianness::Little,
        "big" => Endianness::Big,
        _ => return Err(invalid("endianness", "Endianness must be little or big")),
    };

    let bytes_text = root
        .get("bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("bytes_base64", "Base64 snapshot bytes are required"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(bytes_text)
        .map_err(|_| invalid("bytes_base64", "Snapshot bytes are not valid base64"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(resource(&format!(
            "Snapshot is {} bytes; maximum is {}",
            bytes.len(),
            MAX_INPUT_BYTES
        )));
    }

    let mappings = parse_mappings(root.get("address_mappings"), bytes.len())?;
    let mapper = |address: u64, size: usize| unique_mapping(mappings.iter(), address, size);

    let report = registration_scan::scan_with_layout(
        &bytes,
        metadata_version,
        pointer_width,
        endianness_value,
        &mapper,
    )
    .map_err(scan_failure)?;
    project_report(
        report,
        &mappings,
        metadata_version,
        pointer_width_value,
        endianness,
        bytes.len(),
    )
}

fn unique_mapping<'a, I>(mappings: I, address: u64, size: usize) -> Option<AddressMapping>
where
    I: IntoIterator<Item = &'a Mapping>,
{
    let mut matches = mappings.into_iter().filter_map(|mapping| {
        let delta = usize::try_from(address.checked_sub(mapping.address)?).ok()?;
        let end = delta.checked_add(size)?;
        if end > mapping.available_bytes {
            return None;
        }
        Some(AddressMapping {
            file_offset: mapping.file_offset.checked_add(delta)?,
            available_bytes: mapping.available_bytes.checked_sub(delta)?,
        })
    });
    let first = matches.next()?;
    matches.next().is_none().then_some(first)
}

fn parse_mappings(value: Option<&Value>, input_bytes: usize) -> Result<Vec<Mapping>, Failure> {
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("address_mappings", "Address mappings must be an array"))?;
    if rows.len() > MAX_MAPPINGS {
        return Err(invalid(
            "address_mappings",
            "Address mapping count exceeds the limit",
        ));
    }

    let mut mappings = Vec::with_capacity(rows.len());
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("address_mappings", row, "Mapping must be an object"))?;
        reject_unknown(object, &["address", "file_offset", "available_bytes"])?;
        let address = required_u64_at(object, "address", "address_mappings", row)?;
        let file_offset = usize_from_u64(object, "file_offset", "address_mappings", row)?;
        let available_bytes = usize_from_u64(object, "available_bytes", "address_mappings", row)?;
        let end = file_offset
            .checked_add(available_bytes)
            .ok_or_else(|| invalid_row("address_mappings", row, "Mapping range overflows"))?;
        if end > input_bytes {
            return Err(invalid_row(
                "address_mappings",
                row,
                "Mapping range exceeds supplied snapshot bytes",
            ));
        }
        mappings.push(Mapping {
            address,
            file_offset,
            available_bytes,
        });
    }
    Ok(mappings)
}

fn project_report(
    report: ScanReport,
    mappings: &[Mapping],
    metadata_version: u32,
    pointer_width: u64,
    endianness: &str,
    snapshot_bytes: usize,
) -> Result<Value, Failure> {
    let coverage_complete = !report
        .limitations
        .iter()
        .any(|limitation| limitation.starts_with("The candidate limit was reached"));
    let candidates = report
        .candidates
        .iter()
        .map(|candidate| {
            let fields = candidate
                .fields
                .iter()
                .map(|field| {
                    let source = mapping_for_pointer(mappings, field.pointer, field.required_bytes);
                    json!({
                        "index": field.index,
                        "count": field.count,
                        "pointer": field.pointer,
                        "pointer_file_offset": field.pointer_file_offset,
                        "required_bytes": field.required_bytes,
                        "valid": field.valid,
                        "source": source,
                        "method_pointers": field.method_pointers.iter().map(|method_pointer| json!({
                            "index": method_pointer.index,
                            "pointer": method_pointer.pointer,
                            "source_file_offset": method_pointer.source_file_offset,
                            "target_file_offset": method_pointer.target_file_offset,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "root_file_offset": candidate.root_file_offset,
                "metadata_version": metadata_version,
                "state": state_name(candidate.state),
                "validated_fields": candidate.validated_fields,
                "fields": fields,
                "evidence": candidate.evidence,
            })
        })
        .collect::<Vec<_>>();

    let mut states = Vec::new();
    for candidate in &report.candidates {
        let state = state_name(candidate.state);
        if !states.contains(&state) {
            states.push(state);
        }
    }

    Ok(json!({
        "operation": OPERATION,
        "metadata_version": metadata_version,
        "pointer_width": pointer_width,
        "endianness": endianness,
        "snapshot_bytes": snapshot_bytes,
        "address_mappings": mappings.iter().map(mapping_value).collect::<Vec<_>>(),
        "candidates": candidates,
        "coverage": {
            "candidate_count": report.candidates.len(),
            "candidate_selection": candidate_selection(report.candidates.len()),
            "states": states,
            "bytes_examined": snapshot_bytes,
            "mappings_examined": mappings.len(),
            "complete": coverage_complete,
        },
        "limitations": report.limitations,
    }))
}

fn candidate_selection(candidate_count: usize) -> &'static str {
    match candidate_count {
        0 => "no_observation",
        1 => "unique_observation",
        _ => "ambiguous_observation",
    }
}

fn mapping_for_pointer(mappings: &[Mapping], pointer: u64, required_bytes: usize) -> Value {
    let mapped = mappings.iter().filter_map(|mapping| {
        let delta = usize::try_from(pointer.checked_sub(mapping.address)?).ok()?;
        let end = delta.checked_add(required_bytes)?;
        if end > mapping.available_bytes {
            return None;
        }
        Some(json!({
            "address": pointer,
            "base_address": mapping.address,
            "file_offset": mapping.file_offset.checked_add(delta),
            "available_bytes": mapping.available_bytes - delta,
        }))
    });
    let mut mapped = mapped;
    let first = mapped.next();
    if mapped.next().is_some() {
        Value::Null
    } else {
        first.unwrap_or(Value::Null)
    }
}

fn mapping_value(mapping: &Mapping) -> Value {
    json!({
        "address": mapping.address,
        "file_offset": mapping.file_offset,
        "available_bytes": mapping.available_bytes,
    })
}

fn state_name(state: registration_scan::ValidationState) -> &'static str {
    match state {
        registration_scan::ValidationState::Validated => "validated",
        registration_scan::ValidationState::Ambiguous => "ambiguous",
        registration_scan::ValidationState::Rejected => "rejected",
    }
}

fn scan_failure(error: ScanError) -> Failure {
    match error {
        ScanError::InputTooLarge { actual, maximum } => {
            resource(&format!("Snapshot is {actual} bytes; maximum is {maximum}"))
        }
        ScanError::UnsupportedMetadataVersion(version) => invalid(
            "metadata_version",
            &format!("Unsupported metadata version {version}"),
        ),
    }
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

fn usize_from_u64(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
    row: usize,
) -> Result<usize, Failure> {
    usize::try_from(required_u64_at(object, key, field, row)?)
        .map_err(|_| invalid_row(field, row, &format!("{key} is outside the platform range")))
}

fn invalid(field: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("{field}: {message}"),
        false,
        "provide a bounded snapshot and explicit mappings".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_row(field: &str, row: usize, message: &str) -> Failure {
    invalid(&format!("{field}[{row}]"), message)
}

fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_limit",
        "resource",
        message.to_string(),
        false,
        "reduce the captured snapshot".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
