//! Provider projections over the worker's verified source-backed image ranges.
//!
//! The worker owns object-file parsing and FAT slice selection.  These helpers
//! only validate the bounded worker response and project it into the public
//! native route shapes.

use crate::session::Session;
use crate::worker::{Control, Worker};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

const MAX_RANGES: usize = 4096;

struct SourceMapping {
    start: u64,
    end: u64,
    file_offset: Option<u64>,
    initialized: bool,
}

fn source_mappings(
    worker: &Worker,
    control: &Control,
) -> Result<Vec<SourceMapping>, AnalysisError> {
    let reply = worker.request("image_map", json!({}), Some(control))?;
    let object = reply
        .as_object()
        .ok_or_else(|| invalid("image_map reply must be an object"))?;
    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("image_map reply must contain an items array"))?;
    if items.len() > MAX_RANGES {
        return Err(invalid("image_map returned too many ranges"));
    }
    let mut mappings = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let item = item
            .as_object()
            .ok_or_else(|| invalid(&format!("image_map item {index} is not an object")))?;
        mappings.push(parse_mapping(item, index)?);
    }
    Ok(mappings)
}

fn parse_mapping(item: &Map<String, Value>, index: usize) -> Result<SourceMapping, AnalysisError> {
    let start = parse_canonical_address(required_text(item, "start", index)?)?;
    let end = parse_canonical_address(required_text(item, "end", index)?)?;
    if start > end {
        return Err(invalid(&format!(
            "image_map item {index} has reversed bounds"
        )));
    }
    let initialized = item
        .get("initialized")
        .and_then(Value::as_bool)
        .ok_or_else(|| {
            invalid(&format!(
                "image_map item {index} has invalid initialized flag"
            ))
        })?;
    let file_offset =
        match item.get("file_offset") {
            Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                invalid(&format!("image_map item {index} has invalid file offset"))
            })?),
            None => {
                return Err(invalid(&format!(
                    "image_map item {index} has no file offset field"
                )));
            }
        };
    if initialized && file_offset.is_none() {
        return Err(invalid(&format!(
            "image_map item {index} is initialized but has no file offset"
        )));
    }
    if !initialized && file_offset.is_some() {
        return Err(invalid(&format!(
            "image_map item {index} is uninitialized but has a file offset"
        )));
    }
    Ok(SourceMapping {
        start,
        end,
        file_offset,
        initialized,
    })
}

pub(crate) fn address_to_file_offset(
    session: &Session,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Value, AnalysisError> {
    let address = input
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("address_to_file_offset requires address"))?;
    let address_value = parse_address(address)?;
    session.prepare(control)?;
    let mappings = source_mappings(session.worker.as_ref(), control)?;
    let file_offset = resolve_file_offset(&mappings, address_value)?;
    Ok(json!({
        "address": address,
        "file_offset": file_offset,
        "provider_file_offset": file_offset,
    }))
}

fn resolve_file_offset(mappings: &[SourceMapping], address: u64) -> Result<u64, AnalysisError> {
    let matches = mappings
        .iter()
        .filter(|mapping| {
            mapping.initialized
                && mapping.file_offset.is_some()
                && mapping.start <= address
                && address <= mapping.end
        })
        .collect::<Vec<_>>();
    let [mapping] = matches.as_slice() else {
        return Err(invalid(if matches.is_empty() {
            "address is not covered by a source-backed object section"
        } else {
            "address maps to more than one source-backed object section"
        }));
    };
    mapping
        .file_offset
        .ok_or_else(|| invalid("initialized mapping has no file offset"))?
        .checked_add(address - mapping.start)
        .ok_or_else(|| invalid("computed file offset overflows"))
}

fn parse_address(value: &str) -> Result<u64, AnalysisError> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid("address must be hexadecimal"));
    }
    u64::from_str_radix(digits, 16).map_err(|_| invalid("address exceeds u64"))
}

fn parse_canonical_address(value: &str) -> Result<u64, AnalysisError> {
    let parsed = parse_address(value)?;
    if format!("0x{parsed:x}") != value {
        return Err(invalid("worker returned a non-canonical address"));
    }
    Ok(parsed)
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<&'a str, AnalysisError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("image_map item {index} has no {key}")))
}

fn invalid(message: &str) -> AnalysisError {
    AnalysisError::provider_adapter("ghidra-rust", "image_map")
        .with_user_message(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{SourceMapping, parse_mapping, resolve_file_offset};
    use serde_json::json;

    #[test]
    fn maps_selected_fat_slice_to_original_file_offset() {
        let mappings = [SourceMapping {
            start: 0x1000,
            end: 0x10ff,
            file_offset: Some(0x48000),
            initialized: true,
        }];

        assert_eq!(resolve_file_offset(&mappings, 0x1042).unwrap(), 0x48042);
    }

    #[test]
    fn rejects_zero_fill_without_a_file_offset() {
        let mappings = [SourceMapping {
            start: 0x2000,
            end: 0x20ff,
            file_offset: None,
            initialized: false,
        }];

        assert!(resolve_file_offset(&mappings, 0x2042).is_err());
    }

    #[test]
    fn rejects_ambiguous_overlapping_initialized_ranges() {
        let mappings = [
            SourceMapping {
                start: 0x1000,
                end: 0x10ff,
                file_offset: Some(0x4000),
                initialized: true,
            },
            SourceMapping {
                start: 0x1080,
                end: 0x11ff,
                file_offset: Some(0x5000),
                initialized: true,
            },
        ];

        assert!(resolve_file_offset(&mappings, 0x1090).is_err());
    }

    #[test]
    fn rejects_malformed_mapping_types_instead_of_treating_them_as_unknown() {
        let missing_flag = json!({
            "start": "0x1000",
            "end": "0x10ff",
            "file_offset": 0x4000,
        });
        assert!(parse_mapping(missing_flag.as_object().unwrap(), 0).is_err());

        let malformed_offset = json!({
            "start": "0x1000",
            "end": "0x10ff",
            "initialized": true,
            "file_offset": "0x4000",
        });
        assert!(parse_mapping(malformed_offset.as_object().unwrap(), 1).is_err());
    }
}
