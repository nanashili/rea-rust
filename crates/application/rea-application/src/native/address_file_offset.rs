//! Offline projection from retained native load-image mappings to file offsets.
//!
//! The provider owns address normalization. This module only consumes the
//! provider's already-normalized address and mapping facts; it never opens a
//! database or consults live process state.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "address_to_file_offset";
const MAX_MAPPINGS: usize = 200_000;

/// Resolve one address against supplied load-image mappings.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let address_text = required_text(object, "address")?;
    let address = parse_address(address_text)?;
    let address_space = object.get("address_space").and_then(Value::as_str);
    let mappings = object
        .get("mappings")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("mappings", "Expected an array"))?;
    if mappings.len() > MAX_MAPPINGS {
        return Err(invalid(
            "mappings",
            "Collection exceeds the address mapping limit",
        ));
    }

    let mut candidates = Vec::new();
    for (index, value) in mappings.iter().enumerate() {
        let mapping = value
            .as_object()
            .ok_or_else(|| invalid("mappings", &format!("mappings[{index}] must be an object")))?;
        let candidate = parse_mapping(mapping, index)?;
        if address_space.is_some_and(|space| candidate.address_space != space) {
            continue;
        }
        if candidate.is_file_backed() && candidate.contains(address) {
            candidates.push(candidate);
        }
    }

    let partial = partial_observation(object);
    let selected = match candidates.as_slice() {
        [] => {
            return Err(unmapped(
                partial,
                "The address is not covered by any supplied mapping",
            ));
        }
        [candidate] => candidate,
        _ => return Err(ambiguous(partial, candidates.len())),
    };
    let file_offset = selected
        .file_offset
        .ok_or_else(|| {
            invalid(
                "mappings.file_offset",
                "File-backed mapping has no file offset",
            )
        })?
        .checked_add(address - selected.start)
        .ok_or_else(|| invalid("mappings.file_offset", "Computed file offset overflows u64"))?;

    let mut result = Map::new();
    result.insert("address".into(), Value::String(address_text.into()));
    result.insert("file_offset".into(), Value::from(file_offset));
    if let Some(source_path) = object.get("source_path") {
        result.insert("source_path".into(), source_path.clone());
    }
    if let Some(provider_file_offset) = object.get("provider_file_offset") {
        result.insert("provider_file_offset".into(), provider_file_offset.clone());
    }
    if let Some(image_base_file_offset) = object.get("image_base_file_offset") {
        result.insert(
            "image_base_file_offset".into(),
            image_base_file_offset.clone(),
        );
    }
    Ok(Value::Object(result))
}

#[derive(Clone)]
struct Mapping {
    address_space: String,
    start: u64,
    end: u64,
    file_offset: Option<u64>,
    initialized: bool,
    loaded: bool,
    overlay: bool,
}

impl Mapping {
    fn contains(&self, address: u64) -> bool {
        address >= self.start && address <= self.end
    }

    fn is_file_backed(&self) -> bool {
        self.initialized && self.loaded && !self.overlay && self.file_offset.is_some()
    }
}

fn parse_mapping(mapping: &Map<String, Value>, index: usize) -> Result<Mapping, Failure> {
    let address_space = required_text(mapping, "address_space")?.to_owned();
    let start = parse_address(required_text(mapping, "start")?)?;
    let end = parse_address(required_text(mapping, "end")?)?;
    if end < start {
        return Err(invalid(
            "mappings",
            &format!("mappings[{index}] has an empty or reversed range"),
        ));
    }
    let file_offset = match mapping.get("file_offset") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_u64().ok_or_else(|| {
            invalid(
                "mappings.file_offset",
                "Expected a non-negative integer or null",
            )
        })?),
    };
    let initialized = required_boolean(mapping, "initialized")?;
    let loaded = required_boolean(mapping, "loaded")?;
    let overlay = required_boolean(mapping, "overlay")?;
    Ok(Mapping {
        address_space,
        start,
        end,
        file_offset,
        initialized,
        loaded,
        overlay,
    })
}

fn partial_observation(input: &Map<String, Value>) -> Value {
    let mut partial = Map::new();
    for key in [
        "address",
        "provider_file_offset",
        "provider_source_path",
        "provider_image_header_hex",
    ] {
        if let Some(value) = input.get(key) {
            partial.insert(key.into(), value.clone());
        }
    }
    Value::Object(partial)
}

fn required_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(key, "Expected non-empty text"))
}

fn required_boolean(object: &Map<String, Value>, key: &str) -> Result<bool, Failure> {
    object
        .get(key)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(key, "Expected a boolean"))
}

fn parse_address(value: &str) -> Result<u64, Failure> {
    let digits = value.strip_prefix("0x").ok_or_else(|| {
        invalid(
            "address",
            "Expected a lowercase 0x-prefixed hexadecimal address",
        )
    })?;
    if digits.is_empty()
        || !digits
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(
            "address",
            "Expected a lowercase 0x-prefixed hexadecimal address",
        ));
    }
    u64::from_str_radix(digits, 16).map_err(|_| invalid("address", "Address exceeds u64"))
}

fn unmapped(partial: Value, reason: &str) -> Failure {
    failure("unmapped", reason, partial)
}
fn ambiguous(partial: Value, count: usize) -> Failure {
    failure(
        "ambiguous",
        &format!("Address matches {count} supplied mappings"),
        partial,
    )
}
fn failure(code: &'static str, reason: &str, partial: Value) -> Failure {
    let mut details = BTreeMap::from([
        ("operation", Detail::Text(OPERATION.into())),
        ("reason", Detail::Text(reason.into())),
    ]);
    details.insert(
        "partial_observation",
        Detail::Raw(
            serde_json::value::to_raw_value(&partial).expect("Value serialization cannot fail"),
        ),
    );
    Failure::new(
        code,
        code,
        reason.into(),
        false,
        "Supply one unambiguous, address-covered mapping and retry.".into(),
        details,
    )
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Address-to-file-offset input is invalid.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text(field.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
