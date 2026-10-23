//! Read-only projection and validation for a provider's loaded native image.
//!
//! The provider owns image loading and relocation measurement.  This module
//! intentionally accepts those measured facts as input and only enforces the
//! public `inspect_native_load_image` contract.  It never opens a database,
//! executes an image, or turns a missing value into a guessed address.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_native_load_image";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Validate and project a provider result supplied directly by an adapter.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let value = input
        .get("result")
        .or_else(|| input.get("normalized_result"))
        .or_else(|| input.get("observations"))
        .unwrap_or(input);

    project(value)
}

/// Validate a complete native load-image result without changing its shape.
pub fn project(value: &Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("result", "Expected an object"))?;

    match object.get("status").and_then(Value::as_str) {
        Some("unsupported") => validate_unsupported(object)?,
        Some("verified") | Some("mismatch") => validate_supported(object)?,
        _ => {
            return Err(invalid(
                "status",
                "Expected unsupported, verified, or mismatch",
            ));
        }
    }

    Ok(value.clone())
}

/// Validate a measured provider observation before wrapping it in Evidence.
pub fn validate_observations(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("observations", "Expected an object"))?;
    required_text(object, "executable_format")?;
    required_text(object, "language_id")?;
    required_text(object, "compiler_spec_id")?;
    required_text(object, "image_base")?;
    required_text(object, "default_address_space")?;

    let source_files = array(object, "source_files")?;
    bounded(source_files, "source_files")?;
    for (index, source) in source_files.iter().enumerate() {
        let source = source_object(source, "source_files", index)?;
        // The TypeScript contract preserves an empty source name as a fact.
        required_text_value(source, "name", "source_files")?;
        non_negative_integer(source, "size", "source_files")?;
        digest(
            source.get("original_sha256"),
            "source_files.original_sha256",
        )?;
        digest(
            source.get("modified_sha256"),
            "source_files.modified_sha256",
        )?;
    }

    let mappings = array(object, "mappings")?;
    bounded(mappings, "mappings")?;
    for (index, mapping) in mappings.iter().enumerate() {
        let mapping = source_object(mapping, "mappings", index)?;
        for key in ["block", "start", "end", "address_space"] {
            required_string(mapping, key, "mappings")?;
        }
        required_boolean(mapping, "initialized", "mappings")?;
        required_boolean(mapping, "loaded", "mappings")?;
        required_boolean(mapping, "overlay", "mappings")?;
        positive_integer(mapping, "length", "mappings")?;
        nullable_integer(
            mapping.get("source_file_index"),
            "mappings.source_file_index",
        )?;
        nullable_integer(mapping.get("file_offset"), "mappings.file_offset")?;
        nullable_digest(mapping.get("sha256"), "mappings.sha256")?;
    }

    let relocations = array(object, "relocations")?;
    bounded(relocations, "relocations")?;
    for (index, relocation) in relocations.iter().enumerate() {
        let relocation = source_object(relocation, "relocations", index)?;
        required_string(relocation, "address", "relocations")?;
        nullable_bounded_integer(relocation.get("segment"), "relocations.segment", 0xffff)?;
        nullable_bounded_integer(relocation.get("offset"), "relocations.offset", 0xffff)?;
        required_string(relocation, "status", "relocations")?;
        required_integer(relocation, "type", "relocations")?;
        let values = array(relocation, "values")?;
        bounded(values, "relocations.values")?;
        for value in values {
            if !is_safe_integer(value) {
                return Err(invalid("relocations.values", "Expected an integer"));
            }
        }
        nullable_hex(
            relocation.get("original_bytes_hex"),
            "relocations.original_bytes_hex",
        )?;
        nullable_hex(
            relocation.get("memory_bytes_hex"),
            "relocations.memory_bytes_hex",
        )?;
    }

    validate_addresses(array(object, "entry_points")?, "entry_points")?;
    let contexts = array(object, "entry_context")?;
    bounded(contexts, "entry_context")?;
    for (index, context) in contexts.iter().enumerate() {
        let context = source_object(context, "entry_context", index)?;
        required_string(context, "address", "entry_context")?;
        let registers = array(context, "registers")?;
        bounded(registers, "entry_context.registers")?;
        for (register_index, register) in registers.iter().enumerate() {
            let register = source_object(register, "entry_context.registers", register_index)?;
            required_string(register, "name", "entry_context.registers")?;
            nullable_hex_prefixed(register.get("value_hex"), "entry_context.value_hex")?;
        }
    }

    if let Some(metadata) = object.get("metadata_recovery") {
        let metadata = metadata
            .as_array()
            .ok_or_else(|| invalid("metadata_recovery", "Expected an array"))?;
        bounded(metadata, "metadata_recovery")?;
    }

    Ok(())
}

fn validate_unsupported(object: &Map<String, Value>) -> Result<(), Failure> {
    required_string(object, "reason", "result")?;
    validate_observations(required(object, "observations")?)?;
    strings_array(object, "limitations")
}

fn validate_supported(object: &Map<String, Value>) -> Result<(), Failure> {
    let format = required_string(object, "format", "result")?;
    if format != "dos-mz" && format != "dos-com" && format != "raw-binary" {
        return Err(invalid("format", "Expected dos-mz, dos-com, or raw-binary"));
    }
    digest(object.get("target_sha256"), "target_sha256")?;
    validate_observations(required(object, "observations")?)?;
    let checks = array(object, "checks")?;
    bounded(checks, "checks")?;
    for (index, check) in checks.iter().enumerate() {
        let check = source_object(check, "checks", index)?;
        required_string(check, "name", "checks")?;
        required_boolean(check, "matched", "checks")?;
        if !check.contains_key("expected") || !check.contains_key("observed") {
            return Err(invalid(
                "checks",
                "Each check needs expected and observed values",
            ));
        }
        nullable_integer(check.get("file_offset"), "checks.file_offset")?;
        nullable_string(check.get("address"), "checks.address")?;
    }
    strings_array(object, "limitations")?;

    match format {
        "dos-mz" | "dos-com" => {
            bounded_integer(object, "load_segment", 0xffff)?;
            non_negative_integer(object, "header_bytes", "result")?;
            non_negative_integer(object, "module_bytes", "result")?;
            non_negative_integer(object, "overlay_bytes", "result")?;
            let entry = object_value(object, "entry")?;
            bounded_integer(entry, "relative_segment", 0xffff)?;
            bounded_integer(entry, "offset", 0xffff)?;
            required_string(entry, "linear_address", "entry")?;
        }
        "raw-binary" => {
            let architecture = required(object, "architecture")?;
            if architecture
                .as_str()
                .is_some_and(|value| !is_supported_architecture(value))
                || !architecture.is_string()
            {
                return Err(invalid("architecture", "Expected a supported architecture"));
            }
            required_string(object, "language_id", "result")?;
            required_string(object, "compiler_spec_id", "result")?;
            required_string(object, "base_address", "result")?;
            positive_integer(object, "file_bytes", "result")?;
            let entry = object_value(object, "entry")?;
            required_string(entry, "address", "entry")?;
            if entry.get("file_offset") != Some(&Value::from(0)) {
                return Err(invalid(
                    "entry.file_offset",
                    "Raw-binary entry file_offset must be zero",
                ));
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

fn array<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Vec<Value>, Failure> {
    object
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(key, "Expected an array"))
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, Failure> {
    object
        .get(key)
        .ok_or_else(|| invalid(key, "Missing required value"))
}

fn object_value<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    required(object, key)?
        .as_object()
        .ok_or_else(|| invalid(key, "Expected an object"))
}

fn source_object<'a>(
    value: &'a Value,
    field: &str,
    index: usize,
) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid(field, &format!("{field}[{index}] must be an object")))
}

fn required_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    required_string(object, key, "observations")
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(field, &format!("{key} must be non-empty text")))
}

fn required_text_value<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field, &format!("{key} must be text")))
}

fn is_safe_integer(value: &Value) -> bool {
    value
        .as_i64()
        .is_some_and(|number| number.unsigned_abs() <= MAX_SAFE_INTEGER)
        || value
            .as_u64()
            .is_some_and(|number| number <= MAX_SAFE_INTEGER)
}

fn is_supported_architecture(value: &str) -> bool {
    matches!(value, "x86" | "x86_64" | "arm" | "arm64" | "6502" | "m68k")
}

fn nullable_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_null() && value.as_str().is_none()) {
        return Err(invalid(field, "Expected text or null"));
    }
    Ok(())
}

fn required_boolean(object: &Map<String, Value>, key: &str, field: &str) -> Result<(), Failure> {
    if object.get(key).and_then(Value::as_bool).is_none() {
        return Err(invalid(field, &format!("{key} must be boolean")));
    }
    Ok(())
}

fn required_integer(object: &Map<String, Value>, key: &str, field: &str) -> Result<(), Failure> {
    if object.get(key).and_then(Value::as_i64).is_none() {
        return Err(invalid(field, &format!("{key} must be an integer")));
    }
    Ok(())
}

fn non_negative_integer(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<(), Failure> {
    if object
        .get(key)
        .and_then(Value::as_u64)
        .is_none_or(|value| value > MAX_SAFE_INTEGER)
    {
        return Err(invalid(
            field,
            &format!("{key} must be a non-negative integer"),
        ));
    }
    Ok(())
}

fn positive_integer(object: &Map<String, Value>, key: &str, field: &str) -> Result<(), Failure> {
    if object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0 && *value <= MAX_SAFE_INTEGER)
        .is_none()
    {
        return Err(invalid(field, &format!("{key} must be positive")));
    }
    Ok(())
}

fn bounded_integer(object: &Map<String, Value>, key: &str, max: u64) -> Result<(), Failure> {
    if object
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value <= max)
        .is_none()
    {
        return Err(invalid(key, "Integer is outside its declared range"));
    }
    Ok(())
}

fn nullable_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| {
        !value.is_null()
            && (!value.is_u64()
                || value
                    .as_u64()
                    .is_some_and(|number| number > MAX_SAFE_INTEGER))
    }) {
        return Err(invalid(field, "Expected a non-negative integer or null"));
    }
    Ok(())
}

fn nullable_bounded_integer(value: Option<&Value>, field: &str, max: u64) -> Result<(), Failure> {
    nullable_integer(value, field)?;
    if value
        .and_then(Value::as_u64)
        .is_some_and(|number| number > max)
    {
        return Err(invalid(field, "Integer is outside its declared range"));
    }
    Ok(())
}

fn digest(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(field, "Expected a SHA-256 digest"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(field, "Expected a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn nullable_digest(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_null()) {
        digest(value, field)?;
    }
    Ok(())
}

fn nullable_hex(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value.filter(|value| !value.is_null()) {
        let text = value
            .as_str()
            .ok_or_else(|| invalid(field, "Expected hexadecimal text or null"))?;
        if text.len() % 2 != 0
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid(field, "Expected lowercase hexadecimal bytes"));
        }
    }
    Ok(())
}

fn nullable_hex_prefixed(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value.filter(|value| !value.is_null()) {
        let text = value
            .as_str()
            .ok_or_else(|| invalid(field, "Expected hexadecimal text or null"))?;
        if !text.starts_with("0x")
            || text.len() < 3
            || !text[2..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid(
                field,
                "Expected a lowercase 0x-prefixed hexadecimal value",
            ));
        }
    }
    Ok(())
}

fn validate_addresses(values: &Vec<Value>, field: &str) -> Result<(), Failure> {
    bounded(values, field)?;
    for value in values {
        if value.as_str().is_none_or(str::is_empty) {
            return Err(invalid(field, "Expected non-empty address strings"));
        }
    }
    Ok(())
}

fn strings_array(object: &Map<String, Value>, key: &str) -> Result<(), Failure> {
    let values = array(object, key)?;
    bounded(values, key)?;
    if values
        .iter()
        .any(|value| value.as_str().is_none_or(str::is_empty))
    {
        return Err(invalid(key, "Expected non-empty strings"));
    }
    Ok(())
}

fn bounded(values: &[Value], field: &str) -> Result<(), Failure> {
    if values.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the native load-image limit",
        ));
    }
    Ok(())
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Native load-image input is invalid.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text(field.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
