//! Public captured-only adapter for `inspect_binary_layout`.
//!
//! The adapter accepts either a caller-supplied bounded ELF snapshot or an
//! already retained Evidence record. It never opens a path, launches a
//! target, invokes an external provider, or mutates the selected artifact.

use rea_core::{evidence::record::EvidenceRecord, failure::{Detail, Failure}};
use rea_rust_analysis::{binary_layout, managed};
use serde_json::{json, Map, Value};
use std::{collections::BTreeMap, path::Path};

pub const OPERATION: &str = "inspect_binary_layout";
const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Dispatch the public operation using only inline bytes or retained Evidence.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(unknown_operation(operation));
    }

    project(&input)
}

/// Inspect inline bytes or replay one retained layout Evidence record.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("inspect_binary_layout input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        return replay_evidence(evidence);
    }

    if object.contains_key("bytes_base64") || object.contains_key("bytes") {
        return inspect_bytes(object);
    }

    if object.contains_key("result") || object.contains_key("normalized_result") {
        return replay_result(object);
    }

    Err(invalid(
        "inspect_binary_layout requires bytes, result, normalized_result, or evidence",
    ))
}

fn inspect_bytes(object: &Map<String, Value>) -> Result<Value, Failure> {
    reject_unknown_fields(object, &["path", "bytes_base64", "bytes"])?;
    let path = required_path(object)?;
    let bytes = decode_bytes(object)?;
    let digest = managed::digest(&bytes);
    let layout = binary_layout::read(&bytes).map_err(|error| parse_failure(&path, error))?;
    let mut result = serde_json::to_value(layout)
        .map_err(|error| execution_failure(&path, error.to_string()))?;
    project_public_layout(&mut result, &path)?;
    let result_object = result
        .as_object_mut()
        .ok_or_else(|| execution_failure(&path, "layout is not an object".into()))?;
    result_object.insert(
        "artifact".into(),
        json!({"path": path, "sha256": digest, "bytes": bytes.len()}),
    );
    result_object.insert(
        "diagnostics".into(),
        json!({"stdout": "", "stderr": "", "truncated": false}),
    );
    result_object.insert("limitations".into(), json!(limitations()));
    ensure_output_size(&result, &path)?;

    Ok(json!({
        "result": result,
        "provenance": {
            "operation": OPERATION,
            "source": "caller-supplied-artifact-bytes",
            "execution": "none"
        }
    }))
}

fn replay_evidence(evidence: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("Evidence is not serializable: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&format!("Evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("Evidence operation does not match inspect_binary_layout"));
    }

    let mut result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is invalid JSON: {error}")))?;
    project_public_layout(&mut result, "<retained-evidence>").map_err(|_| {
        integrity("retained Evidence layout does not match the public result contract")
    })?;
    validate_retained_result(&result)?;

    Ok(json!({
        "result": result,
        "evidence_id": record.evidence_id(),
        "provenance": {
            "operation": OPERATION,
            "source": "authenticated-retained-evidence",
            "execution": "unknown"
        }
    }))
}

fn replay_result(object: &Map<String, Value>) -> Result<Value, Failure> {
    let result = object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .ok_or_else(|| invalid("retained layout result is required"))?;
    let mut projected = result.clone();
    project_public_layout(&mut projected, "<retained-result>")?;
    validate_retained_result(&projected)?;

    Ok(json!({
        "result": projected,
        "provenance": {
            "operation": OPERATION,
            "source": "caller-supplied-retained-result",
            "execution": "unknown"
        }
    }))
}

/// Keep the public result aligned with the strict TypeScript contract. The
/// native parser retains additional ELF facts for future projections; those
/// facts must not silently widen this operation's declared result.
fn project_public_layout(result: &mut Value, path: &str) -> Result<(), Failure> {
    let object = result
        .as_object_mut()
        .ok_or_else(|| execution_failure(path, "layout is not an object".into()))?;
    retain_keys(
        object,
        &[
            "format",
            "architecture",
            "image_type",
            "entry_point",
            "runtime_load_base",
            "sections",
            "segments",
            "symbols",
            "relocations",
            "packed_relative_relocations",
            "relocation_inventory_completeness",
            "linkage",
            "mitigations",
        ],
    );
    let supported_architecture = object
        .get("architecture")
        .and_then(Value::as_object)
        .map(|architecture| {
            architecture.get("machine").and_then(Value::as_str) == Some("EM_X86_64")
                && architecture.get("bits").and_then(Value::as_u64) == Some(64)
                && architecture.get("byte_order").and_then(Value::as_str) == Some("little")
        })
        .ok_or_else(|| execution_failure(path, "layout architecture is missing".into()))?;
    if !supported_architecture {
        return Err(Failure::new(
            "unsupported_target",
            "unsupported_target",
            "inspect_binary_layout requires little-endian ELF64 x86-64 input".into(),
            false,
            "Select a supported ELF64 x86-64 snapshot and retry.".into(),
            details(),
        ));
    }
    if let Some(values) = object.get_mut("sections").and_then(Value::as_array_mut) {
        for value in values {
            if let Some(section) = value.as_object_mut() {
                retain_keys(section, &["index", "name", "name_offset", "type", "header_location", "address", "offset", "size", "alignment", "flags", "link", "info", "entry_size", "file_backing"]);
                retain_name(section.get_mut("name"));
            }
        }
    }
    if let Some(values) = object.get_mut("segments").and_then(Value::as_array_mut) {
        for value in values {
            if let Some(segment) = value.as_object_mut() {
                retain_keys(segment, &["index", "type", "header_location", "offset", "file_size", "memory_size", "virtual_address", "physical_address", "alignment", "flags", "file_backing", "permissions"]);
            }
        }
    }
    if let Some(values) = object.get_mut("symbols").and_then(Value::as_array_mut) {
        for value in values {
            if let Some(symbol) = value.as_object_mut() {
                retain_keys(symbol, &["table_index", "entry_index", "name", "name_offset", "location", "value", "value_meaning", "size", "binding", "type", "visibility", "section_index"]);
                retain_name(symbol.get_mut("name"));
            }
        }
    }
    if let Some(values) = object.get_mut("relocations").and_then(Value::as_array_mut) {
        for value in values {
            if let Some(relocation) = value.as_object_mut() {
                retain_keys(relocation, &["section_index", "entry_index", "reported_offset", "target", "location", "type", "symbol_table_index", "symbol_index", "symbol_reference_meaning", "addend"]);
            }
        }
    }
    if let Some(values) = object.get_mut("packed_relative_relocations").and_then(Value::as_array_mut) {
        for value in values {
            if let Some(table) = value.as_object_mut() {
                retain_keys(table, &["section_index", "location", "encoded_bytes_base64", "entries", "offset_meaning", "evidence_kind", "entry_source_locations", "addends"]);
            }
        }
    }
    if let Some(linkage) = object.get_mut("linkage").and_then(Value::as_object_mut) {
        retain_keys(linkage, &["needed_libraries", "interpreters", "got", "plt", "convenience_maps_completeness", "runtime_library_paths"]);
        for field in ["needed_libraries", "interpreters"] {
            if let Some(values) = linkage.get_mut(field).and_then(Value::as_array_mut) {
                for value in values { retain_name(Some(value)); }
            }
        }
    }
    Ok(())
}

fn retain_keys(object: &mut Map<String, Value>, allowed: &[&str]) {
    object.retain(|key, _| allowed.iter().any(|candidate| *candidate == key));
}

fn retain_name(value: Option<&mut Value>) {
    if let Some(value) = value.and_then(Value::as_object_mut) {
        retain_keys(value, &["display", "bytes_base64", "location", "unknown_reason"]);
    }
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object.keys().find(|field| !allowed.iter().any(|candidate| candidate == field)) {
        return Err(invalid(&format!("unexpected inspect_binary_layout field: {field}")));
    }
    Ok(())
}

fn validate_retained_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("retained layout result must be an object"))?;
    let artifact = object
        .get("artifact")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("retained layout result requires artifact identity"))?;
    required_non_empty_text(artifact, "path")?;
    let digest = required_non_empty_text(artifact, "sha256")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("retained artifact sha256 must be a hexadecimal digest"));
    }
    if artifact.get("bytes").and_then(Value::as_u64).is_none() {
        return Err(invalid("retained artifact bytes must be a non-negative integer"));
    }
    Ok(())
}

fn decode_bytes(object: &Map<String, Value>) -> Result<Vec<u8>, Failure> {
    match (object.get("bytes_base64"), object.get("bytes")) {
        (Some(Value::String(encoded)), None) => decode_base64(encoded),
        (None, Some(Value::Array(values))) => {
            if values.len() > MAX_INPUT_BYTES {
                return Err(resource_failure("inline bytes exceed the ELF input limit"));
            }
            values
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .filter(|byte| *byte <= u8::MAX as u64)
                        .map(|byte| byte as u8)
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| invalid("bytes must contain integers from 0 through 255"))
        }
        (Some(_), Some(_)) => Err(invalid("supply only one byte representation")),
        (Some(_), None) => Err(invalid("bytes_base64 must be a string")),
        (None, None) => Err(invalid("bytes_base64 or bytes is required")),
    }
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, Failure> {
    if encoded.len() > ((MAX_INPUT_BYTES + 2) / 3) * 4 || encoded.len() % 4 != 0 {
        return Err(resource_failure("bytes_base64 exceeds the ELF input limit"));
    }

    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    let quartets = encoded.as_bytes().chunks_exact(4);
    let quartet_count = quartets.len();
    for (position, quartet) in quartets.enumerate() {
        let padding = usize::from(quartet[3] == b'=') + usize::from(quartet[2] == b'=');
        let values = [
            base64_value(quartet[0])?,
            base64_value(quartet[1])?,
            if quartet[2] == b'=' { 0 } else { base64_value(quartet[2])? },
            if quartet[3] == b'=' { 0 } else { base64_value(quartet[3])? },
        ];
        if quartet[0] == b'=' || quartet[1] == b'=' || (quartet[2] == b'=' && quartet[3] != b'=') {
            return Err(invalid("bytes_base64 has invalid padding"));
        }
        if (padding == 2 && values[1] & 0x0f != 0)
            || (padding == 1 && values[2] & 0x03 != 0)
        {
            return Err(invalid("bytes_base64 is not canonical"));
        }
        if padding > 0 && position + 1 != quartet_count {
            return Err(invalid("bytes_base64 has padding before the final quartet"));
        }
        output.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 { output.push((values[1] << 4) | (values[2] >> 2)); }
        if padding == 0 { output.push((values[2] << 6) | values[3]); }
    }
    if output.len() > MAX_INPUT_BYTES {
        return Err(resource_failure("decoded bytes exceed the ELF input limit"));
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, Failure> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(invalid("bytes_base64 contains a non-base64 character")),
    }
}

fn required_path(object: &Map<String, Value>) -> Result<String, Failure> {
    let path = required_non_empty_text(object, "path")?.to_owned();
    if !Path::new(&path).is_absolute() || path.contains('\0') {
        return Err(invalid("path must be an absolute filesystem path without NUL bytes"));
    }
    Ok(path)
}

fn required_non_empty_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn limitations() -> Vec<&'static str> {
    vec![
        "This profile inspects ELF EXEC/DYN/REL layout only. It does not launch the target, resolve loaded libraries, or establish runtime behavior.",
        "Names include source ranges where resolvable; relocation inventory completeness and convenience linkage maps remain unknown.",
        "Mitigation values are inferred static indicators and do not prove runtime protection coverage.",
    ]
}

fn ensure_output_size(result: &Value, path: &str) -> Result<(), Failure> {
    let bytes = serde_json::to_vec(result)
        .map_err(|error| execution_failure(path, error.to_string()))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(resource_failure("complete ELF layout exceeds the output limit"));
    }
    Ok(())
}

fn parse_failure(path: &str, error: binary_layout::Error) -> Failure {
    match error {
        binary_layout::Error::InputLimit => resource_failure("ELF input exceeds the input limit"),
        binary_layout::Error::Unsupported(reason) => Failure::new(
            "unsupported_target", "unsupported_target", format!("Unsupported ELF target at {path}: {reason}"),
            false, "Select a supported ELF target and retry.".into(), details(),
        ),
        binary_layout::Error::Format(reason) => Failure::new(
            "analysis_input", "invalid_format", reason.into(), false,
            "Provide a valid ELF snapshot and retry.".into(), details(),
        ),
        binary_layout::Error::Message(reason) => Failure::new(
            "analysis_input", "invalid_format", reason, false,
            "Provide a valid ELF snapshot and retry.".into(), details(),
        ),
    }
}

fn details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", Detail::Text(OPERATION.into()))])
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new(
        "invalid_request", "invalid_input", format!("Binary layout operation is unknown: {operation}"),
        false, "Select inspect_binary_layout with a supplied artifact or retained Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request", "invalid_input", reason.into(), false,
        "Provide a bounded ELF snapshot or authenticated retained layout Evidence.".into(), details(),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure", "integrity_failure", reason.into(), false,
        "Provide intact retained Evidence for inspect_binary_layout.".into(), details(),
    )
}

fn execution_failure(path: &str, reason: String) -> Failure {
    let mut fields = details();
    fields.insert("path", Detail::Text(path.into()));
    Failure::new(
        "execution_failure",
        "execution_failure",
        reason,
        false,
        "Review the reported details.".into(),
        fields,
    )
}

fn resource_failure(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint", "resource_constraint", reason.into(), false,
        "Provide a smaller ELF snapshot or request a bounded retained result.".into(), details(),
    )
}
