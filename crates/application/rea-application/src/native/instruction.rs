//! Read-only projection and validation for one native instruction observation.
//!
//! Instruction bytes are decoded by the provider boundary (for example the
//! Ghidra bridge).  This module deliberately consumes authenticated Evidence
//! rather than opening a database or interpreting executable bytes.  Keeping
//! that ownership explicit prevents the application layer from turning a
//! missing decoder fact into a guessed instruction.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeSet;

pub const OPERATION: &str = "inspect_native_instruction";

const TOP_LEVEL_FIELDS: &[&str] = &[
    "evidence",
    "instruction",
    "native_observation",
    "address",
    "document",
];

/// Validate a caller-selected instruction observation and optional selector.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native instruction input must be an object"))?;
    reject_unknown_fields(object, TOP_LEVEL_FIELDS, "native instruction input")?;

    let evidence = object
        .get("evidence")
        .or_else(|| object.get("instruction"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("native instruction Evidence is required"))?;
    validate_evidence(evidence)?;

    if let Some(address) = object.get("address") {
        require_non_empty_string(address, "address")?;
        if !is_ghidra_input_address(address.as_str().unwrap_or_default()) {
            return Err(invalid(
                "address must be hexadecimal or an encoded address-space hexadecimal value",
            ));
        }
        let retained = instruction_result(evidence)?
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("native instruction result must include address"))?;
        if address.as_str() != Some(retained) {
            return Err(invalid("address does not match retained instruction"));
        }
    }
    if let Some(document) = object.get("document") {
        if !document.is_null() {
            require_non_empty_string(document, "document")?;
        }
    }
    Ok(())
}

/// Match the Ghidra adapter's caller-address grammar without normalizing the
/// caller's spelling.  Canonical provider addresses remain owned by the
/// retained result; this check only constrains a newly supplied selector.
fn is_ghidra_input_address(value: &str) -> bool {
    if is_hex_address(value) {
        return true;
    }

    let Some((space, address)) = value.rsplit_once(':') else {
        return false;
    };
    !space.is_empty()
        && is_encoded_address_space(space)
        && address.len() > 2
        && (address.starts_with("0x") || address.starts_with("0X"))
        && address[2..]
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn is_hex_address(value: &str) -> bool {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    !digits.is_empty()
        && digits
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit())
}

fn is_encoded_address_space(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
            index += 1;
            continue;
        }
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            index += 3;
            continue;
        }
        return false;
    }
    true
}

/// Validate and return a provider result for retention by the runtime adapter.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

/// Project the authenticated instruction result without contacting a provider.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let evidence = input
        .as_object()
        .and_then(|object| {
            object
                .get("evidence")
                .or_else(|| object.get("instruction"))
                .or_else(|| object.get("native_observation"))
        })
        .ok_or_else(|| invalid("native instruction Evidence is required"))?;
    Ok(instruction_result(evidence)?.clone())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("native instruction Evidence must be an object"))?;
    if let Some(operation) = object.get("operation") {
        if operation.as_str() != Some(OPERATION) {
            return Err(invalid(
                "Evidence operation is not inspect_native_instruction",
            ));
        }
    }
    let evidence_id = object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty());
    if evidence_id.is_none() {
        return Err(invalid(
            "native instruction Evidence must include evidence_id",
        ));
    }
    let result = instruction_result(evidence)?;
    validate_result(result)
}

fn instruction_result(evidence: &Value) -> Result<&Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("instruction"))
        .unwrap_or(evidence);
    if !result.is_object() {
        return Err(invalid(
            "native instruction Evidence must contain an object result",
        ));
    }
    Ok(result)
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("native instruction result must be an object"))?;
    let fields = [
        "address",
        "status",
        "procedure",
        "architecture",
        "mode",
        "decoder_context",
        "bytes",
        "length",
        "mnemonic",
        "raw_disassembly",
        "operands",
        "flow",
        "references",
        "incoming_references",
        "limitations",
    ];
    reject_unknown_fields(object, &fields, "native instruction result")?;
    require_string_field(object, "address")?;
    require_enum(
        object,
        "status",
        &[
            "decoded",
            "not-instruction-boundary",
            "data",
            "undecodable",
            "outside-memory",
        ],
    )?;
    require_nullable_string_field(object, "procedure")?;
    require_string_field(object, "architecture")?;
    require_string_field(object, "mode")?;
    if let Some(context) = object.get("decoder_context") {
        validate_decoder_context(context)?;
    }
    validate_nullable_string_field(object, "bytes")?;
    validate_positive_integer_or_null(object, "length")?;
    validate_nullable_string_field(object, "mnemonic")?;
    validate_nullable_string_field(object, "raw_disassembly")?;
    validate_operands(object.get("operands"))?;
    validate_flow(object.get("flow"))?;
    validate_references(object.get("references"), "references")?;
    if let Some(incoming) = object.get("incoming_references") {
        if !incoming.is_null() {
            validate_references(Some(incoming), "incoming_references")?;
        }
    }
    validate_string_array(object.get("limitations"), "limitations")
}

fn validate_decoder_context(value: &Value) -> Result<(), Failure> {
    let entries = value
        .as_array()
        .ok_or_else(|| invalid("decoder_context must be an array"))?;
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid("decoder_context entry must be an object"))?;
        reject_unknown_fields(
            object,
            &["register", "value", "source"],
            "decoder_context entry",
        )?;
        require_non_empty_string_field(object, "register")?;
        require_nullable_non_empty_string_field(object, "value")?;
        require_non_empty_string_field(object, "source")?;
    }
    Ok(())
}

fn validate_operands(value: Option<&Value>) -> Result<(), Failure> {
    let operands = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("operands must be an array"))?;
    for operand in operands {
        let object = operand
            .as_object()
            .ok_or_else(|| invalid("operand must be an object"))?;
        reject_unknown_fields(
            object,
            &[
                "index",
                "raw",
                "provider_type",
                "components",
                "memory_addressing",
            ],
            "operand",
        )?;
        require_non_negative_integer_field(object, "index")?;
        require_string_field(object, "raw")?;
        require_integer_field(object, "provider_type")?;
        if object.get("memory_addressing").and_then(Value::as_str) != Some("unavailable") {
            return Err(invalid("memory_addressing must be unavailable"));
        }
        let components = object
            .get("components")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("operand components must be an array"))?;
        for component in components {
            let component = component
                .as_object()
                .ok_or_else(|| invalid("operand component must be an object"))?;
            reject_unknown_fields(
                component,
                &["kind", "text", "value", "bit_width"],
                "operand component",
            )?;
            require_enum(
                component,
                "kind",
                &["register", "immediate", "address", "unknown"],
            )?;
            require_string_field(component, "text")?;
            require_nullable_string_field(component, "value")?;
            validate_non_negative_integer_or_null(component, "bit_width")?;
        }
    }
    Ok(())
}

fn validate_flow(value: Option<&Value>) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("flow must be an object"))?;
    reject_unknown_fields(
        object,
        &[
            "kind",
            "conditional",
            "computed",
            "direct_destinations",
            "classification_evidence",
        ],
        "flow",
    )?;
    require_enum(
        object,
        "kind",
        &[
            "call",
            "jump",
            "return",
            "fallthrough",
            "terminal",
            "unavailable",
        ],
    )?;
    require_bool_field(object, "conditional")?;
    require_bool_field(object, "computed")?;
    validate_string_array(object.get("direct_destinations"), "direct_destinations")?;
    if let Some(evidence) = object.get("classification_evidence") {
        let entries = evidence
            .as_array()
            .ok_or_else(|| invalid("classification_evidence must be an array"))?;
        for entry in entries {
            let entry = entry
                .as_object()
                .ok_or_else(|| invalid("classification evidence must be an object"))?;
            reject_unknown_fields(entry, &["source", "value"], "classification evidence")?;
            require_non_empty_string_field(entry, "source")?;
            require_non_empty_string_field(entry, "value")?;
        }
    }
    Ok(())
}

fn validate_references(value: Option<&Value>, name: &str) -> Result<(), Failure> {
    let references = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{name} must be an array")))?;
    for reference in references {
        let object = reference
            .as_object()
            .ok_or_else(|| invalid("native reference must be an object"))?;
        reject_unknown_fields(
            object,
            &[
                "target_address",
                "type",
                "call",
                "jump",
                "indirect",
                "computed",
                "operand_index",
                "source_address",
                "data",
                "read",
                "write",
                "primary",
                "provenance",
                "source",
            ],
            "native reference",
        )?;
        require_string_field(object, "target_address")?;
        require_string_field(object, "type")?;
        for field in ["call", "jump", "indirect", "computed"] {
            require_bool_field(object, field)?;
        }
        require_integer_field(object, "operand_index")?;
        require_nullable_non_empty_string_field(object, "source_address")?;
        for field in ["data", "read", "write", "primary"] {
            validate_nullable_bool(object, field)?;
        }
        for field in ["provenance", "source"] {
            require_nullable_non_empty_string_field(object, field)?;
        }
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), Failure> {
    let allowed: BTreeSet<&str> = allowed.iter().copied().collect();
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(invalid(&format!("{label} contains unknown field {field}")));
    }
    Ok(())
}

fn require_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_str).is_none() {
        return Err(invalid(&format!("{field} must be a string")));
    }
    Ok(())
}

fn require_non_empty_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    let value = object
        .get(field)
        .ok_or_else(|| invalid(&format!("{field} is required")))?;
    require_non_empty_string(value, field)
}

fn require_non_empty_string(value: &Value, field: &str) -> Result<(), Failure> {
    if value.as_str().is_none_or(str::is_empty) {
        return Err(invalid(&format!("{field} must be a non-empty string")));
    }
    Ok(())
}

fn require_nullable_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    match object.get(field) {
        Some(value) if value.is_null() || value.is_string() => Ok(()),
        Some(_) => Err(invalid(&format!("{field} must be a string or null"))),
        None => Err(invalid(&format!("{field} is required"))),
    }
}
fn require_nullable_non_empty_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if object.get(field).is_none_or(Value::is_null) {
        return Ok(());
    }
    match object.get(field) {
        Some(value) => require_non_empty_string(value, field),
        None => Ok(()),
    }
}
fn validate_nullable_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    require_nullable_string_field(object, field)
}

fn require_bool_field(object: &serde_json::Map<String, Value>, field: &str) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_bool).is_none() {
        return Err(invalid(&format!("{field} must be a boolean")));
    }
    Ok(())
}

fn validate_nullable_bool(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if object
        .get(field)
        .is_none_or(|value| value.is_null() || value.is_boolean())
    {
        return Ok(());
    }
    Err(invalid(&format!("{field} must be a boolean or null")))
}

fn require_integer_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_i64).is_none() {
        return Err(invalid(&format!("{field} must be an integer")));
    }
    Ok(())
}

fn require_non_negative_integer_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_i64)
        .is_none_or(|value| value < 0)
    {
        return Err(invalid(&format!("{field} must be a non-negative integer")));
    }
    Ok(())
}

fn validate_positive_integer_or_null(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    let value = object
        .get(field)
        .ok_or_else(|| invalid(&format!("{field} is required")))?;
    if value.is_null() || value.as_i64().is_some_and(|number| number > 0) {
        return Ok(());
    }
    Err(invalid(&format!(
        "{field} must be a positive integer or null"
    )))
}

fn validate_non_negative_integer_or_null(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if object
        .get(field)
        .is_none_or(|value| value.is_null() || value.as_i64().is_some_and(|number| number >= 0))
    {
        return Ok(());
    }
    Err(invalid(&format!(
        "{field} must be a non-negative integer or null"
    )))
}

fn validate_string_array(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values.iter().any(|value| value.as_str().is_none()) {
        return Err(invalid(&format!("{field} must contain strings")));
    }
    Ok(())
}

fn require_enum(
    object: &serde_json::Map<String, Value>,
    field: &str,
    values: &[&str],
) -> Result<(), Failure> {
    let value = object.get(field).and_then(Value::as_str);
    if value.is_none_or(|value| !values.contains(&value)) {
        return Err(invalid(&format!("{field} has an invalid value")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated inspect_native_instruction Evidence and preserve static uncertainty.".into(),
        std::collections::BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
