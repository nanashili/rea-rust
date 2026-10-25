//! Validation and projection for one worker-decoded instruction.

use crate::analysis::Read;
use crate::session::Session;
use crate::worker::Control;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value};

fn object<'a>(
    value: &'a Value,
    invalid: &dyn Fn() -> AnalysisError,
) -> Result<&'a Map<String, Value>, AnalysisError> {
    value.as_object().ok_or_else(invalid)
}

fn canonical_address(value: &str) -> Option<String> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    (!digits.is_empty()
        && digits.len() <= 16
        && digits.bytes().all(|byte| byte.is_ascii_hexdigit()))
    .then(|| u64::from_str_radix(digits, 16).ok())
    .flatten()
    .map(|value| format!("0x{value:x}"))
}

fn text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    invalid: &dyn Fn() -> AnalysisError,
) -> Result<&'a str, AnalysisError> {
    object.get(key).and_then(Value::as_str).ok_or_else(invalid)
}

fn optional_text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    invalid: &dyn Fn() -> AnalysisError,
) -> Result<Option<&'a str>, AnalysisError> {
    match object.get(key) {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        _ => Err(invalid()),
    }
}

fn validate_flow(value: &Value, invalid: &dyn Fn() -> AnalysisError) -> Result<(), AnalysisError> {
    let flow = object(value, invalid)?;
    let kind = text(flow, "kind", invalid)?;
    if !matches!(
        kind,
        "call" | "jump" | "return" | "fallthrough" | "terminal" | "unavailable"
    ) {
        return Err(invalid());
    }
    for key in ["conditional", "computed"] {
        if !flow.get(key).and_then(Value::as_bool).is_some() {
            return Err(invalid());
        }
    }
    let destinations = flow
        .get("direct_destinations")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if destinations.iter().any(|item| item.as_str().is_none()) {
        return Err(invalid());
    }
    let evidence = flow
        .get("classification_evidence")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    for item in evidence {
        let item = object(item, invalid)?;
        text(item, "source", invalid)?;
        text(item, "value", invalid)?;
    }
    if let Some(limitations) = flow.get("limitations") {
        let limitations = limitations.as_array().ok_or_else(invalid)?;
        if limitations.iter().any(|item| item.as_str().is_none()) {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_references(
    value: &Value,
    invalid: &dyn Fn() -> AnalysisError,
) -> Result<(), AnalysisError> {
    let references = value.as_array().ok_or_else(invalid)?;
    for reference in references {
        let reference = object(reference, invalid)?;
        text(reference, "target_address", invalid)?;
        text(reference, "type", invalid)?;
        text(reference, "provenance", invalid)?;
        text(reference, "source", invalid)?;
        if reference.get("operand_index").and_then(Value::as_i64) != Some(-1) {
            return Err(invalid());
        }
        for key in [
            "call", "jump", "indirect", "computed", "data", "read", "write",
        ] {
            if reference.get(key).and_then(Value::as_bool).is_none() {
                return Err(invalid());
            }
        }
        match reference.get("primary") {
            Some(Value::Null | Value::Bool(_)) => {}
            _ => return Err(invalid()),
        }
        optional_text(reference, "source_address", invalid)?;
    }
    Ok(())
}

fn validate(result: &Value, invalid: &dyn Fn() -> AnalysisError) -> Result<(), AnalysisError> {
    let result = object(result, invalid)?;
    text(result, "address", invalid)?;
    let status = text(result, "status", invalid)?;
    if !matches!(
        status,
        "decoded" | "not-instruction-boundary" | "undecodable" | "data" | "outside-memory"
    ) {
        return Err(invalid());
    }
    optional_text(result, "procedure", invalid)?;
    text(result, "architecture", invalid)?;
    text(result, "mode", invalid)?;
    let decoder_context = result
        .get("decoder_context")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    for item in decoder_context {
        let item = object(item, invalid)?;
        text(item, "register", invalid)?;
        optional_text(item, "value", invalid)?;
        text(item, "source", invalid)?;
    }
    let bytes = optional_text(result, "bytes", invalid)?;
    let length = result.get("length").and_then(Value::as_u64);
    if result
        .get("length")
        .map_or(true, |value| value.as_u64().is_none() && !value.is_null())
    {
        return Err(invalid());
    }
    match (bytes, length) {
        (Some(bytes), Some(length)) => {
            let encoded_length = usize::try_from(length)
                .ok()
                .and_then(|length| length.checked_mul(2));
            if length == 0
                || encoded_length != Some(bytes.len())
                || !bytes
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(invalid());
            }
        }
        (None, None) if status != "decoded" => {}
        _ => return Err(invalid()),
    }
    optional_text(result, "mnemonic", invalid)?;
    optional_text(result, "raw_disassembly", invalid)?;
    result
        .get("operands")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    validate_flow(result.get("flow").ok_or_else(invalid)?, invalid)?;
    validate_references(result.get("references").ok_or_else(invalid)?, invalid)?;
    match result.get("incoming_references") {
        Some(Value::Null | Value::Array(_)) => {}
        _ => return Err(invalid()),
    }
    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    if limitations.iter().any(|item| item.as_str().is_none()) {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn inspect(
    session: &Session,
    input: &Map<String, Value>,
    control: &Control,
) -> Result<Read, AnalysisError> {
    session.prepare(control)?;
    let address = input
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| session.failure("The instruction address is required."))?;
    let requested = canonical_address(address)
        .ok_or_else(|| session.failure("The instruction address must be hexadecimal."))?;
    let reply = session.worker.request(
        "inspect_instruction",
        serde_json::json!({ "address": requested }),
        Some(control),
    )?;
    let invalid =
        || session.failure("The Ghidra worker returned an invalid instruction observation.");
    validate(&reply, &invalid)?;
    if reply.get("address").and_then(Value::as_str) != Some(requested.as_str()) {
        return Err(invalid());
    }
    Ok(Read {
        result: reply,
        relationship_coverage: None,
        references_truncated: None,
    })
}

#[cfg(test)]
mod tests {
    use super::validate;
    use rea_core::analysis_error::AnalysisError;
    use serde_json::json;

    #[test]
    fn rejects_missing_inconsistent_and_overflowing_decoded_bytes() {
        let mut observation = json!({
            "address": "0x1000",
            "status": "decoded",
            "procedure": null,
            "architecture": "x86:LE:64:default",
            "mode": "unknown",
            "decoder_context": [],
            "bytes": "90",
            "length": 1,
            "mnemonic": "NOP",
            "raw_disassembly": "NOP",
            "operands": [],
            "flow": {
                "kind": "fallthrough",
                "conditional": false,
                "computed": false,
                "direct_destinations": [],
                "classification_evidence": []
            },
            "references": [],
            "incoming_references": null,
            "limitations": []
        });
        let invalid = || AnalysisError::provider_adapter("ghidra-rust", "inspect_instruction");
        assert!(validate(&observation, &invalid).is_ok());

        for (bytes, length) in [
            (json!(null), json!(null)),
            (json!("90"), json!(null)),
            (json!(""), json!(0)),
            (json!("90"), json!(2)),
            (json!("90"), json!(u64::MAX)),
            (json!("zz"), json!(1)),
        ] {
            observation["bytes"] = bytes;
            observation["length"] = length;
            assert!(validate(&observation, &invalid).is_err());
        }
    }
}
