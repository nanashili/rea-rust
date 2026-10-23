//! Application boundary for one captured JEB item decompilation.
//!
//! The JEB adapter owns the MCP request, project state, and interpretation of
//! the engine response.  This producer only authenticates the captured result
//! and returns its exact JSON representation.  In particular, it does not
//! resolve an item, regenerate text, or infer a language from the output.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "decompile_jeb_item";

const MAX_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINE_COUNT: usize = 1_000_000;
const MAX_ID_BYTES: usize = 16 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_LIMITATIONS: usize = 4_096;

/// Validate a request that carries a provider-captured JEB decompilation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let result = selected_result(input)?;
    validate_result(result)
}

/// Return the captured result without changing provider spelling or identity.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    Ok(selected_result(input)?.clone())
}

/// Validate a provider result before the caller wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

/// Project one captured `decompile_jeb_item` Evidence record.
///
/// The Evidence envelope is the authority for operation identity and the
/// normalized result remains the provider's exact JSON value.  This function
/// deliberately does not resolve a project, unit, method, or JEB endpoint.
pub fn decompile_jeb_item(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid("decompile_jeb_item requires captured Evidence"))?;
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("decompile_jeb_item Evidence must be an object"))?;
    if object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid("decompile_jeb_item Evidence has the wrong operation"));
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("decompile_jeb_item Evidence requires evidence_id"));
    }
    validate_provider(object.get("provider"))?;
    validate_limitations(object.get("limitations"))?;
    let result = object
        .get("normalized_result")
        .ok_or_else(|| invalid("decompile_jeb_item Evidence is missing normalized_result"))?;
    validate_result(result)?;
    Ok(result.clone())
}

fn validate_provider(value: Option<&Value>) -> Result<(), Failure> {
    let provider = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("decompile_jeb_item Evidence requires provider identity"))?;
    if provider.get("id").and_then(Value::as_str) != Some("jeb") {
        return Err(invalid("decompile_jeb_item Evidence provider id is not jeb"));
    }
    let name = provider
        .get("name")
        .ok_or_else(|| invalid("decompile_jeb_item Evidence provider name is required"))?;
    bounded_text(Some(name), MAX_ID_BYTES, "provider.name", false)?;
    let version = provider
        .get("version")
        .ok_or_else(|| invalid("decompile_jeb_item Evidence provider version is required"))?;
    if !version.is_null() && version.as_str().is_none() {
        return Err(invalid(
            "decompile_jeb_item Evidence provider version must be text or null",
        ));
    }
    if let Some(version) = version.as_str() {
        if version.len() > MAX_ID_BYTES {
            return Err(resource(
                "decompile_jeb_item Evidence provider version exceeds its byte limit",
            ));
        }
    }
    Ok(())
}

fn selected_result(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("JEB item decompilation input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        return evidence_result(evidence);
    }
    if let Some(result) = object.get("result") {
        return Ok(result);
    }
    if let Some(result) = object.get("decompilation") {
        return Ok(result);
    }
    Err(invalid(
        "JEB item decompilation requires a captured result or Evidence",
    ))
}

fn evidence_result(evidence: &Value) -> Result<&Value, Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("JEB item decompilation Evidence must be an object"))?;
    if let Some(operation) = object.get("operation")
        && operation.as_str() != Some(OPERATION)
    {
        return Err(invalid(
            "JEB item decompilation Evidence has the wrong operation",
        ));
    }
    object
        .get("normalized_result")
        .or_else(|| object.get("result"))
        .or_else(|| object.get("value"))
        .ok_or_else(|| invalid("JEB item decompilation Evidence is missing its result"))
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("JEB item decompilation result must be an object"))?;
    let encoded = serde_json::to_vec(result)
        .map_err(|_| invalid("JEB item decompilation result is not serializable"))?;
    if encoded.len() > MAX_CAPTURE_BYTES {
        return Err(resource("JEB item decompilation exceeds the 16 MiB capture limit"));
    }

    // The provider contract always emits these five fields.  Keep optional
    // diagnostics below, but do not accept an untyped error envelope as a
    // successful decompilation observation.
    validate_engine(object.get("engine"))?;
    validate_identity(object)?;
    validate_text_field(object.get("text"))?;
    validate_item_kind(object.get("item_kind"))?;
    validate_language(object.get("language"))?;
    validate_errors(object)?;
    validate_session_generation(object.get("session_generation"))?;
    validate_provenance(object.get("provenance"))?;
    validate_coverage(object.get("coverage"))?;
    validate_limitations(object.get("limitations"))?;

    Ok(())
}

fn validate_engine(value: Option<&Value>) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid("JEB engine provenance is required"))?;
    let engine = value
        .as_object()
        .ok_or_else(|| invalid("JEB engine provenance must be an object"))?;
    if engine.get("name").and_then(Value::as_str) != Some("jeb") {
        return Err(invalid("JEB engine provenance must name JEB"));
    }
    let version = engine
        .get("version")
        .ok_or_else(|| invalid("JEB engine.version is required"))?;
    bounded_text(Some(version), MAX_ID_BYTES, "engine.version", true)?;
    let endpoint = engine
        .get("endpoint")
        .ok_or_else(|| invalid("JEB engine.endpoint is required"))?;
    bounded_text(Some(endpoint), MAX_ID_BYTES, "engine.endpoint", false)?;
    let gui_client = engine
        .get("gui_client")
        .ok_or_else(|| invalid("JEB engine.gui_client is required"))?;
    if !gui_client.is_null() && gui_client.as_bool().is_none() {
        return Err(invalid("engine.gui_client must be a boolean or null"));
    }
    Ok(())
}

fn validate_identity(object: &Map<String, Value>) -> Result<(), Failure> {
    let unit_path = object
        .get("unit_path")
        .ok_or_else(|| invalid("JEB unit_path is required"))?;
    bounded_text(
        Some(unit_path),
        MAX_ID_BYTES,
        "unit_path",
        true,
    )?;
    let item_address = object
        .get("item_address")
        .ok_or_else(|| invalid("JEB item_address is required"))?;
    bounded_text(
        Some(item_address),
        MAX_ID_BYTES,
        "item_address",
        false,
    )?;
    Ok(())
}

fn validate_item_kind(value: Option<&Value>) -> Result<(), Failure> {
    match value.and_then(Value::as_str) {
        Some("type" | "method") => Ok(()),
        Some(_) => Err(invalid("JEB item_kind must be type or method")),
        None => Err(invalid("JEB item_kind is required")),
    }
}

fn validate_text_field(value: Option<&Value>) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid("JEB decompilation text is required"))?;
    let text = value
        .as_str()
        .ok_or_else(|| invalid("JEB decompilation output must be text"))?;
    if text.len() > MAX_TEXT_BYTES {
        return Err(resource("JEB decompilation output exceeds the 16 MiB limit"));
    }
    if text.lines().count() > MAX_LINE_COUNT {
        return Err(resource("JEB decompilation output exceeds the line limit"));
    }
    Ok(())
}

fn validate_language(value: Option<&Value>) -> Result<(), Failure> {
    bounded_text(value, MAX_ID_BYTES, "language", true)
}

fn validate_errors(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["error", "error_message"] {
        bounded_text(object.get(field), MAX_ERROR_BYTES, field, true)?;
    }
    if let Some(errors) = object.get("errors") {
        let values = errors
            .as_array()
            .ok_or_else(|| invalid("JEB decompilation errors must be an array"))?;
        if values.len() > MAX_LIMITATIONS {
            return Err(resource("JEB decompilation errors exceed the item limit"));
        }
        for error in values {
            let text = error
                .as_str()
                .ok_or_else(|| invalid("JEB decompilation errors must contain text"))?;
            if text.len() > MAX_ERROR_BYTES {
                return Err(resource("JEB decompilation error exceeds the byte limit"));
            }
        }
    }
    Ok(())
}

fn validate_session_generation(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.as_u64().is_none() && value.as_str().is_none() {
        return Err(invalid(
            "JEB session_generation must be a non-negative integer or text",
        ));
    }
    if let Some(text) = value.as_str() {
        if text.is_empty() {
            return Err(invalid("session_generation text must be non-empty"));
        }
        if text.len() > MAX_ID_BYTES {
            return Err(resource("session_generation exceeds its byte limit"));
        }
    }
    Ok(())
}

fn validate_provenance(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    if !value.is_object() && !value.is_array() && !value.is_string() {
        return Err(invalid("JEB provenance must be an object, array, or text"));
    }
    Ok(())
}

fn validate_coverage(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        Value::String(status) if status == "complete" || status == "partial" => Ok(()),
        Value::Object(object) => {
            let status = object.get("status").and_then(Value::as_str);
            if status.is_some_and(|status| matches!(status, "complete" | "partial")) {
                Ok(())
            } else {
                Err(invalid("JEB coverage status must be complete or partial"))
            }
        }
        _ => Err(invalid("JEB coverage must be a status or coverage object")),
    }
}

fn validate_limitations(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid("JEB limitations must be an array"))?;
    if values.len() > MAX_LIMITATIONS {
        return Err(resource("JEB limitations exceed the item limit"));
    }
    for limitation in values {
        let text = limitation
            .as_str()
            .ok_or_else(|| invalid("JEB limitations must contain text"))?;
        if text.len() > MAX_ERROR_BYTES {
            return Err(resource("JEB limitation exceeds the byte limit"));
        }
    }
    Ok(())
}

fn bounded_text(
    value: Option<&Value>,
    max_bytes: usize,
    field: &str,
    nullable: bool,
) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_null() && nullable {
        return Ok(());
    }
    let text = value
        .as_str()
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be non-empty text or null")))?;
    if text.len() > max_bytes {
        return Err(resource(&format!("{field} exceeds its byte limit")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a captured, bounded JEB item decompilation result and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Request a smaller JEB item decompilation result and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
