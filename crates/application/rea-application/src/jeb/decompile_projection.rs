//! Projection of one already-returned JEB decompilation.
//!
//! The JEB adapter owns the MCP call and the engine's interpretation of the
//! item.  This module only validates the captured success facts and preserves
//! them for the native application boundary.  It never opens a project,
//! contacts JEB, or attempts to interpret the returned pseudo-code.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "decompile_jeb_item";

const MAX_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_UNIT_PATH_BYTES: usize = 16 * 1024;
const MAX_ITEM_ADDRESS_BYTES: usize = 16 * 1024;
const MAX_TEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_LINES: usize = 1_000_000;

/// Engine provenance captured by the JEB adapter.
///
/// `None` is intentional: JEB may not report a version, and that omission is
/// not evidence that the engine is unversioned.  The endpoint remains the
/// caller-selected identity of the serving client.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineProvenance {
    pub name: String,
    pub version: Option<String>,
    pub endpoint: String,
    pub gui_client: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ItemKind {
    Type,
    Method,
}

/// Captured facts for one successful `decompile_code_item` response.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DecompileJebItemInput {
    pub engine: EngineProvenance,
    pub unit_path: Option<String>,
    pub item_address: String,
    pub item_kind: ItemKind,
    pub text: String,
}

/// Portable native projection.  It deliberately has the same field identity
/// as the JEB tool result, including an unknown effective unit path when the
/// caller omitted that selector.
pub type DecompileJebItem = DecompileJebItemInput;

/// Validate captured JEB decompiler facts without changing their spelling.
pub fn normalize(input: DecompileJebItemInput) -> Result<DecompileJebItem, Failure> {
    validate_engine(&input.engine)?;
    validate_optional_text(input.unit_path.as_deref(), MAX_UNIT_PATH_BYTES, "unit_path")?;
    validate_required_text(&input.item_address, MAX_ITEM_ADDRESS_BYTES, "item_address")?;
    validate_decompiled_text(&input.text)?;
    Ok(input)
}

/// Parse and project a JSON value already returned by the provider adapter.
pub fn normalize_value(input: &Value) -> Result<Value, Failure> {
    let parsed: DecompileJebItemInput = serde_json::from_value(input.clone())
        .map_err(|error| invalid(&format!("invalid JEB decompilation facts: {error}")))?;
    serde_json::to_value(normalize(parsed)?)
        .map_err(|_| invalid("JEB decompilation projection is not serializable"))
}

/// Validate a captured result while retaining no duplicate interpretation.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let _ = normalize_value(input)?;
    Ok(())
}

/// Return one authenticated retained JEB decompilation Evidence record.
///
/// The public handler accepts Evidence only.  It does not reconstruct a
/// provider execution from caller-supplied fields, and it returns the whole
/// record so limitations, raw output, and provenance remain available to the
/// caller.
pub fn decompile_jeb_item(input: &Value) -> Result<Value, Failure> {
    let input_object = input
        .as_object()
        .ok_or_else(|| invalid("decompile_jeb_item input must be an object"))?;
    if input_object.keys().any(|key| key != "evidence") {
        return Err(invalid("decompile_jeb_item accepts retained Evidence only"));
    }
    let evidence = input_object
        .get("evidence")
        .ok_or_else(|| invalid("decompile_jeb_item requires retained Evidence"))?;
    let evidence_object = evidence
        .as_object()
        .ok_or_else(|| invalid("JEB decompilation Evidence must be an object"))?;

    if evidence_object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid("Evidence operation is not decompile_jeb_item"));
    }
    if evidence_object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid(
            "JEB decompilation Evidence must include evidence_id",
        ));
    }
    validate_provider(evidence_object.get("provider"))?;

    validate_limitations(evidence_object.get("limitations"))?;

    let result = evidence_object
        .get("normalized_result")
        .ok_or_else(|| invalid("JEB decompilation Evidence has no normalized_result"))?;
    let parsed: DecompileJebItemInput = serde_json::from_value(result.clone())
        .map_err(|error| invalid(&format!("invalid JEB decompilation result: {error}")))?;
    normalize(parsed)?;

    Ok(evidence.clone())
}

fn validate_provider(provider: Option<&Value>) -> Result<(), Failure> {
    let provider = provider
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("JEB decompilation Evidence must include provider identity"))?;
    if provider.get("id").and_then(Value::as_str) != Some("jeb") {
        return Err(invalid("JEB decompilation Evidence provider id is not jeb"));
    }
    if provider
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid(
            "JEB decompilation Evidence provider name is missing",
        ));
    }
    let version = provider
        .get("version")
        .ok_or_else(|| invalid("JEB decompilation Evidence provider version is missing"))?;
    if !version.is_null() && version.as_str().is_none() {
        return Err(invalid(
            "JEB decompilation Evidence provider version is invalid",
        ));
    }
    Ok(())
}

fn validate_engine(engine: &EngineProvenance) -> Result<(), Failure> {
    if engine.name != "jeb" {
        return Err(invalid("JEB decompilation engine provenance must name JEB"));
    }
    validate_required_text(&engine.endpoint, MAX_ENDPOINT_BYTES, "engine.endpoint")
}

fn validate_limitations(value: Option<&Value>) -> Result<(), Failure> {
    let limitations = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("JEB decompilation Evidence limitations must be an array"))?;
    if limitations.len() > MAX_LINES {
        return Err(resource(
            "JEB decompilation Evidence limitations exceed the item limit",
        ));
    }
    for limitation in limitations {
        let text = limitation
            .as_str()
            .ok_or_else(|| invalid("JEB decompilation Evidence limitations must contain text"))?;
        if text.len() > MAX_ITEM_ADDRESS_BYTES {
            return Err(resource(
                "JEB decompilation Evidence limitation exceeds its byte limit",
            ));
        }
    }
    Ok(())
}

fn validate_required_text(value: &str, max_bytes: usize, field: &str) -> Result<(), Failure> {
    if value.is_empty() {
        return Err(invalid(&format!("{field} must be non-empty")));
    }
    if value.len() > max_bytes {
        return Err(resource(&format!("{field} exceeds its byte limit")));
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    max_bytes: usize,
    field: &str,
) -> Result<(), Failure> {
    if let Some(value) = value {
        validate_required_text(value, max_bytes, field)?;
    }
    Ok(())
}

fn validate_decompiled_text(text: &str) -> Result<(), Failure> {
    if text.len() > MAX_TEXT_BYTES {
        return Err(resource("decompiled text exceeds the 16 MiB byte limit"));
    }
    if text.lines().count() > MAX_LINES {
        return Err(resource("decompiled text exceeds the line limit"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the successful, bounded JEB decompilation facts returned by the selected engine."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Request a smaller JEB decompilation result or increase the native output bound.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
