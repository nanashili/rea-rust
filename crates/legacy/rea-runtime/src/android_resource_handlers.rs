//! Offline dispatch for retained Android and Apktool observations.
//!
//! The runtime owns transport and presentation.  This adapter intentionally
//! accepts captured package/report data only: it never opens an APK, contacts
//! ADB, invokes Apktool, or resolves a launcher from the environment.

use rea_application::{android, apktool};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const DECODE_OPERATION: &str = "decode_android_resources";
pub const MANIFEST_OPERATION: &str = "inspect_android_manifest_component";
pub const RESOURCE_OPERATION: &str = "inspect_android_resource";
pub const APKTOOL_CLIENT_OPERATION: &str = "inspect_apktool_client";

/// Captured-only operations in the Android resource family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AndroidResourceOperation {
    Decode,
    ManifestComponent,
    Resource,
    ApktoolClient,
}

impl AndroidResourceOperation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            DECODE_OPERATION => Ok(Self::Decode),
            MANIFEST_OPERATION => Ok(Self::ManifestComponent),
            RESOURCE_OPERATION => Ok(Self::Resource),
            APKTOOL_CLIENT_OPERATION => Ok(Self::ApktoolClient),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Decode => DECODE_OPERATION,
            Self::ManifestComponent => MANIFEST_OPERATION,
            Self::Resource => RESOURCE_OPERATION,
            Self::ApktoolClient => APKTOOL_CLIENT_OPERATION,
        }
    }
}

/// Dispatch one captured operation by its public name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    dispatch_typed(AndroidResourceOperation::parse(operation)?, &input)
}

/// Dispatch a previously parsed operation without reinterpreting its name.
pub fn dispatch_typed(
    operation: AndroidResourceOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        AndroidResourceOperation::Decode => decode_report(input),
        AndroidResourceOperation::ManifestComponent => android::manifest_component::inspect(input),
        AndroidResourceOperation::Resource => inspect_resource(input),
        AndroidResourceOperation::ApktoolClient => inspect_apktool_client(input),
    }
}

/// Project a retained Android resource result through the public result
/// envelope. The application producer owns selector validation and matching;
/// this adapter owns the transport-facing shape declared by the contract.
fn inspect_resource(input: &Value) -> Result<Value, Failure> {
    let result = android::resource_inspection::inspect(input)?;
    Ok(serde_json::json!({ "result": result }))
}

/// Preserve a caller-supplied Apktool decode report after checking its envelope.
///
/// Decoding belongs to the TypeScript provider.  A native runtime caller may
/// replay that observation, but cannot ask this adapter to create a new one.
fn decode_report(input: &Value) -> Result<Value, Failure> {
    apktool::resource_analysis::decode(input)
}

/// Validate and preserve a captured Apktool client observation.
fn inspect_apktool_client(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid(APKTOOL_CLIENT_OPERATION, "input must be an object"))?;
    reject_unknown(
        object,
        APKTOOL_CLIENT_OPERATION,
        &["client", "report", "evidence"],
    )?;
    let source = exclusive_source(
        object,
        APKTOOL_CLIENT_OPERATION,
        &["client", "report", "evidence"],
        "captured Apktool client is required",
    )?;
    let result = source
        .get("normalized_result")
        .or_else(|| source.get("result"))
        .unwrap_or(source);
    let client = result.get("client").unwrap_or(result);
    let client_object = client.as_object().ok_or_else(|| {
        invalid(
            APKTOOL_CLIENT_OPERATION,
            "captured client must be an object",
        )
    })?;
    require_non_empty_string(client_object, "command", APKTOOL_CLIENT_OPERATION)?;
    require_enum(
        client_object,
        "command_source",
        &["environment", "path"],
        APKTOOL_CLIENT_OPERATION,
    )?;
    match client_object.get("apktool_version") {
        Some(Value::Null) => {}
        Some(Value::String(value)) if !value.is_empty() => {}
        _ => {
            return Err(invalid(
                APKTOOL_CLIENT_OPERATION,
                "apktool_version must be a string or null",
            ));
        }
    }
    Ok(serde_json::json!({ "result": { "client": client } }))
}

fn exclusive_source<'a>(
    object: &'a Map<String, Value>,
    operation: &str,
    fields: &[&str],
    missing_message: &str,
) -> Result<&'a Value, Failure> {
    let sources = fields
        .iter()
        .filter_map(|field| object.get(*field).map(|value| (*field, value)))
        .collect::<Vec<_>>();

    match sources.as_slice() {
        [(_, value)] => Ok(value),
        [] => Err(invalid(operation, missing_message)),
        _ => Err(invalid(
            operation,
            "provide exactly one captured source field",
        )),
    }
}

fn reject_unknown(
    object: &Map<String, Value>,
    operation: &str,
    allowed: &[&str],
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(operation, "input contains an unknown field"));
    }
    Ok(())
}

fn require_non_empty_string(
    object: &Map<String, Value>,
    field: &str,
    operation: &str,
) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(
            operation,
            &format!("{field} must be a non-empty string"),
        ));
    }
    Ok(())
}

fn require_enum(
    object: &Map<String, Value>,
    field: &str,
    values: &[&str],
    operation: &str,
) -> Result<(), Failure> {
    if object
        .get(field)
        .and_then(Value::as_str)
        .is_none_or(|value| !values.contains(&value))
    {
        return Err(invalid(
            operation,
            &format!("{field} has an unsupported value"),
        ));
    }
    Ok(())
}

fn unknown_operation(name: &str) -> Failure {
    invalid(name, "Android resource operation is unknown")
}

fn invalid(operation: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide bounded captured Android package or Apktool report data.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
