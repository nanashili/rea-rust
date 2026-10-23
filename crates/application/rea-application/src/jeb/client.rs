//! Read-only inspection of a caller-selected JEB MCP client.
//!
//! The runtime owns the MCP transport and process lifecycle. This module only
//! validates a captured `get_client_information` response and projects the
//! stable JEB client identity; it never launches JEB, opens a project, or
//! contacts an endpoint.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_jeb_client";
const MAX_ENDPOINT_LENGTH: usize = 2 * 1024;
const MAX_MESSAGE_LENGTH: usize = 64 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSelection {
    pub endpoint: String,
}

/// Decoded response from JEB's `get_client_information` tool.
///
/// JEB omits fields that its client cannot report. Those omissions remain
/// `None` and become explicit `null` values in the portable result.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct ClientInformation {
    pub success: bool,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub gui_client: Option<bool>,
    #[serde(default)]
    pub startup_ts: Option<u64>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub error: Option<ClientError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientError {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub recovery_tool: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EngineIdentity {
    pub name: &'static str,
    pub version: Option<String>,
    pub endpoint: String,
    pub gui_client: Option<bool>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ClientInspection {
    pub engine: EngineIdentity,
    pub startup_ts: Option<u64>,
    pub message: Option<String>,
}

/// Project a validated, caller-captured JEB client response.
pub fn inspect(
    selection: ClientSelection,
    information: ClientInformation,
) -> Result<ClientInspection, Failure> {
    validate_endpoint(&selection.endpoint)?;
    validate_information(&information)?;

    if !information.success {
        return Err(refusal_failure(&information));
    }

    Ok(ClientInspection {
        engine: EngineIdentity {
            name: "jeb",
            version: information.version,
            endpoint: selection.endpoint,
            gui_client: information.gui_client,
        },
        startup_ts: information.startup_ts,
        message: information.message,
    })
}

/// Parse the adapter-shaped JSON input while retaining endpoint selection.
///
/// The expected input is `{ "selection": { "endpoint": "..." },
/// "client_information": { ... } }`.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("JEB client input must be an object"))?;

    // Native callers may provide a complete retained Evidence record. This
    // path is deliberately projection-only: it never reconstructs an
    // endpoint request and never contacts the JEB process.
    if let Some(evidence) = object.get("evidence") {
        return project_captured_evidence(evidence);
    }
    if object.get("engine").is_some() {
        return validate_projected_result(input);
    }
    let selection: ClientSelection = serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid("JEB client selection is required"))?,
    )
    .map_err(|_| invalid("invalid JEB client selection"))?;
    let information: ClientInformation = serde_json::from_value(
        object
            .get("client_information")
            .cloned()
            .ok_or_else(|| invalid("captured JEB client information is required"))?,
    )
    .map_err(|_| invalid("invalid captured JEB client information"))?;

    serde_json::to_value(inspect(selection, information)?)
        .map_err(|_| invalid("JEB client inspection result is not serializable"))
}

/// Project the normalized result from a captured Evidence envelope.
///
/// The envelope may be supplied directly or through the conventional
/// `normalized_result`/`result`/`value` fields used by native adapters.
pub fn project_captured_evidence(evidence: &Value) -> Result<Value, Failure> {
    let envelope = evidence
        .as_object()
        .ok_or_else(|| invalid("captured JEB Evidence must be an object"))?;
    if let Some(operation) = envelope.get("operation")
        && operation.as_str() != Some(OPERATION)
    {
        return Err(invalid("captured JEB Evidence has the wrong operation"));
    }
    let result = ["normalized_result", "result", "value"]
        .iter()
        .find_map(|key| envelope.get(*key))
        .ok_or_else(|| invalid("captured JEB Evidence is missing its normalized result"))?;
    validate_projected_result(result)
}

fn validate_projected_result(result: &Value) -> Result<Value, Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("captured JEB client result must be an object"))?;
    let engine = object
        .get("engine")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("captured JEB client result is missing engine"))?;
    let name = engine
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("captured JEB client engine name is required"))?;
    if name != "jeb" {
        return Err(invalid("captured JEB client engine name must be jeb"));
    }
    let endpoint = engine
        .get("endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("captured JEB client endpoint is required"))?;
    validate_endpoint(endpoint)?;
    let version = engine
        .get("version")
        .ok_or_else(|| invalid("captured JEB client version is required"))?;
    if !version.is_null() && !version.is_string() {
        return Err(invalid(
            "captured JEB client version must be a string or null",
        ));
    }
    let gui_client = engine
        .get("gui_client")
        .ok_or_else(|| invalid("captured JEB client gui_client is required"))?;
    if !gui_client.is_null() && !gui_client.is_boolean() {
        return Err(invalid(
            "captured JEB client gui_client must be boolean or null",
        ));
    }
    let startup_ts = object
        .get("startup_ts")
        .ok_or_else(|| invalid("captured JEB client startup_ts is required"))?;
    if let Some(value) = startup_ts.as_u64() {
        if value > MAX_SAFE_INTEGER {
            return Err(invalid(
                "captured JEB startup_ts exceeds the JSON safe integer bound",
            ));
        }
    } else if !startup_ts.is_null() {
        return Err(invalid(
            "captured JEB startup_ts must be a nonnegative integer or null",
        ));
    }
    let message = object
        .get("message")
        .ok_or_else(|| invalid("captured JEB client message is required"))?;
    if !message.is_null()
        && (!message.is_string()
            || message
                .as_str()
                .map_or(false, |value| value.len() > MAX_MESSAGE_LENGTH))
    {
        return Err(invalid(
            "captured JEB client message is invalid or exceeds the 64 KiB bound",
        ));
    }
    if object.len() != 3 || engine.len() != 4 {
        return Err(invalid(
            "captured JEB client result contains unknown fields",
        ));
    }
    Ok(result.clone())
}

/// Validate the provider result before Evidence wrapping.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let inspected = inspect_value(input)?;
    if result != inspected {
        return Err(invalid(
            "JEB client result does not match the captured client information",
        ));
    }
    Ok(result)
}

fn validate_endpoint(endpoint: &str) -> Result<(), Failure> {
    if endpoint.is_empty() || endpoint.len() > MAX_ENDPOINT_LENGTH {
        return Err(invalid("JEB MCP endpoint must be non-empty and bounded"));
    }
    let (scheme, remainder) = endpoint
        .split_once("://")
        .ok_or_else(|| invalid("JEB MCP endpoint must be an absolute HTTP(S) URL"))?;
    if scheme != "http" && scheme != "https" {
        return Err(invalid("JEB MCP endpoint must use http or https"));
    }
    if remainder.contains('@') || remainder.contains('?') || remainder.contains('#') {
        return Err(invalid(
            "JEB MCP endpoint credentials, queries, and fragments are not supported",
        ));
    }
    let (authority, path) = remainder.split_once('/').unwrap_or((remainder, ""));
    let host = if let Some(host_and_port) = authority.strip_prefix('[') {
        let (host, suffix) = host_and_port
            .split_once(']')
            .ok_or_else(|| invalid("JEB MCP endpoint has an invalid IPv6 authority"))?;
        if !suffix.is_empty() && !suffix.starts_with(':') {
            return Err(invalid("JEB MCP endpoint has an invalid port"));
        }
        host
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        if port.is_some_and(|port| port.is_empty() || !port.chars().all(|c| c.is_ascii_digit())) {
            return Err(invalid("JEB MCP endpoint has an invalid port"));
        }
        host
    };
    if host != "127.0.0.1" && host != "::1" {
        return Err(invalid(
            "JEB MCP endpoint must use literal loopback host 127.0.0.1 or ::1",
        ));
    }
    if path != "mcp" && path != "mcp/" {
        return Err(invalid("JEB MCP endpoint must use the /mcp route"));
    }
    Ok(())
}

fn validate_information(information: &ClientInformation) -> Result<(), Failure> {
    if information
        .startup_ts
        .is_some_and(|value| value > MAX_SAFE_INTEGER)
    {
        return Err(invalid(
            "JEB startup_ts exceeds the JSON safe integer bound",
        ));
    }
    if information
        .message
        .as_ref()
        .is_some_and(|message| message.len() > MAX_MESSAGE_LENGTH)
    {
        return Err(resource_failure(
            "JEB client message exceeds the 64 KiB bound",
        ));
    }
    Ok(())
}

fn refusal_failure(information: &ClientInformation) -> Failure {
    let reason = information
        .error
        .as_ref()
        .and_then(|error| error.message.as_deref())
        .or(information.message.as_deref())
        .or_else(|| {
            information
                .error
                .as_ref()
                .and_then(|error| error.code.as_deref())
        })
        .unwrap_or("JEB refused the client information request");
    Failure::new(
        "provider_refusal",
        "unsupported_target",
        reason.into(),
        false,
        "Start a JEB client with its MCP service enabled and retry the inspection.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("provider", Detail::Text("jeb".into())),
        ]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-selected loopback JEB MCP endpoint and captured client information."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource_failure(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.into(),
        false,
        "Provide bounded JEB client information and retry the inspection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
