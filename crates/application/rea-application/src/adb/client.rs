//! Read-only inspection of the caller-selected Android Debug Bridge client.
//!
//! The runtime owns process execution and binary selection.  This module only
//! validates a captured `adb version` response and projects the stable client
//! identity; it never contacts devices or starts the adb server.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_adb_client";
const MAX_OUTPUT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathSource {
    Environment,
    Path,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub binary_path: String,
    pub path_source: PathSource,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientIdentity {
    pub binary_path: String,
    pub path_source: PathSource,
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClientInspection {
    pub client: ClientIdentity,
    pub contacted_adb_server: bool,
}

/// Parse a captured `adb version` response.
pub fn inspect(selection: Selection, output: ProbeOutput) -> Result<ClientInspection, Failure> {
    validate_selection(&selection)?;
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(resource_failure());
    }

    let version = parse_build_version(&output.stdout);
    let installed_path = parse_installed_path(&output.stdout);
    let protocol_recognized = output.stdout.lines().any(|line| protocol_line(line.trim()));
    if version.is_none() && !protocol_recognized {
        return Err(Failure::new(
            "configuration_failure",
            "provider_configuration",
            "The selected adb binary did not report a recognizable protocol or build version."
                .into(),
            false,
            "Select a working adb binary and provide its bounded `adb version` output.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("version_probe", Detail::Text("unrecognized_output".into())),
            ]),
        ));
    }

    Ok(ClientInspection {
        client: ClientIdentity {
            binary_path: selection.binary_path,
            path_source: selection.path_source,
            version,
            installed_path,
        },
        contacted_adb_server: false,
    })
}

/// Parse the adapter-shaped JSON input while retaining probe provenance.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("adb client input must be an object"))?;

    // Retained Evidence is already the authenticated source for this
    // operation. Project it directly instead of reconstructing a probe or
    // selecting a binary, which would incorrectly grant execution authority
    // to the offline adapter.
    if let Some(evidence) = object.get("evidence") {
        return project_captured_evidence(evidence);
    }
    if object.contains_key("client") {
        return validate_projected_result(input);
    }

    let selection: Selection = serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid("adb selection is required"))?,
    )
    .map_err(|_| invalid("invalid adb selection"))?;
    let output: ProbeOutput = serde_json::from_value(
        object
            .get("probe")
            .cloned()
            .ok_or_else(|| invalid("captured adb version output is required"))?,
    )
    .map_err(|_| invalid("invalid captured adb version output"))?;
    serde_json::to_value(inspect(selection, output)?)
        .map_err(|_| invalid("result is not serializable"))
}

/// Project the normalized result from a captured Evidence envelope.
pub fn project_captured_evidence(evidence: &Value) -> Result<Value, Failure> {
    let envelope = evidence
        .as_object()
        .ok_or_else(|| invalid("captured ADB client Evidence must be an object"))?;

    if let Some(operation) = envelope.get("operation")
        && operation.as_str() != Some(OPERATION)
    {
        return Err(invalid(
            "captured ADB client Evidence has the wrong operation",
        ));
    }

    let result = ["normalized_result", "result", "value"]
        .iter()
        .find_map(|key| envelope.get(*key))
        .ok_or_else(|| invalid("captured ADB client Evidence is missing its normalized result"))?;

    validate_projected_result(result)
}

fn validate_projected_result(result: &Value) -> Result<Value, Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("captured ADB client result must be an object"))?;
    let inspected: ClientInspection = serde_json::from_value(result.clone())
        .map_err(|_| invalid("captured ADB client result is invalid"))?;

    if object.len() != 2 || inspected.contacted_adb_server {
        return Err(invalid(
            "captured ADB client result contains unknown fields or reports server contact",
        ));
    }

    serde_json::to_value(inspected)
        .map_err(|_| invalid("captured ADB client result is not serializable"))
}

/// Validate the provider result before Evidence wrapping.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let inspected = inspect_value(input)?;
    if result != inspected {
        return Err(invalid(
            "adb client result does not match the captured probe",
        ));
    }
    Ok(result)
}

fn parse_build_version(stdout: &str) -> Option<String> {
    stdout.lines().map(str::trim).find_map(|line| {
        let value = line.strip_prefix("Version ")?.trim();
        if !is_build_version(value) {
            return None;
        }
        Some(value.to_owned())
    })
}

fn is_build_version(value: &str) -> bool {
    let (core, suffix) = value
        .find(|character: char| character == '-' || character == '+')
        .map_or((value, None), |index| {
            (&value[..index], Some(&value[index + 1..]))
        });

    let components: Vec<_> = core.split('.').collect();
    if components.len() != 3
        || components.iter().any(|component| {
            component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return false;
    }

    suffix.is_none_or(|value| {
        !value.is_empty()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
    })
}

fn parse_installed_path(stdout: &str) -> Option<String> {
    stdout.lines().map(str::trim).find_map(|line| {
        let value = line.strip_prefix("Installed as ")?.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn protocol_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("Android Debug Bridge version ") else {
        return false;
    };
    let mut parts = rest.split('.');
    parts.next().is_some_and(|part| part.parse::<u64>().is_ok())
        && parts.next().is_some_and(|part| part.parse::<u64>().is_ok())
        && parts.next().is_some_and(|part| part.parse::<u64>().is_ok())
        && parts.next().is_none()
}

fn validate_selection(selection: &Selection) -> Result<(), Failure> {
    if selection.binary_path.trim().is_empty() {
        return Err(invalid("adb binary_path must not be empty"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-selected adb binary and bounded `adb version` output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource_failure() -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "adb version output exceeds the 64 KiB bound.".into(),
        false,
        "Use a bounded adb version probe output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
