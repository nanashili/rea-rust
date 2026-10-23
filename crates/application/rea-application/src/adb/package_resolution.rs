//! Evidence-only resolution of installed Android package names.
//!
//! The ADB adapter owns the device query and package-list parser. This module
//! consumes the selected client, serial, query, and retained package Evidence;
//! it never contacts a device or reinterprets APK contents.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "resolve_adb_packages";
const MAX_SERIAL_BYTES: usize = 256;
const MAX_QUERY_BYTES: usize = 256;
const MAX_PACKAGE_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 16 * 1024;
const MAX_UNPARSED_LINES: usize = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub binary_path: String,
    pub path_source: String,
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub client: Client,
    pub serial: String,
    pub query: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEntry {
    pub package_name: String,
    pub base_apk_device_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageEvidence {
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    pub packages: Vec<PackageEntry>,
    #[serde(default)]
    pub unparsed_lines: Vec<String>,
    pub coverage: Coverage,
    #[serde(default)]
    pub evidence: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct Resolution {
    pub client: Client,
    pub serial: String,
    pub query: String,
    pub matches: Vec<PackageEntry>,
    pub exact_match: bool,
    pub coverage: Coverage,
}

/// Resolve a caller's query against retained device-package Evidence.
pub fn resolve(
    selection: Selection,
    package_evidence: PackageEvidence,
) -> Result<Resolution, Failure> {
    validate_selection(&selection)?;
    validate_package_evidence(&package_evidence)?;

    if let Some(serial) = package_evidence.serial.as_deref()
        && serial != selection.serial
    {
        return Err(invalid(
            "package Evidence serial does not match the selected serial",
        ));
    }

    let needle = selection.query.to_lowercase();
    let matches = package_evidence
        .packages
        .iter()
        .filter(|package| package.package_name.to_lowercase().contains(&needle))
        .cloned()
        .collect::<Vec<_>>();
    let exact_match = matches.len() == 1 && matches[0].package_name.to_lowercase() == needle;
    let coverage = if package_evidence.unparsed_lines.is_empty()
        && matches!(package_evidence.coverage, Coverage::Complete)
    {
        Coverage::Complete
    } else {
        Coverage::Partial
    };

    Ok(Resolution {
        client: selection.client,
        serial: selection.serial,
        query: selection.query,
        matches,
        exact_match,
        coverage,
    })
}

/// Decode the evidence-shaped adapter input without querying ADB.
pub fn resolve_adb_packages(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB package resolution input must be an object"))?;
    reject_fields(
        object,
        &["selection", "package_evidence", "packages"],
        OPERATION,
    )?;
    let selection = decode_required::<Selection>(object, "selection", "ADB selection is required")?;
    let package_evidence = object
        .get("package_evidence")
        .or_else(|| object.get("packages"))
        .cloned()
        .ok_or_else(|| invalid("device-package Evidence is required"))?;
    let package_evidence = decode_package_evidence(package_evidence)?;

    serde_json::to_value(resolve(selection, package_evidence)?)
        .map_err(|_| invalid("package resolution is not serializable"))
}

/// Backwards-compatible name for adapters that already use the generic value
/// projection entry point.
pub fn resolve_value(input: &Value) -> Result<Value, Failure> {
    resolve_adb_packages(input)
}

fn decode_package_evidence(value: Value) -> Result<PackageEvidence, Failure> {
    let value = if value.get("normalized_result").is_some_and(|_| {
        value.get("operation").and_then(Value::as_str) == Some("list_adb_packages")
    }) {
        value
            .get("normalized_result")
            .cloned()
            .ok_or_else(|| invalid("package Evidence has no normalized_result"))?
    } else {
        value
    };
    let package_evidence: PackageEvidence =
        serde_json::from_value(value).map_err(|_| invalid("invalid device-package Evidence"))?;
    Ok(package_evidence)
}

/// Retain only a result derived from the supplied selectors and package Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = resolve_value(input)?;
    if result != expected {
        return Err(invalid(
            "package resolution does not match the supplied Evidence",
        ));
    }
    Ok(result)
}

fn validate_selection(selection: &Selection) -> Result<(), Failure> {
    if !valid_client(&selection.client) {
        return Err(invalid("ADB client identity is invalid"));
    }
    if !valid_serial(&selection.serial) {
        return Err(invalid("ADB device serial is invalid"));
    }
    if selection.query.is_empty() || selection.query.len() > MAX_QUERY_BYTES {
        return Err(invalid("ADB package query must contain 1 to 256 bytes"));
    }
    Ok(())
}

fn validate_package_evidence(evidence: &PackageEvidence) -> Result<(), Failure> {
    if let Some(serial) = evidence.serial.as_deref()
        && !valid_serial(serial)
    {
        return Err(invalid("device-package Evidence serial is invalid"));
    }
    if let Some(scope) = evidence.scope.as_deref()
        && !matches!(scope, "all" | "third_party" | "system")
    {
        return Err(invalid("device-package Evidence scope is invalid"));
    }
    if evidence.unparsed_lines.len() > MAX_UNPARSED_LINES
        || evidence
            .unparsed_lines
            .iter()
            .any(|line| line.is_empty() || line.len() > MAX_PATH_BYTES)
    {
        return Err(invalid("device-package Evidence has invalid diagnostics"));
    }
    for package in &evidence.packages {
        if package.package_name.is_empty()
            || package.package_name.len() > MAX_PACKAGE_BYTES
            || !valid_package_name(&package.package_name)
            || package.base_apk_device_path.is_empty()
            || package.base_apk_device_path.len() > MAX_PATH_BYTES
        {
            return Err(invalid("device-package Evidence contains an invalid entry"));
        }
    }
    Ok(())
}

fn valid_package_name(name: &str) -> bool {
    name.split('.').all(|segment| {
        !segment.is_empty()
            && segment.bytes().enumerate().all(|(index, byte)| {
                if index == 0 {
                    byte.is_ascii_alphabetic()
                } else {
                    byte.is_ascii_alphanumeric() || byte == b'_'
                }
            })
    })
}

fn valid_client(client: &Client) -> bool {
    !client.binary_path.trim().is_empty()
        && matches!(client.path_source.as_str(), "environment" | "path")
        && client
            .version
            .as_deref()
            .is_none_or(|value| !value.is_empty())
        && client
            .installed_path
            .as_deref()
            .is_none_or(|value| !value.is_empty())
}

fn valid_serial(serial: &str) -> bool {
    !serial.is_empty()
        && serial.len() <= MAX_SERIAL_BYTES
        && !serial
            .chars()
            .any(|character| character.is_whitespace() || matches!(character, '\0' | '"' | '\''))
}

fn decode_required<T: for<'de> Deserialize<'de>>(
    object: &Map<String, Value>,
    field: &str,
    missing: &str,
) -> Result<T, Failure> {
    let value = object.get(field).cloned().ok_or_else(|| invalid(missing))?;
    serde_json::from_value(value).map_err(|_| invalid(&format!("invalid {field}")))
}

fn reject_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    operation: &str,
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("{operation} has unknown field {field}")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide caller-selected package selectors and retained device-package Evidence.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            (
                "source",
                Detail::Text("adb:pm_list_packages_evidence".into()),
            ),
        ]),
    )
}
