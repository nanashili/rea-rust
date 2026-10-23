//! Offline projection of one caller-selected ADB device inspection.
//!
//! The host adapter owns process execution and device selection.  This module
//! consumes a captured `getprop` response and preserves the serial, the fixed
//! property whitelist, and the nullable emulator observation without contacting
//! a device or inferring facts from omitted properties.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_adb_device";
pub const MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;

const PROPERTY_WHITELIST: &[&str] = &[
    "ro.build.version.release",
    "ro.build.version.sdk",
    "ro.build.version.security_patch",
    "ro.build.id",
    "ro.build.fingerprint",
    "ro.build.characteristics",
    "ro.debuggable",
    "ro.kernel.qemu",
    "ro.product.brand",
    "ro.product.device",
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.cpu.abilist",
];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Selection {
    pub serial: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProbeOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceProperty {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceInspection {
    pub serial: String,
    pub properties: Vec<DeviceProperty>,
    pub property_count: usize,
    pub emulator_observed: Option<bool>,
    pub evidence: EvidenceProvenance,
    pub unknowns: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceProvenance {
    pub operation: &'static str,
    pub source: &'static str,
    pub serial: String,
}

/// Project a captured `adb shell getprop` response.  The caller remains the
/// owner of the captured output and any process/device lifecycle.
pub fn inspect(selection: Selection, output: ProbeOutput) -> Result<DeviceInspection, Failure> {
    validate_selection(&selection)?;
    validate_output_size(&output)?;

    let values = parse_properties(&output.stdout);
    let properties = project_whitelisted_properties(&values);
    let emulator_observed = values.get("ro.kernel.qemu").map(|value| value == "1");
    let unknowns = collect_unknowns(&values, &properties, emulator_observed);

    Ok(DeviceInspection {
        serial: selection.serial.clone(),
        property_count: properties.len(),
        properties,
        emulator_observed,
        evidence: EvidenceProvenance {
            operation: OPERATION,
            source: "adb:getprop",
            serial: selection.serial,
        },
        unknowns,
    })
}

/// Parse adapter-shaped JSON while retaining the selected serial as provenance.
pub fn inspect_value(input: &serde_json::Value) -> Result<serde_json::Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB device input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        return project_captured_evidence(evidence);
    }

    if object.contains_key("result") || object.contains_key("normalized_result") {
        let result = object
            .get("normalized_result")
            .or_else(|| object.get("result"))
            .ok_or_else(|| invalid("captured ADB device result is missing"))?;
        return validate_projected_result(result);
    }

    let selection: Selection = serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid("ADB device selection is required"))?,
    )
    .map_err(|_| invalid("invalid ADB device selection"))?;
    let output: ProbeOutput = serde_json::from_value(
        object
            .get("probe")
            .cloned()
            .ok_or_else(|| invalid("captured getprop output is required"))?,
    )
    .map_err(|_| invalid("invalid captured getprop output"))?;

    serde_json::to_value(inspect(selection, output)?)
        .map_err(|_| invalid("result is not serializable"))
}

/// Reuse an already authenticated retained result without reconstructing a
/// probe.  The offline adapter must not turn retained facts back into device
/// or process authority.
fn project_captured_evidence(evidence: &serde_json::Value) -> Result<serde_json::Value, Failure> {
    let envelope = evidence
        .as_object()
        .ok_or_else(|| invalid("captured ADB device Evidence must be an object"))?;

    if let Some(operation) = envelope.get("operation")
        && operation.as_str() != Some(OPERATION)
    {
        return Err(invalid(
            "captured ADB device Evidence has the wrong operation",
        ));
    }

    let result = ["normalized_result", "result", "value"]
        .iter()
        .find_map(|key| envelope.get(*key))
        .ok_or_else(|| invalid("captured ADB device Evidence is missing its normalized result"))?;

    validate_projected_result(result)
}

fn validate_projected_result(result: &serde_json::Value) -> Result<serde_json::Value, Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("captured ADB device result must be an object"))?;

    let serial = object
        .get("serial")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("captured ADB device result requires serial"))?;
    validate_selection(&Selection {
        serial: serial.to_owned(),
    })?;

    let properties = object
        .get("properties")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| invalid("captured ADB device result requires properties"))?;
    for property in properties {
        let property = property
            .as_object()
            .ok_or_else(|| invalid("captured ADB device property must be an object"))?;
        let name = property
            .get("name")
            .and_then(serde_json::Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| invalid("captured ADB device property name is invalid"))?;
        let value = property
            .get("value")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("captured ADB device property value is invalid"))?;
        if !PROPERTY_WHITELIST.contains(&name) || value.is_empty() {
            return Err(invalid(
                "captured ADB device property is outside the whitelist",
            ));
        }
    }

    let property_count = object
        .get("property_count")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("captured ADB device result requires property_count"))?;
    if property_count != properties.len() as u64 {
        return Err(invalid(
            "captured ADB device property_count is inconsistent",
        ));
    }

    let emulator_observed = object
        .get("emulator_observed")
        .ok_or_else(|| invalid("captured ADB device result requires emulator_observed"))?;
    if !emulator_observed.is_boolean() && !emulator_observed.is_null() {
        return Err(invalid("captured ADB device emulator_observed is invalid"));
    }
    validate_emulator_observation(properties, emulator_observed)?;

    Ok(result.clone())
}

fn validate_emulator_observation(
    properties: &[serde_json::Value],
    emulator_observed: &serde_json::Value,
) -> Result<(), Failure> {
    let expected = properties
        .iter()
        .filter_map(serde_json::Value::as_object)
        .find_map(|property| {
            let name = property.get("name")?.as_str()?;
            (name == "ro.kernel.qemu").then(|| {
                property
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .map(|value| value == "1")
            })
        })
        .flatten();
    let observed = emulator_observed.as_bool();
    if observed != expected {
        return Err(invalid(
            "captured ADB device emulator_observed disagrees with ro.kernel.qemu",
        ));
    }
    Ok(())
}

fn parse_properties(stdout: &str) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some(rest) = trimmed.strip_prefix('[') else {
            continue;
        };
        let Some((name, remainder)) = rest.split_once(']') else {
            continue;
        };
        let Some(value) = remainder.strip_prefix(':').map(str::trim_start) else {
            continue;
        };
        let Some(value) = value
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
        else {
            continue;
        };
        if !name.is_empty() {
            values.insert(name.to_owned(), value.to_owned());
        }
    }
    values
}

fn project_whitelisted_properties(values: &BTreeMap<String, String>) -> Vec<DeviceProperty> {
    PROPERTY_WHITELIST
        .iter()
        .filter_map(|name| {
            let value = values.get(*name)?;
            if value.is_empty() {
                return None;
            }
            Some(DeviceProperty {
                name: (*name).to_owned(),
                value: value.clone(),
            })
        })
        .collect()
}

fn collect_unknowns(
    values: &BTreeMap<String, String>,
    properties: &[DeviceProperty],
    emulator_observed: Option<bool>,
) -> Vec<String> {
    let mut unknowns = Vec::new();
    let missing = PROPERTY_WHITELIST
        .iter()
        .filter(|name| !properties.iter().any(|property| property.name == **name))
        .count();
    if missing > 0 {
        unknowns.push(format!(
            "{missing} whitelisted getprop value(s) were absent or empty."
        ));
    }
    if emulator_observed.is_none() {
        unknowns.push("ro.kernel.qemu was not reported; emulator status is unknown.".into());
    }
    if values
        .keys()
        .any(|name| !PROPERTY_WHITELIST.contains(&name.as_str()))
    {
        unknowns.push("Non-whitelisted getprop values were omitted by design.".into());
    }
    unknowns
}

fn validate_selection(selection: &Selection) -> Result<(), Failure> {
    if selection.serial.trim().is_empty()
        || selection.serial.len() > 256
        || selection.serial.chars().any(|character| {
            character.is_whitespace() || character == '\0' || character == '"' || character == '\''
        })
    {
        return Err(invalid("ADB device serial is invalid"));
    }
    Ok(())
}

fn validate_output_size(output: &ProbeOutput) -> Result<(), Failure> {
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::new(
            "analysis_input",
            "resource_constraint",
            "Captured getprop output exceeds the maximum admitted size.".into(),
            false,
            "Provide bounded getprop output and retry.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("max_output_bytes", Detail::Count(MAX_OUTPUT_BYTES as u64)),
            ]),
        ));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the caller-selected serial and bounded captured getprop output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
