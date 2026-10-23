//! Offline projection of an ADB package-list command capture.
//!
//! The host adapter owns the ADB process and device lease.  This module only
//! parses caller-supplied output, so package listing never contacts a device
//! and never treats a device path as a host-local path.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_adb_packages";
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_UNPARSED_LINES_REPORTED: usize = 10;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    All,
    ThirdParty,
    System,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Selection {
    pub serial: String,
    pub scope: Scope,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ProbeOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
    #[serde(default)]
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageEntry {
    pub package_name: String,
    /// A device filesystem path, never a host-local path.
    pub base_apk_device_path: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct PackageListing {
    pub serial: String,
    pub scope: Scope,
    pub packages: Vec<PackageEntry>,
    pub unparsed_lines: Vec<String>,
    pub coverage: Coverage,
    pub evidence: EvidenceProvenance,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    Complete,
    Partial,
}

#[derive(Clone, Debug, Serialize)]
pub struct EvidenceProvenance {
    pub operation: &'static str,
    pub source: &'static str,
    pub serial: String,
    pub scope: Scope,
}

/// Parse one captured `pm list packages -f` response.
pub fn inspect(selection: Selection, output: ProbeOutput) -> Result<PackageListing, Failure> {
    validate_selection(&selection)?;
    validate_output_size(&output)?;

    let parsed = parse_output(&output.stdout);
    let coverage = if output.truncated || !parsed.unparsed_lines.is_empty() {
        Coverage::Partial
    } else {
        Coverage::Complete
    };

    Ok(PackageListing {
        serial: selection.serial.clone(),
        scope: selection.scope.clone(),
        packages: parsed.packages,
        unparsed_lines: parsed
            .unparsed_lines
            .into_iter()
            .take(MAX_UNPARSED_LINES_REPORTED)
            .collect(),
        coverage,
        evidence: EvidenceProvenance {
            operation: OPERATION,
            source: "adb:pm list packages -f",
            serial: selection.serial,
            scope: selection.scope,
        },
    })
}

/// Parse the adapter-shaped JSON input while retaining command provenance.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB package input must be an object"))?;
    let selection: Selection = serde_json::from_value(
        object
            .get("selection")
            .cloned()
            .ok_or_else(|| invalid("ADB package selection is required"))?,
    )
    .map_err(|_| invalid("invalid ADB package selection"))?;
    let output: ProbeOutput = serde_json::from_value(
        object
            .get("probe")
            .cloned()
            .ok_or_else(|| invalid("captured package-list output is required"))?,
    )
    .map_err(|_| invalid("invalid captured package-list output"))?;

    serde_json::to_value(inspect(selection, output)?)
        .map_err(|_| invalid("package listing is not serializable"))
}

#[derive(Debug)]
struct ParsedOutput {
    packages: Vec<PackageEntry>,
    unparsed_lines: Vec<String>,
}

fn parse_output(stdout: &str) -> ParsedOutput {
    let mut packages = Vec::new();
    let mut unparsed_lines = Vec::new();

    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let Some(package_line) = line.strip_prefix("package:") else {
            unparsed_lines.push(raw_line.to_owned());
            continue;
        };
        let Some((device_path, package_name)) = package_line.rsplit_once('=') else {
            unparsed_lines.push(raw_line.to_owned());
            continue;
        };
        if device_path.is_empty()
            || package_name.is_empty()
            || package_name
                .chars()
                .any(|character| character.is_whitespace() || character == '=')
        {
            unparsed_lines.push(raw_line.to_owned());
            continue;
        }

        packages.push(PackageEntry {
            package_name: package_name.to_owned(),
            base_apk_device_path: device_path.to_owned(),
        });
    }

    ParsedOutput {
        packages,
        unparsed_lines,
    }
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
    if output.stdout.len() <= MAX_OUTPUT_BYTES && output.stderr.len() <= MAX_OUTPUT_BYTES {
        return Ok(());
    }

    Err(Failure::new(
        "analysis_input",
        "resource_constraint",
        "Captured package-list output exceeds the maximum admitted size.".into(),
        false,
        "Provide bounded package-list command output and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("max_output_bytes", Detail::Count(MAX_OUTPUT_BYTES as u64)),
        ]),
    ))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide the caller-selected serial and bounded captured package-list output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
