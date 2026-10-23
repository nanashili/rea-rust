//! Read-only inspection of caller-selected Wireshark packet tools.
//!
//! Process ownership belongs to the runtime adapter. This module parses the
//! captured version banners and produces the stable client identity used by
//! packet-capture Evidence; it never opens a capture or contacts a target.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_pcap_client";
const MAX_BANNER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSelection {
    pub command: String,
    pub source: ToolSource,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolSource {
    Environment,
    Path,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientIdentity {
    pub tshark_command: String,
    pub tshark_source: ToolSource,
    pub tshark_version: Option<String>,
    pub capinfos_command: String,
    pub capinfos_source: ToolSource,
    pub capinfos_version: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientInspection {
    pub client: ClientIdentity,
}

/// Parse two already-captured `--version` responses.
pub fn inspect(
    tshark: ToolSelection,
    capinfos: ToolSelection,
    tshark_output: ProbeOutput,
    capinfos_output: ProbeOutput,
) -> Result<ClientInspection, Failure> {
    let tshark_version = parse_version(&tshark_output.stdout, "tshark")?;
    let capinfos_version = parse_version(&capinfos_output.stdout, "capinfos")?;
    Ok(ClientInspection {
        client: ClientIdentity {
            tshark_command: tshark.command,
            tshark_source: tshark.source,
            tshark_version,
            capinfos_command: capinfos.command,
            capinfos_source: capinfos.source,
            capinfos_version,
        },
    })
}

/// Parse the JSON adapter shape, allowing callers to retain probe provenance.
pub fn inspect_value(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    let tshark = required_selection(object, "tshark")?;
    let capinfos = required_selection(object, "capinfos")?;
    let tshark_output = required_output(object, "tshark_output")?;
    let capinfos_output = required_output(object, "capinfos_output")?;

    serde_json::to_value(inspect(tshark, capinfos, tshark_output, capinfos_output)?)
        .map_err(|_| invalid("client result is not serializable"))
}

fn required_selection(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<ToolSelection, Failure> {
    let value = object
        .get(name)
        .cloned()
        .ok_or_else(|| invalid(&format!("{name} selection is required")))?;
    serde_json::from_value(value).map_err(|_| invalid(&format!("invalid {name} selection")))
}

fn required_output(
    object: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<ProbeOutput, Failure> {
    let value = object
        .get(name)
        .cloned()
        .ok_or_else(|| invalid(&format!("{name} is required")))?;
    serde_json::from_value(value).map_err(|_| invalid(&format!("invalid {name}")))
}

fn parse_version(output: &str, tool: &str) -> Result<Option<String>, Failure> {
    if output.len() > MAX_BANNER_BYTES {
        return Err(resource(tool));
    }
    let line = output.lines().map(str::trim).find(|line| !line.is_empty());
    let Some(line) = line else {
        return Ok(None);
    };
    let prefix = format!("{tool} (Wireshark) ");
    if !line.starts_with(&prefix) {
        return Ok(None);
    }
    let version = line[prefix.len()..]
        .split_whitespace()
        .next()
        .unwrap_or_default();
    let components = version.split('.').collect::<Vec<_>>();
    if components.len() < 3
        || components[..3]
            .iter()
            .any(|component| component.parse::<u64>().is_err())
    {
        return Ok(None);
    }
    let major = components[0].parse::<u64>().ok();
    if major != Some(4) {
        return Err(Failure::new(
            "unsupported_version",
            "unsupported_version",
            "Packet summary inspection requires Wireshark 4.x tools.".into(),
            false,
            "Select Wireshark 4.x tshark and capinfos.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("tool", Detail::Text(tool.into())),
                ("version", Detail::Text(line.into())),
            ]),
        ));
    }
    Ok(Some(line.into()))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide both caller-selected Wireshark tools and bounded version output.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(tool: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        format!("{tool} version output exceeds the 64 KiB limit."),
        false,
        "Use a tool with bounded version output.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("tool", Detail::Text(tool.into())),
        ]),
    )
}
