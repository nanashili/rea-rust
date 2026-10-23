//! Read-only projection of a captured adb devices -l response.
//!
//! Process execution and client selection belong to the host adapter. This
//! module parses only the bounded output supplied by that adapter, preserving
//! source ordering and refusing unrecognized device lines.

use crate::adb::client::ClientIdentity;
use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_adb_devices";
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeOutput {
    pub stdout: String,
    #[serde(default)]
    pub stderr: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DeviceListing {
    pub client: ClientIdentity,
    pub devices: Vec<Device>,
    pub may_have_started_adb_server: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Device {
    pub serial: String,
    pub state: DeviceState,
    pub transport: Transport,
    pub product: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub transport_id: Option<u64>,
    pub kind: DeviceKind,
    pub kind_basis: KindBasis,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    #[serde(rename = "no permissions")]
    NoPermissions,
    Unauthorized,
    Authorizing,
    Offline,
    Recovery,
    Sideload,
    Connecting,
    Bootloader,
    Device,
    Unknown,
    Host,
    Rescue,
    Detached,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Usb,
    Tcp,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Emulator,
    Physical,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KindBasis {
    EmulatorSerialPrefix,
    UsbTransport,
    None,
}

/// Parse one bounded adb devices -l response.
pub fn list(client: ClientIdentity, output: ProbeOutput) -> Result<DeviceListing, Failure> {
    ensure_output_bound(&output)?;

    let parsed = parse_output(&output.stdout, &output.stderr);
    if let Some(line) = parsed.unparsed_lines.first() {
        return Err(protocol_failure(line));
    }

    Ok(DeviceListing {
        client,
        devices: parsed.devices,
        may_have_started_adb_server: parsed.daemon_started,
    })
}

struct ParsedOutput {
    devices: Vec<Device>,
    unparsed_lines: Vec<String>,
    daemon_started: bool,
}

fn parse_output(stdout: &str, stderr: &str) -> ParsedOutput {
    let mut parsed = ParsedOutput {
        devices: Vec::new(),
        unparsed_lines: Vec::new(),
        daemon_started: false,
    };

    for raw_line in stdout.split('\n') {
        parse_line(raw_line.trim_end_matches('\r'), &mut parsed);
    }

    if !parsed.daemon_started {
        parsed.daemon_started = stderr
            .split('\n')
            .map(|line| line.trim_end_matches('\r'))
            .any(is_successful_daemon_start_notice);
    }

    parsed
}

fn parse_line(raw_line: &str, parsed: &mut ParsedOutput) {
    let line = raw_line.trim_end();
    if is_successful_daemon_start_notice(line) {
        parsed.daemon_started = true;
        return;
    }
    if line.trim().is_empty() || line.starts_with("List of devices attached") {
        return;
    }
    if line.starts_with("* daemon") {
        return;
    }

    let Some((serial, remainder)) = split_device_line(line) else {
        parsed.unparsed_lines.push(raw_line.to_owned());
        return;
    };
    let Some((state, metadata)) = parse_state(remainder) else {
        parsed.unparsed_lines.push(raw_line.to_owned());
        return;
    };

    parsed.devices.push(parse_device(serial, state, metadata));
}

fn split_device_line(line: &str) -> Option<(&str, &str)> {
    let split_at = line.find(char::is_whitespace)?;
    let serial = &line[..split_at];
    let remainder = line[split_at..].trim_start();
    (!serial.is_empty() && !remainder.is_empty()).then_some((serial, remainder))
}

fn parse_state(remainder: &str) -> Option<(DeviceState, &str)> {
    const STATES: [(&str, fn() -> DeviceState); 13] = [
        ("no permissions", || DeviceState::NoPermissions),
        ("unauthorized", || DeviceState::Unauthorized),
        ("authorizing", || DeviceState::Authorizing),
        ("offline", || DeviceState::Offline),
        ("recovery", || DeviceState::Recovery),
        ("sideload", || DeviceState::Sideload),
        ("connecting", || DeviceState::Connecting),
        ("bootloader", || DeviceState::Bootloader),
        ("device", || DeviceState::Device),
        ("unknown", || DeviceState::Unknown),
        ("host", || DeviceState::Host),
        ("rescue", || DeviceState::Rescue),
        ("detached", || DeviceState::Detached),
    ];

    STATES.iter().find_map(|(name, state)| {
        let rest = remainder.strip_prefix(name)?;
        if rest.is_empty() || rest.chars().next().is_some_and(char::is_whitespace) {
            Some((state(), rest))
        } else {
            None
        }
    })
}

fn parse_device(serial: &str, state: DeviceState, remainder: &str) -> Device {
    let usb = metadata_value(remainder, "usb");
    let is_emulator = is_emulator_serial(serial);
    let kind = if is_emulator {
        DeviceKind::Emulator
    } else if usb.is_some() {
        DeviceKind::Physical
    } else {
        DeviceKind::Unknown
    };
    let kind_basis = match kind {
        DeviceKind::Emulator => KindBasis::EmulatorSerialPrefix,
        DeviceKind::Physical => KindBasis::UsbTransport,
        DeviceKind::Unknown => KindBasis::None,
    };

    Device {
        serial: serial.to_owned(),
        state,
        transport: if usb.is_some() {
            Transport::Usb
        } else if is_emulator || serial.contains(':') {
            Transport::Tcp
        } else {
            Transport::Unknown
        },
        product: metadata_value(remainder, "product"),
        model: metadata_value(remainder, "model"),
        device: metadata_value(remainder, "device"),
        transport_id: metadata_value(remainder, "transport_id")
            .and_then(|value| value.parse::<u64>().ok()),
        kind,
        kind_basis,
    }
}

fn metadata_value(remainder: &str, key: &str) -> Option<String> {
    remainder.split_whitespace().find_map(|field| {
        let (field_key, value) = field.split_once(':')?;
        (field_key == key && !value.is_empty()).then(|| value.to_owned())
    })
}

fn is_emulator_serial(serial: &str) -> bool {
    let suffix = serial.strip_prefix("emulator-").unwrap_or_default();
    !suffix.is_empty() && suffix.chars().all(|character| character.is_ascii_digit())
}

fn is_successful_daemon_start_notice(line: &str) -> bool {
    line == "* daemon started successfully" || line == "* daemon started successfully *"
}

fn ensure_output_bound(output: &ProbeOutput) -> Result<(), Failure> {
    if output.stdout.len() <= MAX_OUTPUT_BYTES && output.stderr.len() <= MAX_OUTPUT_BYTES {
        return Ok(());
    }
    Err(Failure::new(
        "resource_constraint",
        "resource_constraint",
        "adb devices output exceeds the 1 MiB capture bound.".into(),
        false,
        "Use a bounded adb devices probe output.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("maximum_bytes", Detail::Count(MAX_OUTPUT_BYTES as u64)),
        ]),
    ))
}

fn protocol_failure(line: &str) -> Failure {
    Failure::new(
        "protocol_failure",
        "protocol",
        format!("adb devices reported an unrecognized line: {line}"),
        false,
        "Use a compatible adb client and retain its complete devices output.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("unparsed_line", Detail::Text(line.into())),
        ]),
    )
}
