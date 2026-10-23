//! Parsers for adb and Package Manager device output formats.
//!
//! Compatibility owner: `src/adb/AdbDeviceOutput.ts`. Unparseable lines are
//! retained rather than dropped, and derived classifications keep their basis.
use crate::adb::host_file_name::{HostFileNameReason, adb_host_file_name};
use std::sync::OnceLock;

/// Text states emitted by adb's ConnectionState formatter.
pub const ADB_DEVICE_STATES: &[&str] = &[
    "no permissions",
    "unauthorized",
    "authorizing",
    "offline",
    "recovery",
    "sideload",
    "connecting",
    "bootloader",
    "device",
    "unknown",
    "host",
    "rescue",
    "detached",
];

/// One device exactly as `adb devices -l` reports it.
#[derive(Clone, Debug)]
pub struct AdbDeviceEntry {
    pub serial: String,
    pub state: String,
    pub transport: &'static str,
    pub product: Option<String>,
    pub model: Option<String>,
    pub device: Option<String>,
    pub transport_id: Option<i64>,
    pub kind: &'static str,
    pub kind_basis: &'static str,
}

/// Parsed `adb devices -l`.
pub struct DevicesOutput {
    pub devices: Vec<AdbDeviceEntry>,
    pub unparsed_lines: Vec<String>,
    pub daemon_started: bool,
}

pub fn is_successful_daemon_start_notice(line: &str) -> bool {
    line == "* daemon started successfully" || line == "* daemon started successfully *"
}

fn metadata_value(remainder: &str, key: &str) -> Option<String> {
    // (?:^|\s)KEY:(\S+)
    let pattern = format!(r"(?:^|\s){key}:(\S+)");
    let re = regex::Regex::new(&pattern).ok()?;
    re.captures(remainder).map(|caps| caps[1].to_owned())
}

fn emulator_serial_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^emulator-\d+$").unwrap())
}

fn digits_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\d+$").unwrap())
}

fn device_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^(\S+)\s+(.*)$").unwrap())
}

fn split_lines(text: &str) -> Vec<&str> {
    // Matches /\r?\n/.
    text.split('\n')
        .map(|line| line.strip_suffix('\r').unwrap_or(line))
        .collect()
}

/// `parseAdbDevicesOutput(stdout, stderr)`.
pub fn parse_adb_devices_output(stdout: &str, stderr: &str) -> DevicesOutput {
    let mut devices = Vec::new();
    let mut unparsed_lines = Vec::new();
    let mut daemon_started = false;
    for raw_line in split_lines(stdout) {
        let line = raw_line.trim_end();
        if is_successful_daemon_start_notice(line) {
            daemon_started = true;
            continue;
        }
        if line.is_empty() || line.starts_with("List of devices attached") {
            continue;
        }
        if line.starts_with("* daemon") {
            continue;
        }
        let captures = device_line_regex().captures(line);
        let state = captures.as_ref().and_then(|captures| {
            let remainder = &captures[2];
            ADB_DEVICE_STATES.iter().copied().find(|candidate| {
                if !remainder.starts_with(candidate) {
                    return false;
                }
                let next = remainder[candidate.len()..].chars().next();
                next.is_none_or(|c| c.is_whitespace())
            })
        });
        let (Some(captures), Some(state)) = (captures, state) else {
            if !raw_line.trim().is_empty() {
                unparsed_lines.push(raw_line.to_owned());
            }
            continue;
        };
        let serial = captures[1].to_owned();
        let remainder = captures[2][state.len()..].to_owned();
        let usb = metadata_value(&remainder, "usb");
        let transport_id_text = metadata_value(&remainder, "transport_id");
        let parsed_transport_id = transport_id_text
            .as_deref()
            .filter(|text| digits_regex().is_match(text))
            .and_then(|text| text.parse::<i64>().ok());
        let is_emulator = emulator_serial_regex().is_match(&serial);
        let kind = if is_emulator {
            "emulator"
        } else if usb.is_some() {
            "physical"
        } else {
            "unknown"
        };
        let transport = if usb.is_some() {
            "usb"
        } else if is_emulator || serial.contains(':') {
            "tcp"
        } else {
            "unknown"
        };
        let kind_basis = match kind {
            "emulator" => "emulator_serial_prefix",
            "physical" => "usb_transport",
            _ => "none",
        };
        devices.push(AdbDeviceEntry {
            serial,
            state: state.to_owned(),
            transport,
            product: metadata_value(&remainder, "product"),
            model: metadata_value(&remainder, "model"),
            device: metadata_value(&remainder, "device"),
            transport_id: parsed_transport_id,
            kind,
            kind_basis,
        });
    }
    if !daemon_started && !stderr.is_empty() {
        for raw_line in split_lines(stderr) {
            if is_successful_daemon_start_notice(raw_line.trim_end()) {
                daemon_started = true;
                break;
            }
        }
    }
    DevicesOutput {
        devices,
        unparsed_lines,
        daemon_started,
    }
}

const DEVICE_PROPERTY_WHITELIST: &[&str] = &[
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

#[derive(Clone, Debug)]
pub struct AdbDeviceProperty {
    pub name: String,
    pub value: String,
}

/// Parsed `getprop`.
pub struct GetpropOutput {
    pub properties: Vec<AdbDeviceProperty>,
    pub emulator_observed: Option<bool>,
}

fn getprop_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\[([^\]]+)\]:\s*\[(.*)\]$").unwrap())
}

/// `parseGetpropOutput(stdout)`.
pub fn parse_getprop_output(stdout: &str) -> GetpropOutput {
    let mut values: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for raw_line in split_lines(stdout) {
        if let Some(captures) = getprop_line_regex().captures(raw_line.trim()) {
            values.insert(captures[1].to_owned(), captures[2].to_owned());
        }
    }
    let properties = DEVICE_PROPERTY_WHITELIST
        .iter()
        .filter_map(|name| {
            let value = values.get(*name)?;
            if value.is_empty() {
                None
            } else {
                Some(AdbDeviceProperty {
                    name: (*name).to_owned(),
                    value: value.clone(),
                })
            }
        })
        .collect();
    let emulator_observed = values.get("ro.kernel.qemu").map(|qemu| qemu == "1");
    GetpropOutput {
        properties,
        emulator_observed,
    }
}

/// One installed package exactly as `pm list packages -f` reports it.
#[derive(Clone, Debug)]
pub struct AdbPackageEntry {
    pub package_name: String,
    pub base_apk_device_path: String,
}

fn package_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^package:(.+)=([^\s=]+)$").unwrap())
}

/// `parsePackageListOutput(stdout)`.
pub fn parse_package_list_output(stdout: &str) -> (Vec<AdbPackageEntry>, Vec<String>) {
    let mut packages = Vec::new();
    let mut unparsed = Vec::new();
    for raw_line in split_lines(stdout) {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        match package_line_regex().captures(line) {
            Some(captures) => packages.push(AdbPackageEntry {
                package_name: captures[2].to_owned(),
                base_apk_device_path: captures[1].to_owned(),
            }),
            None => unparsed.push(raw_line.to_owned()),
        }
    }
    (packages, unparsed)
}

/// `displayDevicePath(devicePath)`: quote a raw device path for prose without
/// allowing bidi or invisible text.
pub fn display_device_path(device_path: &str) -> String {
    let mut excerpt = String::new();
    let mut count = 0usize;
    for character in device_path.chars() {
        if count == 160 {
            break;
        }
        excerpt.push(character);
        count += 1;
    }
    let is_full = excerpt.chars().count() == device_path.chars().count();
    let quoted = quote_display(&excerpt);
    if is_full {
        quoted
    } else {
        format!("{quoted} (excerpt)")
    }
}

/// `JSON.stringify(excerpt)` then escape control, separator and ignorable
/// code points (leaving ASCII space) as `\u{HEX}`.
fn quote_display(excerpt: &str) -> String {
    let json = serde_json::to_string(excerpt).unwrap_or_else(|_| "\"\"".to_owned());
    let mut result = String::with_capacity(json.len());
    for character in json.chars() {
        if character == ' ' {
            result.push(' ');
        } else if should_escape(character) {
            result.push_str(&format!("\\u{{{:X}}}", character as u32));
        } else {
            result.push(character);
        }
    }
    result
}

fn should_escape(character: char) -> bool {
    let code = character as u32;
    // \p{C} (control + format + surrogate + private-use + unassigned proxied
    // by control/format here), \p{Z} (separators), U+2800, and common default
    // ignorable code points. Approximate the JS class set with the ranges
    // actually reachable in device paths.
    if character.is_control() {
        return true;
    }
    matches!(
        code,
        0x00AD // SOFT HYPHEN (format)
            | 0x200B..=0x200F // zero-width + bidi
            | 0x2028 | 0x2029 // line/paragraph separators
            | 0x202A..=0x202E // bidi embedding/override
            | 0x2060..=0x2064 // word joiner, invisible operators
            | 0x2066..=0x206F // bidi isolates + deprecated format
            | 0xFEFF // zero-width no-break space
            | 0xFFF9..=0xFFFB // interlinear annotation
            | 0x1D173..=0x1D17A // musical control
            | 0xE0001 | 0xE0020..=0xE007F // tags
            | 0x2800 // braille blank
            | 0x00A0 | 0x1680 | 0x2000..=0x200A | 0x202F | 0x205F | 0x3000 // spaces (Z)
    )
}

/// One APK of an installed package exactly as `pm path` reports it.
#[derive(Clone, Debug)]
pub struct AdbPackagePathEntry {
    pub device_path: String,
    pub file_name: String,
    pub role: &'static str,
}

/// Rejected path with its host-name refusal reason.
#[derive(Clone, Debug)]
pub struct RejectedPath {
    pub device_path: String,
    pub reason: HostFileNameReason,
}

/// Parsed `pm path PACKAGE`.
pub struct PmPathOutput {
    pub paths: Vec<AdbPackagePathEntry>,
    pub rejected_paths: Vec<RejectedPath>,
    pub unparsed_lines: Vec<String>,
}

fn pm_path_line_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^package:(.*)$").unwrap())
}

/// `parsePmPathOutput(stdout)`.
pub fn parse_pm_path_output(stdout: &str) -> PmPathOutput {
    let mut paths = Vec::new();
    let mut rejected_paths = Vec::new();
    let mut unparsed_lines = Vec::new();
    for raw_line in split_lines(stdout) {
        if raw_line.is_empty() {
            continue;
        }
        let Some(captures) = pm_path_line_regex().captures(raw_line) else {
            unparsed_lines.push(raw_line.to_owned());
            continue;
        };
        let device_path = captures[1].to_owned();
        match adb_host_file_name(&device_path) {
            Err(reason) => rejected_paths.push(RejectedPath {
                device_path,
                reason,
            }),
            Ok(file_name) => {
                let role = if file_name == "base.apk" {
                    "base"
                } else if file_name.starts_with("split_") && file_name.ends_with(".apk") {
                    "split"
                } else {
                    "unknown"
                };
                paths.push(AdbPackagePathEntry {
                    device_path,
                    file_name,
                    role,
                });
            }
        }
    }
    PmPathOutput {
        paths,
        rejected_paths,
        unparsed_lines,
    }
}
