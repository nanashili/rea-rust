//! Offline projection of a captured `list_adb_directory` response.
//!
//! ADB execution and device ownership stay with the caller.  This module only
//! decodes the NUL-framed records emitted by the provider's directory script.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_adb_directory";
const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_UNPARSED_REPORTED: usize = 10;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Parse a captured output object.  The expected shape is
/// `{client, serial, device_path, stdout_base64, truncated}`.  No device or
/// local filesystem access occurs here.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;

    reject_unknown_fields(
        object,
        &[
            "client",
            "serial",
            "device_path",
            "stdout_base64",
            "truncated",
        ],
    )?;

    let client = object
        .get("client")
        .cloned()
        .ok_or_else(|| invalid("client identity is required"))?;
    let serial = required_text(object, "serial")?;
    let device_path = required_text(object, "device_path")?;
    validate_serial(serial)?;
    validate_device_path(device_path)?;
    let encoded = required_text(object, "stdout_base64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| invalid("stdout_base64 is malformed"))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(resource(
            "captured directory output exceeds the 4 MiB limit",
        ));
    }
    let truncated = match object.get("truncated") {
        None => false,
        Some(value) => value
            .as_bool()
            .ok_or_else(|| invalid("truncated must be a boolean"))?,
    };
    let (entries, unparsed) = parse_records(&bytes)?;
    let coverage = if truncated || !unparsed.is_empty() {
        "partial"
    } else {
        "complete"
    };
    let reported: Vec<Value> = unparsed
        .iter()
        .take(MAX_UNPARSED_REPORTED)
        .map(|line| Value::String(line.clone()))
        .collect();
    Ok(json!({
        "client": client,
        "serial": serial,
        "device_path": device_path,
        "entries": entries,
        "unparsed_lines": reported,
        "coverage": coverage,
    }))
}

fn parse_records(bytes: &[u8]) -> Result<(Vec<Value>, Vec<String>), Failure> {
    let mut entries = Vec::new();
    let mut unparsed = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        let metadata_end = nul(bytes, offset);
        let name_end = metadata_end.and_then(|index| nul(bytes, index + 1));
        let target_end = name_end.and_then(|index| nul(bytes, index + 1));
        let Some(target_end) = target_end else {
            unparsed.push(describe(bytes.get(offset..).unwrap_or_default()));
            break;
        };
        let metadata_end = metadata_end.unwrap();
        let name_end = name_end.unwrap();
        let raw = &bytes[offset..target_end + 1];
        let Some(metadata) = std::str::from_utf8(&bytes[offset..metadata_end]).ok() else {
            unparsed.push(describe(raw));
            offset = target_end + 1;
            continue;
        };
        let Some(name) = std::str::from_utf8(&bytes[metadata_end + 1..name_end]).ok() else {
            unparsed.push(describe(raw));
            offset = target_end + 1;
            continue;
        };
        let Some(target) = std::str::from_utf8(&bytes[name_end + 1..target_end]).ok() else {
            unparsed.push(describe(raw));
            offset = target_end + 1;
            continue;
        };
        match parse_entry(metadata, name, target) {
            Some(entry) => {
                if entries.len() >= MAX_ENTRIES {
                    return Err(resource("directory entry count exceeds the limit"));
                }
                entries.push(entry);
            }
            None => unparsed.push(String::from_utf8_lossy(raw).into_owned()),
        }
        offset = target_end + 1;
    }
    Ok((entries, unparsed))
}

fn parse_entry(metadata: &str, name: &str, target: &str) -> Option<Value> {
    let mut fields = metadata.splitn(5, '|');
    let permissions = fields.next()?;
    let owner = fields.next()?;
    let group = fields.next()?;
    let bytes = fields.next()?.parse::<u64>().ok()?;
    let date = fields.next()?;
    if permissions.len() != 10
        || name.is_empty()
        || name.contains('/')
        || owner.is_empty()
        || group.is_empty()
        || date.is_empty()
        || bytes > MAX_SAFE_INTEGER
        || [owner, group, date]
            .iter()
            .any(|field| field.bytes().any(|byte| byte == b'|' || byte == b'\n'))
    {
        return None;
    }
    let permission_bytes = permissions.as_bytes();
    if !matches!(
        permission_bytes[0] as char,
        'b' | 'c' | 'd' | 'l' | 'p' | 's' | '-'
    ) || permission_bytes[1..]
        .iter()
        .any(|byte| !matches!(*byte as char, 'r' | 'w' | 'x' | 's' | 't' | 'S' | 'T' | '-'))
    {
        return None;
    }
    let mode = permission_bytes.first().copied()? as char;
    if !matches!(mode, 'b' | 'c' | 'd' | 'l' | 'p' | 's' | '-')
        || (mode == 'l') != !target.is_empty()
    {
        return None;
    }
    let kind = match mode {
        'd' => "directory",
        'l' => "symlink",
        '-' => "file",
        _ => "other",
    };
    Some(json!({
        "name": name,
        "kind": kind,
        "permissions": permissions,
        "owner": owner,
        "group": group,
        "bytes": bytes,
        "date": date,
        "link_target": if mode == 'l' { Value::String(target.into()) } else { Value::Null },
    }))
}

fn nul(bytes: &[u8], from: usize) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|index| from + index)
}
fn describe(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => format!("Invalid UTF-8 directory record (hex): {}", hex(bytes)),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn required_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{key} must be a non-empty string")))
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.iter().any(|allowed| field.as_str() == *allowed))
    {
        return Err(invalid(format!("unsupported input field: {field}")));
    }

    Ok(())
}

fn validate_serial(serial: &str) -> Result<(), Failure> {
    if serial.len() > 256
        || serial.bytes().any(|byte| {
            byte.is_ascii_whitespace() || byte == b'\0' || byte == b'"' || byte == b'\''
        })
    {
        return Err(invalid("serial contains whitespace, quotes, or NUL"));
    }
    Ok(())
}
fn validate_device_path(path: &str) -> Result<(), Failure> {
    if !path.starts_with('/') || path.bytes().any(|byte| byte == 0) {
        return Err(invalid("device_path must be absolute and contain no NUL"));
    }
    Ok(())
}
fn invalid(message: impl Into<String>) -> Failure {
    failure(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "correct the captured directory request",
    )
}
fn resource(message: impl Into<String>) -> Failure {
    failure(
        "resource_limit",
        "resource",
        message.into(),
        false,
        "provide a bounded captured directory output",
    )
}
fn failure(
    code: &'static str,
    category: &'static str,
    message: String,
    retryable: bool,
    action: &'static str,
) -> Failure {
    Failure::new(
        code,
        category,
        message,
        retryable,
        action.into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
