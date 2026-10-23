//! Bounded discovery of the field and protocol glossary emitted by TShark.
//!
//! The parser deliberately retains producer order, duplicate registrations, and
//! one-based source lines.  A page is a view over the complete examined glossary;
//! it is never treated as proof that an omitted registration is absent.

use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, env, path::Path, process::Command};

pub const OPERATION: &str = "inspect_packet_fields";
const PROVIDER_ID: &str = "tshark-capture";
const PROVIDER_NAME: &str = "REA TShark capture adapter";
const PROVIDER_VERSION: &str = "tshark@4";
const GLOSSARY_OUTPUT_LIMIT: usize = 32 * 1024 * 1024;
const RECORD_BUDGET: usize = 8 * 1024 * 1024;
const ADDRESS_SPACE_BYTES: usize = 1024 * 1024 * 1024;
const FILE_BYTES: usize = 64 * 1024 * 1024;
const CPU_SECONDS: usize = 30;

#[derive(Debug, Clone)]
struct Selection {
    protocols: bool,
    protocol: Option<String>,
    query: String,
    offset: usize,
    limit: Option<usize>,
}

/// Parse a TShark `-G fields` glossary without retaining the producer string.
///
/// This is public so the adapter can use an already captured producer response
/// in tests or in a host that owns subprocess supervision.  The returned value
/// contains only the selected page and exact source line numbers.
pub fn parse_glossary(input: &Value, glossary: &str) -> Result<Value, Failure> {
    if glossary.is_empty() {
        return Err(invalid(
            "glossary",
            "TShark returned an empty field glossary",
        ));
    }
    if glossary.len() > GLOSSARY_OUTPUT_LIMIT {
        return Err(resource());
    }
    if glossary.contains('\0') {
        return Err(invalid("glossary", "TShark glossary contains a NUL byte"));
    }
    let selection = parse_selection(input)?;
    let query = selection.query.to_lowercase();
    let mut records = Vec::new();
    let mut examined = 0_usize;
    let mut matching = 0_usize;
    let mut source_line = 0_usize;
    let mut retained_bytes = 0_usize;

    for raw_line in glossary.split_inclusive('\n') {
        source_line = source_line.saturating_add(1);
        let line = raw_line.trim_end_matches(['\n', '\r']);
        let columns = line.splitn(9, '\t').collect::<Vec<_>>();
        let (kind, name, abbreviation) = match columns.as_slice() {
            [tag, name, abbreviation] if *tag == "P" => ("protocol", *name, *abbreviation),
            [
                tag,
                name,
                abbreviation,
                field_type,
                parent,
                base,
                mask,
                description,
            ] if *tag == "F" => {
                let _ = (field_type, parent, base, mask, description);
                ("field", *name, *abbreviation)
            }
            _ => return Err(malformed(source_line)),
        };
        if abbreviation.is_empty() {
            return Err(malformed(source_line));
        }
        if (selection.protocols && kind != "protocol") || (!selection.protocols && kind != "field")
        {
            continue;
        }
        examined = examined.saturating_add(1);
        if let Some(protocol) = &selection.protocol {
            let parent = columns.get(4).copied();
            let selected_protocol = if kind == "protocol" {
                abbreviation
            } else {
                parent.unwrap_or_default()
            };
            if selected_protocol != protocol {
                continue;
            }
        }
        let description = columns.get(7).copied().unwrap_or_default();
        if ![name, abbreviation, description]
            .iter()
            .any(|value| value.to_lowercase().contains(&query))
        {
            continue;
        }
        matching = matching.saturating_add(1);
        if matching <= selection.offset
            || selection.limit.is_some_and(|limit| records.len() >= limit)
        {
            continue;
        }
        retained_bytes =
            retained_bytes.saturating_add(line.len().saturating_mul(6).saturating_add(512));
        if retained_bytes > RECORD_BUDGET {
            return Err(resource());
        }
        records.push(json!({
            "source_line": source_line,
            "kind": kind,
            "name": name,
            "abbreviation": abbreviation,
            "field_type": (kind == "field").then(|| columns[3]),
            "parent_protocol": (kind == "field").then(|| columns[4]),
            "display_base": (kind == "field").then(|| columns[5]),
            "bitmask": (kind == "field").then(|| columns[6]),
            "description": (kind == "field").then(|| columns[7]),
        }));
    }

    if source_line == 0 {
        return Err(invalid(
            "glossary",
            "TShark returned an empty field glossary",
        ));
    }
    let returned = records.len();
    let remaining = matching.saturating_sub(selection.offset);
    Ok(json!({
        "selection": selection_json(&selection),
        "records": records,
        "output_window": {
            "examined": examined,
            "matching": matching,
            "returned": returned,
            "has_more": remaining > returned,
        },
    }))
}

/// Run the configured, caller-supplied TShark under util-linux `prlimit`.
pub fn inspect(
    input: &Value,
    cancellation: &Cancellation,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    if cancellation.reason().is_some() {
        return Err(cancelled());
    }
    if !cfg!(target_os = "linux") {
        return Err(unavailable("Packet field discovery requires Linux."));
    }
    let command = configured_executable("REA_TSHARK_COMMAND", "TShark")?;
    let limiter =
        configured_executable_with_default("REA_TSHARK_PRLIMIT_COMMAND", "/usr/bin/prlimit")?;
    let version = run(&limiter, &command, &["--version"])?;
    let version_banner = String::from_utf8_lossy(&version.stdout).into_owned();
    if !is_tshark4(&version_banner) {
        return Err(unavailable("Configured TShark must report version 4.x."));
    }
    let glossary = run(&limiter, &command, &["-G", "fields"])?;
    if cancellation.reason().is_some() {
        return Err(cancelled());
    }
    let glossary_text = String::from_utf8(glossary.stdout)
        .map_err(|_| invalid("producer", "TShark glossary was not UTF-8"))?;
    let mut report = parse_glossary(input, &glossary_text)?;
    let object = report
        .as_object_mut()
        .ok_or_else(|| invalid("result", "Parsed glossary was not an object"))?;
    object.insert(
        "diagnostics".into(),
        Value::String(String::from_utf8_lossy(&glossary.stderr).into_owned()),
    );
    object.insert(
        "tool".into(),
        json!({
            "configured_path": command,
            "path": command,
            "sha256": sha256_file(&command)?,
            "version_banner": version_banner,
            "version_diagnostics": String::from_utf8_lossy(&version.stderr),
            "arguments": ["-G", "fields"],
        }),
    );
    object.insert(
        "resource_limiter".into(),
        json!({
            "configured_path": limiter,
            "path": limiter,
            "sha256": sha256_file(&limiter)?,
            "arguments": prlimit_arguments(&command),
        }),
    );
    object.insert(
        "limits".into(),
        json!({
            "input_bytes": 32 * 1024 * 1024_u64,
            "output_bytes": GLOSSARY_OUTPUT_LIMIT,
            "command_timeout_ms": 30_000,
            "address_space_bytes": ADDRESS_SPACE_BYTES,
            "file_bytes": FILE_BYTES,
            "cpu_seconds": CPU_SECONDS,
            "record_budget_bytes": RECORD_BUDGET,
        }),
    );
    object.insert(
        "configuration".into(),
        Value::String("private-empty-personal-profile".into()),
    );
    object.insert(
        "hardware_acquisition".into(),
        Value::String("not-performed".into()),
    );
    let unsigned = json!({
        "subject": null,
        "provider": {"id": PROVIDER_ID, "name": PROVIDER_NAME, "version": PROVIDER_VERSION},
        "analysis_profile": null,
        "predicate_type": "rea.packet-field-catalog",
        "operation": OPERATION,
        "parameters": input,
        "raw_result": null,
        "normalized_result": report,
        "confidence": "observed",
        "authority": "shipped-tool",
        "environment": null,
        "limitations": [
            "Registrations describe the selected TShark installation, not traffic observed in a capture.",
            "Duplicate abbreviations remain distinct records and source lines; omitted registrations remain unknown.",
            "No capture file, interface, device or target process was opened.",
            "The producer is caller-supplied and identified by digest; digest does not establish publisher authenticity.",
        ],
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": [],
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| invalid("result", &error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| invalid("result", &error.to_string()))?;
    Ok(serde_json::value::RawValue::from_string(evidence.raw().get().to_owned()).unwrap())
}

fn parse_selection(input: &Value) -> Result<Selection, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "kind" | "protocol" | "query" | "offset" | "limit"
        ) {
            return Err(invalid(key, "Unknown selection field"));
        }
    }
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("protocols");
    let protocols = match kind {
        "protocols" => true,
        "fields" => false,
        _ => return Err(invalid("kind", "Expected protocols or fields")),
    };
    let protocol = match object.get("protocol") {
        None | Some(Value::Null) => None,
        Some(value) => {
            let protocol = value
                .as_str()
                .ok_or_else(|| invalid("protocol", "Expected a string or null"))?;
            if protocol.is_empty() || protocol.len() > 8192 {
                return Err(invalid(
                    "protocol",
                    "Expected a non-empty string up to 8192 bytes",
                ));
            }
            Some(protocol.to_owned())
        }
    };
    let query = object.get("query").and_then(Value::as_str).unwrap_or("");
    if query.len() > 8192 {
        return Err(invalid("query", "Expected at most 8192 bytes"));
    }
    let query = query.to_owned();
    let offset = checked_usize(object.get("offset"), "offset", 0)?;
    let limit = match object.get("limit") {
        None | Some(Value::Null) => None,
        Some(value) => Some(checked_usize(Some(value), "limit", 50)?),
    };
    if limit == Some(0) {
        return Err(invalid("limit", "Expected a positive integer or null"));
    }
    if offset > 9_007_199_254_740_991 || limit.is_some_and(|value| value > 9_007_199_254_740_991) {
        return Err(invalid(
            "offset",
            "Expected an integer up to Number.MAX_SAFE_INTEGER",
        ));
    }
    Ok(Selection {
        protocols,
        protocol,
        query,
        offset,
        limit,
    })
}

fn checked_usize(value: Option<&Value>, field: &str, default: usize) -> Result<usize, Failure> {
    match value {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|number| usize::try_from(number).ok())
            .ok_or_else(|| invalid(field, "Expected a nonnegative integer")),
    }
}

fn selection_json(selection: &Selection) -> Value {
    json!({
        "kind": if selection.protocols { "protocols" } else { "fields" },
        "protocol": selection.protocol,
        "query": selection.query,
        "offset": selection.offset,
        "limit": selection.limit,
    })
}

fn configured_executable(name: &str, display: &str) -> Result<String, Failure> {
    let value =
        env::var(name).map_err(|_| unavailable(&format!("Configure {name} for {display}.")))?;
    configured_path(name, value)
}

fn configured_executable_with_default(name: &str, default: &str) -> Result<String, Failure> {
    configured_path(name, env::var(name).unwrap_or_else(|_| default.into()))
}

fn configured_path(name: &str, value: String) -> Result<String, Failure> {
    if !Path::new(&value).is_absolute() {
        return Err(invalid(name, "Expected an absolute executable path"));
    }
    if !Path::new(&value).is_file() {
        return Err(unavailable(
            "Configured packet inspection executable was not found.",
        ));
    }
    Ok(value)
}

fn run(limiter: &str, command: &str, arguments: &[&str]) -> Result<std::process::Output, Failure> {
    let output = Command::new(limiter)
        .args(prlimit_arguments(command))
        .args(arguments)
        .output()
        .map_err(|error| unavailable(&format!("Unable to run TShark through prlimit: {error}")))?;
    if output.stdout.len().saturating_add(output.stderr.len()) > GLOSSARY_OUTPUT_LIMIT {
        return Err(resource());
    }
    if !output.status.success() {
        return Err(unavailable("TShark returned a nonzero exit status."));
    }
    Ok(output)
}

fn prlimit_arguments(command: &str) -> Vec<String> {
    vec![
        format!("--as={ADDRESS_SPACE_BYTES}:{ADDRESS_SPACE_BYTES}"),
        format!("--fsize={FILE_BYTES}:{FILE_BYTES}"),
        format!("--cpu={CPU_SECONDS}:{CPU_SECONDS}"),
        "--core=0:0".into(),
        "--".into(),
        command.into(),
    ]
}

fn sha256_file(path: &str) -> Result<String, Failure> {
    let bytes = std::fs::read(path)
        .map_err(|error| unavailable(&format!("Unable to read configured executable: {error}")))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn is_tshark4(version: &str) -> bool {
    version.lines().any(|line| {
        let Some(version) = line.strip_prefix("TShark (Wireshark) ") else {
            return false;
        };
        version.starts_with("4.")
    })
}

fn malformed(line: usize) -> Failure {
    invalid(
        "glossary",
        &format!("Malformed TShark field glossary record at line {line}"),
    )
}

fn invalid(field: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and retry.".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text(field.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}

fn unavailable(message: &str) -> Failure {
    Failure::new(
        "capability_unavailable",
        "capability_unavailable",
        message.into(),
        true,
        "Configure Linux TShark 4.x and util-linux prlimit, then retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource() -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        "TShark field glossary exceeds its fixed representation budget.".into(),
        false,
        "Narrow the query or page size and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("maximum_bytes", Detail::Count(RECORD_BUDGET as u64)),
        ]),
    )
}

fn cancelled() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "The operation was cancelled before completion.".into(),
        false,
        "Retry the operation if the result is still needed.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
