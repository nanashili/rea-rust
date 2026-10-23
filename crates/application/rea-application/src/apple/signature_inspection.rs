//! Deterministic parsing of bounded `codesign -d --verbose=4` output.
//!
//! The runtime owns command execution and snapshot identity.  This module owns
//! the provider boundary: it parses the display stream, keeps ambiguous or
//! unavailable fields explicit, and never treats a signature as verified trust.

use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_signature";
pub const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_AUTHORITIES: usize = 4096;

/// Parse a codesign display stream into the portable signature result.
pub fn parse_codesign_output(
    output: &str,
    unsigned: bool,
    executable_paths: &[String],
    entitlements: Option<Value>,
    designated_requirement: Option<String>,
    provenance: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(resource(
            "codesign output exceeds the bounded parser capacity",
        ));
    }
    let (identifier, fields) = split_echoed_values(output, executable_paths);
    let mut values = BTreeMap::new();
    let mut authorities = Vec::new();
    let mut cdhashes = Vec::new();

    for line in fields.lines() {
        if let Some(value) = line.strip_prefix("CodeDirectory ") {
            values.insert("CodeDirectory", value.trim().to_owned());
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        if key == "Authority" {
            if authorities.len() >= MAX_AUTHORITIES {
                return Err(resource("authority count exceeds the parser bound"));
            }
            authorities.push(value.to_owned());
        } else if key == "CDHash" {
            cdhashes.push(value.to_owned());
        } else {
            values.insert(key, value.to_owned());
        }
    }
    if !provenance.is_array() {
        return Err(invalid("provenance", "Expected an invocation array"));
    }
    let runtime = values
        .get("CodeDirectory")
        .and_then(|value| parse_hardened_runtime(value));
    let result = json!({
        "signed": !unsigned,
        "identifier": identifier,
        "team_identifier": nullable(values.get("TeamIdentifier")),
        "format": values.get("Format"),
        "cdhashes": cdhashes,
        "hash_algorithms": split_algorithms(values.get("Hash choices")),
        "authorities": authorities,
        "designated_requirement": designated_requirement
            .or_else(|| values.get("designated").cloned()),
        "entitlements": entitlements,
        "timestamp": values.get("Timestamp"),
        "hardened_runtime": runtime,
        "provenance": provenance,
        "limitations": if unsigned {
            json!(["Artifact is not signed."])
        } else {
            json!(["Entitlements and designated requirements require separate bounded commands."])
        },
    });
    serde_json::value::to_raw_value(&result).map_err(|error| output_error(&error.to_string()))
}

/// Validate a supplied codesign capture or retained signature Evidence.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    if let Some(evidence) = object.get("evidence") {
        validate_evidence(evidence)
    } else {
        validate_capture(object)
    }
}

/// Parse a supplied codesign capture or project retained signature Evidence.
/// This handler never invokes codesign, accesses a path, or reads a file.
pub fn inspect(input: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    validate_input(input)?;

    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    parse_capture(object)
}

fn parse_capture(
    object: &serde_json::Map<String, Value>,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let output = object
        .get("output")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("output", "Expected captured codesign output"))?;
    if output.len() > MAX_OUTPUT_BYTES {
        return Err(resource(
            "codesign output exceeds the bounded parser capacity",
        ));
    }
    let unsigned = object
        .get("unsigned")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if object.get("unsigned").is_some() && object["unsigned"].as_bool().is_none() {
        return Err(invalid("unsigned", "Expected a boolean"));
    }
    let paths = object
        .get("executable_paths")
        .map(parse_executable_paths)
        .transpose()?
        .unwrap_or_default();
    let designated_requirement = match object.get("designated_requirement") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| invalid("designated_requirement", "Expected a string or null"))?
                .to_owned(),
        ),
    };
    let provenance = object
        .get("provenance")
        .cloned()
        .unwrap_or_else(|| json!([]));
    if !provenance.is_array() {
        return Err(invalid("provenance", "Expected an invocation array"));
    }
    parse_codesign_output(
        output,
        unsigned,
        &paths,
        object.get("entitlements").cloned(),
        designated_requirement,
        provenance,
    )
}

fn validate_capture(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "output"
                | "unsigned"
                | "executable_paths"
                | "entitlements"
                | "designated_requirement"
                | "provenance"
        ) {
            return Err(invalid(key, "Unknown field"));
        }
    }
    if object.get("output").and_then(Value::as_str).is_none() {
        return Err(invalid("output", "Expected captured codesign output"));
    }
    if let Some(value) = object.get("executable_paths") {
        let paths = value
            .as_array()
            .ok_or_else(|| invalid("executable_paths", "Expected an array"))?;
        if paths.len() > 4096 {
            return Err(resource(
                "executable_paths exceeds the bounded list capacity",
            ));
        }
        if paths.iter().any(|path| path.as_str().is_none()) {
            return Err(invalid("executable_paths", "Expected string paths"));
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("evidence", "Expected an object"))?;
    if object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid(
            "evidence.operation",
            "Expected inspect_signature Evidence",
        ));
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "evidence.evidence_id",
            "Expected a non-empty identifier",
        ));
    }
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid("evidence", &format!("Evidence is not valid JSON: {error}")))?;
    let authenticated = EvidenceRecord::parse(&raw).map_err(|error| {
        invalid(
            "evidence",
            &format!("Evidence authentication failed: {error}"),
        )
    })?;
    let result: Value =
        serde_json::from_str(authenticated.normalized_result().get()).map_err(|error| {
            invalid(
                "evidence.normalized_result",
                &format!("Invalid JSON: {error}"),
            )
        })?;
    validate_result(&result)
}

fn project_evidence(evidence: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| output_error(&error.to_string()))?;
    let authenticated = EvidenceRecord::parse(&raw).map_err(|error| {
        invalid(
            "evidence",
            &format!("Evidence authentication failed: {error}"),
        )
    })?;
    let result: Value = serde_json::from_str(authenticated.normalized_result().get())
        .map_err(|error| output_error(&error.to_string()))?;
    serde_json::value::to_raw_value(&result).map_err(|error| output_error(&error.to_string()))
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("normalized_result", "Expected an object"))?;
    const FIELDS: [&str; 13] = [
        "signed",
        "identifier",
        "team_identifier",
        "format",
        "cdhashes",
        "hash_algorithms",
        "authorities",
        "designated_requirement",
        "entitlements",
        "timestamp",
        "hardened_runtime",
        "provenance",
        "limitations",
    ];
    for field in FIELDS {
        if !object.contains_key(field) {
            return Err(invalid(
                "normalized_result",
                "Missing signature result field",
            ));
        }
    }
    if object.keys().any(|field| !FIELDS.contains(&field.as_str())) {
        return Err(invalid(
            "normalized_result",
            "Unexpected signature result field",
        ));
    }
    if !object["signed"].is_boolean()
        || !(object["identifier"].is_string() || object["identifier"].is_null())
        || !(object["team_identifier"].is_string() || object["team_identifier"].is_null())
        || !(object["format"].is_string() || object["format"].is_null())
        || !(object["designated_requirement"].is_string()
            || object["designated_requirement"].is_null())
        || !(object["timestamp"].is_string() || object["timestamp"].is_null())
        || !(object["hardened_runtime"].is_boolean() || object["hardened_runtime"].is_null())
        || !object["cdhashes"].is_array()
        || !object["hash_algorithms"].is_array()
        || !object["authorities"].is_array()
        || !object["provenance"].is_array()
        || !object["limitations"].is_array()
    {
        return Err(invalid(
            "normalized_result",
            "Signature result field has the wrong type",
        ));
    }
    for field in ["cdhashes", "hash_algorithms", "authorities", "limitations"] {
        if object[field]
            .as_array()
            .is_some_and(|values| values.iter().any(|value| !value.is_string()))
        {
            return Err(invalid(
                "normalized_result",
                "Signature result arrays must contain strings",
            ));
        }
    }
    Ok(())
}

fn parse_executable_paths(value: &Value) -> Result<Vec<String>, Failure> {
    let paths = value
        .as_array()
        .ok_or_else(|| invalid("executable_paths", "Expected an array"))?;

    paths
        .iter()
        .map(|path| {
            path.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("executable_paths", "Expected string paths"))
        })
        .collect()
}

fn split_echoed_values(text: &str, paths: &[String]) -> (Option<String>, String) {
    for path in paths {
        let prefix = format!("Executable={path}");
        if let Some(rest) = text.strip_prefix(&prefix) {
            if let Some((separator, rest)) = strip_record_separator(rest) {
                return split_identifier(rest, Some(separator));
            }
        }
    }

    if text.starts_with("Executable=") {
        if let Some(identifier) = text.find("\nIdentifier=") {
            return split_identifier(&text[identifier + 1..], None);
        }
    }

    (None, text.to_owned())
}

fn strip_record_separator(text: &str) -> Option<(&str, &str)> {
    if let Some(rest) = text.strip_prefix("\r\n") {
        return Some(("\r\n", rest));
    }

    text.strip_prefix('\n').map(|rest| ("\n", rest))
}

fn split_identifier(text: &str, known_separator: Option<&str>) -> (Option<String>, String) {
    let Some(text) = text.strip_prefix("Identifier=") else {
        return (None, text.to_owned());
    };

    let boundary = text
        .rfind("\nFormat=")
        .unwrap_or_else(|| text.find('\n').unwrap_or(text.len()));
    let separator = known_separator.unwrap_or("\r\n");
    let has_carriage_return = separator == "\r\n" && text[..boundary].ends_with('\r');
    let identifier_end = if has_carriage_return {
        boundary - 1
    } else {
        boundary
    };

    (
        Some(text[..identifier_end].to_owned()),
        text[boundary..].to_owned(),
    )
}

fn nullable(value: Option<&String>) -> Value {
    value
        .filter(|value| value.as_str() != "not set")
        .cloned()
        .map(Value::String)
        .unwrap_or(Value::Null)
}

fn split_algorithms(value: Option<&String>) -> Vec<String> {
    value
        .map(|value| {
            value
                .split(|character: char| {
                    character == ',' || character == '+' || character.is_whitespace()
                })
                .filter(|part| !part.is_empty())
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn parse_hardened_runtime(value: &str) -> Option<bool> {
    value.match_indices("flags=").find_map(|(flags_start, _)| {
        if flags_start > 0
            && !value[..flags_start]
                .chars()
                .next_back()
                .is_some_and(char::is_whitespace)
        {
            return None;
        }

        let flags = &value[flags_start + "flags=".len()..];
        let flags = flags.split_once('(')?.1.split_once(')')?.0;

        Some(flags.split(',').any(|flag| flag.trim() == "runtime"))
    })
}

fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Signature input is invalid".into(),
        false,
        "Correct the input and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}

fn output_error(message: &str) -> Failure {
    Failure::new(
        "provider_output_invalid",
        "provider_output_invalid",
        message.into(),
        true,
        "Review the provider output and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(message: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        message.into(),
        false,
        "Select a smaller bounded capture and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
