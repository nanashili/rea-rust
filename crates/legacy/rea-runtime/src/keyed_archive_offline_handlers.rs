//! Offline adapter for decoded NSKeyedArchiver facts.
//!
//! The caller owns acquisition, decoding, and Evidence retention. This adapter
//! only validates the retained identity and selection metadata before delegating
//! the object-table projection to the application producer.

use rea_application::apple::keyed_archive::{self, KeyedArchiveSelection};
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_keyed_archive";

pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input)?;
    validate_input_fields(object)?;
    let selection = selection(object)?;
    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 {
            return Err(invalid(
                "evidence input must contain only the evidence field",
            ));
        }
        let raw = serde_json::value::to_raw_value(evidence)
            .map_err(|error| integrity(&error.to_string()))?;
        let record = EvidenceRecord::parse(&raw).map_err(|error| integrity(&error.to_string()))?;
        if !record.operation_matches(OPERATION) {
            return Err(integrity(
                "captured Evidence operation does not match inspect_keyed_archive",
            ));
        }
        let result: Value = serde_json::from_str(record.normalized_result().get())
            .map_err(|error| integrity(&error.to_string()))?;
        if result.get("objects").is_some() && result.get("roots").is_some() {
            if selection.root.is_some() || selection.offset != 0 || selection.limit != 20_000 {
                return Err(invalid(
                    "selection cannot be applied to an already projected Evidence result; supply decoded archive facts",
                ));
            }
            return Ok(result.clone());
        }
    }
    let facts = archive_facts(object)?;

    keyed_archive::project_decoded_archive(
        facts.value,
        facts.target_sha256,
        facts.archive_path,
        facts.archive_sha256,
        facts.archive_format,
        &selection,
    )
}

struct ArchiveFacts<'a> {
    value: &'a Value,
    target_sha256: &'a str,
    archive_path: &'a str,
    archive_sha256: &'a str,
    archive_format: &'a str,
}

fn archive_facts<'a>(
    object: &'a serde_json::Map<String, Value>,
) -> Result<ArchiveFacts<'a>, Failure> {
    if let Some(evidence) = object.get("evidence") {
        let evidence = evidence
            .as_object()
            .ok_or_else(|| invalid("evidence must be an object"))?;
        let result = evidence
            .get("normalized_result")
            .or_else(|| evidence.get("result"))
            .ok_or_else(|| invalid("evidence must include normalized_result"))?;
        return facts_from_result(result);
    }

    let value = object
        .get("value")
        .ok_or_else(|| invalid("decoded archive value is required"))?;
    facts_from_fields(object, value)
}

fn facts_from_result(result: &Value) -> Result<ArchiveFacts<'_>, Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("normalized_result must be an object"))?;
    let value = object
        .get("value")
        .or_else(|| object.get("decoded_value"))
        .ok_or_else(|| invalid("normalized_result must include decoded value"))?;
    facts_from_fields(object, value)
}

fn facts_from_fields<'a>(
    object: &'a serde_json::Map<String, Value>,
    value: &'a Value,
) -> Result<ArchiveFacts<'a>, Failure> {
    let target_sha256 = required_digest(object, "target_sha256")?;
    let archive_path = required_text(object, "archive_path")?;
    if archive_path.contains('\0') {
        return Err(invalid("archive_path must not contain NUL"));
    }
    let archive_sha256 = required_digest(object, "archive_sha256")?;
    let archive_format = required_text(object, "archive_format")?;
    if !matches!(archive_format, "binary-plist" | "xml-plist") {
        return Err(invalid("archive_format must be binary-plist or xml-plist"));
    }
    Ok(ArchiveFacts {
        value,
        target_sha256,
        archive_path,
        archive_sha256,
        archive_format,
    })
}

fn selection(object: &serde_json::Map<String, Value>) -> Result<KeyedArchiveSelection, Failure> {
    let offset = match object.get("offset") {
        None => 0,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid("offset must be a non-negative integer"))?,
    };
    let limit = match object.get("limit") {
        None => 20_000,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid("limit must be a positive integer"))?,
    };
    let offset = usize::try_from(offset).map_err(|_| invalid("offset is too large"))?;
    let limit = usize::try_from(limit).map_err(|_| invalid("limit is too large"))?;
    if limit == 0 || limit > 20_000 {
        return Err(invalid("limit must be between 1 and 20000"));
    }
    let root = match object.get("root") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| invalid("root must be a string"))?
                .to_owned(),
        ),
    };
    Ok(KeyedArchiveSelection {
        root,
        offset,
        limit,
    })
}

fn validate_input_fields(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    let allowed = [
        "target_sha256",
        "archive_path",
        "archive_sha256",
        "archive_format",
        "value",
        "evidence",
        "root",
        "offset",
        "limit",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("input contains unknown field: {field}")));
    }
    if object.contains_key("evidence") && object.keys().any(|field| field.as_str() != "evidence") {
        return Err(invalid(
            "evidence cannot be combined with decoded archive fields",
        ));
    }
    Ok(())
}

fn input_object(input: &Value) -> Result<&serde_json::Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("inspect_keyed_archive input must be an object"))
}

fn required_text<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} is required")))
}

fn required_digest<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
    let value = required_text(object, field)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(&format!("{field} must be a SHA-256 digest")));
    }
    Ok(value)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide decoded keyed archive facts or retained Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.to_owned(),
        false,
        "Provide authenticated, intact inspect_keyed_archive Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
