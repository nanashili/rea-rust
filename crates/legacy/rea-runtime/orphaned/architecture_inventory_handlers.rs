//! Offline adapter for list_architectures.
//!
//! The application producer validates architecture facts and retained
//! provenance. This adapter admits only a caller-supplied static result or a
//! complete retained Evidence record; it never invokes lipo or inspects a
//! target itself.

use rea_application::native::architecture_inventory;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_rust_analysis::macho;
use serde_json::{Value, json};
use std::collections::BTreeMap;

/// Project caller-supplied architecture facts through the shared producer.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Dispatch an already selected list_architectures request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;

    if let Some(evidence) = input.get("evidence") {
        return project_evidence(evidence);
    }

    if let Some(bytes) = input.get("bytes") {
        return project_bytes(bytes);
    }

    architecture_inventory::project(input)
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(&format!("Evidence is not valid JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(&error.to_string()))?;
    if !record.operation_matches(architecture_inventory::OPERATION) {
        return Err(integrity(
            "captured Evidence operation does not match list_architectures",
        ));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(&format!("Evidence result is invalid JSON: {error}")))?;
    architecture_inventory::validate_input(&result)?;

    Ok(json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("list_architectures input must be an object"))?;

    let has_source = [
        "evidence",
        "result",
        "normalized_result",
        "architectures",
        "bytes",
    ]
        .iter()
        .filter(|field| object.contains_key(**field))
        .count();
    if has_source != 1 {
        return Err(invalid(
            "provide exactly one retained Evidence or static architecture result",
        ));
    }

    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "evidence" | "result" | "normalized_result" | "architectures" | "provenance" | "limitations" | "bytes"
        )
    }) {
        return Err(invalid("list_architectures input contains an unknown field"));
    }

    Ok(())
}

fn project_bytes(value: &Value) -> Result<Value, Failure> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("bytes must be an array of integers"))?;
    if values.len() > 256 * 1024 * 1024 {
        return Err(invalid("bytes exceed the static capture limit"));
    }
    let bytes = values
        .iter()
        .map(|value| {
            let byte = value
                .as_u64()
                .filter(|value| *value <= u8::MAX as u64)
                .ok_or_else(|| invalid("bytes must contain integers from 0 through 255"))?;
            Ok(byte as u8)
        })
        .collect::<Result<Vec<_>, Failure>>()?;
    let slices = macho::architectures(&bytes)
        .map_err(|error| invalid(&format!("static architecture bytes are invalid: {error}")))?;
    let exhaustive = slices.iter().all(|slice| slice.valid);
    let mut limitations = Vec::new();
    if !exhaustive {
        limitations.push("One or more architecture slices extend beyond the supplied bytes.".to_owned());
    }
    let items = slices
        .into_iter()
        .map(|slice| {
            let cpu_subtype_base = slice.cpu_subtype & 0x00ff_ffff;
            json!({
                "name": slice.name,
                "cpu_type": slice.cpu_name,
                "cpu_subtype": slice.cpu_subtype_name,
                "cpu_type_code": slice.cpu,
                "cpu_subtype_code": slice.cpu_subtype,
                "cpu_subtype_base": cpu_subtype_base,
                "capabilities": null,
                "file_offset": slice.file_offset,
                "size": slice.size,
                "alignment": slice.alignment,
            })
        })
        .collect::<Vec<_>>();
    let total = items.len();
    Ok(json!({
        "architectures": {
            "items": items,
            "total": total,
            "exhaustive": exhaustive,
            "limitations": limitations,
        },
        "provenance": [],
        "limitations": [
            "Architecture facts were decoded from caller-supplied bytes without invoking a provider or executing the target."
        ],
    }))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained list_architectures Evidence or caller-supplied static architecture facts.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(architecture_inventory::OPERATION.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn integrity(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "evidence_integrity",
        reason.into(),
        false,
        "Provide authenticated list_architectures Evidence with a matching operation and valid result.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(architecture_inventory::OPERATION.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}
