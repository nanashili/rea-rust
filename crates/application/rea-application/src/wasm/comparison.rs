//! Comparison of authenticated WASM interface facts retained in Evidence.

use crate::ledger::artifact_records::ArtifactRecords;
use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "compare_wasm_interfaces";
const CAPACITY_BYTES: usize = 32 * 1024 * 1024;

pub fn compare(
    input: &Value,
    records: Option<&ArtifactRecords>,
    cancellation: &Cancellation,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .filter(|value| matches!(*value, "imports" | "exports" | "both"))
        .ok_or_else(|| invalid("scope", "Expected imports, exports or both"))?;
    let left = resolve_source(object.get("left"), records)?;
    let right = resolve_source(object.get("right"), records)?;
    let left_record = EvidenceRecord::parse(&left).map_err(|error| integrity("left", error))?;
    let right_record = EvidenceRecord::parse(&right).map_err(|error| integrity("right", error))?;
    ensure_inspection(&left_record, "left")?;
    ensure_inspection(&right_record, "right")?;
    let left_report: Value = serde_json::from_str(left_record.normalized_result().get())
        .map_err(|error| invalid("left", &error.to_string()))?;
    let right_report: Value = serde_json::from_str(right_record.normalized_result().get())
        .map_err(|error| invalid("right", &error.to_string()))?;
    validate_artifact_identity(&left_record, &left_report, "left")?;
    validate_artifact_identity(&right_record, &right_report, "right")?;
    let left_artifact = artifact(&left_report, "left")?;
    let right_artifact = artifact(&right_report, "right")?;
    validate_interface_report(&left_report, "left")?;
    validate_interface_report(&right_report, "right")?;
    let left_interface = interface(&left_report)?;
    let right_interface = interface(&right_report)?;
    let left_entries = selected_entries(left_interface, scope);
    let right_entries = selected_entries(right_interface, scope);

    let mut groups: BTreeMap<(String, Option<String>, String), (Vec<Value>, Vec<Value>)> =
        BTreeMap::new();
    let mut work = 0_usize;
    for (side, entries) in [(&mut 0_u8, left_entries), (&mut 1_u8, right_entries)] {
        for entry in entries {
            work += 1;
            if work % 256 == 0 && cancellation.reason().is_some() {
                return Err(cancelled());
            }
            let key = (
                entry
                    .get("direction")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                entry
                    .get("module")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
            );
            let group = groups.entry(key).or_default();
            if *side == 0 {
                group.0.push(entry);
            } else {
                group.1.push(entry);
            }
        }
    }

    let mut changes = Vec::new();
    let mut summary = BTreeMap::from([
        ("added", 0_u64),
        ("removed", 0),
        ("changed", 0),
        ("unchanged", 0),
        ("unknown", 0),
    ]);
    let left_complete = interface_complete(left_interface);
    let right_complete = interface_complete(right_interface);
    let mut represented = 0_usize;
    for ((direction, module, name), (left, right)) in groups {
        represented = represented.saturating_add(
            512 + left.iter().map(entry_representation_bytes).sum::<usize>()
                + right.iter().map(entry_representation_bytes).sum::<usize>(),
        );
        if represented > CAPACITY_BYTES {
            return Err(Failure::new(
                "resource_constraint",
                "resource_constraint",
                "WASM comparison exceeds typed interface representation capacity".into(),
                false,
                "Select smaller interface Evidence or compare fewer interface directions.".into(),
                BTreeMap::from([
                    ("operation", Detail::Text(OPERATION.into())),
                    ("resource", Detail::Text("capacity".into())),
                    ("maximum_bytes", Detail::Count(CAPACITY_BYTES as u64)),
                ]),
            ));
        }
        work += 1;
        if work % 256 == 0 && cancellation.reason().is_some() {
            return Err(cancelled());
        }
        let l = left.first();
        let r = right.first();
        let (state, reason) = if left.len() > 1 || right.len() > 1 {
            (
                "unknown",
                Some("Duplicate interface names are ambiguous; all occurrences retained"),
            )
        } else if !left_complete || !right_complete {
            (
                "unknown",
                Some(
                    "Incomplete interface inventories cannot establish per-key uniqueness or absence",
                ),
            )
        } else if [l, r].iter().flatten().any(|entry| {
            entry.get("signature").is_none_or(Value::is_null)
                || entry.get("issue").is_some_and(|v| !v.is_null())
                || entry.get("kind").and_then(Value::as_str) == Some("unknown")
        }) {
            (
                "unknown",
                Some("Signature/type semantics were not admitted for every present entry"),
            )
        } else if l.is_none() {
            ("added", None)
        } else if r.is_none() {
            ("removed", None)
        } else if l.and_then(|v| v.get("kind")) != r.and_then(|v| v.get("kind"))
            || l.and_then(|v| v.get("signature")) != r.and_then(|v| v.get("signature"))
        {
            ("changed", None)
        } else {
            ("unchanged", None)
        };
        *summary.get_mut(state).expect("comparison state") += 1;
        changes.push(json!({"direction": direction, "module": module, "name": name, "state": state, "left": left, "right": right, "reason": reason}));
    }
    let coverage = if left_interface.is_none() && right_interface.is_none() {
        "unknown"
    } else if !left_complete || !right_complete || summary["unknown"] > 0 {
        "partial"
    } else {
        "complete-within-inputs"
    };
    let report = json!({
        "left": {"evidence_id": left_record.evidence_id(), "artifact": left_artifact},
        "right": {"evidence_id": right_record.evidence_id(), "artifact": right_artifact},
        "scope": scope, "coverage": coverage, "changes": changes, "summary": summary,
        "limitations": ["Exact declared interface equality is not runtime/ABI compatibility, successful linking or original-source identity.", "Typed facts come from selected validated WASM decoding; unsupported signature semantics and duplicate names remain unknown."]
    });
    let unsigned = json!({
        "subject": null,
        "provider": {"id":"rea-artifact-comparison","name":"REA artifact comparison","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.wasm-interface-comparison",
        "operation":OPERATION,
        "parameters":{"left_evidence_id":left_record.evidence_id(),"right_evidence_id":right_record.evidence_id(),"scope":scope},
        "raw_result":null,"normalized_result":report,"confidence":"derived","authority":"analyst-inference","environment":null,"limitations":[],"relationship_coverage":null,"locations":[],"evidence_links":[left_record.evidence_id(),right_record.evidence_id()]
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| invalid("input", &error.to_string()))?;
    let output =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| integrity("result", error))?;
    Ok(
        serde_json::value::RawValue::from_string(output.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
}

fn resolve_source(
    value: Option<&Value>,
    records: Option<&ArtifactRecords>,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let value = value.ok_or_else(|| invalid("source", "Missing Evidence input"))?;
    if value.get("kind").and_then(Value::as_str) == Some("retained-evidence") {
        let id = value
            .get("evidence_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("evidence_id", "Missing retained Evidence identifier"))?;
        return records
            .and_then(|records| records.find_raw(id).ok().flatten())
            .ok_or_else(|| {
                invalid(
                    "evidence_id",
                    "Evidence reference is not retained in this session",
                )
            });
    }
    if value.get("evidence_id").and_then(Value::as_str).is_some() {
        return Ok(serde_json::value::to_raw_value(value)
            .map_err(|e| invalid("source", &e.to_string()))?);
    }
    Err(invalid(
        "source",
        "Expected complete Evidence or retained-evidence reference",
    ))
}
fn ensure_inspection(record: &EvidenceRecord, side: &str) -> Result<(), Failure> {
    if !record.operation_matches("inspect_wasm_artifact") {
        return Err(invalid(side, "Expected inspect_wasm_artifact Evidence"));
    }
    if record.predicate_type().get() != "\"rea.wasm-artifact\"" {
        return Err(invalid(side, "Expected rea.wasm-artifact Evidence"));
    }
    let raw: Value =
        serde_json::from_str(record.raw().get()).map_err(|error| integrity(side, error))?;
    let subject = raw
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(side, "WASM Evidence must identify its selected file"))?;
    let parameters = raw
        .get("parameters")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(side, "WASM Evidence is missing parameters"))?;
    let subject_path = subject.get("local_path").and_then(Value::as_str);
    let subject_digest = subject
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    let parameter_path = parameters.get("path").and_then(Value::as_str);
    if subject.get("format").and_then(Value::as_str) != Some("file")
        || subject_path.is_none()
        || subject_digest.is_none()
        || parameter_path != subject_path
    {
        return Err(invalid(
            side,
            "WASM Evidence subject and selected path are inconsistent",
        ));
    }
    Ok(())
}
fn artifact(report: &Value, side: &str) -> Result<Value, Failure> {
    report
        .get("artifact")
        .cloned()
        .filter(|v| v.is_object())
        .ok_or_else(|| invalid(side, "Missing WASM artifact identity"))
}

fn validate_artifact_identity(
    record: &EvidenceRecord,
    report: &Value,
    side: &str,
) -> Result<(), Failure> {
    let artifact = artifact(report, side)?;
    let raw: Value =
        serde_json::from_str(record.raw().get()).map_err(|error| integrity(side, error))?;
    let subject = raw
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(side, "WASM Evidence is missing its subject"))?;
    let subject_path = subject.get("local_path").and_then(Value::as_str);
    let subject_digest = subject
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    if artifact.get("path").and_then(Value::as_str) != subject_path
        || artifact.get("sha256").and_then(Value::as_str) != subject_digest
    {
        return Err(invalid(
            side,
            "WASM Evidence subject does not match normalized artifact identity",
        ));
    }
    Ok(())
}
fn interface(report: &Value) -> Result<Option<&Map<String, Value>>, Failure> {
    Ok(report.get("interface").and_then(Value::as_object))
}
fn interface_complete(interface: Option<&Map<String, Value>>) -> bool {
    interface
        .and_then(|v| v.get("state"))
        .and_then(Value::as_str)
        == Some("complete")
}
fn selected_entries(interface: Option<&Map<String, Value>>, scope: &str) -> Vec<Value> {
    interface
        .and_then(|v| v.get("entries"))
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter(|entry| {
                    scope == "both"
                        || entry.get("direction").and_then(Value::as_str)
                            == Some(if scope == "imports" {
                                "import"
                            } else {
                                "export"
                            })
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn validate_interface_report(report: &Value, side: &str) -> Result<(), Failure> {
    let Some(interface) = report.get("interface") else {
        return Ok(());
    };
    let object = interface
        .as_object()
        .ok_or_else(|| invalid(side, "WASM interface must be an object"))?;
    let state = object
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(side, "WASM interface omitted state"))?;
    if !matches!(state, "complete" | "partial") {
        return Err(invalid(side, "WASM interface state is invalid"));
    }
    if !object.get("issues").is_some_and(Value::is_array) {
        return Err(invalid(side, "WASM interface omitted issues"));
    }
    let entries = object
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(side, "WASM interface omitted entries"))?;
    for entry in entries {
        let entry = entry
            .as_object()
            .ok_or_else(|| invalid(side, "WASM interface entry must be an object"))?;
        let direction = entry
            .get("direction")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(side, "WASM interface entry omitted direction"))?;
        let module = entry.get("module");
        if !matches!(direction, "import" | "export")
            || (direction == "import" && !module.is_some_and(Value::is_string))
            || (direction == "export" && !module.is_some_and(Value::is_null))
        {
            return Err(invalid(side, "WASM interface entry direction is invalid"));
        }
        if entry.get("name").and_then(Value::as_str).is_none()
            || entry.get("wat_form").and_then(Value::as_str).is_none()
            || !entry
                .get("index")
                .is_some_and(|value| value.is_number() || value.is_null())
            || !entry
                .get("issue")
                .is_some_and(|value| value.is_string() || value.is_null())
        {
            return Err(invalid(side, "WASM interface entry is incomplete"));
        }
        let kind = entry
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(side, "WASM interface entry omitted kind"))?;
        if !matches!(
            kind,
            "func" | "table" | "memory" | "global" | "tag" | "unknown"
        ) {
            return Err(invalid(side, "WASM interface entry kind is invalid"));
        }
        let signature = entry
            .get("signature")
            .ok_or_else(|| invalid(side, "WASM interface entry omitted signature"))?;
        if kind == "unknown" && !signature.is_null() {
            return Err(invalid(
                side,
                "Unknown WASM interface entries cannot have signatures",
            ));
        }
        if !signature.is_null() && signature.get("kind").and_then(Value::as_str) != Some(kind) {
            return Err(invalid(
                side,
                "WASM interface signature kind disagrees with entry kind",
            ));
        }
    }
    Ok(())
}

fn entry_representation_bytes(entry: &Value) -> usize {
    let mut bytes = 1024_usize;
    for field in ["module", "name", "wat_form", "issue"] {
        if let Some(value) = entry.get(field).and_then(Value::as_str) {
            bytes = bytes.saturating_add(value.len().saturating_mul(6));
        }
    }
    if let Some(signature) = entry.get("signature").filter(|value| !value.is_null()) {
        if matches!(
            signature.get("kind").and_then(Value::as_str),
            Some("func" | "tag")
        ) {
            for field in ["params", "results"] {
                bytes = bytes.saturating_add(
                    signature
                        .get(field)
                        .and_then(Value::as_array)
                        .map_or(0, |values| values.len().saturating_mul(16)),
                );
            }
        } else if let Some(object) = signature.as_object() {
            for value in object.values() {
                if let Some(value) = value.as_str() {
                    bytes = bytes.saturating_add(value.len().saturating_mul(6));
                }
            }
        }
    }
    bytes
}

fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis input is invalid. Check the arguments and retry.".into(),
        false,
        "Correct the listed arguments and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
fn integrity(side: &str, error: impl std::fmt::Display) -> Failure {
    Failure::new(
        "evidence_integrity_mismatch",
        "integrity_mismatch",
        "Evidence is invalid or has changed. Recreate or re-import it, then try again.".into(),
        false,
        "Recreate or re-import the Evidence, then retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("side", Detail::Text(side.into())),
            ("reason", Detail::Text(error.to_string())),
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
