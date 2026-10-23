//! Authenticated comparison of JavaScript application graph versions.

mod change_graph;
mod graph;
mod items;
mod matching;
mod projection;

use crate::ledger::artifact_records::ArtifactRecords;
use graph::{ApplicationEvidence, VersionSource};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "compare_application_versions";

/// Validate the public request shape before looking up retained Evidence.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let request = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    for key in request.keys() {
        if !matches!(
            key.as_str(),
            "left" | "right" | "left_native_observations" | "right_native_observations"
        ) {
            return Err(invalid("input", "Unexpected comparison input field"));
        }
    }

    validate_source_reference(request.get("left"), "left")?;
    validate_source_reference(request.get("right"), "right")?;

    let left_id = evidence_input_id(request.get("left"), "left")?;
    let right_id = evidence_input_id(request.get("right"), "right")?;
    if left_id == right_id {
        return Err(invalid(
            "right",
            "Application version Evidence must be distinct",
        ));
    }

    validate_native_observations(
        request.get("left_native_observations"),
        "left_native_observations",
    )?;
    validate_native_observations(
        request.get("right_native_observations"),
        "right_native_observations",
    )?;

    Ok(())
}

/// Authenticate source Evidence, compare its owned graph facts, and create derived Evidence.
pub fn compare(
    input: &Value,
    records: Option<&ArtifactRecords>,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    validate_input(input)?;

    let request = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    let left = graph::parse_application_source(
        resolve_source(request.get("left"), records, "left")?,
        "left",
    )?;
    let right = graph::parse_application_source(
        resolve_source(request.get("right"), records, "right")?,
        "right",
    )?;
    let left_native = parse_native_observations(
        request.get("left_native_observations"),
        "left_native_observations",
    )?;
    let right_native = parse_native_observations(
        request.get("right_native_observations"),
        "right_native_observations",
    )?;

    let result = projection::compare_versions(&left, &right, &left_native, &right_native)?;

    create_comparison_evidence(&left, &right, &left_native, &right_native, result)
}

fn create_comparison_evidence(
    left: &VersionSource,
    right: &VersionSource,
    left_native: &[ApplicationEvidence],
    right_native: &[ApplicationEvidence],
    result: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parameters = json!({
        "left_evidence_id": left.evidence_id,
        "right_evidence_id": right.evidence_id,
        "left_native_evidence_ids": left_native.iter().map(|evidence| evidence.evidence_id.as_str()).collect::<Vec<_>>(),
        "right_native_evidence_ids": right_native.iter().map(|evidence| evidence.evidence_id.as_str()).collect::<Vec<_>>(),
    });
    let evidence_links = result
        .get("evidence_links")
        .cloned()
        .ok_or_else(|| invalid("result", "Comparison result omitted evidence_links"))?;
    let limitations = result
        .get("limitations")
        .cloned()
        .ok_or_else(|| invalid("result", "Comparison result omitted limitations"))?;
    let unsigned = json!({
        "subject": null,
        "provider": {
            "id": "rea-javascript-application-workflows",
            "name": "REA JavaScript application workflows",
            "version": "1"
        },
        "analysis_profile": null,
        "predicate_type": "rea.application-version-comparison",
        "operation": OPERATION,
        "parameters": parameters,
        "raw_result": null,
        "normalized_result": result,
        "confidence": "inferred",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": limitations,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": evidence_links,
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| invalid("result", &error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| invalid("result", &error.to_string()))?;

    serde_json::value::RawValue::from_string(evidence.raw().get().to_owned())
        .map_err(|error| invalid("result", &error.to_string()))
}

fn resolve_source(
    value: Option<&Value>,
    records: Option<&ArtifactRecords>,
    side: &str,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let value = value.ok_or_else(|| invalid(side, "Missing application Evidence input"))?;

    if value.get("kind").and_then(Value::as_str) == Some("retained-evidence") {
        let evidence_id = evidence_input_id(Some(value), side)?;
        let records = records
            .ok_or_else(|| invalid(side, "Evidence reference is not retained in this session"))?;
        let retained = records.find_raw(evidence_id).map_err(|error| {
            Failure::new(
                "evidence_integrity_mismatch",
                "integrity_mismatch",
                "Retained Evidence could not be read from this session.".into(),
                true,
                "Check the retained Evidence ledger, then retry the comparison.".into(),
                BTreeMap::from([
                    ("operation", Detail::Text(OPERATION.into())),
                    ("side", Detail::Text(side.into())),
                    ("reason", Detail::Text(error.to_string())),
                ]),
            )
        })?;
        return retained
            .ok_or_else(|| invalid(side, "Evidence reference is not retained in this session"));
    }

    serde_json::value::to_raw_value(value).map_err(|error| invalid(side, &error.to_string()))
}

fn parse_native_observations(
    value: Option<&Value>,
    path: &str,
) -> Result<Vec<ApplicationEvidence>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let observations = value
        .as_array()
        .ok_or_else(|| invalid(path, "Expected an array"))?;

    observations
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let raw = serde_json::value::to_raw_value(value)
                .map_err(|error| invalid(path, &error.to_string()))?;
            let record = EvidenceRecord::parse(&raw)
                .map_err(|error| graph::integrity_error(path, index, error))?;
            let subject_digest = record
                .subject_sha256()
                .ok_or_else(|| {
                    invalid(path, "Native handoff Evidence requires an artifact subject")
                })?
                .to_owned();
            Ok(ApplicationEvidence {
                evidence_id: record.evidence_id().to_owned(),
                subject_digest,
            })
        })
        .collect()
}

fn validate_source_reference(value: Option<&Value>, path: &str) -> Result<(), Failure> {
    let value = value.ok_or_else(|| invalid(path, "Missing application Evidence input"))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid(path, "Expected an Evidence object or retained reference"))?;

    if value.get("kind").and_then(Value::as_str) == Some("retained-evidence") {
        if object.len() != 2 {
            return Err(invalid(
                path,
                "Retained Evidence reference has unexpected fields",
            ));
        }
        evidence_input_id(Some(value), path)?;
        return Ok(());
    }

    if value.get("evidence_id").and_then(Value::as_str).is_none() {
        return Err(invalid(
            path,
            "Expected complete Evidence or retained-evidence reference",
        ));
    }
    Ok(())
}

fn validate_native_observations(value: Option<&Value>, path: &str) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let observations = value
        .as_array()
        .ok_or_else(|| invalid(path, "Expected an array"))?;
    let mut evidence_ids = std::collections::BTreeSet::new();

    for observation in observations {
        let evidence_id = evidence_input_id(Some(observation), path)?;
        if !evidence_ids.insert(evidence_id) {
            return Err(invalid(path, "Native observations must be unique"));
        }
    }

    Ok(())
}

fn evidence_input_id<'a>(value: Option<&'a Value>, path: &str) -> Result<&'a str, Failure> {
    value
        .and_then(|value| value.get("evidence_id"))
        .and_then(Value::as_str)
        .filter(|identifier| is_prefixed_digest(identifier, "ev_"))
        .ok_or_else(|| invalid(path, "Evidence must include a valid evidence_id"))
}

fn is_prefixed_digest(identifier: &str, prefix: &str) -> bool {
    identifier.strip_prefix(prefix).is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn invalid(path: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Application version comparison input is invalid. Check the arguments and retry.".into(),
        false,
        "Provide two distinct authenticated application graph Evidence records and unique native observations.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
