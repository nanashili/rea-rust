//! Offline adapter for compare_web_screenshots.
//!
//! The application producer owns PNG validation and pixel metrics. This
//! boundary only selects caller-supplied screenshot observations (or
//! authenticated Evidence), extracts their inline artifacts, and retains the
//! selected identities and source limitations. It never reads a path or
//! contacts a browser.

use rea_application::web;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{value::to_raw_value, Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = web::screenshot_comparison::OPERATION;

/// Compare two caller-supplied screenshot observations.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_ref(&input)
}

/// Compare observations without taking ownership of the request.
pub fn dispatch_ref(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    reject_unknown_fields(object)?;

    let before = resolve_observation(object.get("before"), "before")?;
    let after = resolve_observation(object.get("after"), "after")?;
    let threshold = object.get("channel_threshold").cloned();

    let mut comparison_input = Map::new();
    comparison_input.insert("before".into(), before.artifact.clone());
    comparison_input.insert("after".into(), after.artifact.clone());
    if let Some(threshold) = threshold {
        comparison_input.insert("channel_threshold".into(), threshold);
    }

    let result = web::screenshot_comparison::compare(&Value::Object(comparison_input))?;
    Ok(json!({
        "result": result,
        "provenance": {
            "source": "caller-supplied-captured-screenshots",
            "execution": "none",
            "before": before.provenance,
            "after": after.provenance,
        },
    }))
}

struct ResolvedObservation {
    artifact: Value,
    provenance: Value,
}

fn resolve_observation(value: Option<&Value>, field: &str) -> Result<ResolvedObservation, Failure> {
    let value = value.ok_or_else(|| invalid(&format!("{field} is required")))?;
    let source = authenticated_observation(value, field)?;
    let observation = source.as_ref().unwrap_or(value);
    let object = observation
        .as_object()
        .ok_or_else(|| invalid(&format!("{field} screenshot observation must be an object")))?;
    let artifact = if object.contains_key("data_base64") {
        observation.clone()
    } else {
        object
            .get("artifact")
            .filter(|candidate| candidate.is_object())
            .ok_or_else(|| invalid(&format!("{field} screenshot observation requires artifact")))?
            .clone()
    };

    let identity = artifact_identity(&artifact, field)?;
    let mut provenance = Map::from([
        ("sha256".into(), identity.sha256),
        ("bytes".into(), identity.bytes),
        ("media_type".into(), identity.media_type),
    ]);
    if let Some(evidence_id) = authenticated_evidence_id(value) {
        provenance.insert("evidence_id".into(), Value::String(evidence_id));
    }
    if let Some(limitations) = object.get("limitations") {
        if limitations.is_array() {
            provenance.insert("limitations".into(), limitations.clone());
        }
    }
    Ok(ResolvedObservation {
        artifact,
        provenance: Value::Object(provenance),
    })
}

fn authenticated_observation<'a>(value: &'a Value, field: &str) -> Result<Option<Value>, Failure> {
    let candidate = if value.get("evidence").is_some() {
        value.get("evidence")
    } else if value.get("evidence_id").is_some() {
        Some(value)
    } else {
        None
    };
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    let object = candidate
        .as_object()
        .ok_or_else(|| invalid(&format!("{field} Evidence must be an object")))?;
    if object.get("evidence_id").and_then(Value::as_str).is_none() {
        return Err(invalid(&format!("{field} Evidence requires evidence_id")));
    }
    let raw = to_raw_value(candidate)
        .map_err(|error| invalid(&format!("{field} Evidence is not canonical JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("{field} Evidence authentication failed: {error}")))?;
    if !record.operation_matches("capture_web_screenshot") {
        return Err(invalid(&format!("{field} Evidence has the wrong operation")));
    }
    serde_json::from_str(record.normalized_result().get())
        .map(Some)
        .map_err(|error| invalid(&format!("{field} Evidence normalized_result is invalid: {error}")))
}

fn authenticated_evidence_id(value: &Value) -> Option<String> {
    value
        .get("evidence_id")
        .or_else(|| value.get("evidence").and_then(|item| item.get("evidence_id")))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

struct ArtifactIdentity {
    sha256: Value,
    bytes: Value,
    media_type: Value,
}

fn artifact_identity(artifact: &Value, field: &str) -> Result<ArtifactIdentity, Failure> {
    let object = artifact
        .as_object()
        .ok_or_else(|| invalid(&format!("{field}.artifact must be an object")))?;
    Ok(ArtifactIdentity {
        sha256: required_string(object, "sha256", field)?,
        bytes: object
            .get("bytes")
            .cloned()
            .ok_or_else(|| invalid(&format!("{field}.artifact.bytes is required")))?,
        media_type: required_string(object, "media_type", field)?,
    })
}

fn required_string(object: &Map<String, Value>, key: &str, field: &str) -> Result<Value, Failure> {
    object
        .get(key)
        .filter(|value| value.as_str().is_some_and(|text| !text.is_empty()))
        .cloned()
        .ok_or_else(|| invalid(&format!("{field}.artifact.{key} is required")))
}

fn reject_unknown_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "before" | "after" | "channel_threshold"))
    {
        return Err(invalid("input contains an unknown field"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide two bounded captured screenshot observations or authenticated screenshot Evidence; the runtime does not capture browsers or read paths.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("authority".into(), Detail::Text("caller-supplied-capture-or-authenticated-evidence".into())),
        ]),
    )
}
