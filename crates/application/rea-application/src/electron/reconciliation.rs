//! Boundary ownership for JavaScript static/runtime reconciliation.
//!
//! The producer owns graph matching.  This module validates the identity and
//! cardinality invariants before a reconciled result crosses into CLI/MCP and
//! preserves the producer's explicit unknowns and coverage fields.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "reconcile_javascript_runtime";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("reconciliation input must be an object"))?;

    reject_unknown_fields(object, ["static_layers", "runtime_observations"])?;

    let static_layers = object
        .get("static_layers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("static_layers must be an array"))?;
    let runtime = object
        .get("runtime_observations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("runtime_observations must be an array"))?;
    if static_layers.is_empty() || runtime.is_empty() {
        return Err(invalid(
            "static_layers and runtime_observations must each contain one or more Evidence records",
        ));
    }

    for layer in static_layers {
        validate_static_layer(layer)?;
    }

    let application_count = static_layers
        .iter()
        .filter(|layer| {
            layer
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("application")
                == "application"
        })
        .count();
    if application_count != 1 {
        return Err(invalid("exactly one application static layer is required"));
    }

    ensure_unique_ids(static_layers, "analysis", "static layer Evidence")?;
    for observation in runtime {
        let object = observation
            .as_object()
            .ok_or_else(|| invalid("runtime observations must be Evidence objects"))?;
        if object.get("evidence_id").and_then(Value::as_str).is_none() {
            return Err(invalid("runtime observations must include an evidence_id"));
        }
    }

    ensure_unique_ids(runtime, "evidence_id", "runtime observation Evidence")
}

fn reject_unknown_fields<const N: usize>(
    object: &serde_json::Map<String, Value>,
    allowed: [&str; N],
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("reconciliation input contains an unknown field"));
    }
    Ok(())
}

fn validate_static_layer(layer: &Value) -> Result<(), Failure> {
    let object = layer
        .as_object()
        .ok_or_else(|| invalid("static layers must be objects"))?;
    reject_unknown_fields(object, ["role", "analysis", "runtime_mappings"])?;

    if let Some(role) = object.get("role").and_then(Value::as_str) {
        if !matches!(role, "application" | "cache" | "assets") {
            return Err(invalid("static layer role is unsupported"));
        }
    }
    object
        .get("analysis")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("static layers must include an Evidence object in analysis"))?;

    let mappings = match object.get("runtime_mappings") {
        Some(value) => value
            .as_array()
            .ok_or_else(|| invalid("runtime_mappings must be an array"))?
            .as_slice(),
        None => &[],
    };
    let mut mapping_keys = BTreeSet::new();
    for mapping in mappings {
        validate_runtime_mapping(mapping, &mut mapping_keys)?;
    }
    Ok(())
}

fn validate_runtime_mapping(
    mapping: &Value,
    mapping_keys: &mut BTreeSet<String>,
) -> Result<(), Failure> {
    let object = mapping
        .as_object()
        .ok_or_else(|| invalid("runtime mappings must be objects"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("runtime mapping kind is required"))?;
    let artifact_prefix = object
        .get("artifact_prefix")
        .and_then(Value::as_str)
        .unwrap_or("");
    validate_artifact_prefix(artifact_prefix)?;

    let key = match kind {
        "file-root" => {
            reject_unknown_fields(object, ["kind", "root", "artifact_prefix"])?;
            let root = object
                .get("root")
                .and_then(Value::as_str)
                .filter(|root| !root.is_empty())
                .ok_or_else(|| invalid("file-root mapping requires a non-empty root"))?;
            format!("file-root\0{root}\0{artifact_prefix}")
        }
        "url-prefix" => {
            reject_unknown_fields(object, ["kind", "prefix", "artifact_prefix"])?;
            let prefix = object
                .get("prefix")
                .and_then(Value::as_str)
                .filter(|prefix| !prefix.is_empty())
                .ok_or_else(|| invalid("url-prefix mapping requires a non-empty prefix"))?;
            validate_runtime_url_prefix(prefix)?;
            format!("url-prefix\0{prefix}\0{artifact_prefix}")
        }
        _ => return Err(invalid("runtime mapping kind is unsupported")),
    };

    if !mapping_keys.insert(key) {
        return Err(invalid("runtime mappings must be unique"));
    }
    Ok(())
}

fn validate_artifact_prefix(prefix: &str) -> Result<(), Failure> {
    if prefix.is_empty()
        || (!prefix.starts_with('/')
            && !prefix.contains('\\')
            && prefix
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
    {
        return Ok(());
    }
    Err(invalid(
        "artifact_prefix must be a safe relative POSIX path",
    ))
}

fn validate_runtime_url_prefix(prefix: &str) -> Result<(), Failure> {
    let scheme_end = prefix
        .find("://")
        .ok_or_else(|| invalid("runtime URL prefix must be HTTP(S)"))?;
    let scheme = &prefix[..scheme_end];
    if !matches!(scheme, "http" | "https") {
        return Err(invalid("runtime URL prefix must be HTTP(S)"));
    }
    let authority = &prefix[scheme_end + 3..]
        .split(['/', '?', '#'])
        .next()
        .unwrap_or("");
    if authority.is_empty()
        || authority.contains('@')
        || prefix.contains('?')
        || prefix.contains('#')
    {
        return Err(invalid(
            "runtime URL prefix must not contain credentials, query, or fragment",
        ));
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("reconciliation result must be an object"));
    }
    Ok(result)
}

fn ensure_unique_ids(records: &[Value], field: &str, label: &str) -> Result<(), Failure> {
    let mut ids = BTreeSet::new();
    for record in records {
        let value = record
            .get(field)
            .and_then(Value::as_str)
            .or_else(|| {
                record
                    .get(field)
                    .and_then(|nested| nested.get("evidence_id"))
                    .and_then(Value::as_str)
            })
            .ok_or_else(|| invalid(&format!("{label} is missing {field}")))?;
        if !ids.insert(value) {
            return Err(invalid(&format!("{label} Evidence IDs must be unique")));
        }
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide one application static layer and unique runtime Evidence records.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "static_layers": [{
                "role": "application",
                "analysis": {"evidence_id": "ev_static"}
            }],
            "runtime_observations": [{"evidence_id": "ev_runtime"}]
        })
    }

    #[test]
    fn accepts_one_application_layer_and_unique_runtime_evidence() {
        validate_input(&input()).expect("valid reconciliation input");
        let result =
            retain_result(&input(), serde_json::json!({"items": []})).expect("result is retained");
        assert_eq!(result["items"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn rejects_duplicate_runtime_evidence() {
        let mut value = input();
        value["runtime_observations"] = serde_json::json!([
            {"evidence_id": "duplicate"},
            {"evidence_id": "duplicate"}
        ]);
        assert!(validate_input(&value).is_err());
    }
}
