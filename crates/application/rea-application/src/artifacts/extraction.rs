//! Offline artifact extraction projection.
//!
//! The filesystem and format adapters own reading bytes.  This module owns
//! the deterministic, evidence-preserving projection of an already observed
//! inventory into an extraction result.  It deliberately does not create or
//! delete files: callers that have write authority may materialize the
//! returned `artifacts` using the same paths and digests.

use base64::Engine;
use rea_core::{
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "extract_artifact";
pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 1_000_000;
pub const MAX_PATH_BYTES: usize = 4096;

/// Extract the regular entries represented by an inventory and caller-owned
/// observed bytes.  `path` is retained as source identity and is never opened.
/// The input shape is `{path, output_root, inventory, entries}` where each
/// entry has `occurrence_id` and `bytes_base64`.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input)?;
    let path = required_text(object, "path")?;
    let output_root = required_text(object, "output_root")?;
    let integrity_policy = required_text(object, "integrity_policy")?;
    if integrity_policy != "fail" && integrity_policy != "record-and-continue" {
        return Err(invalid(
            "integrity_policy must be fail or record-and-continue",
        ));
    }
    validate_path(path, "path")?;
    validate_path(output_root, "output_root")?;

    let inventory = object
        .get("inventory")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("inventory must be an object"))?;
    let occurrences = inventory
        .get("occurrences")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("inventory.occurrences must be an array"))?;
    let entries = decode_entries(object.get("entries"))?;
    if occurrences.len() > MAX_ENTRIES {
        return Err(resource("artifact inventory exceeds the entry limit"));
    }

    let selected = select_active_occurrences(occurrences)?;
    let needed_node_ids: BTreeSet<&str> = selected
        .iter()
        .filter_map(|occurrence| occurrence.get("artifact_id").and_then(Value::as_str))
        .collect();
    let nodes = index_nodes(inventory.get("nodes"), &needed_node_ids)?;
    let mut extracted = Vec::with_capacity(selected.len());
    let mut selected_ids = Vec::with_capacity(selected.len());
    let mut paths = BTreeSet::new();

    for occurrence in selected {
        let occurrence_id = required_text(occurrence, "occurrence_id")?;
        let logical_path = required_text(occurrence, "logical_path")?;
        if !paths.insert(logical_path.to_owned()) {
            return Err(conflict(format!(
                "artifact extraction path collision: {logical_path}"
            )));
        }
        let artifact_id = match occurrence.get("artifact_id").and_then(Value::as_str) {
            Some(artifact_id) => artifact_id,
            None if occurrence.get("entry_kind").and_then(Value::as_str) == Some("file")
                && occurrence.get("hash_status").and_then(Value::as_str) == Some("unavailable") =>
            {
                return Err(integrity(format!(
                    "observed bytes are unavailable for extractable entry: {logical_path}"
                )));
            }
            None => {
                return Err(invalid(format!(
                    "selected occurrence has no extractable artifact identity: {occurrence_id}"
                )));
            }
        };
        let node = nodes.get(artifact_id).ok_or_else(|| {
            integrity(format!(
                "selected occurrence has no inventory node: {occurrence_id}"
            ))
        })?;
        let bytes = entries.get(occurrence_id).ok_or_else(|| {
            integrity(format!(
                "inventoried regular artifact entry was not observed: {logical_path}"
            ))
        })?;
        if occurrence
            .get("encrypted")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            return Err(unsupported(format!(
                "archive entry {logical_path} is encrypted; REA does not decrypt archive entries"
            )));
        }
        let digest = sha256(bytes);
        let expected = node
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let expected_size = node.get("size").and_then(Value::as_u64).unwrap_or(u64::MAX);
        let integrity_mismatch = digest != expected || bytes.len() as u64 != expected_size;
        if integrity_mismatch && integrity_policy == "fail" {
            return Err(integrity(format!(
                "observed bytes disagree with inventory node: {logical_path}"
            )));
        }
        selected_ids.push(occurrence_id.to_owned());
        extracted.push(json!({
            "artifact_id": artifact_id,
            "relative_path": logical_path,
            "sha256": digest,
            "bytes_written": bytes.len(),
            "created": true,
        }));
    }

    extracted.sort_by(|left, right| {
        left["relative_path"]
            .as_str()
            .cmp(&right["relative_path"].as_str())
    });
    selected_ids.sort();
    let source_manifest_id = inventory
        .get("manifest")
        .and_then(Value::as_object)
        .and_then(|manifest| manifest.get("manifest_id"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("inventory.manifest.manifest_id is required"))?;
    let semantic = json!({
        "source_manifest_id": source_manifest_id,
        "selected_occurrence_ids": selected_ids,
        "files_sha256": canonical_json::digest(&extracted)
            .map_err(|error| invalid(format!("extraction manifest could not be serialized: {error}")))?,
        "output_root_alias": "$OUTPUT_ROOT",
    });
    let extraction_id = format!(
        "aex_{}",
        canonical_json::digest(&semantic).map_err(|error| invalid(format!(
            "extraction manifest could not be serialized: {error}"
        )))?
    );
    let contradictions = inventory
        .get("integrity_contradictions")
        .and_then(Value::as_array)
        .map(|items| {
            Value::Array(
                items
                    .iter()
                    .filter(|item| {
                        item.get("occurrence_id")
                            .and_then(Value::as_str)
                            .is_some_and(|id| selected_ids.iter().any(|selected| selected == id))
                    })
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let mut limitations = vec![Value::String(
        "All regular files in the active artifact were materialized; nested archive contents remain represented by their containing file.".into(),
    )];
    if contradictions
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        limitations.push(Value::String(format!(
            "{} extracted file(s) contradict declared integrity metadata; their bytes are observed-untrusted.",
            contradictions.as_array().map_or(0, Vec::len)
        )));
    }
    let mut extraction_manifest = semantic
        .as_object()
        .cloned()
        .ok_or_else(|| invalid("extraction manifest could not be represented"))?;
    extraction_manifest.insert("extraction_id".into(), Value::String(extraction_id));
    Ok(json!({
        "manifest": inventory.get("manifest").cloned().unwrap_or(Value::Null),
        "extraction_manifest": Value::Object(extraction_manifest),
        "output_root": output_root,
        "artifacts": extracted,
        "containment_verified": true,
        "cleanup": {"attempted": false, "verified": true, "residual_paths": []},
        "provenance": [],
        "integrity_contradictions": contradictions,
        "limitations": limitations,
    }))
}

fn select_active_occurrences(occurrences: &[Value]) -> Result<Vec<&Map<String, Value>>, Failure> {
    let regular: BTreeSet<String> = occurrences
        .iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let kind = object.get("entry_kind")?.as_str()?;
            (kind == "file" || kind == "slice")
                .then(|| object.get("logical_path")?.as_str().map(str::to_owned))
                .flatten()
        })
        .collect();
    occurrences
        .iter()
        .filter_map(|value| {
            let object = value.as_object()?;
            let kind = object.get("entry_kind")?.as_str()?;
            if kind != "file" && kind != "slice" {
                return None;
            }
            let path = object.get("logical_path")?.as_str()?;
            if path == "." {
                return None;
            }
            let mut parent = path;
            while let Some(index) = parent.rfind('/') {
                parent = &parent[..index];
                if regular.contains(parent) {
                    return None;
                }
            }
            Some(Ok(object))
        })
        .collect()
}

fn index_nodes(
    value: Option<&Value>,
    needed_ids: &BTreeSet<&str>,
) -> Result<BTreeMap<String, Map<String, Value>>, Failure> {
    let nodes = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("inventory.nodes must be an array"))?;
    let mut indexed = BTreeMap::new();
    for node in nodes {
        let object = node
            .as_object()
            .ok_or_else(|| invalid("inventory node must be an object"))?;
        let id = required_text(object, "artifact_id")?.to_owned();
        if !needed_ids.contains(id.as_str()) {
            continue;
        }
        if indexed.insert(id, object.clone()).is_some() {
            return Err(conflict("duplicate inventory artifact_id"));
        }
    }
    Ok(indexed)
}

fn decode_entries(value: Option<&Value>) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
    let entries = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("entries must be an array"))?;
    let mut decoded = BTreeMap::new();
    let mut total = 0usize;
    for entry in entries {
        let object = entry
            .as_object()
            .ok_or_else(|| invalid("extraction entry must be an object"))?;
        let id = required_text(object, "occurrence_id")?.to_owned();
        let encoded = required_text(object, "bytes_base64")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| invalid("bytes_base64 is malformed"))?;
        total = total
            .checked_add(bytes.len())
            .ok_or_else(|| resource("observed bytes exceed the extraction limit"))?;
        if total > MAX_INPUT_BYTES {
            return Err(resource("observed bytes exceed the extraction limit"));
        }
        if decoded.insert(id, bytes).is_some() {
            return Err(conflict("duplicate extraction occurrence_id"));
        }
    }
    Ok(decoded)
}

fn input_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))
}
fn required_text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{key} must be a non-empty string")))
}
fn validate_path(path: &str, field: &str) -> Result<(), Failure> {
    if path.len() > MAX_PATH_BYTES || path.as_bytes().contains(&0) {
        return Err(invalid(format!("{field} is invalid")));
    }
    Ok(())
}
fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}
fn invalid(message: impl Into<String>) -> Failure {
    failure(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "correct the extraction request",
    )
}
fn integrity(message: impl Into<String>) -> Failure {
    failure(
        "artifact_integrity",
        "integrity",
        message.into(),
        false,
        "supply a complete matching inventory and observed bytes",
    )
}
fn conflict(message: impl Into<String>) -> Failure {
    failure(
        "artifact_path_conflict",
        "conflict",
        message.into(),
        false,
        "remove duplicate normalized paths",
    )
}
fn unsupported(message: impl Into<String>) -> Failure {
    failure(
        "unsupported_target",
        "unsupported",
        message.into(),
        false,
        "provide an unencrypted extractable artifact",
    )
}
fn resource(message: impl Into<String>) -> Failure {
    failure(
        "resource_limit",
        "resource",
        message.into(),
        false,
        "reduce the requested artifact size",
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
