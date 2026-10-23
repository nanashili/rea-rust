//! `compareArtifacts`: deterministic inventory comparison.
//!
//! Compatibility owner: `domain/artifactComparison.ts`.

use super::canonical::canonical_json;
use super::inventory::InventorySet;
use crate::js::compare_code_points;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

const OPERATION: &str = "Comparison";

/// A finished comparison: the public payload plus its status.
pub struct ArtifactComparison {
    pub value: Value,
    pub status: String,
}

/// `compareArtifacts`.
pub fn compare_artifacts(
    left: &InventorySet,
    right: &InventorySet,
    left_evidence_ids: &[String],
    right_evidence_ids: &[String],
) -> Result<ArtifactComparison, AnalysisError> {
    let left_complete = left.complete;
    let right_complete = right.complete;
    let same_scope = left.coverage["scope"] == right.coverage["scope"];
    let root_coverage_complete = same_scope
        && left.complete
        && right.complete
        && left.coverage["status"] == "complete"
        && right.coverage["status"] == "complete";
    let entry_coverage_complete =
        root_coverage_complete && left.coverage["scope"] == "container-entries";

    let left_covered = same_scope && left.complete && left.coverage["status"] == "complete";
    let right_covered = same_scope && right.complete && right.coverage["status"] == "complete";
    let left_occurrence_count = left.manifest["occurrence_count"].as_u64().unwrap_or(0);
    let right_occurrence_count = right.manifest["occurrence_count"].as_u64().unwrap_or(0);
    let fully_covered = left_covered
        && right_covered
        && (entry_coverage_complete
            || (root_coverage_complete
                && left_occurrence_count == 1
                && right_occurrence_count == 1));

    let mut evidence_links: Vec<String> =
        Vec::with_capacity(left_evidence_ids.len() + right_evidence_ids.len());
    evidence_links.extend(left_evidence_ids.iter().cloned());
    evidence_links.extend(right_evidence_ids.iter().cloned());

    let left_by_path = occurrences_by_path(&left.occurrences);
    let right_by_path = occurrences_by_path(&right.occurrences);

    let (mut changes, has_ambiguous) = compare_occurrences(
        left,
        right,
        &left_by_path,
        &right_by_path,
        &evidence_links,
        root_coverage_complete,
        entry_coverage_complete,
    )?;

    let mut limitations: Vec<String> = Vec::new();
    for item in &left.limitations {
        limitations.push(format!("Left: {item}"));
    }
    for item in &right.limitations {
        limitations.push(format!("Right: {item}"));
    }
    if !left_complete {
        limitations.push("Left artifact inventory is incomplete.".to_owned());
    }
    if !right_complete {
        limitations.push("Right artifact inventory is incomplete.".to_owned());
    }
    if !same_scope {
        limitations.push("Artifact inventory scopes differ.".to_owned());
    }
    if same_scope
        && left.coverage["scope"] == "root"
        && (left_occurrence_count > 1 || right_occurrence_count > 1)
    {
        limitations.push("Container entry coverage is unavailable for child paths.".to_owned());
    }
    if left.coverage["status"] != "complete" {
        limitations.push("Left artifact inventory traversal coverage is unknown.".to_owned());
    }
    if right.coverage["status"] != "complete" {
        limitations.push("Right artifact inventory traversal coverage is unknown.".to_owned());
    }
    if has_ambiguous {
        limitations.push(
            "Duplicate logical paths cannot be paired across inventories; comparisons for those paths are unknown."
                .to_owned(),
        );
    }

    apply_root_hash_change(left, right, &mut changes, &evidence_links)?;

    let summary = summarize(left, right, &changes, fully_covered);

    let status = if !left_complete || !right_complete {
        "truncated"
    } else if changes
        .iter()
        .any(|change| change["classification"] == "contradiction")
    {
        "contradiction"
    } else if !fully_covered {
        "unknown"
    } else if changes
        .iter()
        .any(|change| change["classification"] == "unknown")
    {
        "unknown"
    } else if changes.is_empty() {
        "unchanged"
    } else {
        "changed"
    };

    // limitations: [...new Set(limitations)].sort(compareUnicodeCodePoints).
    let mut seen = std::collections::HashSet::new();
    limitations.retain(|item| seen.insert(item.clone()));
    limitations.sort_by(|a, b| compare_code_points(a, b));

    // Each change is re-keyed into `artifactChangeSchema` order, exactly as
    // `artifactComparisonResultSchema.parse` normalizes the result.
    let changes: Vec<Value> = changes.iter().map(schema_order_change).collect();

    // artifactComparisonResultSchema shape order.
    let value = json!({
        "status": status,
        "left_manifest_id": left.manifest["manifest_id"],
        "right_manifest_id": right.manifest["manifest_id"],
        "summary": summary,
        "changes": changes,
        "limitations": limitations,
    });

    Ok(ArtifactComparison {
        value,
        status: status.to_owned(),
    })
}

/// Re-key one change into `artifactChangeSchema` property order.
fn schema_order_change(change: &Value) -> Value {
    let field = |key: &str| change.get(key).cloned().unwrap_or(Value::Null);
    json!({
        "classification": field("classification"),
        "logical_path": field("logical_path"),
        "dimensions": field("dimensions"),
        "left_occurrence_id": field("left_occurrence_id"),
        "right_occurrence_id": field("right_occurrence_id"),
        "left_artifact_id": field("left_artifact_id"),
        "right_artifact_id": field("right_artifact_id"),
        "evidence_links": field("evidence_links"),
    })
}

fn occurrences_by_path(occurrences: &[Value]) -> BTreeMap<String, Vec<Value>> {
    // Preserve per-path insertion order; keyed map for stable path iteration.
    let mut output: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for occurrence in occurrences {
        let path = occurrence["logical_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        output.entry(path).or_default().push(occurrence.clone());
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn compare_occurrences(
    left: &InventorySet,
    right: &InventorySet,
    left_by_path: &BTreeMap<String, Vec<Value>>,
    right_by_path: &BTreeMap<String, Vec<Value>>,
    evidence_links: &[String],
    root_covered: bool,
    entries_covered: bool,
) -> Result<(Vec<Value>, bool), AnalysisError> {
    let left_nodes = nodes_by_id(&left.nodes);
    let right_nodes = nodes_by_id(&right.nodes);
    let left_relations = relations_by_path(left)?;
    let right_relations = relations_by_path(right)?;

    // paths = sorted union of keys (BTreeMap keys already code-point ordered).
    let mut paths: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for key in left_by_path.keys().chain(right_by_path.keys()) {
        if seen.insert(key.clone()) {
            paths.push(key.clone());
        }
    }
    paths.sort_by(|a, b| compare_code_points(a, b));

    let empty: Vec<Value> = Vec::new();
    let mut output = Vec::new();
    let mut has_ambiguous = false;
    for path in paths {
        let left_matches = left_by_path.get(&path).unwrap_or(&empty);
        let right_matches = right_by_path.get(&path).unwrap_or(&empty);
        if left_matches.len() > 1 || right_matches.len() > 1 {
            has_ambiguous = true;
            output.push(json!({
                "logical_path": path,
                "classification": "unknown",
                "dimensions": ["availability"],
                "left_occurrence_id": Value::Null,
                "right_occurrence_id": Value::Null,
                "left_artifact_id": Value::Null,
                "right_artifact_id": Value::Null,
                "evidence_links": evidence_links,
            }));
            continue;
        }
        let left_occurrence = left_matches.first();
        let right_occurrence = right_matches.first();
        let change = classify_path(ClassifyPathInput {
            path: &path,
            left_occurrence,
            right_occurrence,
            left_node: node_for(left_occurrence, &left_nodes),
            right_node: node_for(right_occurrence, &right_nodes),
            left_relations: left_relations.get(&path).map(Vec::as_slice).unwrap_or(&[]),
            right_relations: right_relations.get(&path).map(Vec::as_slice).unwrap_or(&[]),
            root_covered,
            entries_covered,
            evidence_links,
        });
        if let Some(change) = change {
            output.push(change);
        }
    }
    Ok((output, has_ambiguous))
}

fn nodes_by_id(nodes: &[Value]) -> std::collections::HashMap<String, Value> {
    nodes
        .iter()
        .filter_map(|node| {
            node["artifact_id"]
                .as_str()
                .map(|id| (id.to_owned(), node.clone()))
        })
        .collect()
}

fn node_for<'a>(
    occurrence: Option<&Value>,
    nodes: &'a std::collections::HashMap<String, Value>,
) -> Option<&'a Value> {
    let occurrence = occurrence?;
    let artifact_id = occurrence.get("artifact_id")?;
    if artifact_id.is_null() {
        return None;
    }
    nodes.get(artifact_id.as_str()?)
}

struct ClassifyPathInput<'a> {
    path: &'a str,
    left_occurrence: Option<&'a Value>,
    right_occurrence: Option<&'a Value>,
    left_node: Option<&'a Value>,
    right_node: Option<&'a Value>,
    left_relations: &'a [Value],
    right_relations: &'a [Value],
    root_covered: bool,
    entries_covered: bool,
    evidence_links: &'a [String],
}

fn build_change_base(input: &ClassifyPathInput<'_>) -> Map<String, Value> {
    let mut object = Map::new();
    object.insert("logical_path".into(), json!(input.path));
    object.insert(
        "left_occurrence_id".into(),
        optional_field(input.left_occurrence, "occurrence_id"),
    );
    object.insert(
        "right_occurrence_id".into(),
        optional_field(input.right_occurrence, "occurrence_id"),
    );
    object.insert(
        "left_artifact_id".into(),
        optional_field(input.left_occurrence, "artifact_id"),
    );
    object.insert(
        "right_artifact_id".into(),
        optional_field(input.right_occurrence, "artifact_id"),
    );
    object.insert("evidence_links".into(), json!(input.evidence_links));
    object
}

fn optional_field(occurrence: Option<&Value>, key: &str) -> Value {
    match occurrence.and_then(|occurrence| occurrence.get(key)) {
        Some(value) if !value.is_null() => value.clone(),
        _ => Value::Null,
    }
}

fn classify_presence(input: &ClassifyPathInput<'_>) -> Option<Value> {
    let covered = if input.path == "." {
        input.root_covered
    } else {
        input.entries_covered
    };
    if input.left_occurrence.is_none() {
        let mut base = build_change_base(input);
        base.insert(
            "classification".into(),
            json!(if covered { "added" } else { "unknown" }),
        );
        base.insert(
            "dimensions".into(),
            json!([if covered { "content" } else { "availability" }]),
        );
        return Some(Value::Object(base));
    }
    if input.right_occurrence.is_none() {
        let mut base = build_change_base(input);
        base.insert(
            "classification".into(),
            json!(if covered { "removed" } else { "unknown" }),
        );
        base.insert(
            "dimensions".into(),
            json!([if covered { "content" } else { "availability" }]),
        );
        return Some(Value::Object(base));
    }
    None
}

fn hash_status(occurrence: Option<&Value>) -> Option<&str> {
    occurrence.and_then(|occurrence| occurrence["hash_status"].as_str())
}

fn classify_integrity(input: &ClassifyPathInput<'_>, base: &Map<String, Value>) -> Option<Value> {
    if hash_status(input.left_occurrence) == Some("mismatched")
        || hash_status(input.right_occurrence) == Some("mismatched")
    {
        let mut object = base.clone();
        object.insert("classification".into(), json!("contradiction"));
        object.insert("dimensions".into(), json!(["integrity"]));
        return Some(Value::Object(object));
    }
    None
}

fn classify_availability(
    input: &ClassifyPathInput<'_>,
    base: &Map<String, Value>,
) -> Option<Value> {
    if hash_status(input.left_occurrence) != Some("verified")
        || hash_status(input.right_occurrence) != Some("verified")
        || input.left_node.is_none()
        || input.right_node.is_none()
    {
        let mut object = base.clone();
        object.insert("classification".into(), json!("unknown"));
        object.insert("dimensions".into(), json!(["availability"]));
        return Some(Value::Object(object));
    }
    None
}

fn classify_path(input: ClassifyPathInput<'_>) -> Option<Value> {
    if let Some(presence) = classify_presence(&input) {
        return Some(presence);
    }
    let base = build_change_base(&input);
    if let Some(integrity) = classify_integrity(&input, &base) {
        return Some(integrity);
    }
    if let Some(availability) = classify_availability(&input, &base) {
        return Some(availability);
    }
    let dimensions = changed_dimensions(&input);
    if dimensions.is_empty() {
        return None;
    }
    let mut object = base;
    object.insert("classification".into(), json!("changed"));
    object.insert("dimensions".into(), json!(dimensions));
    Some(Value::Object(object))
}

fn occurrence_field<'a>(occurrence: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    occurrence.and_then(|occurrence| occurrence.get(key))
}

fn changed_dimensions(input: &ClassifyPathInput<'_>) -> Vec<&'static str> {
    let (Some(left), Some(right)) = (input.left_node, input.right_node) else {
        return vec!["availability"];
    };
    let mut dimensions = Vec::new();
    if left["sha256"] != right["sha256"] {
        dimensions.push("content");
    }
    if occurrence_field(input.left_occurrence, "artifact_kind")
        != occurrence_field(input.right_occurrence, "artifact_kind")
    {
        dimensions.push("kind");
    }
    if left["format"] != right["format"]
        || occurrence_field(input.left_occurrence, "artifact_format")
            != occurrence_field(input.right_occurrence, "artifact_format")
    {
        dimensions.push("format");
    }
    if left["size"] != right["size"] {
        dimensions.push("size");
    }
    if occurrence_field(input.left_occurrence, "executable")
        != occurrence_field(input.right_occurrence, "executable")
    {
        dimensions.push("executable");
    }
    if json_string(input.left_relations) != json_string(input.right_relations) {
        dimensions.push("relations");
    }
    if metadata_changed(input, left, right) {
        dimensions.push("metadata");
    }
    dimensions
}

fn metadata_changed(input: &ClassifyPathInput<'_>, left: &Value, right: &Value) -> bool {
    left["media_type"] != right["media_type"]
        || left["architecture"] != right["architecture"]
        || left["content_state"] != right["content_state"]
        || occurrence_field(input.left_occurrence, "entry_kind")
            != occurrence_field(input.right_occurrence, "entry_kind")
        || occurrence_field(input.left_occurrence, "encrypted")
            != occurrence_field(input.right_occurrence, "encrypted")
        || json_string_value(&left["limitations"]) != json_string_value(&right["limitations"])
        || json_string_value(&optional_value(input.left_occurrence, "limitations"))
            != json_string_value(&optional_value(input.right_occurrence, "limitations"))
}

fn optional_value(occurrence: Option<&Value>, key: &str) -> Value {
    occurrence
        .and_then(|occurrence| occurrence.get(key))
        .cloned()
        .unwrap_or(Value::Null)
}

/// `JSON.stringify` of a slice of JSON values (preserves key order).
fn json_string(values: &[Value]) -> String {
    serde_json::to_string(values).unwrap_or_default()
}

/// `JSON.stringify` of a JSON value. The TS inputs here are always present
/// arrays (occurrence/node limitations), so null vs. `undefined` never differ.
fn json_string_value(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

#[derive(Clone)]
struct RelationProjection {
    value: Value,
    json: String,
}

fn relations_by_path(
    inventory: &InventorySet,
) -> Result<std::collections::HashMap<String, Vec<Value>>, AnalysisError> {
    let occurrences: std::collections::HashMap<&str, &Value> = inventory
        .occurrences
        .iter()
        .filter_map(|occurrence| {
            occurrence["occurrence_id"]
                .as_str()
                .map(|id| (id, occurrence))
        })
        .collect();
    let mut output: std::collections::HashMap<String, Vec<RelationProjection>> =
        std::collections::HashMap::new();
    for edge in &inventory.edges {
        let occurrence = occurrences.get(edge["occurrence_id"].as_str().unwrap_or_default());
        let Some(occurrence) = occurrence else {
            continue;
        };
        if occurrence["artifact_id"].is_null() {
            continue;
        }
        let path = occurrence["logical_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let parent_logical_path = if occurrence["parent_occurrence_id"].is_null() {
            Value::Null
        } else {
            occurrences
                .get(
                    occurrence["parent_occurrence_id"]
                        .as_str()
                        .unwrap_or_default(),
                )
                .map(|parent| parent["logical_path"].clone())
                .unwrap_or(Value::Null)
        };
        let projection = json!({
            "parent_logical_path": parent_logical_path,
            "child_artifact_id": occurrence["artifact_id"],
            "relation": edge["relation"],
            "logical_path": occurrence["logical_path"],
            "producer": edge["producer"],
        });
        let json = canonical_json(&projection, OPERATION)?;
        output.entry(path).or_default().push(RelationProjection {
            value: projection,
            json,
        });
    }
    let mut result = std::collections::HashMap::new();
    for (path, mut values) in output {
        values.sort_by(|left, right| compare_code_points(&left.json, &right.json));
        result.insert(path, values.into_iter().map(|item| item.value).collect());
    }
    Ok(result)
}

fn summarize(left: &InventorySet, right: &InventorySet, changes: &[Value], covered: bool) -> Value {
    let mut added = 0u64;
    let mut removed = 0u64;
    let mut changed = 0u64;
    let mut unknown = 0u64;
    let mut contradiction = 0u64;
    for change in changes {
        match change["classification"].as_str() {
            Some("added") => added += 1,
            Some("removed") => removed += 1,
            Some("changed") => changed += 1,
            Some("unknown") => unknown += 1,
            Some("contradiction") => contradiction += 1,
            _ => {}
        }
    }
    let changed_paths: std::collections::HashSet<&str> = changes
        .iter()
        .filter(|change| change["classification"] != "added")
        .filter_map(|change| change["logical_path"].as_str())
        .collect();
    let unchanged = if covered {
        left.occurrences
            .iter()
            .filter(|occurrence| {
                !changed_paths.contains(occurrence["logical_path"].as_str().unwrap_or_default())
            })
            .count() as u64
    } else {
        0
    };
    let unknown = if covered {
        unknown
    } else {
        let left_count = left.manifest["occurrence_count"].as_u64().unwrap_or(0);
        let right_count = right.manifest["occurrence_count"].as_u64().unwrap_or(0);
        let base = left_count.max(right_count);
        let subtracted = added + removed + changed + contradiction;
        let remainder = base.saturating_sub(subtracted);
        unknown.max(remainder)
    };
    json!({
        "unchanged": unchanged,
        "added": added,
        "removed": removed,
        "changed": changed,
        "unknown": unknown,
        "contradiction": contradiction,
    })
}

fn apply_root_hash_change(
    left: &InventorySet,
    right: &InventorySet,
    changes: &mut Vec<Value>,
    evidence_links: &[String],
) -> Result<(), AnalysisError> {
    if left.manifest["root_sha256"] == right.manifest["root_sha256"] {
        return Ok(());
    }
    let index = changes
        .iter()
        .position(|change| change["logical_path"] == ".");
    if let Some(index) = index {
        let existing = &changes[index];
        let dimensions: Vec<String> = existing["dimensions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let classification = existing["classification"].as_str().unwrap_or_default();
        if dimensions.iter().any(|dimension| dimension == "content")
            || (classification != "unknown" && classification != "changed")
        {
            return Ok(());
        }
        let new_dimensions = DIMENSION_OPTIONS
            .iter()
            .filter(|dimension| {
                **dimension == "content" || dimensions.iter().any(|existing| existing == *dimension)
            })
            .copied()
            .collect::<Vec<_>>();
        let mut links: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for link in existing["evidence_links"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .chain(evidence_links.iter().cloned())
        {
            if seen.insert(link.clone()) {
                links.push(link);
            }
        }
        let mut object = existing.as_object().cloned().unwrap_or_default();
        object.insert("classification".into(), json!("changed"));
        object.insert("dimensions".into(), json!(new_dimensions));
        object.insert("evidence_links".into(), json!(links));
        changes[index] = Value::Object(object);
        return Ok(());
    }
    let left_root = left
        .occurrences
        .iter()
        .find(|occurrence| occurrence["logical_path"] == ".");
    let right_root = right
        .occurrences
        .iter()
        .find(|occurrence| occurrence["logical_path"] == ".");
    changes.push(json!({
        "classification": "changed",
        "logical_path": ".",
        "dimensions": ["content"],
        "left_occurrence_id": left_root.map(|occurrence| occurrence["occurrence_id"].clone()).unwrap_or(Value::Null),
        "right_occurrence_id": right_root.map(|occurrence| occurrence["occurrence_id"].clone()).unwrap_or(Value::Null),
        "left_artifact_id": left_root.map(|occurrence| occurrence["artifact_id"].clone()).unwrap_or(Value::Null),
        "right_artifact_id": right_root.map(|occurrence| occurrence["artifact_id"].clone()).unwrap_or(Value::Null),
        "evidence_links": evidence_links,
    }));
    Ok(())
}

const DIMENSION_OPTIONS: [&str; 9] = [
    "content",
    "kind",
    "format",
    "size",
    "executable",
    "relations",
    "metadata",
    "availability",
    "integrity",
];
