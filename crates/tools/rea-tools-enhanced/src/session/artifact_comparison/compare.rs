//! `compareArtifacts`: deterministic inventory comparison.
//!
//! Compatibility owner: `domain/artifactComparison.ts`.

use super::inventory::InventorySet;
use rea_application::javascript::graph::json::{Json, Obj};
use rea_core::JsString;
use rea_core::analysis_error::AnalysisError;
use std::collections::BTreeMap;

/// A finished comparison: the public payload plus its status.
pub struct ArtifactComparison {
    pub value: Json,
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
        && left.coverage["status"].as_str() == Some("complete")
        && right.coverage["status"].as_str() == Some("complete");
    let entry_coverage_complete =
        root_coverage_complete && left.coverage["scope"].as_str() == Some("container-entries");

    let left_covered =
        same_scope && left.complete && left.coverage["status"].as_str() == Some("complete");
    let right_covered =
        same_scope && right.complete && right.coverage["status"].as_str() == Some("complete");
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
        && left.coverage["scope"].as_str() == Some("root")
        && (left_occurrence_count > 1 || right_occurrence_count > 1)
    {
        limitations.push("Container entry coverage is unavailable for child paths.".to_owned());
    }
    if left.coverage["status"].as_str() != Some("complete") {
        limitations.push("Left artifact inventory traversal coverage is unknown.".to_owned());
    }
    if right.coverage["status"].as_str() != Some("complete") {
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
        .any(|change| change["classification"].as_str() == Some("contradiction"))
    {
        "contradiction"
    } else if !fully_covered {
        "unknown"
    } else if changes
        .iter()
        .any(|change| change["classification"].as_str() == Some("unknown"))
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
    limitations.sort_by(|a, b| {
        JsString::from(a.as_str()).compare_code_points(&JsString::from(b.as_str()))
    });

    // Each change is re-keyed into `artifactChangeSchema` order, exactly as
    // `artifactComparisonResultSchema.parse` normalizes the result.
    let changes: Vec<Json> = changes.iter().map(schema_order_change).collect();

    // artifactComparisonResultSchema shape order.
    let value: Json = Obj::new()
        .with("status", status)
        .with("left_manifest_id", left.manifest["manifest_id"].clone())
        .with("right_manifest_id", right.manifest["manifest_id"].clone())
        .with("summary", summary)
        .with("changes", Json::Array(changes))
        .with(
            "limitations",
            rea_application::javascript::graph::json::strings(limitations),
        )
        .into();

    Ok(ArtifactComparison {
        value,
        status: status.to_owned(),
    })
}

/// Re-key one change into `artifactChangeSchema` property order.
fn schema_order_change(change: &Json) -> Json {
    let field = |key: &str| change.get(key).cloned().unwrap_or(Json::Null);
    Obj::new()
        .with("classification", field("classification"))
        .with("logical_path", field("logical_path"))
        .with("dimensions", field("dimensions"))
        .with("left_occurrence_id", field("left_occurrence_id"))
        .with("right_occurrence_id", field("right_occurrence_id"))
        .with("left_artifact_id", field("left_artifact_id"))
        .with("right_artifact_id", field("right_artifact_id"))
        .with("evidence_links", field("evidence_links"))
        .into()
}

fn occurrences_by_path(occurrences: &[Json]) -> BTreeMap<JsString, Vec<Json>> {
    // Preserve per-path insertion order; keyed map for stable path iteration.
    let mut output: BTreeMap<JsString, Vec<Json>> = BTreeMap::new();
    for occurrence in occurrences {
        let path = occurrence["logical_path"]
            .as_js_string()
            .cloned()
            .unwrap_or_default();
        output.entry(path).or_default().push(occurrence.clone());
    }
    output
}

#[allow(clippy::too_many_arguments)]
fn compare_occurrences(
    left: &InventorySet,
    right: &InventorySet,
    left_by_path: &BTreeMap<JsString, Vec<Json>>,
    right_by_path: &BTreeMap<JsString, Vec<Json>>,
    evidence_links: &[String],
    root_covered: bool,
    entries_covered: bool,
) -> Result<(Vec<Json>, bool), AnalysisError> {
    let left_nodes = nodes_by_id(&left.nodes);
    let right_nodes = nodes_by_id(&right.nodes);
    let left_relations = relations_by_path(left)?;
    let right_relations = relations_by_path(right)?;

    // paths = sorted union of keys (BTreeMap keys already code-point ordered).
    let mut paths: Vec<JsString> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for key in left_by_path.keys().chain(right_by_path.keys()) {
        if seen.insert(key.clone()) {
            paths.push(key.clone());
        }
    }
    paths.sort_by(JsString::compare_code_points);

    let empty: Vec<Json> = Vec::new();
    let mut output = Vec::new();
    let mut has_ambiguous = false;
    for path in paths {
        let left_matches = left_by_path.get(&path).unwrap_or(&empty);
        let right_matches = right_by_path.get(&path).unwrap_or(&empty);
        if left_matches.len() > 1 || right_matches.len() > 1 {
            has_ambiguous = true;
            output.push(
                Obj::new()
                    .with("logical_path", path.clone())
                    .with("classification", "unknown")
                    .with("dimensions", Json::Array(vec![Json::from("availability")]))
                    .with("left_occurrence_id", Json::Null)
                    .with("right_occurrence_id", Json::Null)
                    .with("left_artifact_id", Json::Null)
                    .with("right_artifact_id", Json::Null)
                    .with(
                        "evidence_links",
                        Json::Array(evidence_links.iter().cloned().map(Json::from).collect()),
                    )
                    .into(),
            );
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

fn nodes_by_id(nodes: &[Json]) -> std::collections::HashMap<String, Json> {
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
    occurrence: Option<&Json>,
    nodes: &'a std::collections::HashMap<String, Json>,
) -> Option<&'a Json> {
    let occurrence = occurrence?;
    let artifact_id = occurrence.get("artifact_id")?;
    if artifact_id.is_null() {
        return None;
    }
    nodes.get(artifact_id.as_str()?)
}

struct ClassifyPathInput<'a> {
    path: &'a JsString,
    left_occurrence: Option<&'a Json>,
    right_occurrence: Option<&'a Json>,
    left_node: Option<&'a Json>,
    right_node: Option<&'a Json>,
    left_relations: &'a [Json],
    right_relations: &'a [Json],
    root_covered: bool,
    entries_covered: bool,
    evidence_links: &'a [String],
}

fn build_change_base(input: &ClassifyPathInput<'_>) -> Obj {
    let mut object = Obj::new();
    object.set("logical_path", input.path.clone());
    object.set(
        "left_occurrence_id",
        optional_field(input.left_occurrence, "occurrence_id"),
    );
    object.set(
        "right_occurrence_id",
        optional_field(input.right_occurrence, "occurrence_id"),
    );
    object.set(
        "left_artifact_id",
        optional_field(input.left_occurrence, "artifact_id"),
    );
    object.set(
        "right_artifact_id",
        optional_field(input.right_occurrence, "artifact_id"),
    );
    object.set(
        "evidence_links",
        Json::Array(
            input
                .evidence_links
                .iter()
                .cloned()
                .map(Json::from)
                .collect(),
        ),
    );
    object
}

fn optional_field(occurrence: Option<&Json>, key: &str) -> Json {
    match occurrence.and_then(|occurrence| occurrence.get(key)) {
        Some(value) if !value.is_null() => value.clone(),
        _ => Json::Null,
    }
}

fn classify_presence(input: &ClassifyPathInput<'_>) -> Option<Json> {
    let covered = if input.path == "." {
        input.root_covered
    } else {
        input.entries_covered
    };
    if input.left_occurrence.is_none() {
        let mut base = build_change_base(input);
        base.set("classification", if covered { "added" } else { "unknown" });
        base.set(
            "dimensions",
            Json::Array(vec![Json::from(if covered {
                "content"
            } else {
                "availability"
            })]),
        );
        return Some(base.into());
    }
    if input.right_occurrence.is_none() {
        let mut base = build_change_base(input);
        base.set(
            "classification",
            if covered { "removed" } else { "unknown" },
        );
        base.set(
            "dimensions",
            Json::Array(vec![Json::from(if covered {
                "content"
            } else {
                "availability"
            })]),
        );
        return Some(base.into());
    }
    None
}

fn hash_status(occurrence: Option<&Json>) -> Option<&str> {
    occurrence.and_then(|occurrence| occurrence["hash_status"].as_str())
}

fn classify_integrity(input: &ClassifyPathInput<'_>, base: &Obj) -> Option<Json> {
    if hash_status(input.left_occurrence) == Some("mismatched")
        || hash_status(input.right_occurrence) == Some("mismatched")
    {
        let mut object = base.clone();
        object.set("classification", "contradiction");
        object.set("dimensions", Json::Array(vec![Json::from("integrity")]));
        return Some(object.into());
    }
    None
}

fn classify_availability(input: &ClassifyPathInput<'_>, base: &Obj) -> Option<Json> {
    if hash_status(input.left_occurrence) != Some("verified")
        || hash_status(input.right_occurrence) != Some("verified")
        || input.left_node.is_none()
        || input.right_node.is_none()
    {
        let mut object = base.clone();
        object.set("classification", "unknown");
        object.set("dimensions", Json::Array(vec![Json::from("availability")]));
        return Some(object.into());
    }
    None
}

fn classify_path(input: ClassifyPathInput<'_>) -> Option<Json> {
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
    object.set("classification", "changed");
    object.set(
        "dimensions",
        Json::Array(dimensions.into_iter().map(Json::from).collect()),
    );
    Some(object.into())
}

fn occurrence_field<'a>(occurrence: Option<&'a Json>, key: &str) -> Option<&'a Json> {
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

fn metadata_changed(input: &ClassifyPathInput<'_>, left: &Json, right: &Json) -> bool {
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

fn optional_value(occurrence: Option<&Json>, key: &str) -> Json {
    occurrence
        .and_then(|occurrence| occurrence.get(key))
        .cloned()
        .unwrap_or(Json::Null)
}

/// `JSON.stringify` of a slice of JSON values (preserves key order).
fn json_string(values: &[Json]) -> String {
    Json::Array(values.to_vec()).stringify()
}

/// `JSON.stringify` of a JSON value. The TS inputs here are always present
/// arrays (occurrence/node limitations), so null vs. `undefined` never differ.
fn json_string_value(value: &Json) -> String {
    value.stringify()
}

#[derive(Clone)]
struct RelationProjection {
    value: Json,
    json: String,
}

fn relations_by_path(
    inventory: &InventorySet,
) -> Result<std::collections::HashMap<JsString, Vec<Json>>, AnalysisError> {
    let occurrences: std::collections::HashMap<&str, &Json> = inventory
        .occurrences
        .iter()
        .filter_map(|occurrence| {
            occurrence["occurrence_id"]
                .as_str()
                .map(|id| (id, occurrence))
        })
        .collect();
    let mut output: std::collections::HashMap<JsString, Vec<RelationProjection>> =
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
            .as_js_string()
            .cloned()
            .unwrap_or_default();
        let parent_logical_path = if occurrence["parent_occurrence_id"].is_null() {
            Json::Null
        } else {
            occurrences
                .get(
                    occurrence["parent_occurrence_id"]
                        .as_str()
                        .unwrap_or_default(),
                )
                .map(|parent| parent["logical_path"].clone())
                .unwrap_or(Json::Null)
        };
        let projection = Obj::new()
            .with("parent_logical_path", parent_logical_path)
            .with("child_artifact_id", occurrence["artifact_id"].clone())
            .with("relation", edge["relation"].clone())
            .with("logical_path", occurrence["logical_path"].clone())
            .with("producer", edge["producer"].clone());
        let json = Json::from(projection.clone()).canonical();
        output.entry(path).or_default().push(RelationProjection {
            value: projection.into(),
            json,
        });
    }
    let mut result = std::collections::HashMap::new();
    for (path, mut values) in output {
        values.sort_by(|left, right| {
            JsString::from(left.json.as_str())
                .compare_code_points(&JsString::from(right.json.as_str()))
        });
        result.insert(path, values.into_iter().map(|item| item.value).collect());
    }
    Ok(result)
}

fn summarize(left: &InventorySet, right: &InventorySet, changes: &[Json], covered: bool) -> Json {
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
    let changed_paths: std::collections::HashSet<JsString> = changes
        .iter()
        .filter(|change| change["classification"].as_str() != Some("added"))
        .filter_map(|change| change["logical_path"].as_js_string().cloned())
        .collect();
    let unchanged = if covered {
        left.occurrences
            .iter()
            .filter(|occurrence| {
                !occurrence["logical_path"]
                    .as_js_string()
                    .is_some_and(|path| changed_paths.contains(path))
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
    Obj::new()
        .with("unchanged", unchanged as f64)
        .with("added", added as f64)
        .with("removed", removed as f64)
        .with("changed", changed as f64)
        .with("unknown", unknown as f64)
        .with("contradiction", contradiction as f64)
        .into()
}

fn apply_root_hash_change(
    left: &InventorySet,
    right: &InventorySet,
    changes: &mut Vec<Json>,
    evidence_links: &[String],
) -> Result<(), AnalysisError> {
    if left.manifest["root_sha256"] == right.manifest["root_sha256"] {
        return Ok(());
    }
    let index = changes
        .iter()
        .position(|change| change["logical_path"].as_str() == Some("."));
    if let Some(index) = index {
        let existing = &changes[index];
        let dimensions: Vec<String> = existing["dimensions"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Json::as_str)
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
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .chain(evidence_links.iter().cloned())
        {
            if seen.insert(link.clone()) {
                links.push(link);
            }
        }
        let mut object = existing.as_object().cloned().unwrap_or_default();
        object.set("classification", "changed");
        object.set(
            "dimensions",
            Json::Array(new_dimensions.into_iter().map(Json::from).collect()),
        );
        object.set(
            "evidence_links",
            Json::Array(links.into_iter().map(Json::from).collect()),
        );
        changes[index] = object.into();
        return Ok(());
    }
    let left_root = left
        .occurrences
        .iter()
        .find(|occurrence| occurrence["logical_path"].as_str() == Some("."));
    let right_root = right
        .occurrences
        .iter()
        .find(|occurrence| occurrence["logical_path"].as_str() == Some("."));
    changes.push(
        Obj::new()
            .with("classification", "changed")
            .with("logical_path", ".")
            .with("dimensions", Json::Array(vec![Json::from("content")]))
            .with(
                "left_occurrence_id",
                left_root.map(|occurrence| occurrence["occurrence_id"].clone()),
            )
            .with(
                "right_occurrence_id",
                right_root.map(|occurrence| occurrence["occurrence_id"].clone()),
            )
            .with(
                "left_artifact_id",
                left_root.map(|occurrence| occurrence["artifact_id"].clone()),
            )
            .with(
                "right_artifact_id",
                right_root.map(|occurrence| occurrence["artifact_id"].clone()),
            )
            .with(
                "evidence_links",
                Json::Array(evidence_links.iter().cloned().map(Json::from).collect()),
            )
            .into(),
    );
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
