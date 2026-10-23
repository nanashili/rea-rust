//! Deterministic comparison of authenticated artifact-inventory Evidence.
//!
//! This module owns the application projection for `compare_artifacts`.  The
//! inventory producer remains responsible for parsing and authenticating graph
//! facts; this workflow only pairs occurrences by their caller-visible logical
//! paths and preserves the Evidence identifiers that support every row.

use crate::artifacts::inventory_evidence::normalize_result;
use crate::ledger::artifact_records::ArtifactRecords;
use rea_core::{
    cancellation::Cancellation,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "compare_artifacts";

/// Compare two complete or partial artifact inventories and return derived Evidence.
pub fn compare(
    input: &Value,
    records: Option<&ArtifactRecords>,
    cancellation: &Cancellation,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let left_source = resolve_source(object.get("left"), records)?;
    let right_source = resolve_source(object.get("right"), records)?;
    let left = parse_inventory_source(&left_source, "left", cancellation)?;
    let right = parse_inventory_source(&right_source, "right", cancellation)?;

    let evidence_links = vec![left.evidence_id.clone(), right.evidence_id.clone()];
    let comparison = compare_inventories(
        &left.inventory,
        &right.inventory,
        &evidence_links,
        cancellation,
    )?;
    let result = json!({
        "status": comparison.status,
        "left_manifest_id": left.inventory.manifest["manifest_id"],
        "right_manifest_id": right.inventory.manifest["manifest_id"],
        "summary": comparison.summary,
        "changes": comparison.changes,
        "limitations": comparison.limitations,
    });
    let unsigned = json!({
        "subject": null,
        "provider": {"id": "artifact-comparison", "name": "REA artifact comparison", "version": "1"},
        "analysis_profile": null,
        "predicate_type": "rea.artifact-comparison",
        "operation": OPERATION,
        "parameters": {"left_evidence_ids": [left.evidence_id], "right_evidence_ids": [right.evidence_id]},
        "raw_result": null,
        "normalized_result": result,
        "confidence": "derived",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": comparison.limitations,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": evidence_links,
    });
    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| invalid("result", &error.to_string()))?;
    let output =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| integrity("result", error))?;
    Ok(
        serde_json::value::RawValue::from_string(output.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
}

struct ParsedSource {
    evidence_id: String,
    inventory: Inventory,
}

struct Inventory {
    manifest: Value,
    nodes: Vec<Value>,
    occurrences: Vec<Value>,
    edges: Vec<Value>,
    coverage: Value,
    limitations: Vec<String>,
    complete: bool,
}

fn parse_inventory_source(
    source: &Box<serde_json::value::RawValue>,
    side: &str,
    cancellation: &Cancellation,
) -> Result<ParsedSource, Failure> {
    let record = EvidenceRecord::parse(source).map_err(|error| integrity(side, error))?;
    let evidence_id = record.evidence_id().to_owned();
    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(side, &error.to_string()))?;
    let mut pages = Vec::new();
    if record.operation_matches("inventory_artifact") {
        pages.push(normalize_result(normalized).map_err(|error| invalid(side, &error))?);
    } else if record.operation_matches("inspect_artifact") {
        let substeps = normalized
            .get("substeps")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid(side, "inspect_artifact Evidence has no inventory substeps"))?;
        for (index, substep) in substeps.iter().enumerate() {
            if index % 64 == 0 && cancellation.reason().is_some() {
                return Err(cancelled());
            }
            let nested = substep
                .get("evidence")
                .ok_or_else(|| invalid(side, "Artifact inspection substep has no Evidence"))?;
            let nested_raw = serde_json::value::to_raw_value(nested)
                .map_err(|error| invalid(side, &error.to_string()))?;
            let nested_record =
                EvidenceRecord::parse(&nested_raw).map_err(|error| integrity(side, error))?;
            if !nested_record.operation_matches("inventory_artifact") {
                return Err(invalid(
                    side,
                    "Artifact inspection substep is not inventory Evidence",
                ));
            }
            let page: Value = serde_json::from_str(nested_record.normalized_result().get())
                .map_err(|error| invalid(side, &error.to_string()))?;
            pages.push(normalize_result(page).map_err(|error| invalid(side, &error))?);
        }
    } else {
        return Err(invalid(
            side,
            "Expected inspect_artifact or inventory_artifact Evidence",
        ));
    }
    assemble_inventory(pages, &evidence_id, side)
}

fn assemble_inventory(
    pages: Vec<Value>,
    evidence_id: &str,
    side: &str,
) -> Result<ParsedSource, Failure> {
    let first = pages
        .first()
        .ok_or_else(|| invalid(side, "Artifact inventory requires at least one page"))?;
    let manifest = first["manifest"].clone();
    let coverage = first["coverage"].clone();
    let mut nodes = BTreeMap::new();
    let mut occurrences = BTreeMap::new();
    let mut edges = BTreeMap::new();
    let contradictions = first["integrity_contradictions"].clone();
    let mut limitations = Vec::new();
    drop(first);
    for page in pages {
        if page["manifest"] != manifest
            || page["coverage"] != coverage
            || page["integrity_contradictions"] != contradictions
        {
            return Err(invalid(
                side,
                "Artifact inventory pages disagree about their graph",
            ));
        }
        for item in page["nodes"].as_array().into_iter().flatten() {
            merge_page(&mut nodes, item, "artifact_id", side, "node")?;
        }
        for item in page["occurrences"].as_array().into_iter().flatten() {
            merge_page(&mut occurrences, item, "occurrence_id", side, "occurrence")?;
        }
        for item in page["edges"].as_array().into_iter().flatten() {
            merge_page(&mut edges, item, "edge_id", side, "edge")?;
        }
        limitations.extend(
            page["limitations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    let complete = manifest["node_count"].as_u64() == Some(nodes.len() as u64)
        && manifest["occurrence_count"].as_u64() == Some(occurrences.len() as u64)
        && manifest["edge_count"].as_u64() == Some(edges.len() as u64);
    Ok(ParsedSource {
        evidence_id: evidence_id.to_owned(),
        inventory: Inventory {
            manifest,
            nodes: nodes.into_values().collect(),
            occurrences: occurrences.into_values().collect(),
            edges: edges.into_values().collect(),
            coverage,
            limitations,
            complete,
        },
    })
}

fn merge_page(
    target: &mut BTreeMap<String, Value>,
    value: &Value,
    key: &str,
    side: &str,
    kind: &str,
) -> Result<(), Failure> {
    let id = value[key]
        .as_str()
        .ok_or_else(|| invalid(side, &format!("Artifact inventory {kind} has no {key}")))?;
    if let Some(previous) = target.get(id) {
        if previous != value {
            return Err(invalid(
                side,
                &format!("Artifact inventory {kind} pages conflict"),
            ));
        }
    } else {
        target.insert(id.to_owned(), value.clone());
    }
    Ok(())
}

fn compare_inventories(
    left: &Inventory,
    right: &Inventory,
    evidence_links: &[String],
    cancellation: &Cancellation,
) -> Result<Comparison, Failure> {
    let same_scope = left.coverage["scope"] == right.coverage["scope"];
    let root_covered = same_scope
        && left.complete
        && right.complete
        && left.coverage["status"] == "complete"
        && right.coverage["status"] == "complete";
    let entries_covered = root_covered && left.coverage["scope"] == "container-entries";
    let left_covered = root_covered;
    let right_covered = root_covered;
    let fully_covered = left_covered
        && right_covered
        && (entries_covered
            || (left.manifest["occurrence_count"] == 1 && right.manifest["occurrence_count"] == 1));
    let left_paths = occurrences_by_path(&left.occurrences);
    let right_paths = occurrences_by_path(&right.occurrences);
    let mut paths = left_paths.keys().cloned().collect::<BTreeSet<_>>();
    paths.extend(right_paths.keys().cloned());
    let left_nodes = nodes_by_id(&left.nodes);
    let right_nodes = nodes_by_id(&right.nodes);
    let left_relations = relations_by_path(left);
    let right_relations = relations_by_path(right);
    let mut changes = Vec::new();
    let mut ambiguous = false;
    for (index, path) in paths.into_iter().enumerate() {
        if index % 256 == 0 && cancellation.reason().is_some() {
            return Err(cancelled());
        }
        let l = left_paths.get(&path).cloned().unwrap_or_default();
        let r = right_paths.get(&path).cloned().unwrap_or_default();
        if l.len() > 1 || r.len() > 1 {
            ambiguous = true;
            changes.push(change(
                &path,
                "unknown",
                &["availability"],
                None,
                None,
                evidence_links,
            ));
            continue;
        }
        if let Some(item) = classify(
            &path,
            l.first(),
            r.first(),
            left_nodes.get(
                l.first()
                    .map(|v| v["artifact_id"].as_str())
                    .flatten()
                    .unwrap_or(""),
            ),
            right_nodes.get(
                r.first()
                    .map(|v| v["artifact_id"].as_str())
                    .flatten()
                    .unwrap_or(""),
            ),
            left_relations.get(&path),
            right_relations.get(&path),
            root_covered,
            entries_covered,
            evidence_links,
        ) {
            changes.push(item);
        }
    }
    apply_root_hash_change(left, right, &mut changes, evidence_links);
    let summary = summarize(left, right, &changes, fully_covered);
    let mut limitations = left
        .limitations
        .iter()
        .map(|item| format!("Left: {item}"))
        .collect::<Vec<_>>();
    limitations.extend(
        right
            .limitations
            .iter()
            .map(|item| format!("Right: {item}")),
    );
    if !left.complete {
        limitations.push("Left artifact inventory is incomplete.".into());
    }
    if !right.complete {
        limitations.push("Right artifact inventory is incomplete.".into());
    }
    if !same_scope {
        limitations.push("Artifact inventory scopes differ.".into());
    }
    if same_scope
        && left.coverage["scope"] == "root"
        && (left.manifest["occurrence_count"].as_u64().unwrap_or(0) > 1
            || right.manifest["occurrence_count"].as_u64().unwrap_or(0) > 1)
    {
        limitations.push("Container entry coverage is unavailable for child paths.".into());
    }
    if left.coverage["status"] != "complete" {
        limitations.push("Left artifact inventory traversal coverage is unknown.".into());
    }
    if right.coverage["status"] != "complete" {
        limitations.push("Right artifact inventory traversal coverage is unknown.".into());
    }
    if ambiguous {
        limitations.push("Duplicate logical paths cannot be paired across inventories; comparisons for those paths are unknown.".into());
    }
    limitations.sort();
    limitations.dedup();
    let status = if !left.complete || !right.complete {
        "truncated"
    } else if changes
        .iter()
        .any(|v| v["classification"] == "contradiction")
    {
        "contradiction"
    } else if !fully_covered || changes.iter().any(|v| v["classification"] == "unknown") {
        "unknown"
    } else if changes.is_empty() {
        "unchanged"
    } else {
        "changed"
    };
    Ok(Comparison {
        status,
        summary,
        changes,
        limitations,
    })
}

struct Comparison {
    status: &'static str,
    summary: Value,
    changes: Vec<Value>,
    limitations: Vec<String>,
}

fn occurrences_by_path(items: &[Value]) -> BTreeMap<String, Vec<Value>> {
    let mut output = BTreeMap::new();
    for item in items {
        if let Some(path) = item["logical_path"].as_str() {
            output
                .entry(path.to_owned())
                .or_insert_with(Vec::new)
                .push(item.clone());
        }
    }
    output
}
fn nodes_by_id(items: &[Value]) -> BTreeMap<String, Value> {
    items
        .iter()
        .filter_map(|item| {
            item["artifact_id"]
                .as_str()
                .map(|id| (id.to_owned(), item.clone()))
        })
        .collect()
}

fn classify(
    path: &str,
    left: Option<&Value>,
    right: Option<&Value>,
    left_node: Option<&Value>,
    right_node: Option<&Value>,
    left_relations: Option<&Vec<Value>>,
    right_relations: Option<&Vec<Value>>,
    root_covered: bool,
    entries_covered: bool,
    links: &[String],
) -> Option<Value> {
    let covered = if path == "." {
        root_covered
    } else {
        entries_covered
    };
    if left.is_none() {
        return Some(change(
            path,
            if covered { "added" } else { "unknown" },
            &[if covered { "content" } else { "availability" }],
            None,
            right,
            links,
        ));
    }
    if right.is_none() {
        return Some(change(
            path,
            if covered { "removed" } else { "unknown" },
            &[if covered { "content" } else { "availability" }],
            left,
            None,
            links,
        ));
    }
    let base = [left, right];
    if base
        .iter()
        .flatten()
        .any(|item| item["hash_status"] == "mismatched")
    {
        return Some(change(
            path,
            "contradiction",
            &["integrity"],
            left,
            right,
            links,
        ));
    }
    if base
        .iter()
        .flatten()
        .any(|item| item["hash_status"] != "verified")
        || left_node.is_none()
        || right_node.is_none()
    {
        return Some(change(
            path,
            "unknown",
            &["availability"],
            left,
            right,
            links,
        ));
    }
    let l = left_node.unwrap();
    let r = right_node.unwrap();
    let mut dimensions = Vec::new();
    if l["sha256"] != r["sha256"] {
        dimensions.push("content");
    }
    if left.unwrap()["artifact_kind"] != right.unwrap()["artifact_kind"] {
        dimensions.push("kind");
    }
    if l["format"] != r["format"]
        || left.unwrap()["artifact_format"] != right.unwrap()["artifact_format"]
    {
        dimensions.push("format");
    }
    if l["size"] != r["size"] {
        dimensions.push("size");
    }
    if left.unwrap()["executable"] != right.unwrap()["executable"] {
        dimensions.push("executable");
    }
    if left_relations.unwrap_or(&Vec::new()) != right_relations.unwrap_or(&Vec::new()) {
        dimensions.push("relations");
    }
    if metadata_changed(l, r, left.unwrap(), right.unwrap()) {
        dimensions.push("metadata");
    }
    if dimensions.is_empty() {
        None
    } else {
        Some(change(path, "changed", &dimensions, left, right, links))
    }
}

fn metadata_changed(
    left_node: &Value,
    right_node: &Value,
    left_occurrence: &Value,
    right_occurrence: &Value,
) -> bool {
    left_node["media_type"] != right_node["media_type"]
        || left_node["architecture"] != right_node["architecture"]
        || left_node["content_state"] != right_node["content_state"]
        || left_occurrence["entry_kind"] != right_occurrence["entry_kind"]
        || left_occurrence["encrypted"] != right_occurrence["encrypted"]
        || left_node["limitations"] != right_node["limitations"]
        || left_occurrence["limitations"] != right_occurrence["limitations"]
}

fn change(
    path: &str,
    classification: &str,
    dimensions: &[&str],
    left: Option<&Value>,
    right: Option<&Value>,
    links: &[String],
) -> Value {
    json!({"classification": classification, "logical_path": path, "dimensions": dimensions, "left_occurrence_id": left.and_then(|v| v["occurrence_id"].as_str()), "right_occurrence_id": right.and_then(|v| v["occurrence_id"].as_str()), "left_artifact_id": left.and_then(|v| v["artifact_id"].as_str()), "right_artifact_id": right.and_then(|v| v["artifact_id"].as_str()), "evidence_links": links})
}

fn relations_by_path(inventory: &Inventory) -> BTreeMap<String, Vec<Value>> {
    let occurrences = inventory
        .occurrences
        .iter()
        .filter_map(|v| v["occurrence_id"].as_str().map(|id| (id, v)))
        .collect::<BTreeMap<_, _>>();
    let mut output = BTreeMap::new();
    for edge in &inventory.edges {
        let Some(occurrence) = edge["occurrence_id"]
            .as_str()
            .and_then(|id| occurrences.get(id))
        else {
            continue;
        };
        let Some(artifact_id) = occurrence["artifact_id"].as_str() else {
            continue;
        };
        let parent_path = occurrence["parent_occurrence_id"]
            .as_str()
            .and_then(|id| occurrences.get(id))
            .and_then(|v| v["logical_path"].as_str());
        let projection = json!({"parent_logical_path": parent_path, "child_artifact_id": artifact_id, "relation": edge["relation"], "logical_path": occurrence["logical_path"], "producer": edge["producer"]});
        output
            .entry(
                occurrence["logical_path"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
            .or_insert_with(Vec::new)
            .push(projection);
    }
    for values in output.values_mut() {
        values.sort_by_key(|v| serde_json::to_string(v).unwrap_or_default());
    }
    output
}

fn summarize(left: &Inventory, right: &Inventory, changes: &[Value], covered: bool) -> Value {
    let mut counts = BTreeMap::from([
        (String::from("added"), 0_u64),
        (String::from("removed"), 0),
        (String::from("changed"), 0),
        (String::from("unknown"), 0),
        (String::from("contradiction"), 0),
    ]);
    for item in changes {
        if let Some(key) = item["classification"].as_str() {
            *counts.entry(key.into()).or_default() += 1;
        }
    }
    let changed_paths = changes
        .iter()
        .filter(|v| v["classification"] != "added")
        .filter_map(|v| v["logical_path"].as_str())
        .collect::<BTreeSet<_>>();
    let left_occurrence_count = left.manifest["occurrence_count"].as_u64().unwrap_or(0);
    let right_occurrence_count = right.manifest["occurrence_count"].as_u64().unwrap_or(0);
    let possible_unknown = left_occurrence_count
        .max(right_occurrence_count)
        .saturating_sub(counts["added"])
        .saturating_sub(counts["removed"])
        .saturating_sub(counts["changed"])
        .saturating_sub(counts["contradiction"]);
    let unknown = if covered {
        counts["unknown"]
    } else {
        counts["unknown"].max(possible_unknown)
    };
    json!({"unchanged": if covered { left.occurrences.iter().filter(|v| !changed_paths.contains(v["logical_path"].as_str().unwrap_or_default())).count() } else { 0 }, "added": counts["added"], "removed": counts["removed"], "changed": counts["changed"], "unknown": unknown, "contradiction": counts["contradiction"]})
}

fn apply_root_hash_change(
    left: &Inventory,
    right: &Inventory,
    changes: &mut Vec<Value>,
    links: &[String],
) {
    if left.manifest["root_sha256"] == right.manifest["root_sha256"] {
        return;
    }
    if let Some(change) = changes.iter_mut().find(|v| v["logical_path"] == ".") {
        if change["dimensions"]
            .as_array()
            .is_some_and(|d| d.iter().any(|v| v == "content"))
            || (change["classification"] != "unknown" && change["classification"] != "changed")
        {
            return;
        }
        change["classification"] = json!("changed");
        let mut dimensions = change["dimensions"].as_array().cloned().unwrap_or_default();
        dimensions.insert(0, json!("content"));
        change["dimensions"] = Value::Array(dimensions);
    } else {
        let l = left.occurrences.iter().find(|v| v["logical_path"] == ".");
        let r = right.occurrences.iter().find(|v| v["logical_path"] == ".");
        changes.push(change(".", "changed", &["content"], l, r, links));
    }
}

fn resolve_source(
    value: Option<&Value>,
    records: Option<&ArtifactRecords>,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let value = value.ok_or_else(|| invalid("source", "Missing Evidence input"))?;
    if value.get("evidence_id").and_then(Value::as_str).is_some() {
        let raw = serde_json::value::to_raw_value(value)
            .map_err(|e| invalid("source", &e.to_string()))?;
        let record = EvidenceRecord::parse(&raw).map_err(|error| integrity("source", error))?;
        if record.operation_matches("inspect_analysis_view") {
            return resolve_analysis_view_summary(&raw, records);
        }
        return Ok(raw);
    }
    if value["kind"] == "retained-evidence" {
        let id = value["evidence_id"]
            .as_str()
            .ok_or_else(|| invalid("evidence_id", "Missing retained Evidence identifier"))?;
        return records
            .and_then(|r| r.find_raw(id).ok().flatten())
            .ok_or_else(|| {
                invalid(
                    "evidence_id",
                    "Evidence reference is not retained in this session",
                )
            });
    }
    Err(invalid(
        "source",
        "Expected complete Evidence or retained-evidence reference",
    ))
}

fn resolve_analysis_view_summary(
    summary_raw: &serde_json::value::RawValue,
    records: Option<&ArtifactRecords>,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let summary_record =
        EvidenceRecord::parse(summary_raw).map_err(|error| integrity("source", error))?;
    let summary: Value = serde_json::from_str(summary_record.normalized_result().get())
        .map_err(|error| invalid("source", &error.to_string()))?;
    let parent_id = summary["parent_evidence_id"].as_str().ok_or_else(|| {
        invalid(
            "source",
            "Artifact analysis summary has no parent Evidence identifier",
        )
    })?;
    let parent_raw = records
        .ok_or_else(|| {
            invalid(
                "source",
                "Artifact analysis summary requires retained parent Evidence",
            )
        })?
        .find_raw(parent_id)
        .map_err(|error| invalid("source", &error.to_string()))?
        .ok_or_else(|| {
            invalid(
                "source",
                "Artifact analysis summary parent Evidence is not retained",
            )
        })?;
    let parent_value: Value = serde_json::from_str(parent_raw.get())
        .map_err(|error| invalid("source", &error.to_string()))?;
    let projected = super::inventory_view::project(&parent_value, &json!({"kind": "summary"}))?;
    let projected_record =
        EvidenceRecord::parse(&projected).map_err(|error| integrity("source", error))?;
    if projected_record.evidence_id() != summary_record.evidence_id() {
        return Err(invalid(
            "source",
            "Artifact analysis summary does not match its retained parent inventory",
        ));
    }
    Ok(parent_raw)
}

fn invalid(path: &str, message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Artifact comparison input is invalid.".into(),
        false,
        "Check the comparison inputs and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
fn integrity(path: &str, error: impl std::fmt::Display) -> Failure {
    invalid(
        path,
        &format!("Evidence integrity validation failed: {error}"),
    )
}
fn cancelled() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "Artifact comparison was cancelled.".into(),
        true,
        "Retry the comparison.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
