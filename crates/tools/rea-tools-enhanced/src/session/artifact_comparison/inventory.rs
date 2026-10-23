//! Parse, merge and validate artifact inventory Evidence pages.
//!
//! Compatibility owner: `domain/artifactInventoryEvidence.ts`. Per-page schema
//! validation reuses `rea_application::artifacts::inventory_evidence::normalize_result`
//! (the native port of `artifactInventoryResultSchema.parse`). Merge ordering,
//! completeness and graph-identity checks follow the TypeScript owner.

use super::canonical::{canonical_json, type_error};
use super::identity::{
    artifact_contradiction_id, artifact_edge_id, artifact_graph_digest, artifact_id_for_content,
    artifact_manifest_id, occurrence_id_for_location,
};
use crate::derived::parse_evidence;
use crate::js::compare_code_points;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use serde_json::Value;
use std::collections::BTreeMap;

const CONTEXT: &str = "Artifact inventory";
const COVERAGE_CONTEXT: &str = "Artifact inventory coverage";

/// A merged inventory used by the comparison.
pub struct InventorySet {
    pub manifest: Value,
    pub nodes: Vec<Value>,
    pub occurrences: Vec<Value>,
    pub edges: Vec<Value>,
    pub integrity_contradictions: Value,
    pub limitations: Vec<String>,
    pub complete: bool,
    pub coverage: Value,
}

/// Evidence records and the assembled inventory.
pub struct ParsedInventorySet {
    pub evidence_ids: Vec<String>,
    pub inventory: InventorySet,
}

fn normalize_page(value: &Value) -> Result<Value, AnalysisError> {
    rea_application::artifacts::inventory_evidence::normalize_result(value.clone())
        .map_err(|message| type_error(message))
}

/// Validate one authenticated inventory carrier's subject against its manifest.
fn validate_inventory_subject(subject: &Value, manifest: &Value) -> Result<(), AnalysisError> {
    if subject.is_null()
        || subject["digest"]["sha256"] != manifest["root_sha256"]
        || subject["format"] != manifest["root_format"]
    {
        return Err(type_error(
            "Artifact inventory Evidence subject does not match its root digest",
        ));
    }
    Ok(())
}

fn validate_inventory_page(inventory: &Value) -> Result<(), AnalysisError> {
    assert_unique(inventory["nodes"].as_array(), "artifact_id", "node ID")?;
    assert_unique(
        inventory["occurrences"].as_array(),
        "occurrence_id",
        "occurrence ID",
    )?;
    assert_unique(inventory["edges"].as_array(), "edge_id", "edge ID")?;
    for node in inventory["nodes"].as_array().into_iter().flatten() {
        let expected = artifact_id_for_content(node["sha256"].as_str().unwrap_or_default())?;
        if node["artifact_id"].as_str() != Some(expected.as_str()) {
            return Err(type_error("Artifact node ID is not content-addressed"));
        }
    }
    Ok(())
}

fn assert_unique(values: Option<&Vec<Value>>, key: &str, label: &str) -> Result<(), AnalysisError> {
    let values = values.cloned().unwrap_or_default();
    let mut seen = std::collections::HashSet::new();
    for value in &values {
        let id = value[key].as_str().unwrap_or_default().to_owned();
        if !seen.insert(id) {
            return Err(type_error(format!(
                "Artifact inventory contains a duplicate {label}"
            )));
        }
    }
    Ok(())
}

/// Parse an authenticated inventory carrier (`inventory_artifact`) into a page.
fn parse_inventory_evidence_page(evidence: &Value) -> Result<Value, AnalysisError> {
    if evidence["operation"].as_str() != Some("inventory_artifact") {
        return Err(type_error(
            "Artifact inventory page must be inventory_artifact Evidence",
        ));
    }
    let inventory = normalize_page(&evidence["normalized_result"])?;
    validate_inventory_subject(&evidence["subject"], &inventory["manifest"])?;
    validate_inventory_page(&inventory)?;
    Ok(inventory)
}

/// `parseArtifactInventoryEvidence`.
pub fn parse_artifact_inventory_evidence(
    carriers: &[Evidence],
) -> Result<ParsedInventorySet, AnalysisError> {
    let mut pages: Vec<Value> = Vec::new();
    let mut evidence_ids: Vec<String> = Vec::with_capacity(carriers.len());
    for carrier in carriers {
        evidence_ids.push(carrier.id().to_owned());
        let value = carrier.value();
        match value["operation"].as_str() {
            Some("inventory_artifact") => pages.push(parse_inventory_evidence_page(value)?),
            Some("inspect_artifact") => {
                pages.extend(parse_inspection_inventory_payload(
                    &value["normalized_result"],
                    &value["subject"],
                )?);
            }
            _ => {
                return Err(type_error(
                    "Artifact comparison requires inspect_artifact Evidence",
                ));
            }
        }
    }
    Ok(ParsedInventorySet {
        evidence_ids,
        inventory: assemble_inventory_results(pages)?,
    })
}

/// Shared owner boundary for `inspect_artifact` payloads.
fn parse_inspection_inventory_payload(
    input: &Value,
    subject: &Value,
) -> Result<Vec<Value>, AnalysisError> {
    // The full inspection schema is validated by the native inventory-view
    // owner; here we authenticate the substep Evidence and inventory pages and
    // apply the inspection-specific invariants of `parseInspectionInventoryPayload`.
    let substeps = input["substeps"].as_array();
    let substeps_completed = input["coverage"]["substeps_completed"].as_u64();
    let substeps =
        substeps.ok_or_else(|| type_error("Artifact inspection requires inventory substeps"))?;
    if substeps.is_empty() {
        return Err(type_error(
            "Artifact inspection requires inventory substeps",
        ));
    }
    if substeps_completed != Some(substeps.len() as u64) {
        return Err(type_error(
            "Artifact inspection substep count does not match its coverage declaration",
        ));
    }
    let mut pages = Vec::with_capacity(substeps.len());
    for substep in substeps {
        let nested_evidence = &substep["evidence"];
        let evidence = parse_evidence(nested_evidence).map_err(|error| {
            AnalysisError::evidence_integrity(crate::derived::evidence_failure_message(&error))
        })?;
        if substep["evidence_id"].as_str() != Some(evidence.id()) {
            return Err(type_error(
                "Artifact inspection substep evidence ID does not match nested Evidence",
            ));
        }
        pages.push(parse_inventory_evidence_page(evidence.value())?);
    }
    // validateInspectionSubject: subject must match the first page manifest.
    let first_manifest = &pages[0]["manifest"];
    validate_inspection_subject(input, subject, first_manifest)?;
    Ok(pages)
}

fn validate_inspection_subject(
    inspection: &Value,
    subject: &Value,
    manifest: &Value,
) -> Result<(), AnalysisError> {
    let inspection_subject = &inspection["subject"];
    if inspection_subject["manifest_id"] != manifest["manifest_id"]
        || inspection_subject["root_artifact_id"] != manifest["root_artifact_id"]
        || inspection_subject["root_sha256"] != manifest["root_sha256"]
        || inspection_subject["root_format"] != manifest["root_format"]
    {
        return Err(type_error(
            "Artifact inspection subject does not match its inventory manifest",
        ));
    }
    if subject.is_null()
        || subject["digest"]["sha256"] != manifest["root_sha256"]
        || subject["format"] != manifest["root_format"]
    {
        return Err(type_error(
            "Artifact inspection Evidence subject does not match its root manifest",
        ));
    }
    Ok(())
}

/// `assembleInventoryResults`.
fn assemble_inventory_results(pages: Vec<Value>) -> Result<InventorySet, AnalysisError> {
    let first = pages
        .first()
        .cloned()
        .ok_or_else(|| type_error("Artifact inventory requires Evidence pages"))?;
    let manifest_json = canonical_json(&first["manifest"], CONTEXT)?;
    let coverage_json = canonical_json(&first["coverage"], COVERAGE_CONTEXT)?;
    let contradictions_json = canonical_json(&first["integrity_contradictions"], CONTEXT)?;

    let mut nodes: BTreeMap<String, Value> = BTreeMap::new();
    let mut occurrences: BTreeMap<String, Value> = BTreeMap::new();
    let mut edges: BTreeMap<String, Value> = BTreeMap::new();

    for page in &pages {
        if canonical_json(&page["manifest"], CONTEXT)? != manifest_json {
            return Err(type_error(
                "Artifact inventory pages do not share one manifest",
            ));
        }
        if canonical_json(&page["coverage"], COVERAGE_CONTEXT)? != coverage_json {
            return Err(type_error(
                "Artifact inventory pages do not share one coverage declaration",
            ));
        }
        if canonical_json(&page["integrity_contradictions"], CONTEXT)? != contradictions_json {
            return Err(type_error(
                "Artifact inventory pages do not share integrity contradictions",
            ));
        }
        for node in page["nodes"].as_array().into_iter().flatten() {
            merge_exact(
                &mut nodes,
                node["artifact_id"].as_str().unwrap_or_default(),
                node,
                "node",
            )?;
        }
        for occurrence in page["occurrences"].as_array().into_iter().flatten() {
            merge_exact(
                &mut occurrences,
                occurrence["occurrence_id"].as_str().unwrap_or_default(),
                occurrence,
                "occurrence",
            )?;
        }
        for edge in page["edges"].as_array().into_iter().flatten() {
            merge_exact(
                &mut edges,
                edge["edge_id"].as_str().unwrap_or_default(),
                edge,
                "edge",
            )?;
        }
    }

    let inventory = ordered_inventory(&first, &pages, nodes, occurrences, edges)?;
    if inventory.complete {
        validate_complete_inventory(&inventory)?;
    }
    Ok(inventory)
}

fn ordered_inventory(
    first: &Value,
    pages: &[Value],
    nodes: BTreeMap<String, Value>,
    occurrences: BTreeMap<String, Value>,
    edges: BTreeMap<String, Value>,
) -> Result<InventorySet, AnalysisError> {
    // nodes/edges sorted by their id via code-point ordering (BTreeMap keys).
    let mut nodes_vec: Vec<Value> = nodes.into_values().collect();
    nodes_vec.sort_by(|a, b| {
        compare_code_points(
            a["artifact_id"].as_str().unwrap_or_default(),
            b["artifact_id"].as_str().unwrap_or_default(),
        )
    });
    let mut edges_vec: Vec<Value> = edges.into_values().collect();
    edges_vec.sort_by(|a, b| {
        compare_code_points(
            a["edge_id"].as_str().unwrap_or_default(),
            b["edge_id"].as_str().unwrap_or_default(),
        )
    });

    let occurrences_vec = order_occurrences(
        first["manifest"]["root_artifact_id"]
            .as_str()
            .unwrap_or_default(),
        occurrences.into_values().collect(),
    )?;

    // limitations: union over pages in order, dedup, sort by code points.
    let mut limitations: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for page in pages {
        for item in page["limitations"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if seen.insert(item.to_owned()) {
                limitations.push(item.to_owned());
            }
        }
    }
    limitations.sort_by(|a, b| compare_code_points(a, b));

    let node_count = first["manifest"]["node_count"].as_u64();
    let occurrence_count = first["manifest"]["occurrence_count"].as_u64();
    let edge_count = first["manifest"]["edge_count"].as_u64();
    let complete = node_count == Some(nodes_vec.len() as u64)
        && occurrence_count == Some(occurrences_vec.len() as u64)
        && edge_count == Some(edges_vec.len() as u64);

    Ok(InventorySet {
        manifest: first["manifest"].clone(),
        nodes: nodes_vec,
        occurrences: occurrences_vec,
        edges: edges_vec,
        integrity_contradictions: first["integrity_contradictions"].clone(),
        limitations,
        complete,
        coverage: first["coverage"].clone(),
    })
}

fn order_occurrences(
    root_artifact_id: &str,
    occurrences: Vec<Value>,
) -> Result<Vec<Value>, AnalysisError> {
    // Group by logical_path preserving JS Map insertion order within a group.
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, Vec<Value>> =
        std::collections::HashMap::new();
    for occurrence in occurrences {
        let path = occurrence["logical_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        if !groups.contains_key(&path) {
            order.push(path.clone());
        }
        groups.entry(path).or_default().push(occurrence);
    }
    // Sort paths by code points.
    order.sort_by(|a, b| compare_code_points(a, b));

    let mut output = Vec::new();
    for path in order {
        let mut group = groups.remove(&path).unwrap_or_default();
        if group.len() < 2 {
            output.extend(group);
            continue;
        }
        let entry_kind = group[0]["entry_kind"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let mut ordinal_by_id: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for ordinal in 0..group.len() {
            let id = occurrence_id_for_location(
                root_artifact_id,
                &path,
                &entry_kind,
                if ordinal == 0 { None } else { Some(ordinal) },
            )?;
            ordinal_by_id.insert(id, ordinal);
        }
        let max = usize::MAX;
        group.sort_by(|left, right| {
            let left_ordinal = ordinal_by_id
                .get(left["occurrence_id"].as_str().unwrap_or_default())
                .copied()
                .unwrap_or(max);
            let right_ordinal = ordinal_by_id
                .get(right["occurrence_id"].as_str().unwrap_or_default())
                .copied()
                .unwrap_or(max);
            left_ordinal.cmp(&right_ordinal).then_with(|| {
                compare_code_points(
                    left["occurrence_id"].as_str().unwrap_or_default(),
                    right["occurrence_id"].as_str().unwrap_or_default(),
                )
            })
        });
        output.extend(group);
    }
    Ok(output)
}

fn validate_complete_inventory(inventory: &InventorySet) -> Result<(), AnalysisError> {
    let node_ids: std::collections::HashSet<&str> = inventory
        .nodes
        .iter()
        .filter_map(|node| node["artifact_id"].as_str())
        .collect();
    let occurrence_ids: std::collections::HashSet<&str> = inventory
        .occurrences
        .iter()
        .filter_map(|occurrence| occurrence["occurrence_id"].as_str())
        .collect();

    let root_node = inventory
        .nodes
        .iter()
        .find(|node| node["artifact_id"] == inventory.manifest["root_artifact_id"]);
    if root_node.map(|node| &node["sha256"]) != Some(&inventory.manifest["root_sha256"]) {
        return Err(type_error(
            "Artifact root node does not match its manifest digest",
        ));
    }

    let root_occurrence = inventory
        .occurrences
        .iter()
        .find(|occurrence| occurrence["logical_path"] == ".");
    match root_occurrence {
        Some(occurrence)
            if occurrence["artifact_id"] == inventory.manifest["root_artifact_id"]
                && occurrence["artifact_format"] == inventory.manifest["root_format"] => {}
        _ => {
            return Err(type_error(
                "Artifact root occurrence does not match its manifest representation",
            ));
        }
    }

    let mut duplicate_ordinal_by_path: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for occurrence in &inventory.occurrences {
        let path = occurrence["logical_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        let ordinal = *duplicate_ordinal_by_path.get(&path).unwrap_or(&0);
        duplicate_ordinal_by_path.insert(path, ordinal + 1);
        validate_occurrence(occurrence, inventory, &node_ids, &occurrence_ids, ordinal)?;
    }

    let occurrences_by_id: std::collections::HashMap<&str, &Value> = inventory
        .occurrences
        .iter()
        .filter_map(|occurrence| {
            occurrence["occurrence_id"]
                .as_str()
                .map(|id| (id, occurrence))
        })
        .collect();
    for edge in &inventory.edges {
        validate_edge(edge, &node_ids, &occurrences_by_id)?;
    }

    for contradiction in inventory
        .integrity_contradictions
        .as_array()
        .into_iter()
        .flatten()
    {
        if !node_ids.contains(
            contradiction["parent_artifact_id"]
                .as_str()
                .unwrap_or_default(),
        ) || !occurrence_ids
            .contains(contradiction["occurrence_id"].as_str().unwrap_or_default())
        {
            return Err(type_error(
                "Integrity contradiction references a missing graph member",
            ));
        }
        let expected = artifact_contradiction_id(
            inventory.manifest["root_artifact_id"]
                .as_str()
                .unwrap_or_default(),
            contradiction["logical_path"].as_str().unwrap_or_default(),
            contradiction["declared_sha256"]
                .as_str()
                .unwrap_or_default(),
            contradiction["observed_sha256"]
                .as_str()
                .unwrap_or_default(),
        )?;
        if contradiction["contradiction_id"].as_str() != Some(expected.as_str()) {
            return Err(type_error(
                "Integrity contradiction ID does not match its identity",
            ));
        }
    }

    let contradictions = inventory
        .integrity_contradictions
        .as_array()
        .cloned()
        .unwrap_or_default();
    let graph_sha256 = artifact_graph_digest(
        &inventory.nodes,
        &inventory.occurrences,
        &inventory.edges,
        &contradictions,
    )?;
    if inventory.manifest["graph_sha256"].as_str() != Some(graph_sha256.as_str()) {
        return Err(type_error(
            "Artifact graph commitment does not match its members",
        ));
    }
    let manifest_id = artifact_manifest_id(
        inventory.manifest["root_artifact_id"]
            .as_str()
            .unwrap_or_default(),
        &graph_sha256,
    )?;
    if inventory.manifest["manifest_id"].as_str() != Some(manifest_id.as_str()) {
        return Err(type_error(
            "Artifact manifest ID does not match its commitment",
        ));
    }
    Ok(())
}

fn validate_occurrence(
    occurrence: &Value,
    inventory: &InventorySet,
    node_ids: &std::collections::HashSet<&str>,
    occurrence_ids: &std::collections::HashSet<&str>,
    duplicate_ordinal: usize,
) -> Result<(), AnalysisError> {
    if !occurrence["artifact_id"].is_null()
        && !node_ids.contains(occurrence["artifact_id"].as_str().unwrap_or_default())
    {
        return Err(type_error("Artifact occurrence references a missing node"));
    }
    if !occurrence["parent_occurrence_id"].is_null()
        && !occurrence_ids.contains(
            occurrence["parent_occurrence_id"]
                .as_str()
                .unwrap_or_default(),
        )
    {
        return Err(type_error(
            "Artifact occurrence references a missing parent",
        ));
    }
    let expected = occurrence_id_for_location(
        inventory.manifest["root_artifact_id"]
            .as_str()
            .unwrap_or_default(),
        occurrence["logical_path"].as_str().unwrap_or_default(),
        occurrence["entry_kind"].as_str().unwrap_or_default(),
        if duplicate_ordinal == 0 {
            None
        } else {
            Some(duplicate_ordinal)
        },
    )?;
    if occurrence["occurrence_id"].as_str() != Some(expected.as_str()) {
        return Err(type_error(
            "Artifact occurrence ID does not match its identity",
        ));
    }
    Ok(())
}

fn validate_edge(
    edge: &Value,
    node_ids: &std::collections::HashSet<&str>,
    occurrences: &std::collections::HashMap<&str, &Value>,
) -> Result<(), AnalysisError> {
    let occurrence = occurrences.get(edge["occurrence_id"].as_str().unwrap_or_default());
    let valid = node_ids.contains(edge["parent_artifact_id"].as_str().unwrap_or_default())
        && match occurrence {
            None => false,
            Some(occurrence) => {
                !occurrence["artifact_id"].is_null()
                    && node_ids.contains(occurrence["artifact_id"].as_str().unwrap_or_default())
            }
        };
    if !valid {
        return Err(type_error(
            "Artifact edge references a missing graph member",
        ));
    }
    let occurrence = occurrence.unwrap();
    let expected = artifact_edge_id(edge, occurrence)?;
    if edge["edge_id"].as_str() != Some(expected.as_str()) {
        return Err(type_error("Artifact edge ID does not match its identity"));
    }
    Ok(())
}

fn merge_exact(
    output: &mut BTreeMap<String, Value>,
    key: &str,
    value: &Value,
    label: &str,
) -> Result<(), AnalysisError> {
    if let Some(previous) = output.get(key) {
        if canonical_json(previous, CONTEXT)? != canonical_json(value, CONTEXT)? {
            return Err(type_error(format!(
                "Artifact inventory has conflicting {label} pages"
            )));
        }
    } else {
        output.insert(key.to_owned(), value.clone());
    }
    Ok(())
}
