//! Parse, merge and validate artifact inventory Evidence pages.
//!
//! Compatibility owner: `parseArtifactInventoryEvidence` in
//! `src/domain/artifactInventoryEvidence.ts` and `artifactIdentity.ts`.
//! Per-page schema validation reuses
//! `rea_application::artifacts::inventory_evidence::normalize_result` (the
//! native port of `artifactInventoryResultSchema.parse`). Merge ordering,
//! completeness and graph-identity checks follow the TypeScript owner.
use crate::rejection::Rejection;
use rea_core::canonical_json;
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

const CONTEXT: &str = "Artifact inventory";
const COVERAGE_CONTEXT: &str = "Artifact inventory coverage";

/// A merged inventory (`InventorySet`).
pub struct InventorySet {
    pub manifest: Value,
    pub occurrences: Vec<Value>,
    pub nodes: Vec<Value>,
    pub integrity_contradictions: Value,
    pub limitations: Vec<String>,
    /// Merged member counts match the manifest.
    pub complete: bool,
    pub coverage: Value,
}

impl InventorySet {
    /// `hasCompleteInventoryCoverage(inventory, scope)`.
    pub fn has_complete_coverage(&self, scope: &str) -> bool {
        self.complete
            && self.coverage["scope"].as_str() == Some(scope)
            && self.coverage["status"].as_str() == Some("complete")
    }

    pub fn root_format(&self) -> &str {
        self.manifest["root_format"].as_str().unwrap_or_default()
    }

    pub fn root_sha256(&self) -> &str {
        self.manifest["root_sha256"].as_str().unwrap_or_default()
    }
}

/// `ParsedInventorySet`: authenticated carriers and their merged inventory.
pub struct ParsedInventorySet {
    pub evidence: Vec<Value>,
    pub inventory: InventorySet,
}

/// `parseEvidence`: authenticate one record. The original raises a Zod
/// custom issue at `evidence_id` for a forged identifier.
pub fn parse_evidence(value: &Value) -> Result<Value, Rejection> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| Rejection::type_error(error.to_string()))?;
    EvidenceRecord::parse(&raw).map_err(|error| match error {
        EvidenceRecordError::SemanticIdMismatch => Rejection::nested(
            "evidence_id",
            "Evidence semantic identifier does not match its record",
        ),
        other => Rejection::nested_root(other.to_string()),
    })?;
    Ok(value.clone())
}

/// `parseArtifactInventoryEvidence`.
pub fn parse_artifact_inventory_evidence(
    carriers: &[Value],
) -> Result<ParsedInventorySet, Rejection> {
    let evidence = carriers
        .iter()
        .map(parse_evidence)
        .collect::<Result<Vec<_>, _>>()?;
    let mut pages = Vec::new();
    for carrier in &evidence {
        match carrier["operation"].as_str() {
            Some("inventory_artifact") => pages.push(parse_inventory_evidence_page(carrier)?),
            Some("inspect_artifact") => pages.extend(parse_inspection_inventory_payload(
                &carrier["normalized_result"],
                &carrier["subject"],
            )?),
            _ => {
                return Err(Rejection::type_error(
                    "Artifact comparison requires inspect_artifact Evidence",
                ));
            }
        }
    }
    Ok(ParsedInventorySet {
        evidence,
        inventory: assemble_inventory_results(pages)?,
    })
}

fn normalize_page(value: &Value) -> Result<Value, Rejection> {
    rea_application::artifacts::inventory_evidence::normalize_result(value.clone())
        .map_err(Rejection::nested_root)
}

/// `parseInventoryEvidencePage` / `parseInventoryPage`.
fn parse_inventory_evidence_page(evidence: &Value) -> Result<Value, Rejection> {
    if evidence["operation"].as_str() != Some("inventory_artifact") {
        return Err(Rejection::type_error(
            "Artifact inventory page must be inventory_artifact Evidence",
        ));
    }
    let inventory = normalize_page(&evidence["normalized_result"])?;
    validate_inventory_subject(&evidence["subject"], &inventory["manifest"])?;
    validate_inventory_page(&inventory)?;
    Ok(inventory)
}

/// `validateArtifactInventorySubject`.
fn validate_inventory_subject(subject: &Value, manifest: &Value) -> Result<(), Rejection> {
    if subject.is_null()
        || subject["digest"]["sha256"] != manifest["root_sha256"]
        || subject["format"] != manifest["root_format"]
    {
        return Err(Rejection::type_error(
            "Artifact inventory Evidence subject does not match its root digest",
        ));
    }
    Ok(())
}

fn validate_inventory_page(inventory: &Value) -> Result<(), Rejection> {
    assert_unique(&inventory["nodes"], "artifact_id", "node ID")?;
    assert_unique(&inventory["occurrences"], "occurrence_id", "occurrence ID")?;
    assert_unique(&inventory["edges"], "edge_id", "edge ID")?;
    for node in members(&inventory["nodes"]) {
        let expected = artifact_id_for_content(text(&node["sha256"]))?;
        if node["artifact_id"].as_str() != Some(expected.as_str()) {
            return Err(Rejection::type_error(
                "Artifact node ID is not content-addressed",
            ));
        }
    }
    Ok(())
}

fn assert_unique(values: &Value, key: &str, label: &str) -> Result<(), Rejection> {
    let mut seen = HashSet::new();
    for value in members(values) {
        if !seen.insert(text(&value[key])) {
            return Err(Rejection::type_error(format!(
                "Artifact inventory contains a duplicate {label}"
            )));
        }
    }
    Ok(())
}

/// `parseInspectionInventoryPayload`. The complete inspection schema is
/// owned by the inventory-view port; this applies the inspection-specific
/// invariants and authenticates every nested inventory page.
fn parse_inspection_inventory_payload(
    input: &Value,
    subject: &Value,
) -> Result<Vec<Value>, Rejection> {
    let substeps = input["substeps"].as_array().ok_or_else(|| {
        Rejection::nested(
            "substeps",
            "Invalid input: expected array, received undefined",
        )
    })?;
    if input["coverage"]["substeps_completed"].as_u64() != Some(substeps.len() as u64) {
        return Err(Rejection::type_error(
            "Artifact inspection substep count does not match its coverage declaration",
        ));
    }
    let mut pages = Vec::with_capacity(substeps.len());
    for substep in substeps {
        let evidence = parse_evidence(&substep["evidence"])?;
        if substep["evidence_id"] != evidence["evidence_id"] {
            return Err(Rejection::type_error(
                "Artifact inspection substep evidence ID does not match nested Evidence",
            ));
        }
        pages.push(parse_inventory_evidence_page(&evidence)?);
    }
    let Some(first) = pages.first() else {
        return Err(Rejection::type_error(
            "Artifact inspection requires inventory substeps",
        ));
    };
    let manifest = &first["manifest"];
    let declared = &input["subject"];
    if declared["manifest_id"] != manifest["manifest_id"]
        || declared["root_artifact_id"] != manifest["root_artifact_id"]
        || declared["root_sha256"] != manifest["root_sha256"]
        || declared["root_format"] != manifest["root_format"]
    {
        return Err(Rejection::type_error(
            "Artifact inspection subject does not match its inventory manifest",
        ));
    }
    if subject.is_null()
        || subject["digest"]["sha256"] != manifest["root_sha256"]
        || subject["format"] != manifest["root_format"]
    {
        return Err(Rejection::type_error(
            "Artifact inspection Evidence subject does not match its root manifest",
        ));
    }
    Ok(pages)
}

/// `assembleInventoryResults`.
fn assemble_inventory_results(pages: Vec<Value>) -> Result<InventorySet, Rejection> {
    let Some(first) = pages.first() else {
        return Err(Rejection::type_error(
            "Artifact inventory requires Evidence pages",
        ));
    };
    let manifest_json = canonical(&first["manifest"], CONTEXT)?;
    let coverage_json = canonical(&first["coverage"], COVERAGE_CONTEXT)?;
    let contradictions_json = canonical(&first["integrity_contradictions"], CONTEXT)?;
    let mut nodes = Members::default();
    let mut occurrences = Members::default();
    let mut edges = Members::default();
    for page in &pages {
        if canonical(&page["manifest"], CONTEXT)? != manifest_json {
            return Err(Rejection::type_error(
                "Artifact inventory pages do not share one manifest",
            ));
        }
        if canonical(&page["coverage"], COVERAGE_CONTEXT)? != coverage_json {
            return Err(Rejection::type_error(
                "Artifact inventory pages do not share one coverage declaration",
            ));
        }
        if canonical(&page["integrity_contradictions"], CONTEXT)? != contradictions_json {
            return Err(Rejection::type_error(
                "Artifact inventory pages do not share integrity contradictions",
            ));
        }
        for node in members(&page["nodes"]) {
            nodes.merge(text(&node["artifact_id"]), node, "node")?;
        }
        for occurrence in members(&page["occurrences"]) {
            occurrences.merge(text(&occurrence["occurrence_id"]), occurrence, "occurrence")?;
        }
        for edge in members(&page["edges"]) {
            edges.merge(text(&edge["edge_id"]), edge, "edge")?;
        }
    }
    let mut node_values = nodes.into_values();
    node_values.sort_by(|left, right| text(&left["artifact_id"]).cmp(text(&right["artifact_id"])));
    let mut edge_values = edges.into_values();
    edge_values.sort_by(|left, right| text(&left["edge_id"]).cmp(text(&right["edge_id"])));
    let occurrence_values = order_occurrences(
        text(&first["manifest"]["root_artifact_id"]),
        occurrences.into_values(),
    )?;
    let mut limitations = Vec::new();
    let mut seen = HashSet::new();
    for page in &pages {
        for item in members(&page["limitations"]).filter_map(Value::as_str) {
            if seen.insert(item.to_owned()) {
                limitations.push(item.to_owned());
            }
        }
    }
    limitations.sort();
    let count = |field: &str| first["manifest"][field].as_u64();
    let complete = count("node_count") == Some(node_values.len() as u64)
        && count("occurrence_count") == Some(occurrence_values.len() as u64)
        && count("edge_count") == Some(edge_values.len() as u64);
    let inventory = InventorySet {
        manifest: first["manifest"].clone(),
        occurrences: occurrence_values,
        nodes: node_values,
        integrity_contradictions: first["integrity_contradictions"].clone(),
        limitations,
        complete,
        coverage: first["coverage"].clone(),
    };
    if inventory.complete {
        validate_complete_inventory(&inventory, &edge_values)?;
    }
    Ok(inventory)
}

/// Insertion-ordered exact merge (`mergeExact` over a JavaScript `Map`).
#[derive(Default)]
struct Members {
    order: Vec<String>,
    values: HashMap<String, Value>,
}

impl Members {
    fn merge(&mut self, key: &str, value: &Value, label: &str) -> Result<(), Rejection> {
        match self.values.get(key) {
            Some(previous) => {
                if canonical(previous, CONTEXT)? != canonical(value, CONTEXT)? {
                    return Err(Rejection::type_error(format!(
                        "Artifact inventory has conflicting {label} pages"
                    )));
                }
                self.values.insert(key.to_owned(), value.clone());
            }
            None => {
                self.order.push(key.to_owned());
                self.values.insert(key.to_owned(), value.clone());
            }
        }
        Ok(())
    }

    fn into_values(mut self) -> Vec<Value> {
        self.order
            .iter()
            .filter_map(|key| self.values.remove(key))
            .collect()
    }
}

/// `orderOccurrences`: group by path (code-point order), then order
/// duplicates by their location ordinal.
fn order_occurrences(
    root_artifact_id: &str,
    occurrences: Vec<Value>,
) -> Result<Vec<Value>, Rejection> {
    let mut groups: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for occurrence in occurrences {
        groups
            .entry(text(&occurrence["logical_path"]).to_owned())
            .or_default()
            .push(occurrence);
    }
    let mut output = Vec::new();
    for (path, mut group) in groups {
        if group.len() < 2 {
            output.extend(group);
            continue;
        }
        let entry_kind = text(&group[0]["entry_kind"]).to_owned();
        let mut ordinal_by_id = HashMap::new();
        for ordinal in 0..group.len() {
            let id = occurrence_id_for_location(
                root_artifact_id,
                &path,
                &entry_kind,
                (ordinal != 0).then_some(ordinal),
            )?;
            ordinal_by_id.insert(id, ordinal);
        }
        group.sort_by(|left, right| {
            let ordinal = |value: &Value| {
                ordinal_by_id
                    .get(text(&value["occurrence_id"]))
                    .copied()
                    .unwrap_or(usize::MAX)
            };
            ordinal(left)
                .cmp(&ordinal(right))
                .then_with(|| text(&left["occurrence_id"]).cmp(text(&right["occurrence_id"])))
        });
        output.extend(group);
    }
    Ok(output)
}

fn validate_complete_inventory(inventory: &InventorySet, edges: &[Value]) -> Result<(), Rejection> {
    let manifest = &inventory.manifest;
    let node_ids: HashSet<&str> = inventory
        .nodes
        .iter()
        .map(|node| text(&node["artifact_id"]))
        .collect();
    let occurrence_ids: HashSet<&str> = inventory
        .occurrences
        .iter()
        .map(|occurrence| text(&occurrence["occurrence_id"]))
        .collect();
    let root_node = inventory
        .nodes
        .iter()
        .find(|node| node["artifact_id"] == manifest["root_artifact_id"]);
    if root_node.map(|node| &node["sha256"]) != Some(&manifest["root_sha256"]) {
        return Err(Rejection::type_error(
            "Artifact root node does not match its manifest digest",
        ));
    }
    let root_occurrence = inventory
        .occurrences
        .iter()
        .find(|occurrence| occurrence["logical_path"] == ".");
    if !root_occurrence.is_some_and(|occurrence| {
        occurrence["artifact_id"] == manifest["root_artifact_id"]
            && occurrence["artifact_format"] == manifest["root_format"]
    }) {
        return Err(Rejection::type_error(
            "Artifact root occurrence does not match its manifest representation",
        ));
    }
    let root_artifact_id = text(&manifest["root_artifact_id"]);
    let mut ordinals: HashMap<&str, usize> = HashMap::new();
    for occurrence in &inventory.occurrences {
        let path = text(&occurrence["logical_path"]);
        let ordinal = ordinals.get(path).copied().unwrap_or(0);
        ordinals.insert(path, ordinal + 1);
        if !occurrence["artifact_id"].is_null()
            && !node_ids.contains(text(&occurrence["artifact_id"]))
        {
            return Err(Rejection::type_error(
                "Artifact occurrence references a missing node",
            ));
        }
        if !occurrence["parent_occurrence_id"].is_null()
            && !occurrence_ids.contains(text(&occurrence["parent_occurrence_id"]))
        {
            return Err(Rejection::type_error(
                "Artifact occurrence references a missing parent",
            ));
        }
        let expected = occurrence_id_for_location(
            root_artifact_id,
            path,
            text(&occurrence["entry_kind"]),
            (ordinal != 0).then_some(ordinal),
        )?;
        if occurrence["occurrence_id"].as_str() != Some(expected.as_str()) {
            return Err(Rejection::type_error(
                "Artifact occurrence ID does not match its identity",
            ));
        }
    }
    let occurrences_by_id: HashMap<&str, &Value> = inventory
        .occurrences
        .iter()
        .map(|occurrence| (text(&occurrence["occurrence_id"]), occurrence))
        .collect();
    for edge in edges {
        let occurrence = occurrences_by_id.get(text(&edge["occurrence_id"]));
        let Some(occurrence) = occurrence.filter(|occurrence| {
            node_ids.contains(text(&edge["parent_artifact_id"]))
                && !occurrence["artifact_id"].is_null()
                && node_ids.contains(text(&occurrence["artifact_id"]))
        }) else {
            return Err(Rejection::type_error(
                "Artifact edge references a missing graph member",
            ));
        };
        let expected = format!(
            "edge_{}",
            digest(
                &json!({
                    "parent_artifact_id": edge["parent_artifact_id"],
                    "child_artifact_id": occurrence["artifact_id"],
                    "relation": edge["relation"],
                    "occurrence_id": edge["occurrence_id"],
                    "logical_path": occurrence["logical_path"],
                }),
                "Artifact",
            )?
        );
        if edge["edge_id"].as_str() != Some(expected.as_str()) {
            return Err(Rejection::type_error(
                "Artifact edge ID does not match its identity",
            ));
        }
    }
    let contradictions = inventory
        .integrity_contradictions
        .as_array()
        .cloned()
        .unwrap_or_default();
    for contradiction in &contradictions {
        if !node_ids.contains(text(&contradiction["parent_artifact_id"]))
            || !occurrence_ids.contains(text(&contradiction["occurrence_id"]))
        {
            return Err(Rejection::type_error(
                "Integrity contradiction references a missing graph member",
            ));
        }
        let expected = format!(
            "ic_{}",
            digest(
                &json!({
                    "root_artifact_id": root_artifact_id,
                    "logical_path": contradiction["logical_path"],
                    "declared_sha256": contradiction["declared_sha256"],
                    "observed_sha256": contradiction["observed_sha256"],
                }),
                "Artifact",
            )?
        );
        if contradiction["contradiction_id"].as_str() != Some(expected.as_str()) {
            return Err(Rejection::type_error(
                "Integrity contradiction ID does not match its identity",
            ));
        }
    }
    let graph_sha256 = digest(
        &json!({
            "nodes": inventory.nodes,
            "occurrences": inventory.occurrences,
            "edges": edges,
            "integrity_contradictions": contradictions,
        }),
        "Artifact",
    )?;
    if manifest["graph_sha256"].as_str() != Some(graph_sha256.as_str()) {
        return Err(Rejection::type_error(
            "Artifact graph commitment does not match its members",
        ));
    }
    let manifest_id = format!(
        "agm_{}",
        digest(
            &json!({ "root_artifact_id": root_artifact_id, "graph_sha256": graph_sha256 }),
            "Artifact",
        )?
    );
    if manifest["manifest_id"].as_str() != Some(manifest_id.as_str()) {
        return Err(Rejection::type_error(
            "Artifact manifest ID does not match its commitment",
        ));
    }
    Ok(())
}

/// `artifactIdForContent`.
fn artifact_id_for_content(sha256: &str) -> Result<String, Rejection> {
    Ok(format!(
        "art_{}",
        digest(&json!({ "sha256": sha256 }), "Artifact")?
    ))
}

/// `occurrenceIdForLocation`.
fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &str,
    entry_kind: &str,
    duplicate_ordinal: Option<usize>,
) -> Result<String, Rejection> {
    if logical_path == "." {
        return Ok(format!(
            "occ_{}",
            digest(&json!({ "root": root_artifact_id }), "Artifact")?
        ));
    }
    let mut object = Map::new();
    object.insert("root_artifact_id".into(), json!(root_artifact_id));
    object.insert("logical_path".into(), json!(logical_path));
    object.insert("entry_kind".into(), json!(entry_kind));
    if let Some(ordinal) = duplicate_ordinal {
        object.insert("duplicate_ordinal".into(), json!(ordinal));
    }
    Ok(format!(
        "occ_{}",
        digest(&Value::Object(object), "Artifact")?
    ))
}

/// `canonicalJson(value, context)`.
fn canonical(value: &Value, context: &str) -> Result<String, Rejection> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| Rejection::type_error(error.to_string()))?;
    let mut bytes = Vec::new();
    canonical_json::write(&raw, &mut bytes)
        .map_err(|_| Rejection::type_error(format!("{context} could not canonicalize data")))?;
    Ok(String::from_utf8(bytes).unwrap_or_default())
}

/// `digestCanonicalValue(value, context)`.
pub fn digest(value: &Value, context: &str) -> Result<String, Rejection> {
    canonical_json::digest(value)
        .map_err(|_| Rejection::type_error(format!("{context} could not canonicalize data")))
}

fn members(value: &Value) -> impl Iterator<Item = &Value> {
    value.as_array().into_iter().flatten()
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}
