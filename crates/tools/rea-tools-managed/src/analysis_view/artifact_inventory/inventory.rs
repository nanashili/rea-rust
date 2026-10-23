//! Owner boundary for artifact inventory and inspection Evidence parsing.
//!
//! Compatibility owners: `src/domain/artifactInventoryEvidence.ts`,
//! `src/domain/artifactInspection.ts`, `src/domain/artifactIdentity.ts` and the
//! inventory graph schema in `src/domain/artifactGraph.ts`.
use crate::common::json;
use crate::common::schema;
use crate::common::view::Parent;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, OnceLock};

/// Parsed inventory source backing both carriers.
pub struct InventorySource {
    pub inventory: Value,
    pub evidence_ids: Vec<String>,
    pub inspection: Option<Value>,
}

/// Either a caller-correctable `TypeError`/`ZodError` (surfaced as a `["source"]`
/// input issue carrying the message) or a fatal error that propagates verbatim.
pub enum SourceFault {
    /// `cause.message` of a `TypeError` or `ZodError`.
    Input(String),
    /// Authentication or output errors (not caught by `parseSource`).
    Fatal(AnalysisError),
}

type Faulted<T> = Result<T, SourceFault>;

/// `parseSource`: reuse the owning inventory parser for both carriers. A
/// `TypeError`/`ZodError` becomes `Input(message)`; other errors propagate.
pub fn parse_source(parent: &Parent<'_>) -> Faulted<InventorySource> {
    if parent.operation == "inventory_artifact" {
        parse_inventory_artifact(parent)
    } else {
        parse_inspection_artifact(parent)
    }
}

fn type_error<T>(message: impl Into<String>) -> Faulted<T> {
    Err(SourceFault::Input(message.into()))
}

// ---------------------------------------------------------------------------
// inventory_artifact carrier.
// ---------------------------------------------------------------------------

fn parse_inventory_artifact(parent: &Parent<'_>) -> Faulted<InventorySource> {
    let page = parse_inventory_page(parent.normalized_result, parent.subject)?;
    let inventory = assemble_inventory_results(&[page])?;
    Ok(InventorySource {
        inventory,
        evidence_ids: vec![parent.evidence_id.to_owned()],
        inspection: None,
    })
}

/// `parseInventoryPage`: structural parse + subject + page validation.
fn parse_inventory_page(input: &Value, subject: &Value) -> Faulted<Value> {
    let inventory = parse_inventory_schema(input)?;
    let manifest = inventory.get("manifest").cloned().unwrap_or(Value::Null);
    validate_artifact_inventory_subject(subject, &manifest)?;
    validate_inventory_page(&inventory)?;
    Ok(inventory)
}

/// Parse `input` with `artifactInventoryResultSchema` (a `z.strictObject`).
fn parse_inventory_schema(input: &Value) -> Faulted<Value> {
    let Some(root) = inventory_schema() else {
        return Err(SourceFault::Fatal(AnalysisError::output(
            crate::common::view::OPERATION,
            "The inventory_artifact result contract is unavailable.",
        )));
    };
    // Retained results use `z.object` strip semantics, matching `parse_result`;
    // a parse failure is a `ZodError`, surfaced as its message.
    schema::parse_stripped(&root, input)
        .map_err(|issues| SourceFault::Input(schema::describe(&issues)))
}

/// `validateArtifactInventorySubject`.
fn validate_artifact_inventory_subject(subject: &Value, manifest: &Value) -> Faulted<()> {
    let digest = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    let format = subject.get("format").and_then(Value::as_str);
    if !subject.is_object()
        || digest != manifest.get("root_sha256").and_then(Value::as_str)
        || format != manifest.get("root_format").and_then(Value::as_str)
    {
        return type_error("Artifact inventory Evidence subject does not match its root digest");
    }
    Ok(())
}

/// `validateInventoryPage`: unique IDs and content-addressed node IDs.
fn validate_inventory_page(inventory: &Value) -> Faulted<()> {
    assert_unique(json::array_at(inventory, "nodes"), "artifact_id", "node ID")?;
    assert_unique(
        json::array_at(inventory, "occurrences"),
        "occurrence_id",
        "occurrence ID",
    )?;
    assert_unique(json::array_at(inventory, "edges"), "edge_id", "edge ID")?;
    for node in json::array_at(inventory, "nodes") {
        let id = node
            .get("artifact_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let sha256 = node
            .get("sha256")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if id != artifact_id_for_content(sha256) {
            return type_error("Artifact node ID is not content-addressed");
        }
    }
    Ok(())
}

fn assert_unique(rows: &[Value], key: &str, label: &str) -> Faulted<()> {
    let mut seen = BTreeSet::new();
    for row in rows {
        let id = row
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if !seen.insert(id) {
            return type_error(format!("Artifact inventory contains a duplicate {label}"));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// inspect_artifact carrier.
// ---------------------------------------------------------------------------

fn parse_inspection_artifact(parent: &Parent<'_>) -> Faulted<InventorySource> {
    // `parseArtifactInspectionInventoryResult`.
    let inspection = parse_inspection_result(parent.normalized_result)?;
    let coverage_substeps = inspection
        .get("coverage")
        .and_then(|coverage| coverage.get("substeps_completed"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let substeps = json::array_at(&inspection, "substeps");
    if coverage_substeps != substeps.len() as u64 {
        return type_error(
            "Artifact inspection substep count does not match its coverage declaration",
        );
    }
    let mut pages = Vec::new();
    let mut evidence_ids = Vec::new();
    for step in substeps {
        let step_evidence = step.get("evidence").cloned().unwrap_or(Value::Null);
        // `parseEvidence(step.evidence)`: authenticate (propagates on failure).
        let evidence = crate::common::authenticate(&step_evidence).map_err(SourceFault::Fatal)?;
        let evidence_id = evidence
            .get("evidence_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if step.get("evidence_id").and_then(Value::as_str) != Some(evidence_id) {
            return type_error(
                "Artifact inspection substep evidence ID does not match nested Evidence",
            );
        }
        pages.push(parse_inventory_evidence_page(&evidence)?);
        evidence_ids.push(evidence_id.to_owned());
    }
    let Some(first_manifest) = pages
        .first()
        .map(|page| page.get("manifest").cloned().unwrap_or(Value::Null))
    else {
        return type_error("Artifact inspection requires inventory substeps");
    };
    validate_inspection_subject(parent.subject, &inspection, &first_manifest)?;
    let inventory = assemble_inventory_results(&pages)?;
    Ok(InventorySource {
        inventory,
        evidence_ids,
        inspection: Some(inspection),
    })
}

/// Parse `input` with `artifactInspectionResultSchema` via the catalog contract.
fn parse_inspection_result(input: &Value) -> Faulted<Value> {
    let Some(root) = schema::tool_result_schema("inspect_artifact") else {
        return Err(SourceFault::Fatal(AnalysisError::output(
            crate::common::view::OPERATION,
            "The inspect_artifact result contract is unavailable.",
        )));
    };
    schema::parse_stripped(&root, input)
        .map_err(|issues| SourceFault::Input(schema::describe(&issues)))
}

/// `parseInventoryEvidencePage`: operation check then page parse.
fn parse_inventory_evidence_page(evidence: &Value) -> Faulted<Value> {
    if evidence.get("operation").and_then(Value::as_str) != Some("inventory_artifact") {
        return type_error("Artifact inventory page must be inventory_artifact Evidence");
    }
    let normalized = evidence
        .get("normalized_result")
        .cloned()
        .unwrap_or(Value::Null);
    let subject = evidence.get("subject").cloned().unwrap_or(Value::Null);
    parse_inventory_page(&normalized, &subject)
}

/// `validateInspectionSubject`.
fn validate_inspection_subject(
    subject: &Value,
    inspection: &Value,
    manifest: &Value,
) -> Faulted<()> {
    let inspection_subject = inspection.get("subject").unwrap_or(&Value::Null);
    let field =
        |value: &Value, key: &str| value.get(key).and_then(Value::as_str).map(str::to_owned);
    if field(inspection_subject, "manifest_id") != field(manifest, "manifest_id")
        || field(inspection_subject, "root_artifact_id") != field(manifest, "root_artifact_id")
        || field(inspection_subject, "root_sha256") != field(manifest, "root_sha256")
        || field(inspection_subject, "root_format") != field(manifest, "root_format")
    {
        return type_error("Artifact inspection subject does not match its inventory manifest");
    }
    let digest = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str);
    let fmt = subject.get("format").and_then(Value::as_str);
    if !subject.is_object()
        || digest != manifest.get("root_sha256").and_then(Value::as_str)
        || fmt != manifest.get("root_format").and_then(Value::as_str)
    {
        return type_error("Artifact inspection Evidence subject does not match its root manifest");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Assembly (`assembleInventoryResults`, `orderedInventory`, completeness).
// ---------------------------------------------------------------------------

fn assemble_inventory_results(pages: &[Value]) -> Faulted<Value> {
    let Some(first) = pages.first() else {
        return type_error("Artifact inventory requires Evidence pages");
    };
    let manifest_digest = canonical(first.get("manifest").unwrap_or(&Value::Null))?;
    let coverage_digest = canonical(first.get("coverage").unwrap_or(&Value::Null))?;
    let first_contradictions_digest = canonical(
        first
            .get("integrity_contradictions")
            .unwrap_or(&Value::Null),
    )?;

    let mut nodes: BTreeMap<String, Value> = BTreeMap::new();
    let mut occurrences: BTreeMap<String, Value> = BTreeMap::new();
    let mut edges: BTreeMap<String, Value> = BTreeMap::new();

    for page in pages {
        if canonical(page.get("manifest").unwrap_or(&Value::Null))? != manifest_digest {
            return type_error("Artifact inventory pages do not share one manifest");
        }
        if canonical(page.get("coverage").unwrap_or(&Value::Null))? != coverage_digest {
            return type_error("Artifact inventory pages do not share one coverage declaration");
        }
        if canonical(page.get("integrity_contradictions").unwrap_or(&Value::Null))?
            != first_contradictions_digest
        {
            return type_error("Artifact inventory pages do not share integrity contradictions");
        }
        for node in json::array_at(page, "nodes") {
            merge_exact(&mut nodes, id_of(node, "artifact_id"), node, "node")?;
        }
        for occurrence in json::array_at(page, "occurrences") {
            merge_exact(
                &mut occurrences,
                id_of(occurrence, "occurrence_id"),
                occurrence,
                "occurrence",
            )?;
        }
        for edge in json::array_at(page, "edges") {
            merge_exact(&mut edges, id_of(edge, "edge_id"), edge, "edge")?;
        }
    }

    let inventory = ordered_inventory(first, pages, &nodes, &occurrences, &edges)?;
    if inventory.get("complete").and_then(Value::as_bool) == Some(true) {
        validate_complete_inventory(&inventory)?;
    }
    Ok(inventory)
}

fn id_of(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `mergeExact`: a later page may repeat a member only with identical bytes.
/// Insertion order is irrelevant; `orderedInventory` re-sorts by ID.
fn merge_exact(
    output: &mut BTreeMap<String, Value>,
    key: String,
    value: &Value,
    label: &str,
) -> Faulted<()> {
    if let Some(previous) = output.get(&key)
        && canonical(previous)? != canonical(value)?
    {
        return type_error(format!("Artifact inventory has conflicting {label} pages"));
    }
    output.insert(key, value.clone());
    Ok(())
}

fn ordered_inventory(
    first: &Value,
    pages: &[Value],
    nodes: &BTreeMap<String, Value>,
    occurrences: &BTreeMap<String, Value>,
    edges: &BTreeMap<String, Value>,
) -> Faulted<Value> {
    let manifest = first.get("manifest").cloned().unwrap_or(Value::Null);
    // `[...map.values()].sort(compareUnicodeCodePoints(id))`.
    let mut node_rows: Vec<Value> = nodes.values().cloned().collect();
    node_rows
        .sort_by(|left, right| sort_key(left, "artifact_id").cmp(&sort_key(right, "artifact_id")));
    let occurrence_rows = order_occurrences(
        manifest
            .get("root_artifact_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        occurrences.values().cloned().collect(),
    )?;
    let mut edge_rows: Vec<Value> = edges.values().cloned().collect();
    edge_rows.sort_by(|left, right| sort_key(left, "edge_id").cmp(&sort_key(right, "edge_id")));

    // `[...new Set(pages.flatMap(limitations))].sort(compareUnicodeCodePoints)`.
    let mut limitation_set: BTreeSet<String> = BTreeSet::new();
    let mut limitations: Vec<String> = Vec::new();
    for page in pages {
        for limitation in json::strings(page.get("limitations").unwrap_or(&Value::Null)) {
            if limitation_set.insert(limitation.clone()) {
                limitations.push(limitation);
            }
        }
    }
    limitations.sort();

    let node_count = manifest
        .get("node_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let occurrence_count = manifest
        .get("occurrence_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let edge_count = manifest
        .get("edge_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let complete = node_rows.len() as u64 == node_count
        && occurrence_rows.len() as u64 == occurrence_count
        && edge_rows.len() as u64 == edge_count;

    let contradictions = first
        .get("integrity_contradictions")
        .cloned()
        .unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("manifest".into(), manifest);
    out.insert("nodes".into(), Value::Array(node_rows));
    out.insert("occurrences".into(), Value::Array(occurrence_rows));
    out.insert("edges".into(), Value::Array(edge_rows));
    // Consumer reads `integrity_contradictions`; `complete` carries the
    // merged-count conclusion. The TS `InventorySet` also exposes `coverage`.
    out.insert("integrity_contradictions".into(), contradictions);
    out.insert("limitations".into(), json!(limitations));
    out.insert(
        "coverage".into(),
        first.get("coverage").cloned().unwrap_or(Value::Null),
    );
    out.insert("complete".into(), json!(complete));
    Ok(Value::Object(out))
}

fn sort_key(value: &Value, key: &str) -> Vec<u16> {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .encode_utf16()
        .collect()
}

/// `orderOccurrences`: group by logical path, order groups, then order within
/// duplicate groups by reconstructed occurrence ordinal.
fn order_occurrences(root_artifact_id: &str, occurrences: Vec<Value>) -> Faulted<Vec<Value>> {
    let mut groups: BTreeMap<Vec<u16>, (String, Vec<Value>)> = BTreeMap::new();
    for occurrence in occurrences {
        let path = occurrence
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        groups
            .entry(path.encode_utf16().collect())
            .or_insert_with(|| (path.clone(), Vec::new()))
            .1
            .push(occurrence);
    }
    let mut ordered = Vec::new();
    for (_, (path, mut group)) in groups {
        if group.len() < 2 {
            ordered.append(&mut group);
            continue;
        }
        let Some(first) = group.first().cloned() else {
            return type_error("Duplicate occurrence group is empty");
        };
        let entry_kind = first
            .get("entry_kind")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut ordinal_by_id: BTreeMap<String, usize> = BTreeMap::new();
        for ordinal in 0..group.len() {
            let id = occurrence_id_for_location(
                root_artifact_id,
                &path,
                entry_kind,
                if ordinal == 0 { None } else { Some(ordinal) },
            );
            ordinal_by_id.insert(id, ordinal);
        }
        group.sort_by(|left, right| {
            let left_id = left
                .get("occurrence_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let right_id = right
                .get("occurrence_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let left_ordinal = ordinal_by_id
                .get(left_id)
                .copied()
                .unwrap_or(MAX_SAFE_INTEGER);
            let right_ordinal = ordinal_by_id
                .get(right_id)
                .copied()
                .unwrap_or(MAX_SAFE_INTEGER);
            left_ordinal
                .cmp(&right_ordinal)
                .then_with(|| left_id.encode_utf16().cmp(right_id.encode_utf16()))
        });
        ordered.append(&mut group);
    }
    Ok(ordered)
}

const MAX_SAFE_INTEGER: usize = 9_007_199_254_740_991;

/// `validateCompleteInventory`.
fn validate_complete_inventory(inventory: &Value) -> Faulted<()> {
    let manifest = inventory.get("manifest").unwrap_or(&Value::Null);
    let nodes = json::array_at(inventory, "nodes");
    let occurrences = json::array_at(inventory, "occurrences");
    let edges = json::array_at(inventory, "edges");
    let contradictions = json::array_at(inventory, "integrity_contradictions");
    let root_artifact_id = manifest
        .get("root_artifact_id")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let node_ids: BTreeSet<&str> = nodes
        .iter()
        .filter_map(|node| node.get("artifact_id").and_then(Value::as_str))
        .collect();
    let occurrence_ids: BTreeSet<&str> = occurrences
        .iter()
        .filter_map(|occurrence| occurrence.get("occurrence_id").and_then(Value::as_str))
        .collect();

    let root_node = nodes
        .iter()
        .find(|node| node.get("artifact_id").and_then(Value::as_str) == Some(root_artifact_id));
    if root_node
        .and_then(|node| node.get("sha256"))
        .and_then(Value::as_str)
        != manifest.get("root_sha256").and_then(Value::as_str)
    {
        return type_error("Artifact root node does not match its manifest digest");
    }

    let root_occurrence = occurrences
        .iter()
        .find(|occurrence| occurrence.get("logical_path").and_then(Value::as_str) == Some("."));
    let root_occurrence_matches = root_occurrence.is_some_and(|occurrence| {
        occurrence.get("artifact_id").and_then(Value::as_str)
            == manifest.get("root_artifact_id").and_then(Value::as_str)
            && occurrence.get("artifact_format").and_then(Value::as_str)
                == manifest.get("root_format").and_then(Value::as_str)
    });
    if !root_occurrence_matches {
        return type_error("Artifact root occurrence does not match its manifest representation");
    }

    let mut duplicate_ordinal: BTreeMap<String, usize> = BTreeMap::new();
    for occurrence in occurrences {
        let path = occurrence
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let ordinal = *duplicate_ordinal.get(&path).unwrap_or(&0);
        duplicate_ordinal.insert(path, ordinal + 1);
        validate_occurrence(
            occurrence,
            root_artifact_id,
            &node_ids,
            &occurrence_ids,
            ordinal,
        )?;
    }

    let occurrences_by_id: BTreeMap<&str, &Value> = occurrences
        .iter()
        .filter_map(|occurrence| {
            occurrence
                .get("occurrence_id")
                .and_then(Value::as_str)
                .map(|id| (id, occurrence))
        })
        .collect();
    for edge in edges {
        validate_edge(edge, &node_ids, &occurrences_by_id)?;
    }

    for contradiction in contradictions {
        let parent_id = contradiction
            .get("parent_artifact_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let occurrence_id = contradiction
            .get("occurrence_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !node_ids.contains(parent_id) || !occurrence_ids.contains(occurrence_id) {
            return type_error("Integrity contradiction references a missing graph member");
        }
        let expected = artifact_contradiction_id(
            root_artifact_id,
            contradiction
                .get("logical_path")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            contradiction
                .get("declared_sha256")
                .and_then(Value::as_str)
                .unwrap_or_default(),
            contradiction
                .get("observed_sha256")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        if contradiction
            .get("contradiction_id")
            .and_then(Value::as_str)
            != Some(expected.as_str())
        {
            return type_error("Integrity contradiction ID does not match its identity");
        }
    }

    let graph_sha256 = artifact_graph_digest(&nodes, &occurrences, &edges, &contradictions)?;
    if Some(graph_sha256.as_str()) != manifest.get("graph_sha256").and_then(Value::as_str) {
        return type_error("Artifact graph commitment does not match its members");
    }
    let manifest_id = artifact_manifest_id(root_artifact_id, &graph_sha256);
    if Some(manifest_id.as_str()) != manifest.get("manifest_id").and_then(Value::as_str) {
        return type_error("Artifact manifest ID does not match its commitment");
    }
    Ok(())
}

fn validate_occurrence(
    occurrence: &Value,
    root_artifact_id: &str,
    node_ids: &BTreeSet<&str>,
    occurrence_ids: &BTreeSet<&str>,
    duplicate_ordinal: usize,
) -> Faulted<()> {
    if let Some(artifact_id) = occurrence.get("artifact_id").and_then(Value::as_str)
        && !node_ids.contains(artifact_id)
    {
        return type_error("Artifact occurrence references a missing node");
    }
    if let Some(parent) = occurrence
        .get("parent_occurrence_id")
        .and_then(Value::as_str)
        && !occurrence_ids.contains(parent)
    {
        return type_error("Artifact occurrence references a missing parent");
    }
    let expected = occurrence_id_for_location(
        root_artifact_id,
        occurrence
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        occurrence
            .get("entry_kind")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        if duplicate_ordinal == 0 {
            None
        } else {
            Some(duplicate_ordinal)
        },
    );
    if occurrence.get("occurrence_id").and_then(Value::as_str) != Some(expected.as_str()) {
        return type_error("Artifact occurrence ID does not match its identity");
    }
    Ok(())
}

fn validate_edge(
    edge: &Value,
    node_ids: &BTreeSet<&str>,
    occurrences: &BTreeMap<&str, &Value>,
) -> Faulted<()> {
    let occurrence_id = edge
        .get("occurrence_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let occurrence = occurrences.get(occurrence_id).copied();
    let parent_artifact_id = edge
        .get("parent_artifact_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let occurrence_artifact_id = occurrence
        .and_then(|value| value.get("artifact_id"))
        .and_then(Value::as_str);
    if !node_ids.contains(parent_artifact_id)
        || occurrence.is_none()
        || occurrence_artifact_id.is_none()
        || !node_ids.contains(occurrence_artifact_id.unwrap_or_default())
    {
        return type_error("Artifact edge references a missing graph member");
    }
    let occurrence = occurrence.unwrap_or(&Value::Null);
    if edge.get("edge_id").and_then(Value::as_str)
        != Some(artifact_edge_id(edge, occurrence).as_str())
    {
        return type_error("Artifact edge ID does not match its identity");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Identity helpers (`src/domain/artifactIdentity.ts`).
// ---------------------------------------------------------------------------

/// `digestCanonicalValue(value)`: 64-char lowercase hex of the canonical form.
fn digest_canonical(value: &Value) -> String {
    json::canonical_digest(value, "Artifact").unwrap_or_default()
}

/// Canonical digest used for page-equality comparisons (`canonicalJson` equality).
fn canonical(value: &Value) -> Faulted<String> {
    json::canonical_digest(value, "Artifact inventory").map_err(SourceFault::Fatal)
}

fn artifact_id_for_content(sha256: &str) -> String {
    format!("art_{}", digest_canonical(&json!({ "sha256": sha256 })))
}

fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &str,
    entry_kind: &str,
    duplicate_ordinal: Option<usize>,
) -> String {
    if logical_path == "." {
        return format!(
            "occ_{}",
            digest_canonical(&json!({ "root": root_artifact_id }))
        );
    }
    let mut semantic = Map::new();
    semantic.insert("root_artifact_id".into(), json!(root_artifact_id));
    semantic.insert("logical_path".into(), json!(logical_path));
    semantic.insert("entry_kind".into(), json!(entry_kind));
    if let Some(ordinal) = duplicate_ordinal {
        semantic.insert("duplicate_ordinal".into(), json!(ordinal));
    }
    format!("occ_{}", digest_canonical(&Value::Object(semantic)))
}

fn artifact_graph_digest(
    nodes: &[Value],
    occurrences: &[Value],
    edges: &[Value],
    contradictions: &[Value],
) -> Faulted<String> {
    let value = json!({
        "nodes": nodes,
        "occurrences": occurrences,
        "edges": edges,
        "integrity_contradictions": contradictions,
    });
    canonical(&value)
}

fn artifact_manifest_id(root_artifact_id: &str, graph_sha256: &str) -> String {
    format!(
        "agm_{}",
        digest_canonical(
            &json!({ "root_artifact_id": root_artifact_id, "graph_sha256": graph_sha256 })
        )
    )
}

fn artifact_contradiction_id(
    root_artifact_id: &str,
    logical_path: &str,
    declared_sha256: &str,
    observed_sha256: &str,
) -> String {
    format!(
        "ic_{}",
        digest_canonical(&json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": logical_path,
            "declared_sha256": declared_sha256,
            "observed_sha256": observed_sha256,
        }))
    )
}

fn artifact_edge_id(edge: &Value, occurrence: &Value) -> String {
    format!(
        "edge_{}",
        digest_canonical(&json!({
            "parent_artifact_id": edge.get("parent_artifact_id").cloned().unwrap_or(Value::Null),
            "child_artifact_id": occurrence.get("artifact_id").cloned().unwrap_or(Value::Null),
            "relation": edge.get("relation").cloned().unwrap_or(Value::Null),
            "occurrence_id": edge.get("occurrence_id").cloned().unwrap_or(Value::Null),
            "logical_path": occurrence.get("logical_path").cloned().unwrap_or(Value::Null),
        }))
    )
}

// ---------------------------------------------------------------------------
// Inventory schema extraction from the frozen catalog.
// ---------------------------------------------------------------------------

/// The `artifactInventoryResultSchema` JSON Schema, extracted from the embedded
/// `inspect_artifact` substep-evidence contract (`inventory_artifact` is not a
/// standalone catalog tool). Rooted with the document `$defs` for references.
fn inventory_schema() -> Option<Arc<Value>> {
    static CACHE: OnceLock<Option<Arc<Value>>> = OnceLock::new();
    CACHE
        .get_or_init(|| build_inventory_schema().map(Arc::new))
        .clone()
}

fn build_inventory_schema() -> Option<Value> {
    let contract = rea_mcp::catalog().tool("inspect_artifact")?;
    let document = contract.output_schema()?;
    let normalized = document.get("properties")?.get("normalized_result")?;
    let resolved = resolve_in(document, normalized);
    // Non-view branch of the result union.
    let branch = match resolved
        .get("anyOf")
        .or_else(|| resolved.get("oneOf"))
        .and_then(Value::as_array)
    {
        Some(options) => options
            .iter()
            .find(|option| !is_view_result(document, option))?,
        None => resolved,
    };
    let branch = resolve_in(document, branch);
    let substeps = resolve_in(document, branch.get("properties")?.get("substeps")?);
    let items = resolve_in(document, substeps.get("items")?);
    let evidence = resolve_in(document, items.get("properties")?.get("evidence")?);
    let inventory = evidence.get("properties")?.get("normalized_result")?;
    Some(root_with_defs(document, resolve_in(document, inventory)))
}

fn resolve_in<'a>(document: &'a Value, schema: &'a Value) -> &'a Value {
    let mut current = schema;
    for _ in 0..64 {
        let Some(pointer) = current
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|r| r.strip_prefix('#'))
        else {
            break;
        };
        match document.pointer(pointer) {
            Some(target) => current = target,
            None => break,
        }
    }
    current
}

fn is_view_result(document: &Value, schema: &Value) -> bool {
    resolve_in(document, schema)
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key("parent_evidence_id"))
}

fn root_with_defs(document: &Value, schema: &Value) -> Value {
    let mut root = schema.as_object().cloned().unwrap_or_default();
    if let Some(defs) = document.get("$defs") {
        root.insert("$defs".into(), defs.clone());
    }
    Value::Object(root)
}
