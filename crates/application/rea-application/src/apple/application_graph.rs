//! Execution-free Apple application graph projection.
//!
//! The projection consumes authenticated artifact-inventory Evidence. It does
//! not open the inventory's target again, parse plist or signing content, or
//! execute application code.

use crate::artifacts;
use rea_core::{
    canonical_json,
    evidence::record::{EvidenceRecord, EvidenceRecordError},
    failure::{Detail, Failure},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub const OPERATION: &str = "project_apple_application_graph";
const INVENTORY_OPERATION: &str = "inventory_artifact";
const INSPECTION_OPERATION: &str = "inspect_artifact";
const MAX_BRIDGE_CANDIDATE_JSON_BYTES: usize = 2 * 1024 * 1024;

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_input(input)
        .map(|_| ())
        .map_err(ProjectionError::into_failure)
}

/// Project authenticated inventory Evidence without reading archive contents.
pub fn project(input: &Value) -> Result<Value, String> {
    let parsed = parse_input(input).map_err(|error| error.to_string())?;
    project_inventory(&parsed)
}

/// Wrap the deterministic graph projection in authenticated, linked Evidence.
pub fn project_evidence(input: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parsed = parse_input(input).map_err(ProjectionError::into_failure)?;
    let result = project_inventory(&parsed).map_err(|reason| invalid(&reason))?;
    let source_evidence_ids = result["source_evidence_ids"].clone();
    let subject = projected_subject(
        parsed
            .carriers
            .first()
            .expect("parse_input rejects empty Evidence"),
        &result["root_sha256"],
    )?;
    let limitations = result["limitations"].clone();

    let unsigned = json!({
        "subject": subject,
        "provider": {
            "id": "rea-apple-application",
            "name": "REA Apple application workflows",
            "version": "1"
        },
        "analysis_profile": null,
        "predicate_type": "rea.apple-application-graph",
        "operation": OPERATION,
        "parameters": {"inventory_evidence_ids": source_evidence_ids.clone()},
        "raw_result": null,
        "normalized_result": result,
        "confidence": "inferred",
        "authority": "analyst-inference",
        "environment": null,
        "limitations": limitations,
        "relationship_coverage": null,
        "locations": [],
        "evidence_links": source_evidence_ids
    });

    let raw = serde_json::value::to_raw_value(&unsigned)
        .map_err(|error| protocol_failure(&error.to_string()))?;
    let evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| protocol_failure(&error.to_string()))?;
    Ok(
        serde_json::value::RawValue::from_string(evidence.raw().get().to_owned())
            .expect("validated Evidence is valid JSON"),
    )
}

struct ParsedInput {
    carriers: Vec<EvidenceRecord>,
    source_evidence_ids: Vec<String>,
    pages: Vec<InventoryPage>,
}

struct InventoryPage {
    result: Value,
}

fn parse_input(input: &Value) -> Result<ParsedInput, ProjectionError> {
    let object = input
        .as_object()
        .ok_or_else(|| ProjectionError::Invalid("input must be an object".into()))?;
    if object.len() != 1 || !object.contains_key("inventory_evidence") {
        return Err(ProjectionError::Invalid(
            "input must contain only inventory_evidence".into(),
        ));
    }

    let values = object
        .get("inventory_evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| ProjectionError::Invalid("inventory_evidence must be an array".into()))?;
    if values.is_empty() {
        return Err(ProjectionError::Invalid(
            "inventory_evidence must contain at least one record".into(),
        ));
    }

    let mut carriers = Vec::with_capacity(values.len());
    let mut pages = Vec::new();
    let mut source_evidence_ids = Vec::with_capacity(values.len());

    for value in values {
        let record = parse_evidence_record(value)?;
        source_evidence_ids.push(record.evidence_id().to_owned());

        if record.operation_matches(INVENTORY_OPERATION) {
            pages.push(parse_inventory_page(&record)?);
        } else if record.operation_matches(INSPECTION_OPERATION) {
            pages.extend(parse_inspection_pages(&record)?);
        } else {
            return Err(ProjectionError::Invalid(
                "Apple application projection requires inventory_artifact or inspect_artifact Evidence".into(),
            ));
        }

        carriers.push(record);
    }

    if pages.is_empty() {
        return Err(ProjectionError::Invalid(
            "Artifact inspection requires inventory substeps".into(),
        ));
    }
    source_evidence_ids.sort();

    Ok(ParsedInput {
        carriers,
        source_evidence_ids,
        pages,
    })
}

fn parse_evidence_record(value: &Value) -> Result<EvidenceRecord, ProjectionError> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| ProjectionError::Invalid(error.to_string()))?;
    EvidenceRecord::parse(&raw).map_err(ProjectionError::from)
}

fn parse_inventory_page(record: &EvidenceRecord) -> Result<InventoryPage, ProjectionError> {
    let result = artifacts::inventory_evidence::normalize_result(parse_record_result(&record)?)
        .map_err(ProjectionError::Invalid)?;
    validate_inventory_subject(&record, &result)?;
    validate_page_shape(&result)?;

    Ok(InventoryPage { result })
}

fn parse_inspection_pages(carrier: &EvidenceRecord) -> Result<Vec<InventoryPage>, ProjectionError> {
    let inspection = parse_record_result(carrier)?;
    let inspection: ArtifactInspectionResult =
        serde_json::from_value(inspection).map_err(|error| {
            ProjectionError::Invalid(format!(
                "Artifact inspection result does not match its schema: {error}"
            ))
        })?;
    validate_inspection_result(&inspection)?;

    if inspection.coverage.substeps_completed != inspection.substeps.len() as u64 {
        return Err(ProjectionError::Invalid(
            "Artifact inspection substep count does not match its coverage declaration".into(),
        ));
    }

    let mut pages = Vec::with_capacity(inspection.substeps.len());
    for substep in &inspection.substeps {
        let record = parse_evidence_record(&substep.evidence)?;
        if substep.evidence_id != record.evidence_id() {
            return Err(ProjectionError::Invalid(
                "Artifact inspection substep evidence ID does not match nested Evidence".into(),
            ));
        }
        if !record.operation_matches(INVENTORY_OPERATION) {
            return Err(ProjectionError::Invalid(
                "Artifact inspection substep is not inventory_artifact Evidence".into(),
            ));
        }
        pages.push(parse_inventory_page(&record)?);
    }

    let first = pages.first().ok_or_else(|| {
        ProjectionError::Invalid("Artifact inspection requires inventory substeps".into())
    })?;
    validate_inspection_subject(carrier, &inspection, &first.result)?;
    Ok(pages)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionResult {
    inspection_id: String,
    subject: ArtifactInspectionSubject,
    substeps: Vec<ArtifactInspectionSubstep>,
    observations: Vec<ArtifactInspectionObservation>,
    hypotheses: Vec<ArtifactInspectionHypothesis>,
    contradictions: Vec<ArtifactInspectionContradiction>,
    unexplored_branches: Vec<ArtifactInspectionBranch>,
    next_probes: Vec<ArtifactInspectionProbe>,
    coverage: ArtifactInspectionCoverage,
    evidence_links: Vec<String>,
    limitations: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionSubject {
    manifest_id: String,
    root_artifact_id: String,
    root_sha256: String,
    root_format: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionSubstep {
    substep_id: String,
    operation: String,
    status: String,
    evidence_id: String,
    evidence: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionObservation {
    observation_id: String,
    kind: String,
    subject: String,
    #[serde(rename = "value")]
    _value: Value,
    evidence_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionHypothesis {
    hypothesis_id: String,
    statement: String,
    confidence: String,
    basis_evidence_ids: Vec<String>,
    limitation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionContradiction {
    contradiction_id: String,
    statement: String,
    occurrence_id: String,
    declared_sha256: String,
    observed_sha256: String,
    evidence_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionBranch {
    branch_id: String,
    reason: String,
    detail: String,
    next_probe: Value,
    evidence_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionProbe {
    operation: String,
    rationale: String,
    authority: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInspectionCoverage {
    status: String,
    substeps_completed: u64,
    observations_retained: u64,
    observations_omitted: u64,
    hypotheses_retained: u64,
    hypotheses_omitted: u64,
    unexplored_branches_retained: u64,
    unexplored_branches_omitted: u64,
    next_probes_retained: u64,
    next_probes_omitted: u64,
}

fn validate_inspection_result(
    inspection: &ArtifactInspectionResult,
) -> Result<(), ProjectionError> {
    validate_inspection_identity(&inspection.inspection_id, &inspection.subject)?;
    validate_inspection_substeps(&inspection.substeps)?;
    validate_inspection_observations(&inspection.observations)?;
    validate_inspection_hypotheses(&inspection.hypotheses)?;
    validate_inspection_contradictions(&inspection.contradictions)?;
    validate_inspection_branches(&inspection.unexplored_branches)?;
    validate_inspection_probes(&inspection.next_probes)?;
    validate_inspection_coverage(&inspection.coverage)?;
    validate_inspection_evidence_links(&inspection.evidence_links, &inspection.limitations)?;

    Ok(())
}

fn validate_inspection_identity(
    inspection_id: &str,
    subject: &ArtifactInspectionSubject,
) -> Result<(), ProjectionError> {
    validate_prefixed_digest(inspection_id, "ai", "inspection_id")?;
    validate_prefixed_digest(&subject.manifest_id, "agm", "inspection manifest_id")?;
    validate_prefixed_digest(
        &subject.root_artifact_id,
        "art",
        "inspection root_artifact_id",
    )?;
    validate_sha256(&subject.root_sha256, "inspection root_sha256")?;
    validate_nonempty(&subject.root_format, "inspection root_format")
}

fn validate_inspection_substeps(
    substeps: &[ArtifactInspectionSubstep],
) -> Result<(), ProjectionError> {
    if substeps.is_empty() {
        return Err(invalid_inspection_field(
            "substeps",
            "must contain at least one entry",
        ));
    }
    for substep in substeps {
        validate_prefixed_digest(&substep.substep_id, "ais", "substep_id")?;
        if substep.operation != INVENTORY_OPERATION || substep.status != "completed" {
            return Err(invalid_inspection_field(
                "substeps",
                "entries must be completed inventory_artifact operations",
            ));
        }
        validate_prefixed_digest(&substep.evidence_id, "ev", "substep evidence_id")?;
    }

    Ok(())
}

fn validate_inspection_observations(
    observations: &[ArtifactInspectionObservation],
) -> Result<(), ProjectionError> {
    for observation in observations {
        validate_prefixed_digest(&observation.observation_id, "aio", "observation_id")?;
        if !matches!(observation.kind.as_str(), "root-manifest" | "integrity") {
            return Err(invalid_inspection_field(
                "observations.kind",
                "has an unknown value",
            ));
        }
        validate_nonempty(&observation.subject, "observations.subject")?;
        validate_prefixed_digest(&observation.evidence_id, "ev", "observations.evidence_id")?;
    }

    Ok(())
}

fn validate_inspection_hypotheses(
    hypotheses: &[ArtifactInspectionHypothesis],
) -> Result<(), ProjectionError> {
    for hypothesis in hypotheses {
        validate_prefixed_digest(&hypothesis.hypothesis_id, "aih", "hypothesis_id")?;
        validate_nonempty(&hypothesis.statement, "hypotheses.statement")?;
        if !matches!(hypothesis.confidence.as_str(), "medium" | "low") {
            return Err(invalid_inspection_field(
                "hypotheses.confidence",
                "has an unknown value",
            ));
        }
        if hypothesis.basis_evidence_ids.is_empty() {
            return Err(invalid_inspection_field(
                "hypotheses.basis_evidence_ids",
                "must contain at least one entry",
            ));
        }
        for evidence_id in &hypothesis.basis_evidence_ids {
            validate_prefixed_digest(evidence_id, "ev", "hypotheses.basis_evidence_ids")?;
        }
        validate_nonempty(&hypothesis.limitation, "hypotheses.limitation")?;
    }

    Ok(())
}

fn validate_inspection_contradictions(
    contradictions: &[ArtifactInspectionContradiction],
) -> Result<(), ProjectionError> {
    for contradiction in contradictions {
        validate_prefixed_digest(&contradiction.contradiction_id, "aic", "contradiction_id")?;
        validate_nonempty(&contradiction.statement, "contradictions.statement")?;
        validate_prefixed_digest(
            &contradiction.occurrence_id,
            "occ",
            "contradictions.occurrence_id",
        )?;
        validate_sha256(
            &contradiction.declared_sha256,
            "contradictions.declared_sha256",
        )?;
        validate_sha256(
            &contradiction.observed_sha256,
            "contradictions.observed_sha256",
        )?;
        validate_prefixed_digest(
            &contradiction.evidence_id,
            "ev",
            "contradictions.evidence_id",
        )?;
    }

    Ok(())
}

fn validate_inspection_branches(
    branches: &[ArtifactInspectionBranch],
) -> Result<(), ProjectionError> {
    for branch in branches {
        validate_prefixed_digest(&branch.branch_id, "aib", "branch_id")?;
        if !matches!(
            branch.reason.as_str(),
            "format-specific-analysis-required" | "unknown-format"
        ) {
            return Err(invalid_inspection_field(
                "unexplored_branches.reason",
                "has an unknown value",
            ));
        }
        validate_nonempty(&branch.detail, "unexplored_branches.detail")?;
        validate_optional_probe(&branch.next_probe)?;
        validate_prefixed_digest(&branch.evidence_id, "ev", "unexplored_branches.evidence_id")?;
    }

    Ok(())
}

fn validate_inspection_probes(probes: &[ArtifactInspectionProbe]) -> Result<(), ProjectionError> {
    for probe in probes {
        validate_probe(probe)?;
    }

    Ok(())
}

fn validate_inspection_coverage(
    coverage: &ArtifactInspectionCoverage,
) -> Result<(), ProjectionError> {
    if !matches!(
        coverage.status.as_str(),
        "complete-within-substeps" | "partial" | "truncated"
    ) {
        return Err(invalid_inspection_field(
            "coverage.status",
            "has an unknown value",
        ));
    }
    for count in [
        coverage.substeps_completed,
        coverage.observations_retained,
        coverage.observations_omitted,
        coverage.hypotheses_retained,
        coverage.hypotheses_omitted,
        coverage.unexplored_branches_retained,
        coverage.unexplored_branches_omitted,
        coverage.next_probes_retained,
        coverage.next_probes_omitted,
    ] {
        if count > 9_007_199_254_740_991 {
            return Err(invalid_inspection_field(
                "coverage",
                "contains a count outside the safe-integer range",
            ));
        }
    }
    if coverage.substeps_completed == 0 {
        return Err(invalid_inspection_field(
            "coverage.substeps_completed",
            "must be at least one",
        ));
    }

    Ok(())
}

fn validate_inspection_evidence_links(
    evidence_links: &[String],
    limitations: &[String],
) -> Result<(), ProjectionError> {
    if evidence_links.is_empty() {
        return Err(invalid_inspection_field(
            "evidence_links",
            "must contain at least one entry",
        ));
    }
    for evidence_id in evidence_links {
        validate_prefixed_digest(evidence_id, "ev", "evidence_links")?;
    }
    for limitation in limitations {
        validate_nonempty(limitation, "limitations")?;
    }

    Ok(())
}

fn validate_optional_probe(value: &Value) -> Result<(), ProjectionError> {
    if value.is_null() {
        return Ok(());
    }
    let probe: ArtifactInspectionProbe =
        serde_json::from_value(value.clone()).map_err(|error| {
            ProjectionError::Invalid(format!(
                "Artifact inspection next_probe does not match its schema: {error}"
            ))
        })?;
    validate_probe(&probe)
}

fn validate_probe(probe: &ArtifactInspectionProbe) -> Result<(), ProjectionError> {
    validate_nonempty(&probe.operation, "next_probes.operation")?;
    validate_nonempty(&probe.rationale, "next_probes.rationale")?;
    if !matches!(
        probe.authority.as_str(),
        "artifact-bytes"
            | "managed-static-analysis"
            | "native-analysis-provider"
            | "ast-static-analysis"
    ) {
        return Err(invalid_inspection_field(
            "next_probes.authority",
            "has an unknown value",
        ));
    }
    Ok(())
}

fn validate_prefixed_digest(value: &str, prefix: &str, field: &str) -> Result<(), ProjectionError> {
    let Some(digest) = value.strip_prefix(&format!("{prefix}_")) else {
        return Err(invalid_inspection_field(field, "has an invalid identifier"));
    };
    validate_sha256(digest, field)
}

fn validate_sha256(value: &str, field: &str) -> Result<(), ProjectionError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_inspection_field(
            field,
            "must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_nonempty(value: &str, field: &str) -> Result<(), ProjectionError> {
    if value.is_empty() {
        return Err(invalid_inspection_field(field, "must not be empty"));
    }
    Ok(())
}

fn invalid_inspection_field(field: &str, reason: &str) -> ProjectionError {
    ProjectionError::Invalid(format!("Artifact inspection {field} {reason}"))
}

fn parse_record_result(record: &EvidenceRecord) -> Result<Value, ProjectionError> {
    serde_json::from_str(record.normalized_result().get()).map_err(|error| {
        ProjectionError::Invalid(format!("Evidence normalized_result is invalid: {error}"))
    })
}

fn validate_inventory_subject(
    record: &EvidenceRecord,
    result: &Value,
) -> Result<(), ProjectionError> {
    let manifest = result
        .get("manifest")
        .ok_or_else(|| ProjectionError::Invalid("inventory result has no manifest".into()))?;
    let root_sha256 = required_string(manifest, "root_sha256", "inventory manifest")?;
    let root_format = required_string(manifest, "root_format", "inventory manifest")?;
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| ProjectionError::Invalid(error.to_string()))?;
    if subject.is_null()
        || subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            .and_then(Value::as_str)
            != Some(root_sha256)
        || subject.get("format").and_then(Value::as_str) != Some(root_format)
    {
        return Err(ProjectionError::Invalid(
            "Artifact inventory Evidence subject does not match its root digest".into(),
        ));
    }
    Ok(())
}

fn validate_inspection_subject(
    carrier: &EvidenceRecord,
    inspection: &ArtifactInspectionResult,
    first_inventory: &Value,
) -> Result<(), ProjectionError> {
    let manifest = first_inventory
        .get("manifest")
        .ok_or_else(|| ProjectionError::Invalid("inventory has no manifest".into()))?;
    if Some(inspection.subject.manifest_id.as_str())
        != manifest.get("manifest_id").and_then(Value::as_str)
        || Some(inspection.subject.root_artifact_id.as_str())
            != manifest.get("root_artifact_id").and_then(Value::as_str)
        || Some(inspection.subject.root_sha256.as_str())
            != manifest.get("root_sha256").and_then(Value::as_str)
        || Some(inspection.subject.root_format.as_str())
            != manifest.get("root_format").and_then(Value::as_str)
    {
        return Err(ProjectionError::Invalid(
            "Artifact inspection subject does not match its inventory manifest".into(),
        ));
    }

    let outer_subject: Value = serde_json::from_str(carrier.subject().get())
        .map_err(|error| ProjectionError::Invalid(error.to_string()))?;
    if outer_subject.is_null()
        || outer_subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            != manifest.get("root_sha256")
        || outer_subject.get("format") != manifest.get("root_format")
    {
        return Err(ProjectionError::Invalid(
            "Artifact inspection Evidence subject does not match its root manifest".into(),
        ));
    }
    Ok(())
}

fn validate_page_shape(result: &Value) -> Result<(), ProjectionError> {
    for field in ["nodes", "occurrences", "edges", "integrity_contradictions"] {
        if !result.get(field).is_some_and(Value::is_array) {
            return Err(ProjectionError::Invalid(format!(
                "inventory result {field} must be an array"
            )));
        }
    }
    if !result.get("coverage").is_some_and(Value::is_object) {
        return Err(ProjectionError::Invalid(
            "inventory result has no coverage declaration".into(),
        ));
    }
    let manifest = result
        .get("manifest")
        .and_then(Value::as_object)
        .ok_or_else(|| ProjectionError::Invalid("inventory result has no manifest".into()))?;
    for field in [
        "root_artifact_id",
        "root_sha256",
        "root_format",
        "graph_sha256",
    ] {
        required_string(
            &Value::Object(manifest.clone()),
            field,
            "inventory manifest",
        )?;
    }

    for node in result["nodes"].as_array().expect("validated array") {
        let id = required_string(node, "artifact_id", "inventory node")?;
        let sha256 = required_string(node, "sha256", "inventory node")?;
        let expected = artifact_id_for_sha256(sha256)?;
        if id != expected {
            return Err(ProjectionError::Invalid(
                "Artifact node ID is not content-addressed".into(),
            ));
        }
    }
    assert_unique_page_ids(result, "nodes", "artifact_id", "node ID")?;
    assert_unique_page_ids(result, "occurrences", "occurrence_id", "occurrence ID")?;
    assert_unique_page_ids(result, "edges", "edge_id", "edge ID")?;
    Ok(())
}

fn assert_unique_page_ids(
    result: &Value,
    collection: &str,
    identity: &str,
    label: &str,
) -> Result<(), ProjectionError> {
    let values = result[collection]
        .as_array()
        .expect("page shape has validated arrays");
    let mut ids = HashSet::with_capacity(values.len());
    for value in values {
        let id = required_string(value, identity, "inventory graph member")?;
        if !ids.insert(id) {
            return Err(ProjectionError::Invalid(format!(
                "Artifact inventory contains a duplicate {label}"
            )));
        }
    }
    Ok(())
}

fn project_inventory(parsed: &ParsedInput) -> Result<Value, String> {
    let inventory = Inventory::assemble(&parsed.pages)?;
    let root_format = match inventory.root_format.as_str() {
        "ipa" | "directory" | "zip" | "dmg" => inventory.root_format.as_str(),
        other => {
            return Err(format!(
                "Apple application projection requires IPA, directory, ZIP, or DMG inventory Evidence (got {other})"
            ));
        }
    };
    let entries = inventory.entries()?;
    let tree = index_tree(&entries);
    let first_carrier = parsed
        .carriers
        .first()
        .ok_or("Apple projection requires Evidence")?;
    let subject: Value =
        serde_json::from_str(first_carrier.subject().get()).map_err(|error| error.to_string())?;
    let subject_name = subject
        .get("name")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let roots = application_roots(&tree, subject_name, root_format);
    let bundles = detect_bundles(&tree, &roots);

    let file_components = entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
        .filter_map(|entry| entry.component.clone())
        .collect::<Vec<_>>();
    let attributed = attribute_components(&file_components, &roots, root_format);
    let unavailable_entries = entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
        .filter_map(|entry| entry.unavailable.clone())
        .collect::<Vec<_>>();
    let unavailable = attribute_components(&unavailable_entries, &roots, root_format);
    let classified = classify_components(&entries, &attributed.all, &roots);
    let runtime_families = identify_runtime_families(&attributed.all);
    let bridge = identify_bridge_candidates(
        &classified.javascript,
        &deduplicate_components(
            classified
                .executables
                .iter()
                .chain(classified.native_libraries.iter())
                .cloned(),
        ),
        &roots,
    );
    let mut symlinks = entries
        .iter()
        .filter(|entry| entry.kind == "symlink")
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    symlinks.sort();
    let uninventoried_image = root_format == "dmg" && inventory.occurrences.len() == 1;
    let inventory_complete = inventory.complete
        && inventory.coverage.get("scope").and_then(Value::as_str) == Some("container-entries")
        && inventory.coverage.get("status").and_then(Value::as_str) == Some("complete");
    let complete = inventory_complete && !uninventoried_image;
    let limitations = projection_limitations(
        &inventory,
        inventory_complete,
        uninventoried_image,
        &roots,
        &bundles,
        !symlinks.is_empty(),
        entries.iter().any(|entry| is_sidecar(&entry.path)),
        attributed.unattributed + unavailable.unattributed,
        !unavailable.all.is_empty(),
        &bridge.coverage,
    );

    let mut without_id = json!({
        "root_sha256": inventory.root_sha256,
        "root_format": root_format,
        "platforms": platforms_of(&bundles),
        "source_evidence_ids": parsed.source_evidence_ids,
        "application_roots": roots,
        "bundles": bundles,
        "components": classified.as_value(),
        "unavailable_components": unavailable.all,
        "symlinks": symlinks,
        "runtime_families": runtime_families,
        "bridge_candidates": bridge.candidates,
        "bridge_candidate_coverage": bridge.coverage,
        "coverage": {
            "status": if complete
                && unavailable.all.is_empty()
                && bridge.coverage["status"] == "complete"
            { "complete-within-inventory" } else { "partial" },
            "inventory_complete": inventory.complete,
        },
        "limitations": limitations,
    });
    let projection_id = canonical_json::digest(&without_id).map_err(|error| error.to_string())?;
    without_id["projection_id"] = Value::String(format!("aap_{projection_id}"));
    Ok(without_id)
}

struct Inventory {
    root_artifact_id: String,
    root_sha256: String,
    root_format: String,
    nodes: BTreeMap<String, Value>,
    occurrences: Vec<Value>,
    edges: Vec<Value>,
    integrity_contradictions: Vec<Value>,
    coverage: Value,
    complete: bool,
    limitations: Vec<String>,
}

impl Inventory {
    fn assemble(pages: &[InventoryPage]) -> Result<Self, String> {
        let first = pages
            .first()
            .ok_or("Artifact inventory requires Evidence pages")?;
        let manifest = first
            .result
            .get("manifest")
            .ok_or("inventory result has no manifest")?;
        let coverage = first
            .result
            .get("coverage")
            .ok_or("inventory result has no coverage")?;
        let contradictions = first
            .result
            .get("integrity_contradictions")
            .ok_or("inventory has no integrity contradictions")?;
        let mut nodes = BTreeMap::new();
        let mut occurrences = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut limitations = BTreeSet::new();

        for page in pages {
            for (field, expected, description) in [
                ("manifest", manifest, "one manifest"),
                ("coverage", coverage, "one coverage declaration"),
                (
                    "integrity_contradictions",
                    contradictions,
                    "shared integrity contradictions",
                ),
            ] {
                if page.result.get(field) != Some(expected) {
                    return Err(format!(
                        "Artifact inventory pages do not share {description}"
                    ));
                }
            }

            merge_members(&mut nodes, &page.result["nodes"], "artifact_id", "node")?;
            merge_members(
                &mut occurrences,
                &page.result["occurrences"],
                "occurrence_id",
                "occurrence",
            )?;
            merge_members(&mut edges, &page.result["edges"], "edge_id", "edge")?;
            if let Some(values) = page.result.get("limitations").and_then(Value::as_array) {
                limitations.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
            }
        }

        let root_artifact_id =
            required_string(manifest, "root_artifact_id", "inventory manifest")?.to_owned();
        let root_sha256 =
            required_string(manifest, "root_sha256", "inventory manifest")?.to_owned();
        let root_format =
            required_string(manifest, "root_format", "inventory manifest")?.to_owned();
        let expected_nodes = required_count(manifest, "node_count")?;
        let expected_occurrences = required_count(manifest, "occurrence_count")?;
        let expected_edges = required_count(manifest, "edge_count")?;
        let complete = nodes.len() == expected_nodes
            && occurrences.len() == expected_occurrences
            && edges.len() == expected_edges;
        let mut occurrences = occurrences.into_values().collect::<Vec<_>>();
        order_occurrences(&mut occurrences, &root_artifact_id);
        let edges = edges.into_values().collect::<Vec<_>>();
        let integrity_contradictions = contradictions
            .as_array()
            .ok_or("inventory integrity_contradictions must be an array")?
            .clone();
        let inventory = Self {
            root_artifact_id,
            root_sha256,
            root_format,
            nodes,
            occurrences,
            edges,
            integrity_contradictions,
            coverage: coverage.clone(),
            complete,
            limitations: limitations.into_iter().collect(),
        };

        if inventory.complete {
            inventory.validate_complete(manifest)?;
        }
        Ok(inventory)
    }

    fn validate_complete(&self, manifest: &Value) -> Result<(), String> {
        let root_node = self.nodes.get(&self.root_artifact_id);
        if root_node
            .and_then(|node| node.get("sha256"))
            .and_then(Value::as_str)
            != Some(self.root_sha256.as_str())
        {
            return Err("Artifact root node does not match its manifest digest".into());
        }
        let root_occurrence = self
            .occurrences
            .iter()
            .find(|occurrence| occurrence.get("logical_path").and_then(Value::as_str) == Some("."));
        if root_occurrence
            .and_then(|occurrence| occurrence.get("artifact_id"))
            .and_then(Value::as_str)
            != Some(self.root_artifact_id.as_str())
            || root_occurrence
                .and_then(|occurrence| occurrence.get("artifact_format"))
                .and_then(Value::as_str)
                != Some(self.root_format.as_str())
        {
            return Err(
                "Artifact root occurrence does not match its manifest representation".into(),
            );
        }

        let node_ids = self.nodes.keys().cloned().collect::<HashSet<_>>();
        let occurrence_ids = self
            .occurrences
            .iter()
            .filter_map(|occurrence| occurrence.get("occurrence_id").and_then(Value::as_str))
            .map(str::to_owned)
            .collect::<HashSet<_>>();
        let mut duplicate_ordinal_by_path = HashMap::new();
        for occurrence in &self.occurrences {
            let path = required_string(occurrence, "logical_path", "inventory occurrence")?;
            let ordinal = duplicate_ordinal_by_path
                .entry(path.to_owned())
                .or_insert(0);
            validate_occurrence(
                occurrence,
                &self.root_artifact_id,
                &node_ids,
                &occurrence_ids,
                *ordinal,
            )?;
            *ordinal += 1;
        }
        for edge in &self.edges {
            validate_edge(edge, &self.root_artifact_id, &node_ids, &self.occurrences)?;
        }
        for contradiction in &self.integrity_contradictions {
            validate_contradiction(
                contradiction,
                &self.root_artifact_id,
                &node_ids,
                &occurrence_ids,
            )?;
        }

        let nodes = self.nodes.values().cloned().collect::<Vec<_>>();
        let mut edges = self.edges.clone();
        edges.sort_by_key(|edge| {
            edge.get("edge_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        });
        let graph_sha256 = canonical_json::digest(&json!({
            "nodes": nodes,
            "occurrences": self.occurrences,
            "edges": edges,
            "integrity_contradictions": self.integrity_contradictions,
        }))
        .map_err(|error| error.to_string())?;
        if manifest.get("graph_sha256").and_then(Value::as_str) != Some(graph_sha256.as_str()) {
            return Err("Artifact graph commitment does not match its members".into());
        }
        let manifest_id = canonical_json::digest(&json!({
            "root_artifact_id": self.root_artifact_id,
            "graph_sha256": graph_sha256,
        }))
        .map_err(|error| error.to_string())?;
        if manifest.get("manifest_id").and_then(Value::as_str)
            != Some(format!("agm_{manifest_id}").as_str())
        {
            return Err("Artifact manifest ID does not match its commitment".into());
        }
        Ok(())
    }

    fn entries(&self) -> Result<Vec<Entry>, String> {
        self.occurrences
            .iter()
            .filter(|occurrence| {
                occurrence.get("logical_path").and_then(Value::as_str) != Some(".")
            })
            .map(|occurrence| self.entry(occurrence))
            .collect()
    }

    fn entry(&self, occurrence: &Value) -> Result<Entry, String> {
        let path = required_string(occurrence, "logical_path", "inventory occurrence")?.to_owned();
        let kind = required_string(occurrence, "entry_kind", "inventory occurrence")?.to_owned();
        let format =
            required_string(occurrence, "artifact_format", "inventory occurrence")?.to_owned();
        let artifact_id = occurrence
            .get("artifact_id")
            .ok_or("inventory occurrence has no artifact_id")?;
        if artifact_id.is_null() {
            return Ok(Entry {
                path: path.clone(),
                kind,
                component: None,
                unavailable: Some(json!({
                    "path": path,
                    "artifact_id": null,
                    "sha256": null,
                    "format": format,
                    "encrypted": occurrence.get("encrypted").and_then(Value::as_bool).unwrap_or(false),
                    "limitations": occurrence.get("limitations").cloned().unwrap_or_else(|| json!([])),
                })),
            });
        }

        let id = artifact_id
            .as_str()
            .ok_or("inventory occurrence has invalid artifact_id")?;
        let node = self
            .nodes
            .get(id)
            .ok_or("inventory occurrence references a missing node")?;
        let sha256 = node
            .get("sha256")
            .cloned()
            .ok_or("inventory node has no sha256")?;
        Ok(Entry {
            path: path.clone(),
            kind,
            component: Some(json!({
                "path": path,
                "artifact_id": id,
                "sha256": sha256,
                "format": format,
            })),
            unavailable: None,
        })
    }
}

fn merge_members(
    output: &mut BTreeMap<String, Value>,
    values: &Value,
    identity_field: &str,
    member_name: &str,
) -> Result<(), String> {
    let values = values
        .as_array()
        .ok_or_else(|| format!("inventory result {member_name}s must be an array"))?;
    for value in values {
        let id = required_string(value, identity_field, "inventory graph member")?;
        if let Some(previous) = output.get(id) {
            if previous != value {
                return Err(format!(
                    "Artifact inventory has conflicting {member_name} pages"
                ));
            }
        } else {
            output.insert(id.to_owned(), value.clone());
        }
    }
    Ok(())
}

fn order_occurrences(occurrences: &mut [Value], root_artifact_id: &str) {
    let mut grouped: BTreeMap<&str, Vec<&Value>> = BTreeMap::new();
    for occurrence in occurrences.iter() {
        let path = occurrence
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        grouped.entry(path).or_default().push(occurrence);
    }
    let mut ranks = HashMap::new();
    for (path, group) in grouped {
        let kind = group
            .first()
            .and_then(|occurrence| occurrence.get("entry_kind"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        for (ordinal, _) in group.iter().enumerate() {
            let id = occurrence_id_for_location(root_artifact_id, path, kind, ordinal);
            ranks.insert(id, ordinal);
        }
    }

    occurrences.sort_by(|left, right| {
        let left_path = left
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let right_path = right
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        left_path.cmp(right_path).then_with(|| {
            let left_id = left
                .get("occurrence_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let right_id = right
                .get("occurrence_id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            ranks
                .get(left_id)
                .copied()
                .unwrap_or(usize::MAX)
                .cmp(&ranks.get(right_id).copied().unwrap_or(usize::MAX))
                .then_with(|| left_id.cmp(right_id))
        })
    });
}

fn validate_occurrence(
    occurrence: &Value,
    root_artifact_id: &str,
    node_ids: &HashSet<String>,
    occurrence_ids: &HashSet<String>,
    ordinal: usize,
) -> Result<(), String> {
    let id = required_string(occurrence, "occurrence_id", "inventory occurrence")?;
    let path = required_string(occurrence, "logical_path", "inventory occurrence")?;
    let kind = required_string(occurrence, "entry_kind", "inventory occurrence")?;
    if occurrence_id_for_location(root_artifact_id, path, kind, ordinal) != id {
        return Err("Artifact occurrence ID does not match its identity".into());
    }
    if let Some(artifact_id) = occurrence.get("artifact_id").and_then(Value::as_str)
        && !node_ids.contains(artifact_id)
    {
        return Err("Artifact occurrence references a missing node".into());
    }
    if let Some(parent_id) = occurrence
        .get("parent_occurrence_id")
        .and_then(Value::as_str)
        && !occurrence_ids.contains(parent_id)
    {
        return Err("Artifact occurrence references a missing parent".into());
    }
    Ok(())
}

fn validate_edge(
    edge: &Value,
    root_artifact_id: &str,
    node_ids: &HashSet<String>,
    occurrences: &[Value],
) -> Result<(), String> {
    let parent_id = required_string(edge, "parent_artifact_id", "inventory edge")?;
    let occurrence_id = required_string(edge, "occurrence_id", "inventory edge")?;
    let occurrence = occurrences
        .iter()
        .find(|item| item.get("occurrence_id").and_then(Value::as_str) == Some(occurrence_id))
        .ok_or("Artifact edge references a missing occurrence")?;
    let child_id = required_string(occurrence, "artifact_id", "inventory occurrence")?;
    let path = required_string(occurrence, "logical_path", "inventory occurrence")?;
    let relation = required_string(edge, "relation", "inventory edge")?;
    if !node_ids.contains(parent_id) || !node_ids.contains(child_id) {
        return Err("Artifact edge references a missing graph member".into());
    }
    let expected = prefixed_digest(
        "edge",
        &json!({
            "parent_artifact_id": parent_id,
            "child_artifact_id": child_id,
            "relation": relation,
            "occurrence_id": occurrence_id,
            "logical_path": path,
        }),
    )?;
    if edge.get("edge_id").and_then(Value::as_str) != Some(expected.as_str()) {
        return Err("Artifact edge ID does not match its identity".into());
    }
    let _ = root_artifact_id;
    Ok(())
}

fn validate_contradiction(
    contradiction: &Value,
    root_artifact_id: &str,
    node_ids: &HashSet<String>,
    occurrence_ids: &HashSet<String>,
) -> Result<(), String> {
    let parent_id = required_string(
        contradiction,
        "parent_artifact_id",
        "integrity contradiction",
    )?;
    let occurrence_id = required_string(contradiction, "occurrence_id", "integrity contradiction")?;
    let path = required_string(contradiction, "logical_path", "integrity contradiction")?;
    let declared_sha256 =
        required_string(contradiction, "declared_sha256", "integrity contradiction")?;
    let observed_sha256 =
        required_string(contradiction, "observed_sha256", "integrity contradiction")?;
    if !node_ids.contains(parent_id) || !occurrence_ids.contains(occurrence_id) {
        return Err("Integrity contradiction references a missing graph member".into());
    }
    let expected = prefixed_digest(
        "ic",
        &json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": path,
            "declared_sha256": declared_sha256,
            "observed_sha256": observed_sha256,
        }),
    )?;
    if contradiction
        .get("contradiction_id")
        .and_then(Value::as_str)
        != Some(expected.as_str())
    {
        return Err("Integrity contradiction ID does not match its identity".into());
    }
    Ok(())
}

fn artifact_id_for_sha256(sha256: &str) -> Result<String, String> {
    prefixed_digest("art", &json!({ "sha256": sha256 }))
}

fn occurrence_id_for_location(
    root_artifact_id: &str,
    path: &str,
    kind: &str,
    ordinal: usize,
) -> String {
    let identity = if path == "." {
        json!({"root":root_artifact_id})
    } else if ordinal == 0 {
        json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": path,
            "entry_kind": kind,
        })
    } else {
        json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": path,
            "entry_kind": kind,
            "duplicate_ordinal": ordinal,
        })
    };
    prefixed_digest("occ", &identity).unwrap_or_default()
}

fn prefixed_digest(prefix: &str, identity: &Value) -> Result<String, String> {
    let digest = canonical_json::digest(identity).map_err(|error| error.to_string())?;
    Ok(format!("{prefix}_{digest}"))
}

fn required_string<'a>(value: &'a Value, field: &str, owner: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{owner} has no valid {field}"))
}

fn required_count(value: &Value, field: &str) -> Result<usize, String> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| format!("inventory manifest has no valid {field}"))
}

#[derive(Clone)]
struct Entry {
    path: String,
    kind: String,
    component: Option<Value>,
    unavailable: Option<Value>,
}

#[derive(Default)]
struct Tree {
    directories: BTreeMap<String, BTreeSet<String>>,
    files: BTreeMap<String, BTreeMap<String, Value>>,
}

fn index_tree(entries: &[Entry]) -> Tree {
    let mut tree = Tree::default();
    for entry in entries {
        if is_sidecar(&entry.path) {
            continue;
        }
        let segments = entry.path.split('/').collect::<Vec<_>>();
        let mut parent = String::new();
        for (index, segment) in segments.iter().enumerate() {
            let leaf = index + 1 == segments.len();
            if !leaf || entry.kind == "directory" {
                tree.directories
                    .entry(parent.clone())
                    .or_default()
                    .insert((*segment).to_owned());
            } else if entry.kind == "file" {
                if let Some(component) = &entry.component {
                    tree.files
                        .entry(parent.clone())
                        .or_default()
                        .insert((*segment).to_owned(), component.clone());
                }
            }
            parent = join_path(&parent, segment);
        }
    }
    tree
}

fn application_roots(tree: &Tree, subject_name: &str, root_format: &str) -> Vec<String> {
    if root_format == "directory" && ends_ascii_case_insensitive(subject_name, ".app") {
        return vec![".".into()];
    }

    let mut found = BTreeSet::new();
    for path in directory_paths(tree) {
        let segments = path.split('/').collect::<Vec<_>>();
        let payload_app = segments
            .first()
            .is_some_and(|segment| anatomy_name_is(segment, "Payload"))
            && segments
                .get(1)
                .is_some_and(|segment| ends_ascii_case_insensitive(segment, ".app"));
        if payload_app {
            found.insert(format!("{}/{}", segments[0], segments[1]));
            continue;
        }

        for index in 0..segments.len().saturating_sub(1) {
            if ends_ascii_case_insensitive(segments[index], ".app")
                && anatomy_name_is(segments[index + 1], "Contents")
            {
                found.insert(segments[..=index].join("/"));
                break;
            }
        }
    }

    let candidates = found.into_iter().collect::<Vec<_>>();
    candidates
        .iter()
        .filter(|candidate| {
            !candidates
                .iter()
                .any(|other| other != *candidate && is_within(candidate, other))
        })
        .cloned()
        .collect()
}

fn detect_bundles(tree: &Tree, roots: &[String]) -> Vec<Bundle> {
    let mut paths = roots.iter().cloned().collect::<BTreeSet<_>>();
    for path in directory_paths(tree) {
        let name = path.rsplit('/').next().unwrap_or_default();
        if is_bundle_name(name) && roots.iter().any(|root| is_within(&path, root)) {
            paths.insert(path);
        }
    }

    paths
        .iter()
        .map(|path| {
            let layout = bundle_layout(path, tree);
            Bundle {
                path: path.clone(),
                parent_path: enclosing_bundle(path, &paths),
                role: if roots.contains(path) {
                    "application".into()
                } else {
                    bundle_role(path)
                },
                layout,
                role_basis: "path-convention",
                info_plist_path: info_plist_path(path, layout, tree),
                executable_candidates: executable_candidates(path, layout, tree),
                signing_paths: signing_paths(path, layout, tree),
            }
        })
        .collect()
}

#[derive(Clone)]
struct Bundle {
    path: String,
    parent_path: Option<String>,
    layout: &'static str,
    role: String,
    role_basis: &'static str,
    info_plist_path: Option<String>,
    executable_candidates: Vec<String>,
    signing_paths: Vec<String>,
}

impl serde::Serialize for Bundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("Bundle", 8)?;
        state.serialize_field("path", &self.path)?;
        state.serialize_field("parent_path", &self.parent_path)?;
        state.serialize_field("layout", self.layout)?;
        state.serialize_field("role", &self.role)?;
        state.serialize_field("role_basis", self.role_basis)?;
        state.serialize_field("info_plist_path", &self.info_plist_path)?;
        state.serialize_field("executable_candidates", &self.executable_candidates)?;
        state.serialize_field("signing_paths", &self.signing_paths)?;
        state.end()
    }
}

fn directory_paths(tree: &Tree) -> Vec<String> {
    let mut paths = Vec::new();
    for (parent, names) in &tree.directories {
        for name in names {
            paths.push(join_path(parent, name));
        }
    }
    paths.sort();
    paths
}

fn bundle_layout(bundle: &str, tree: &Tree) -> &'static str {
    let directory = bundle_directory(bundle);
    if named_directory(tree, directory, "Contents").is_some() {
        "macos-deep"
    } else if named_directory(tree, directory, "Versions").is_some() {
        "versioned-framework"
    } else {
        "shallow"
    }
}

fn bundle_role(bundle: &str) -> String {
    let segments = bundle.split('/').collect::<Vec<_>>();
    let name = segments
        .last()
        .copied()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let container = segments
        .get(segments.len().saturating_sub(2))
        .copied()
        .unwrap_or_default();
    if name.ends_with(".appex") {
        return "app-extension".into();
    }
    if name.ends_with(".xpc") {
        return "xpc-service".into();
    }
    if name.ends_with(".framework") {
        return "framework".into();
    }
    if name.ends_with(".systemextension") {
        return "system-extension".into();
    }
    if name.ends_with(".dext") {
        return "driver-extension".into();
    }
    if name.ends_with(".bundle") {
        if anatomy_name_is(container, "PlugIns") {
            return "plug-in".into();
        }
        return if anatomy_name_is(container, "Resources") {
            "resource-bundle".into()
        } else {
            "bundle".into()
        };
    }
    if !name.ends_with(".app") {
        return "plug-in".into();
    }
    if anatomy_name_is(container, "LoginItems")
        && segments
            .get(segments.len().saturating_sub(3))
            .is_some_and(|segment| anatomy_name_is(segment, "Library"))
    {
        return "login-item".into();
    }
    if anatomy_name_is(container, "Helpers") {
        return "helper-application".into();
    }
    "nested-application".into()
}

fn info_plist_path(bundle: &str, layout: &str, tree: &Tree) -> Option<String> {
    let directories = content_directories(bundle, layout, tree);
    if directories.len() != 1 {
        return None;
    }
    let directory = directories.first()?;
    let parent = if layout == "versioned-framework" {
        named_directory(tree, directory, "Resources")?
    } else {
        directory.clone()
    };
    named_file(tree, &parent, "Info.plist")
}

fn executable_candidates(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let mut result = Vec::new();
    for directory in content_directories(bundle, layout, tree) {
        let executable_directory = if layout == "macos-deep" {
            named_directory(tree, &directory, "MacOS")
        } else {
            Some(directory)
        };
        let Some(executable_directory) = executable_directory else {
            continue;
        };
        if let Some(files) = tree.files.get(&executable_directory) {
            result.extend(
                files
                    .values()
                    .filter(|file| is_macho(&file["format"]))
                    .filter_map(|file| file["path"].as_str().map(str::to_owned)),
            );
        }
    }
    result.sort();
    result
}

fn signing_paths(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let mut result = Vec::new();
    for directory in content_directories(bundle, layout, tree) {
        if let Some(signature_directory) = named_directory(tree, &directory, "_CodeSignature")
            && let Some(path) = named_file(tree, &signature_directory, "CodeResources")
        {
            result.push(path);
        }
        for name in ["embedded.provisionprofile", "embedded.mobileprovision"] {
            if let Some(path) = named_file(tree, &directory, name) {
                result.push(path);
            }
        }
    }
    result.sort();
    result
}

fn content_directories(bundle: &str, layout: &str, tree: &Tree) -> Vec<String> {
    let directory = bundle_directory(bundle);
    if layout == "macos-deep" {
        return named_directory(tree, directory, "Contents")
            .into_iter()
            .collect();
    }
    if layout == "shallow" {
        return vec![directory.to_owned()];
    }
    let Some(versions) = named_directory(tree, directory, "Versions") else {
        return Vec::new();
    };
    let mut real_versions = tree
        .directories
        .get(&versions)
        .into_iter()
        .flatten()
        .filter(|version| !anatomy_name_is(version, "Current"))
        .map(|version| join_path(&versions, version))
        .collect::<Vec<_>>();
    real_versions.sort();
    real_versions
}

fn named_directory(tree: &Tree, directory: &str, expected: &str) -> Option<String> {
    let name = anatomy_child(
        tree.directories.get(directory)?.iter().map(String::as_str),
        expected,
    )?;
    Some(join_path(directory, name))
}

fn named_file(tree: &Tree, directory: &str, expected: &str) -> Option<String> {
    let name = anatomy_child(
        tree.files.get(directory)?.keys().map(String::as_str),
        expected,
    )?;
    Some(join_path(directory, name))
}

fn anatomy_child<'a>(names: impl IntoIterator<Item = &'a str>, expected: &str) -> Option<&'a str> {
    let mut exact = None;
    let mut folded: Option<&'a str> = None;
    for name in names {
        if name == expected {
            exact = Some(name);
        } else if anatomy_name_is(name, expected) && folded.is_none_or(|current| name < current) {
            folded = Some(name);
        }
    }
    exact.or(folded)
}

fn enclosing_bundle(path: &str, bundles: &BTreeSet<String>) -> Option<String> {
    if path != "." {
        let segments = path.split('/').collect::<Vec<_>>();
        for length in (1..segments.len()).rev() {
            let candidate = segments[..length].join("/");
            if bundles.contains(&candidate) {
                return Some(candidate);
            }
        }
    }
    bundles.contains(".").then(|| ".".into())
}

fn platforms_of(bundles: &[Bundle]) -> Vec<&'static str> {
    let mut platforms = BTreeSet::new();
    for bundle in bundles.iter().filter(|bundle| bundle.role == "application") {
        if bundle.layout == "macos-deep" {
            platforms.insert("macos");
        } else if bundle.layout == "shallow" && bundle.info_plist_path.is_some() {
            platforms.insert("ios");
        }
    }
    platforms.into_iter().collect()
}

struct Attributed<T> {
    all: Vec<T>,
    unattributed: usize,
}

fn attribute_components<T: Clone + PathValue>(
    values: &[T],
    roots: &[String],
    root_format: &str,
) -> Attributed<T> {
    let visible = values
        .iter()
        .filter(|value| !is_sidecar(value.path()))
        .collect::<Vec<_>>();
    if root_format == "ipa" {
        return Attributed {
            all: visible.into_iter().cloned().collect(),
            unattributed: 0,
        };
    }
    let all = visible
        .iter()
        .filter(|value| roots.iter().any(|root| is_within(value.path(), root)))
        .map(|value| (*value).clone())
        .collect::<Vec<_>>();
    let unattributed = visible.len() - all.len();
    Attributed { all, unattributed }
}

trait PathValue {
    fn path(&self) -> &str;
}

impl PathValue for Value {
    fn path(&self) -> &str {
        self.get("path").and_then(Value::as_str).unwrap_or_default()
    }
}

struct Classified {
    bundle_metadata: Vec<Value>,
    executables: Vec<Value>,
    frameworks: Vec<Value>,
    native_libraries: Vec<Value>,
    javascript: Vec<Value>,
    signing: Vec<Value>,
    privileged_helpers: Vec<Value>,
    launchd_plists: Vec<Value>,
    helpers: Vec<Value>,
}

impl Classified {
    fn as_value(&self) -> Value {
        json!({
            "bundle_metadata": self.bundle_metadata,
            "executables": self.executables,
            "frameworks": self.frameworks,
            "native_libraries": self.native_libraries,
            "javascript": self.javascript,
            "signing": self.signing,
            "privileged_helpers": self.privileged_helpers,
            "launchd_plists": self.launchd_plists,
            "helpers": self.helpers,
        })
    }
}

fn classify_components(entries: &[Entry], all: &[Value], roots: &[String]) -> Classified {
    let bundle_metadata = all
        .iter()
        .filter(|component| {
            anatomy_name_is(last_path_segment(component_path(component)), "Info.plist")
        })
        .cloned()
        .collect();
    let executables = all
        .iter()
        .filter(|component| {
            is_macho(&component["format"])
                && (is_within_roots(component_path(component), roots)
                    || !is_native_library(component_path(component)))
        })
        .cloned()
        .collect();
    let frameworks = all
        .iter()
        .filter(|component| component_path(component).contains(".framework/"))
        .cloned()
        .collect();
    let native_libraries = all
        .iter()
        .filter(|component| is_native_library(component_path(component)))
        .cloned()
        .collect();
    let javascript = all
        .iter()
        .filter(|component| component["format"] == "javascript-bundle")
        .cloned()
        .collect();
    let signing = all
        .iter()
        .filter(|component| {
            anatomy_tail_matches(
                component_path(component),
                &["_CodeSignature", "CodeResources"],
            ) || anatomy_name_is(
                last_path_segment(component_path(component)),
                "embedded.mobileprovision",
            ) || anatomy_name_is(
                last_path_segment(component_path(component)),
                "embedded.provisionprofile",
            )
        })
        .cloned()
        .collect();
    let privileged_helpers = matching_components(entries, roots, |path| {
        anatomy_tail_matches(path, &["Contents", "Library", "LaunchServices", "*"])
    });
    let launchd_plists = matching_components(entries, roots, |path| path.ends_with(".plist"))
        .into_iter()
        .filter_map(|mut component| {
            let domain = launchd_domain(component_path(&component))?;
            component["domain"] = Value::String(domain.into());
            Some(component)
        })
        .collect();
    let helpers = matching_components(entries, roots, |path| {
        anatomy_tail_matches(path, &["Contents", "Helpers", "*"])
    });

    Classified {
        bundle_metadata,
        executables,
        frameworks,
        native_libraries,
        javascript,
        signing,
        privileged_helpers,
        launchd_plists,
        helpers,
    }
}

fn last_path_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

fn is_within_roots(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| is_within(path, root))
}

fn matching_components(
    entries: &[Entry],
    roots: &[String],
    matches_path: impl Fn(&str) -> bool,
) -> Vec<Value> {
    entries
        .iter()
        .filter(|entry| {
            entry.kind == "file"
                && !is_sidecar(&entry.path)
                && roots.iter().any(|root| is_within(&entry.path, root))
                && matches_path(&entry.path)
        })
        .filter_map(|entry| entry.component.clone())
        .collect()
}

fn component_path(value: &Value) -> &str {
    value
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn deduplicate_components(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut by_path = BTreeMap::new();
    for value in values {
        by_path.insert(component_path(&value).to_owned(), value);
    }
    by_path.into_values().collect()
}

fn identify_runtime_families(all: &[Value]) -> Vec<&'static str> {
    let mut families = BTreeSet::new();
    if all.iter().any(|component| is_macho(&component["format"])) {
        families.insert("native");
    }
    if all
        .iter()
        .any(|component| is_swift_runtime_library(component_path(component)))
    {
        families.insert("swift-objective-c");
    }
    if all
        .iter()
        .any(|component| component["format"] == "javascript-bundle")
    {
        families.insert("javascript");
    }
    for component in all {
        if let Some(family) = native_runtime_convention(component_path(component)) {
            families.insert(family);
        }
    }
    families.into_iter().collect()
}

struct BridgeProjection {
    candidates: Vec<Value>,
    coverage: Value,
}

fn identify_bridge_candidates(
    scripts: &[Value],
    native: &[Value],
    roots: &[String],
) -> BridgeProjection {
    let owner = |path: &str| {
        roots
            .iter()
            .find(|root| is_within(path, root))
            .map(String::as_str)
    };
    let mut script_groups: Vec<(Option<String>, Vec<&Value>)> = Vec::new();
    for script in scripts {
        let root = owner(component_path(script)).map(str::to_owned);
        if let Some((last_root, group)) = script_groups.last_mut()
            && *last_root == root
        {
            group.push(script);
        } else {
            script_groups.push((root, vec![script]));
        }
    }

    let mut native_by_root: BTreeMap<Option<String>, Vec<&Value>> = BTreeMap::new();
    for component in native {
        native_by_root
            .entry(owner(component_path(component)).map(str::to_owned))
            .or_default()
            .push(component);
    }

    let total = script_groups.iter().fold(0usize, |sum, (root, scripts)| {
        sum.saturating_add(
            scripts
                .len()
                .saturating_mul(native_by_root.get(root).map_or(0, Vec::len)),
        )
    });
    let mut candidates = Vec::new();
    let mut estimated_bytes = 2usize;
    'candidate_groups: for (root, group_scripts) in &script_groups {
        let Some(group_native) = native_by_root.get(root) else {
            continue;
        };
        for script in group_scripts {
            for component in group_native {
                let native_path = component_path(component);
                let candidate = json!({
                    "source_path": component_path(script),
                    "native_path": native_path,
                    "basis": bridge_basis(native_path),
                });
                let serialized_size =
                    serde_json::to_vec(&candidate).map_or(usize::MAX, |bytes| bytes.len());
                let additional =
                    serialized_size.saturating_add(usize::from(!candidates.is_empty()));
                if estimated_bytes.saturating_add(additional) > MAX_BRIDGE_CANDIDATE_JSON_BYTES {
                    break 'candidate_groups;
                }
                estimated_bytes += additional;
                candidates.push(candidate);
            }
        }
    }

    let emitted = candidates.len();
    BridgeProjection {
        candidates,
        coverage: json!({
            "status": if emitted == total { "complete" } else { "partial" },
            "total_candidates": total,
            "emitted_candidates": emitted,
            "omitted_candidates": total.saturating_sub(emitted),
        }),
    }
}

fn bridge_basis(path: &str) -> &'static str {
    match native_runtime_convention(path) {
        Some("react-native") => "react-native-convention",
        Some("flutter") => "flutter-convention",
        Some("unity") => "unity-convention",
        _ => "javascript-and-native-content",
    }
}

fn native_runtime_convention(path: &str) -> Option<&'static str> {
    for segment in path.split('/') {
        let segment = segment.to_lowercase();
        match segment.as_str() {
            "react.framework"
            | "reactnative.framework"
            | "libreactnative.so"
            | "libreactnativejni.so"
            | "libhermes_executor.so"
            | "libhermes.so"
            | "hermes.framework" => return Some("react-native"),
            "libflutter.so" | "flutter.framework" => return Some("flutter"),
            "libunity.so" | "unityframework.framework" => return Some("unity"),
            _ => {}
        }
    }
    None
}

fn is_swift_runtime_library(path: &str) -> bool {
    path.split('/').any(|segment| {
        let segment = segment.to_lowercase();
        segment.starts_with("libswift") && segment.ends_with(".dylib") && segment.len() > 12
    })
}

fn is_native_library(path: &str) -> bool {
    let path = path.to_ascii_lowercase();
    path.ends_with(".dylib") || path.ends_with(".so")
}

fn is_macho(format: &Value) -> bool {
    matches!(format.as_str(), Some("mach-o" | "mach-o-universal"))
}

fn is_bundle_name(name: &str) -> bool {
    [
        ".app",
        ".appex",
        ".xpc",
        ".framework",
        ".systemextension",
        ".dext",
        ".bundle",
        ".plugin",
        ".qlgenerator",
        ".mdimporter",
    ]
    .iter()
    .any(|suffix| ends_ascii_case_insensitive(name, suffix))
}

fn is_sidecar(path: &str) -> bool {
    let mut segments = path.split('/').peekable();
    let mut basename = "";
    while let Some(segment) = segments.next() {
        if segments.peek().is_none() {
            basename = segment;
        }
        if segment == "__MACOSX" {
            return true;
        }
    }
    basename.starts_with("._")
}

fn anatomy_name_is(actual: &str, expected: &str) -> bool {
    actual.to_lowercase() == expected.to_lowercase()
}

fn anatomy_tail_matches(path: &str, expected: &[&str]) -> bool {
    let actual = path.split('/').collect::<Vec<_>>();
    if actual.len() < expected.len() {
        return false;
    }
    actual[actual.len() - expected.len()..]
        .iter()
        .zip(expected)
        .all(|(actual, expected)| {
            *actual != "" && (*expected == "*" || anatomy_name_is(actual, expected))
        })
}

fn launchd_domain(path: &str) -> Option<&'static str> {
    if anatomy_tail_matches(path, &["Contents", "Library", "LaunchAgents", "*"]) {
        Some("agent")
    } else if anatomy_tail_matches(path, &["Contents", "Library", "LaunchDaemons", "*"]) {
        Some("daemon")
    } else {
        None
    }
}

fn is_within(path: &str, root: &str) -> bool {
    root == "." || path == root || path.starts_with(&format!("{root}/"))
}

fn ends_ascii_case_insensitive(value: &str, suffix: &str) -> bool {
    value
        .to_ascii_lowercase()
        .ends_with(&suffix.to_ascii_lowercase())
}

fn bundle_directory(bundle: &str) -> &str {
    if bundle == "." { "" } else { bundle }
}

fn join_path(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}/{name}")
    }
}

fn projection_limitations(
    inventory: &Inventory,
    inventory_complete: bool,
    uninventoried_image: bool,
    roots: &[String],
    bundles: &[Bundle],
    has_symlinks: bool,
    has_sidecars: bool,
    unattributed: usize,
    has_unavailable: bool,
    bridge_coverage: &Value,
) -> Vec<String> {
    let mut limitations = inventory.limitations.clone();
    if !inventory_complete {
        limitations.push("Source inventory coverage is partial; absence is unknown.".into());
    }
    if uninventoried_image {
        limitations.push(
            "The DMG's contents were not inventoried on this host; bundle absence is unknown."
                .into(),
        );
    }
    if roots.is_empty() {
        limitations.push("No application bundle (Payload/*.app or *.app/Contents) was present in the supplied inventory pages.".into());
    }
    if bundles
        .iter()
        .any(|bundle| bundle.layout == "versioned-framework" && bundle.info_plist_path.is_none())
    {
        limitations.push("A versioned framework has several version directories or no Versions/*/Resources/Info.plist; the Info.plist that Versions/Current selects is unknown because symlink targets are not inventoried.".into());
    }
    if has_symlinks {
        limitations.push("Symlinks are reported by path only; their targets are not inventoried, so bundles are reported at their real paths.".into());
    }
    if unattributed > 0 {
        limitations.push(format!("{unattributed} inventoried entries outside every application root are not attributed to the application."));
    }
    if has_sidecars {
        limitations.push("AppleDouble sidecar entries (._* files and __MACOSX/) describe neighbouring files and are excluded from bundle roles.".into());
    }
    if bridge_coverage["status"] == "partial" {
        limitations.push(format!("Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.", bridge_coverage["omitted_candidates"]));
    }
    if has_unavailable {
        limitations.push("Some inventoried files have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component absence is unknown.".into());
    }
    limitations.extend([
        "Bundle roles follow path conventions. Read each info_plist_path with inspect_plist for CFBundleExecutable, identifiers, and declared services.".into(),
        "Bundle identifiers and signing claims require dedicated plist and CMS parsing; this projection reports only exact paths and hashes.".into(),
        "Runtime families are inferred from inventory formats and bounded framework path conventions, not observed runtime loading.".into(),
        "Generic framework and dylib paths do not establish Swift or Objective-C; this inventory projection does not decode language metadata.".into(),
        "Bridge candidates are path-based hypotheses, not observed runtime calls.".into(),
        "A bridge basis is inferred from the native path and is repeated for every managed component.".into(),
    ]);
    limitations
}

fn projected_subject(carrier: &EvidenceRecord, root_sha256: &Value) -> Result<Value, Failure> {
    let source: Value = serde_json::from_str(carrier.subject().get())
        .map_err(|error| protocol_failure(&error.to_string()))?;
    if source.is_null() {
        return Ok(Value::Null);
    }
    let path = source
        .get("local_path")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_failure("authenticated Evidence subject has no local_path"))?;
    let format = source
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_failure("authenticated Evidence subject has no format"))?;
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("artifact");
    Ok(json!({
        "name": name,
        "digest": {"sha256": root_sha256},
        "format": format,
        "architecture": null,
        "local_path": path,
    }))
}

#[derive(Debug)]
enum ProjectionError {
    Invalid(String),
    EvidenceIntegrity(String),
}

impl ProjectionError {
    fn into_failure(self) -> Failure {
        match self {
            Self::Invalid(reason) => invalid(&reason),
            Self::EvidenceIntegrity(reason) => Failure::new(
                "evidence_integrity_mismatch",
                "integrity_mismatch",
                reason.clone(),
                false,
                "Supply unchanged, authenticated inventory Evidence records.".into(),
                BTreeMap::from([
                    ("operation", Detail::Text(OPERATION.into())),
                    ("reason", Detail::Text(reason)),
                ]),
            ),
        }
    }
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) | Self::EvidenceIntegrity(reason) => formatter.write_str(reason),
        }
    }
}

impl From<EvidenceRecordError> for ProjectionError {
    fn from(error: EvidenceRecordError) -> Self {
        let reason = error.to_string();
        match error {
            EvidenceRecordError::SemanticIdMismatch => Self::EvidenceIntegrity(reason),
            _ => Self::Invalid(reason),
        }
    }
}

impl From<String> for ProjectionError {
    fn from(reason: String) -> Self {
        Self::Invalid(reason)
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated IPA, .app directory, ZIP, or DMG inventory Evidence for execution-free projection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "provider_protocol_error",
        "provider_protocol_error",
        "Apple application projection could not commit valid Evidence.".into(),
        false,
        "Check the retained inventory Evidence and retry the projection.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}
