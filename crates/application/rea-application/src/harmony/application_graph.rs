//! Execution-free HarmonyOS application graph projection.
//!
//! This owner consumes authenticated artifact-inventory Evidence only. It
//! preserves source identities and inventory uncertainty while attributing
//! paths to HarmonyOS application components; it never opens or executes a
//! package.

use crate::artifacts;
use rea_core::{
    canonical_json,
    evidence::record::{EvidenceRecord, EvidenceRecordError},
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_harmony_application_graph";
const INVENTORY_OPERATION: &str = "inventory_artifact";
const INSPECTION_OPERATION: &str = "inspect_artifact";
const MAX_BRIDGE_CANDIDATE_JSON_BYTES: usize = 2 * 1024 * 1024;

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_pages(input)
        .map(|_| ())
        .map_err(ProjectionInputError::into_failure)
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid(
            "Harmony application graph result must be an object",
        ));
    }
    Ok(result)
}

/// Project authenticated inventory Evidence without acquiring or interpreting
/// package contents.
pub fn project(input: &Value) -> Result<Value, String> {
    let pages = parse_pages(input).map_err(|error| error.to_string())?;
    project_pages(&pages)
}

/// Project authenticated inventory Evidence into the derived Evidence shape used by REA.
pub fn project_evidence(input: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let pages = parse_pages(input).map_err(ProjectionInputError::into_failure)?;
    let mut result = project_pages(&pages).map_err(|reason| invalid(&reason))?;
    let source_evidence_ids = pages
        .iter()
        .map(|page| page.source_evidence_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    result["source_evidence_ids"] = json!(source_evidence_ids);

    let mut limitations = result["limitations"].clone();
    let subject = projected_subject(
        pages.first().expect("parse_pages rejects empty input"),
        &result["root_sha256"],
        &mut limitations,
    )?;
    result["limitations"] = limitations.clone();

    let unsigned = json!({
        "subject": subject,
        "provider": {
            "id": "rea-harmony-application",
            "name": "REA HarmonyOS application workflows",
            "version": "1"
        },
        "analysis_profile": null,
        "predicate_type": "rea.harmony-application-graph",
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

fn project_pages(pages: &[Page]) -> Result<Value, String> {
    let inventory = Inventory::assemble(pages)?;
    let root_format = match inventory.root_format.as_str() {
        "hap" | "hsp" | "app-pack" => inventory.root_format.clone(),
        other => return Err(format!("unsupported Harmony root format {other:?}")),
    };
    let entries = inventory.entries()?;
    let components = classify(&entries);
    let unavailable = entries
        .iter()
        .filter_map(|entry| entry.unavailable.clone())
        .collect::<Vec<_>>();
    let bridge = bridge_candidates(&components.bytecode, &components.native_libraries);

    let mut source_evidence_ids = pages
        .iter()
        .map(|page| page.source_evidence_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    source_evidence_ids.sort();

    let coverage_complete = inventory.complete
        && inventory.coverage == json!({"scope":"container-entries","status":"complete"});
    let mut limitations = inventory.limitations.clone();
    if !coverage_complete {
        limitations.push("Source inventory coverage is partial; absence is unknown.".into());
    }
    if !unavailable.is_empty() {
        limitations.push("Some inventoried occurrences have no authenticated content identity. Their paths and limitations are retained in unavailable_components; component and runtime absence is unknown.".into());
    }
    limitations.extend([
        "Manifest, module, resource, and signing semantics require a dedicated HarmonyOS provider; this projection reports exact inventory paths and hashes only.",
        "The packaging model is a path-presence heuristic: a Stage model is claimed only from module.json and a FA model only from config.json; both can coexist with unusual layouts.",
        "Runtime families are inferred from inventory formats and paths; filename suffixes do not establish valid Ark bytecode.",
        "The signing component lists META-INF certificate-entry suffixes only; signatures applied by the packaging tool live in the ZIP signing block rather than archive entries, so an empty signing list does not mean the package is unsigned.",
        "Bridge candidates are path-based hypotheses, not decoded N-API declarations or observed runtime calls.",
        "HarmonyOS .har shared libraries are not identified by this projection; the .har suffix also names HTTP Archive JSON, so that classification requires verified ZIP bytes.",
    ].into_iter().map(str::to_owned));
    if root_format == "app-pack" {
        limitations.extend([
            "App Pack child packages are listed by inventory path only; their contents are not recursively inventoried by this projection.",
            "The app-pack root classification is a verified-ZIP-magic plus .app suffix rule; the projection does not require pack.info or child packages before reporting the root format.",
        ].into_iter().map(str::to_owned));
    }
    if bridge.coverage_status == "partial" {
        limitations.push(format!(
            "Bridge candidate pairs exceeded the projection safety budget; {} hypotheses are omitted. Component arrays still include every component from the supplied inventory pages.",
            bridge.omitted_candidates
        ));
    }

    let components_value = components.as_value();
    let runtime = runtime_families(&entries, &components);
    let app_pack_children = if root_format == "app-pack" {
        entries
            .iter()
            .filter_map(|entry| entry.component.clone())
            .filter(|component| {
                component["path"].as_str().is_some_and(|path| {
                    let path = path.to_ascii_lowercase();
                    path.ends_with(".hap") || path.ends_with(".hsp")
                })
            })
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let result_without_id = json!({
        "root_sha256": inventory.root_sha256,
        "root_format": root_format,
        "source_evidence_ids": source_evidence_ids,
        "packaging_model": packaging_model(&components.manifests),
        "components": components_value,
        "unavailable_components": unavailable,
        "app_pack_children": app_pack_children,
        "runtime_families": runtime,
        "bridge_candidates": bridge.candidates,
        "bridge_candidate_coverage": {
            "status": bridge.coverage_status,
            "total_candidates": bridge.total_candidates,
            "emitted_candidates": bridge.emitted_candidates,
            "omitted_candidates": bridge.omitted_candidates,
        },
        "coverage": {
            "status": if coverage_complete && unavailable.is_empty() && bridge.coverage_status == "complete" { "complete-within-inventory" } else { "partial" },
            "inventory_complete": inventory.complete,
        },
        "limitations": limitations,
    });
    let digest = canonical_json::digest(&result_without_id).map_err(|error| error.to_string())?;
    let mut result = result_without_id;
    result["projection_id"] = json!(format!("hmp_{digest}"));
    Ok(result)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide one or more authenticated HAP, HSP, or App Pack inventory Evidence records for execution-free projection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn protocol_failure(reason: &str) -> Failure {
    Failure::new(
        "provider_protocol_error",
        "provider_protocol_error",
        "Harmony application projection could not commit valid Evidence.".into(),
        false,
        "Check the retained inventory Evidence and retry the projection.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

fn projected_subject(
    page: &Page,
    root_sha256: &Value,
    limitations: &mut Value,
) -> Result<Value, Failure> {
    if page.record.subject().get() == "null" {
        limitations
            .as_array_mut()
            .expect("projection limitations are an array")
            .insert(
                0,
                json!("Artifact identity is unavailable for this observation."),
            );
        return Ok(Value::Null);
    }

    let source_subject: Value = serde_json::from_str(page.record.subject().get())
        .map_err(|error| protocol_failure(&error.to_string()))?;
    let path = source_subject
        .get("local_path")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_failure("authenticated Evidence subject has no local_path"))?;
    let format = source_subject
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
        "local_path": path
    }))
}

#[derive(Debug)]
enum ProjectionInputError {
    Invalid(String),
    EvidenceIntegrity(String),
}

impl ProjectionInputError {
    fn into_failure(self) -> Failure {
        match self {
            Self::Invalid(reason) => invalid(&reason),
            Self::EvidenceIntegrity(reason) => Failure::new(
                "evidence_integrity_mismatch",
                "integrity_mismatch",
                reason.clone(),
                false,
                "Supply an unchanged, authenticated inventory Evidence record.".into(),
                BTreeMap::from([
                    ("operation", Detail::Text(OPERATION.into())),
                    ("reason", Detail::Text(reason)),
                ]),
            ),
        }
    }
}

impl std::fmt::Display for ProjectionInputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) | Self::EvidenceIntegrity(reason) => formatter.write_str(reason),
        }
    }
}

impl From<EvidenceRecordError> for ProjectionInputError {
    fn from(error: EvidenceRecordError) -> Self {
        let reason = error.to_string();
        match error {
            EvidenceRecordError::SemanticIdMismatch => Self::EvidenceIntegrity(reason),
            _ => Self::Invalid(reason),
        }
    }
}

struct Page {
    record: EvidenceRecord,
    source_evidence_id: String,
    result: Value,
}

fn parse_pages(input: &Value) -> Result<Vec<Page>, ProjectionInputError> {
    let object = input
        .as_object()
        .ok_or_else(|| ProjectionInputError::Invalid("input must be an object".into()))?;
    if object.len() != 1 || !object.contains_key("inventory_evidence") {
        return Err(ProjectionInputError::Invalid(
            "input must contain only inventory_evidence".into(),
        ));
    }

    let records = object
        .get("inventory_evidence")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProjectionInputError::Invalid("inventory_evidence must be an array".into())
        })?;
    if records.is_empty() {
        return Err(ProjectionInputError::Invalid(
            "inventory_evidence must contain at least one record".into(),
        ));
    }

    let mut ids = BTreeSet::new();
    let mut pages = Vec::new();
    for value in records {
        let record = parse_record(value)?;
        if !ids.insert(record.evidence_id().to_owned()) {
            return Err(ProjectionInputError::Invalid(
                "inventory Evidence IDs must be unique".into(),
            ));
        }
        if record.operation_matches(INVENTORY_OPERATION) {
            pages.push(parse_inventory_page(record, None)?);
        } else if record.operation_matches(INSPECTION_OPERATION) {
            pages.extend(parse_inspection_pages(&record)?);
        } else {
            return Err(ProjectionInputError::Invalid(
                "Harmony application projection requires inventory_artifact or inspect_artifact Evidence".into(),
            ));
        }
    }
    if pages.is_empty() {
        return Err(ProjectionInputError::Invalid(
            "Artifact inspection requires inventory substeps".into(),
        ));
    }
    Ok(pages)
}

fn parse_record(value: &Value) -> Result<EvidenceRecord, ProjectionInputError> {
    if !value.is_object() {
        return Err(ProjectionInputError::Invalid(
            "inventory Evidence must be an object".into(),
        ));
    }

    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| ProjectionInputError::Invalid(error.to_string()))?;
    EvidenceRecord::parse(&raw).map_err(ProjectionInputError::from)
}

fn parse_inventory_page(
    record: EvidenceRecord,
    source_evidence_id: Option<&str>,
) -> Result<Page, ProjectionInputError> {
    let result = serde_json::from_str(record.normalized_result().get()).map_err(|error| {
        ProjectionInputError::Invalid(format!(
            "inventory Evidence normalized_result is invalid: {error}"
        ))
    })?;
    let result = artifacts::inventory_evidence::normalize_result(result)
        .map_err(ProjectionInputError::Invalid)?;
    validate_inventory_subject(&record, &result)?;
    validate_page_shape(&result)?;

    let source_evidence_id = source_evidence_id
        .unwrap_or_else(|| record.evidence_id())
        .to_owned();
    Ok(Page {
        record,
        source_evidence_id,
        result,
    })
}

fn parse_inspection_pages(carrier: &EvidenceRecord) -> Result<Vec<Page>, ProjectionInputError> {
    let inspection: Value =
        serde_json::from_str(carrier.normalized_result().get()).map_err(|error| {
            ProjectionInputError::Invalid(format!("Artifact inspection result is invalid: {error}"))
        })?;
    let substeps = inspection
        .get("substeps")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            ProjectionInputError::Invalid("Artifact inspection result has no substeps".into())
        })?;
    let completed = inspection
        .get("coverage")
        .and_then(|value| value.get("substeps_completed"))
        .and_then(Value::as_u64);
    if completed != Some(substeps.len() as u64) || substeps.is_empty() {
        return Err(ProjectionInputError::Invalid(
            "Artifact inspection substep count does not match its coverage declaration".into(),
        ));
    }
    let mut pages = Vec::with_capacity(substeps.len());
    for substep in substeps {
        let evidence = substep.get("evidence").ok_or_else(|| {
            ProjectionInputError::Invalid("Artifact inspection substep has no Evidence".into())
        })?;
        let evidence_id = substep
            .get("evidence_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProjectionInputError::Invalid(
                    "Artifact inspection substep has no evidence_id".into(),
                )
            })?;
        let record = parse_record(evidence)?;
        if evidence_id != record.evidence_id() || !record.operation_matches(INVENTORY_OPERATION) {
            return Err(ProjectionInputError::Invalid(
                "Artifact inspection substep must contain matching inventory_artifact Evidence"
                    .into(),
            ));
        }
        pages.push(parse_inventory_page(record, Some(carrier.evidence_id()))?);
    }
    let first = pages.first().ok_or_else(|| {
        ProjectionInputError::Invalid("Artifact inspection requires inventory substeps".into())
    })?;
    let manifest = first
        .result
        .get("manifest")
        .ok_or_else(|| ProjectionInputError::Invalid("inventory result has no manifest".into()))?;
    let subject = inspection.get("subject").ok_or_else(|| {
        ProjectionInputError::Invalid("Artifact inspection result has no subject".into())
    })?;
    for field in [
        "manifest_id",
        "root_artifact_id",
        "root_sha256",
        "root_format",
    ] {
        if subject.get(field) != manifest.get(field) {
            return Err(ProjectionInputError::Invalid(
                "Artifact inspection subject does not match its inventory manifest".into(),
            ));
        }
    }
    validate_inventory_subject(carrier, &first.result)?;
    Ok(pages)
}

fn validate_inventory_subject(
    record: &EvidenceRecord,
    result: &Value,
) -> Result<(), ProjectionInputError> {
    let manifest = result
        .get("manifest")
        .ok_or_else(|| ProjectionInputError::Invalid("inventory result has no manifest".into()))?;
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| ProjectionInputError::Invalid(error.to_string()))?;
    if subject.is_null()
        || subject.get("digest").and_then(|value| value.get("sha256"))
            != manifest.get("root_sha256")
        || subject.get("format") != manifest.get("root_format")
    {
        return Err(ProjectionInputError::Invalid(
            "Artifact inventory Evidence subject does not match its root digest".into(),
        ));
    }
    Ok(())
}

fn validate_page_shape(result: &Value) -> Result<(), ProjectionInputError> {
    for field in ["nodes", "occurrences", "edges", "integrity_contradictions"] {
        if !result.get(field).is_some_and(Value::is_array) {
            return Err(ProjectionInputError::Invalid(format!(
                "inventory result {field} must be an array"
            )));
        }
    }
    if !result.get("coverage").is_some_and(Value::is_object) {
        return Err(ProjectionInputError::Invalid(
            "inventory result has no coverage declaration".into(),
        ));
    }
    Ok(())
}

struct Inventory {
    root_sha256: String,
    root_format: String,
    nodes: BTreeMap<String, Value>,
    occurrences: Vec<Value>,
    edges: BTreeMap<String, Value>,
    integrity_contradictions: Vec<Value>,
    limitations: Vec<String>,
    coverage: Value,
    complete: bool,
}

impl Inventory {
    fn assemble(pages: &[Page]) -> Result<Self, String> {
        let first = pages
            .first()
            .ok_or("Artifact inventory requires Evidence pages")?;
        let manifest = first
            .result
            .get("manifest")
            .ok_or("inventory result has no manifest")?;
        let root_sha256 = manifest
            .get("root_sha256")
            .and_then(Value::as_str)
            .ok_or("inventory manifest has no root_sha256")?
            .to_owned();
        let root_format = manifest
            .get("root_format")
            .and_then(Value::as_str)
            .ok_or("inventory manifest has no root_format")?
            .to_owned();
        let coverage = first
            .result
            .get("coverage")
            .cloned()
            .ok_or("inventory result has no coverage")?;
        let mut nodes = BTreeMap::new();
        let mut occurrences = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let contradictions = first
            .result
            .get("integrity_contradictions")
            .ok_or("inventory has no integrity contradictions")?;
        let mut limitations = Vec::new();
        for page in pages {
            if page.result.get("manifest") != Some(manifest)
                || page.result.get("coverage") != Some(&coverage)
                || page.result.get("integrity_contradictions") != Some(contradictions)
            {
                return Err(
                    "Artifact inventory pages do not share one manifest or coverage declaration"
                        .into(),
                );
            }
            for node in page
                .result
                .get("nodes")
                .and_then(Value::as_array)
                .ok_or("inventory result nodes must be an array")?
            {
                merge(&mut nodes, node, "artifact_id")?;
            }
            for occurrence in page
                .result
                .get("occurrences")
                .and_then(Value::as_array)
                .ok_or("inventory result occurrences must be an array")?
            {
                merge(&mut occurrences, occurrence, "occurrence_id")?;
            }
            for edge in page
                .result
                .get("edges")
                .and_then(Value::as_array)
                .ok_or("inventory result edges must be an array")?
            {
                merge(&mut edges, edge, "edge_id")?;
            }
            if let Some(values) = page.result.get("limitations").and_then(Value::as_array) {
                for value in values {
                    if let Some(text) = value.as_str() {
                        if !limitations.iter().any(|item| item == text) {
                            limitations.push(text.to_owned());
                        }
                    }
                }
            }
        }
        let node_count = manifest
            .get("node_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let occurrence_count = manifest
            .get("occurrence_count")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let edge_count = manifest
            .get("edge_count")
            .and_then(Value::as_u64)
            .ok_or("inventory manifest has no edge_count")? as usize;
        let complete = nodes.len() == node_count
            && occurrences.len() == occurrence_count
            && edges.len() == edge_count;
        let mut ordered_occurrences = occurrences.into_values().collect::<Vec<_>>();
        order_occurrences(
            &mut ordered_occurrences,
            manifest["root_artifact_id"].as_str().unwrap_or_default(),
        );
        let inventory = Self {
            root_sha256,
            root_format,
            nodes,
            occurrences: ordered_occurrences,
            edges,
            integrity_contradictions: contradictions.as_array().cloned().unwrap_or_default(),
            limitations,
            coverage,
            complete,
        };
        if inventory.complete {
            inventory.validate_complete(manifest)?;
        }
        Ok(inventory)
    }

    fn validate_complete(&self, manifest: &Value) -> Result<(), String> {
        let root_id = manifest
            .get("root_artifact_id")
            .and_then(Value::as_str)
            .ok_or("inventory manifest has no root_artifact_id")?;
        if self
            .nodes
            .get(root_id)
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
            != Some(root_id)
            || root_occurrence
                .and_then(|occurrence| occurrence.get("artifact_format"))
                .and_then(Value::as_str)
                != Some(self.root_format.as_str())
        {
            return Err(
                "Artifact root occurrence does not match its manifest representation".into(),
            );
        }
        Ok(())
    }

    fn entries(&self) -> Result<Vec<Entry>, String> {
        let mut entries = Vec::new();
        for occurrence in &self.occurrences {
            let path = occurrence
                .get("logical_path")
                .and_then(Value::as_str)
                .ok_or("inventory occurrence has no logical_path")?;
            if path == "." {
                continue;
            }
            let kind = occurrence
                .get("entry_kind")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let artifact_id = occurrence.get("artifact_id").and_then(Value::as_str);
            let entry = if let Some(id) = artifact_id {
                let node = self
                    .nodes
                    .get(id)
                    .ok_or("inventory occurrence references a missing node")?;
                Entry {
                    path: path.to_owned(),
                    kind: kind.to_owned(),
                    component: Some(json!({
                        "path": path,
                        "artifact_id": id,
                        "sha256": node["sha256"],
                        "format": occurrence["artifact_format"],
                    })),
                    unavailable: None,
                }
            } else {
                Entry {
                    path: path.to_owned(),
                    kind: kind.to_owned(),
                    component: None,
                    unavailable: Some(json!({
                        "path": path,
                        "artifact_id": null,
                        "sha256": null,
                        "format": occurrence["artifact_format"],
                        "encrypted": occurrence["encrypted"],
                        "limitations": occurrence["limitations"],
                    })),
                }
            };
            entries.push(entry);
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(entries)
    }
}

fn merge(values: &mut BTreeMap<String, Value>, value: &Value, key: &str) -> Result<(), String> {
    let id = value
        .get(key)
        .and_then(Value::as_str)
        .ok_or("inventory graph member has no identity")?;
    if let Some(previous) = values.get(id) {
        if previous != value {
            return Err(format!("Artifact inventory has conflicting {key} pages"));
        }
    } else {
        values.insert(id.to_owned(), value.clone());
    }
    Ok(())
}

fn order_occurrences(occurrences: &mut [Value], root_artifact_id: &str) {
    let mut ranks = BTreeMap::new();
    let mut grouped: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for occurrence in occurrences.iter() {
        let path = occurrence
            .get("logical_path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        grouped.entry(path).or_default().push(occurrence);
    }
    for (path, group) in grouped {
        let kind = group
            .first()
            .and_then(|value| value.get("entry_kind"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        for ordinal in 0..group.len() {
            ranks.insert(
                occurrence_id_for_location(root_artifact_id, &path, kind, ordinal),
                ordinal,
            );
        }
    }
    occurrences.sort_by(|left, right| {
        let left_path = left["logical_path"].as_str().unwrap_or_default();
        let right_path = right["logical_path"].as_str().unwrap_or_default();
        left_path.cmp(right_path).then_with(|| {
            let left_id = left["occurrence_id"].as_str().unwrap_or_default();
            let right_id = right["occurrence_id"].as_str().unwrap_or_default();
            ranks
                .get(left_id)
                .copied()
                .unwrap_or(usize::MAX)
                .cmp(&ranks.get(right_id).copied().unwrap_or(usize::MAX))
                .then_with(|| left_id.cmp(right_id))
        })
    });
}

fn occurrence_id_for_location(
    root_artifact_id: &str,
    path: &str,
    kind: &str,
    ordinal: usize,
) -> String {
    let identity = if path == "." {
        json!({"root": root_artifact_id})
    } else if ordinal == 0 {
        json!({"root_artifact_id": root_artifact_id, "logical_path": path, "entry_kind": kind})
    } else {
        json!({"root_artifact_id": root_artifact_id, "logical_path": path, "entry_kind": kind, "duplicate_ordinal": ordinal})
    };
    canonical_json::digest(&identity)
        .map(|digest| format!("occ_{digest}"))
        .unwrap_or_default()
}

#[derive(Clone)]
struct Entry {
    path: String,
    kind: String,
    component: Option<Value>,
    unavailable: Option<Value>,
}

struct Components {
    manifests: Vec<Value>,
    bytecode: Vec<Value>,
    resources: Vec<Value>,
    native_libraries: Vec<Value>,
    javascript: Vec<Value>,
    signing: Vec<Value>,
}

impl Components {
    fn as_value(&self) -> Value {
        json!({
            "manifests": self.manifests,
            "bytecode": self.bytecode,
            "resources": self.resources,
            "native_libraries": self.native_libraries,
            "javascript": self.javascript,
            "signing": self.signing,
        })
    }
}

fn classify(entries: &[Entry]) -> Components {
    let files = entries
        .iter()
        .filter(|entry| entry.kind == "file" || entry.kind == "slice")
        .filter_map(|entry| entry.component.clone())
        .collect::<Vec<_>>();
    Components {
        manifests: files
            .iter()
            .filter(|value| is_manifest(component_path(value)))
            .cloned()
            .collect(),
        bytecode: files
            .iter()
            .filter(|value| has_suffix(component_path(value), &[".abc", ".pa"]))
            .cloned()
            .collect(),
        resources: files
            .iter()
            .filter(|value| is_resource_path(component_path(value)))
            .cloned()
            .collect(),
        native_libraries: files
            .iter()
            .filter(|value| {
                value["format"] == "elf" || is_architecture_library_path(component_path(value))
            })
            .cloned()
            .collect(),
        javascript: files
            .iter()
            .filter(|value| {
                value["format"] == "javascript-bundle"
                    || has_suffix(component_path(value), &[".js", ".mjs", ".cjs"])
            })
            .cloned()
            .collect(),
        signing: files
            .iter()
            .filter(|value| is_signing_entry(component_path(value)))
            .cloned()
            .collect(),
    }
}

fn component_path(value: &Value) -> &str {
    value["path"].as_str().unwrap_or_default()
}

fn is_manifest(path: &str) -> bool {
    ["module.json", "config.json", "pack.info"]
        .iter()
        .any(|name| path_component_is(path, name))
}

fn is_resource_path(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    path_component_is(path, "resources.index")
        || (segments.len() >= 2 && segments[0].eq_ignore_ascii_case("resources"))
        || (segments.len() >= 4
            && segments[0].eq_ignore_ascii_case("assets")
            && segments[2].eq_ignore_ascii_case("resources"))
}

fn is_architecture_library_path(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    segments.windows(3).last().is_some_and(|segments| {
        segments[0].eq_ignore_ascii_case("libs")
            && !segments[1].is_empty()
            && !segments[2].is_empty()
            && has_suffix(segments[2], &[".so"])
    })
}

fn is_signing_entry(path: &str) -> bool {
    let Some((directory, file)) = path.split_once('/') else {
        return false;
    };
    directory.eq_ignore_ascii_case("META-INF")
        && !file.contains('/')
        && has_suffix(
            file,
            &[".p7b", ".sig", ".cer", ".crt", ".pem", ".provision"],
        )
}

fn path_component_is(path: &str, component: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|last| last.eq_ignore_ascii_case(component))
}

fn has_suffix(path: &str, suffixes: &[&str]) -> bool {
    let path = path.to_ascii_lowercase();
    suffixes.iter().any(|suffix| path.ends_with(suffix))
}

fn packaging_model(manifests: &[Value]) -> &'static str {
    if manifests.iter().any(|value| {
        value["path"]
            .as_str()
            .is_some_and(|path| path.to_ascii_lowercase().ends_with("module.json"))
    }) {
        "stage"
    } else if manifests.iter().any(|value| {
        value["path"]
            .as_str()
            .is_some_and(|path| path.to_ascii_lowercase().ends_with("config.json"))
    }) {
        "fa"
    } else {
        "unknown"
    }
}

fn runtime_families(entries: &[Entry], components: &Components) -> Vec<&'static str> {
    let mut families = BTreeSet::new();
    if !components.bytecode.is_empty() {
        families.insert("ark");
    }
    if entries.iter().any(|entry| {
        entry
            .component
            .as_ref()
            .is_some_and(|value| value["format"] == "elf")
    }) {
        families.insert("native");
    }
    if !components.javascript.is_empty() {
        families.insert("javascript");
    }
    for entry in entries {
        if let Some(family) = native_runtime_convention(&entry.path) {
            families.insert(family);
        }
    }
    families.into_iter().collect()
}

fn native_runtime_convention(path: &str) -> Option<&'static str> {
    path.split('/')
        .find_map(|segment| match segment.to_ascii_lowercase().as_str() {
            "react.framework"
            | "reactnative.framework"
            | "libreactnative.so"
            | "libreactnativejni.so"
            | "libhermes_executor.so"
            | "libhermes.so"
            | "hermes.framework" => Some("react-native"),
            "libflutter.so" | "flutter.framework" => Some("flutter"),
            "libunity.so" | "unityframework.framework" => Some("unity"),
            _ => None,
        })
}

struct BridgeProjection {
    candidates: Vec<Value>,
    total_candidates: usize,
    emitted_candidates: usize,
    omitted_candidates: usize,
    coverage_status: &'static str,
}

fn is_napi_library_path(path: &str) -> bool {
    let segments = path.split('/').collect::<Vec<_>>();
    segments.windows(3).last().is_some_and(|segments| {
        segments[0].eq_ignore_ascii_case("libs")
            && !segments[1].is_empty()
            && segments[2].to_ascii_lowercase().starts_with("lib")
            && has_suffix(segments[2], &[".so"])
    })
}

fn bridge_candidates(managed: &[Value], native: &[Value]) -> BridgeProjection {
    let total_candidates = managed.len().saturating_mul(native.len());
    let mut candidates = Vec::new();
    let mut encoded_bytes: usize = 0;
    'candidate_loop: for left in managed {
        for right in native {
            let native_path = right["path"].as_str().unwrap_or_default();
            let candidate = json!({
                "managed_path": left["path"],
                "native_path": right["path"],
                "basis": if is_napi_library_path(native_path) { "napi-library-convention" } else { "managed-and-native-content" },
            });
            let size = serde_json::to_vec(&candidate)
                .map(|bytes| bytes.len())
                .unwrap_or(usize::MAX);
            if encoded_bytes.saturating_add(size) > MAX_BRIDGE_CANDIDATE_JSON_BYTES {
                break 'candidate_loop;
            }
            encoded_bytes += size;
            candidates.push(candidate);
        }
    }
    let emitted_candidates = candidates.len();
    BridgeProjection {
        candidates,
        total_candidates,
        emitted_candidates,
        omitted_candidates: total_candidates.saturating_sub(emitted_candidates),
        coverage_status: if emitted_candidates == total_candidates {
            "complete"
        } else {
            "partial"
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        let root_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let normalized_result = json!({
            "manifest": {
                "manifest_id": "agm_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "root_artifact_id": "art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "root_sha256": root_sha256,
                "root_format": "hap",
                "graph_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
                "node_count": 2,
                "occurrence_count": 2,
                "edge_count": 0
            },
            "nodes": [
                {"artifact_id":"art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "format":"zip", "sha256":root_sha256, "size":100, "media_type":null, "architecture":null, "content_state":"materialized", "limitations":[]},
                {"artifact_id":"art_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "format":"file", "sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "size":1, "media_type":null, "architecture":null, "content_state":"materialized", "limitations":[]}
            ],
            "occurrences": [
                {"occurrence_id":"occ_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "artifact_id":"art_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "parent_occurrence_id":null, "logical_path":".", "entry_kind":"directory", "artifact_kind":"container", "artifact_format":"hap", "declared_size":null, "compressed_size":null, "executable":false, "encrypted":false, "hash_status":"verified", "source_location":null, "limitations":[]},
                {"occurrence_id":"occ_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "artifact_id":"art_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "parent_occurrence_id":"occ_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "logical_path":"module.abc", "entry_kind":"file", "artifact_kind":"unknown", "artifact_format":"file", "declared_size":1, "compressed_size":null, "executable":false, "encrypted":false, "hash_status":"verified", "source_location":null, "limitations":[]}
            ],
            "edges": [],
            "provenance": [],
            "integrity_contradictions": [],
            "coverage": {"scope":"container-entries", "status":"complete"},
            "limitations": []
        });
        let evidence = inventory_evidence("inventory_artifact", normalized_result);

        json!({"inventory_evidence": [evidence]})
    }

    fn inventory_evidence(operation: &str, normalized_result: Value) -> Value {
        let unsigned = json!({
            "subject": {
                "name":"fixture.hap",
                "digest":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
                "format":"hap",
                "architecture":null,
                "local_path":"/tmp/fixture.hap"
            },
            "provider":{"id":"rea-artifact-inventory","name":"REA artifact inventory","version":"1"},
            "analysis_profile":null,
            "predicate_type":"rea.artifact-inventory",
            "operation":operation,
            "parameters":{"path":"/tmp/fixture.hap"},
            "raw_result":null,
            "normalized_result":normalized_result,
            "confidence":"observed",
            "authority":"shipped-artifact",
            "environment":null,
            "limitations":[],
            "relationship_coverage":null,
            "locations":[],
            "evidence_links":[]
        });
        let raw = serde_json::value::to_raw_value(&unsigned).expect("unsigned Evidence JSON");
        let record = EvidenceRecord::create_unsigned(&raw).expect("authenticated Evidence");

        serde_json::from_str(record.raw().get()).expect("Evidence JSON")
    }

    #[test]
    fn rejects_duplicate_evidence_identity() {
        let mut value = input();
        value["inventory_evidence"] = json!([
            value["inventory_evidence"][0].clone(),
            value["inventory_evidence"][0].clone()
        ]);
        assert!(validate_input(&value).is_err());
    }

    #[test]
    fn rejects_malformed_inventory_evidence() {
        let malformed = json!({"inventory_evidence": []});
        assert!(validate_input(&malformed).is_err());
    }

    #[test]
    fn rejects_inventory_without_manifest_identity() {
        let mut malformed = input();
        malformed["inventory_evidence"][0]["normalized_result"]["manifest"]
            .as_object_mut()
            .expect("manifest object")
            .remove("manifest_id");
        assert!(validate_input(&malformed).is_err());
    }

    #[test]
    fn preserves_source_identity_and_projects_components() {
        let input = input();
        let result = project(&input).unwrap();
        assert_eq!(
            result["source_evidence_ids"],
            json!([input["inventory_evidence"][0]["evidence_id"]])
        );
        assert_eq!(result["components"]["bytecode"][0]["path"], "module.abc");
    }

    #[test]
    fn emits_authenticated_inferred_evidence_linked_to_inventory_source() {
        let input = input();
        let source_id = input["inventory_evidence"][0]["evidence_id"]
            .as_str()
            .expect("source Evidence ID")
            .to_owned();
        let raw = project_evidence(&input).expect("projected Evidence");
        let evidence = EvidenceRecord::parse(&raw).expect("authenticated projected Evidence");
        let value: Value = serde_json::from_str(raw.get()).expect("projected Evidence JSON");

        assert_eq!(
            evidence.operation().get(),
            "\"project_harmony_application_graph\""
        );
        assert_eq!(
            evidence.predicate_type().get(),
            "\"rea.harmony-application-graph\""
        );
        assert_eq!(evidence.authority().get(), "\"analyst-inference\"");
        assert_eq!(evidence.confidence().get(), "\"inferred\"");
        assert_eq!(value["provider"]["id"], "rea-harmony-application");
        assert_eq!(value["evidence_links"], json!([source_id]));
        assert_eq!(value["subject"]["local_path"], "/tmp/fixture.hap");
        assert_eq!(
            value["subject"]["digest"]["sha256"],
            input["inventory_evidence"][0]["normalized_result"]["manifest"]["root_sha256"]
        );
    }

    #[test]
    fn rejects_modified_inventory_semantic_identifier() {
        let mut input = input();
        input["inventory_evidence"][0]["normalized_result"]["limitations"] =
            json!(["changed after authentication"]);

        let failure = validate_input(&input).expect_err("modified Evidence must be rejected");

        assert_eq!(failure.code(), "evidence_integrity_mismatch");
        assert_eq!(failure.operation(), Some(OPERATION));
    }

    #[test]
    fn rejects_non_inventory_operation_even_when_record_is_authenticated() {
        let wrong_operation = inventory_evidence("inspect_artifact", json!({}));
        let input = json!({"inventory_evidence": [wrong_operation]});

        assert!(validate_input(&input).is_err());
    }
}
