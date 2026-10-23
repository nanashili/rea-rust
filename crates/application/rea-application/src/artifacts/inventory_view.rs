//! Authenticated, bounded views over retained artifact inventory Evidence.
//!
//! This module only projects retained records. It never reopens an artifact,
//! reruns an inventory command, or treats an omitted inventory member as proof
//! that the member does not exist.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";

/// Project an inventory summary or bounded inventory collection page.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;

    let source = match record.operation_matches("inventory_artifact") {
        true => Source::inventory(&record)?,
        false if record.operation_matches("inspect_artifact") => Source::inspection(&record)?,
        false => {
            return Err(invalid(
                "Artifact inventory views require inventory_artifact or inspect_artifact Evidence.",
            ));
        }
    };

    let body = project_body(&record, parent, view, &source)?;
    create_view_evidence(&record, view, body)
}

struct Source {
    manifest: Value,
    coverage: Value,
    nodes: Vec<Value>,
    occurrences: Vec<Value>,
    edges: Vec<Value>,
    contradictions: Vec<Value>,
    limitations: Vec<String>,
    evidence_ids: Vec<String>,
    inspection: Option<Value>,
    complete: bool,
}

impl Source {
    fn inventory(record: &EvidenceRecord) -> Result<Self, Failure> {
        let page = parse_inventory_record(record)?;
        Self::from_pages(vec![(record.evidence_id().to_owned(), page)], None)
    }

    fn inspection(record: &EvidenceRecord) -> Result<Self, Failure> {
        let inspection = parse_inspection(record)?;
        let substeps = inspection
            .get("substeps")
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("Artifact inspection is missing inventory substeps."))?;
        if inspection["coverage"]["substeps_completed"].as_u64() != Some(substeps.len() as u64) {
            return Err(invalid(
                "Artifact inspection substep count does not match its coverage declaration.",
            ));
        }

        let mut pages = Vec::with_capacity(substeps.len());
        for substep in substeps {
            if substep["operation"] != "inventory_artifact" || substep["status"] != "completed" {
                return Err(invalid(
                    "Artifact inspection substeps must be completed inventory_artifact operations.",
                ));
            }
            let evidence_id = substep["evidence_id"]
                .as_str()
                .ok_or_else(|| invalid("Artifact inspection substep evidence_id is missing."))?;
            let evidence = substep
                .get("evidence")
                .ok_or_else(|| invalid("Artifact inspection substep evidence is missing."))?;
            let raw = serde_json::value::to_raw_value(evidence)
                .map_err(|error| invalid(&error.to_string()))?;
            let nested =
                EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
            if nested.evidence_id() != evidence_id
                || !nested.operation_matches("inventory_artifact")
            {
                return Err(invalid(
                    "Artifact inspection substep evidence does not match its declared inventory Evidence.",
                ));
            }
            pages.push((evidence_id.to_owned(), parse_inventory_record(&nested)?));
        }

        let source = Self::from_pages(pages, Some(inspection.clone()))?;
        validate_inspection_subject(&inspection, &source.manifest, record)?;
        Ok(source)
    }

    fn from_pages(pages: Vec<(String, Value)>, inspection: Option<Value>) -> Result<Self, Failure> {
        let first = pages
            .first()
            .ok_or_else(|| invalid("Artifact inventory requires at least one Evidence page."))?;
        let manifest = first.1["manifest"].clone();
        let coverage = first.1["coverage"].clone();
        let contradictions = first.1["integrity_contradictions"].clone();
        let mut nodes = BTreeMap::new();
        let mut occurrences = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut limitations = BTreeSet::new();
        let mut evidence_ids = Vec::with_capacity(pages.len());

        for (evidence_id, page) in pages {
            if page["manifest"] != manifest
                || page["coverage"] != coverage
                || page["integrity_contradictions"] != contradictions
            {
                return Err(invalid(
                    "Artifact inventory pages do not share one manifest, coverage declaration, and contradiction set.",
                ));
            }
            evidence_ids.push(evidence_id);
            if let Some(values) = page["limitations"].as_array() {
                for value in values {
                    if let Some(value) = value.as_str() {
                        limitations.insert(value.to_owned());
                    }
                }
            }
            merge_records(&mut nodes, page["nodes"].as_array(), "artifact_id")?;
            merge_records(
                &mut occurrences,
                page["occurrences"].as_array(),
                "occurrence_id",
            )?;
            merge_records(&mut edges, page["edges"].as_array(), "edge_id")?;
        }

        let mut nodes = nodes.into_values().collect::<Vec<_>>();
        let mut occurrences = occurrences.into_values().collect::<Vec<_>>();
        let mut edges = edges.into_values().collect::<Vec<_>>();
        nodes.sort_by_key(|value| value["artifact_id"].as_str().unwrap_or_default().to_owned());
        occurrences = order_occurrences(&manifest, occurrences);
        edges.sort_by_key(|value| value["edge_id"].as_str().unwrap_or_default().to_owned());

        let complete = nodes.len() == manifest["node_count"].as_u64().unwrap_or(0) as usize
            && occurrences.len() == manifest["occurrence_count"].as_u64().unwrap_or(0) as usize
            && edges.len() == manifest["edge_count"].as_u64().unwrap_or(0) as usize;
        Ok(Self {
            manifest,
            coverage,
            nodes,
            occurrences,
            edges,
            contradictions: contradictions.as_array().cloned().unwrap_or_default(),
            limitations: limitations.into_iter().collect(),
            evidence_ids,
            inspection,
            complete,
        })
    }
}

fn parse_inventory_record(record: &EvidenceRecord) -> Result<Value, Failure> {
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let normalized =
        super::inventory_evidence::normalize_result(result).map_err(|error| invalid(&error))?;
    validate_subject(record, &normalized)?;
    Ok(normalized)
}

fn parse_inspection(record: &EvidenceRecord) -> Result<Value, Failure> {
    serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("Artifact inspection result is invalid: {error}")))
}

fn validate_subject(record: &EvidenceRecord, inventory: &Value) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    if subject.is_null()
        || subject["digest"]["sha256"] != inventory["manifest"]["root_sha256"]
        || subject["format"] != inventory["manifest"]["root_format"]
    {
        return Err(invalid(
            "Artifact inventory Evidence subject does not match its root manifest.",
        ));
    }
    Ok(())
}

fn validate_inspection_subject(
    inspection: &Value,
    manifest: &Value,
    record: &EvidenceRecord,
) -> Result<(), Failure> {
    if inspection["subject"]["manifest_id"] != manifest["manifest_id"]
        || inspection["subject"]["root_artifact_id"] != manifest["root_artifact_id"]
        || inspection["subject"]["root_sha256"] != manifest["root_sha256"]
        || inspection["subject"]["root_format"] != manifest["root_format"]
    {
        return Err(invalid(
            "Artifact inspection subject does not match its inventory manifest.",
        ));
    }
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    if subject.is_null()
        || subject["digest"]["sha256"] != manifest["root_sha256"]
        || subject["format"] != manifest["root_format"]
    {
        return Err(invalid(
            "Artifact inspection Evidence subject does not match its root manifest.",
        ));
    }
    Ok(())
}

fn merge_records(
    target: &mut BTreeMap<String, Value>,
    values: Option<&Vec<Value>>,
    key: &str,
) -> Result<(), Failure> {
    for value in values.ok_or_else(|| invalid("Artifact inventory collection is missing."))? {
        let id = value[key]
            .as_str()
            .ok_or_else(|| invalid("Artifact inventory collection member has no identifier."))?;
        if let Some(existing) = target.get(id) {
            if existing != value {
                return Err(invalid(
                    "Artifact inventory pages contain conflicting records.",
                ));
            }
        } else {
            target.insert(id.to_owned(), value.clone());
        }
    }
    Ok(())
}

fn order_occurrences(manifest: &Value, mut occurrences: Vec<Value>) -> Vec<Value> {
    let root_artifact_id = manifest["root_artifact_id"].as_str().unwrap_or_default();
    let mut grouped = BTreeMap::<String, Vec<Value>>::new();
    for occurrence in occurrences.drain(..) {
        let path = occurrence["logical_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        grouped.entry(path).or_default().push(occurrence);
    }

    let mut ordered = Vec::new();
    for (path, mut group) in grouped {
        if group.len() > 1 {
            let first_kind = group[0]["entry_kind"].as_str().unwrap_or_default();
            let mut ordinal_by_id = BTreeMap::new();
            for ordinal in 0..group.len() {
                let identity = if path == "." {
                    json!({"root": root_artifact_id})
                } else if ordinal == 0 {
                    json!({
                        "root_artifact_id": root_artifact_id,
                        "logical_path": path,
                        "entry_kind": first_kind,
                    })
                } else {
                    json!({
                        "root_artifact_id": root_artifact_id,
                        "logical_path": path,
                        "entry_kind": first_kind,
                        "duplicate_ordinal": ordinal,
                    })
                };
                if let Ok(digest) = rea_core::canonical_json::digest(&identity) {
                    ordinal_by_id.insert(format!("occ_{digest}"), ordinal);
                }
            }
            group.sort_by_key(|value| {
                (
                    ordinal_by_id
                        .get(value["occurrence_id"].as_str().unwrap_or_default())
                        .copied()
                        .unwrap_or(usize::MAX),
                    value["occurrence_id"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned(),
                )
            });
        }
        ordered.extend(group);
    }
    ordered
}

fn validate_view(view: &Value) -> Result<(), Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Artifact Evidence supports summary and inventory views."))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Artifact Evidence supports summary and inventory views."))?;

    match kind {
        "summary" => {
            if object.len() != 1 {
                return Err(invalid(
                    "Artifact summary views do not accept extra fields.",
                ));
            }
        }
        "inventory" => {
            let collection = object
                .get("collection")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("Artifact inventory collection is required."))?;
            let allowed = if collection == "occurrences" {
                ["kind", "collection", "logical_paths", "offset", "limit"].as_slice()
            } else {
                ["kind", "collection", "offset", "limit"].as_slice()
            };
            if !matches!(
                collection,
                "nodes" | "occurrences" | "edges" | "integrity_contradictions"
            ) {
                return Err(invalid("Unknown artifact inventory collection."));
            }
            if object.keys().any(|key| !allowed.contains(&key.as_str())) {
                return Err(invalid(
                    "Artifact inventory view contains an unknown field.",
                ));
            }
            if let Some(paths) = object.get("logical_paths") {
                if !paths
                    .as_array()
                    .is_some_and(|items| items.iter().all(Value::is_string))
                {
                    return Err(invalid(
                        "Artifact occurrence logical_paths must be strings.",
                    ));
                }
            }
            validate_nonnegative_integer(object.get("offset"), "offset")?;
            validate_positive_integer(object.get("limit"), "limit")?;
        }
        _ => {
            return Err(invalid(
                "Artifact Evidence supports summary and inventory views.",
            ));
        }
    }
    Ok(())
}

fn validate_nonnegative_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        if value.as_u64().is_none() {
            return Err(invalid(&format!(
                "Artifact inventory {field} must be a nonnegative integer."
            )));
        }
    }
    Ok(())
}

fn validate_positive_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        if value.as_u64().map_or(true, |number| number == 0) {
            return Err(invalid(&format!(
                "Artifact inventory {field} must be positive."
            )));
        }
    }
    Ok(())
}

fn project_body(
    record: &EvidenceRecord,
    parent: &Value,
    view: &Value,
    source: &Source,
) -> Result<Value, Failure> {
    validate_view(view)?;
    let kind = view["kind"]
        .as_str()
        .ok_or_else(|| invalid("Artifact Evidence supports summary and inventory views."))?;
    let limitations = merged_limitations(parent, source);
    let shared = json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": if record.operation_matches("inspect_artifact") { "inspect_artifact" } else { "inventory_artifact" },
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": subject_path(record)?, "sha256": source.manifest["root_sha256"]},
        "limitations": limitations,
        "unknowns": inventory_unknowns(source)
    });

    match kind {
        "summary" => summary(source, view, shared),
        "inventory" => page(source, view, shared),
        _ => Err(invalid(
            "Artifact Evidence supports summary and inventory views.",
        )),
    }
}

fn summary(source: &Source, view: &Value, shared: Value) -> Result<Value, Failure> {
    let mut counts = Map::new();
    for kind in ["file", "directory", "symlink", "slice"] {
        counts.insert(
            kind.to_owned(),
            Value::from(
                source
                    .occurrences
                    .iter()
                    .filter(|row| row["entry_kind"] == kind)
                    .count() as u64,
            ),
        );
    }
    let examined = source.nodes.len() + source.occurrences.len() + source.edges.len();
    let mut output = json!({
        "kind":"summary", "view":view,
        "summary": {"manifest":source.manifest.clone(), "available_counts":{"nodes":source.nodes.len(),"occurrences":source.occurrences.len(),"edges":source.edges.len(),"integrity_contradictions":source.contradictions.len()}, "observed_entry_kind_counts":counts, "source_complete":source.complete, "inventory_evidence_ids":source.evidence_ids.clone(), "inspection":source.inspection.as_ref().map(|value| json!({"coverage":value["coverage"],"unexplored_branches":value["unexplored_branches"]})), "limitation_count":shared["limitations"].as_array().map_or(0, Vec::len)},
        "coverage": complete_coverage(examined),
    });
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    Ok(output)
}

fn page(source: &Source, view: &Value, shared: Value) -> Result<Value, Failure> {
    let collection = view["collection"]
        .as_str()
        .ok_or_else(|| invalid("Artifact inventory collection is required."))?;
    let offset = view["offset"].as_u64().unwrap_or(0) as usize;
    let limit = view["limit"].as_u64().unwrap_or(64) as usize;
    if limit == 0 {
        return Err(invalid("Artifact inventory view limit must be positive."));
    }
    let mut rows = match collection {
        "nodes" => source.nodes.clone(),
        "occurrences" => source.occurrences.clone(),
        "edges" => source.edges.clone(),
        "integrity_contradictions" => source.contradictions.clone(),
        _ => return Err(invalid("Unknown artifact inventory collection.")),
    };
    if collection == "occurrences" {
        if let Some(paths) = view.get("logical_paths").and_then(Value::as_array) {
            let paths = paths
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>();
            rows.retain(|row| paths.contains(row["logical_path"].as_str().unwrap_or_default()));
        }
    }
    let items = rows
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut output = json!({"kind":"inventory","view":view,"manifest":source.manifest.clone(),"inventory_evidence_ids":source.evidence_ids.clone(),"source_complete":source.complete,"items":items,"coverage":page_coverage(offset, items.len(), rows.len())});
    output
        .as_object_mut()
        .unwrap()
        .extend(shared.as_object().unwrap().clone());
    Ok(output)
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let locations = body["artifact"]["path"]
        .as_str()
        .filter(|path| !path.is_empty())
        .map(|path| vec![json!({"kind":"artifact-path", "path":path})])
        .unwrap_or_default();
    let limitations = body["limitations"].clone();

    let unsigned = json!({
        "subject": subject,
        "provider": {"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view},
        "raw_result":null,
        "normalized_result":body,
        "confidence":"derived",
        "authority":authority,
        "environment":null,
        "limitations":limitations,
        "relationship_coverage":null,
        "locations":locations,
        "evidence_links":[record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}

fn subject_path(record: &EvidenceRecord) -> Result<String, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(subject["local_path"]
        .as_str()
        .unwrap_or_default()
        .to_owned())
}

fn merged_limitations(parent: &Value, source: &Source) -> Vec<String> {
    let mut values = BTreeSet::new();
    if let Some(items) = parent["limitations"].as_array() {
        for item in items.iter().filter_map(Value::as_str) {
            values.insert(item.to_owned());
        }
    }
    values.extend(source.limitations.iter().cloned());
    values.into_iter().collect()
}

fn inventory_unknowns(source: &Source) -> Vec<String> {
    let mut unknowns = vec![
        "Inventory does not establish application runtime behavior or complete format-specific analysis."
            .to_owned(),
    ];
    if !source.complete {
        unknowns.push(
            "Parent inventory is partial; counts and exhausted pages cover only available records. Missing matches do not establish absence."
                .to_owned(),
        );
    }
    unknowns
}

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the retained Evidence or view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
