//! Lossless views over retained artifact inventory Evidence.

use crate::javascript::graph::json::{Json, Obj};
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";

/// Compatibility wrapper. Raw MCP dispatch uses [`project_raw`].
pub fn project(
    parent: &serde_json::Value,
    view: &serde_json::Value,
) -> Result<Box<RawValue>, Failure> {
    let parent = parse_value(parent)?;
    let view = parse_value(view)?;
    project_raw(&parent, &view)
}

pub fn project_raw(parent: &Json, view: &Json) -> Result<Box<RawValue>, Failure> {
    let view = normalize_view(view)?;
    let parent_raw =
        RawValue::from_string(parent.stringify()).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;
    let source = Source::from_record(parent, &record)?;
    let body = project_body(parent, &record, &view, &source)?;
    create_view_evidence(parent, &record, &view, body)
}

fn parse_value(value: &serde_json::Value) -> Result<Json, Failure> {
    let raw =
        serde_json::value::to_raw_value(value).map_err(|error| invalid(&error.to_string()))?;
    crate::javascript::graph::json::parse(raw.get()).map_err(|error| invalid(&error.to_string()))
}

struct Source {
    manifest: Json,
    nodes: Vec<Json>,
    occurrences: Vec<Json>,
    edges: Vec<Json>,
    contradictions: Vec<Json>,
    limitations: Vec<String>,
    evidence_ids: Vec<String>,
    inspection: Option<Json>,
    complete: bool,
}

impl Source {
    fn from_record(parent: &Json, record: &EvidenceRecord) -> Result<Self, Failure> {
        match parent.at("operation").as_str() {
            Some("inventory_artifact") => {
                let page = parse_page(parent, record)?;
                Self::merge(vec![(record.evidence_id().to_owned(), page)], None)
            }
            Some("inspect_artifact") => {
                let inspection =
                    parse_json(parent.at("normalized_result"), "Artifact inspection result")?;
                let substeps = inspection.at("substeps").arr();
                if inspection.at("coverage").at("substeps_completed").as_f64()
                    != Some(substeps.len() as f64)
                {
                    return Err(invalid(
                        "Artifact inspection substep count does not match its coverage declaration.",
                    ));
                }
                let mut pages = Vec::with_capacity(substeps.len());
                for substep in substeps {
                    if substep.at("operation").as_str() != Some("inventory_artifact")
                        || substep.at("status").as_str() != Some("completed")
                    {
                        return Err(invalid(
                            "Artifact inspection substeps must be completed inventory_artifact operations.",
                        ));
                    }
                    let id = substep.at("evidence_id").as_str().ok_or_else(|| {
                        invalid("Artifact inspection substep evidence_id is missing.")
                    })?;
                    let evidence = substep.get("evidence").ok_or_else(|| {
                        invalid("Artifact inspection substep evidence is missing.")
                    })?;
                    let raw = RawValue::from_string(evidence.stringify())
                        .map_err(|error| invalid(&error.to_string()))?;
                    let nested =
                        EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
                    if nested.evidence_id() != id || !nested.operation_matches("inventory_artifact")
                    {
                        return Err(invalid(
                            "Artifact inspection substep evidence does not match its declared inventory Evidence.",
                        ));
                    }
                    pages.push((id.to_owned(), parse_page(evidence, &nested)?));
                }
                let source = Self::merge(pages, Some(inspection.clone()))?;
                validate_inspection_subject(&inspection, &source.manifest, parent)?;
                Ok(source)
            }
            _ => Err(invalid(
                "Artifact inventory views require inventory_artifact or inspect_artifact Evidence.",
            )),
        }
    }

    fn merge(pages: Vec<(String, Json)>, inspection: Option<Json>) -> Result<Self, Failure> {
        let first = pages
            .first()
            .ok_or_else(|| invalid("Artifact inventory requires at least one Evidence page."))?;
        let manifest = first.1.at("manifest").clone();
        let coverage = first.1.at("coverage").clone();
        let contradictions = first.1.at("integrity_contradictions").clone();
        let mut nodes = BTreeMap::new();
        let mut occurrences = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut limitations = BTreeSet::new();
        let mut evidence_ids = Vec::with_capacity(pages.len());
        for (id, page) in pages {
            if page.at("manifest") != &manifest
                || page.at("coverage") != &coverage
                || page.at("integrity_contradictions") != &contradictions
            {
                return Err(invalid(
                    "Artifact inventory pages do not share one manifest, coverage declaration, and contradiction set.",
                ));
            }
            evidence_ids.push(id);
            for value in page.at("limitations").arr() {
                if let Some(text) = value.as_str() {
                    limitations.insert(text.to_owned());
                }
            }
            merge_records(&mut nodes, page.at("nodes").arr(), "artifact_id")?;
            merge_records(
                &mut occurrences,
                page.at("occurrences").arr(),
                "occurrence_id",
            )?;
            merge_records(&mut edges, page.at("edges").arr(), "edge_id")?;
        }
        let mut nodes = nodes.into_values().collect::<Vec<_>>();
        nodes.sort_by_key(|value| value.at("artifact_id").str().to_owned());
        let occurrences = order_occurrences(&manifest, occurrences.into_values().collect());
        let mut edges = edges.into_values().collect::<Vec<_>>();
        edges.sort_by_key(|value| value.at("edge_id").str().to_owned());
        let complete = nodes.len() == count(&manifest, "node_count")
            && occurrences.len() == count(&manifest, "occurrence_count")
            && edges.len() == count(&manifest, "edge_count");
        Ok(Self {
            manifest,
            nodes,
            occurrences,
            edges,
            contradictions: contradictions.arr().to_vec(),
            limitations: limitations.into_iter().collect(),
            evidence_ids,
            inspection,
            complete,
        })
    }
}

fn parse_json(value: &Json, label: &str) -> Result<Json, Failure> {
    crate::javascript::graph::json::parse(value.stringify().as_str())
        .map_err(|error| invalid(&format!("{label} is invalid: {error}")))
}
fn parse_page(value: &Json, record: &EvidenceRecord) -> Result<Json, Failure> {
    let raw = RawValue::from_string(value.at("normalized_result").stringify())
        .map_err(|error| invalid(&error.to_string()))?;
    let normalized = rea_core::artifact_inventory::normalize_result_text(&raw)
        .map_err(|error| invalid(&error))?;
    let page = crate::javascript::graph::json::parse(normalized.get())
        .map_err(|error| invalid(&error.to_string()))?;
    let subject = crate::javascript::graph::json::parse(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    if subject.at("digest").at("sha256") != page.at("manifest").at("root_sha256")
        || subject.at("format") != page.at("manifest").at("root_format")
    {
        return Err(invalid(
            "Artifact inventory Evidence subject does not match its root manifest.",
        ));
    }
    Ok(page)
}
fn validate_inspection_subject(
    inspection: &Json,
    manifest: &Json,
    parent: &Json,
) -> Result<(), Failure> {
    let subject = inspection.at("subject");
    if subject.at("manifest_id") != manifest.at("manifest_id")
        || subject.at("root_artifact_id") != manifest.at("root_artifact_id")
        || subject.at("root_sha256") != manifest.at("root_sha256")
        || subject.at("root_format") != manifest.at("root_format")
        || parent.at("subject").at("digest").at("sha256") != manifest.at("root_sha256")
        || parent.at("subject").at("format") != manifest.at("root_format")
    {
        return Err(invalid(
            "Artifact inspection subject does not match its inventory manifest.",
        ));
    }
    Ok(())
}
fn merge_records(
    target: &mut BTreeMap<String, Json>,
    values: &[Json],
    key: &str,
) -> Result<(), Failure> {
    for value in values {
        let id = value
            .at(key)
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
fn order_occurrences(manifest: &Json, occurrences: Vec<Json>) -> Vec<Json> {
    let mut groups =
        BTreeMap::<crate::javascript::semantic::value_types::JsString, Vec<Json>>::new();
    for occurrence in occurrences {
        groups
            .entry(occurrence.at("logical_path").text().clone())
            .or_default()
            .push(occurrence);
    }
    let root = manifest.at("root_artifact_id").str();
    let mut ordered = Vec::new();
    for (path, mut group) in groups {
        if group.len() > 1 {
            let kind = group[0].at("entry_kind").str();
            let mut ordinals = BTreeMap::new();
            for ordinal in 0..group.len() {
                let mut identity = Obj::new()
                    .with("root_artifact_id", root)
                    .with("logical_path", &path)
                    .with("entry_kind", kind);
                if path.as_str() == Some(".") {
                    identity = Obj::new().with("root", root);
                }
                if ordinal > 0 {
                    identity.set("duplicate_ordinal", ordinal);
                }
                ordinals.insert(format!("occ_{}", Json::from(identity).digest()), ordinal);
            }
            group.sort_by_key(|value| {
                (
                    ordinals
                        .get(value.at("occurrence_id").str())
                        .copied()
                        .unwrap_or(usize::MAX),
                    value.at("occurrence_id").str().to_owned(),
                )
            });
        }
        ordered.extend(group);
    }
    ordered
}

fn validate_view(view: &Json) -> Result<(), Failure> {
    let object = view
        .as_obj()
        .ok_or_else(|| invalid("Artifact Evidence supports summary and inventory views."))?;
    match view.at("kind").as_str() {
        Some("summary") if object.len() == 1 => Ok(()),
        Some("summary") => Err(invalid(
            "Artifact summary views do not accept extra fields.",
        )),
        Some("inventory") => {
            let collection = view
                .at("collection")
                .as_str()
                .ok_or_else(|| invalid("Artifact inventory collection is required."))?;
            if !matches!(
                collection,
                "nodes" | "occurrences" | "edges" | "integrity_contradictions"
            ) {
                return Err(invalid("Unknown artifact inventory collection."));
            }
            let allowed = if collection == "occurrences" {
                ["kind", "collection", "logical_paths", "offset", "limit"].as_slice()
            } else {
                ["kind", "collection", "offset", "limit"].as_slice()
            };
            if object
                .iter()
                .any(|(key, _)| !allowed.contains(&key.as_str().unwrap_or_default()))
            {
                return Err(invalid(
                    "Artifact inventory view contains an unknown field.",
                ));
            }
            if view.get("logical_paths").is_some()
                && !view
                    .at("logical_paths")
                    .arr()
                    .iter()
                    .all(|value| value.as_js_string().is_some())
            {
                return Err(invalid(
                    "Artifact occurrence logical_paths must be strings.",
                ));
            }
            validate_integer(view.get("offset"), false, "offset")?;
            validate_integer(view.get("limit"), true, "limit")
        }
        _ => Err(invalid(
            "Artifact Evidence supports summary and inventory views.",
        )),
    }
}

/// Apply the defaults owned by `analysisViewRequestSchema` before projection.
///
/// The exact raw projection path is also used by retained Evidence and
/// comparison resolution, so it cannot rely on the outer Value-schema parser
/// having already materialized `offset` and `limit`.
fn normalize_view(view: &Json) -> Result<Json, Failure> {
    validate_view(view)?;
    if view.at("kind").as_str() != Some("inventory") {
        return Ok(view.clone());
    }

    let mut normalized = Obj::new()
        .with("kind", view.at("kind"))
        .with("collection", view.at("collection"));
    if let Some(logical_paths) = view.get("logical_paths") {
        normalized.set("logical_paths", logical_paths.clone());
    }
    normalized.set(
        "offset",
        view.get("offset")
            .cloned()
            .unwrap_or_else(|| Json::from(0usize)),
    );
    normalized.set(
        "limit",
        view.get("limit")
            .cloned()
            .unwrap_or_else(|| Json::from(64usize)),
    );
    Ok(normalized.into())
}
fn validate_integer(value: Option<&Json>, positive: bool, field: &str) -> Result<(), Failure> {
    if let Some(value) = value {
        let valid = value.as_f64().is_some_and(|number| {
            number.is_finite()
                && number.fract() == 0.0
                && number >= 0.0
                && (!positive || number > 0.0)
        });
        if !valid {
            return Err(invalid(&format!(
                "Artifact inventory {field} must be {}.",
                if positive {
                    "positive"
                } else {
                    "a nonnegative integer"
                }
            )));
        }
    }
    Ok(())
}

fn project_body(
    parent: &Json,
    record: &EvidenceRecord,
    view: &Json,
    source: &Source,
) -> Result<Json, Failure> {
    let limitations = merged_limitations(parent, source);
    let shared = Obj::new()
        .with("parent_evidence_id", record.evidence_id())
        .with("parent_operation", parent.at("operation"))
        .with(
            "parent_digest",
            record
                .evidence_id()
                .strip_prefix("ev_")
                .unwrap_or(record.evidence_id()),
        )
        .with(
            "artifact",
            Obj::new()
                .with("path", parent.at("subject").at("local_path"))
                .with("sha256", source.manifest.at("root_sha256")),
        )
        .with("limitations", strings(limitations))
        .with("unknowns", strings(inventory_unknowns(source)));
    if view.at("kind").as_str() == Some("summary") {
        summary(source, view, shared)
    } else {
        page(source, view, shared)
    }
}
fn summary(source: &Source, view: &Json, shared: Obj) -> Result<Json, Failure> {
    let mut kinds = Obj::new();
    for kind in ["file", "directory", "symlink", "slice"] {
        kinds.set(
            kind,
            source
                .occurrences
                .iter()
                .filter(|row| row.at("entry_kind").as_str() == Some(kind))
                .count(),
        );
    }
    let examined = source.nodes.len() + source.occurrences.len() + source.edges.len();
    let inspection = source.inspection.as_ref().map(|value| {
        Obj::new()
            .with("coverage", value.at("coverage"))
            .with("unexplored_branches", value.at("unexplored_branches"))
    });
    let summary = Obj::new()
        .with("manifest", &source.manifest)
        .with(
            "available_counts",
            Obj::new()
                .with("nodes", source.nodes.len())
                .with("occurrences", source.occurrences.len())
                .with("edges", source.edges.len())
                .with("integrity_contradictions", source.contradictions.len()),
        )
        .with("observed_entry_kind_counts", kinds)
        .with("source_complete", source.complete)
        .with(
            "inventory_evidence_ids",
            strings(source.evidence_ids.clone()),
        )
        .with("inspection", inspection)
        .with(
            "limitation_count",
            shared
                .get("limitations")
                .map_or(0, |value| value.arr().len()),
        );
    let mut output = Obj::new()
        .with("kind", "summary")
        .with("view", view)
        .with("summary", summary)
        .with("coverage", complete_coverage(examined));
    output.extend_from(&shared);
    Ok(output.into())
}
fn page(source: &Source, view: &Json, shared: Obj) -> Result<Json, Failure> {
    let collection = view.at("collection").str();
    let mut rows = match collection {
        "nodes" => source.nodes.clone(),
        "occurrences" => source.occurrences.clone(),
        "edges" => source.edges.clone(),
        "integrity_contradictions" => source.contradictions.clone(),
        _ => return Err(invalid("Unknown artifact inventory collection.")),
    };
    if collection == "occurrences" {
        if let Some(paths) = view.get("logical_paths") {
            rows.retain(|row| {
                paths
                    .arr()
                    .iter()
                    .any(|path| path.as_js_string() == row.at("logical_path").as_js_string())
            });
        }
    }
    let offset = count(view, "offset");
    let limit = count(view, "limit").max(1);
    let items = rows
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut output = Obj::new()
        .with("kind", "inventory")
        .with("view", view)
        .with("manifest", &source.manifest)
        .with(
            "inventory_evidence_ids",
            strings(source.evidence_ids.clone()),
        )
        .with("source_complete", source.complete)
        .with("items", items.clone())
        .with("coverage", page_coverage(offset, items.len(), rows.len()));
    output.extend_from(&shared);
    Ok(output.into())
}

fn create_view_evidence(
    parent: &Json,
    record: &EvidenceRecord,
    view: &Json,
    body: Json,
) -> Result<Box<RawValue>, Failure> {
    let mut locations = Vec::new();
    if let Some(path) = body.at("artifact").at("path").as_js_string() {
        if !path.is_empty() {
            locations.push(
                Obj::new()
                    .with("kind", "artifact-path")
                    .with("path", path)
                    .into(),
            );
        }
    }
    let mut body = body;
    let view_digest = body.digest();
    if let Json::Object(object) = &mut body {
        object.set("view_digest", view_digest);
    } else {
        return Err(invalid("Artifact inventory view must be an object."));
    }

    let unsigned: Json = Obj::new()
        .with("subject", parent.at("subject"))
        .with(
            "provider",
            Obj::new()
                .with("id", "rea-analysis-view")
                .with("name", "REA analysis view projection")
                .with("version", "1"),
        )
        .with("analysis_profile", Json::Null)
        .with("predicate_type", "rea.analysis-view")
        .with("operation", OPERATION)
        .with(
            "parameters",
            Obj::new()
                .with("parent_evidence_id", record.evidence_id())
                .with("view", view),
        )
        .with("raw_result", Json::Null)
        .with("normalized_result", body.clone())
        .with("confidence", "derived")
        .with("authority", parent.at("authority"))
        .with("environment", Json::Null)
        .with("limitations", body.at("limitations"))
        .with("relationship_coverage", Json::Null)
        .with("locations", locations)
        .with("evidence_links", vec![Json::from(record.evidence_id())])
        .into();
    let raw =
        RawValue::from_string(unsigned.stringify()).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}
fn merged_limitations(parent: &Json, source: &Source) -> Vec<String> {
    let mut values = BTreeSet::new();
    for value in parent.at("limitations").arr() {
        if let Some(text) = value.as_str() {
            values.insert(text.to_owned());
        }
    }
    values.extend(source.limitations.iter().cloned());
    values.into_iter().collect()
}
fn inventory_unknowns(source: &Source) -> Vec<String> {
    let mut values = vec!["Inventory does not establish application runtime behavior or complete format-specific analysis.".to_owned()];
    if !source.complete {
        values.push("Parent inventory is partial; counts and exhausted pages cover only available records. Missing matches do not establish absence.".to_owned());
    }
    values
}
fn strings(values: Vec<String>) -> Json {
    Json::array(values.into_iter().map(Json::from).collect())
}
fn count(value: &Json, key: &str) -> usize {
    value
        .at(key)
        .as_f64()
        .filter(|number| *number >= 0.0)
        .map_or(0, |number| number as usize)
}
fn complete_coverage(total: usize) -> Json {
    Obj::new()
        .with("status", "complete-within-view")
        .with("examined", total)
        .with("total", total)
        .with("next_offset", Json::Null)
        .with("exhausted", true)
        .into()
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Json {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    Obj::new()
        .with("status", if examined == 0 { "empty" } else { "page" })
        .with("examined", examined)
        .with("total", total)
        .with(
            "next_offset",
            if exhausted {
                Json::Null
            } else {
                Json::from(offset + examined)
            },
        )
        .with("exhausted", exhausted)
        .into()
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
