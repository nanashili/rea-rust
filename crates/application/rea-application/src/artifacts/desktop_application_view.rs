//! Bounded views over retained desktop application Evidence.
//!
//! This module only projects an already retained report. It does not revisit
//! the directory or rerun any probes.

use crate::artifacts::desktop_application;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "inspect_desktop_application";
const DIAGNOSTIC_PREVIEW_FILES: usize = 2;
const DIAGNOSTIC_PREVIEW_UNITS: usize = 256;

/// Project a desktop application summary or bounded collection page.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw = serde_json::value::to_raw_value(parent)
        .map_err(|error| invalid(&format!("parent could not be encoded: {error}")))?;
    let record = EvidenceRecord::parse(&parent_raw)
        .map_err(|error| invalid(&format!("parent Evidence is invalid: {error}")))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Desktop application views require inspect_desktop_application Evidence.",
        ));
    }

    let report = desktop_application::project(&json!({"evidence": parent}))?;
    validate_subject(&record, &report)?;
    let requested = parse_view(view)?;
    let shared = shared_fields(&record, &report)?;
    let body = match requested {
        RequestedView::Summary => summary(&report, shared)?,
        RequestedView::Collection(request) => collection_page(&report, request, shared)?,
    };

    create_view_evidence(&record, view.clone(), body)
}

enum RequestedView {
    Summary,
    Collection(CollectionRequest),
}

struct CollectionRequest {
    collection: String,
    offset: usize,
    limit: usize,
    paths: Option<Vec<String>>,
    ids: Option<Vec<String>>,
    families: Option<Vec<String>>,
    has_issues: Option<bool>,
    fields: Option<Vec<String>>,
}

fn parse_view(view: &Value) -> Result<RequestedView, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("Desktop application view must be an object."))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Desktop application view kind is required."))?;
    match kind {
        "summary" => {
            require_keys(object, &["kind"])?;
            Ok(RequestedView::Summary)
        }
        "desktop-application" => parse_collection_view(object),
        _ => Err(invalid(
            "Desktop directory Evidence supports summary and desktop-application views.",
        )),
    }
}

fn parse_collection_view(object: &Map<String, Value>) -> Result<RequestedView, Failure> {
    let collection = object
        .get("collection")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("Desktop application collection is required."))?;
    if ![
        "files",
        "candidates",
        "omissions",
        "components",
        "next_probes",
    ]
    .contains(&collection)
    {
        return Err(invalid("Desktop application collection is unsupported."));
    }
    let offset = nonnegative_usize(object.get("offset"), 0, "offset")?;
    let limit = nonnegative_usize(object.get("limit"), 64, "limit")?;
    if limit == 0 {
        return Err(invalid("Desktop application view limit must be positive."));
    }
    let paths = string_array(object.get("paths"), "paths")?;
    let families = string_array(object.get("families"), "families")?;
    let fields = string_array(object.get("fields"), "fields")?;
    let has_issues = object
        .get("has_issues")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid("has_issues must be a boolean."))
        })
        .transpose()?;
    let ids = match collection {
        "files" => string_array(object.get("file_ids"), "file_ids")?,
        "omissions" => string_array(object.get("omission_ids"), "omission_ids")?,
        _ => None,
    };

    let allowed = match collection {
        "files" => &[
            "kind",
            "collection",
            "offset",
            "limit",
            "paths",
            "file_ids",
            "has_issues",
            "fields",
        ][..],
        "omissions" => &[
            "kind",
            "collection",
            "offset",
            "limit",
            "paths",
            "omission_ids",
            "fields",
        ][..],
        "candidates" => &[
            "kind",
            "collection",
            "offset",
            "limit",
            "families",
            "fields",
        ][..],
        _ => &["kind", "collection", "offset", "limit", "fields"][..],
    };
    require_keys_subset(object, allowed)?;

    Ok(RequestedView::Collection(CollectionRequest {
        collection: collection.to_owned(),
        offset,
        limit,
        paths,
        ids,
        families,
        has_issues,
        fields,
    }))
}

fn validate_subject(record: &EvidenceRecord, report: &Value) -> Result<(), Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&format!("desktop subject is invalid: {error}")))?;
    let same = subject["format"] == "directory"
        && subject["local_path"] == report["root"]["path"]
        && subject["digest"]["sha256"] == report["root"]["snapshot_sha256"];
    if same {
        Ok(())
    } else {
        Err(invalid(
            "Parent must identify the same examined directory snapshot.",
        ))
    }
}

fn shared_fields(record: &EvidenceRecord, report: &Value) -> Result<Value, Failure> {
    let parent: Value = serde_json::from_str(record.raw().get())
        .map_err(|error| invalid(&format!("parent Evidence is invalid: {error}")))?;
    let mut limitations = BTreeSet::new();
    add_strings(&mut limitations, parent.get("limitations"));
    add_strings(&mut limitations, report.get("limitations"));
    let mut unknowns = vec!["Runtime behavior and unread bytes remain unknown.".to_owned()];
    if report["coverage"]["status"] == "partial" {
        unknowns.push(
            "Source inspection is partial; an exhausted page does not establish absence."
                .to_owned(),
        );
    }
    Ok(json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": report["root"]["path"], "sha256": report["root"]["snapshot_sha256"]},
        "limitations": limitations.into_iter().collect::<Vec<_>>(),
        "unknowns": unknowns,
    }))
}

fn summary(report: &Value, shared: Value) -> Result<Value, Failure> {
    let files = array(report, "files")?;
    let mut paths = BTreeMap::new();
    let mut probe_issues = json!({
        "file_count": 0,
        "issue_count": 0,
        "preview": [],
        "preview_truncated": false,
    });
    for file in files {
        let id = string(file, "file_id")?;
        paths.insert(id.to_owned(), string(file, "path")?.to_owned());
        let issues = array(file, "issues")?;
        if issues.is_empty() {
            continue;
        }
        probe_issues["file_count"] = json!(probe_issues["file_count"].as_u64().unwrap_or(0) + 1);
        probe_issues["issue_count"] =
            json!(probe_issues["issue_count"].as_u64().unwrap_or(0) + issues.len() as u64);
        let preview = probe_issues["preview"]
            .as_array_mut()
            .expect("preview is initialized as an array");
        if preview.len() < DIAGNOSTIC_PREVIEW_FILES {
            let path_preview = text_preview(string(file, "path")?);
            let issue = issues[0]
                .as_str()
                .ok_or_else(|| invalid("file issue must be a string"))?;
            let issue_preview = text_preview(issue);
            preview.push(json!({
                "file_id": id,
                "path_preview": path_preview.0,
                "read_status": file["read_status"],
                "issue_count": issues.len(),
                "first_issue_preview": issue_preview.0,
                "text_truncated": path_preview.1 || issue_preview.1,
            }));
        }
    }
    probe_issues["preview_truncated"] = json!(
        probe_issues["file_count"].as_u64().unwrap_or(0)
            > probe_issues["preview"].as_array().map_or(0, Vec::len) as u64
    );

    let candidates = summarize_basis(array(report, "candidates")?, &paths)?;
    let components = summarize_basis(array(report, "components")?, &paths)?;
    let next_probe_groups = group_probes(array(report, "next_probes")?);
    let summary = json!({
        "root": report["root"],
        "source_coverage": report["coverage"],
        "available_counts": {
            "files": files.len(), "omissions": array(report, "omissions")?.len(),
            "candidates": array(report, "candidates")?.len(), "components": array(report, "components")?.len(),
            "next_probes": array(report, "next_probes")?.len(),
        },
        "probe_issues": probe_issues,
        "candidates": candidates,
        "components": components,
        "next_probe_groups": next_probe_groups,
    });
    let mut output = json!({"kind":"summary", "view":{"kind":"summary"}, "summary":summary, "coverage":complete_coverage(files.len())});
    merge_shared(&mut output, shared);
    Ok(output)
}

fn collection_page(
    report: &Value,
    request: CollectionRequest,
    shared: Value,
) -> Result<Value, Failure> {
    let source = array(report, &request.collection)?;
    let mut rows = source.clone();
    if request.paths.is_some()
        || request.ids.is_some()
        || request.has_issues.is_some()
        || request.families.is_some()
    {
        rows.retain(|row| matches_filters(row, &request));
    }
    let id_field = match request.collection.as_str() {
        "files" => "file_id",
        "omissions" => "omission_id",
        "candidates" => "candidate_id",
        "components" => "component_id",
        "next_probes" => "probe_id",
        _ => unreachable!(),
    };
    let fields = request.fields.map(|values| {
        let mut selected = values.into_iter().collect::<BTreeSet<_>>();
        selected.insert(id_field.to_owned());
        selected
    });
    let items = rows
        .iter()
        .skip(request.offset)
        .take(request.limit)
        .map(|row| project_fields(row, fields.as_ref()))
        .collect::<Vec<_>>();
    let examined = items.len();
    let mut output = json!({
        "kind":"desktop-application", "view": {"kind":"desktop-application", "collection":request.collection, "offset":request.offset, "limit":request.limit},
        "source_coverage": report["coverage"], "items": items,
        "coverage": page_coverage(request.offset, examined, rows.len()),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn matches_filters(row: &Value, request: &CollectionRequest) -> bool {
    let path_match = request
        .paths
        .as_ref()
        .map_or(true, |paths| paths.iter().any(|path| row["path"] == *path));
    let id_field = if request.collection == "files" {
        "file_id"
    } else {
        "omission_id"
    };
    let id_match = request
        .ids
        .as_ref()
        .map_or(true, |ids| ids.iter().any(|id| row[id_field] == *id));
    let issue_match = request.has_issues.map_or(true, |expected| {
        row["issues"]
            .as_array()
            .map_or(false, |issues| !issues.is_empty())
            == expected
    });
    let family_match = request.families.as_ref().map_or(true, |families| {
        families.iter().any(|family| row["family"] == *family)
    });
    path_match && id_match && issue_match && family_match
}

fn summarize_basis(
    rows: &[Value],
    paths: &BTreeMap<String, String>,
) -> Result<Vec<Value>, Failure> {
    rows.iter()
        .map(|row| {
            let mut result = row
                .as_object()
                .cloned()
                .ok_or_else(|| invalid("desktop summary row must be an object"))?;
            let ids = result
                .remove("basis_file_ids")
                .and_then(|value| value.as_array().cloned())
                .ok_or_else(|| invalid("desktop basis_file_ids is missing"))?;
            result.insert("basis_file_count".into(), json!(ids.len()));
            result.insert(
                "basis_path_preview".into(),
                json!(
                    ids.iter()
                        .take(2)
                        .map(|id| paths
                            .get(id.as_str().unwrap_or_default())
                            .cloned()
                            .unwrap_or_else(|| id.as_str().unwrap_or_default().to_owned()))
                        .collect::<Vec<_>>()
                ),
            );
            Ok(Value::Object(result))
        })
        .collect()
}

fn group_probes(probes: &[Value]) -> Vec<Value> {
    let mut groups = BTreeMap::<String, Value>::new();
    for probe in probes {
        let operation = probe["operation"].as_str().unwrap_or_default().to_owned();
        if let Some(group) = groups.get_mut(&operation) {
            group["count"] = json!(group["count"].as_u64().unwrap_or(0) + 1);
        } else {
            groups.insert(
                operation.clone(),
                json!({"operation":operation,"count":1,"example":probe}),
            );
        }
    }
    groups.into_values().collect()
}

fn project_fields(row: &Value, fields: Option<&BTreeSet<String>>) -> Value {
    match fields {
        None => row.clone(),
        Some(fields) => Value::Object(
            row.as_object()
                .map(|object| {
                    object
                        .iter()
                        .filter(|(key, _)| fields.contains(*key))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect()
                })
                .unwrap_or_default(),
        ),
    }
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let path = body["artifact"]["path"].as_str().map(str::to_owned);
    let limitations = body["limitations"].clone();
    let unsigned = json!({
        "subject": subject, "provider":{"id":"rea-analysis-view","name":"REA analysis view projection","version":"1"},
        "analysis_profile":null, "predicate_type":"rea.analysis-view", "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view}, "raw_result":null,
        "normalized_result":body, "confidence":"derived", "authority":"analyst-inference", "environment":null,
        "limitations":limitations, "relationship_coverage":null,
        "locations":path.map(|path| vec![json!({"kind":"artifact-path","path":path})]).unwrap_or_default(),
        "evidence_links":[record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}

fn text_preview(value: &str) -> (String, bool) {
    let units = value.encode_utf16().collect::<Vec<_>>();
    let mut end = units.len().min(DIAGNOSTIC_PREVIEW_UNITS);
    if end < units.len() && end > 0 && (0xd800..=0xdbff).contains(&units[end - 1]) {
        end -= 1;
    }
    (String::from_utf16_lossy(&units[..end]), end < units.len())
}

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}
fn merge_shared(output: &mut Value, shared: Value) {
    if let (Some(target), Some(source)) = (output.as_object_mut(), shared.as_object()) {
        target.extend(source.clone());
    }
}
fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, Failure> {
    value[field]
        .as_array()
        .ok_or_else(|| invalid(&format!("{field} must be an array")))
}
fn string<'a>(value: &'a Value, field: &str) -> Result<&'a str, Failure> {
    value[field]
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a string")))
}
fn add_strings(set: &mut BTreeSet<String>, value: Option<&Value>) {
    if let Some(values) = value.and_then(Value::as_array) {
        for value in values {
            if let Some(value) = value.as_str() {
                set.insert(value.to_owned());
            }
        }
    }
}
fn string_array(value: Option<&Value>, field: &str) -> Result<Option<Vec<String>>, Failure> {
    value
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| invalid(&format!("{field} must be an array")))
                .and_then(|values| {
                    values
                        .iter()
                        .map(|item| {
                            item.as_str()
                                .map(str::to_owned)
                                .ok_or_else(|| invalid(&format!("{field} must contain strings")))
                        })
                        .collect()
                })
        })
        .transpose()
}
fn nonnegative_usize(value: Option<&Value>, default: u64, field: &str) -> Result<usize, Failure> {
    usize::try_from(value.and_then(Value::as_u64).unwrap_or(default))
        .map_err(|_| invalid(&format!("{field} is too large")))
}
fn require_keys(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    require_keys_subset(object, allowed)?;
    if allowed.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid("desktop view is missing a required field"));
    }
    Ok(())
}
fn require_keys_subset(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid("desktop view contains an unknown field"));
    }
    Ok(())
}
fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Desktop application Evidence input is invalid.".into(),
        false,
        "Provide retained inspect_desktop_application Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}
