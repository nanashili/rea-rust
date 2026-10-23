//! Views over retained `inspect_desktop_application` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/desktopApplicationView.ts`.
use crate::common::json;
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::HashSet;

// Bound diagnostic context independently of the retained report size. Previews
// are display values; stable file IDs select the original paths and all issues.
const DIAGNOSTIC_PREVIEW_FILES: usize = 2;
const DIAGNOSTIC_PREVIEW_UNITS: usize = 256;

/// `file.issues.length > 0`.
fn has_probe_issues(file: &Value) -> bool {
    !json::array_at(file, "issues").is_empty()
}

/// `diagnosticTextPreview`: first `DIAGNOSTIC_PREVIEW_UNITS` UTF-16 units,
/// never splitting a surrogate pair.
fn diagnostic_text_preview(value: &str) -> (String, bool) {
    let units: Vec<u16> = value.encode_utf16().collect();
    let length = units.len();
    let mut end = length.min(DIAGNOSTIC_PREVIEW_UNITS);
    if end > 0 && end < length {
        let last = units[end - 1];
        if (0xd800..=0xdbff).contains(&last) {
            end -= 1;
        }
    }
    (String::from_utf16_lossy(&units[..end]), end < length)
}

/// The stable identity field for each collection.
fn id_field(collection: &str) -> &'static str {
    match collection {
        "files" => "file_id",
        "omissions" => "omission_id",
        "candidates" => "candidate_id",
        "components" => "component_id",
        "next_probes" => "probe_id",
        _ => "",
    }
}

/// `projectDesktopApplicationView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "desktop-application" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Desktop directory Evidence supports summary and desktop-application views.",
        ));
    }
    let report = parent.parse_result("inspect_desktop_application")?;

    let root = report.get("root").cloned().unwrap_or(Value::Null);
    let root_path = root.get("path").and_then(Value::as_str);
    let root_snapshot = root.get("snapshot_sha256").and_then(Value::as_str);
    let subject = parent.subject;
    let subject_ok = subject.is_object()
        && subject.get("format").and_then(Value::as_str) == Some("directory")
        && subject.get("local_path").and_then(Value::as_str) == root_path
        && subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            .and_then(Value::as_str)
            == root_snapshot;
    if !subject_ok {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "Parent must identify the same examined directory snapshot.",
        ));
    }

    // `[...new Set([...])]`: first-seen order, not sorted.
    let mut limitations: Vec<String> = Vec::new();
    for limitation in parent.limitations.iter().cloned().chain(json::strings(
        report.get("limitations").unwrap_or(&Value::Null),
    )) {
        if !limitations.contains(&limitation) {
            limitations.push(limitation);
        }
    }
    let coverage_status = report
        .get("coverage")
        .and_then(|coverage| coverage.get("status"))
        .and_then(Value::as_str);
    let mut unknowns = vec!["Runtime behavior and unread bytes remain unknown.".to_owned()];
    if coverage_status == Some("partial") {
        unknowns.push(
            "Source inspection is partial; an exhausted page does not establish absence."
                .to_owned(),
        );
    }
    let shared_artifact = json!({
        "path": root_path,
        "sha256": root_snapshot,
    });
    // Shared fields inserted in TS object-spread order.
    let shared = |map: &mut Map<String, Value>| {
        map.insert("parent_evidence_id".into(), json!(parent.evidence_id));
        map.insert(
            "parent_operation".into(),
            json!("inspect_desktop_application"),
        );
        map.insert("parent_digest".into(), json!(parent.digest()));
        map.insert("artifact".into(), shared_artifact.clone());
        map.insert("limitations".into(), json!(limitations));
        map.insert("unknowns".into(), json!(unknowns));
    };

    let files = json::array_at(&report, "files");

    if kind == "summary" {
        // byId maps file_id -> path during the single pass over files.
        let mut by_id: std::collections::HashMap<String, String> = std::collections::HashMap::new();
        let mut file_count = 0u64;
        let mut issue_count = 0u64;
        let mut preview: Vec<Value> = Vec::new();
        for file in files {
            if let (Some(id), Some(path)) = (
                file.get("file_id").and_then(Value::as_str),
                file.get("path").and_then(Value::as_str),
            ) {
                by_id.insert(id.to_owned(), path.to_owned());
            }
            if !has_probe_issues(file) {
                continue;
            }
            let issues = json::array_at(file, "issues");
            file_count += 1;
            issue_count += issues.len() as u64;
            if preview.len() == DIAGNOSTIC_PREVIEW_FILES {
                continue;
            }
            let Some(first_issue) = issues.first().and_then(Value::as_str) else {
                continue;
            };
            let (path_text, path_trunc) =
                diagnostic_text_preview(file.get("path").and_then(Value::as_str).unwrap_or(""));
            let (issue_text, issue_trunc) = diagnostic_text_preview(first_issue);
            preview.push(json!({
                "file_id": file.get("file_id").cloned().unwrap_or(Value::Null),
                "path_preview": path_text,
                "read_status": file.get("read_status").cloned().unwrap_or(Value::Null),
                "issue_count": issues.len(),
                "first_issue_preview": issue_text,
                "text_truncated": path_trunc || issue_trunc,
            }));
        }
        let preview_truncated = file_count > preview.len() as u64;
        let probe_issues = json!({
            "file_count": file_count,
            "issue_count": issue_count,
            "preview": preview,
            "preview_truncated": preview_truncated,
        });

        let summarize_basis = |row: &Value| -> Value {
            let basis = json::array_at(row, "basis_file_ids");
            let mut value = json::without(row, &["basis_file_ids"]);
            let preview: Vec<Value> = basis
                .iter()
                .take(2)
                .map(|id| match id.as_str() {
                    Some(id) => {
                        Value::String(by_id.get(id).cloned().unwrap_or_else(|| id.to_owned()))
                    }
                    None => id.clone(),
                })
                .collect();
            value.insert("basis_file_count".into(), json!(basis.len()));
            value.insert("basis_path_preview".into(), Value::Array(preview));
            Value::Object(value)
        };
        let candidates: Vec<Value> = json::array_at(&report, "candidates")
            .iter()
            .map(summarize_basis)
            .collect();
        let components: Vec<Value> = json::array_at(&report, "components")
            .iter()
            .map(summarize_basis)
            .collect();

        // Group next_probes by operation preserving first-seen order.
        let mut group_order: Vec<String> = Vec::new();
        let mut group_count: std::collections::HashMap<String, u64> =
            std::collections::HashMap::new();
        let mut group_example: std::collections::HashMap<String, Value> =
            std::collections::HashMap::new();
        for probe in json::array_at(&report, "next_probes") {
            let operation = probe
                .get("operation")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            match group_count.get_mut(&operation) {
                Some(count) => *count += 1,
                None => {
                    group_order.push(operation.clone());
                    group_count.insert(operation.clone(), 1);
                    group_example.insert(operation.clone(), probe.clone());
                }
            }
        }
        let next_probe_groups: Vec<Value> = group_order
            .iter()
            .map(|operation| {
                json!({
                    "operation": operation,
                    "count": group_count.get(operation).copied().unwrap_or(0),
                    "example": group_example.get(operation).cloned().unwrap_or(Value::Null),
                })
            })
            .collect();

        let mut summary = Map::new();
        summary.insert("root".into(), root);
        summary.insert(
            "source_coverage".into(),
            report.get("coverage").cloned().unwrap_or(Value::Null),
        );
        summary.insert(
            "available_counts".into(),
            json!({
                "files": files.len(),
                "omissions": json::array_at(&report, "omissions").len(),
                "candidates": json::array_at(&report, "candidates").len(),
                "components": json::array_at(&report, "components").len(),
                "next_probes": json::array_at(&report, "next_probes").len(),
            }),
        );
        summary.insert("probe_issues".into(), probe_issues);
        summary.insert("candidates".into(), Value::Array(candidates));
        summary.insert("components".into(), Value::Array(components));
        summary.insert("next_probe_groups".into(), Value::Array(next_probe_groups));

        let mut out = Map::new();
        out.insert("kind".into(), json!("summary"));
        out.insert("view".into(), view.clone());
        shared(&mut out);
        out.insert("summary".into(), Value::Object(summary));
        out.insert(
            "coverage".into(),
            complete_within_view(files.len(), files.len()),
        );
        return Ok(Value::Object(out));
    }

    // desktop-application page view.
    let collection = json::str_at(view, "collection")
        .unwrap_or_default()
        .to_owned();
    let all_rows = json::array_at(&report, &collection);
    let mut rows: Vec<Value> = all_rows.to_vec();

    if collection == "files" || collection == "omissions" {
        let paths: Option<HashSet<String>> = view
            .get("paths")
            .map(|v| json::strings(v).into_iter().collect());
        let ids: Option<HashSet<String>> = {
            let key = if collection == "files" {
                "file_ids"
            } else {
                "omission_ids"
            };
            view.get(key)
                .map(|v| json::strings(v).into_iter().collect())
        };
        let with_issues: Option<bool> = if collection == "files" {
            view.get("has_issues").and_then(Value::as_bool)
        } else {
            None
        };
        if paths.is_some() || ids.is_some() || with_issues.is_some() {
            rows = all_rows
                .iter()
                .filter(|row| {
                    let path_ok = match &paths {
                        Some(set) => row
                            .get("path")
                            .and_then(Value::as_str)
                            .is_some_and(|p| set.contains(p)),
                        None => true,
                    };
                    let id_ok = match &ids {
                        Some(set) => {
                            let id_key = if row.get("file_id").is_some() {
                                "file_id"
                            } else {
                                "omission_id"
                            };
                            row.get(id_key)
                                .and_then(Value::as_str)
                                .is_some_and(|id| set.contains(id))
                        }
                        None => true,
                    };
                    let issue_ok = match with_issues {
                        Some(flag) => row.get("issues").is_some() && has_probe_issues(row) == flag,
                        None => true,
                    };
                    path_ok && id_ok && issue_ok
                })
                .cloned()
                .collect();
        }
    }

    if collection == "candidates"
        && let Some(families) = view.get("families")
    {
        let selected: HashSet<String> = json::strings(families).into_iter().collect();
        rows = all_rows
            .iter()
            .filter(|row| {
                row.get("family")
                    .and_then(Value::as_str)
                    .is_some_and(|family| selected.contains(family))
            })
            .cloned()
            .collect();
    }

    let fields: Option<HashSet<String>> = view.get("fields").map(|v| {
        let mut set: HashSet<String> = HashSet::new();
        set.insert(id_field(&collection).to_owned());
        set.extend(json::strings(v));
        set
    });

    let (offset, limit) = offset_limit(view);
    let selected = page(&rows, offset, limit);
    let examined = selected.len();
    let items: Vec<Value> = selected
        .into_iter()
        .map(|row| match &fields {
            None => row,
            Some(set) => {
                let mut filtered = Map::new();
                if let Some(object) = row.as_object() {
                    for (key, value) in object {
                        if set.contains(key.as_str()) {
                            filtered.insert(key.clone(), value.clone());
                        }
                    }
                }
                Value::Object(filtered)
            }
        })
        .collect();

    let mut out = Map::new();
    out.insert("kind".into(), json!("desktop-application"));
    out.insert("view".into(), view.clone());
    shared(&mut out);
    out.insert(
        "source_coverage".into(),
        report.get("coverage").cloned().unwrap_or(Value::Null),
    );
    out.insert("items".into(), Value::Array(items));
    out.insert(
        "coverage".into(),
        page_coverage(offset, examined, rows.len()),
    );
    Ok(Value::Object(out))
}
