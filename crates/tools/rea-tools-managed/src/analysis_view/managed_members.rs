//! Views over retained `inspect_managed_members` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/managedMemberView.ts`.
use super::managed_artifact::{combined_limitations, identity_unknowns};
use crate::common::json::{self, object};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

const COLLECTIONS: [&str; 8] = [
    "types",
    "exported_types",
    "fields",
    "methods",
    "member_refs",
    "call_edges",
    "field_accesses",
    "user_strings",
];

/// Rows of one collection; `None` when the parent never examined it.
fn collection_rows<'a>(report: &'a Value, collection: &str) -> Option<&'a [Value]> {
    let rows = if collection == "user_strings" {
        report.get("user_strings")?.get("literals")?
    } else {
        report.get(collection)?
    };
    rows.as_array().map(Vec::as_slice)
}

/// `summarizeMembers`: everything but the member collections, replaced by counts.
fn summarize(report: &Value) -> (Map<String, Value>, usize) {
    let mut summary = json::without(report, &COLLECTIONS);
    let user_strings = report.get("user_strings").unwrap_or(&Value::Null);
    let summary_user_strings = if user_strings.is_object() {
        json!({
            "state": user_strings.get("state").cloned().unwrap_or(Value::Null),
            "issues": user_strings.get("issues").cloned().unwrap_or(Value::Null),
        })
    } else {
        Value::Null
    };
    let count = |name: &str| json::array_at(report, name).len();
    let exported = report
        .get("exported_types")
        .and_then(Value::as_array)
        .map(Vec::len);
    let literals = user_strings
        .get("literals")
        .and_then(Value::as_array)
        .map(Vec::len);
    let counts = [
        ("types", Some(count("types"))),
        ("exported_types", exported),
        ("fields", Some(count("fields"))),
        ("methods", Some(count("methods"))),
        ("member_refs", Some(count("member_refs"))),
        ("call_edges", Some(count("call_edges"))),
        ("field_accesses", Some(count("field_accesses"))),
        ("user_strings", literals),
    ];
    let total = counts.iter().map(|(_, count)| count.unwrap_or(0)).sum();
    let mut reported = Map::new();
    for (name, count) in counts {
        reported.insert(name.into(), count.map_or(Value::Null, Value::from));
    }
    // Spread order: identity fields keep their place; user_strings is replaced.
    let mut ordered = Map::new();
    for (key, value) in std::mem::take(&mut summary) {
        ordered.insert(key, value);
    }
    ordered.insert("user_strings".into(), summary_user_strings);
    ordered.insert("reported_counts".into(), Value::Object(reported));
    (ordered, total)
}

/// `projectManagedMemberView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "managed-members" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Managed member inspection supports summary and managed-members views.",
        ));
    }
    let report = parent.parse_result("inspect_managed_members")?;
    let artifact = report.get("artifact").cloned().unwrap_or(Value::Null);
    let identity_scope = report.get("identity_scope").cloned().unwrap_or(Value::Null);
    let selection = report.get("selection").cloned().unwrap_or(Value::Null);
    let mut unknowns = vec![
        "Collection counts and pages cover producer-returned rows; member completeness remains the original coverage, not an absence claim about unreturned rows.".to_owned(),
    ];
    if !selection.is_null() {
        unknowns.push(
            "Exported types and member references cover the whole assembly; the other collections cover only the selected declaring types.".to_owned(),
        );
    }
    unknowns.extend(identity_unknowns(
        parent,
        identity_scope.get("requires_mvid").unwrap_or(&Value::Null),
    ));
    let shared_artifact = json!({
        "path": artifact.get("path").cloned().unwrap_or(Value::Null),
        "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
    });
    let limitations = combined_limitations(parent, &report);
    if kind == "summary" {
        let (summary, total) = summarize(&report);
        return Ok(object([
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("parent_evidence_id", json!(parent.evidence_id)),
            ("parent_operation", json!("inspect_managed_members")),
            ("parent_digest", json!(parent.digest())),
            ("artifact", shared_artifact),
            ("limitations", json!(limitations)),
            ("unknowns", json!(unknowns)),
            ("summary", Value::Object(summary)),
            ("coverage", complete_within_view(total, total)),
        ]));
    }
    let collection = json::str_at(view, "collection")
        .unwrap_or_default()
        .to_owned();
    let Some(rows) = collection_rows(&report, &collection) else {
        return Err(view_error(
            &["view", "collection"],
            "invalid_value",
            format!(
                "The parent Evidence did not examine {collection}; repeat inspect_managed_members with the current runtime to record it."
            ),
        ));
    };
    let (offset, limit) = offset_limit(view);
    let selected = page(rows, offset, limit);
    let examined = selected.len();
    let total = rows.len();
    let user_strings = report.get("user_strings").unwrap_or(&Value::Null);
    let source_coverage = if collection == "user_strings" && user_strings.is_object() {
        json!({
            "state": user_strings.get("state").cloned().unwrap_or(Value::Null),
            "issues": user_strings.get("issues").cloned().unwrap_or(Value::Null),
        })
    } else {
        report.get("coverage").cloned().unwrap_or(Value::Null)
    };
    Ok(object([
        ("kind", json!("managed-members")),
        ("view", view.clone()),
        (
            "page",
            json!({ "collection": collection, "rows": Value::Array(selected) }),
        ),
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_managed_members")),
        ("parent_digest", json!(parent.digest())),
        ("artifact", shared_artifact),
        ("limitations", json!(limitations)),
        ("unknowns", json!(unknowns)),
        (
            "signature_resolution",
            report
                .get("signature_resolution")
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "nesting_read",
            report.get("nesting_read").cloned().unwrap_or(Value::Null),
        ),
        ("identity_scope", identity_scope),
        ("selection", selection),
        (
            "source_metadata_status",
            report
                .get("metadata")
                .and_then(|metadata| metadata.get("status"))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        ("source_coverage", source_coverage),
        ("coverage", page_coverage(offset, examined, total)),
    ]))
}
