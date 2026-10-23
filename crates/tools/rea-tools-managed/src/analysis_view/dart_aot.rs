//! Views over retained `inspect_dart_aot` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/dartAotView.ts`.
use crate::common::json::{self, object, spread};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

const POOLS: [&str; 3] = ["package_uris", "dart_uris", "class_like_tokens"];

/// `projectDartAotView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "dart-aot" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Dart AOT Evidence supports summary and string-pool pages.",
        ));
    }
    let report = parent.parse_result("inspect_dart_aot")?;
    let source_pool = report.get("string_pool").unwrap_or(&Value::Null);
    let mut string_pool = json::without(source_pool, &POOLS);
    string_pool.insert(
        "returned_counts".into(),
        json!({
            "package_uris": json::array_at(source_pool, "package_uris").len(),
            "dart_uris": json::array_at(source_pool, "dart_uris").len(),
            "class_like_tokens": json::array_at(source_pool, "class_like_tokens").len(),
        }),
    );
    let string_pool = Value::Object(string_pool);
    let target = report.get("target").unwrap_or(&Value::Null);
    let mut unknowns = vec![
        "String-pool entries are byte-pattern observations, not recovered typed classes or functions.".to_owned(),
        "Counts ending in _at_least remain lower bounds; exhausting returned strings does not establish a complete snapshot inventory.".to_owned(),
    ];
    if !parent.has_subject() {
        unknowns.push(
            "The parent has no recorded subject; its normalized target identity cannot be cross-checked against a subject digest.".to_owned(),
        );
    }
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_dart_aot")),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({
                "path": target.get("path").cloned().unwrap_or(Value::Null),
                "sha256": target.get("sha256").cloned().unwrap_or(Value::Null),
            }),
        ),
        ("limitations", json!(parent.limitations)),
        ("unknowns", json!(unknowns)),
    ];
    let with_shared =
        |entries: Vec<(&'static str, Value)>| object(shared.iter().cloned().chain(entries));
    if kind == "summary" {
        let summary = spread(&report, &json!({ "string_pool": string_pool }));
        return Ok(with_shared(vec![
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("summary", summary),
            ("coverage", complete_within_view(1, 1)),
        ]));
    }
    let collection = json::array_at(
        source_pool,
        json::str_at(view, "collection").unwrap_or_default(),
    );
    let (offset, limit) = offset_limit(view);
    let items = page(collection, offset, limit);
    let examined = items.len();
    let field = |name: &str| report.get(name).cloned().unwrap_or(Value::Null);
    Ok(with_shared(vec![
        ("kind", json!("dart-aot")),
        ("view", view.clone()),
        ("items", Value::Array(items)),
        ("abi", field("abi")),
        ("libapp", field("libapp")),
        ("source_coverage", field("coverage")),
        ("string_pool", string_pool),
        (
            "coverage",
            page_coverage(offset, examined, collection.len()),
        ),
    ]))
}
