//! Views over retained `inspect_wasm_artifact` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/wasmArtifactView.ts`.
use crate::common::json::{self, js_len, object, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, text_page, view_error,
    view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

/// `projectWasmArtifactView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "wasm" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "WASM Evidence supports summary and wasm views.",
        ));
    }
    let report = parent.parse_result("inspect_wasm_artifact")?;
    let artifact = report.get("artifact").unwrap_or(&Value::Null);
    // `wasmArtifactMatchesSubject`.
    let subject = parent.subject;
    let matches = subject.is_object()
        && subject.get("local_path") == artifact.get("path")
        && subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            == artifact.get("sha256")
        && parent.subject_format() == Some("file");
    if !matches {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "WASM parent Evidence subject must identify the report's exact path and SHA-256.",
        ));
    }
    let limitations = unique_sorted(parent.limitations.iter().cloned().chain(json::strings(
        report.get("limitations").unwrap_or(&Value::Null),
    )));
    let mut unknowns = vec![
        "Decoded WAT is not original source. Runtime behavior and network acquisition were not performed.".to_owned(),
    ];
    if json::array_at(&report, "glue")
        .iter()
        .any(|glue| json::str_at(glue, "parse_status") != Some("complete"))
    {
        unknowns.push(
            "Selected glue parsing is incomplete; unmatched references do not establish absence."
                .to_owned(),
        );
    }
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_wasm_artifact")),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({
                "path": artifact.get("path").cloned().unwrap_or(Value::Null),
                "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
            }),
        ),
        ("limitations", json!(limitations)),
        ("unknowns", json!(unknowns)),
    ];
    let with_shared = |entries: Vec<(&'static str, Value)>| {
        object(entries.into_iter().chain(shared.iter().cloned()))
    };
    let count = |name: &str| json::array_at(&report, name).len();
    let field = |name: &str| report.get(name).cloned().unwrap_or(Value::Null);
    if kind == "summary" {
        let wat = report.get("wat").unwrap_or(&Value::Null);
        let total = count("sections") + count("imports") + count("exports");
        let summary = json!({
            "bytes": artifact.get("bytes").cloned().unwrap_or(Value::Null),
            "validation": field("validation"),
            "available_counts": {
                "sections": count("sections"),
                "imports": count("imports"),
                "exports": count("exports"),
                "candidates": count("candidates"),
                "glue": count("glue"),
            },
            "wat": {
                "sha256": wat.get("sha256").cloned().unwrap_or(Value::Null),
                "representation": wat.get("representation").cloned().unwrap_or(Value::Null),
                "code_units": js_len(json::str_at(wat, "text").unwrap_or_default()),
            },
            "tool_profile": field("tool_profile"),
            "runtime_execution": field("runtime_execution"),
            "network_fetch": field("network_fetch"),
            "limitation_count": limitations.len(),
        });
        return Ok(with_shared(vec![
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("summary", summary),
            ("coverage", complete_within_view(total, total)),
        ]));
    }
    let facet = json::str_at(view, "facet").unwrap_or_default();
    let (offset, limit) = offset_limit(view);
    if facet == "tool_profile" {
        if offset != 0 {
            return Err(view_error(
                &["view", "offset"],
                "invalid_value",
                "Singleton tool_profile requires offset 0.",
            ));
        }
        return Ok(with_shared(vec![
            ("kind", json!("wasm")),
            ("view", view.clone()),
            ("item", field("tool_profile")),
            ("coverage", complete_within_view(1, 1)),
        ]));
    }
    if matches!(facet, "wat" | "headers" | "details") {
        let text = if facet == "wat" {
            report
                .get("wat")
                .and_then(|wat| wat.get("text"))
                .and_then(Value::as_str)
                .unwrap_or_default()
        } else {
            json::str_at(&report, facet).unwrap_or_default()
        };
        let (item, coverage) = text_page(text, offset, limit, facet)?;
        return Ok(with_shared(vec![
            ("kind", json!("wasm")),
            ("view", view.clone()),
            ("item", item),
            ("coverage", coverage),
        ]));
    }
    let rows = json::array_at(&report, facet);
    let item = page(rows, offset, limit);
    let examined = item.len();
    Ok(with_shared(vec![
        ("kind", json!("wasm")),
        ("view", view.clone()),
        ("item", Value::Array(item)),
        ("coverage", page_coverage(offset, examined, rows.len())),
    ]))
}
