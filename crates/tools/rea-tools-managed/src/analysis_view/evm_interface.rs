//! Views over retained `inspect_evm_interface` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/evmInterfaceView.ts`.
use crate::common::json::{self, js_len, object, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, text_page, view_error,
    view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

/// `projectEvmInterfaceView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "evm" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "EVM Evidence supports summary and evm views.",
        ));
    }
    let report = parent.parse_result("inspect_evm_interface")?;
    let artifact = report.get("artifact").unwrap_or(&Value::Null);
    let subject = parent.subject;
    if !subject.is_object()
        || parent.subject_format() != Some("file")
        || subject.get("local_path") != artifact.get("path")
        || subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            != artifact.get("sha256")
    {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "EVM parent subject must identify the report's exact carrier path and SHA-256.",
        ));
    }
    let limitations = unique_sorted(parent.limitations.iter().cloned().chain(json::strings(
        report.get("limitations").unwrap_or(&Value::Null),
    )));
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_evm_interface")),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({
                "path": artifact.get("path").cloned().unwrap_or(Value::Null),
                "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
            }),
        ),
        ("limitations", json!(limitations)),
        (
            "unknowns",
            json!([
                "Candidates remain inferred; discovery completeness, bytecode kind, hardfork and deployment authenticity are unknown. Runtime execution was not performed."
            ]),
        ),
    ];
    let with_shared = |entries: Vec<(&'static str, Value)>| {
        object(entries.into_iter().chain(shared.iter().cloned()))
    };
    let field = |name: &str| report.get(name).cloned().unwrap_or(Value::Null);
    let functions = json::array_at(&report, "functions");
    let bytecode = report.get("bytecode").unwrap_or(&Value::Null);
    let diagnostics = report.get("diagnostics").unwrap_or(&Value::Null);
    if kind == "summary" {
        let mut summary_diagnostics = json::without(diagnostics, &["stdout"]);
        summary_diagnostics.insert(
            "stdout_code_units".into(),
            json!(js_len(
                json::str_at(diagnostics, "stdout").unwrap_or_default()
            )),
        );
        let summary = json!({
            "artifact": field("artifact"),
            "bytecode": json::without(bytecode, &["hex"]),
            "evidence_kind": field("evidence_kind"),
            "functions": functions,
            "discovery_completeness": field("discovery_completeness"),
            "runtime_execution": field("runtime_execution"),
            "diagnostics": summary_diagnostics,
            "limitations": field("limitations"),
        });
        return Ok(with_shared(vec![
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("summary", summary),
            (
                "coverage",
                complete_within_view(functions.len(), functions.len()),
            ),
        ]));
    }
    let facet = json::str_at(view, "facet").unwrap_or_default();
    let (offset, limit) = offset_limit(view);
    if facet == "functions" {
        let item = page(functions, offset, limit);
        let examined = item.len();
        return Ok(with_shared(vec![
            ("kind", json!("evm")),
            ("view", view.clone()),
            ("item", Value::Array(item)),
            ("coverage", page_coverage(offset, examined, functions.len())),
        ]));
    }
    let text = if facet == "bytecode_hex" {
        json::str_at(bytecode, "hex")
    } else {
        json::str_at(diagnostics, facet)
    }
    .unwrap_or_default();
    let (item, coverage) = text_page(text, offset, limit, facet)?;
    Ok(with_shared(vec![
        ("kind", json!("evm")),
        ("view", view.clone()),
        ("item", item),
        ("coverage", coverage),
    ]))
}
