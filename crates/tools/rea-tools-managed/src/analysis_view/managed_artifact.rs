//! Views over retained `inspect_managed_artifact` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/managedArtifactView.ts`.
use crate::common::json::{self, object, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

/// `managedViewIdentityUnknowns`: token scope and identity limits shared by
/// every managed metadata view.
pub fn identity_unknowns(parent: &Parent<'_>, mvid: &Value) -> Vec<String> {
    let mut unknowns = vec![
        "Metadata tokens are build-local coordinates bound to the recorded artifact SHA-256 and module MVID; this view does not load or execute the assembly.".to_owned(),
    ];
    if !parent.has_subject() {
        unknowns.push(
            "The parent has no recorded subject; its normalized artifact identity cannot be cross-checked against a subject digest.".to_owned(),
        );
    }
    if mvid.is_null() {
        unknowns.push(
            "The module MVID is unknown; tokens cannot establish a cross-observation module match."
                .to_owned(),
        );
    }
    unknowns
}

/// Combined parent and report limitations in canonical order.
pub fn combined_limitations(parent: &Parent<'_>, report: &Value) -> Vec<String> {
    unique_sorted(parent.limitations.iter().cloned().chain(json::strings(
        report.get("limitations").unwrap_or(&Value::Null),
    )))
}

/// `projectManagedArtifactView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "managed" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Managed artifact inspection supports summary and managed views.",
        ));
    }
    let report = parent.parse_result("inspect_managed_artifact")?;
    let artifact = report.get("artifact").cloned().unwrap_or(Value::Null);
    let artifact_sha256 = artifact.get("sha256").cloned().unwrap_or(Value::Null);
    let mvid = report
        .get("module")
        .and_then(|module| module.get("mvid"))
        .cloned()
        .unwrap_or(Value::Null);
    let identity_scope = json!({
        "token_identity": "build-local",
        "requires_artifact_sha256": artifact_sha256,
        "requires_mvid": mvid,
    });
    let mut unknowns = vec![
        "Collection counts and pages cover producer-returned rows; metadata completeness remains the original metadata status and coverage, not an absence claim about unreturned rows.".to_owned(),
    ];
    unknowns.extend(identity_unknowns(parent, &mvid));
    let shared_artifact = json!({
        "path": artifact.get("path").cloned().unwrap_or(Value::Null),
        "sha256": artifact_sha256,
    });
    let limitations = combined_limitations(parent, &report);
    let rows = |name: &str| json::array_at(&report, name).to_vec();
    if kind == "summary" {
        let references = json::array_at(&report, "references").len();
        let resources = json::array_at(&report, "resources").len();
        let attributes = json::array_at(&report, "attributes").len();
        let mut summary = json::without(&report, &["references", "resources", "attributes"]);
        summary.insert(
            "reported_counts".into(),
            json!({ "references": references, "resources": resources, "attributes": attributes }),
        );
        summary.insert("identity_scope".into(), identity_scope);
        let total = references + resources + attributes;
        return Ok(object([
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("parent_evidence_id", json!(parent.evidence_id)),
            ("parent_operation", json!("inspect_managed_artifact")),
            ("parent_digest", json!(parent.digest())),
            ("artifact", shared_artifact),
            ("limitations", json!(limitations)),
            ("unknowns", json!(unknowns)),
            ("summary", Value::Object(summary)),
            ("coverage", complete_within_view(total, total)),
        ]));
    }
    let collection_name = json::str_at(view, "collection").unwrap_or_default();
    let collection = rows(collection_name);
    let (offset, limit) = offset_limit(view);
    let item = page(&collection, offset, limit);
    let examined = item.len();
    Ok(object([
        ("kind", json!("managed")),
        ("view", view.clone()),
        ("item", Value::Array(item)),
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_managed_artifact")),
        ("parent_digest", json!(parent.digest())),
        ("artifact", shared_artifact),
        ("limitations", json!(limitations)),
        ("unknowns", json!(unknowns)),
        ("identity_scope", identity_scope),
        (
            "source_metadata_status",
            report
                .get("metadata")
                .and_then(|metadata| metadata.get("status"))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        (
            "source_coverage",
            report.get("coverage").cloned().unwrap_or(Value::Null),
        ),
        (
            "coverage",
            page_coverage(offset, examined, collection.len()),
        ),
    ]))
}
