//! Views over retained `inspect_android_package` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/androidPackageView.ts`.
use crate::common::json::{self, js_len, object, spread};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, text_page, view_error, view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

/// `projectAndroidPackageView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary" && kind != "android" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Android package Evidence supports summary and manifest views.",
        ));
    }
    let report = parent.parse_result("inspect_android_package")?;
    // Engine artifact_sha256 identifies the JAR, never the APK. A missing
    // authenticated APK subject cannot be repaired using the engine identity.
    if !parent.has_subject() {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "Android package views require the recorded APK subject identity.",
        ));
    }
    let manifest = report.get("manifest").unwrap_or(&Value::Null);
    let status = manifest.get("status").cloned().unwrap_or(Value::Null);
    let mut unknowns = vec![
        "APK signatures were not verified; package declarations do not establish authenticity or runtime behavior.".to_owned(),
    ];
    if status.as_str() == Some("partial") {
        unknowns.push(
            "The decoded manifest is partial; exhausting retained text does not establish complete manifest coverage.".to_owned(),
        );
    }
    let shared = [
        ("parent_evidence_id", json!(parent.evidence_id)),
        ("parent_operation", json!("inspect_android_package")),
        ("parent_digest", json!(parent.digest())),
        (
            "artifact",
            json!({
                "path": parent.subject.get("local_path").cloned().unwrap_or(Value::Null),
                "sha256": parent
                    .subject
                    .get("digest")
                    .and_then(|digest| digest.get("sha256"))
                    .cloned()
                    .unwrap_or(Value::Null),
            }),
        ),
        ("limitations", json!(parent.limitations)),
        ("unknowns", json!(unknowns)),
    ];
    let with_shared =
        |entries: Vec<(&'static str, Value)>| object(shared.iter().cloned().chain(entries));
    let text = json::str_at(manifest, "text").unwrap_or_default();
    if kind == "summary" {
        let mut summary_manifest = json::without(manifest, &["text"]);
        summary_manifest.insert("text_code_units".into(), json!(js_len(text)));
        summary_manifest.insert("text_included".into(), json!(false));
        let summary = spread(&report, &json!({ "manifest": summary_manifest }));
        return Ok(with_shared(vec![
            ("kind", json!("summary")),
            ("view", view.clone()),
            ("summary", summary),
            ("coverage", complete_within_view(1, 1)),
        ]));
    }
    let (offset, limit) = offset_limit(view);
    let (item, coverage) = text_page(text, offset, limit, "Manifest")?;
    let item = spread(
        &item,
        &json!({
            "source_status": status,
            "reported_total_bytes": manifest.get("reported_total_bytes").cloned().unwrap_or(Value::Null),
        }),
    );
    Ok(with_shared(vec![
        ("kind", json!("android")),
        ("view", view.clone()),
        ("item", item),
        ("coverage", coverage),
    ]))
}
