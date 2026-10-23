//! Resolve an artifact summary view to its retained parent inventory.
//!
//! Compatibility owner: `application/artifacts/ArtifactComparisonEvidence.ts`
//! `resolveArtifactComparisonEvidence`. The native analysis-view projector
//! (`rea_application::analysis_view::project`) is the owner of the summary
//! reprojection that `inspectAnalysisViewValidated` performs in the original.

use super::canonical::type_error;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::Evidence;
use rea_mcp::Session;
use serde_json::{Value, json};
use std::sync::Arc;

/// `resolveArtifactComparisonEvidence`.
///
/// A non-`inspect_analysis_view` Evidence passes through unchanged. A summary
/// carrier is validated against its retained parent inventory, and that parent
/// is returned.
pub fn resolve(session: &Arc<Session>, evidence: Evidence) -> Result<Evidence, AnalysisError> {
    let value = evidence.value();
    if value["operation"].as_str() != Some("inspect_analysis_view") {
        return Ok(evidence);
    }

    let summary = &value["normalized_result"];
    if !is_artifact_inventory_summary(summary) {
        return Err(AnalysisError::input(
            "compare_artifacts",
            vec![InputIssue::new(
                &["evidence"],
                "invalid_value",
                "Artifact comparison accepts only an artifact inventory summary from inspect_analysis_view.",
            )],
        ));
    }

    let parent_id = summary["parent_evidence_id"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let Some(parent_value) = session.evidence(&parent_id) else {
        return Err(AnalysisError::evidence_reference(
            parent_id,
            "missing",
            "retained complete artifact inventory Evidence",
            None,
        ));
    };

    // inspectAnalysisViewValidated(source: retained parent, view: summary).
    let reprojected =
        rea_application::analysis_view::project(&parent_value, &json!({ "kind": "summary" }))
            .map_err(AnalysisError::from)?;
    let reprojected_value: Value =
        serde_json::from_str(reprojected.get()).map_err(|error| type_error(error.to_string()))?;

    if reprojected_value["evidence_id"].as_str() != Some(evidence.id()) {
        return Err(AnalysisError::evidence_integrity(
            "Artifact summary does not match its retained parent inventory.",
        ));
    }

    Ok(Evidence::from_authenticated(parent_id, parent_value))
}

/// Minimal structural recognition of the artifact inventory summary carrier.
///
/// The authoritative schema is `artifactInventorySummaryViewResultSchema`; this
/// recognizes its discriminants so a non-summary (or non-artifact) carrier is
/// rejected like the original `safeParse` failure.
fn is_artifact_inventory_summary(summary: &Value) -> bool {
    summary["kind"].as_str() == Some("summary")
        && matches!(
            summary["parent_operation"].as_str(),
            Some("inspect_artifact") | Some("inventory_artifact")
        )
        && summary["parent_evidence_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("ev_") && id.len() == 67)
        && summary.get("summary").is_some()
}
