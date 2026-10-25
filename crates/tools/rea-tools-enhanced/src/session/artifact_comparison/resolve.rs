//! Resolve an artifact summary view to its retained parent inventory.
//!
//! Compatibility owner: `application/artifacts/ArtifactComparisonEvidence.ts`
//! `resolveArtifactComparisonEvidence`. The native analysis-view projector
//! (`rea_application::analysis_view::project`) is the owner of the summary
//! reprojection that `inspectAnalysisViewValidated` performs in the original.

use super::canonical::type_error;
use rea_application::javascript::graph::json::{self, Json, Obj};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::record::EvidenceRecord;
use rea_mcp::Session;

/// `resolveArtifactComparisonEvidence`.
///
/// A non-`inspect_analysis_view` Evidence passes through unchanged. A summary
/// carrier is validated against its retained parent inventory, and that parent
/// is returned.
pub fn resolve(
    session: &Session,
    evidence: EvidenceRecord,
) -> Result<EvidenceRecord, AnalysisError> {
    let value = json::parse(evidence.raw().get())
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    if value.at("operation").as_str() != Some("inspect_analysis_view") {
        return Ok(evidence);
    }

    let summary = value.at("normalized_result");
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

    let parent_id = summary
        .at("parent_evidence_id")
        .as_str()
        .unwrap_or_default();
    let Some(parent_raw) = session.evidence_raw(parent_id) else {
        return Err(AnalysisError::evidence_reference(
            parent_id.to_owned(),
            "missing",
            "retained complete artifact inventory Evidence",
            None,
        ));
    };

    let parent = EvidenceRecord::parse(&parent_raw)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    let parent_value = json::parse(parent.raw().get())
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    let view: Json = Obj::new().with("kind", "summary").into();
    let reprojected = rea_application::artifacts::inventory_view::project_raw(&parent_value, &view)
        .map_err(|error| type_error(error.to_string()))?;
    let reprojected = EvidenceRecord::parse(&reprojected)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;

    if reprojected.evidence_id() != evidence.evidence_id() {
        return Err(AnalysisError::evidence_integrity(
            "Artifact summary does not match its retained parent inventory.",
        ));
    }

    Ok(parent)
}

/// Minimal structural recognition of the artifact inventory summary carrier.
///
/// The authoritative schema is `artifactInventorySummaryViewResultSchema`; this
/// recognizes its discriminants so a non-summary (or non-artifact) carrier is
/// rejected like the original `safeParse` failure.
fn is_artifact_inventory_summary(summary: &Json) -> bool {
    summary.at("kind").as_str() == Some("summary")
        && matches!(
            summary.at("parent_operation").as_str(),
            Some("inspect_artifact") | Some("inventory_artifact")
        )
        && summary
            .at("parent_evidence_id")
            .as_str()
            .is_some_and(|id| id.starts_with("ev_") && id.len() == 67)
        && !summary.at("summary").is_null()
}
