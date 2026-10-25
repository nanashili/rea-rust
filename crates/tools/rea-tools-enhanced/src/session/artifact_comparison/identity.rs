//! Artifact graph identity recomputation.
//!
//! Compatibility owner: `domain/artifactIdentity.ts`. Digests use canonical
//! JSON SHA-256 (`digestCanonicalValue`).

use super::canonical::digest_canonical_value;
use rea_application::javascript::graph::json::{Json, Obj};
use rea_core::JsString;
use rea_core::analysis_error::AnalysisError;

const CONTEXT: &str = "Artifact";

/// `artifactIdForContent`.
pub fn artifact_id_for_content(sha256: &str) -> Result<String, AnalysisError> {
    Ok(format!(
        "art_{}",
        digest_canonical_value(&Obj::new().with("sha256", sha256).into(), CONTEXT)?
    ))
}

/// `occurrenceIdForLocation`.
pub fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &JsString,
    entry_kind: &JsString,
    duplicate_ordinal: Option<usize>,
) -> Result<String, AnalysisError> {
    if logical_path == &JsString::from(".") {
        return Ok(format!(
            "occ_{}",
            digest_canonical_value(&Obj::new().with("root", root_artifact_id).into(), CONTEXT)?
        ));
    }
    let mut object = Obj::new()
        .with("root_artifact_id", root_artifact_id)
        .with("logical_path", logical_path)
        .with("entry_kind", entry_kind);
    if let Some(ordinal) = duplicate_ordinal {
        object.set("duplicate_ordinal", ordinal);
    }
    Ok(format!(
        "occ_{}",
        digest_canonical_value(&object.into(), CONTEXT)?
    ))
}

/// `artifactGraphDigest`.
pub fn artifact_graph_digest(
    nodes: &[Json],
    occurrences: &[Json],
    edges: &[Json],
    contradictions: &[Json],
) -> Result<String, AnalysisError> {
    digest_canonical_value(
        &Obj::new()
            .with("nodes", Json::Array(nodes.to_vec()))
            .with("occurrences", Json::Array(occurrences.to_vec()))
            .with("edges", Json::Array(edges.to_vec()))
            .with(
                "integrity_contradictions",
                Json::Array(contradictions.to_vec()),
            )
            .into(),
        CONTEXT,
    )
}

/// `artifactManifestId`.
pub fn artifact_manifest_id(
    root_artifact_id: &str,
    graph_sha256: &str,
) -> Result<String, AnalysisError> {
    Ok(format!(
        "agm_{}",
        digest_canonical_value(
            &Obj::new()
                .with("root_artifact_id", root_artifact_id)
                .with("graph_sha256", graph_sha256)
                .into(),
            CONTEXT,
        )?
    ))
}

/// `artifactContradictionId`.
pub fn artifact_contradiction_id(
    root_artifact_id: &str,
    logical_path: &JsString,
    declared_sha256: &str,
    observed_sha256: &str,
) -> Result<String, AnalysisError> {
    Ok(format!(
        "ic_{}",
        digest_canonical_value(
            &Obj::new()
                .with("root_artifact_id", root_artifact_id)
                .with("logical_path", logical_path)
                .with("declared_sha256", declared_sha256)
                .with("observed_sha256", observed_sha256)
                .into(),
            CONTEXT,
        )?
    ))
}

/// `artifactEdgeId`.
pub fn artifact_edge_id(edge: &Json, occurrence: &Json) -> Result<String, AnalysisError> {
    Ok(format!(
        "edge_{}",
        digest_canonical_value(
            &Obj::new()
                .with("parent_artifact_id", edge.at("parent_artifact_id"))
                .with("child_artifact_id", occurrence.at("artifact_id"))
                .with("relation", edge.at("relation"))
                .with("occurrence_id", edge.at("occurrence_id"))
                .with("logical_path", occurrence.at("logical_path"))
                .into(),
            CONTEXT,
        )?
    ))
}
