//! Artifact graph identity recomputation.
//!
//! Compatibility owner: `domain/artifactIdentity.ts`. Digests use canonical
//! JSON SHA-256 (`digestCanonicalValue`).

use super::canonical::digest_canonical_value;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

const CONTEXT: &str = "Artifact";

/// `artifactIdForContent`.
pub fn artifact_id_for_content(sha256: &str) -> Result<String, AnalysisError> {
    Ok(format!(
        "art_{}",
        digest_canonical_value(&json!({ "sha256": sha256 }), CONTEXT)?
    ))
}

/// `occurrenceIdForLocation`.
pub fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &str,
    entry_kind: &str,
    duplicate_ordinal: Option<usize>,
) -> Result<String, AnalysisError> {
    if logical_path == "." {
        return Ok(format!(
            "occ_{}",
            digest_canonical_value(&json!({ "root": root_artifact_id }), CONTEXT)?
        ));
    }
    let mut object = serde_json::Map::new();
    object.insert("root_artifact_id".into(), json!(root_artifact_id));
    object.insert("logical_path".into(), json!(logical_path));
    object.insert("entry_kind".into(), json!(entry_kind));
    if let Some(ordinal) = duplicate_ordinal {
        object.insert("duplicate_ordinal".into(), json!(ordinal));
    }
    Ok(format!(
        "occ_{}",
        digest_canonical_value(&Value::Object(object), CONTEXT)?
    ))
}

/// `artifactGraphDigest`.
pub fn artifact_graph_digest(
    nodes: &[Value],
    occurrences: &[Value],
    edges: &[Value],
    contradictions: &[Value],
) -> Result<String, AnalysisError> {
    digest_canonical_value(
        &json!({
            "nodes": nodes,
            "occurrences": occurrences,
            "edges": edges,
            "integrity_contradictions": contradictions,
        }),
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
            &json!({ "root_artifact_id": root_artifact_id, "graph_sha256": graph_sha256 }),
            CONTEXT,
        )?
    ))
}

/// `artifactContradictionId`.
pub fn artifact_contradiction_id(
    root_artifact_id: &str,
    logical_path: &str,
    declared_sha256: &str,
    observed_sha256: &str,
) -> Result<String, AnalysisError> {
    Ok(format!(
        "ic_{}",
        digest_canonical_value(
            &json!({
                "root_artifact_id": root_artifact_id,
                "logical_path": logical_path,
                "declared_sha256": declared_sha256,
                "observed_sha256": observed_sha256,
            }),
            CONTEXT,
        )?
    ))
}

/// `artifactEdgeId`.
pub fn artifact_edge_id(edge: &Value, occurrence: &Value) -> Result<String, AnalysisError> {
    Ok(format!(
        "edge_{}",
        digest_canonical_value(
            &json!({
                "parent_artifact_id": edge["parent_artifact_id"],
                "child_artifact_id": occurrence["artifact_id"],
                "relation": edge["relation"],
                "occurrence_id": edge["occurrence_id"],
                "logical_path": occurrence["logical_path"],
            }),
            CONTEXT,
        )?
    ))
}
