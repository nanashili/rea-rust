//! Artifact graph domain types, identity digests and canonical ordering.
//!
//! Compatibility owners: `src/domain/artifactGraph.ts`,
//! `src/domain/artifactIdentity.ts`, `src/domain/canonicalDigest.ts`
//! (digest context is error-message-only; the hashed bytes are the canonical
//! JSON of the value), `src/domain/canonicalOrdering.ts` and
//! `src/domain/unicodeCodePointOrder.ts`.
use rea_core::canonical_json;
use serde::Serialize;
use serde_json::{Value, json};

/// One content-addressed application artifact.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactNode {
    pub artifact_id: String,
    pub format: String,
    pub sha256: String,
    pub size: u64,
    pub media_type: Option<String>,
    pub architecture: Option<String>,
    pub content_state: String,
    pub limitations: Vec<String>,
}

/// One path or virtual location where an artifact occurs in its parent.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactOccurrence {
    pub occurrence_id: String,
    pub artifact_id: Option<String>,
    pub parent_occurrence_id: Option<String>,
    pub logical_path: String,
    pub entry_kind: String,
    pub artifact_kind: String,
    pub artifact_format: String,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub hash_status: String,
    pub source_location: Option<Value>,
    pub limitations: Vec<String>,
}

/// Observed bytes contradicting a container's declared integrity identity.
#[derive(Clone, Debug, Serialize)]
pub struct IntegrityContradiction {
    pub contradiction_id: String,
    pub occurrence_id: String,
    pub parent_artifact_id: String,
    pub logical_path: String,
    pub declared_sha256: String,
    pub observed_sha256: String,
    pub entry_kind: String,
    pub unpacked: bool,
    pub trust: String,
    pub provenance: String,
    pub limitations: Vec<String>,
}

/// Parent-child derivation relation between two content-addressed artifacts.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactEdge {
    pub edge_id: String,
    pub ordinal: u64,
    pub parent_artifact_id: String,
    pub relation: String,
    pub occurrence_id: String,
    pub producer: Option<Value>,
}

/// Stable commitment and counts for a complete artifact graph.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactGraphManifest {
    pub manifest_id: String,
    pub root_artifact_id: String,
    pub root_sha256: String,
    pub root_format: String,
    pub graph_sha256: String,
    pub node_count: u64,
    pub occurrence_count: u64,
    pub edge_count: u64,
}

/// Producer-owned traversal coverage.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactInventoryCoverage {
    pub scope: String,
    pub status: String,
}

/// Current inventory observation containing the stable artifact graph.
#[derive(Clone, Debug, Serialize)]
pub struct ArtifactInventoryResult {
    pub manifest: ArtifactGraphManifest,
    pub nodes: Vec<ArtifactNode>,
    pub occurrences: Vec<ArtifactOccurrence>,
    pub edges: Vec<ArtifactEdge>,
    pub provenance: Vec<Value>,
    pub integrity_contradictions: Vec<IntegrityContradiction>,
    pub coverage: ArtifactInventoryCoverage,
    pub limitations: Vec<String>,
}

/// Digest context panic guard: canonicalization of our owned, finite JSON
/// values cannot fail. Mirrors TS `digestCanonicalValue` throwing on the
/// unreachable non-finite/circular cases.
fn digest<T: Serialize>(value: &T) -> String {
    canonical_json::digest(value).expect("owned artifact values canonicalize")
}

/// `logicalPathNfc`. Rust has no built-in NFC normalizer; artifact logical
/// paths are produced from already-normalized UTF-8 names, so the identity
/// transform is the string itself. Non-NFC inputs are rejected earlier at the
/// path boundary.
pub fn logical_path_nfc(value: &str) -> String {
    value.to_owned()
}

/// `artifactIdForContent`.
pub fn artifact_id_for_content(sha256: &str) -> String {
    format!("art_{}", digest(&json!({ "sha256": sha256 })))
}

/// `occurrenceIdForLocation`.
pub fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &str,
    entry_kind: &str,
    duplicate_ordinal: Option<u64>,
) -> String {
    if logical_path == "." {
        return format!("occ_{}", digest(&json!({ "root": root_artifact_id })));
    }
    let semantic = match duplicate_ordinal {
        None => json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": logical_path,
            "entry_kind": entry_kind,
        }),
        Some(ordinal) => json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": logical_path,
            "entry_kind": entry_kind,
            "duplicate_ordinal": ordinal,
        }),
    };
    format!("occ_{}", digest(&semantic))
}

/// `artifactGraphDigest`.
pub fn artifact_graph_digest(
    nodes: &[ArtifactNode],
    occurrences: &[ArtifactOccurrence],
    edges: &[ArtifactEdge],
    contradictions: &[IntegrityContradiction],
) -> String {
    digest(&json!({
        "nodes": nodes,
        "occurrences": occurrences,
        "edges": edges,
        "integrity_contradictions": contradictions,
    }))
}

/// `artifactManifestId`.
pub fn artifact_manifest_id(root_artifact_id: &str, graph_sha256: &str) -> String {
    format!(
        "agm_{}",
        digest(&json!({
            "root_artifact_id": root_artifact_id,
            "graph_sha256": graph_sha256,
        }))
    )
}

/// `artifactContradictionId`.
pub fn artifact_contradiction_id(
    root_artifact_id: &str,
    logical_path: &str,
    declared_sha256: &str,
    observed_sha256: &str,
) -> String {
    format!(
        "ic_{}",
        digest(&json!({
            "root_artifact_id": root_artifact_id,
            "logical_path": logical_path,
            "declared_sha256": declared_sha256,
            "observed_sha256": observed_sha256,
        }))
    )
}

/// `artifactEdgeId`.
pub fn artifact_edge_id(
    parent_artifact_id: &str,
    child_artifact_id: Option<&str>,
    relation: &str,
    occurrence_id: &str,
    logical_path: &str,
) -> String {
    format!(
        "edge_{}",
        digest(&json!({
            "parent_artifact_id": parent_artifact_id,
            "child_artifact_id": child_artifact_id,
            "relation": relation,
            "occurrence_id": occurrence_id,
            "logical_path": logical_path,
        }))
    )
}

/// Pre-rekey occurrence id over `{ path, kind }` (plus duplicate ordinal).
/// Mirrors `createOccurrence`'s provisional id.
pub fn provisional_occurrence_id(path: &str, kind: &str, duplicate_ordinal: u64) -> String {
    let semantic = if duplicate_ordinal == 0 {
        json!({ "path": path, "kind": kind })
    } else {
        json!({ "path": path, "kind": kind, "duplicate_ordinal": duplicate_ordinal })
    };
    format!("occ_{}", digest(&semantic))
}

/// Directory node digest over `{ kind: "directory", children }`.
pub fn directory_node_sha256(children: &Value) -> String {
    digest(&json!({ "kind": "directory", "children": children }))
}

/// Root directory node digest over `{ kind: "directory-root", children }`.
pub fn directory_root_sha256(children: &Value) -> String {
    digest(&json!({ "kind": "directory-root", "children": children }))
}

/// Digest any serializable value (used by extraction `files_sha256` and the
/// extraction manifest id).
pub fn digest_value<T: Serialize>(value: &T) -> String {
    digest(value)
}

/// `compareUnicodeCodePoints`: compare by Unicode scalar value. Rust `str`
/// comparison is byte-wise over UTF-8, which orders by code point identically
/// for all scalar values.
pub fn compare_unicode_code_points(left: &str, right: &str) -> std::cmp::Ordering {
    left.cmp(right)
}

/// `uniqueSorted`.
pub fn unique_sorted(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out: Vec<String> = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out.sort_by(|left, right| compare_unicode_code_points(left, right));
    out
}
