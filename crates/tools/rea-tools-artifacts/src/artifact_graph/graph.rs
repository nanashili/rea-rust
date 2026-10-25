//! Artifact graph domain types, identity digests and canonical ordering.
//!
//! Compatibility owners: `src/domain/artifactGraph.ts`,
//! `src/domain/artifactIdentity.ts`, `src/domain/canonicalDigest.ts`
//! (digest context is error-message-only; the hashed bytes are the canonical
//! JSON of the value), `src/domain/canonicalOrdering.ts` and
//! `src/domain/unicodeCodePointOrder.ts`.
use rea_core::JsString;
use rea_core::canonical_json;
use serde::Serialize;
use serde_json::json;

#[derive(Serialize)]
struct OccurrenceIdentity<'a> {
    root_artifact_id: &'a str,
    logical_path: &'a JsString,
    entry_kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_ordinal: Option<u64>,
}

#[derive(Serialize)]
struct ContradictionIdentity<'a> {
    root_artifact_id: &'a str,
    logical_path: &'a JsString,
    declared_sha256: &'a str,
    observed_sha256: &'a str,
}

#[derive(Serialize)]
struct EdgeIdentity<'a> {
    parent_artifact_id: &'a str,
    child_artifact_id: Option<&'a str>,
    relation: &'a str,
    occurrence_id: &'a str,
    logical_path: &'a JsString,
}

#[derive(Serialize)]
struct ProvisionalIdentity<'a> {
    path: &'a JsString,
    kind: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    duplicate_ordinal: Option<u64>,
}

#[derive(Serialize)]
struct ArtifactGraphIdentity<'a> {
    nodes: &'a [ArtifactNode],
    occurrences: &'a [ArtifactOccurrence],
    edges: &'a [ArtifactEdge],
    integrity_contradictions: &'a [IntegrityContradiction],
}

#[derive(Serialize)]
struct DirectoryIdentity<'a, T> {
    kind: &'static str,
    children: &'a T,
}

/// Shared artifact-inventory facts.
pub use rea_core::artifact_inventory::{
    ArtifactEdge, ArtifactGraphManifest, ArtifactInventoryCoverage, ArtifactInventoryResult,
    ArtifactNode, ArtifactOccurrence, IntegrityContradiction, RequiredNullable,
};

/// Digest context panic guard: canonicalization of our owned, finite JSON
/// values cannot fail. Mirrors TS `digestCanonicalValue` throwing on the
/// unreachable non-finite/circular cases.
fn digest<T: Serialize>(value: &T) -> String {
    canonical_json::digest(value).expect("owned artifact values canonicalize")
}

/// `artifactIdForContent`.
pub fn artifact_id_for_content(sha256: &str) -> String {
    format!("art_{}", digest(&json!({ "sha256": sha256 })))
}

/// `occurrenceIdForLocation`.
pub fn occurrence_id_for_location(
    root_artifact_id: &str,
    logical_path: &JsString,
    entry_kind: &str,
    duplicate_ordinal: Option<u64>,
) -> String {
    if logical_path == "." {
        return format!("occ_{}", digest(&json!({ "root": root_artifact_id })));
    }
    let semantic = OccurrenceIdentity {
        root_artifact_id,
        logical_path,
        entry_kind,
        duplicate_ordinal,
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
    digest(&ArtifactGraphIdentity {
        nodes,
        occurrences,
        edges,
        integrity_contradictions: contradictions,
    })
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
    logical_path: &JsString,
    declared_sha256: &str,
    observed_sha256: &str,
) -> String {
    format!(
        "ic_{}",
        digest(&ContradictionIdentity {
            root_artifact_id,
            logical_path,
            declared_sha256,
            observed_sha256,
        })
    )
}

/// `artifactEdgeId`.
pub fn artifact_edge_id(
    parent_artifact_id: &str,
    child_artifact_id: Option<&str>,
    relation: &str,
    occurrence_id: &str,
    logical_path: &JsString,
) -> String {
    format!(
        "edge_{}",
        digest(&EdgeIdentity {
            parent_artifact_id,
            child_artifact_id,
            relation,
            occurrence_id,
            logical_path,
        })
    )
}

/// Pre-rekey occurrence id over `{ path, kind }` (plus duplicate ordinal).
/// Mirrors `createOccurrence`'s provisional id.
pub fn provisional_occurrence_id(path: &JsString, kind: &str, duplicate_ordinal: u64) -> String {
    let semantic = ProvisionalIdentity {
        path,
        kind,
        duplicate_ordinal: (duplicate_ordinal != 0).then_some(duplicate_ordinal),
    };
    format!("occ_{}", digest(&semantic))
}

/// Directory node digest over `{ kind: "directory", children }`.
pub fn directory_node_sha256<T: Serialize>(children: &T) -> String {
    digest(&DirectoryIdentity {
        kind: "directory",
        children,
    })
}

/// Root directory node digest over `{ kind: "directory-root", children }`.
pub fn directory_root_sha256<T: Serialize>(children: &T) -> String {
    digest(&DirectoryIdentity {
        kind: "directory-root",
        children,
    })
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

/// Compare logical paths by decoded Unicode code points while retaining lone
/// UTF-16 surrogates as their exact code units.
pub fn compare_js_code_points(left: &JsString, right: &JsString) -> std::cmp::Ordering {
    left.compare_code_points(right)
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

#[cfg(test)]
mod tests {
    use super::directory_node_sha256;
    use rea_core::JsString;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Child {
        name: JsString,
        artifact_id: Option<String>,
        entry_kind: &'static str,
    }

    #[test]
    fn directory_digest_retains_unpaired_utf16_member_names() {
        let children = [Child {
            name: JsString::from_utf16([
                b'x' as u16,
                0xd800,
                b'.' as u16,
                b'j' as u16,
                b's' as u16,
            ]),
            artifact_id: Some("art_x".to_owned()),
            entry_kind: "file",
        }];

        assert_eq!(
            directory_node_sha256(&children),
            "2140f209a0ef6dc15ecc9f27c50b8b8cb5ac26cad30478d283cf1131cfe5450b"
        );
    }
}
