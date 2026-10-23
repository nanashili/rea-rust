//! Parsed artifact-inventory facts shared by application projections.
//!
//! This boundary mirrors the TypeScript inventory result schema: the result
//! and coverage objects are closed, nested records drop unknown fields, and
//! caller values are normalized once before projections consume them.

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Number, Value};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInventoryResult {
    manifest: ArtifactGraphManifest,
    nodes: Vec<ArtifactNode>,
    occurrences: Vec<ArtifactOccurrence>,
    edges: Vec<ArtifactEdge>,
    provenance: Vec<ArtifactCommand>,
    integrity_contradictions: Vec<IntegrityContradiction>,
    coverage: ArtifactInventoryCoverage,
    limitations: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct ArtifactGraphManifest {
    manifest_id: String,
    root_artifact_id: String,
    root_sha256: String,
    root_format: String,
    graph_sha256: String,
    node_count: u64,
    occurrence_count: u64,
    edge_count: u64,
}

#[derive(Deserialize, Serialize)]
struct ArtifactNode {
    artifact_id: String,
    format: String,
    sha256: String,
    size: u64,
    media_type: RequiredNullable<String>,
    architecture: RequiredNullable<String>,
    content_state: String,
    limitations: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct ArtifactOccurrence {
    occurrence_id: String,
    artifact_id: RequiredNullable<String>,
    parent_occurrence_id: RequiredNullable<String>,
    logical_path: String,
    entry_kind: String,
    artifact_kind: String,
    artifact_format: String,
    declared_size: RequiredNullable<u64>,
    compressed_size: RequiredNullable<u64>,
    executable: bool,
    encrypted: bool,
    hash_status: String,
    source_location: RequiredNullable<ArtifactByteRange>,
    limitations: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct ArtifactByteRange {
    offset: u64,
    length: u64,
}

#[derive(Deserialize, Serialize)]
struct ArtifactEdge {
    edge_id: String,
    ordinal: u64,
    parent_artifact_id: String,
    relation: String,
    occurrence_id: String,
    producer: RequiredNullable<ArtifactCommand>,
}

#[derive(Deserialize, Serialize)]
struct ArtifactCommand {
    tool: String,
    arguments: Vec<String>,
    tool_version: RequiredNullable<String>,
    executable_sha256: RequiredNullable<String>,
    exit_code: RequiredNullable<Number>,
    effects: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct IntegrityContradiction {
    contradiction_id: String,
    occurrence_id: String,
    parent_artifact_id: String,
    logical_path: String,
    declared_sha256: String,
    observed_sha256: String,
    entry_kind: String,
    unpacked: bool,
    trust: String,
    provenance: String,
    limitations: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactInventoryCoverage {
    scope: String,
    status: String,
}

/// Validate and normalize one authenticated inventory result.
///
/// Serde ignores unknown fields in nested inventory records, matching the
/// source schema's ordinary objects. The result and coverage structs reject
/// unknown fields because the source schema closes those two boundaries.
pub fn normalize_result(input: Value) -> Result<Value, String> {
    let result: ArtifactInventoryResult = serde_json::from_value(input)
        .map_err(|error| format!("Artifact inventory result does not match its schema: {error}"))?;

    validate_inventory_result(&result)?;

    serde_json::to_value(result).map_err(|error| error.to_string())
}

#[derive(Serialize)]
#[serde(transparent)]
struct RequiredNullable<T>(Option<T>);

impl<'de, T> Deserialize<'de> for RequiredNullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<T>::deserialize(deserializer).map(Self)
    }
}

fn validate_inventory_result(result: &ArtifactInventoryResult) -> Result<(), String> {
    validate_manifest(&result.manifest)?;

    for node in &result.nodes {
        validate_node(node)?;
    }
    for occurrence in &result.occurrences {
        validate_occurrence(occurrence)?;
    }
    for edge in &result.edges {
        validate_edge(edge)?;
    }
    for command in &result.provenance {
        validate_command(command)?;
    }
    for contradiction in &result.integrity_contradictions {
        validate_contradiction(contradiction)?;
    }

    validate_enum(
        &result.coverage.scope,
        &["root", "container-entries"],
        "coverage.scope",
    )?;
    validate_enum(
        &result.coverage.status,
        &["complete", "unknown"],
        "coverage.status",
    )?;

    Ok(())
}

fn validate_manifest(manifest: &ArtifactGraphManifest) -> Result<(), String> {
    validate_prefixed_digest(&manifest.manifest_id, "agm", "manifest.manifest_id")?;
    validate_prefixed_digest(
        &manifest.root_artifact_id,
        "art",
        "manifest.root_artifact_id",
    )?;
    validate_sha256(&manifest.root_sha256, "manifest.root_sha256")?;
    validate_enum(
        &manifest.root_format,
        ARTIFACT_FORMATS,
        "manifest.root_format",
    )?;
    validate_sha256(&manifest.graph_sha256, "manifest.graph_sha256")?;
    if manifest.node_count == 0 || manifest.occurrence_count == 0 {
        return Err(
            "Artifact inventory manifest counts must include a root node and occurrence".into(),
        );
    }
    Ok(())
}

fn validate_node(node: &ArtifactNode) -> Result<(), String> {
    validate_prefixed_digest(&node.artifact_id, "art", "node.artifact_id")?;
    validate_enum(&node.format, CONTENT_FORMATS, "node.format")?;
    validate_sha256(&node.sha256, "node.sha256")?;
    validate_safe_integer(node.size, "node.size")?;
    validate_nullable_text(&node.media_type, "node.media_type")?;
    validate_nullable_text(&node.architecture, "node.architecture")?;
    validate_enum(
        &node.content_state,
        &["materialized", "embedded", "virtual"],
        "node.content_state",
    )?;
    Ok(())
}

fn validate_occurrence(occurrence: &ArtifactOccurrence) -> Result<(), String> {
    validate_prefixed_digest(&occurrence.occurrence_id, "occ", "occurrence.occurrence_id")?;
    validate_nullable_identifier(&occurrence.artifact_id, "art", "occurrence.artifact_id")?;
    validate_nullable_identifier(
        &occurrence.parent_occurrence_id,
        "occ",
        "occurrence.parent_occurrence_id",
    )?;
    validate_bounded_path(&occurrence.logical_path)?;
    validate_enum(
        &occurrence.entry_kind,
        &["file", "directory", "symlink", "slice"],
        "occurrence.entry_kind",
    )?;
    validate_enum(
        &occurrence.artifact_kind,
        ARTIFACT_KINDS,
        "occurrence.artifact_kind",
    )?;
    validate_enum(
        &occurrence.artifact_format,
        ARTIFACT_FORMATS,
        "occurrence.artifact_format",
    )?;
    validate_nullable_safe_integer(&occurrence.declared_size, "occurrence.declared_size")?;
    validate_nullable_safe_integer(&occurrence.compressed_size, "occurrence.compressed_size")?;
    validate_enum(
        &occurrence.hash_status,
        &["verified", "mismatched", "not-hashed", "unavailable"],
        "occurrence.hash_status",
    )?;
    if let Some(range) = &occurrence.source_location.0 {
        validate_safe_integer(range.offset, "occurrence.source_location.offset")?;
        validate_safe_integer(range.length, "occurrence.source_location.length")?;
    }
    Ok(())
}

fn validate_edge(edge: &ArtifactEdge) -> Result<(), String> {
    validate_prefixed_digest(&edge.edge_id, "edge", "edge.edge_id")?;
    validate_prefixed_digest(&edge.parent_artifact_id, "art", "edge.parent_artifact_id")?;
    validate_enum(
        &edge.relation,
        &[
            "contains",
            "extracts",
            "slice-of",
            "embeds",
            "loads",
            "maps-source",
            "derived-from",
        ],
        "edge.relation",
    )?;
    validate_prefixed_digest(&edge.occurrence_id, "occ", "edge.occurrence_id")?;
    if let Some(command) = &edge.producer.0 {
        validate_command(command)?;
    }
    Ok(())
}

fn validate_command(command: &ArtifactCommand) -> Result<(), String> {
    validate_nonempty(&command.tool, "command.tool")?;
    validate_nullable_digest(&command.executable_sha256, "command.executable_sha256")?;
    if let Some(exit_code) = &command.exit_code.0
        && !is_integer(exit_code)
    {
        return Err("Artifact command exit_code must be an integer or null".into());
    }
    for effect in &command.effects {
        validate_enum(effect, &["read", "write", "mount"], "command.effects")?;
    }
    Ok(())
}

fn validate_contradiction(contradiction: &IntegrityContradiction) -> Result<(), String> {
    validate_prefixed_digest(
        &contradiction.contradiction_id,
        "ic",
        "integrity_contradiction.contradiction_id",
    )?;
    validate_prefixed_digest(
        &contradiction.occurrence_id,
        "occ",
        "integrity_contradiction.occurrence_id",
    )?;
    validate_prefixed_digest(
        &contradiction.parent_artifact_id,
        "art",
        "integrity_contradiction.parent_artifact_id",
    )?;
    validate_bounded_path(&contradiction.logical_path)?;
    validate_sha256(
        &contradiction.declared_sha256,
        "integrity_contradiction.declared_sha256",
    )?;
    validate_sha256(
        &contradiction.observed_sha256,
        "integrity_contradiction.observed_sha256",
    )?;
    validate_enum(
        &contradiction.entry_kind,
        &["file", "slice"],
        "integrity_contradiction.entry_kind",
    )?;
    if contradiction.trust != "observed-untrusted"
        || contradiction.provenance != "container-integrity-metadata-versus-observed-bytes"
    {
        return Err("Artifact integrity contradiction has unknown trust or provenance".into());
    }
    if contradiction.limitations.is_empty() {
        return Err("Artifact integrity contradiction limitations must not be empty".into());
    }
    Ok(())
}

fn validate_nullable_text(value: &RequiredNullable<String>, field: &str) -> Result<(), String> {
    if let Some(value) = &value.0 {
        validate_nonempty(value, field)?;
    }
    Ok(())
}

fn validate_nullable_identifier(
    value: &RequiredNullable<String>,
    prefix: &str,
    field: &str,
) -> Result<(), String> {
    if let Some(value) = &value.0 {
        validate_prefixed_digest(value, prefix, field)?;
    }
    Ok(())
}

fn validate_nullable_digest(value: &RequiredNullable<String>, field: &str) -> Result<(), String> {
    if let Some(value) = &value.0 {
        validate_sha256(value, field)?;
    }
    Ok(())
}

fn validate_nullable_safe_integer(
    value: &RequiredNullable<u64>,
    field: &str,
) -> Result<(), String> {
    if let Some(value) = value.0 {
        validate_safe_integer(value, field)?;
    }
    Ok(())
}

fn validate_safe_integer(value: u64, field: &str) -> Result<(), String> {
    if value > MAX_SAFE_INTEGER {
        return Err(format!(
            "Artifact inventory {field} is outside the safe-integer range"
        ));
    }
    Ok(())
}

fn validate_bounded_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.split('/').any(|part| part.is_empty() || part == "..")
    {
        return Err("Artifact inventory path must be a normalized relative POSIX path".into());
    }
    Ok(())
}

fn validate_nonempty(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("Artifact inventory {field} must not be empty"));
    }
    Ok(())
}

fn validate_prefixed_digest(value: &str, prefix: &str, field: &str) -> Result<(), String> {
    let Some(digest) = value.strip_prefix(&format!("{prefix}_")) else {
        return Err(format!(
            "Artifact inventory {field} has an invalid identifier"
        ));
    };
    validate_sha256(digest, field)
}

fn validate_sha256(value: &str, field: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "Artifact inventory {field} must be a lowercase SHA-256 digest"
        ));
    }
    Ok(())
}

fn validate_enum(value: &str, allowed: &[&str], field: &str) -> Result<(), String> {
    if !allowed.contains(&value) {
        return Err(format!("Artifact inventory {field} has an unknown value"));
    }
    Ok(())
}

fn is_integer(value: &Number) -> bool {
    value.as_i64().is_some()
        || value.as_u64().is_some()
        || value
            .as_f64()
            .is_some_and(|number| number.is_finite() && number.fract() == 0.0)
}

const ARTIFACT_KINDS: &[&str] = &[
    "container",
    "executable",
    "dynamic-library",
    "framework",
    "native-addon",
    "javascript",
    "source-map",
    "plist",
    "entitlements",
    "resource",
    "universal-slice",
    "package-metadata",
    "unknown",
];

const CONTENT_FORMATS: &[&str] = &[
    "zip",
    "mach-o-universal",
    "mach-o",
    "elf",
    "pe",
    "dos-mz",
    "plist",
    "nib",
    "directory",
    "file",
    "unknown",
];

const ARTIFACT_FORMATS: &[&str] = &[
    "dmg",
    "zip",
    "pkg",
    "asar",
    "javascript-bundle",
    "source-map",
    "mach-o-universal",
    "mach-o",
    "elf",
    "pe",
    "dos-mz",
    "dos-com",
    "raw-binary",
    "hopper",
    "analysis-database",
    "ipa",
    "apk",
    "msix",
    "appx",
    "hap",
    "hsp",
    "app-pack",
    "plist",
    "nib",
    "entitlements",
    "directory",
    "file",
    "unknown",
];
