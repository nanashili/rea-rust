//! Shared typed artifact-inventory facts and validation.
#![allow(missing_docs)]
//!
//! This boundary mirrors the TypeScript inventory result schema: the result
//! and coverage objects are closed, nested records drop unknown fields, and
//! caller values are normalized once before projections consume them. Logical
//! paths use [`JsString`] so escaped unpaired UTF-16 surrogates from ASAR names
//! remain available to every inventory projection.

use crate::JsString;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::value::RawValue;
use serde_json::{Number, Value};

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct ArtifactInventoryResult {
    pub manifest: ArtifactGraphManifest,
    pub nodes: Vec<ArtifactNode>,
    pub occurrences: Vec<ArtifactOccurrence>,
    pub edges: Vec<ArtifactEdge>,
    pub provenance: Vec<ArtifactCommand>,
    pub integrity_contradictions: Vec<IntegrityContradiction>,
    pub coverage: ArtifactInventoryCoverage,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ArtifactGraphManifest {
    pub manifest_id: String,
    pub root_artifact_id: String,
    pub root_sha256: String,
    pub root_format: String,
    pub graph_sha256: String,
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub node_count: u64,
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub occurrence_count: u64,
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub edge_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ArtifactNode {
    pub artifact_id: String,
    pub format: String,
    pub sha256: String,
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub size: u64,
    pub media_type: RequiredNullable<String>,
    pub architecture: RequiredNullable<String>,
    pub content_state: String,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ArtifactOccurrence {
    pub occurrence_id: String,
    pub artifact_id: RequiredNullable<String>,
    pub parent_occurrence_id: RequiredNullable<String>,
    pub logical_path: JsString,
    pub entry_kind: String,
    pub artifact_kind: String,
    pub artifact_format: String,
    #[serde(deserialize_with = "deserialize_nullable_schema_integer")]
    pub declared_size: RequiredNullable<u64>,
    #[serde(deserialize_with = "deserialize_nullable_schema_integer")]
    pub compressed_size: RequiredNullable<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub hash_status: String,
    pub source_location: RequiredNullable<ArtifactByteRange>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ArtifactByteRange {
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub offset: u64,
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ArtifactEdge {
    pub edge_id: String,
    #[serde(deserialize_with = "deserialize_schema_integer")]
    pub ordinal: u64,
    pub parent_artifact_id: String,
    pub relation: String,
    pub occurrence_id: String,
    pub producer: RequiredNullable<ArtifactCommand>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct ArtifactCommand {
    pub tool: String,
    pub arguments: Vec<String>,
    pub tool_version: RequiredNullable<String>,
    pub executable_sha256: RequiredNullable<String>,
    pub exit_code: RequiredNullable<Number>,
    pub effects: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct IntegrityContradiction {
    pub contradiction_id: String,
    pub occurrence_id: String,
    pub parent_artifact_id: String,
    pub logical_path: JsString,
    pub declared_sha256: String,
    pub observed_sha256: String,
    pub entry_kind: String,
    pub unpacked: bool,
    pub trust: String,
    pub provenance: String,
    pub limitations: Vec<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactInventoryCoverage {
    pub scope: String,
    pub status: String,
}

/// Validate and normalize one authenticated inventory result.
///
/// Serde ignores unknown fields in nested inventory records, matching the
/// source schema's ordinary objects. The result and coverage structs reject
/// unknown fields because the source schema closes those two boundaries.
pub fn normalize_result(input: Value) -> Result<Value, String> {
    let result = parse_validated_result(input)?;

    serde_json::to_value(result).map_err(|error| error.to_string())
}

/// Normalize retained inventory JSON while preserving exact JavaScript paths.
pub fn normalize_result_text(input: &RawValue) -> Result<Box<RawValue>, String> {
    let result = parse_validated_result_text(input)?;

    let output = serde_json::to_string(&result).map_err(|error| error.to_string())?;
    RawValue::from_string(output).map_err(|error| error.to_string())
}

/// Parse one inventory result without applying semantic validation.
pub fn parse_result(input: Value) -> Result<ArtifactInventoryResult, String> {
    serde_json::from_value(input)
        .map_err(|error| format!("Artifact inventory result does not match its schema: {error}"))
}

/// Parse an inventory result directly from retained JSON text.
///
/// Callers that may receive ASAR names containing escaped unpaired UTF-16
/// surrogates must use this boundary instead of first materializing a
/// `serde_json::Value`.
pub fn parse_result_text(input: &RawValue) -> Result<ArtifactInventoryResult, String> {
    serde_json::from_str(input.get())
        .map_err(|error| format!("Artifact inventory result does not match its schema: {error}"))
}

/// Parse and semantically validate inventory JSON without losing string units.
pub fn parse_validated_result_text(input: &RawValue) -> Result<ArtifactInventoryResult, String> {
    let result = parse_result_text(input)?;

    validate_inventory_result(&result)?;

    Ok(result)
}

/// Parse and semantically validate one inventory result before projection.
pub fn parse_validated_result(input: Value) -> Result<ArtifactInventoryResult, String> {
    let result = parse_result(input)?;

    validate_inventory_result(&result)?;

    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RequiredNullable<T>(Option<T>);

impl<T> RequiredNullable<T> {
    pub fn from_option(value: Option<T>) -> Self {
        Self(value)
    }

    pub fn is_none(&self) -> bool {
        self.0.is_none()
    }

    pub fn as_ref(&self) -> Option<&T> {
        self.0.as_ref()
    }
}

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

/// Decode a JSON number accepted by the TypeScript `z.number().int()` schema.
///
/// JavaScript has one `number` type, so JSON `1` and `1.0` both arrive at Zod
/// as the same integer value. Serde's direct `u64` decoder rejects the latter
/// because it retains the source number's decimal representation. Keep the
/// typed Rust fact while accepting both representations at this boundary.
fn deserialize_schema_integer<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    deserialize_schema_integer_value(value)
}

fn deserialize_nullable_schema_integer<'de, D>(
    deserializer: D,
) -> Result<RequiredNullable<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<Value>::deserialize(deserializer)?;
    value
        .map(deserialize_schema_integer_value)
        .transpose()
        .map(RequiredNullable)
}

fn deserialize_schema_integer_value<E>(value: Value) -> Result<u64, E>
where
    E: de::Error,
{
    let Value::Number(number) = value else {
        return Err(de::Error::custom("expected a nonnegative integer"));
    };

    if let Some(integer) = number.as_u64() {
        return Ok(integer);
    }

    let Some(float) = number.as_f64() else {
        return Err(de::Error::custom("expected a nonnegative integer"));
    };
    if !float.is_finite() || float < 0.0 || float.fract() != 0.0 {
        return Err(de::Error::custom("expected a nonnegative integer"));
    }

    Ok(float as u64)
}

fn validate_safe_integer(value: u64, field: &str) -> Result<(), String> {
    if value > MAX_SAFE_INTEGER {
        return Err(format!(
            "Artifact inventory {field} is outside the safe-integer range"
        ));
    }
    Ok(())
}

fn validate_bounded_path(path: &JsString) -> Result<(), String> {
    if path == "." {
        return Ok(());
    }

    let units = path.units();
    let unsafe_component = units
        .split(|unit| *unit == u16::from(b'/'))
        .any(|component| {
            component.is_empty()
                || component == [u16::from(b'.'), u16::from(b'.')]
                || component == [u16::from(b'.')]
        });
    if units.is_empty() || units.first() == Some(&u16::from(b'/')) || unsafe_component {
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

#[cfg(test)]
mod tests {
    use super::{ArtifactByteRange, parse_validated_result};
    use serde_json::{Value, json};

    fn inventory_with_source_location(source_location: Value) -> Value {
        let digest = "0".repeat(64);
        json!({
            "manifest": {
                "manifest_id": format!("agm_{digest}"),
                "root_artifact_id": format!("art_{digest}"),
                "root_sha256": digest,
                "root_format": "file",
                "graph_sha256": "0".repeat(64),
                "node_count": 1,
                "occurrence_count": 1,
                "edge_count": 0,
            },
            "nodes": [{
                "artifact_id": format!("art_{}", "0".repeat(64)),
                "format": "file",
                "sha256": "0".repeat(64),
                "size": 1,
                "media_type": null,
                "architecture": null,
                "content_state": "materialized",
                "limitations": [],
            }],
            "occurrences": [{
                "occurrence_id": format!("occ_{}", "0".repeat(64)),
                "artifact_id": format!("art_{}", "0".repeat(64)),
                "parent_occurrence_id": null,
                "logical_path": ".",
                "entry_kind": "file",
                "artifact_kind": "unknown",
                "artifact_format": "file",
                "declared_size": 1,
                "compressed_size": null,
                "executable": false,
                "encrypted": false,
                "hash_status": "not-hashed",
                "source_location": source_location,
                "limitations": [],
            }],
            "edges": [],
            "provenance": [],
            "integrity_contradictions": [],
            "coverage": {"scope": "root", "status": "complete"},
            "limitations": [],
        })
    }

    #[test]
    fn byte_ranges_accept_integral_json_floats() {
        let range: ArtifactByteRange = serde_json::from_value(json!({
            "offset": 1.0,
            "length": 2.0,
        }))
        .expect("Zod integer values may arrive as JSON decimals");

        assert_eq!(range.offset, 1);
        assert_eq!(range.length, 2);
    }

    #[test]
    fn byte_ranges_reject_fractional_numbers() {
        let error = serde_json::from_value::<ArtifactByteRange>(json!({
            "offset": 1.5,
            "length": 2,
        }))
        .expect_err("fractional values violate z.number().int()");

        assert!(error.to_string().contains("nonnegative integer"));
    }

    #[test]
    fn validated_inventory_accepts_integral_decimal_ranges_but_keeps_safe_cap() {
        let parsed = parse_validated_result(inventory_with_source_location(json!({
            "offset": 1.0,
            "length": 2.0,
        })))
        .expect("Zod integer values may arrive as JSON decimals");
        let range = parsed.occurrences[0]
            .source_location
            .as_ref()
            .expect("source location remains present");
        assert_eq!(range.offset, 1);
        assert_eq!(range.length, 2);

        let error = match parse_validated_result(inventory_with_source_location(json!({
            "offset": 9_007_199_254_740_992_u64,
            "length": 2,
        }))) {
            Ok(_) => panic!("Zod integer values remain safe integers"),
            Err(error) => error,
        };
        assert!(error.contains("outside the safe-integer range"));
    }
}
