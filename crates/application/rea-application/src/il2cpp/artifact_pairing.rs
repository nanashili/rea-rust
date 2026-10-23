//! Captured-only pairing of the artifacts which make up an IL2CPP build.
//!
//! This module deliberately does not inspect paths or infer relationships from
//! filenames.  A pairing is useful only when the caller supplied enough stable
//! identity (build/target, architecture, and digest) to prove it.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "pair_il2cpp_artifacts";
const MAX_ARTIFACTS: usize = 1024;

/// Correlate metadata, native, and optional managed assembly captures.
///
/// Input may contain `artifacts` directly, or authenticated Evidence records
/// in `evidence`. Each artifact must expose `kind` (`metadata`, `native`, or
/// `managed`), a stable target/build identity, architecture, and SHA-256.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    // The public contract requires at least one caller-supplied artifact
    // source.  An empty object must not be interpreted as an empty, complete
    // pairing result because that would bypass the contract's `oneOf`
    // admission rule.
    if !object.contains_key("artifacts") && !object.contains_key("evidence") {
        return Err(invalid("input", "Either artifacts or evidence is required"));
    }

    let mut artifacts = Vec::new();
    if let Some(values) = object.get("artifacts") {
        let rows = values
            .as_array()
            .ok_or_else(|| invalid("artifacts", "Expected an array"))?;
        artifacts.extend(rows.iter().cloned());
    }
    if let Some(values) = object.get("evidence") {
        let rows = values
            .as_array()
            .ok_or_else(|| invalid("evidence", "Expected an array"))?;
        for (index, value) in rows.iter().enumerate() {
            let raw = serde_json::value::to_raw_value(value)
                .map_err(|error| invalid("evidence", &error.to_string()))?;
            let record = EvidenceRecord::parse(&raw)
                .map_err(|error| invalid("evidence", &format!("evidence[{index}]: {error}")))?;
            let operation = serde_json::from_str::<String>(record.operation().get())
                .map_err(|_| invalid("evidence.operation", "Operation must be a string"))?;
            let result: Value =
                serde_json::from_str(record.normalized_result().get()).map_err(|error| {
                    invalid(
                        "evidence.normalized_result",
                        &format!("evidence[{index}].normalized_result: {error}"),
                    )
                })?;
            let mut artifact = result
                .as_object()
                .cloned()
                .ok_or_else(|| invalid("evidence.normalized_result", "Result must be an object"))?;
            let subject: Value = serde_json::from_str(record.subject().get()).map_err(|error| {
                invalid(
                    "evidence.subject",
                    &format!("evidence[{index}].subject: {error}"),
                )
            })?;
            artifact.insert("evidence_subject".into(), subject);
            artifact.insert(
                "evidence_id".into(),
                Value::String(record.evidence_id().to_owned()),
            );
            artifact.insert("evidence_operation".into(), Value::String(operation));
            artifacts.push(Value::Object(artifact));
        }
    }
    if artifacts.len() > MAX_ARTIFACTS {
        return Err(invalid("artifacts", "Too many artifacts"));
    }

    let mut normalized = Vec::with_capacity(artifacts.len());
    for (index, value) in artifacts.into_iter().enumerate() {
        normalized.push(normalize_artifact(value, index)?);
    }

    let mut groups: BTreeMap<PairingIdentity, Vec<usize>> = BTreeMap::new();
    for (index, artifact) in normalized.iter().enumerate() {
        if let Some(identity) = artifact.pairing_identity() {
            groups.entry(identity).or_default().push(index);
        }
    }
    let mut pairs = Vec::new();
    let mut used = BTreeSet::new();
    for (identity, indices) in groups {
        let metadata: Vec<_> = indices
            .iter()
            .copied()
            .filter(|i| normalized[*i].kind == "metadata")
            .collect();
        let native: Vec<_> = indices
            .iter()
            .copied()
            .filter(|i| normalized[*i].kind == "native")
            .collect();
        let managed: Vec<_> = indices
            .iter()
            .copied()
            .filter(|i| normalized[*i].kind == "managed")
            .collect();
        let status = if metadata.len() == 1 && native.len() == 1 {
            "paired"
        } else if metadata.is_empty() || native.is_empty() {
            "unresolved"
        } else {
            "ambiguous"
        };
        for index in indices.iter() {
            used.insert(*index);
        }
        pairs.push(json!({ "identity": identity.base, "status": status,
            "metadata": values(&normalized, &metadata), "native": values(&normalized, &native),
            "managed": values(&normalized, &managed),
            "ambiguity": if status == "ambiguous" { Value::String("Multiple metadata or native artifacts share the exact identity".into()) } else { Value::Null }
        }));
    }
    let ungrouped: Vec<_> = normalized
        .iter()
        .enumerate()
        .filter(|(index, _)| !used.contains(index))
        .map(|(_, artifact)| artifact.source.clone())
        .collect();
    let pair_count = pairs.len();
    let ungrouped_count = ungrouped.len();
    let partial = pairs
        .iter()
        .any(|pair| pair["status"] == "ambiguous" || pair["status"] == "unresolved")
        || ungrouped_count != 0;
    Ok(
        json!({ "status": if partial { "partial" } else { "complete" }, "pairs": pairs, "ungrouped": ungrouped,
        "coverage": { "artifacts": normalized.len(), "pairs": pair_count, "ungrouped": ungrouped_count } }),
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize)]
struct Identity {
    target_id: String,
    build_id: String,
    architecture: String,
    sha256: String,
}

/// Pairing identity is the exact tuple advertised by the public contract.
/// Image and module facts remain attached to each source artifact, but they do
/// not silently narrow a pairing that the caller established with this tuple.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct PairingIdentity {
    base: Identity,
}

#[derive(Clone)]
struct Artifact {
    kind: String,
    source: Value,
    target_id: Option<String>,
    build_id: Option<String>,
    architecture: Option<String>,
    sha256: Option<String>,
    image_index: Option<u64>,
    image_name: Option<String>,
    module_name: Option<String>,
}
impl Artifact {
    fn base_identity(&self) -> Option<Identity> {
        Some(Identity {
            target_id: self.target_id.clone()?,
            build_id: self.build_id.clone()?,
            architecture: self.architecture.clone()?,
            sha256: self.sha256.clone()?,
        })
    }

    fn pairing_identity(&self) -> Option<PairingIdentity> {
        Some(PairingIdentity {
            base: self.base_identity()?,
        })
    }
}

fn normalize_artifact(value: Value, index: usize) -> Result<Artifact, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("artifacts[{index}"), "Expected an object"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("artifact.kind", "Kind is required"))?;
    if !matches!(kind, "metadata" | "native" | "managed") {
        return Err(invalid(
            "artifact.kind",
            "Kind must be metadata, native, or managed",
        ));
    }
    let target_id = identity_field(
        object,
        index,
        "target_id",
        &["target_id", "target", "bundle_id"],
    )?;
    let build_id = identity_field(object, index, "build_id", &["build_id", "build", "version"])?;
    let architecture = identity_field(object, index, "architecture", &["architecture", "arch"])?;
    let sha256 = identity_field(object, index, "sha256", &["sha256", "digest"])?;
    let image_index = identity_number(
        object,
        index,
        "image_index",
        &["image_index", "image_id", "index"],
    )?;
    let image_name = identity_field(
        object,
        index,
        "image_name",
        &["image_name", "assembly_name", "image"],
    )?;
    let module_name = identity_field(object, index, "module_name", &["module_name", "module"])?;
    if let Some(value) = &sha256 {
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(invalid(
                "artifact.sha256",
                "SHA-256 must be lowercase hexadecimal",
            ));
        }
    }
    Ok(Artifact {
        kind: kind.into(),
        source: value,
        target_id,
        build_id,
        architecture,
        sha256,
        image_index,
        image_name,
        module_name,
    })
}

/// Read an integer identity value while accepting the numeric forms emitted
/// by metadata captures.  Numeric text is canonicalized before aliases are
/// compared, so `1` and `"1"` express the same caller-supplied identity.
fn identity_number(
    object: &Map<String, Value>,
    index: usize,
    canonical_name: &str,
    aliases: &[&str],
) -> Result<Option<u64>, Failure> {
    let mut selected: Option<(&str, u64)> = None;

    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let parsed = if value.is_null() {
            continue;
        } else if let Some(number) = value.as_u64() {
            Some(number)
        } else if let Some(text) = value.as_str() {
            let text = text.trim();
            let (digits, radix) = text
                .strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .map_or((text, 10), |digits| (digits, 16));
            u64::from_str_radix(digits, radix).ok()
        } else {
            None
        };
        let Some(parsed) = parsed else {
            return Err(invalid(
                &format!("artifacts[{index}].{canonical_name}"),
                "Image indices must be non-negative integers",
            ));
        };

        if let Some((selected_alias, selected_value)) = &selected {
            if *selected_value != parsed {
                return Err(invalid(
                    &format!("artifacts[{index}].{canonical_name}"),
                    &format!("Conflicting identity aliases {selected_alias} and {alias}"),
                ));
            }
        } else {
            selected = Some((alias, parsed));
        }
    }

    Ok(selected.map(|(_, value)| value))
}

/// Read one identity value while rejecting contradictory aliases.
///
/// Aliases are accepted for compatibility with captured provider output, but
/// silently choosing one of two different values would manufacture a pairing
/// that the caller did not prove. Null aliases remain omitted values so that
/// incomplete captures are still reported as ungrouped rather than rejected.
fn identity_field(
    object: &Map<String, Value>,
    index: usize,
    canonical_name: &str,
    aliases: &[&str],
) -> Result<Option<String>, Failure> {
    let mut selected: Option<(&str, String)> = None;

    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let Some(value) = value.as_str() else {
            if value.is_null() {
                continue;
            }
            return Err(invalid(
                &format!("artifacts[{index}].{canonical_name}"),
                "Identity values must be strings when supplied",
            ));
        };

        if value.is_empty() {
            return Err(invalid(
                &format!("artifacts[{index}].{canonical_name}"),
                "Identity values must be non-empty strings when supplied",
            ));
        }

        if let Some((selected_alias, selected_value)) = &selected {
            if selected_value != value {
                return Err(invalid(
                    &format!("artifacts[{index}].{canonical_name}"),
                    &format!("Conflicting identity aliases {selected_alias} and {alias}"),
                ));
            }
        } else {
            selected = Some((alias, value.to_owned()));
        }
    }

    Ok(selected.map(|(_, value)| value))
}

fn values(artifacts: &[Artifact], indices: &[usize]) -> Vec<Value> {
    indices
        .iter()
        .map(|index| artifacts[*index].source.clone())
        .collect()
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details("invalid_request", "invalid_input", "IL2CPP artifact pairing input is invalid.".into(), false, "Supply authenticated artifact captures with exact build identity, architecture, and lowercase SHA-256 digests.".into(), BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into())), ("field".into(), Detail::Text(field.into())), ("reason".into(), Detail::Text(reason.into()))]))
}
