//! Analysis-profile and snapshot-target domain projections.
//!
//! Compatibility owners: `src/domain/analysisProfile.ts`
//! (`analysisProfilesEqual`, `committedProviderSchema`) and
//! `src/domain/analysisSnapshot.ts` (`snapshotTarget`, `snapshotBinding`,
//! `snapshotMatchesTarget`, `snapshotMatchesProfile`, `snapshotMatchesBinding`).
use rea_analysis::BinaryTarget;
use serde_json::{Map, Value, json};

/// Compare two already-validated analysis-profile commitments without
/// interpreting their parameters (TS `analysisProfilesEqual`).
pub(crate) fn analysis_profiles_equal(left: &Value, right: &Value) -> bool {
    let (Some(left), Some(right)) = (left.as_object(), right.as_object()) else {
        return false;
    };
    string_eq(left.get("digest"), right.get("digest"))
        && provider_eq(left.get("provider"), right.get("provider"))
}

fn provider_eq(left: Option<&Value>, right: Option<&Value>) -> bool {
    let (Some(left), Some(right)) = (
        left.and_then(Value::as_object),
        right.and_then(Value::as_object),
    ) else {
        return false;
    };
    string_eq(left.get("id"), right.get("id"))
        && string_eq(left.get("name"), right.get("name"))
        && version_eq(left.get("version"), right.get("version"))
}

fn string_eq(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left.and_then(Value::as_str), right.and_then(Value::as_str)) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

/// Provider versions may be `null`; `null == null` and `"v" == "v"`.
fn version_eq(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (Some(Value::Null) | None, Some(Value::Null) | None) => true,
        (Some(Value::String(left)), Some(Value::String(right))) => left == right,
        _ => false,
    }
}

/// Project a binary into the path-free identity used for cache invalidation
/// (TS `snapshotTarget`). Key order matches the TS object literals exactly.
pub(crate) fn snapshot_target(target: &BinaryTarget) -> Value {
    let mut object = Map::new();
    if target.format == "raw-binary" {
        object.insert("sha256".into(), json!(target.sha256));
        object.insert("kind".into(), json!(target.kind));
        object.insert(
            "architecture".into(),
            target
                .architecture
                .clone()
                .map_or(Value::Null, Value::String),
        );
        object.insert("format".into(), json!(target.format));
        object.insert(
            "entry_point".into(),
            target
                .metadata
                .get("entryPoint")
                .cloned()
                .unwrap_or(Value::Null),
        );
    } else {
        object.insert("sha256".into(), json!(target.sha256));
        object.insert("kind".into(), json!(target.kind));
        object.insert(
            "architecture".into(),
            target
                .architecture
                .clone()
                .map_or(Value::Null, Value::String),
        );
        object.insert("format".into(), json!(target.format));
    }
    Value::Object(object)
}

/// Build the immutable provider/profile binding for a cached snapshot (TS
/// `snapshotBinding`). The caller supplies a validated profile commitment.
pub(crate) fn snapshot_binding(profile: &Value) -> Value {
    let provider = profile.get("provider").cloned().unwrap_or(Value::Null);
    json!({
        "provider": provider,
        "analysis_profile": profile,
    })
}

/// Compare an open binary with the immutable target identity in a snapshot
/// (TS `snapshotMatchesTarget`).
pub(crate) fn snapshot_matches_target(snapshot: &Value, target: &BinaryTarget) -> bool {
    let Some(snapshot) = snapshot.as_object() else {
        return false;
    };
    let snapshot_sha = snapshot.get("sha256").and_then(Value::as_str);
    let snapshot_kind = snapshot.get("kind").and_then(Value::as_str);
    let snapshot_format = snapshot.get("format").and_then(Value::as_str);
    let snapshot_architecture = snapshot.get("architecture");
    let target_architecture = target
        .architecture
        .clone()
        .map_or(Value::Null, Value::String);
    let base = snapshot_sha == Some(target.sha256.as_str())
        && snapshot_kind == Some(target.kind.as_str())
        && snapshot_format == Some(target.format.as_str())
        && snapshot_architecture == Some(&target_architecture);
    if !base {
        return false;
    }
    if snapshot_format != Some("raw-binary") {
        return true;
    }
    // Raw-binary identity also pins the mapped entry point.
    if target.format != "raw-binary" {
        return false;
    }
    let snapshot_entry = snapshot.get("entry_point");
    let target_entry = target.metadata.get("entryPoint");
    snapshot_entry == target_entry
}

/// Compare a snapshot binding with the selected concrete profile (TS
/// `snapshotMatchesProfile`).
pub(crate) fn snapshot_matches_profile(binding: &Value, profile: &Value) -> bool {
    let Some(binding) = binding.as_object() else {
        return false;
    };
    let binding_provider = binding.get("provider");
    let profile_provider = profile.get("provider");
    provider_eq(binding_provider, profile_provider)
        && binding
            .get("analysis_profile")
            .is_some_and(|binding_profile| analysis_profiles_equal(binding_profile, profile))
}

/// Compare the open binary with the stored target identity (TS
/// `snapshotMatchesTarget(snapshotTarget(current), target)`).
pub(crate) fn target_identity_matches(current: &BinaryTarget, target: &BinaryTarget) -> bool {
    snapshot_matches_target(&snapshot_target(current), target)
}
