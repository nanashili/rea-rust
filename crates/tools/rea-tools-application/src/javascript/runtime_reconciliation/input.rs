//! The Zod refinements of `reconcileJavaScriptRuntimeInputSchema`
//! (`javascriptRuntimeReconciliationSchemas.ts`) that the frozen JSON Schema
//! cannot express, and the service's `normalizeRuntimeMappingRoots`.
//!
//! The JSON Schema boundary already enforced structure and applied defaults;
//! this module applies the field refinements and overwrites in schema order,
//! then the object-level `superRefine` only when the fields succeeded, as Zod
//! does.
use super::paths;
use super::{custom, join, str_of};
use rea_core::analysis_error::InputIssue;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

const PREFIX_MESSAGE: &str = "Artifact prefix must be empty or a safe relative POSIX path";
const URL_MESSAGE: &str =
    "Runtime URL prefix must be HTTP(S) without credentials, query, or fragment";

/// `safePrefixSchema`.
fn safe_prefix(value: &str) -> bool {
    value.is_empty()
        || (!paths::logical_path_escapes_root(value)
            && value
                .split('/')
                .all(|part| !matches!(part, "" | "." | "..")))
}

/// `analysisProfileSchema`'s digest refinement, then the Evidence-level
/// `validateAnalysisProfileProvider`, in Zod's evaluation order.
fn profile_issues(evidence: &Value, path: &[Value], issues: &mut Vec<InputIssue>) {
    let profile = &evidence["analysis_profile"];
    if profile.is_null() {
        return;
    }
    let unsigned = json!({ "provider": profile["provider"], "parameters": profile["parameters"] });
    let digest = rea_core::canonical_json::digest(&unsigned).ok();
    if digest.as_deref() != profile["digest"].as_str() {
        issues.push(custom(
            &join(path, &[json!("analysis_profile"), json!("digest")]),
            "Analysis profile digest does not match its parameters",
        ));
    }
    let (declared, provider) = (&profile["provider"], &evidence["provider"]);
    if declared["id"] != provider["id"]
        || declared["name"] != provider["name"]
        || declared["version"] != provider["version"]
    {
        issues.push(custom(
            &join(path, &[json!("analysis_profile"), json!("provider")]),
            "Analysis profile provider does not match Evidence provider",
        ));
    }
}

fn mapping_key(mapping: &Value) -> String {
    if mapping["kind"] == "file-root" {
        format!(
            "file-root\0{}\0{}",
            str_of(&mapping["root"]),
            str_of(&mapping["artifact_prefix"])
        )
    } else {
        format!(
            "url-prefix\0{}\0{}",
            str_of(&mapping["prefix"]),
            str_of(&mapping["artifact_prefix"])
        )
    }
}

/// Parse the caller input as the original Zod schema does.
pub fn refine(raw: &Value) -> Result<Value, Vec<InputIssue>> {
    let mut input = raw.clone();
    let mut issues = Vec::new();
    let layers = input["static_layers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let mut refined_layers = Vec::with_capacity(layers.len());
    for (index, layer) in layers.into_iter().enumerate() {
        let mut layer = layer.as_object().cloned().unwrap_or_default();
        let layer_path = [json!("static_layers"), json!(index)];
        layer.entry("role").or_insert_with(|| json!("application"));
        profile_issues(
            &layer["analysis"],
            &join(&layer_path, &[json!("analysis")]),
            &mut issues,
        );
        let mappings = layer
            .get("runtime_mappings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut refined = Vec::with_capacity(mappings.len());
        for (position, mapping) in mappings.into_iter().enumerate() {
            let mut mapping = mapping.as_object().cloned().unwrap_or_default();
            let path = join(&layer_path, &[json!("runtime_mappings"), json!(position)]);
            if mapping.get("kind").and_then(Value::as_str) == Some("url-prefix") {
                let prefix = mapping
                    .get("prefix")
                    .map(str_of)
                    .unwrap_or_default()
                    .to_owned();
                match paths::normalize_runtime_url_prefix(&prefix) {
                    Some(normalized) => {
                        mapping.insert("prefix".into(), json!(normalized));
                    }
                    None => issues.push(custom(&join(&path, &[json!("prefix")]), URL_MESSAGE)),
                }
            }
            let prefix = mapping
                .entry("artifact_prefix")
                .or_insert_with(|| json!(""));
            if !safe_prefix(str_of(prefix)) {
                issues.push(custom(
                    &join(&path, &[json!("artifact_prefix")]),
                    PREFIX_MESSAGE,
                ));
            }
            refined.push(Value::Object(mapping));
        }
        // `normalizeRuntimeMappings`: dedupe by key, sort by key.
        let unique: BTreeMap<String, Value> = refined
            .into_iter()
            .map(|mapping| (mapping_key(&mapping), mapping))
            .collect();
        layer.insert(
            "runtime_mappings".into(),
            Value::Array(unique.into_values().collect()),
        );
        refined_layers.push(Value::Object(layer));
    }
    input["static_layers"] = Value::Array(refined_layers);
    for (index, observation) in input["runtime_observations"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        profile_issues(
            observation,
            &[json!("runtime_observations"), json!(index)],
            &mut issues,
        );
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    let layers = input["static_layers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if layers
        .iter()
        .filter(|layer| layer["role"] == "application")
        .count()
        != 1
    {
        issues.push(custom(
            &[json!("static_layers")],
            "Exactly one application static layer is required",
        ));
    }
    if !unique_ids(layers.iter().map(|layer| &layer["analysis"]["evidence_id"])) {
        issues.push(custom(
            &[json!("static_layers")],
            "Static layer Evidence must be unique",
        ));
    }
    let runtime = input["runtime_observations"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    if !unique_ids(
        runtime
            .iter()
            .map(|observation| &observation["evidence_id"]),
    ) {
        issues.push(custom(
            &[json!("runtime_observations")],
            "Runtime observation Evidence must be unique",
        ));
    }
    if issues.is_empty() {
        Ok(input)
    } else {
        Err(issues)
    }
}

fn unique_ids<'a>(ids: impl Iterator<Item = &'a Value>) -> bool {
    let mut seen = HashSet::new();
    ids.map(str_of).all(|id| seen.insert(id))
}

/// `normalizeRuntimeMappingRoots`: resolve relative `file-root` roots
/// against the server's working directory, as Node `path.resolve` does.
pub fn normalize_runtime_mapping_roots(mut input: Value) -> Value {
    for layer in input["static_layers"].as_array_mut().into_iter().flatten() {
        for mapping in layer["runtime_mappings"]
            .as_array_mut()
            .into_iter()
            .flatten()
        {
            if mapping["kind"] != "file-root" {
                continue;
            }
            let root = str_of(&mapping["root"]).to_owned();
            if paths::is_portable_absolute_path(&root) {
                continue;
            }
            let resolved = std::path::absolute(&root)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or(root);
            let normalized = paths::posix_normalize(&resolved);
            let trimmed = if normalized.len() > 1 {
                normalized.trim_end_matches('/').to_owned()
            } else {
                normalized
            };
            mapping["root"] = json!(trimmed);
        }
    }
    input
}
