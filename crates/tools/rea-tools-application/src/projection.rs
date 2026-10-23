//! Shared mobile application inventory projection semantics.
//!
//! Compatibility owners: `src/domain/mobileApplicationGraphProjection.ts`,
//! `src/domain/bridgeCandidateProjection.ts`, `src/domain/nativeConvention.ts`
//! and `src/application/InventoryProjectionEvidence.ts`.
use crate::inventory::{self, InventorySet, ParsedInventorySet};
use crate::rejection::Rejection;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use serde_json::{Value, json};

/// Maximum UTF-8 JSON size of a retained candidate array.
const MAX_BRIDGE_CANDIDATE_JSON_BYTES: usize = 2 * 1024 * 1024;

/// One occurrence with either authenticated or unavailable content.
pub struct Entry {
    pub path: String,
    pub kind: String,
    pub component: Option<Value>,
    pub unavailable: Option<Value>,
}

/// `projectedInventoryEntries`: interpret identity once, before attribution.
pub fn entries(inventory: &InventorySet) -> Result<Vec<Entry>, Rejection> {
    let nodes: std::collections::HashMap<&str, &Value> = inventory
        .nodes
        .iter()
        .map(|node| (node["artifact_id"].as_str().unwrap_or_default(), node))
        .collect();
    inventory
        .occurrences
        .iter()
        .filter(|occurrence| occurrence["logical_path"].as_str() != Some("."))
        .map(|occurrence| {
            let path = occurrence["logical_path"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let kind = occurrence["entry_kind"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            let format = occurrence["artifact_format"].clone();
            if occurrence["artifact_id"].is_null() {
                return Ok(Entry {
                    unavailable: Some(json!({
                        "path": path,
                        "artifact_id": null,
                        "sha256": null,
                        "format": format,
                        "encrypted": occurrence["encrypted"],
                        "limitations": occurrence["limitations"],
                    })),
                    path,
                    kind,
                    component: None,
                });
            }
            let node = nodes
                .get(occurrence["artifact_id"].as_str().unwrap_or_default())
                .ok_or_else(|| {
                    Rejection::type_error("Application projection occurrence has no artifact node")
                })?;
            Ok(Entry {
                component: Some(json!({
                    "path": path,
                    "artifact_id": node["artifact_id"],
                    "sha256": node["sha256"],
                    "format": format,
                })),
                path,
                kind,
                unavailable: None,
            })
        })
        .collect()
}

/// `projectedFileComponents`: files and slices with authenticated content.
pub fn file_components(entries: &[Entry]) -> Vec<Value> {
    entries
        .iter()
        .filter(|entry| matches!(entry.kind.as_str(), "file" | "slice"))
        .filter_map(|entry| entry.component.clone())
        .collect()
}

/// Every unavailable occurrence, in inventory order.
pub fn unavailable_components(entries: &[Entry]) -> Vec<Value> {
    entries
        .iter()
        .filter_map(|entry| entry.unavailable.clone())
        .collect()
}

/// `projectionCoverage(inventory, budgetComplete)`.
pub fn coverage(inventory: &InventorySet, budget_complete: bool) -> Value {
    json!({
        "status": if inventory.has_complete_coverage("container-entries") && budget_complete {
            "complete-within-inventory"
        } else {
            "partial"
        },
        "inventory_complete": inventory.complete,
    })
}

/// One left/right group of `projectCartesianCandidates`.
pub struct CandidateGroup<'a> {
    pub left: Vec<&'a Value>,
    pub right: Vec<&'a Value>,
}

/// `projectCartesianCandidates`: a deterministic prefix of grouped Cartesian
/// candidates within the retained JSON byte budget.
pub fn cartesian_candidates(
    groups: &[CandidateGroup<'_>],
    create: impl Fn(&str, &Value) -> Value,
) -> (Vec<Value>, Value) {
    let total: usize = groups
        .iter()
        .map(|group| group.left.len() * group.right.len())
        .sum();
    let prepared: Vec<(Vec<(&str, usize)>, Vec<(&Value, usize)>)> = groups
        .iter()
        .map(|group| {
            let left = group
                .left
                .iter()
                .map(|value| {
                    let path = path_of(value);
                    (path, json_len(&Value::String(path.to_owned())))
                })
                .collect();
            let right = group
                .right
                .iter()
                .map(|value| (*value, json_len(&create("", value)) - 2))
                .collect();
            (left, right)
        })
        .collect();
    let mut estimated_full = 2 + total.saturating_sub(1);
    for (left, right) in &prepared {
        estimated_full += left.len() * right.iter().map(|(_, overhead)| overhead).sum::<usize>()
            + right.len() * left.iter().map(|(_, bytes)| bytes).sum::<usize>();
    }
    let emit_all = estimated_full <= MAX_BRIDGE_CANDIDATE_JSON_BYTES;
    let mut candidates = Vec::new();
    let mut retained = 2usize;
    'groups: for (left, right) in &prepared {
        for (path, path_bytes) in left {
            for (value, overhead) in right {
                let additional = overhead + path_bytes + usize::from(!candidates.is_empty());
                if !emit_all && retained + additional > MAX_BRIDGE_CANDIDATE_JSON_BYTES {
                    break 'groups;
                }
                candidates.push(create(path, value));
                retained += additional;
            }
        }
    }
    let emitted = candidates.len();
    let coverage = json!({
        "status": if emitted == total { "complete" } else { "partial" },
        "total_candidates": total,
        "emitted_candidates": emitted,
        "omitted_candidates": total - emitted,
    });
    (candidates, coverage)
}

fn json_len(value: &Value) -> usize {
    serde_json::to_string(value)
        .map(|text| text.len())
        .unwrap_or(0)
}

/// Path of a projected component.
pub fn path_of(component: &Value) -> &str {
    component["path"].as_str().unwrap_or_default()
}

/// Inventory format of a projected component.
pub fn format_of(component: &Value) -> &str {
    component["format"].as_str().unwrap_or_default()
}

/// `nativeRuntimeConvention`: a runtime family named by one complete segment.
pub fn native_runtime_convention(path: &str) -> Option<&'static str> {
    for segment in path.split('/') {
        let folded = segment.to_lowercase();
        match folded.as_str() {
            "react.framework"
            | "reactnative.framework"
            | "libreactnative.so"
            | "libreactnativejni.so"
            | "libhermes_executor.so"
            | "libhermes.so"
            | "hermes.framework" => return Some("react-native"),
            "libflutter.so" | "flutter.framework" => return Some("flutter"),
            "libunity.so" | "unityframework.framework" => return Some("unity"),
            _ => {}
        }
    }
    None
}

/// `isSwiftRuntimeLibrary`: a `libswift*.dylib` segment.
pub fn is_swift_runtime_library(path: &str) -> bool {
    path.split('/').any(|segment| {
        let folded = segment.to_lowercase();
        folded
            .strip_prefix("libswift")
            .and_then(|rest| rest.strip_suffix(".dylib"))
            .is_some_and(|middle| !middle.is_empty())
    })
}

/// Fold one character as a Unicode-aware case-insensitive regular
/// expression does for the ASCII vocabulary these projections match.
fn fold(character: char) -> char {
    match character {
        '\u{17F}' => 's',
        '\u{212A}' => 'k',
        _ => {
            let mut lower = character.to_lowercase();
            match (lower.next(), lower.next()) {
                (Some(single), None) => single,
                _ => character,
            }
        }
    }
}

/// Case-insensitive equality (regular expression `iu` semantics).
pub fn eq_ci(actual: &str, expected: &str) -> bool {
    actual.chars().count() == expected.chars().count()
        && actual
            .chars()
            .zip(expected.chars())
            .all(|(a, b)| fold(a) == fold(b))
}

/// Case-insensitive suffix test (regular expression `iu` semantics).
pub fn ends_with_ci(actual: &str, suffix: &str) -> bool {
    let count = suffix.chars().count();
    let total = actual.chars().count();
    total >= count
        && eq_ci(
            &actual.chars().skip(total - count).collect::<String>(),
            suffix,
        )
}

/// Case-insensitive prefix test (regular expression `iu` semantics).
pub fn starts_with_ci(actual: &str, prefix: &str) -> bool {
    let count = prefix.chars().count();
    actual.chars().count() >= count
        && eq_ci(&actual.chars().take(count).collect::<String>(), prefix)
}

/// `[^/]+<extension>$` on the final segment: a non-empty stem and the suffix.
pub fn segment_has_extension(segment: &str, extension: &str) -> bool {
    segment.chars().count() > extension.chars().count() && ends_with_ci(segment, extension)
}

/// Last path segment.
pub fn last_segment(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

/// `(?:^|\/)<directory>\/[^/]+\/<prefix>[^/]+<extension>$` (case-insensitive).
pub fn library_layout(path: &str, directory: &str, prefix: &str, extension: &str) -> bool {
    let segments: Vec<&str> = path.split('/').collect();
    let count = segments.len();
    if count < 3 {
        return false;
    }
    let (container, abi, file) = (
        segments[count - 3],
        segments[count - 2],
        segments[count - 1],
    );
    if !eq_ci(container, directory) || abi.is_empty() || !starts_with_ci(file, prefix) {
        return false;
    }
    let rest: String = file.chars().skip(prefix.chars().count()).collect();
    segment_has_extension(&rest, extension)
}

/// `^<directory>\/[^/]+\.(?:<extensions>)$` (case-insensitive).
pub fn direct_child_with_extension(path: &str, directory: &str, extensions: &[&str]) -> bool {
    let mut segments = path.split('/');
    match (segments.next(), segments.next(), segments.next()) {
        (Some(first), Some(file), None) => {
            eq_ci(first, directory)
                && extensions
                    .iter()
                    .any(|extension| segment_has_extension(file, extension))
        }
        _ => false,
    }
}

/// `evidence.map(id).sort(compareUnicodeCodePoints)` (duplicates kept).
pub fn source_ids(parsed: &ParsedInventorySet) -> Vec<String> {
    let mut ids: Vec<String> = parsed
        .evidence
        .iter()
        .map(|evidence| {
            evidence["evidence_id"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    ids.sort();
    ids
}

/// `projectionDigest(value, label)`.
pub fn projection_digest(value: &Value, label: &str) -> Result<String, Rejection> {
    inventory::digest(value, label)
        .map_err(|_| Rejection::type_error(format!("{label} is not canonical JSON")))
}

/// Add `projection_id` (`<prefix>_<digest of the id-less projection>`) in
/// the result schema's leading position.
pub fn identified(result: Value, prefix: &str, label: &str) -> Result<Value, Rejection> {
    let digest = projection_digest(&result, label)?;
    let mut output = serde_json::Map::new();
    output.insert(
        "projection_id".into(),
        Value::String(format!("{prefix}_{digest}")),
    );
    if let Value::Object(fields) = result {
        output.extend(fields);
    }
    Ok(Value::Object(output))
}

/// The service-level options of `projectInventoryEvidence`.
pub struct InventoryProjection {
    pub operation: &'static str,
    pub predicate_type: &'static str,
    pub provider: (&'static str, &'static str),
    /// Android always reports `apk`; Apple and HarmonyOS copy the first
    /// subject's format.
    pub fixed_subject_format: Option<&'static str>,
    pub project: fn(&ParsedInventorySet) -> Result<Value, Rejection>,
}

/// `projectInventoryEvidence`: project the parsed request and wrap the
/// deterministic result in derived Evidence.
pub fn project_inventory_evidence(
    options: &InventoryProjection,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    let carriers = input["inventory_evidence"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    let parsed = inventory::parse_artifact_inventory_evidence(&carriers)
        .map_err(|rejection| rejection.into_input_error(options.operation))?;
    let result = (options.project)(&parsed)
        .map_err(|rejection| rejection.into_input_error(options.operation))?;
    let first_subject = &parsed.evidence[0]["subject"];
    let target = (!first_subject.is_null()).then(|| SubjectTarget {
        path: first_subject["local_path"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        sha256: result["root_sha256"]
            .as_str()
            .unwrap_or_default()
            .to_owned(),
        format: options
            .fixed_subject_format
            .map(str::to_owned)
            .or_else(|| first_subject["format"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "unknown".to_owned()),
        architecture: None,
    });
    let source_ids: Vec<String> = result["source_evidence_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let limitations: Vec<String> = result["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let provider = EvidenceProvider::new(options.provider.0, options.provider.1, Some("1".into()));
    let observation = Observation::new(
        options.operation,
        json!({ "inventory_evidence_ids": source_ids }),
        result,
    )
    .predicate(options.predicate_type)
    .raw(Value::Null)
    .confidence("inferred")
    .authority("analyst-inference")
    .limitations(limitations)
    .links(source_ids);
    Evidence::create(target.as_ref(), &provider, observation).map_err(|_| {
        AnalysisError::protocol(format!(
            "{} produced an invalid result",
            match options.operation {
                "project_android_application_graph" => "Android application projection",
                "project_apple_application_graph" => "Apple application projection",
                _ => "HarmonyOS application projection",
            }
        ))
    })
}
