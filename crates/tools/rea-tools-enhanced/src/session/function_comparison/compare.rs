//! `compareFunctions`: deterministic 8-dimension function comparison.
//!
//! Compatibility owner: `domain/functionComparison.ts`.
use super::canonical::canonical_json;
use super::dimensions::{ComparisonContext, compare_dimensions};
use super::normalization::{code_point_order, function_match};
use super::results::{dimension_status, overall_status, summarize};
use super::snapshot::{FunctionSnapshot, parse_function_evidence};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::HashSet;
const OPERATION: &str = "Function comparison";
/// Result of a function comparison: the public payload plus its limitations.
pub struct FunctionComparison {
    pub value: Value,
    pub status: String,
    pub limitations: Vec<String>,
    /// Dimensions whose status is reported (`changed`/`unknown`) for scoping.
    pub reported_dimensions: Vec<String>,
}
/// `compareFunctions`. Reusable entry point for the investigation tools.
#[allow(dead_code)]
pub fn compare_functions(
    left_input: &Value,
    right_input: &Value,
) -> Result<FunctionComparison, AnalysisError> {
    let left = parse_function_evidence(left_input)?;
    let right = parse_function_evidence(right_input)?;
    compare_snapshots(left, right)
}
/// Compare two already-parsed snapshots.
pub fn compare_snapshots(
    left: FunctionSnapshot,
    right: FunctionSnapshot,
) -> Result<FunctionComparison, AnalysisError> {
    let links = vec![left.evidence_id.clone(), right.evidence_id.clone()];
    let left_provider = canonical_json(&left.evidence["provider"], OPERATION)?;
    let right_provider = canonical_json(&right.evidence["provider"], OPERATION)?;
    let providers_differ = left_provider != right_provider;
    let context = ComparisonContext {
        links: &links,
        providers_differ,
    };
    let dimensions = compare_dimensions(&left, &right, &context)?;
    let function_match = function_match(&left.dossier, &right.dossier);
    let changes: Vec<Value> = dimensions
        .iter()
        .filter(|dimension| dimension_status(dimension) != "unchanged")
        .cloned()
        .collect();
    let status = overall_status(&dimensions, function_match.status);
    // limitations: dedup preserving first-seen order, then sort by code points.
    let mut limitations: Vec<String> = Vec::new();
    for item in &left.limitations {
        limitations.push(format!("Left: {item}"));
    }
    for item in &right.limitations {
        limitations.push(format!("Right: {item}"));
    }
    if providers_differ {
        limitations.push(
            "Provider-specific pseudocode and assembly representations were not equated."
                .to_owned(),
        );
    }
    let mut seen = HashSet::new();
    limitations.retain(|item| seen.insert(item.clone()));
    limitations.sort_by(|a, b| code_point_order(a, b));
    // comparisonUnknownInput's dimension set: filtered by the overall status.
    let reported_dimensions: Vec<String> = dimensions
        .iter()
        .filter(|dimension| {
            let dimension_status = dimension_status(dimension);
            if status == "unknown" {
                dimension_status == "unknown"
            } else {
                dimension_status == "changed"
            }
        })
        .map(|dimension| {
            dimension["dimension"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        })
        .collect();
    let summary = summarize(&dimensions);
    // functionComparisonResultSchema shape order.
    let value = json!({
        "status": status,
        "function_match": function_match.to_value(),
        "left_subject_sha256": left.subject_sha256(),
        "right_subject_sha256": right.subject_sha256(),
        "summary": summary,
        "dimensions": dimensions,
        "changes": changes,
        "limitations": limitations,
    });
    Ok(FunctionComparison {
        value,
        status: status.to_owned(),
        limitations,
        reported_dimensions,
    })
}
