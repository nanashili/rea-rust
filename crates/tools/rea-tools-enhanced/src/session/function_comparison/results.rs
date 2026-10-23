//! Dimension result construction and overall status.
//!
//! Compatibility owner: `functionComparisonResults.ts`.

use super::canonical::digest_canonical_value;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

const OPERATION: &str = "Function comparison";

/// Inputs for a resolved (`unchanged`/`changed`) dimension.
pub struct DimensionResultInput<'a> {
    pub dimension: &'static str,
    pub changed: bool,
    pub left: &'a Value,
    pub right: &'a Value,
    pub links: &'a [String],
    pub providers_differ: bool,
    pub left_count: Option<i64>,
    pub right_count: Option<i64>,
    pub text_delta: Value,
    pub limitations: Vec<String>,
}

fn digest(value: &Value) -> Result<String, AnalysisError> {
    digest_canonical_value(value, OPERATION)
}

/// `dimensionResult`: object field order matches the TS spread of `context`
/// then the status/conclusion fields.
pub fn dimension_result(input: DimensionResultInput<'_>) -> Result<Value, AnalysisError> {
    let mut object = serde_json::Map::new();
    object.insert("dimension".into(), json!(input.dimension));
    object.insert("left_digest".into(), json!(digest(input.left)?));
    object.insert("right_digest".into(), json!(digest(input.right)?));
    object.insert("left_count".into(), count_value(input.left_count));
    object.insert("right_count".into(), count_value(input.right_count));
    object.insert("text_delta".into(), input.text_delta);
    object.insert("evidence_links".into(), json!(input.links));
    object.insert("limitations".into(), json!(input.limitations));
    if input.changed {
        object.insert("status".into(), json!("changed"));
        object.insert(
            "conclusion_kind".into(),
            json!(if input.providers_differ {
                "contradiction"
            } else {
                "derived_relationship"
            }),
        );
    } else {
        object.insert("status".into(), json!("unchanged"));
        object.insert("conclusion_kind".into(), json!("derived_relationship"));
    }
    Ok(Value::Object(object))
}

/// `unresolvedDimension`.
pub fn unresolved_dimension(
    dimension: &'static str,
    links: &[String],
    left_count: Option<i64>,
    right_count: Option<i64>,
    limitations: Vec<String>,
) -> Value {
    json!({
        "dimension": dimension,
        "status": "unknown",
        "left_digest": Value::Null,
        "right_digest": Value::Null,
        "left_count": count_value(left_count),
        "right_count": count_value(right_count),
        "text_delta": Value::Null,
        "conclusion_kind": "unresolved_branch",
        "evidence_links": links,
        "limitations": limitations,
    })
}

fn count_value(count: Option<i64>) -> Value {
    match count {
        Some(value) => json!(value),
        None => Value::Null,
    }
}

/// Read a dimension's `status` field.
pub fn dimension_status(dimension: &Value) -> &str {
    dimension["status"].as_str().unwrap_or_default()
}

/// `overallStatus`.
pub fn overall_status(dimensions: &[Value], match_status: &str) -> &'static str {
    if match_status == "mismatched" {
        return "changed";
    }
    if match_status == "ambiguous" {
        return "unknown";
    }
    if dimensions
        .iter()
        .any(|dimension| dimension_status(dimension) == "changed")
    {
        return "changed";
    }
    if dimensions
        .iter()
        .any(|dimension| dimension_status(dimension) == "unknown")
    {
        return "unknown";
    }
    "unchanged"
}

/// `summarize`.
pub fn summarize(dimensions: &[Value]) -> Value {
    let count = |status: &str| {
        dimensions
            .iter()
            .filter(|dimension| dimension_status(dimension) == status)
            .count()
    };
    json!({
        "unchanged": count("unchanged"),
        "changed": count("changed"),
        "unknown": count("unknown"),
    })
}
