//! Authenticated retained `inspect_web_network_capture` results.
//!
//! Compatibility owners: `webNetworkCaptureSchema` (strict alternatives plus
//! `refineCoverage`) in `src/domain/webNetworkCapture.ts` and
//! `admitHarCaptureParent` in `WebNetworkProjectionAccumulator.ts`.
use super::budget::Budget;
use crate::common::schema::{self, Issue, IssueKind};
use crate::common::view::{OPERATION, Parent, view_error};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::sync::Arc;

pub const CAPTURE_OPERATION: &str = "inspect_web_network_capture";

type Parsed = Result<Arc<Value>, Vec<Issue>>;

/// `webNetworkCaptureSchema.safeParse(parent.normalizedResult)`, cached for
/// immutable parents. Issues are relative to the normalized result.
pub fn parse_capture(parent: &Parent<'_>) -> Result<Parsed, AnalysisError> {
    let parsed = parent.cached("web_network_capture", || {
        let Some(root) = schema::tool_result_schema(CAPTURE_OPERATION) else {
            return Err(AnalysisError::output(
                OPERATION,
                format!("The {CAPTURE_OPERATION} result contract is unavailable."),
            ));
        };
        Ok(schema::parse_strict(&root, parent.normalized_result)
            .and_then(|capture| refine_coverage(&capture).map(|()| Arc::new(capture))))
    })?;
    Ok((*parsed).clone())
}

/// `refineCoverage`: retained ordinals are unique and below the declared total.
fn refine_coverage(capture: &Value) -> Result<(), Vec<Issue>> {
    let total = capture
        .get("total_records")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let mut seen = HashSet::new();
    for (index, record) in capture
        .get("records")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .enumerate()
    {
        let ordinal = record.get("ordinal").and_then(Value::as_f64).unwrap_or(0.0);
        if ordinal >= total || !seen.insert(ordinal.to_bits()) {
            return Err(vec![Issue {
                path: vec![json!("records"), json!(index), json!("ordinal")],
                kind: IssueKind::Custom {
                    message:
                        "Retained ordinals must be unique and within the declared capture total."
                            .into(),
                },
                aborts: false,
            }]);
        }
    }
    Ok(())
}

/// `parent.subject` names exactly the report's artifact path and SHA-256.
pub fn subject_identifies(parent: &Parent<'_>, artifact: &Value) -> bool {
    parent.subject.is_object()
        && parent.subject.get("local_path") == artifact.get("path")
        && parent
            .subject
            .get("digest")
            .and_then(|digest| digest.get("sha256"))
            == artifact.get("sha256")
}

/// The capture-subject correction shared by capture and manifest views.
pub fn subject_error() -> AnalysisError {
    view_error(
        &["source", "subject"],
        "invalid_value",
        "Capture parent subject must identify the report's exact path and SHA-256.",
    )
}

fn unsupported(parent: &Parent<'_>, reason: impl Into<String>) -> AnalysisError {
    AnalysisError::unsupported_target(OPERATION, parent.evidence_id, reason)
}

/// `z.object({ sensitive_value_count: z.number().int().nonnegative() })`.
fn sensitive_value_count(parameters: &Value) -> Option<f64> {
    let count = parameters
        .as_object()?
        .get("sensitive_value_count")?
        .as_f64()?;
    (count.fract() == 0.0 && (0.0..=9_007_199_254_740_991.0).contains(&count)).then_some(count)
}

/// `admitHarCaptureParent`: authenticate and gate a retained HAR parent before
/// a grouping view reads any record.
pub fn admit_har_capture_parent(
    parent: &Parent<'_>,
    view_kind: &str,
    budget: &mut Budget,
) -> Result<Arc<Value>, AnalysisError> {
    if parent.operation != CAPTURE_OPERATION {
        let required = if view_kind == "environment-manifest" {
            "inspect_web_network_capture or capture_browser_scenario"
        } else {
            "inspect_web_network_capture"
        };
        return Err(unsupported(
            parent,
            format!(
                "View {view_kind} is unsupported for parent operation {}; {view_kind} requires {required}.",
                parent.operation
            ),
        ));
    }
    budget.admit_capture_clone(parent.normalized_result, false)?;
    let Ok(capture) = parse_capture(parent)? else {
        return Err(view_error(
            &["source"],
            "invalid_value",
            "Parent Evidence result does not match inspect_web_network_capture.",
        ));
    };
    let format = capture
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if format != "har" {
        return Err(unsupported(
            parent,
            format!("{view_kind} does not support capture format {format}."),
        ));
    }
    let artifact = capture.get("artifact").unwrap_or(&Value::Null);
    if view_kind == "environment-manifest"
        && !artifact.get("sha256").is_none_or(Value::is_null)
        && !subject_identifies(parent, artifact)
    {
        return Err(subject_error());
    }
    match sensitive_value_count(parent.parameters) {
        Some(count) if count == 0.0 => Ok(capture),
        _ => Err(unsupported(parent, "sensitive_values_unretained")),
    }
}
