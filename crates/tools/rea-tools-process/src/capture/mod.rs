//! Verified process-capture values.
//!
//! Compatibility owners: `parseProcessCapture` (`processCaptureParsing.ts`),
//! `processCaptureSchema` (`processCapture.ts`) and
//! `collectProcessCaptureIssues` (`processCaptureValidation.ts`).
pub mod schema;
pub mod validation;

use crate::shape::{self, Issue};
use serde_json::Value;
use std::sync::OnceLock;

/// Why a value is not a verified process capture.
pub enum CaptureError {
    /// The original `ZodError`: shape issues in Zod order.
    Shape(Vec<Issue>),
    /// The original `TypeError` listing every custom invariant issue.
    Invariant(String),
}

impl CaptureError {
    /// `describeValidationFailure(cause)`.
    pub fn describe(&self) -> String {
        match self {
            Self::Shape(issues) => shape::describe(issues),
            Self::Invariant(message) => message.clone(),
        }
    }
}

fn capture_shape() -> &'static shape::Shape {
    static SHAPE: OnceLock<shape::Shape> = OnceLock::new();
    SHAPE.get_or_init(schema::capture)
}

/// `parseProcessCapture`: the Zod output (unknown keys of non-strict
/// objects stripped, keys in shape order) once every invariant holds.
pub fn parse(input: &Value) -> Result<Value, CaptureError> {
    let mut issues = Vec::new();
    let parsed = capture_shape().parse(Some(input), &mut Vec::new(), &mut issues);
    let mut custom = Vec::new();
    // Nested `processCaptureFinalizationSchema.superRefine` runs when its
    // own subtree has no aborting issue.
    if let Some(finalization) = parsed.get("exit").and_then(|exit| exit.get("finalization"))
        && finalization.is_object()
        && !shape::aborted_under(&issues, &["exit", "finalization"])
    {
        custom.extend(validation::finalization_refinements(
            finalization,
            "exit.finalization",
        ));
    }
    // The top-level refinement runs unless an aborting issue exists.
    if !shape::aborted_under(&issues, &[]) {
        if text_at(&parsed, &["settlement", "cleanup_outcome"]) == Some("failed") {
            custom.push((
                "settlement.cleanup_outcome".to_owned(),
                "verified captures cannot contain failed cleanup".to_owned(),
            ));
        }
        custom.extend(validation::collect_issues(&parsed));
    }
    if !custom.is_empty() {
        return Err(CaptureError::Invariant(format!(
            "Invalid process capture: {}",
            custom
                .iter()
                .map(|(path, message)| format!("{path}: {message}"))
                .collect::<Vec<_>>()
                .join("; ")
        )));
    }
    if !issues.is_empty() {
        return Err(CaptureError::Shape(issues));
    }
    Ok(parsed)
}

fn text_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |value, key| value.get(*key))
        .and_then(Value::as_str)
}
