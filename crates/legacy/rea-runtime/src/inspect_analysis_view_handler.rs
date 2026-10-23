//! Runtime boundary for captured-Evidence-only analysis views.
//!
//! The shared analysis-view dispatcher owns provider-specific routing. This
//! adapter validates the public request envelope and forwards a complete
//! retained Evidence record with its caller-selected bounded view.

use rea_application::analysis_view;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, value::RawValue};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_analysis_view";

/// Project one captured analysis Evidence record into a bounded view.
///
/// The shared projection owns the lossless JSON text; returning it unchanged
/// keeps unpaired UTF-16 metadata intact for both CLI and MCP delivery.
pub fn project(input: &Value) -> Result<Box<RawValue>, Failure> {
    let object = request_object(input)?;
    let parent = required_object(object, "parent_evidence")?;
    let view = required_object(object, "view")?;

    analysis_view::project(parent, view)
}

fn request_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Request must be an object."))?;
    if object.len() != 2 || !object.contains_key("parent_evidence") || !object.contains_key("view")
    {
        return Err(invalid(
            "Request must contain only parent_evidence and view.",
        ));
    }
    Ok(object)
}

fn required_object<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value, Failure> {
    object
        .get(field)
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid(&format!("{field} must be an object.")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Analysis view input is invalid.".into(),
        false,
        "Provide complete retained Evidence and a bounded view, then retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
