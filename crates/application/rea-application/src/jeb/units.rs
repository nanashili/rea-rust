//! Projection of a captured JEB code-unit inventory page.
//!
//! JEB owns unit discovery, wildcard matching, and project state.  This
//! module only validates the page returned by that adapter and preserves its
//! caller selections, ordering, identity, and coverage.  It never queries
//! JEB or opens or mutates a project.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "list_jeb_units";

const MAX_ENDPOINT_BYTES: usize = 2 * 1024;
const MAX_FILTER_BYTES: usize = 16 * 1024;
const MAX_PARENT_PATH_BYTES: usize = 16 * 1024;
const MAX_UNIT_PATH_BYTES: usize = 16 * 1024;
const MAX_UNIT_TYPE_BYTES: usize = 4 * 1024;
const MAX_PAGE_COUNT: u64 = 100;
const MAX_UNITS: usize = MAX_PAGE_COUNT as usize;

/// Engine provenance captured alongside the inventory page.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineProvenance {
    pub name: String,
    pub version: Option<String>,
    pub endpoint: String,
    pub gui_client: Option<bool>,
}

/// Caller-selected project/session identity retained with a page.
///
/// Both values are optional because the JEB protocol does not expose stable
/// identifiers for every client.  An omitted value remains unknown rather
/// than being replaced by a guessed path or generated identifier.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProjectIdentity {
    pub session_id: Option<String>,
    pub project_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JebUnit {
    pub unit_path: String,
    pub unit_type: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Coverage {
    Complete,
    Partial,
}

/// One provider-returned page, including all request selections.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JebUnitsInput {
    pub engine: EngineProvenance,
    #[serde(default)]
    pub identity: ProjectIdentity,
    pub filter: Option<String>,
    pub parent_unit_path: Option<String>,
    pub index: u64,
    pub count: u64,
    pub units: Vec<JebUnit>,
    pub coverage: Coverage,
}

/// Native result projection.  The page's order is retained exactly.
pub type JebUnits = JebUnitsInput;

/// Validate and preserve a captured JEB unit page.
pub fn normalize(input: JebUnitsInput) -> Result<JebUnits, Failure> {
    validate_engine(&input.engine)?;
    validate_identity(&input.identity)?;
    validate_optional_text(input.filter.as_deref(), MAX_FILTER_BYTES, "filter")?;
    validate_optional_text(
        input.parent_unit_path.as_deref(),
        MAX_PARENT_PATH_BYTES,
        "parent_unit_path",
    )?;

    if input.count == 0 || input.count > MAX_PAGE_COUNT {
        return Err(invalid("JEB unit page count must be between 1 and 100"));
    }
    if input.units.len() > MAX_UNITS || input.units.len() as u64 > input.count {
        return Err(invalid("JEB unit page exceeds its requested count"));
    }

    let expected_coverage = if input.units.len() < input.count as usize {
        Coverage::Complete
    } else {
        Coverage::Partial
    };
    if input.coverage != expected_coverage {
        return Err(invalid(
            "JEB unit page coverage does not match the returned page length",
        ));
    }

    for unit in &input.units {
        validate_required_text(&unit.unit_path, MAX_UNIT_PATH_BYTES, "unit_path")?;
        validate_required_text(&unit.unit_type, MAX_UNIT_TYPE_BYTES, "unit_type")?;
    }

    Ok(input)
}

/// Parse and project already-returned JEB inventory facts.
pub fn normalize_value(input: &Value) -> Result<Value, Failure> {
    let parsed: JebUnitsInput = serde_json::from_value(input.clone())
        .map_err(|error| invalid(&format!("invalid JEB unit inventory: {error}")))?;
    let normalized = normalize(parsed)?;
    // `identity` is adapter provenance used for validation, not part of the
    // public list_jeb_units result schema.  Construct the public projection
    // explicitly so serde cannot leak internal capture fields into Evidence.
    serde_json::to_value(serde_json::json!({
        "engine": normalized.engine,
        "filter": normalized.filter,
        "parent_unit_path": normalized.parent_unit_path,
        "index": normalized.index,
        "count": normalized.count,
        "units": normalized.units,
        "coverage": normalized.coverage,
    }))
    .map_err(|_| invalid("JEB unit inventory projection is not serializable"))
}

/// Confirm that a runtime result is exactly the normalized captured page.
/// This keeps the provider's source order and caller selections immutable at
/// the Evidence retention boundary.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    let expected = normalize_value(input)?;
    if result != expected {
        return Err(invalid("JEB unit result does not match the captured page"));
    }
    Ok(result)
}

/// Validate a captured page without contacting the provider.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let _ = normalize_value(input)?;
    Ok(())
}

fn validate_engine(engine: &EngineProvenance) -> Result<(), Failure> {
    if engine.name != "jeb" {
        return Err(invalid("JEB unit inventory provenance must name JEB"));
    }
    validate_required_text(&engine.endpoint, MAX_ENDPOINT_BYTES, "engine.endpoint")
}

fn validate_identity(identity: &ProjectIdentity) -> Result<(), Failure> {
    validate_optional_text(
        identity.session_id.as_deref(),
        MAX_FILTER_BYTES,
        "session_id",
    )?;
    validate_optional_text(
        identity.project_id.as_deref(),
        MAX_FILTER_BYTES,
        "project_id",
    )
}

fn validate_required_text(value: &str, max_bytes: usize, field: &str) -> Result<(), Failure> {
    if value.is_empty() {
        return Err(invalid(&format!("{field} must be non-empty")));
    }
    if value.len() > max_bytes {
        return Err(resource(&format!("{field} exceeds its byte limit")));
    }
    Ok(())
}

fn validate_optional_text(
    value: Option<&str>,
    max_bytes: usize,
    field: &str,
) -> Result<(), Failure> {
    if let Some(value) = value {
        validate_required_text(value, max_bytes, field)?;
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a bounded JEB unit page captured from the selected project session.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Request a smaller JEB unit page within the native bounds.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
