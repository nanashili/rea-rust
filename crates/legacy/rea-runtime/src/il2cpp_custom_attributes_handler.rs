//! Runtime adapter for `project_il2cpp_custom_attributes`.
//!
//! Attribute ranges and payload facts are supplied by a static decoder or a
//! retained capture. The application projection owns validation and joining;
//! this boundary does not read artifacts, execute constructors, or resolve
//! absent and ambiguous links.

use rea_application::il2cpp;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Stable public operation name.
pub const OPERATION: &str = il2cpp::custom_attributes::OPERATION;

/// Project caller-supplied IL2CPP custom-attribute ranges and payload facts.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    dispatch_typed(&input)
}

/// Project an already-selected static or captured request.
pub fn dispatch_typed(input: &Value) -> Result<Value, Failure> {
    validate_request_shape(input)?;

    il2cpp::custom_attributes::project(input)
}

fn validate_request_shape(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Request must be an object."))?;

    if object.contains_key("metadata") {
        validate_metadata_request(object)
    } else {
        validate_fields(object, "direct request")?;
        require_range_alias(object, "direct request")
    }
}

fn validate_metadata_request(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in object.keys() {
        if field != "metadata" && !is_base64_alias(field) {
            return Err(invalid(&format!(
                "Unsupported metadata request field `{field}`."
            )));
        }
    }

    let metadata = object
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("metadata must be an object."))?;

    validate_fields(metadata, "metadata")?;
    require_range_alias(metadata, "metadata")
}

fn validate_fields(object: &Map<String, Value>, scope: &str) -> Result<(), Failure> {
    for field in object.keys() {
        if !is_range_alias(field) && !is_data_alias(field) && !is_metadata_rows_alias(field) {
            return Err(invalid(&format!("Unsupported {scope} field `{field}`.")));
        }
    }

    Ok(())
}

fn require_range_alias(object: &Map<String, Value>, scope: &str) -> Result<(), Failure> {
    if is_range_alias_present(object) {
        return Ok(());
    }

    Err(invalid(&format!(
        "{scope} must contain attribute_data_ranges, attributeDataRanges, or ranges."
    )))
}

fn is_range_alias_present(object: &Map<String, Value>) -> bool {
    ["attribute_data_ranges", "attributeDataRanges", "ranges"]
        .iter()
        .any(|field| object.contains_key(*field))
}

fn is_range_alias(field: &str) -> bool {
    matches!(
        field,
        "attribute_data_ranges" | "attributeDataRanges" | "ranges"
    )
}

fn is_data_alias(field: &str) -> bool {
    matches!(
        field,
        "attribute_data" | "attributeData" | "data" | "attribute_data_base64" | "data_base64"
    )
}

fn is_base64_alias(field: &str) -> bool {
    matches!(field, "attribute_data_base64" | "data_base64")
}

fn is_metadata_rows_alias(field: &str) -> bool {
    matches!(
        field,
        "types"
            | "type_definitions"
            | "typeDefinitions"
            | "methods"
            | "method_definitions"
            | "methodDefinitions"
            | "fields"
            | "field_definitions"
            | "fieldDefinitions"
            | "events"
            | "event_definitions"
            | "eventDefinitions"
            | "properties"
            | "property_definitions"
            | "propertyDefinitions"
            | "parameters"
            | "parameter_definitions"
            | "parameterDefinitions"
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP custom-attributes input is invalid.".into(),
        false,
        "Provide one bounded attribute-range collection from static or captured evidence, then retry."
            .into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
