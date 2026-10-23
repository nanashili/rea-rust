//! Validation and retention of provider function-analysis observations.
//!
//! The provider owns decoding and address resolution.  This boundary only
//! checks the shape of those facts, retains the provider values verbatim, and
//! carries envelope metadata into the application layer.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "analyze_function";
const MAX_ARRAY_ITEMS: usize = 65_536;

/// Validate the caller-owned request before it crosses an adapter boundary.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    if object.len() != 1 || !object.contains_key("procedure") {
        return Err(invalid(
            "analyze_function input must contain only procedure",
        ));
    }
    require_non_empty_string(object.get("procedure"), "procedure")
}

/// Parse a bridge observation or retained Evidence result into one stable shape.
pub fn normalize(input: &Value) -> Result<Value, Failure> {
    let source = input
        .get("normalized_result")
        .or_else(|| input.get("result"))
        .unwrap_or(input);
    let observation = source.get("value").unwrap_or(source);
    let dossier = observation.get("dossier").unwrap_or(observation);
    validate_dossier(dossier)?;

    let mut normalized = Map::new();
    normalized.insert("dossier".into(), dossier.clone());
    copy_array_from_sources(input, source, &mut normalized, "limitations")?;
    copy_from_sources(input, source, &mut normalized, "relationship_coverage");
    copy_from_sources(input, source, &mut normalized, "selection");
    copy_from_sources(input, source, &mut normalized, "analysis_profile");
    copy_from_sources(input, source, &mut normalized, "locations");
    Ok(Value::Object(normalized))
}

/// Alias used by application adapters that call projections uniformly.
pub fn project(input: &Value) -> Result<Value, Failure> {
    normalize(input)
}

/// Validate the provider-neutral function dossier without rewriting its facts.
pub fn validate_dossier(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("function dossier must be an object"))?;
    let required = [
        "procedure",
        "pseudocode",
        "assembly",
        "comments",
        "callers",
        "callees",
        "incoming_references",
        "outgoing_references",
        "referenced_strings",
        "referenced_names",
        "basic_blocks",
        "native_api",
        "native_value_flow",
        "limitations",
    ];
    for field in required {
        if !object.contains_key(field) {
            return Err(invalid(&format!("function dossier requires {field}")));
        }
    }
    reject_unknown_fields(
        object,
        &[
            "procedure",
            "pseudocode",
            "assembly",
            "comments",
            "callers",
            "callees",
            "incoming_references",
            "outgoing_references",
            "unresolved_calls",
            "referenced_strings",
            "referenced_names",
            "swift_string_literals",
            "swift_string_literal_omissions",
            "basic_blocks",
            "native_api",
            "native_value_flow",
            "facet_availability",
            "limitations",
        ],
        "function dossier",
    )?;

    validate_identity(object.get("procedure"), "procedure")?;
    let procedure = object
        .get("procedure")
        .and_then(Value::as_object)
        .expect("validated procedure");
    if !procedure.contains_key("signature") || !procedure.contains_key("locals") {
        return Err(invalid("procedure must retain signature and locals"));
    }
    if procedure.get("signature") != Some(&Value::Null) {
        require_string(procedure.get("signature"), "procedure.signature")?;
    }
    validate_locals(procedure.get("locals"))?;
    require_string(object.get("pseudocode"), "pseudocode")?;
    validate_string_array(object.get("assembly"), "assembly")?;
    validate_comments(object.get("comments"))?;
    validate_identities(object.get("callers"), "callers")?;
    validate_identities(object.get("callees"), "callees")?;
    validate_references(object.get("incoming_references"), "incoming_references")?;
    validate_references(object.get("outgoing_references"), "outgoing_references")?;
    validate_optional_unresolved_calls(object.get("unresolved_calls"))?;
    validate_referenced_strings(object.get("referenced_strings"))?;
    validate_referenced_names(object.get("referenced_names"))?;
    validate_swift_pair(object)?;
    validate_basic_blocks(object.get("basic_blocks"))?;
    validate_nullable_object(object.get("native_api"), "native_api")?;
    validate_nullable_object(object.get("native_value_flow"), "native_value_flow")?;
    validate_facets(object.get("facet_availability"))?;
    validate_string_array(object.get("limitations"), "limitations")
}

fn validate_identity(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("{field} must be an object")))?;
    reject_unknown_fields(
        object,
        &["address", "name", "classification", "body"],
        field,
    )?;
    require_string(object.get("address"), &format!("{field}.address"))?;
    require_string(object.get("name"), &format!("{field}.name"))?;
    if !object.contains_key("classification") || !object.contains_key("body") {
        return Err(invalid(&format!(
            "{field} must retain classification and body"
        )));
    }
    validate_nullable_object(
        object.get("classification"),
        &format!("{field}.classification"),
    )?;
    if let Some(classification) = object.get("classification") {
        if !classification.is_null() {
            let classification = classification
                .as_object()
                .ok_or_else(|| invalid(&format!("{field}.classification must be an object")))?;
            reject_unknown_fields(
                classification,
                &["external", "thunk", "thunk_target", "provenance"],
                &format!("{field}.classification"),
            )?;
            if !matches!(classification.get("external"), Some(Value::Bool(_)))
                || !matches!(classification.get("thunk"), Some(Value::Bool(_)))
            {
                return Err(invalid(&format!(
                    "{field}.classification must declare external and thunk booleans"
                )));
            }
            match classification.get("thunk_target") {
                Some(Value::Null) => {}
                Some(value) => {
                    require_string(Some(value), &format!("{field}.classification.thunk_target"))?
                }
                None => {
                    return Err(invalid(&format!(
                        "{field}.classification requires thunk_target"
                    )));
                }
            }
            require_non_empty_string(
                classification.get("provenance"),
                &format!("{field}.classification.provenance"),
            )?;
        }
    }
    validate_body(object.get("body"), &format!("{field}.body"))
}

fn validate_identities(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    for (index, item) in array(value, field)?.iter().enumerate() {
        validate_identity(Some(item), &format!("{field}[{index}]"))?;
    }
    Ok(())
}

fn validate_locals(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in array(value, "procedure.locals")?.iter().enumerate() {
        let local = object(item, &format!("procedure.locals[{index}]"))?;
        reject_unknown_fields(
            local,
            &["description", "provenance", "name", "stack_displacement"],
            "local",
        )?;
        require_string(local.get("description"), "local.description")?;
        require_non_empty_string(local.get("provenance"), "local.provenance")?;
        if let Some(name) = local.get("name") {
            if *name != Value::Null {
                require_string(Some(name), "local.name")?;
            }
        }
        if let Some(displacement) = local.get("stack_displacement") {
            if *displacement != Value::Null {
                require_string(Some(displacement), "local.stack_displacement")?;
            }
        }
    }
    Ok(())
}

fn validate_comments(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in array(value, "comments")?.iter().enumerate() {
        let object = object(item, &format!("comments[{index}]"))?;
        reject_unknown_fields(object, &["address", "kind", "text"], "comment")?;
        require_string(object.get("address"), "comment.address")?;
        require_string(object.get("text"), "comment.text")?;
        if !matches!(
            object.get("kind").and_then(Value::as_str),
            Some("comment" | "inline")
        ) {
            return Err(invalid("comment.kind must be comment or inline"));
        }
    }
    Ok(())
}

fn validate_references(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    for (index, item) in array(value, field)?.iter().enumerate() {
        let object = object(item, &format!("{field}[{index}]"))?;
        reject_unknown_fields(
            object,
            &[
                "source_address",
                "target_address",
                "source_procedure",
                "target_procedure",
                "kind",
                "call",
            ],
            "reference",
        )?;
        require_string(object.get("source_address"), "reference.source_address")?;
        require_string(object.get("target_address"), "reference.target_address")?;
        validate_nullable_identity(object.get("source_procedure"), "reference.source_procedure")?;
        validate_nullable_identity(object.get("target_procedure"), "reference.target_procedure")?;
        validate_object(object.get("kind"), "reference.kind")?;
    }
    Ok(())
}

fn validate_nullable_identity(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value == Some(&Value::Null) {
        return Ok(());
    }
    validate_identity(value, field)
}

fn validate_body(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let body = object(
        value.ok_or_else(|| invalid(&format!("{field} is required")))?,
        field,
    )?;
    let available = body
        .get("available")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(&format!("{field}.available must be a boolean")))?;
    if !available {
        reject_unknown_fields(body, &["available", "reason"], field)?;
        require_string(body.get("reason"), &format!("{field}.reason"))?;
        return Ok(());
    }

    reject_unknown_fields(
        body,
        &[
            "available",
            "provenance",
            "ranges",
            "total_bytes",
            "span_bytes",
            "non_contiguous",
            "contains_entry",
        ],
        field,
    )?;
    require_non_empty_string(body.get("provenance"), &format!("{field}.provenance"))?;
    let ranges = array(body.get("ranges"), &format!("{field}.ranges"))?;
    for (index, range) in ranges.iter().enumerate() {
        let range = object(range, &format!("{field}.ranges[{index}]"))?;
        reject_unknown_fields(range, &["start", "end"], "function body range")?;
        require_string(range.get("start"), "function body range.start")?;
        require_string(range.get("end"), "function body range.end")?;
    }
    if !matches!(body.get("total_bytes"), Some(Value::Number(number)) if number.as_u64().is_some())
    {
        return Err(invalid(&format!(
            "{field}.total_bytes must be a non-negative integer"
        )));
    }
    match body.get("span_bytes") {
        Some(Value::Null) => {}
        Some(Value::Number(number)) if number.as_u64().is_some() => {}
        _ => {
            return Err(invalid(&format!(
                "{field}.span_bytes must be a non-negative integer or null"
            )));
        }
    }
    if !matches!(body.get("non_contiguous"), Some(Value::Bool(_)))
        || !matches!(body.get("contains_entry"), Some(Value::Bool(_)))
    {
        return Err(invalid(&format!(
            "{field} must retain non_contiguous and contains_entry booleans"
        )));
    }
    Ok(())
}

fn validate_optional_unresolved_calls(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    for (index, item) in array(Some(value), "unresolved_calls")?.iter().enumerate() {
        let object = object(item, &format!("unresolved_calls[{index}]"))?;
        reject_unknown_fields(object, &["address", "reason"], "unresolved_call")?;
        require_string(object.get("address"), "unresolved_call.address")?;
        require_string(object.get("reason"), "unresolved_call.reason")?;
    }
    Ok(())
}

fn validate_referenced_strings(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in array(value, "referenced_strings")?.iter().enumerate() {
        let object = object(item, &format!("referenced_strings[{index}]"))?;
        reject_unknown_fields(
            object,
            &[
                "address",
                "value",
                "provider_value",
                "decoding",
                "string",
                "source_address",
            ],
            "referenced_string",
        )?;
        require_string(object.get("address"), "referenced_string.address")?;
        require_string(object.get("value"), "referenced_string.value")?;
        require_string(
            object.get("source_address"),
            "referenced_string.source_address",
        )?;
    }
    Ok(())
}

fn validate_referenced_names(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in array(value, "referenced_names")?.iter().enumerate() {
        let object = object(item, &format!("referenced_names[{index}]"))?;
        reject_unknown_fields(
            object,
            &["address", "value", "source_address"],
            "referenced_name",
        )?;
        require_string(object.get("address"), "referenced_name.address")?;
        require_string(object.get("value"), "referenced_name.value")?;
        require_string(
            object.get("source_address"),
            "referenced_name.source_address",
        )?;
    }
    Ok(())
}

fn validate_swift_pair(object: &Map<String, Value>) -> Result<(), Failure> {
    let has_literals = object.contains_key("swift_string_literals");
    let has_omissions = object.contains_key("swift_string_literal_omissions");
    if has_literals != has_omissions {
        return Err(invalid(
            "Swift literals and omissions must be retained together",
        ));
    }
    for field in ["swift_string_literals", "swift_string_literal_omissions"] {
        if object.contains_key(field) {
            array(object.get(field), field)?;
        }
    }
    Ok(())
}

fn validate_basic_blocks(value: Option<&Value>) -> Result<(), Failure> {
    for (index, item) in array(value, "basic_blocks")?.iter().enumerate() {
        let object = object(item, &format!("basic_blocks[{index}]"))?;
        reject_unknown_fields(object, &["start", "end", "successors"], "basic_block")?;
        for field in ["start", "end", "successors"] {
            if !object.contains_key(field) {
                return Err(invalid(&format!("basic_blocks[{index}] requires {field}")));
            }
        }
        require_string(object.get("start"), "basic_block.start")?;
        require_string(object.get("end"), "basic_block.end")?;
        validate_string_array(object.get("successors"), "basic_block.successors")?;
    }
    Ok(())
}

fn validate_facets(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let facets = object(value, "facet_availability")?;
    reject_unknown_fields(
        facets,
        &[
            "pseudocode",
            "assembly",
            "comments",
            "callers",
            "callees",
            "references",
            "strings_names",
            "cfg",
        ],
        "facet_availability",
    )?;
    for item in facets.values() {
        let facet = object(item, "facet_availability entry")?;
        reject_unknown_fields(facet, &["available", "reason"], "facet availability entry")?;
        match facet.get("available") {
            Some(Value::Bool(true)) => {}
            Some(Value::Bool(false)) => {
                require_non_empty_string(facet.get("reason"), "facet reason")?;
            }
            _ => return Err(invalid("facet availability must declare boolean available")),
        }
    }
    Ok(())
}

fn validate_string_array(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    for item in array(value, field)? {
        require_string(Some(item), field)?;
    }
    Ok(())
}

fn array<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a Vec<Value>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    if values.len() > MAX_ARRAY_ITEMS {
        return Err(invalid(&format!("{field} exceeds the supported bound")));
    }
    Ok(values)
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid(&format!("{field} must be an object")))
}

fn validate_object(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    object(
        value.ok_or_else(|| invalid(&format!("{field} is required")))?,
        field,
    )
    .map(|_| ())
}

fn validate_nullable_object(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    match value {
        Some(Value::Null) => Ok(()),
        Some(value) => validate_object(Some(value), field),
        None => Err(invalid(&format!("{field} is required"))),
    }
}

fn require_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str).is_none() {
        return Err(invalid(&format!("{field} must be a string")));
    }
    Ok(())
}

fn require_non_empty_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str).map_or(true, str::is_empty) {
        return Err(invalid(&format!("{field} must be a non-empty string")));
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(unknown) = object
        .keys()
        .find(|key| !allowed.iter().any(|allowed| *allowed == key.as_str()))
    {
        return Err(invalid(&format!(
            "{field} contains unsupported field {unknown}"
        )));
    }
    Ok(())
}

fn copy_array_from_sources(
    primary: &Value,
    secondary: &Value,
    output: &mut Map<String, Value>,
    field: &str,
) -> Result<(), Failure> {
    if let Some(value) = primary.get(field).or_else(|| secondary.get(field)) {
        validate_string_array(Some(value), field)?;
        output.insert(field.into(), value.clone());
    }
    Ok(())
}

fn copy_from_sources(
    primary: &Value,
    secondary: &Value,
    output: &mut Map<String, Value>,
    field: &str,
) {
    if let Some(value) = primary.get(field).or_else(|| secondary.get(field)) {
        output.insert(field.into(), value.clone());
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a complete analyze_function observation and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
