//! Lossless validation for JavaScript analysis-view results.
//!
//! The published view contract is supplied by the adapter that owns the MCP
//! catalog. Keeping the validator here lets every adapter validate the same
//! exact graph result without making the application layer depend on MCP.

use crate::javascript::graph::json::Json;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::schema::{Issue, IssueKind, Parser, UnknownKeys, resolve_schema};
use serde_json::{Map, Value};

const OPERATION: &str = "inspect_analysis_view";

/// Parse an exact view request against the published input contract.
///
/// The parser operates on a collision-safe shadow `Value`, then defaults are
/// merged back into the original graph. Existing keys and all source strings
/// remain owned by the exact graph, including unpaired UTF-16 units.
pub fn parse_input(input: &Json, root: &Value) -> Result<Json, AnalysisError> {
    parse_input_for_operation(OPERATION, input, root)
}

/// Parse an exact request against its adapter's named operation contract.
pub fn parse_input_for_operation(
    operation: &str,
    input: &Json,
    root: &Value,
) -> Result<Json, AnalysisError> {
    let mut invalid_strings = Vec::new();
    let shadow = shadow_value(input, &mut invalid_strings);
    let parsed = Parser::new(root, UnknownKeys::Reject)
        .parse(&shadow)
        .map_err(|issues| AnalysisError::input(operation, input_issues(input, &issues)))?;

    restore_defaults(operation, input, &parsed)
}

fn input_issues(input: &Json, issues: &[Issue]) -> Vec<InputIssue> {
    issues
        .iter()
        .map(|issue| input_issue(input, issue))
        .collect()
}

fn input_issue(input: &Json, issue: &Issue) -> InputIssue {
    let value_present = value_at_path(input, &issue.path).is_some();
    let (reason, message, expected, minimum, maximum) = match &issue.kind {
        IssueKind::InvalidType { expected } => (
            if value_present {
                "invalid_type"
            } else {
                "missing_argument"
            },
            if value_present {
                Some(format!("Expected {expected}"))
            } else {
                None
            },
            Some(Value::String(expected.clone())),
            None,
            None,
        ),
        IssueKind::InvalidValue { values } => (
            "invalid_value",
            Some("Value is not permitted by the contract".to_owned()),
            Some(Value::Array(values.clone())),
            None,
            None,
        ),
        IssueKind::TooSmall { minimum, exclusive } => (
            "out_of_range",
            Some(if *exclusive {
                "Value is below the exclusive minimum".to_owned()
            } else {
                "Value is below the minimum".to_owned()
            }),
            None,
            *minimum,
            None,
        ),
        IssueKind::TooBig { maximum, exclusive } => (
            "out_of_range",
            Some(if *exclusive {
                "Value is above the exclusive maximum".to_owned()
            } else {
                "Value is above the maximum".to_owned()
            }),
            None,
            None,
            *maximum,
        ),
        IssueKind::InvalidFormat { message, .. } | IssueKind::Custom { message } => {
            ("invalid_format", Some(message.clone()), None, None, None)
        }
        IssueKind::UnrecognizedKeys { keys } => (
            "unknown_argument",
            Some(format!("Unknown properties: {}", keys.join(", "))),
            None,
            None,
            None,
        ),
        IssueKind::InvalidUnion { .. } => (
            "invalid_value",
            Some("Value does not match any published variant".to_owned()),
            None,
            None,
            None,
        ),
    };
    InputIssue {
        path: issue.path.clone(),
        reason,
        message,
        expected,
        minimum,
        maximum,
    }
}

fn value_at_path<'a>(value: &'a Json, path: &[Value]) -> Option<&'a Json> {
    let mut current = value;
    for part in path {
        current = match part {
            Value::String(key) => current.get(key)?,
            Value::Number(index) => current.arr().get(index.as_u64()? as usize)?,
            _ => return None,
        };
    }
    Some(current)
}

fn restore_defaults(
    operation: &str,
    original: &Json,
    parsed: &Value,
) -> Result<Json, AnalysisError> {
    match (original, parsed) {
        (Json::Object(original_object), Value::Object(parsed_object)) => {
            let mut restored = original_object.clone();
            for (key, value) in parsed_object {
                if let Some(existing) = original_object.get(key.as_str()) {
                    restored.set(key.clone(), restore_defaults(operation, existing, value)?);
                } else if !key.starts_with("__utf16_key_") {
                    restored.set(key.clone(), json_from_value(operation, value)?);
                }
            }
            Ok(Json::Object(restored))
        }
        (Json::Array(original_items), Value::Array(parsed_items)) => {
            let mut restored = Vec::with_capacity(original_items.len());
            for (index, original_item) in original_items.iter().enumerate() {
                let item = parsed_items.get(index).unwrap_or(&Value::Null);
                restored.push(restore_defaults(operation, original_item, item)?);
            }
            Ok(Json::array(restored))
        }
        _ => Ok(original.clone()),
    }
}

fn json_from_value(operation: &str, value: &Value) -> Result<Json, AnalysisError> {
    let serialized = serde_json::to_string(value)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
    crate::javascript::graph::json::parse(&serialized).map_err(|error| {
        AnalysisError::output(
            operation,
            format!("Published input default is not exact JSON: {error}"),
        )
    })
}

/// Validate one exact JavaScript view result against a published contract.
pub fn validate(result: &Json, root: &Value) -> Result<(), AnalysisError> {
    let mut invalid_strings = Vec::new();
    let shadow = shadow_value(result, &mut invalid_strings);
    Parser::new(root, UnknownKeys::Reject)
        .parse(&shadow)
        .map_err(|issues| {
            AnalysisError::output(
                OPERATION,
                format!(
                    "Analysis view result does not satisfy its contract: {}",
                    describe(&issues)
                ),
            )
        })?;

    for path in invalid_strings {
        if requires_exact_string_semantics(root, root, &shadow, &path) {
            return Err(AnalysisError::output(
                OPERATION,
                format!(
                    "Analysis view result contains an unpaired UTF-16 string at {} under a constrained schema field.",
                    format_path(&path)
                ),
            ));
        }
    }

    Ok(())
}

fn describe(issues: &[Issue]) -> String {
    issues
        .first()
        .map(|issue| format!("{issue:?}"))
        .unwrap_or_else(|| "unknown schema issue".to_owned())
}

#[derive(Clone, Debug)]
enum PathPart {
    Key(String),
    Index(usize),
}

fn shadow_value(value: &Json, invalid_strings: &mut Vec<Vec<PathPart>>) -> Value {
    let mut path = Vec::new();
    shadow_at_path(value, &mut path, invalid_strings)
}

fn shadow_at_path(
    value: &Json,
    path: &mut Vec<PathPart>,
    invalid_strings: &mut Vec<Vec<PathPart>>,
) -> Value {
    match value {
        Json::Null => Value::Null,
        Json::Bool(value) => Value::Bool(*value),
        Json::Number(value) => shadow_number(*value),
        Json::String(value) => match value.as_str() {
            Some(text) => Value::String(text.to_owned()),
            None => {
                invalid_strings.push(path.clone());
                Value::String(shadow_string(value))
            }
        },
        Json::Array(values) => Value::Array(
            values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    path.push(PathPart::Index(index));
                    let shadow = shadow_at_path(value, path, invalid_strings);
                    path.pop();
                    shadow
                })
                .collect(),
        ),
        Json::Object(object) => {
            let mut shadow = Map::new();
            for (key, value) in object.iter() {
                let base_key = key
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("__utf16_key_{}", units_hex(key.units())));
                let key_shadow = unique_shadow_key(&shadow, base_key);
                path.push(PathPart::Key(key_shadow.clone()));
                let value_shadow = shadow_at_path(value, path, invalid_strings);
                path.pop();
                shadow.insert(key_shadow, value_shadow);
            }
            Value::Object(shadow)
        }
    }
}

fn shadow_number(value: f64) -> Value {
    if value.is_finite() && value.fract() == 0.0 {
        if value >= i64::MIN as f64 && value < 2_f64.powi(63) {
            return Value::Number(serde_json::Number::from(value as i64));
        }
        if value >= 0.0 && value < 2_f64.powi(64) {
            return Value::Number(serde_json::Number::from(value as u64));
        }
    }
    serde_json::Number::from_f64(value)
        .map(Value::Number)
        .unwrap_or(Value::Null)
}

fn unique_shadow_key(existing: &Map<String, Value>, base: String) -> String {
    if !existing.contains_key(&base) {
        return base;
    }
    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}__{suffix}");
        if !existing.contains_key(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}

fn shadow_string(value: &crate::javascript::semantic::value_types::JsString) -> String {
    value
        .units()
        .iter()
        .map(|unit| {
            if (0xd800..=0xdfff).contains(unit) {
                '\u{e000}'
            } else {
                char::from_u32(u32::from(*unit)).unwrap_or('\u{e001}')
            }
        })
        .collect()
}

fn units_hex(units: &[u16]) -> String {
    let mut output = String::with_capacity(units.len() * 4);
    for unit in units {
        output.push_str(&format!("{unit:04x}"));
    }
    output
}

fn format_path(path: &[PathPart]) -> String {
    if path.is_empty() {
        return "<root>".to_owned();
    }
    path.iter()
        .map(|part| match part {
            PathPart::Key(key) => key.clone(),
            PathPart::Index(index) => index.to_string(),
        })
        .collect::<Vec<_>>()
        .join(".")
}

#[cfg(test)]
mod tests {
    use super::shadow_number;

    #[test]
    fn preserves_integer_number_boundaries_without_saturation() {
        let signed_minimum = shadow_number(-(2_f64.powi(63)));
        assert_eq!(signed_minimum.as_i64(), Some(i64::MIN));

        let unsigned_boundary = shadow_number(2_f64.powi(63));
        assert_eq!(unsigned_boundary.as_u64(), Some(2_u64.pow(63)));

        let floating_boundary = shadow_number(2_f64.powi(64));
        assert_eq!(floating_boundary.as_i64(), None);
        assert_eq!(floating_boundary.as_u64(), None);
        assert_eq!(floating_boundary.as_f64(), Some(2_f64.powi(64)));
    }
}

/// Return whether a string constraint cannot be delegated to the UTF-8 shadow.
/// Length, enum and const checks retain their JavaScript semantics here:
/// lengths count UTF-16 units and an invalid-unit string cannot equal a valid
/// catalog literal. Most patterns reject the shadow value before this point.
/// The published path pattern `^[^\\x00]*$` is also exact for surrogate
/// units, because a surrogate is neither NUL nor a line terminator; it is
/// explicitly exempted below. Other pattern checks require the original units.
fn requires_exact_string_semantics(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &[PathPart],
) -> bool {
    let candidates = schemas_at_path(root, schema, Some(value), path);
    candidates
        .iter()
        .filter(|schema| schema_accepts_string(schema))
        .any(|schema| has_lossy_string_constraint(schema))
}

fn schemas_at_path<'a>(
    document: &'a Value,
    schema: &'a Value,
    value: Option<&Value>,
    path: &[PathPart],
) -> Vec<&'a Value> {
    if let Some(reference) = schema.get("$ref").and_then(Value::as_str)
        && let Some(resolved) = resolve_local_reference(document, reference)
    {
        return schemas_at_path(document, resolved, value, path);
    }
    if path.is_empty() {
        return vec![schema];
    }
    let Some(object) = schema.as_object() else {
        return Vec::new();
    };
    let mut candidates = Vec::new();
    for key in ["allOf", "anyOf", "oneOf"] {
        if let Some(options) = object.get(key).and_then(Value::as_array) {
            let matching = options
                .iter()
                .filter(|option| branch_matches_value(document, option, value))
                .collect::<Vec<_>>();
            let selected = if matching.is_empty() {
                options.iter().collect::<Vec<_>>()
            } else {
                matching
            };
            for option in selected {
                candidates.extend(schemas_at_path(document, option, value, path));
            }
        }
    }
    match &path[0] {
        PathPart::Key(key) => {
            let property = object
                .get("properties")
                .and_then(Value::as_object)
                .and_then(|properties| properties.get(key));
            if let Some(property) = property {
                candidates.extend(schemas_at_path(
                    document,
                    property,
                    value.and_then(|value| value.as_object()?.get(key)),
                    &path[1..],
                ));
            } else if let Some(additional) = object.get("additionalProperties") {
                candidates.extend(schemas_at_path(
                    document,
                    additional,
                    value.and_then(|value| value.as_object()?.get(key)),
                    &path[1..],
                ));
            }
        }
        PathPart::Index(index) => {
            if let Some(items) = object.get("items") {
                candidates.extend(schemas_at_path(
                    document,
                    items,
                    value.and_then(|value| value.as_array()?.get(*index)),
                    &path[1..],
                ));
            }
        }
    }
    candidates
}

fn branch_matches_value(document: &Value, schema: &Value, value: Option<&Value>) -> bool {
    let Some(reference) = schema.get("$ref").and_then(Value::as_str) else {
        return branch_matches_object(document, schema, value);
    };
    resolve_local_reference(document, reference).map_or(true, |resolved| {
        branch_matches_object(document, resolved, value)
    })
}

fn branch_matches_object(document: &Value, schema: &Value, value: Option<&Value>) -> bool {
    let Some(Value::Object(actual)) = value else {
        return true;
    };
    let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
        return true;
    };

    for (key, property) in properties {
        let Some(actual_value) = actual.get(key) else {
            continue;
        };
        let Some(property) = resolve_schema(document, property).ok() else {
            continue;
        };
        if let Some(expected) = property.get("const")
            && actual_value != expected
        {
            return false;
        }
        if let Some(expected) = property.get("enum").and_then(Value::as_array)
            && !expected.iter().any(|candidate| candidate == actual_value)
        {
            return false;
        }
    }

    true
}

fn resolve_local_reference<'a>(document: &'a Value, reference: &str) -> Option<&'a Value> {
    let mut current = document;
    let path = reference.strip_prefix("#/")?.split('/');
    for part in path {
        let decoded = part.replace("~1", "/").replace("~0", "~");
        current = current.get(&decoded)?;
    }
    Some(current)
}

fn schema_accepts_string(schema: &Value) -> bool {
    match schema.get("type") {
        Some(Value::String(kind)) => kind == "string",
        Some(Value::Array(kinds)) => kinds.iter().any(|kind| kind.as_str() == Some("string")),
        None => {
            schema.get("const").is_some_and(Value::is_string)
                || schema
                    .get("enum")
                    .and_then(Value::as_array)
                    .is_some_and(|values| values.iter().any(Value::is_string))
                || ["minLength", "maxLength", "pattern", "format"]
                    .iter()
                    .any(|key| schema.get(*key).is_some())
        }
        _ => false,
    }
}

fn has_lossy_string_constraint(schema: &Value) -> bool {
    schema.get("format").is_some()
        || schema
            .get("pattern")
            .and_then(Value::as_str)
            .is_some_and(|pattern| pattern != r"^[^\x00]*$")
}
