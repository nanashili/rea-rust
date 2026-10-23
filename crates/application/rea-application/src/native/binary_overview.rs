//! Provider-neutral projection for the native `binary_overview` operation.
//!
//! The provider owns binary interpretation.  This module only validates the
//! inventory facts that the provider supplied and projects the stable overview
//! shape consumed by the application and Evidence adapters.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "binary_overview";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Validate and project a provider inventory summary.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("binary overview input must be an object"))?;

    reject_unknown_fields(
        object,
        &["document", "segments", "procedure_count", "string_count"],
    )?;

    let document = required_non_empty_string(object, "document")?.to_owned();
    let procedure_count = required_count(object, "procedure_count")?;
    let string_count = required_count(object, "string_count")?;

    let mut result = Map::new();
    result.insert("document".into(), Value::String(document));
    result.insert("procedure_count".into(), number(procedure_count));
    result.insert("string_count".into(), number(string_count));

    if let Some(segments) = object.get("segments") {
        let segments = parse_segments(segments)?;
        let image_base = common_image_base(&segments);

        if let Some(image_base) = image_base {
            result.insert("image_base".into(), Value::String(image_base));
        }

        result.insert(
            "segment_count".into(),
            number(
                u64::try_from(segments.len()).map_err(|_| {
                    resource("segment count exceeds the representable integer range")
                })?,
            ),
        );
        result.insert(
            "segments".into(),
            Value::Array(segments.into_iter().map(Segment::project).collect()),
        );
    }

    Ok(Value::Object(result))
}

/// The adapter-facing validation entry point mirrors the other native
/// application producers and avoids performing the projection twice.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    project(input).map(|_| ())
}

#[derive(Clone)]
struct Segment {
    name: String,
    start: String,
    end: String,
    length: Option<u64>,
    image_base: Option<String>,
    address_space: Option<String>,
}

impl Segment {
    fn project(self) -> Value {
        let mut object = Map::new();
        object.insert("name".into(), Value::String(self.name));
        object.insert("start".into(), Value::String(self.start));
        object.insert("end".into(), Value::String(self.end));
        object.insert(
            "length".into(),
            self.length.map(number).unwrap_or(Value::Null),
        );
        if let Some(image_base) = self.image_base {
            object.insert("image_base".into(), Value::String(image_base));
        }
        if let Some(address_space) = self.address_space {
            object.insert("address_space".into(), Value::String(address_space));
        }
        Value::Object(object)
    }
}

fn parse_segments(value: &Value) -> Result<Vec<Segment>, Failure> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid("segments must be an array"))?;
    let mut segments = Vec::with_capacity(array.len());

    for (index, value) in array.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid(&format!("segments[{index}] must be an object")))?;
        reject_unknown_fields(
            object,
            &[
                "name",
                "start",
                "end",
                "readable",
                "writable",
                "executable",
                "image_base",
                "address_space",
                "permissions",
                "provenance",
                "initialized",
                "overlay",
                "sections",
            ],
        )?;

        let name = required_string(object, "name", index)?;
        let start = required_string(object, "start", index)?;
        let end = required_string(object, "end", index)?;

        // The source schema requires these permission facts even though the
        // overview deliberately omits them from its public projection.
        required_bool(object, "readable", index)?;
        required_bool(object, "writable", index)?;
        required_bool(object, "executable", index)?;

        let image_base = optional_non_empty_string(object, "image_base", index)?;
        let address_space = optional_non_empty_string(object, "address_space", index)?;
        let length = address_distance(&start, &end);

        segments.push(Segment {
            name,
            start,
            end,
            length,
            image_base,
            address_space,
        });
    }

    Ok(segments)
}

fn common_image_base(segments: &[Segment]) -> Option<String> {
    let first = segments.first()?.image_base.as_ref()?;
    if segments
        .iter()
        .all(|segment| segment.image_base.as_ref() == Some(first))
    {
        Some(first.clone())
    } else {
        None
    }
}

fn address_distance(start: &str, end: &str) -> Option<u64> {
    let (start_space, start_offset) = address_coordinate(start)?;
    let (end_space, end_offset) = address_coordinate(end)?;
    if start_space != end_space || end_offset < start_offset {
        return None;
    }
    let distance = end_offset - start_offset;
    (distance <= MAX_SAFE_INTEGER as u128).then_some(distance as u64)
}

fn address_coordinate(value: &str) -> Option<(Option<&str>, u128)> {
    let separator = value.rfind(":0x");
    let (space, offset) = match separator {
        Some(0) => return None,
        Some(index) => (Some(&value[..index]), &value[index + 1..]),
        None => (None, value),
    };
    if !offset.starts_with("0x") || offset.len() <= 2 {
        return None;
    }
    let digits = &offset[2..];
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u128::from_str_radix(digits, 16)
        .ok()
        .map(|value| (space, value))
}

fn reject_unknown_fields(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown field `{field}` in binary overview"
        )));
    }
    Ok(())
}

fn required_non_empty_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn required_string(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<String, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(&format!("segments[{index}].{field} must be a string")))
}

fn optional_non_empty_string(
    object: &Map<String, Value>,
    field: &str,
    index: usize,
) -> Result<Option<String>, Failure> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(Value::String(_)) => Err(invalid(&format!(
            "segments[{index}].{field} must not be empty"
        ))),
        Some(_) => Err(invalid(&format!(
            "segments[{index}].{field} must be a string"
        ))),
    }
}

fn required_bool(object: &Map<String, Value>, field: &str, index: usize) -> Result<(), Failure> {
    if object.get(field).and_then(Value::as_bool).is_none() {
        return Err(invalid(&format!(
            "segments[{index}].{field} must be a boolean"
        )));
    }
    Ok(())
}

fn required_count(object: &Map<String, Value>, field: &str) -> Result<u64, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| invalid(&format!("{field} must be a non-negative safe integer")))?;
    Ok(value)
}

fn number(value: u64) -> Value {
    Value::Number(Number::from(value))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a complete provider binary inventory summary and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: &str) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        reason.to_owned(),
        false,
        "Select a binary inventory within the supported resource boundary.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
