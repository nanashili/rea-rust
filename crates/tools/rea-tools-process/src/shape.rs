//! A small Zod-v4-compatible shape parser for process-capture records.
//!
//! The original runtime parses process captures with Zod before checking
//! cross-field invariants. This module mirrors the parts of that behavior the
//! capture schema uses: issue wording and order, which issues abort later
//! refinements (type, literal, enum, union and unknown-key failures) and
//! which do not (string, number and length checks), key stripping for
//! non-strict objects and output keys in shape order.
use crate::json::safe_integer;
use serde_json::{Map, Value};

/// One Zod issue: path, message and whether later refinements still run.
#[derive(Clone, Debug)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
    pub continuable: bool,
}

/// One schema node.
pub enum Shape {
    /// `z.string()` with optional `.min(n)`, 64-hex pattern or ISO datetime.
    Str {
        min: Option<usize>,
        sha256: bool,
        datetime: bool,
    },
    /// `z.number().int()` with an optional inclusive or exclusive lower bound.
    Int {
        minimum: Option<i64>,
        positive: bool,
    },
    Bool,
    Null,
    Literal(&'static str),
    Enum(&'static [&'static str]),
    Nullable(Box<Shape>),
    Array {
        item: Box<Shape>,
        min: Option<usize>,
    },
    Object {
        fields: Vec<(&'static str, Shape, bool)>,
        strict: bool,
    },
    /// `z.record(z.string(), jsonValueSchema)`.
    Record,
    /// `z.discriminatedUnion(key, branches)`; each branch lists its tags.
    Union {
        key: &'static str,
        branches: Vec<(&'static [&'static str], Shape)>,
    },
}

/// Field helpers.
pub fn required(name: &'static str, shape: Shape) -> (&'static str, Shape, bool) {
    (name, shape, false)
}
pub fn optional(name: &'static str, shape: Shape) -> (&'static str, Shape, bool) {
    (name, shape, true)
}
pub fn object(fields: Vec<(&'static str, Shape, bool)>) -> Shape {
    Shape::Object {
        fields,
        strict: false,
    }
}
pub fn strict(fields: Vec<(&'static str, Shape, bool)>) -> Shape {
    Shape::Object {
        fields,
        strict: true,
    }
}
pub fn array(item: Shape) -> Shape {
    Shape::Array {
        item: Box::new(item),
        min: None,
    }
}
pub fn nullable(shape: Shape) -> Shape {
    Shape::Nullable(Box::new(shape))
}
pub fn string() -> Shape {
    Shape::Str {
        min: None,
        sha256: false,
        datetime: false,
    }
}
pub fn nonempty_string() -> Shape {
    Shape::Str {
        min: Some(1),
        sha256: false,
        datetime: false,
    }
}
pub fn sha256() -> Shape {
    Shape::Str {
        min: None,
        sha256: true,
        datetime: false,
    }
}
pub fn datetime() -> Shape {
    Shape::Str {
        min: None,
        sha256: false,
        datetime: true,
    }
}
pub fn integer() -> Shape {
    Shape::Int {
        minimum: None,
        positive: false,
    }
}
pub fn nonnegative() -> Shape {
    Shape::Int {
        minimum: Some(0),
        positive: false,
    }
}
pub fn positive() -> Shape {
    Shape::Int {
        minimum: None,
        positive: true,
    }
}

fn received(value: Option<&Value>) -> &'static str {
    match value {
        None => "undefined",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn quoted(values: &[&str]) -> String {
    values
        .iter()
        .map(|value| serde_json::to_string(value).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("|")
}

/// Zod's `z.iso.datetime()` default: UTC `Z` only, optional seconds and
/// arbitrary fractional precision, with calendar-valid fields.
pub fn is_iso_datetime(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range.clone())
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
            .then(|| text[range].parse::<u32>().ok())
            .flatten()
    };
    let Some(body) = text.strip_suffix('Z') else {
        return false;
    };
    if body.len() < 16 || bytes[4] != b'-' || bytes[7] != b'-' || bytes[10] != b'T' {
        return false;
    }
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute)) = (
        digits(0..4),
        digits(5..7),
        digits(8..10),
        digits(11..13),
        digits(14..16),
    ) else {
        return false;
    };
    if bytes[13] != b':' || hour > 23 || minute > 59 {
        return false;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    if day == 0 || day > days {
        return false;
    }
    let rest = &body[16..];
    if rest.is_empty() {
        return true;
    }
    let Some(seconds) = rest.strip_prefix(':') else {
        return false;
    };
    if seconds.len() < 2 || !seconds.as_bytes()[..2].iter().all(u8::is_ascii_digit) {
        return false;
    }
    if seconds[..2].parse::<u32>().unwrap_or(99) > 59 {
        return false;
    }
    let fraction = &seconds[2..];
    fraction.is_empty()
        || fraction
            .strip_prefix('.')
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

fn is_sha256(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

impl Shape {
    /// Parse `value`, appending issues and returning the Zod output value.
    pub fn parse(
        &self,
        value: Option<&Value>,
        path: &mut Vec<String>,
        issues: &mut Vec<Issue>,
    ) -> Value {
        let push = |issues: &mut Vec<Issue>, path: &[String], message: String, continuable| {
            issues.push(Issue {
                path: path.to_vec(),
                message,
                continuable,
            });
        };
        let invalid_type = |issues: &mut Vec<Issue>, path: &[String], expected: &str| {
            push(
                issues,
                path,
                format!(
                    "Invalid input: expected {expected}, received {}",
                    received(value)
                ),
                false,
            );
        };
        match self {
            Self::Nullable(inner) => match value {
                Some(Value::Null) => Value::Null,
                _ => inner.parse(value, path, issues),
            },
            Self::Str {
                min,
                sha256,
                datetime,
            } => {
                let Some(Value::String(text)) = value else {
                    invalid_type(issues, path, "string");
                    return value.cloned().unwrap_or(Value::Null);
                };
                if let Some(min) = min
                    && text.encode_utf16().count() < *min
                {
                    push(
                        issues,
                        path,
                        format!("Too small: expected string to have >={min} characters"),
                        true,
                    );
                }
                if *sha256 && !is_sha256(text) {
                    push(
                        issues,
                        path,
                        "Invalid string: must match pattern /^[a-f0-9]{64}$/u".into(),
                        true,
                    );
                }
                if *datetime && !is_iso_datetime(text) {
                    push(issues, path, "Invalid ISO datetime".into(), true);
                }
                Value::String(text.clone())
            }
            Self::Int { minimum, positive } => {
                let Some(number @ Value::Number(_)) = value else {
                    invalid_type(issues, path, "number");
                    return value.cloned().unwrap_or(Value::Null);
                };
                let as_float = number.as_f64().unwrap_or(f64::NAN);
                if safe_integer(number).is_none() {
                    if as_float.fract() == 0.0 && as_float.is_finite() {
                        let message = if as_float > 0.0 {
                            "Too big: expected int to be <=9007199254740991"
                        } else {
                            "Too small: expected int to be >=-9007199254740991"
                        };
                        push(issues, path, message.into(), true);
                    } else {
                        push(
                            issues,
                            path,
                            "Invalid input: expected int, received number".into(),
                            true,
                        );
                    }
                }
                if let Some(minimum) = minimum
                    && as_float < *minimum as f64
                {
                    push(
                        issues,
                        path,
                        format!("Too small: expected number to be >={minimum}"),
                        true,
                    );
                }
                if *positive && as_float <= 0.0 {
                    push(
                        issues,
                        path,
                        "Too small: expected number to be >0".into(),
                        true,
                    );
                }
                number.clone()
            }
            Self::Bool => match value {
                Some(Value::Bool(flag)) => Value::Bool(*flag),
                _ => {
                    invalid_type(issues, path, "boolean");
                    value.cloned().unwrap_or(Value::Null)
                }
            },
            Self::Null => match value {
                Some(Value::Null) => Value::Null,
                _ => {
                    invalid_type(issues, path, "null");
                    value.cloned().unwrap_or(Value::Null)
                }
            },
            Self::Literal(expected) => {
                if value.and_then(Value::as_str) != Some(*expected) {
                    push(
                        issues,
                        path,
                        format!("Invalid input: expected {}", quoted(&[expected])),
                        false,
                    );
                }
                value.cloned().unwrap_or(Value::Null)
            }
            Self::Enum(options) => {
                if !value
                    .and_then(Value::as_str)
                    .is_some_and(|text| options.contains(&text))
                {
                    push(
                        issues,
                        path,
                        format!("Invalid option: expected one of {}", quoted(options)),
                        false,
                    );
                }
                value.cloned().unwrap_or(Value::Null)
            }
            Self::Array { item, min } => {
                let Some(Value::Array(items)) = value else {
                    invalid_type(issues, path, "array");
                    return value.cloned().unwrap_or(Value::Null);
                };
                if let Some(min) = min
                    && items.len() < *min
                {
                    push(
                        issues,
                        path,
                        format!("Too small: expected array to have >={min} items"),
                        true,
                    );
                }
                let mut output = Vec::with_capacity(items.len());
                for (index, element) in items.iter().enumerate() {
                    path.push(index.to_string());
                    output.push(item.parse(Some(element), path, issues));
                    path.pop();
                }
                Value::Array(output)
            }
            Self::Record => match value {
                Some(Value::Object(object)) => Value::Object(object.clone()),
                _ => {
                    invalid_type(issues, path, "record");
                    value.cloned().unwrap_or(Value::Null)
                }
            },
            Self::Object { fields, strict } => {
                let Some(Value::Object(object)) = value else {
                    invalid_type(issues, path, "object");
                    return value.cloned().unwrap_or(Value::Null);
                };
                let mut output = Map::new();
                for (name, shape, is_optional) in fields {
                    let present = object.get(*name);
                    if present.is_none() && *is_optional {
                        continue;
                    }
                    path.push((*name).to_owned());
                    let parsed = shape.parse(present, path, issues);
                    path.pop();
                    if present.is_some() {
                        output.insert((*name).to_owned(), parsed);
                    }
                }
                if *strict {
                    let unknown = object
                        .keys()
                        .filter(|key| !fields.iter().any(|(name, _, _)| name == key))
                        .map(|key| serde_json::to_string(key).unwrap_or_default())
                        .collect::<Vec<_>>();
                    if !unknown.is_empty() {
                        push(
                            issues,
                            path,
                            format!(
                                "Unrecognized key{}: {}",
                                if unknown.len() > 1 { "s" } else { "" },
                                unknown.join(", ")
                            ),
                            false,
                        );
                    }
                }
                Value::Object(output)
            }
            Self::Union { key, branches } => {
                let Some(Value::Object(object)) = value else {
                    invalid_type(issues, path, "object");
                    return value.cloned().unwrap_or(Value::Null);
                };
                let tag = object.get(*key).and_then(Value::as_str);
                match branches
                    .iter()
                    .find(|(tags, _)| tag.is_some_and(|tag| tags.contains(&tag)))
                {
                    Some((_, branch)) => branch.parse(value, path, issues),
                    None => {
                        // The runtime's Zod error map names every tag.
                        let expected = branches
                            .iter()
                            .flat_map(|(tags, _)| tags.iter())
                            .map(|tag| format!("'{tag}'"))
                            .collect::<Vec<_>>()
                            .join(" | ");
                        path.push((*key).to_owned());
                        push(
                            issues,
                            path,
                            format!("Invalid discriminator value. Expected {expected}"),
                            false,
                        );
                        path.pop();
                        value.cloned().unwrap_or(Value::Null)
                    }
                }
            }
        }
    }
}

/// Whether any issue at or below `prefix` aborts later refinements there.
pub fn aborted_under(issues: &[Issue], prefix: &[&str]) -> bool {
    issues.iter().any(|issue| {
        !issue.continuable
            && issue.path.len() >= prefix.len()
            && issue
                .path
                .iter()
                .zip(prefix)
                .all(|(left, right)| left == right)
    })
}

/// `describeValidationFailure` for a Zod error.
pub fn describe(issues: &[Issue]) -> String {
    let Some(first) = issues.first() else {
        return "at the document root: invalid value".into();
    };
    let location = if first.path.is_empty() {
        "the document root".to_owned()
    } else {
        first.path.join(".")
    };
    let rest = issues.len() - 1;
    format!(
        "at {location}: {}{}",
        first.message,
        if rest == 0 {
            String::new()
        } else {
            format!(" ({rest} more issues)")
        }
    )
}
