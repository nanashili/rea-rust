//! Minimal Zod 4–compatible parsing for provider payloads and Evidence results.
//!
//! The original contracts are Zod schemas whose *parsed output* is what the
//! workflows retain. This module mirrors exactly the subset of Zod 4 semantics
//! those schemas use:
//!
//! - `z.object` strips unknown keys, `z.strictObject`/`.strict()` rejects them;
//!   parsed objects are rebuilt in schema shape order (Zod's output order).
//! - Absent `optional`/`exactOptional` keys stay absent; `default` keys are
//!   inserted at their shape position.
//! - `z.number().int()` accepts only safe integers; string lengths count
//!   UTF-16 code units like JavaScript's `length`.
//! - `z.union` returns the first successful option; `z.discriminatedUnion`
//!   selects the option whose discriminator accepts the input value.
//! - Refinements (`superRefine`) run on the successfully parsed value.
//!
//! Issue text is diagnostic only: every original caller maps a failed parse
//! to its own fixed typed error.
use serde_json::{Map, Value};
use std::sync::Arc;

/// Largest integer JavaScript represents exactly.
pub const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;

/// Refinement over the parsed value; `Err` carries the issue message.
pub type Check = fn(&Value) -> Result<(), String>;

/// String predicate standing in for a Zod regex check.
pub type Pattern = fn(&str) -> bool;

/// String constraints (`min`/`max` count UTF-16 code units).
#[derive(Clone, Copy, Default)]
pub struct StringRules {
    pub min: Option<usize>,
    pub max: Option<usize>,
    pub pattern: Option<Pattern>,
}

/// Number constraints.
#[derive(Clone, Copy, Default)]
pub struct NumberRules {
    pub integer: bool,
    pub min: Option<f64>,
    pub exclusive_min: Option<f64>,
    pub max: Option<f64>,
}

/// Array length constraints.
#[derive(Clone, Copy, Default)]
pub struct Length {
    pub min: Option<usize>,
    pub max: Option<usize>,
}

/// Unknown-key policy of an object schema.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum UnknownKeys {
    /// Default `z.object`: drop unknown keys from the output.
    Strip,
    /// `z.strictObject` / `.strict()`: reject unknown keys.
    Strict,
}

/// Key presence rule for one object field.
#[derive(Clone)]
pub enum Presence {
    Required,
    /// `optional()` / `exactOptional()`: an absent key stays absent.
    Optional,
    /// `default(value)`: an absent key becomes the default.
    Default(fn() -> Value),
}

/// One object field in shape order.
#[derive(Clone)]
pub struct Field {
    pub name: &'static str,
    pub schema: Schema,
    pub presence: Presence,
}

/// Object schema in shape order.
#[derive(Clone)]
pub struct ObjectSchema {
    pub fields: Vec<Field>,
    pub unknown: UnknownKeys,
}

/// A Zod schema subset.
#[derive(Clone)]
pub enum Schema {
    /// `z.unknown()` / `jsonValueSchema`.
    Unknown,
    Null,
    Bool,
    String(StringRules),
    Number(NumberRules),
    Literal(Value),
    Enum(&'static [&'static str]),
    Array(Box<Schema>, Length),
    /// Fixed tuple (exact length).
    Tuple(Vec<Schema>),
    /// `z.record(z.string(), value)`.
    Record(Box<Schema>),
    Object(Arc<ObjectSchema>),
    Nullable(Box<Schema>),
    Union(Vec<Schema>),
    /// Discriminated union by key; options are object schemas.
    Discriminated(&'static str, Vec<Schema>),
    Refined(Box<Schema>, Check),
}

/// One parse failure (diagnostic text only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
}

impl std::fmt::Display for Issue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.path.is_empty() {
            formatter.write_str(&self.message)
        } else {
            write!(formatter, "{}: {}", self.path.join("."), self.message)
        }
    }
}

fn issue(path: &[String], message: impl Into<String>) -> Issue {
    Issue {
        path: path.to_vec(),
        message: message.into(),
    }
}

/// JavaScript string length (UTF-16 code units).
pub fn utf16_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Whether `value` is a JavaScript safe integer.
pub fn is_safe_integer(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                (integer as f64).abs() <= MAX_SAFE_INTEGER
            } else if let Some(integer) = number.as_u64() {
                integer as f64 <= MAX_SAFE_INTEGER
            } else {
                number.as_f64().is_some_and(|float| {
                    float.is_finite() && float.fract() == 0.0 && float.abs() <= MAX_SAFE_INTEGER
                })
            }
        }
        _ => false,
    }
}

/// A JSON number's exact safe-integer value (`5` and `5.0` alike).
pub fn integer(value: &Value) -> Option<i64> {
    if !is_safe_integer(value) {
        return None;
    }
    let number = value.as_number()?;
    number
        .as_i64()
        .or_else(|| number.as_u64().and_then(|value| i64::try_from(value).ok()))
        .or_else(|| number.as_f64().map(|value| value as i64))
}

impl Schema {
    /// Parse `value`, returning Zod's parsed output.
    pub fn parse(&self, value: &Value) -> Result<Value, Issue> {
        let mut path = Vec::new();
        self.run(value, &mut path)
    }

    /// Whether `value` satisfies the schema.
    pub fn accepts(&self, value: &Value) -> bool {
        self.parse(value).is_ok()
    }

    fn run(&self, value: &Value, path: &mut Vec<String>) -> Result<Value, Issue> {
        match self {
            Self::Unknown => Ok(value.clone()),
            Self::Null => match value {
                Value::Null => Ok(Value::Null),
                _ => Err(issue(path, "Invalid input: expected null")),
            },
            Self::Bool => match value {
                Value::Bool(_) => Ok(value.clone()),
                _ => Err(issue(path, "Invalid input: expected boolean")),
            },
            Self::String(rules) => {
                let Value::String(text) = value else {
                    return Err(issue(path, "Invalid input: expected string"));
                };
                if rules.min.is_some() || rules.max.is_some() {
                    let length = utf16_len(text);
                    if rules.min.is_some_and(|min| length < min) {
                        return Err(issue(
                            path,
                            "Too small: expected string to have more characters",
                        ));
                    }
                    if rules.max.is_some_and(|max| length > max) {
                        return Err(issue(
                            path,
                            "Too big: expected string to have fewer characters",
                        ));
                    }
                }
                if let Some(pattern) = rules.pattern
                    && !pattern(text)
                {
                    return Err(issue(path, "Invalid string: must match pattern"));
                }
                Ok(value.clone())
            }
            Self::Number(rules) => {
                let Some(number) = value.as_f64().filter(|_| value.is_number()) else {
                    return Err(issue(path, "Invalid input: expected number"));
                };
                if rules.integer && !is_safe_integer(value) {
                    return Err(issue(path, "Invalid input: expected int"));
                }
                if rules.min.is_some_and(|min| number < min)
                    || rules.exclusive_min.is_some_and(|min| number <= min)
                {
                    return Err(issue(path, "Too small: expected number to be larger"));
                }
                if rules.max.is_some_and(|max| number > max) {
                    return Err(issue(path, "Too big: expected number to be smaller"));
                }
                Ok(value.clone())
            }
            Self::Literal(expected) => {
                if literal_equals(expected, value) {
                    Ok(value.clone())
                } else {
                    Err(issue(path, format!("Invalid input: expected {expected}")))
                }
            }
            Self::Enum(options) => match value {
                Value::String(text) if options.contains(&text.as_str()) => Ok(value.clone()),
                _ => Err(issue(path, "Invalid option")),
            },
            Self::Array(item, length) => {
                let Value::Array(items) = value else {
                    return Err(issue(path, "Invalid input: expected array"));
                };
                if length.min.is_some_and(|min| items.len() < min) {
                    return Err(issue(path, "Too small: expected array to have more items"));
                }
                if length.max.is_some_and(|max| items.len() > max) {
                    return Err(issue(path, "Too big: expected array to have fewer items"));
                }
                let mut output = Vec::with_capacity(items.len());
                for (index, entry) in items.iter().enumerate() {
                    path.push(index.to_string());
                    let parsed = item.run(entry, path);
                    path.pop();
                    output.push(parsed?);
                }
                Ok(Value::Array(output))
            }
            Self::Tuple(items) => {
                let Value::Array(entries) = value else {
                    return Err(issue(path, "Invalid input: expected tuple"));
                };
                if entries.len() != items.len() {
                    return Err(issue(path, "Invalid tuple length"));
                }
                let mut output = Vec::with_capacity(items.len());
                for (index, (schema, entry)) in items.iter().zip(entries).enumerate() {
                    path.push(index.to_string());
                    let parsed = schema.run(entry, path);
                    path.pop();
                    output.push(parsed?);
                }
                Ok(Value::Array(output))
            }
            Self::Record(item) => {
                let Value::Object(entries) = value else {
                    return Err(issue(path, "Invalid input: expected record"));
                };
                let mut output = Map::new();
                for (key, entry) in entries {
                    path.push(key.clone());
                    let parsed = item.run(entry, path);
                    path.pop();
                    output.insert(key.clone(), parsed?);
                }
                Ok(Value::Object(output))
            }
            Self::Object(object) => object.run(value, path),
            Self::Nullable(inner) => match value {
                Value::Null => Ok(Value::Null),
                _ => inner.run(value, path),
            },
            Self::Union(options) => {
                let mut first = None;
                for option in options {
                    match option.run(value, path) {
                        Ok(parsed) => return Ok(parsed),
                        Err(error) => {
                            first.get_or_insert(error);
                        }
                    }
                }
                Err(first.unwrap_or_else(|| issue(path, "Invalid input")))
            }
            Self::Discriminated(key, options) => {
                let Value::Object(object) = value else {
                    return Err(issue(path, "Invalid input: expected object"));
                };
                let discriminator = object.get(*key);
                for option in options {
                    if option.discriminator_accepts(key, discriminator) {
                        return option.run(value, path);
                    }
                }
                path.push((*key).to_owned());
                let error = issue(path, "Invalid input");
                path.pop();
                Err(error)
            }
            Self::Refined(inner, check) => {
                let parsed = inner.run(value, path)?;
                check(&parsed).map_err(|message| issue(path, message))?;
                Ok(parsed)
            }
        }
    }

    fn discriminator_accepts(&self, key: &str, value: Option<&Value>) -> bool {
        match self {
            Self::Object(object) => object
                .fields
                .iter()
                .find(|field| field.name == key)
                .is_some_and(|field| value.is_some_and(|value| field.schema.accepts(value))),
            Self::Refined(inner, _) => inner.discriminator_accepts(key, value),
            _ => false,
        }
    }

    /// The object shape when this schema is (a refinement of) an object.
    pub fn object_shape(&self) -> Option<&Arc<ObjectSchema>> {
        match self {
            Self::Object(object) => Some(object),
            Self::Refined(inner, _) => inner.object_shape(),
            _ => None,
        }
    }
}

fn literal_equals(expected: &Value, value: &Value) -> bool {
    match (expected, value) {
        (Value::Number(left), Value::Number(right)) => left.as_f64() == right.as_f64(),
        _ => expected == value,
    }
}

impl ObjectSchema {
    fn run(&self, value: &Value, path: &mut Vec<String>) -> Result<Value, Issue> {
        let Value::Object(input) = value else {
            return Err(issue(path, "Invalid input: expected object"));
        };
        let mut output = Map::new();
        for field in &self.fields {
            match input.get(field.name) {
                Some(entry) => {
                    path.push(field.name.to_owned());
                    let parsed = field.schema.run(entry, path);
                    path.pop();
                    output.insert(field.name.to_owned(), parsed?);
                }
                None => match &field.presence {
                    Presence::Required => {
                        path.push(field.name.to_owned());
                        let error =
                            issue(path, "Invalid input: expected value, received undefined");
                        path.pop();
                        return Err(error);
                    }
                    Presence::Optional => {}
                    Presence::Default(default) => {
                        output.insert(field.name.to_owned(), default());
                    }
                },
            }
        }
        if self.unknown == UnknownKeys::Strict
            && let Some(key) = input
                .keys()
                .find(|key| !self.fields.iter().any(|field| field.name == key.as_str()))
        {
            return Err(issue(path, format!("Unrecognized key: \"{key}\"")));
        }
        Ok(Value::Object(output))
    }

    /// Shape extension (`.extend`/`.safeExtend`): existing keys keep their
    /// position with the replacement schema; new keys are appended.
    pub fn extended(&self, fields: Vec<Field>) -> Self {
        let mut extended = self.clone();
        for field in fields {
            if let Some(existing) = extended
                .fields
                .iter_mut()
                .find(|existing| existing.name == field.name)
            {
                *existing = field;
            } else {
                extended.fields.push(field);
            }
        }
        extended
    }

    /// Shape without the named keys (`.omit`).
    pub fn omitted(&self, names: &[&str]) -> Self {
        let mut omitted = self.clone();
        omitted.fields.retain(|field| !names.contains(&field.name));
        omitted
    }

    /// Same shape with a different unknown-key policy.
    pub fn with_unknown(&self, unknown: UnknownKeys) -> Self {
        let mut changed = self.clone();
        changed.unknown = unknown;
        changed
    }
}

// ---------------------------------------------------------------------------
// Builders mirroring the Zod spellings used by the original contracts.

pub fn unknown() -> Schema {
    Schema::Unknown
}
pub fn null() -> Schema {
    Schema::Null
}
pub fn boolean() -> Schema {
    Schema::Bool
}
pub fn string() -> Schema {
    Schema::String(StringRules::default())
}
/// `z.string().min(min)`.
pub fn string_min(min: usize) -> Schema {
    Schema::String(StringRules {
        min: Some(min),
        ..StringRules::default()
    })
}
/// `z.string().regex(...)`.
pub fn string_matching(pattern: Pattern) -> Schema {
    Schema::String(StringRules {
        pattern: Some(pattern),
        ..StringRules::default()
    })
}
/// `z.string().min(min).regex(...)`.
pub fn string_min_matching(min: usize, pattern: Pattern) -> Schema {
    Schema::String(StringRules {
        min: Some(min),
        max: None,
        pattern: Some(pattern),
    })
}
pub fn number() -> Schema {
    Schema::Number(NumberRules::default())
}
/// `z.number().int()`.
pub fn int() -> Schema {
    Schema::Number(NumberRules {
        integer: true,
        ..NumberRules::default()
    })
}
/// `z.number().int().min(min)`.
pub fn int_min(min: i64) -> Schema {
    Schema::Number(NumberRules {
        integer: true,
        min: Some(min as f64),
        ..NumberRules::default()
    })
}
/// `z.number().int().min(min).max(max)`.
pub fn int_range(min: i64, max: i64) -> Schema {
    Schema::Number(NumberRules {
        integer: true,
        min: Some(min as f64),
        max: Some(max as f64),
        ..NumberRules::default()
    })
}
/// `z.number().int().nonnegative()`.
pub fn nonnegative_int() -> Schema {
    int_min(0)
}
/// `z.number().int().positive()`.
pub fn positive_int() -> Schema {
    Schema::Number(NumberRules {
        integer: true,
        exclusive_min: Some(0.0),
        ..NumberRules::default()
    })
}
/// `z.number().nonnegative()` (any finite number at least zero).
pub fn nonnegative_number() -> Schema {
    Schema::Number(NumberRules {
        min: Some(0.0),
        ..NumberRules::default()
    })
}
/// `z.number().min(min).max(max)`.
pub fn number_range(min: f64, max: f64) -> Schema {
    Schema::Number(NumberRules {
        min: Some(min),
        max: Some(max),
        ..NumberRules::default()
    })
}
pub fn literal(value: Value) -> Schema {
    Schema::Literal(value)
}
pub fn literal_str(value: &'static str) -> Schema {
    Schema::Literal(Value::String(value.to_owned()))
}
pub fn literal_bool(value: bool) -> Schema {
    Schema::Literal(Value::Bool(value))
}
pub fn enumeration(options: &'static [&'static str]) -> Schema {
    Schema::Enum(options)
}
pub fn array(item: Schema) -> Schema {
    Schema::Array(Box::new(item), Length::default())
}
/// `z.array(item).min(min)`.
pub fn array_min(item: Schema, min: usize) -> Schema {
    Schema::Array(
        Box::new(item),
        Length {
            min: Some(min),
            max: None,
        },
    )
}
/// `z.array(item).min(min).max(max)` / `.length(n)`.
pub fn array_range(item: Schema, min: usize, max: usize) -> Schema {
    Schema::Array(
        Box::new(item),
        Length {
            min: Some(min),
            max: Some(max),
        },
    )
}
pub fn tuple(items: Vec<Schema>) -> Schema {
    Schema::Tuple(items)
}
pub fn record(value: Schema) -> Schema {
    Schema::Record(Box::new(value))
}
pub fn nullable(inner: Schema) -> Schema {
    Schema::Nullable(Box::new(inner))
}
pub fn union(options: Vec<Schema>) -> Schema {
    Schema::Union(options)
}
pub fn discriminated(key: &'static str, options: Vec<Schema>) -> Schema {
    Schema::Discriminated(key, options)
}
pub fn refine(inner: Schema, check: Check) -> Schema {
    Schema::Refined(Box::new(inner), check)
}
/// Required field.
pub fn field(name: &'static str, schema: Schema) -> Field {
    Field {
        name,
        schema,
        presence: Presence::Required,
    }
}
/// `optional()` / `exactOptional()` field.
pub fn optional(name: &'static str, schema: Schema) -> Field {
    Field {
        name,
        schema,
        presence: Presence::Optional,
    }
}
/// `default(...)` field.
pub fn defaulted(name: &'static str, schema: Schema, default: fn() -> Value) -> Field {
    Field {
        name,
        schema,
        presence: Presence::Default(default),
    }
}
/// `z.object(...)` (strips unknown keys).
pub fn object(fields: Vec<Field>) -> Schema {
    Schema::Object(Arc::new(ObjectSchema {
        fields,
        unknown: UnknownKeys::Strip,
    }))
}
/// `z.strictObject(...)` / `.strict()`.
pub fn strict(fields: Vec<Field>) -> Schema {
    Schema::Object(Arc::new(ObjectSchema {
        fields,
        unknown: UnknownKeys::Strict,
    }))
}
/// Wrap an object shape as a schema.
pub fn from_shape(shape: ObjectSchema) -> Schema {
    Schema::Object(Arc::new(shape))
}

/// Default factories shared by many schemas.
pub fn empty_array() -> Value {
    Value::Array(Vec::new())
}
pub fn null_value() -> Value {
    Value::Null
}
pub fn false_value() -> Value {
    Value::Bool(false)
}
pub fn zero() -> Value {
    Value::from(0)
}

/// `^[a-f0-9]{64}$`.
pub fn is_lower_sha256(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
