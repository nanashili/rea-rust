//! Shared JSON Schema parser for source Zod-compatible validation facts.

use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, OnceLock};

use crate::digests::PrefixedDigestContract;

/// How keys outside a closed object shape are treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownKeys {
    /// `z.object`: unknown keys are dropped from the parsed value.
    Strip,
    /// `z.strictObject`: unknown keys are reported.
    Reject,
}

/// Why a local schema reference could not be resolved.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    ExternalReference,
    MissingReference,
    CyclicReference,
}

/// One Zod issue with an absolute path from the parsed root.
#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub struct Issue {
    pub path: Vec<Value>,
    pub kind: IssueKind,
    /// Check failures continue parsing; type and shape failures abort a branch.
    pub aborts: bool,
}

/// Zod issue codes used by the original projection.
#[allow(missing_docs)]
#[derive(Clone, Debug)]
pub enum IssueKind {
    InvalidType {
        expected: String,
    },
    InvalidValue {
        values: Vec<Value>,
    },
    TooSmall {
        minimum: Option<f64>,
        exclusive: bool,
    },
    TooBig {
        maximum: Option<f64>,
        exclusive: bool,
    },
    InvalidFormat {
        format: String,
        message: String,
    },
    UnrecognizedKeys {
        keys: Vec<String>,
    },
    /// Branch issues carry absolute paths; `options` lists unmatched discriminators.
    InvalidUnion {
        errors: Vec<Vec<Issue>>,
        options: Option<Vec<Value>>,
    },
    Custom {
        message: String,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParseState {
    Succeeded,
    Aborted,
    Continuable,
}

fn compiled(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache
        .entry(pattern.to_owned())
        .or_insert_with(|| Regex::new(pattern).ok())
        .clone()
}

fn is_absolute_local_path(value: &str) -> bool {
    value.starts_with('/')
        || (value.len() >= 3
            && value.as_bytes()[0].is_ascii_alphabetic()
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'/' | b'\\'))
}

fn is_json_object_projection(schema: &Map<String, Value>) -> bool {
    schema.get("type").and_then(Value::as_str) == Some("object")
        && !schema.contains_key("properties")
        && !schema.contains_key("required")
        && schema.get("additionalProperties") == Some(&Value::Object(Map::new()))
}

/// Source-owned facts that supplement a lossy JSON Schema projection.
#[derive(Clone, Copy, Debug, Default)]
pub struct SchemaMetadata {
    /// Explicit digest contracts available to this named schema owner.
    pub prefixed_digests: &'static [PrefixedDigestContract],
    /// Explicit defaults omitted from the advertised schema projection.
    pub defaults: &'static [DefaultField],
    /// Source-owned root refinements requiring at least one named field.
    pub at_least_one_fields: &'static [AtLeastOneFields],
    /// Source-owned root refinements requiring exactly one named field.
    pub exactly_one_fields: &'static [ExactlyOneFields],
    /// Source-owned array refinements requiring an exact count of item values.
    pub exactly_one_array_item_values: &'static [ExactlyOneArrayItemValue],
    /// Explicit source messages for named regular-expression contracts.
    pub pattern_messages: &'static [PatternMessage],
    /// Explicit source messages for regular-expression contracts at one path.
    pub field_pattern_messages: &'static [FieldPatternMessage],
    /// Explicit source refinements requiring absolute local paths.
    pub absolute_path_messages: &'static [AbsolutePathMessage],
    /// Explicit source messages for lower-bound failures at one path.
    pub minimum_messages: &'static [MinimumMessage],
    /// Source-owned fields that must be the literal boolean `true`.
    pub required_true_fields: &'static [&'static str],
}

/// A named source refinement requiring one field from a finite set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtLeastOneFields {
    /// Top-level object fields examined by the refinement.
    pub fields: &'static [&'static str],
    /// Original source message for the refinement.
    pub message: &'static str,
}

/// A named source refinement requiring exactly one field from a finite set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactlyOneFields {
    /// Top-level object fields examined by the refinement.
    pub fields: &'static [&'static str],
    /// Original source message for the refinement.
    pub message: &'static str,
}

/// A source-owned refinement requiring exactly one array item with a field value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExactlyOneArrayItemValue {
    /// Top-level array field examined by the refinement.
    pub array_field: &'static str,
    /// Item field compared with `value`.
    pub item_field: &'static str,
    /// Required item field value.
    pub value: &'static str,
    /// Original source message for the refinement.
    pub message: &'static str,
}

/// A source-owned message for one exact JSON Schema pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PatternMessage {
    /// JSON Schema pattern emitted by the source contract.
    pub pattern: &'static str,
    /// Original source validation message.
    pub message: &'static str,
}

/// A source-owned message for one exact JSON Schema pattern at one path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldPatternMessage {
    /// Object path relative to the contract root.
    pub path: &'static [&'static str],
    /// JSON Schema pattern emitted by the source contract.
    pub pattern: &'static str,
    /// Original source validation message.
    pub message: &'static str,
}

/// A source-owned absolute local path refinement for one object path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsolutePathMessage {
    /// Object path relative to the contract root.
    pub path: &'static [&'static str],
    /// Original source validation message.
    pub message: &'static str,
}

/// A source-owned message replacing a projected lower-bound message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinimumMessage {
    /// Object path relative to the contract root.
    pub path: &'static [&'static str],
    /// Original source validation message.
    pub message: &'static str,
}

/// A source-owned default for a named top-level contract field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefaultField {
    /// Object path relative to the contract root.
    pub path: &'static [&'static str],
    /// The source default value.
    pub value: DefaultValue,
}

/// Default values currently needed by named graph input contracts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefaultValue {
    /// An empty source array default.
    EmptyArray,
    /// A source string default.
    String(&'static str),
    /// The browser scenario storage object and its source array defaults.
    BrowserStorage,
}

impl SchemaMetadata {
    fn regex_message(self, path: &[Value], pattern: &str) -> Option<&'static str> {
        self.field_pattern_messages
            .iter()
            .find(|contract| {
                contract.pattern == pattern
                    && contract.path.len() == path.len()
                    && contract.path.iter().zip(path).all(|(expected, actual)| {
                        *expected == "*" || actual.as_str() == Some(*expected)
                    })
            })
            .map(|contract| contract.message)
            .or_else(|| {
                self.prefixed_digests
                    .iter()
                    .find(|contract| contract.pattern == pattern)
                    .map(|contract| contract.invalid_message)
            })
            .or_else(|| {
                self.pattern_messages
                    .iter()
                    .find(|contract| contract.pattern == pattern)
                    .map(|contract| contract.message)
            })
    }
}

/// A parser bound to one schema document (for `#/$defs/...` references).
pub struct Parser<'r> {
    root: &'r Value,
    unknown_keys: UnknownKeys,
    metadata: SchemaMetadata,
}

/// Validate a value against a rooted schema using strict object semantics.
pub fn validate(root: &Value, value: &Value) -> Result<Value, Vec<Issue>> {
    Parser::new(root, UnknownKeys::Reject).parse(value)
}

/// Validate with explicit source metadata for a named contract owner.
pub fn validate_with_metadata(
    root: &Value,
    value: &Value,
    metadata: SchemaMetadata,
) -> Result<Value, Vec<Issue>> {
    Parser::new(root, UnknownKeys::Reject)
        .with_metadata(metadata)
        .parse(value)
}

/// Collect parser facts without collapsing a dirty-but-continuable branch.
pub fn diagnose_with_metadata(
    root: &Value,
    value: &Value,
    metadata: SchemaMetadata,
) -> (Option<Value>, Vec<Issue>) {
    Parser::new(root, UnknownKeys::Reject)
        .with_metadata(metadata)
        .diagnose(value)
}

/// Resolve a schema reference chain within one JSON Schema document.
pub fn resolve_schema<'a>(root: &'a Value, schema: &'a Value) -> Result<&'a Value, ResolveError> {
    resolve_reference_chain(root, schema).map(|(resolved, _)| resolved)
}

fn resolve_reference_chain<'a>(
    root: &'a Value,
    schema: &'a Value,
) -> Result<(&'a Value, Option<&'a Value>), ResolveError> {
    let mut current = schema;
    let mut default = schema.get("default");
    let mut references = HashSet::new();

    loop {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return Ok((current, default));
        };
        if !references.insert(reference) {
            return Err(ResolveError::CyclicReference);
        }

        let Some(pointer) = reference.strip_prefix('#') else {
            return Err(ResolveError::ExternalReference);
        };
        let Some(target) = root.pointer(pointer) else {
            return Err(ResolveError::MissingReference);
        };

        current = target;
        if default.is_none() {
            default = current.get("default");
        }
    }
}

impl<'r> Parser<'r> {
    #[allow(missing_docs)]
    pub fn new(root: &'r Value, unknown_keys: UnknownKeys) -> Self {
        Self {
            root,
            unknown_keys,
            metadata: SchemaMetadata::default(),
        }
    }

    /// Attach source-owned facts for the named contract being parsed.
    pub fn with_metadata(mut self, metadata: SchemaMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Parse `value` against the document root.
    pub fn parse(&self, value: &Value) -> Result<Value, Vec<Issue>> {
        let (parsed, issues) = self.diagnose(value);
        if issues.is_empty() {
            Ok(parsed.unwrap_or(Value::Null))
        } else {
            Err(issues)
        }
    }

    /// Preserve parsed facts and issue abort state for a union owner.
    pub fn diagnose(&self, value: &Value) -> (Option<Value>, Vec<Issue>) {
        let mut issues = Vec::new();
        let mut path = Vec::new();
        let parsed = self.check(self.root, Some(value), &mut path, &mut issues);
        self.check_at_least_one_fields(parsed.as_ref(), &mut issues);
        self.check_exactly_one_fields(parsed.as_ref(), &mut issues);
        self.check_exactly_one_array_item_values(parsed.as_ref(), &mut issues);
        self.check_required_true_fields(parsed.as_ref(), &mut issues);
        if issues.is_empty() {
            let mut parsed = parsed.unwrap_or(Value::Null);
            self.apply_defaults(&mut parsed);
            (Some(parsed), issues)
        } else {
            (parsed, issues)
        }
    }

    fn check_at_least_one_fields(&self, parsed: Option<&Value>, issues: &mut Vec<Issue>) {
        let Some(object) = parsed.and_then(Value::as_object) else {
            return;
        };
        if issues.iter().any(|issue| {
            issue.path.is_empty() && matches!(issue.kind, IssueKind::UnrecognizedKeys { .. })
        }) {
            return;
        }

        for requirement in self.metadata.at_least_one_fields {
            if requirement
                .fields
                .iter()
                .all(|field| !object.contains_key(*field))
            {
                Self::push(
                    issues,
                    &[],
                    IssueKind::Custom {
                        message: requirement.message.to_owned(),
                    },
                    true,
                );
            }
        }
    }

    fn check_exactly_one_fields(&self, parsed: Option<&Value>, issues: &mut Vec<Issue>) {
        let Some(object) = parsed.and_then(Value::as_object) else {
            return;
        };
        if issues.iter().any(|issue| {
            issue.path.is_empty() && matches!(issue.kind, IssueKind::UnrecognizedKeys { .. })
        }) {
            return;
        }

        for requirement in self.metadata.exactly_one_fields {
            let present = requirement
                .fields
                .iter()
                .filter(|field| object.contains_key(**field))
                .count();
            if present != 1 {
                Self::push(
                    issues,
                    &[],
                    IssueKind::Custom {
                        message: requirement.message.to_owned(),
                    },
                    true,
                );
            }
        }
    }

    fn check_exactly_one_array_item_values(&self, parsed: Option<&Value>, issues: &mut Vec<Issue>) {
        let Some(object) = parsed.and_then(Value::as_object) else {
            return;
        };

        for requirement in self.metadata.exactly_one_array_item_values {
            let Some(items) = object
                .get(requirement.array_field)
                .and_then(Value::as_array)
            else {
                continue;
            };
            if items.iter().any(|item| !item.is_object()) {
                continue;
            }
            let matching_items = items
                .iter()
                .filter(|item| {
                    item.as_object()
                        .and_then(|item| item.get(requirement.item_field))
                        .and_then(Value::as_str)
                        == Some(requirement.value)
                })
                .count();
            if matching_items != 1 {
                Self::push(
                    issues,
                    &[Value::String(requirement.array_field.to_owned())],
                    IssueKind::Custom {
                        message: requirement.message.to_owned(),
                    },
                    true,
                );
            }
        }
    }

    fn check_required_true_fields(&self, parsed: Option<&Value>, issues: &mut Vec<Issue>) {
        let Some(object) = parsed.and_then(Value::as_object) else {
            return;
        };

        for field in self.metadata.required_true_fields {
            if let Some(value) = object.get(*field)
                && value != &Value::Bool(true)
            {
                let path = vec![Value::String((*field).to_owned())];
                issues.retain(|issue| issue.path != path);
                Self::push(
                    issues,
                    &path,
                    IssueKind::InvalidValue {
                        values: vec![Value::Bool(true)],
                    },
                    true,
                );
            }
        }
    }

    fn apply_defaults(&self, parsed: &mut Value) {
        let Some(object) = parsed.as_object_mut() else {
            return;
        };

        for field in self.metadata.defaults {
            let Some(name) = field.path.first() else {
                continue;
            };
            if field.path.len() != 1 || object.contains_key(*name) {
                continue;
            }
            let value = match field.value {
                DefaultValue::EmptyArray => Value::Array(Vec::new()),
                DefaultValue::String(value) => Value::String(value.to_owned()),
                DefaultValue::BrowserStorage => serde_json::json!({
                    "cookies": [],
                    "local_storage": [],
                    "session_storage": [],
                }),
            };
            object.insert((*name).to_owned(), value);
        }
    }

    /// Follow local references; a sibling `default` is returned separately.
    fn resolve<'a>(&'a self, schema: &'a Value) -> (&'a Value, Option<&'a Value>) {
        static UNSUPPORTED_SCHEMA: OnceLock<Value> = OnceLock::new();

        match resolve_reference_chain(self.root, schema) {
            Ok((resolved, default)) => (resolved, default),
            Err(_) => (UNSUPPORTED_SCHEMA.get_or_init(|| Value::Bool(false)), None),
        }
    }

    fn push(issues: &mut Vec<Issue>, path: &[Value], kind: IssueKind, aborts: bool) {
        issues.push(Issue {
            path: path.to_vec(),
            kind,
            aborts,
        });
    }

    fn push_minimum(
        &self,
        issues: &mut Vec<Issue>,
        path: &[Value],
        minimum: Option<f64>,
        exclusive: bool,
    ) {
        if let Some(message) = self
            .metadata
            .minimum_messages
            .iter()
            .find(|contract| {
                contract.path.len() == path.len()
                    && contract.path.iter().zip(path).all(|(expected, actual)| {
                        *expected == "*" || actual.as_str() == Some(*expected)
                    })
            })
            .map(|contract| contract.message)
        {
            Self::push(
                issues,
                path,
                IssueKind::Custom {
                    message: message.to_owned(),
                },
                false,
            );
            return;
        }

        Self::push(
            issues,
            path,
            IssueKind::TooSmall { minimum, exclusive },
            false,
        );
    }

    /// Parse one value (`None` is an absent property).
    fn check(
        &self,
        schema: &Value,
        value: Option<&Value>,
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
    ) -> Option<Value> {
        let (schema, default) = self.resolve(schema);
        if value.is_none()
            && let Some(default) = default
        {
            return Some(default.clone());
        }
        let object = match schema {
            Value::Bool(true) => return value.cloned(),
            Value::Bool(false) => {
                Self::push(
                    issues,
                    path,
                    IssueKind::Custom {
                        message: "Invalid input".into(),
                    },
                    true,
                );
                return value.cloned();
            }
            Value::Object(object) => object,
            _ => return value.cloned(),
        };

        if object
            .get("not")
            .is_some_and(|not| matches!(not, Value::Object(fields) if fields.is_empty()))
        {
            Self::push(
                issues,
                path,
                IssueKind::InvalidType {
                    expected: "never".into(),
                },
                true,
            );
            return value.cloned();
        }

        if let Some(options) = object.get("oneOf").and_then(Value::as_array) {
            // Object discriminators select a single branch before parsing it.
            // Array unions have no discriminator and must still enforce
            // oneOf's exactly-one rule; requiring an object here rejects
            // valid tuple branches such as relationship coverage directions.
            return if self.discriminator(options).is_some() {
                self.discriminated(options, value, path, issues)
            } else {
                self.union(options, value, path, issues, true)
            };
        }
        if let Some(options) = object.get("anyOf").and_then(Value::as_array) {
            return self.union(options, value, path, issues, false);
        }
        // Literal and enum schemas report invalid_value before any type check.
        if let Some(constant) = object.get("const") {
            if value != Some(constant) {
                Self::push(
                    issues,
                    path,
                    IssueKind::InvalidValue {
                        values: vec![constant.clone()],
                    },
                    true,
                );
            }
            return value.cloned();
        }
        if let Some(options) = object.get("enum").and_then(Value::as_array) {
            if !value.is_some_and(|value| options.contains(value)) {
                Self::push(
                    issues,
                    path,
                    IssueKind::InvalidValue {
                        values: options.clone(),
                    },
                    true,
                );
            }
            return value.cloned();
        }

        let Some(value) = value else {
            let expected = match object.get("type") {
                _ if is_json_object_projection(object) => "nonoptional".to_owned(),
                Some(Value::String(name)) if name == "integer" => "number".to_owned(),
                Some(Value::String(name))
                    if name == "object" && object.contains_key("propertyNames") =>
                {
                    "record".to_owned()
                }
                Some(Value::String(name)) => name.clone(),
                Some(Value::Array(names)) => names
                    .iter()
                    .filter_map(Value::as_str)
                    .find(|name| *name != "null")
                    .map(|name| if name == "integer" { "number" } else { name })
                    .unwrap_or("nonoptional")
                    .to_owned(),
                _ => "nonoptional".to_owned(),
            };
            Self::push(issues, path, IssueKind::InvalidType { expected }, true);
            return None;
        };

        if let Some(expected) = object.get("type") {
            let names: Vec<&str> = match expected {
                Value::String(name) => vec![name.as_str()],
                Value::Array(names) => names.iter().filter_map(Value::as_str).collect(),
                _ => Vec::new(),
            };
            if !names.is_empty() && !names.iter().any(|name| type_matches(name, value)) {
                if is_json_object_projection(object) {
                    Self::push(
                        issues,
                        path,
                        IssueKind::Custom {
                            message: "Expected JSON object".into(),
                        },
                        true,
                    );
                    return Some(value.clone());
                }
                let primary = names
                    .iter()
                    .find(|name| **name != "null")
                    .copied()
                    .unwrap_or(names[0]);
                let expected = if primary == "object" && object.contains_key("propertyNames") {
                    "record"
                } else if primary == "integer" {
                    if value.is_number() { "int" } else { "number" }
                } else {
                    primary
                };
                Self::push(
                    issues,
                    path,
                    IssueKind::InvalidType {
                        expected: expected.to_owned(),
                    },
                    true,
                );
                self.check_size_after_type_mismatch(object, value, path, issues);
                return Some(value.clone());
            }
        }

        match value {
            Value::String(text) => {
                self.check_string(object, text, path, issues);
                self.check_all_of(object, value, path, issues);
                Some(value.clone())
            }
            Value::Number(number) => {
                if let Some(number) = number.as_f64() {
                    check_number(object, number, path, issues);
                }
                self.check_all_of(object, value, path, issues);
                Some(value.clone())
            }
            Value::Array(items) => {
                let parsed = self.check_array(object, items, path, issues);
                self.check_all_of(object, value, path, issues);
                Some(parsed)
            }
            Value::Object(map) => {
                let parsed = self.check_object(object, map, path, issues);
                self.check_all_of(object, value, path, issues);
                Some(parsed)
            }
            _ => Some(value.clone()),
        }
    }

    fn check_all_of(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
    ) {
        let Some(parts) = schema.get("allOf").and_then(Value::as_array) else {
            return;
        };
        for part in parts {
            self.check(part, Some(value), path, issues);
        }
    }

    fn check_size_after_type_mismatch(
        &self,
        schema: &Map<String, Value>,
        value: &Value,
        path: &[Value],
        issues: &mut Vec<Issue>,
    ) {
        let (minimum, maximum, length) = match value {
            Value::String(text) => (
                schema.get("minItems").and_then(Value::as_f64),
                schema.get("maxItems").and_then(Value::as_f64),
                text.chars().count() as f64,
            ),
            Value::Array(items) => (
                schema.get("minLength").and_then(Value::as_f64),
                schema.get("maxLength").and_then(Value::as_f64),
                items.len() as f64,
            ),
            _ => (None, None, 0.0),
        };
        if let Some(limit) = minimum
            && length < limit
        {
            self.push_minimum(issues, path, Some(limit), false);
        }
        if let Some(limit) = maximum
            && length > limit
        {
            Self::push(
                issues,
                path,
                IssueKind::TooBig {
                    maximum: Some(limit),
                    exclusive: false,
                },
                false,
            );
        }
    }

    fn check_string(
        &self,
        schema: &Map<String, Value>,
        text: &str,
        path: &[Value],
        issues: &mut Vec<Issue>,
    ) {
        let length = text.encode_utf16().count() as f64;
        if let Some(minimum) = schema.get("minLength").and_then(Value::as_f64)
            && length < minimum
        {
            self.push_minimum(issues, path, Some(minimum), false);
        }
        if let Some(maximum) = schema.get("maxLength").and_then(Value::as_f64)
            && length > maximum
        {
            Self::push(
                issues,
                path,
                IssueKind::TooBig {
                    maximum: Some(maximum),
                    exclusive: false,
                },
                false,
            );
        }
        if let Some(format) = schema.get("format").and_then(Value::as_str) {
            let (valid, name) = match format {
                "uuid" => (uuid_like(text), "uuid"),
                "date-time" => (iso_datetime(text), "datetime"),
                "email" => (text.contains('@'), "email"),
                "uri" => (text.contains(':'), "url"),
                other => (true, other),
            };
            if !valid {
                Self::push(
                    issues,
                    path,
                    IssueKind::InvalidFormat {
                        format: name.to_owned(),
                        message: format!("Invalid {name}"),
                    },
                    false,
                );
            }
        }
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str) {
            match compiled(pattern) {
                Some(regex) if !regex.is_match(text) => Self::push(
                    issues,
                    path,
                    IssueKind::InvalidFormat {
                        format: "regex".into(),
                        message: self.metadata.regex_message(path, pattern).map_or_else(
                            || format!("Invalid string: must match pattern /{pattern}/u"),
                            str::to_owned,
                        ),
                    },
                    false,
                ),
                Some(_) => {}
                None => Self::push(
                    issues,
                    path,
                    IssueKind::InvalidFormat {
                        format: "regex".into(),
                        message: format!("Unsupported regex pattern /{pattern}/u"),
                    },
                    true,
                ),
            }
        }

        if let Some(contract) = self
            .metadata
            .absolute_path_messages
            .iter()
            .find(|contract| {
                contract.path.len() == path.len()
                    && contract.path.iter().zip(path).all(|(expected, actual)| {
                        *expected == "*" || actual.as_str() == Some(*expected)
                    })
            })
            && !is_absolute_local_path(text)
        {
            Self::push(
                issues,
                path,
                IssueKind::Custom {
                    message: contract.message.to_owned(),
                },
                false,
            );
        }
    }

    fn check_array(
        &self,
        schema: &Map<String, Value>,
        items: &[Value],
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
    ) -> Value {
        let length = items.len() as f64;
        if let Some(minimum) = schema.get("minItems").and_then(Value::as_f64)
            && length < minimum
        {
            self.push_minimum(issues, path, Some(minimum), false);
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_f64)
            && length > maximum
        {
            Self::push(
                issues,
                path,
                IssueKind::TooBig {
                    maximum: Some(maximum),
                    exclusive: false,
                },
                false,
            );
        }
        let prefix = schema.get("prefixItems").and_then(Value::as_array);
        let rest = schema.get("items");
        let mut parsed = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let item_schema = prefix.and_then(|prefix| prefix.get(index)).or(rest);
            let value = match item_schema {
                Some(item_schema) => {
                    path.push(Value::from(index));
                    let value = self.check(item_schema, Some(item), path, issues);
                    path.pop();
                    value.unwrap_or(Value::Null)
                }
                None => item.clone(),
            };
            parsed.push(value);
        }
        Value::Array(parsed)
    }

    fn check_object(
        &self,
        schema: &Map<String, Value>,
        object: &Map<String, Value>,
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
    ) -> Value {
        let empty = Map::new();
        let properties = schema
            .get("properties")
            .and_then(Value::as_object)
            .unwrap_or(&empty);
        let required: Vec<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .map(|required| required.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut parsed = Map::new();
        for (key, property) in properties {
            path.push(Value::String(key.clone()));
            match object.get(key) {
                Some(value) => {
                    if let Some(value) = self.check(property, Some(value), path, issues) {
                        parsed.insert(key.clone(), value);
                    }
                }
                None => {
                    let (_, default) = self.resolve(property);
                    if let Some(default) = default {
                        parsed.insert(key.clone(), default.clone());
                    } else if required.contains(&key.as_str()) {
                        self.check(property, None, path, issues);
                    }
                }
            }
            path.pop();
        }
        for key in &required {
            if !properties.contains_key(*key) && !object.contains_key(*key) {
                path.push(Value::String((*key).to_owned()));
                Self::push(
                    issues,
                    path,
                    IssueKind::InvalidType {
                        expected: "nonoptional".into(),
                    },
                    true,
                );
                path.pop();
            }
        }

        self.check_object_size(schema, object, path, issues);

        let additional = schema.get("additionalProperties");
        let pattern_properties = schema.get("patternProperties").and_then(Value::as_object);
        let property_names = schema.get("propertyNames");
        let mut unknown = Vec::new();
        for (key, value) in object {
            if properties.contains_key(key) {
                continue;
            }
            if let Some(names) = property_names {
                path.push(Value::String(key.clone()));
                self.check(names, Some(&Value::String(key.clone())), path, issues);
                path.pop();
            }
            if let Some(patterns) = pattern_properties
                && let Some((_, pattern_schema)) = patterns
                    .iter()
                    .find(|(pattern, _)| compiled(pattern).is_some_and(|regex| regex.is_match(key)))
            {
                path.push(Value::String(key.clone()));
                if let Some(value) = self.check(pattern_schema, Some(value), path, issues) {
                    parsed.insert(key.clone(), value);
                }
                path.pop();
                continue;
            }
            match additional {
                Some(Value::Bool(false)) => {
                    if self.unknown_keys == UnknownKeys::Reject {
                        unknown.push(key.clone());
                    }
                }
                Some(extra @ Value::Object(_)) => {
                    path.push(Value::String(key.clone()));
                    if let Some(value) = self.check(extra, Some(value), path, issues) {
                        parsed.insert(key.clone(), value);
                    }
                    path.pop();
                }
                _ => {
                    parsed.insert(key.clone(), value.clone());
                }
            }
        }
        if !unknown.is_empty() {
            Self::push(
                issues,
                path,
                IssueKind::UnrecognizedKeys { keys: unknown },
                true,
            );
        }
        Value::Object(parsed)
    }

    fn check_object_size(
        &self,
        schema: &Map<String, Value>,
        object: &Map<String, Value>,
        path: &[Value],
        issues: &mut Vec<Issue>,
    ) {
        if path.is_empty() && !self.metadata.at_least_one_fields.is_empty() {
            return;
        }

        let count = object.len() as f64;
        if let Some(minimum) = schema.get("minProperties").and_then(Value::as_f64)
            && count < minimum
            && !issues
                .iter()
                .any(|issue| issue.aborts && issue.path.starts_with(path))
        {
            Self::push(
                issues,
                path,
                IssueKind::TooSmall {
                    minimum: Some(minimum),
                    exclusive: false,
                },
                false,
            );
        }
        if let Some(maximum) = schema.get("maxProperties").and_then(Value::as_f64)
            && count > maximum
        {
            Self::push(
                issues,
                path,
                IssueKind::TooBig {
                    maximum: Some(maximum),
                    exclusive: false,
                },
                false,
            );
        }
    }

    /// `z.union` (and `.nullable()`, rendered as a two-branch union with null).
    fn union(
        &self,
        options: &[Value],
        value: Option<&Value>,
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
        exclusive: bool,
    ) -> Option<Value> {
        if !exclusive && options.len() == 2 {
            let null_branch = options.iter().position(|option| {
                let (option, _) = self.resolve(option);
                option.get("type").and_then(Value::as_str) == Some("null")
                    && option.as_object().is_some_and(|object| object.len() == 1)
            });
            if let Some(null_index) = null_branch {
                if value == Some(&Value::Null) {
                    return Some(Value::Null);
                }
                return self.check(&options[1 - null_index], value, path, issues);
            }
        }
        let mut results = Vec::with_capacity(options.len());
        for option in options {
            let mut branch = Vec::new();
            let parsed = self.check(option, value, &mut path.clone(), &mut branch);
            let state = parse_state(&branch);
            if !exclusive && state == ParseState::Succeeded {
                return parsed;
            }
            results.push((parsed, branch, state));
        }
        let successful: Vec<usize> = results
            .iter()
            .enumerate()
            .filter(|(_, (_, _, state))| *state == ParseState::Succeeded)
            .map(|(index, _)| index)
            .collect();
        if successful.len() == 1 {
            return results.swap_remove(successful[0]).0;
        }
        if exclusive && successful.len() > 1 {
            Self::push(
                issues,
                path,
                IssueKind::InvalidUnion {
                    errors: results.into_iter().map(|(_, branch, _)| branch).collect(),
                    options: self.union_options(options),
                },
                true,
            );
            return value.cloned();
        }
        let nonaborted: Vec<usize> = results
            .iter()
            .enumerate()
            .filter(|(_, (_, _, state))| *state == ParseState::Continuable)
            .map(|(index, _)| index)
            .collect();
        if nonaborted.len() == 1 {
            let (parsed, branch, _) = results.swap_remove(nonaborted[0]);
            issues.extend(branch);
            return parsed;
        }
        Self::push(
            issues,
            path,
            IssueKind::InvalidUnion {
                errors: results.into_iter().map(|(_, branch, _)| branch).collect(),
                options: self.union_options(options),
            },
            true,
        );
        value.cloned()
    }

    fn union_options(&self, options: &[Value]) -> Option<Vec<Value>> {
        let mut values = Vec::new();
        for option in options {
            let (resolved, _) = self.resolve(option);
            let Some(object) = resolved.as_object() else {
                continue;
            };
            if let Some(constant) = object.get("const") {
                values.push(constant.clone());
            }
            if let Some(enums) = object.get("enum").and_then(Value::as_array) {
                values.extend(enums.iter().cloned());
            }
        }
        (!values.is_empty()).then_some(values)
    }

    /// `z.discriminatedUnion`, rendered as `oneOf` with constant discriminators.
    fn discriminated(
        &self,
        options: &[Value],
        value: Option<&Value>,
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
    ) -> Option<Value> {
        let Some(Value::Object(object)) = value else {
            Self::push(
                issues,
                path,
                IssueKind::InvalidType {
                    expected: "object".into(),
                },
                true,
            );
            return value.cloned();
        };
        let Some(key) = self.discriminator(options) else {
            return self.union(options, value, path, issues, false);
        };
        let candidate = object.get(&key);
        let mut all = Vec::new();
        for option in options {
            let values = self.discriminator_values(option, &key);
            if candidate.is_some_and(|candidate| values.contains(candidate)) {
                return self.check(option, value, path, issues);
            }
            all.extend(values);
        }
        path.push(Value::String(key));
        Self::push(
            issues,
            path,
            IssueKind::InvalidUnion {
                errors: Vec::new(),
                options: Some(all),
            },
            true,
        );
        path.pop();
        value.cloned()
    }

    /// The `z.discriminatedUnion` key: a property constant in every option
    /// (nested unions included) whose values select exactly one option. A
    /// property that is constant everywhere but shared between options (for
    /// example a common `parent_operation` enum) cannot discriminate.
    fn discriminator(&self, options: &[Value]) -> Option<String> {
        let first = options.first()?;
        let candidates = self.constant_keys(first);
        candidates.into_iter().find(|key| {
            let mut seen = std::collections::HashSet::new();
            options.iter().all(|option| {
                // Nested unions may repeat their parent's constant.
                let values = self
                    .discriminator_values(option, key)
                    .iter()
                    .map(Value::to_string)
                    .collect::<std::collections::HashSet<_>>();
                !values.is_empty() && values.into_iter().all(|value| seen.insert(value))
            })
        })
    }

    fn constant_keys(&self, option: &Value) -> Vec<String> {
        let (option, _) = self.resolve(option);
        if let Some(nested) = option
            .get("oneOf")
            .or_else(|| option.get("anyOf"))
            .and_then(Value::as_array)
        {
            return nested
                .first()
                .map(|first| self.constant_keys(first))
                .unwrap_or_default();
        }
        option
            .get("properties")
            .and_then(Value::as_object)
            .map(|properties| {
                properties
                    .iter()
                    .filter(|(_, property)| {
                        let (property, _) = self.resolve(property);
                        property.get("const").is_some()
                            || property
                                .get("enum")
                                .and_then(Value::as_array)
                                .is_some_and(|values| !values.is_empty())
                    })
                    .map(|(key, _)| key.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn discriminator_values(&self, option: &Value, key: &str) -> Vec<Value> {
        let (option, _) = self.resolve(option);
        if let Some(nested) = option
            .get("oneOf")
            .or_else(|| option.get("anyOf"))
            .and_then(Value::as_array)
        {
            return nested
                .iter()
                .flat_map(|nested| self.discriminator_values(nested, key))
                .collect();
        }
        let Some(property) = option
            .get("properties")
            .and_then(|properties| properties.get(key))
        else {
            return Vec::new();
        };
        let (property, _) = self.resolve(property);
        if let Some(constant) = property.get("const") {
            return vec![constant.clone()];
        }
        property
            .get("enum")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    }
}

fn parse_state(issues: &[Issue]) -> ParseState {
    if issues.is_empty() {
        ParseState::Succeeded
    } else if issues.iter().any(|issue| issue.aborts) {
        ParseState::Aborted
    } else {
        ParseState::Continuable
    }
}

fn type_matches(expected: &str, value: &Value) -> bool {
    match expected {
        "object" => value.is_object(),
        "array" => value.is_array(),
        "string" => value.is_string(),
        "boolean" => value.is_boolean(),
        "null" => value.is_null(),
        "number" => value.is_number(),
        "integer" => value
            .as_f64()
            .is_some_and(|number| number.is_finite() && number.fract() == 0.0),
        _ => true,
    }
}

fn check_number(schema: &Map<String, Value>, number: f64, path: &[Value], issues: &mut Vec<Issue>) {
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && number < minimum
    {
        Parser::push(
            issues,
            path,
            IssueKind::TooSmall {
                minimum: Some(minimum),
                exclusive: false,
            },
            false,
        );
    }
    if let Some(minimum) = schema.get("exclusiveMinimum").and_then(Value::as_f64)
        && number <= minimum
    {
        Parser::push(
            issues,
            path,
            IssueKind::TooSmall {
                minimum: Some(minimum),
                exclusive: true,
            },
            false,
        );
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
        && number > maximum
    {
        Parser::push(
            issues,
            path,
            IssueKind::TooBig {
                maximum: Some(maximum),
                exclusive: false,
            },
            false,
        );
    }
    if let Some(maximum) = schema.get("exclusiveMaximum").and_then(Value::as_f64)
        && number >= maximum
    {
        Parser::push(
            issues,
            path,
            IssueKind::TooBig {
                maximum: Some(maximum),
                exclusive: true,
            },
            false,
        );
    }
    if let Some(divisor) = schema.get("multipleOf").and_then(Value::as_f64)
        && divisor != 0.0
        && (number / divisor).fract() != 0.0
    {
        Parser::push(
            issues,
            path,
            IssueKind::Custom {
                message: format!("Invalid number: must be a multiple of {divisor}"),
            },
            false,
        );
    }
}

fn uuid_like(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn iso_datetime(text: &str) -> bool {
    compiled(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})$")
        .is_some_and(|regex| regex.is_match(text))
}

#[cfg(test)]
mod tests {
    use super::{
        AtLeastOneFields, ExactlyOneArrayItemValue, IssueKind, ResolveError, SchemaMetadata,
        resolve_schema, validate, validate_with_metadata,
    };
    use crate::digests::EVIDENCE_ID;
    use serde_json::json;

    #[test]
    fn unresolved_reference_fails_closed() {
        let schema = json!({"$ref": "#/defs/missing"});

        assert!(validate(&schema, &json!(null)).is_err());
    }

    #[test]
    fn unresolved_reference_does_not_apply_sibling_default() {
        let schema = json!({
            "$ref": "#/defs/missing",
            "default": "unsafe-fallback"
        });

        assert!(validate(&schema, &json!(null)).is_err());
    }

    #[test]
    fn cyclic_reference_fails_closed() {
        let schema = json!({
            "$ref": "#/$defs/node",
            "$defs": {"node": {"$ref": "#/$defs/node"}}
        });

        assert!(validate(&schema, &json!({})).is_err());
    }

    #[test]
    fn resolver_reports_reference_failures_without_fallback() {
        let missing = json!({"$ref": "#/$defs/missing"});
        let external = json!({"$ref": "other.json"});
        let cyclic = json!({
            "$ref": "#/$defs/node",
            "$defs": {"node": {"$ref": "#/$defs/node"}}
        });

        assert_eq!(
            resolve_schema(&missing, &missing),
            Err(ResolveError::MissingReference)
        );
        assert_eq!(
            resolve_schema(&external, &external),
            Err(ResolveError::ExternalReference)
        );
        assert_eq!(
            resolve_schema(&cyclic, &cyclic),
            Err(ResolveError::CyclicReference)
        );
    }

    #[test]
    fn all_of_keeps_sibling_type_and_size_constraints() {
        let schema = json!({
            "type": "string",
            "minLength": 1,
            "allOf": [{"pattern": "^[^\\u0000]*$"}]
        });

        assert!(validate(&schema, &json!(null)).is_err());
        assert!(validate(&schema, &json!("")).is_err());
        assert!(validate(&schema, &json!("valid")).is_ok());
    }

    #[test]
    fn object_property_limits_are_checked() {
        let schema = json!({
            "type": "object",
            "minProperties": 1,
            "maxProperties": 1
        });

        assert!(validate(&schema, &json!({})).is_err());
        assert!(validate(&schema, &json!({"first": 1})).is_ok());
        assert!(validate(&schema, &json!({"first": 1, "second": 2})).is_err());
    }

    #[test]
    fn named_at_least_one_refinement_is_applied() {
        let schema = json!({
            "type": "object",
            "minProperties": 1,
            "properties": {
                "artifact": {"type": "object"},
                "members": {"type": "object"}
            }
        });
        let metadata = SchemaMetadata {
            at_least_one_fields: &[AtLeastOneFields {
                fields: &["artifact", "members"],
                message: "Invalid input",
            }],
            ..SchemaMetadata::default()
        };

        let issues = validate_with_metadata(&schema, &json!({}), metadata)
            .expect_err("named refinement rejects an empty input");

        assert!(matches!(
            &issues[0].kind,
            IssueKind::Custom { message } if message == "Invalid input"
        ));
    }

    #[test]
    fn named_exactly_one_array_item_refinement_is_applied() {
        let schema = json!({
            "type": "object",
            "properties": {
                "static_layers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"role": {"type": "string"}}
                    }
                }
            }
        });
        let metadata = SchemaMetadata {
            exactly_one_array_item_values: &[ExactlyOneArrayItemValue {
                array_field: "static_layers",
                item_field: "role",
                value: "application",
                message: "Exactly one application static layer is required",
            }],
            ..SchemaMetadata::default()
        };

        let issues = validate_with_metadata(
            &schema,
            &json!({"static_layers": [{"role": "runtime"}]}),
            metadata,
        )
        .expect_err("named refinement rejects a missing application layer");

        assert!(matches!(
            &issues[0].kind,
            IssueKind::Custom { message }
                if message == "Exactly one application static layer is required"
        ));
    }

    #[test]
    fn named_prefixed_digest_keeps_source_owned_message() {
        let schema = json!({
            "type": "string",
            "pattern": "^ev_[a-f0-9]{64}$"
        });
        let metadata = SchemaMetadata {
            prefixed_digests: &[EVIDENCE_ID],
            ..SchemaMetadata::default()
        };
        let issues = validate_with_metadata(&schema, &json!("ev_invalid"), metadata)
            .expect_err("digest is invalid");

        assert!(matches!(
            &issues[0].kind,
            IssueKind::InvalidFormat { message, .. }
                if message == "Expected a ev_ prefixed lowercase sha256 digest"
        ));
    }

    #[test]
    fn unrelated_pattern_keeps_generic_message_without_metadata() {
        let schema = json!({
            "type": "string",
            "pattern": "^ev_[a-f0-9]{64}$"
        });
        let issues = validate(&schema, &json!("ev_invalid")).expect_err("value is invalid");

        assert!(matches!(
            &issues[0].kind,
            IssueKind::InvalidFormat { message, .. }
                if message == "Invalid string: must match pattern /^ev_[a-f0-9]{64}$/u"
        ));
    }
}
