//! Zod-equivalent parsing over the frozen catalog's JSON Schema projections.
//!
//! Compatibility owners: the Zod contracts the original runtime parsed with
//! (`schema.safeParse`), `src/domain/inputIssueProjection.ts` (issue
//! projection) and `parseAnalysisViewResult` in
//! `src/domain/analysisView/analysisViewParent.ts`.
//!
//! The catalog carries the exact JSON Schema projection of every advertised
//! result contract, so a parent result is parsed against its owner's frozen
//! projection: declared defaults (including `default` beside a `$ref`) are
//! applied, unknown keys of plain objects are stripped like `z.object`, and
//! failures are reported as Zod issue codes before the original projection
//! into caller correction metadata.
use rea_core::analysis_error::{AnalysisError, InputIssue};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

/// How keys outside a closed object shape are treated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownKeys {
    /// `z.object`: unknown keys are dropped from the parsed value.
    Strip,
    /// `z.strictObject`: unknown keys are reported.
    Reject,
}

/// One Zod issue with an absolute path from the parsed root.
#[derive(Clone, Debug)]
pub struct Issue {
    pub path: Vec<Value>,
    pub kind: IssueKind,
    /// Check failures continue parsing; type and shape failures abort a branch.
    pub aborts: bool,
}

/// Zod issue codes used by the original projection.
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
    },
    TooBig {
        maximum: Option<f64>,
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

/// A parser bound to one schema document (for `#/$defs/...` references).
pub struct Parser<'r> {
    root: &'r Value,
    unknown_keys: UnknownKeys,
}

impl<'r> Parser<'r> {
    pub fn new(root: &'r Value, unknown_keys: UnknownKeys) -> Self {
        Self { root, unknown_keys }
    }

    /// Parse `value` against the document root.
    pub fn parse(&self, value: &Value) -> Result<Value, Vec<Issue>> {
        let mut issues = Vec::new();
        let mut path = Vec::new();
        let parsed = self.check(self.root, Some(value), &mut path, &mut issues);
        if issues.is_empty() {
            Ok(parsed.unwrap_or(Value::Null))
        } else {
            Err(issues)
        }
    }

    /// Follow local references; a sibling `default` is returned separately.
    fn resolve<'a>(&'a self, schema: &'a Value) -> (&'a Value, Option<&'a Value>) {
        let mut current = schema;
        let mut default = schema.get("default");
        for _ in 0..64 {
            let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
                break;
            };
            let Some(pointer) = reference.strip_prefix('#') else {
                break;
            };
            match self.root.pointer(pointer) {
                Some(target) => {
                    current = target;
                    if default.is_none() {
                        default = current.get("default");
                    }
                }
                None => break,
            }
        }
        (current, default)
    }

    fn push(issues: &mut Vec<Issue>, path: &[Value], kind: IssueKind, aborts: bool) {
        issues.push(Issue {
            path: path.to_vec(),
            kind,
            aborts,
        });
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

        if let Some(options) = object.get("oneOf").and_then(Value::as_array) {
            return self.discriminated(options, value, path, issues);
        }
        if let Some(options) = object.get("anyOf").and_then(Value::as_array) {
            return self.union(options, value, path, issues);
        }
        if let Some(parts) = object.get("allOf").and_then(Value::as_array) {
            let mut merged: Option<Value> = None;
            for part in parts {
                let parsed = self.check(part, value, path, issues);
                merged = match (merged, parsed) {
                    (Some(Value::Object(mut left)), Some(Value::Object(right))) => {
                        for (key, item) in right {
                            left.insert(key, item);
                        }
                        Some(Value::Object(left))
                    }
                    (_, parsed) => parsed,
                };
            }
            return merged;
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
                Some(Value::String(name)) if name == "integer" => "number".to_owned(),
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
                let primary = names
                    .iter()
                    .find(|name| **name != "null")
                    .copied()
                    .unwrap_or(names[0]);
                let expected = if primary == "integer" {
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
                return Some(value.clone());
            }
        }

        match value {
            Value::String(text) => {
                self.check_string(object, text, path, issues);
                Some(value.clone())
            }
            Value::Number(number) => {
                if let Some(number) = number.as_f64() {
                    check_number(object, number, path, issues);
                }
                Some(value.clone())
            }
            Value::Array(items) => Some(self.check_array(object, items, path, issues)),
            Value::Object(map) => Some(self.check_object(object, map, path, issues)),
            _ => Some(value.clone()),
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
            Self::push(
                issues,
                path,
                IssueKind::TooSmall {
                    minimum: Some(minimum),
                },
                false,
            );
        }
        if let Some(maximum) = schema.get("maxLength").and_then(Value::as_f64)
            && length > maximum
        {
            Self::push(
                issues,
                path,
                IssueKind::TooBig {
                    maximum: Some(maximum),
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
        if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
            && let Some(regex) = compiled(pattern)
            && !regex.is_match(text)
        {
            Self::push(
                issues,
                path,
                IssueKind::InvalidFormat {
                    format: "regex".into(),
                    message: format!("Invalid string: must match pattern /{pattern}/u"),
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
            Self::push(
                issues,
                path,
                IssueKind::TooSmall {
                    minimum: Some(minimum),
                },
                false,
            );
        }
        if let Some(maximum) = schema.get("maxItems").and_then(Value::as_f64)
            && length > maximum
        {
            Self::push(
                issues,
                path,
                IssueKind::TooBig {
                    maximum: Some(maximum),
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

    /// `z.union` (and `.nullable()`, rendered as a two-branch union with null).
    fn union(
        &self,
        options: &[Value],
        value: Option<&Value>,
        path: &mut Vec<Value>,
        issues: &mut Vec<Issue>,
    ) -> Option<Value> {
        if options.len() == 2 {
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
            if branch.is_empty() {
                return parsed;
            }
            results.push((parsed, branch));
        }
        let nonaborted: Vec<usize> = results
            .iter()
            .enumerate()
            .filter(|(_, (_, branch))| branch.iter().all(|issue| !issue.aborts))
            .map(|(index, _)| index)
            .collect();
        if nonaborted.len() == 1 {
            let (parsed, branch) = results.swap_remove(nonaborted[0]);
            issues.extend(branch);
            return parsed;
        }
        Self::push(
            issues,
            path,
            IssueKind::InvalidUnion {
                errors: results.into_iter().map(|(_, branch)| branch).collect(),
                options: None,
            },
            true,
        );
        value.cloned()
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
            return self.union(options, value, path, issues);
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

// ---------------------------------------------------------------------------
// Issue projection (`projectInputIssues`).
// ---------------------------------------------------------------------------

fn value_at_path<'a>(input: &'a Value, path: &[Value]) -> Option<&'a Value> {
    let mut current = input;
    for part in path {
        current = match (current, part) {
            (Value::Object(object), Value::String(key)) => object.get(key)?,
            (Value::Array(items), Value::Number(index)) => {
                items.get(usize::try_from(index.as_u64()?).ok()?)?
            }
            (Value::Object(object), Value::Number(index)) => object.get(&index.to_string())?,
            _ => return None,
        };
    }
    Some(current)
}

fn is_safe_expected(value: &Value) -> bool {
    matches!(
        value,
        Value::Null | Value::String(_) | Value::Number(_) | Value::Bool(_)
    )
}

fn projected_key(issue: &InputIssue) -> String {
    let mut object = Map::new();
    object.insert("path".into(), Value::Array(issue.path.clone()));
    object.insert("reason".into(), Value::String(issue.reason.into()));
    if let Some(message) = &issue.message {
        object.insert("message".into(), Value::String(message.clone()));
    }
    if let Some(expected) = &issue.expected {
        object.insert("expected".into(), expected.clone());
    }
    if let Some(minimum) = issue.minimum {
        object.insert("minimum".into(), Value::from(minimum));
    }
    if let Some(maximum) = issue.maximum {
        object.insert("maximum".into(), Value::from(maximum));
    }
    Value::Object(object).to_string()
}

fn input_issue(path: Vec<Value>, reason: &'static str) -> InputIssue {
    InputIssue {
        path,
        reason,
        message: None,
        expected: None,
        minimum: None,
        maximum: None,
    }
}

fn project_issue(issue: &Issue, input: &Value, output: &mut Vec<InputIssue>) {
    let path = issue.path.clone();
    match &issue.kind {
        IssueKind::InvalidUnion { errors, options } => {
            if errors.is_empty() {
                let mut projected = input_issue(
                    path.clone(),
                    if value_at_path(input, &path).is_none() {
                        "missing_argument"
                    } else {
                        "invalid_value"
                    },
                );
                if let Some(options) = options {
                    projected.expected = Some(Value::Array(
                        options
                            .iter()
                            .filter(|value| is_safe_expected(value))
                            .cloned()
                            .collect(),
                    ));
                }
                output.push(projected);
                return;
            }
            let mut flattened = Vec::new();
            for branch in errors {
                for branch_issue in branch {
                    project_issue(branch_issue, input, &mut flattened);
                }
            }
            let mut seen = std::collections::HashSet::new();
            for projected in flattened {
                if seen.insert(projected_key(&projected)) {
                    output.push(projected);
                }
            }
        }
        IssueKind::UnrecognizedKeys { keys } => {
            for key in keys {
                let mut key_path = path.clone();
                key_path.push(Value::String(key.clone()));
                output.push(input_issue(key_path, "unknown_argument"));
            }
        }
        IssueKind::InvalidType { expected } => {
            let mut projected = input_issue(
                path.clone(),
                if value_at_path(input, &path).is_none() {
                    "missing_argument"
                } else {
                    "invalid_type"
                },
            );
            projected.expected = Some(Value::String(expected.clone()));
            output.push(projected);
        }
        IssueKind::TooSmall { minimum } => {
            let mut projected = input_issue(path, "out_of_range");
            projected.minimum = minimum.filter(|value| value.is_finite());
            output.push(projected);
        }
        IssueKind::TooBig { maximum } => {
            let mut projected = input_issue(path, "out_of_range");
            projected.maximum = maximum.filter(|value| value.is_finite());
            output.push(projected);
        }
        IssueKind::InvalidFormat { format, message } => {
            let mut projected = input_issue(path, "invalid_format");
            projected.expected = Some(Value::String(format.clone()));
            if format == "regex" && !message.is_empty() {
                projected.message = Some(message.clone());
            }
            output.push(projected);
        }
        IssueKind::InvalidValue { values } => {
            let mut projected = input_issue(path, "invalid_value");
            projected.expected = Some(Value::Array(
                values
                    .iter()
                    .filter(|value| is_safe_expected(value))
                    .cloned()
                    .collect(),
            ));
            output.push(projected);
        }
        IssueKind::Custom { message } => {
            let mut projected = input_issue(path, "invalid_value");
            if !message.is_empty() {
                projected.message = Some(message.clone());
            }
            output.push(projected);
        }
    }
}

/// Project parsed issues into caller correction metadata (`projectInputIssues`).
pub fn project_issues(issues: &[Issue], input: &Value) -> Vec<InputIssue> {
    let mut output = Vec::new();
    for issue in issues {
        project_issue(issue, input, &mut output);
    }
    output
}

/// Prefix every issue path (for example `["source", "normalized_result"]`).
pub fn prefix_issues(issues: Vec<Issue>, prefix: &[&str]) -> Vec<Issue> {
    issues
        .into_iter()
        .map(|issue| prefix_issue(issue, prefix))
        .collect()
}

fn prefix_issue(mut issue: Issue, prefix: &[&str]) -> Issue {
    let mut path: Vec<Value> = prefix
        .iter()
        .map(|part| Value::String((*part).into()))
        .collect();
    path.append(&mut issue.path);
    issue.path = path;
    if let IssueKind::InvalidUnion { errors, .. } = &mut issue.kind {
        for branch in errors.iter_mut() {
            let taken = std::mem::take(branch);
            *branch = taken
                .into_iter()
                .map(|nested| prefix_issue(nested, prefix))
                .collect();
        }
    }
    issue
}

/// `analysisInputErrorFromIssues(operation, issues, input)`.
pub fn input_error_from_issues(
    operation: &str,
    issues: &[Issue],
    input: &Value,
    additional: Vec<InputIssue>,
) -> AnalysisError {
    let mut projected = project_issues(issues, input);
    projected.extend(additional);
    AnalysisError::input(operation, projected)
}

// ---------------------------------------------------------------------------
// Catalog projections.
// ---------------------------------------------------------------------------

fn schema_cache() -> &'static Mutex<HashMap<String, Option<Arc<Value>>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Arc<Value>>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn rooted(document: &Value, schema: &Value) -> Value {
    let mut root = match schema {
        Value::Object(object) => object.clone(),
        other => {
            let mut object = Map::new();
            object.insert("allOf".into(), Value::Array(vec![other.clone()]));
            object
        }
    };
    if let Some(defs) = document.get("$defs") {
        root.insert("$defs".into(), defs.clone());
    }
    Value::Object(root)
}

fn resolve_in<'a>(document: &'a Value, schema: &'a Value) -> &'a Value {
    let mut current = schema;
    for _ in 0..64 {
        let Some(pointer) = current
            .get("$ref")
            .and_then(Value::as_str)
            .and_then(|reference| reference.strip_prefix('#'))
        else {
            break;
        };
        match document.pointer(pointer) {
            Some(target) => current = target,
            None => break,
        }
    }
    current
}

fn is_view_result(document: &Value, schema: &Value) -> bool {
    let schema = resolve_in(document, schema);
    schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key("parent_evidence_id"))
}

/// The complete (non-view) `normalized_result` contract of one catalog tool.
pub fn tool_result_schema(tool: &str) -> Option<Arc<Value>> {
    cached_schema(&format!("result:{tool}"), || {
        let contract = rea_mcp::catalog().tool(tool)?;
        let document = contract.output_schema()?;
        let normalized = document.get("properties")?.get("normalized_result")?;
        let resolved = resolve_in(document, normalized);
        let branch = match resolved
            .get("anyOf")
            .or_else(|| resolved.get("oneOf"))
            .and_then(Value::as_array)
        {
            Some(options) => options
                .iter()
                .find(|option| !is_view_result(document, option))
                .unwrap_or(resolved),
            None => resolved,
        };
        Some(rooted(document, branch))
    })
}

/// The `inspect_analysis_view` result contract (`analysisViewResultSchema`).
pub fn view_result_schema() -> Option<Arc<Value>> {
    cached_schema("view-result", || {
        let contract = rea_mcp::catalog().tool("inspect_analysis_view")?;
        let document = contract.output_schema()?;
        let normalized = document.get("properties")?.get("normalized_result")?;
        Some(rooted(document, normalized))
    })
}

/// One named property contract inside the analysis-view input schema, rooted
/// for standalone parsing (for example the `view` request union).
pub fn view_input_schema() -> Option<Arc<Value>> {
    cached_schema("view-input", || {
        let contract = rea_mcp::catalog().tool("inspect_analysis_view")?;
        Some(rooted(contract.input_schema(), contract.input_schema()))
    })
}

/// Rooted `inputSchema` of a catalog tool.
pub fn tool_input_schema(tool: &str) -> Option<Arc<Value>> {
    cached_schema(&format!("input:{tool}"), || {
        let contract = rea_mcp::catalog().tool(tool)?;
        Some(rooted(contract.input_schema(), contract.input_schema()))
    })
}

fn cached_schema(key: &str, build: impl FnOnce() -> Option<Value>) -> Option<Arc<Value>> {
    let mut cache = schema_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(found) = cache.get(key) {
        return found.clone();
    }
    let built = build().map(Arc::new);
    cache.insert(key.to_owned(), built.clone());
    built
}

/// Parse `value` against a rooted schema with `z.object` semantics.
pub fn parse_stripped(root: &Value, value: &Value) -> Result<Value, Vec<Issue>> {
    Parser::new(root, UnknownKeys::Strip).parse(value)
}

/// Parse `value` against a rooted schema with `z.strictObject` semantics.
pub fn parse_strict(root: &Value, value: &Value) -> Result<Value, Vec<Issue>> {
    Parser::new(root, UnknownKeys::Reject).parse(value)
}

/// A short human-readable rendering of the first issues (diagnostics only).
pub fn describe(issues: &[Issue]) -> String {
    issues
        .iter()
        .take(4)
        .map(|issue| {
            let path = issue
                .path
                .iter()
                .map(|part| match part {
                    Value::String(text) => text.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(".");
            let kind = match &issue.kind {
                IssueKind::InvalidType { expected } => format!("expected {expected}"),
                IssueKind::InvalidValue { values } => format!(
                    "expected one of {}",
                    values
                        .iter()
                        .map(Value::to_string)
                        .collect::<Vec<_>>()
                        .join("|")
                ),
                IssueKind::TooSmall { .. } => "too small".into(),
                IssueKind::TooBig { .. } => "too big".into(),
                IssueKind::InvalidFormat { message, .. } => message.clone(),
                IssueKind::UnrecognizedKeys { keys } => format!("unrecognized keys {keys:?}"),
                IssueKind::InvalidUnion { .. } => "no union branch matched".into(),
                IssueKind::Custom { message } => message.clone(),
            };
            if path.is_empty() {
                kind
            } else {
                format!("{path}: {kind}")
            }
        })
        .collect::<Vec<_>>()
        .join("; ")
}
