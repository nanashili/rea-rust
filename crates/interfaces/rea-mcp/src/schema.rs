//! Advertised-input validation with the original SDK/Zod issue wording.
//!
//! The frozen catalog carries the exact JSON Schema projection the original
//! runtime advertised. This validator interprets that projection, applies
//! declared defaults like the original parser, and formats issues exactly as
//! `Input validation error: Invalid arguments for tool NAME: ISSUES`.
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// One rejected argument location and message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issue {
    pub path: Vec<String>,
    pub message: String,
}

impl Issue {
    fn new(path: &[String], message: impl Into<String>) -> Self {
        Self {
            path: path.to_vec(),
            message: message.into(),
        }
    }

    /// SDK issue formatting: `path.joined: message` or the bare message.
    pub fn render(&self) -> String {
        if self.path.is_empty() {
            self.message.clone()
        } else {
            format!("{}: {}", self.path.join("."), self.message)
        }
    }
}

/// Render the SDK's complete validation failure text.
pub fn validation_error_text(tool: &str, issues: &[Issue]) -> String {
    format!(
        "Input validation error: Invalid arguments for tool {tool}: {}",
        issues
            .iter()
            .map(Issue::render)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

/// Validate `value` against `schema`, returning the parsed value with
/// declared defaults applied, or every issue found.
pub fn validate(schema: &Value, value: &Value) -> Result<Value, Vec<Issue>> {
    let mut issues = Vec::new();
    let parsed = check(schema, schema, value, &mut Vec::new(), &mut issues);
    if issues.is_empty() {
        Ok(parsed)
    } else {
        Err(issues)
    }
}

/// Whether `value` satisfies `schema` (used for union branches).
pub fn matches(schema: &Value, value: &Value) -> bool {
    let mut issues = Vec::new();
    check(schema, schema, value, &mut Vec::new(), &mut issues);
    issues.is_empty()
}

fn received_type(value: Option<&Value>) -> &'static str {
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

/// Follow local `#/$defs/...` references within the same root document.
fn resolve<'a>(root: &'a Value, schema: &'a Value) -> &'a Value {
    let mut current = schema;
    for _ in 0..64 {
        let Some(reference) = current.get("$ref").and_then(Value::as_str) else {
            return current;
        };
        let Some(pointer) = reference.strip_prefix('#') else {
            return current;
        };
        match root.pointer(pointer) {
            Some(target) => current = target,
            None => return current,
        }
    }
    current
}

fn number_text(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e21 {
        format!("{}", value as i128)
    } else {
        let mut buffer = ryu_text(value);
        if buffer.ends_with(".0") {
            buffer.truncate(buffer.len() - 2);
        }
        buffer
    }
}

fn ryu_text(value: f64) -> String {
    serde_json::Number::from_f64(value)
        .map(|number| number.to_string())
        .unwrap_or_else(|| value.to_string())
}

fn primitive_text(value: &Value) -> String {
    match value {
        Value::String(text) => format!("\"{text}\""),
        Value::Number(number) => number
            .as_f64()
            .map(number_text)
            .unwrap_or_else(|| number.to_string()),
        other => other.to_string(),
    }
}

fn js_length(text: &str) -> usize {
    text.encode_utf16().count()
}

fn compiled(pattern: &str) -> Option<Regex> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Regex>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().ok()?;
    cache
        .entry(pattern.to_owned())
        .or_insert_with(|| Regex::new(pattern).ok())
        .clone()
}

fn uuid_like(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        let dash = matches!(index, 8 | 13 | 18 | 23);
        if dash != (*byte == b'-') {
            return false;
        }
        if !dash && !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn iso_datetime(text: &str) -> bool {
    compiled(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})$")
        .is_some_and(|regex| regex.is_match(text))
}

fn check(
    root: &Value,
    schema: &Value,
    value: &Value,
    path: &mut Vec<String>,
    issues: &mut Vec<Issue>,
) -> Value {
    let schema = resolve(root, schema);
    match schema {
        Value::Bool(true) => return value.clone(),
        Value::Bool(false) => {
            issues.push(Issue::new(path, "Invalid input"));
            return value.clone();
        }
        Value::Object(_) => {}
        _ => return value.clone(),
    }

    // Unions and intersections.
    if let Some(options) = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)
    {
        let mut matched = None;
        for option in options {
            let mut option_issues = Vec::new();
            let parsed = check(root, option, value, &mut path.clone(), &mut option_issues);
            if option_issues.is_empty() {
                matched = Some(parsed);
                break;
            }
        }
        match matched {
            Some(parsed) => return parsed,
            None => {
                // A discriminated-union branch that matches its discriminator
                // reports that branch's precise issues, as the original parser does.
                if let Some(branch) = discriminated_branch(root, options, value) {
                    let parsed = check(root, branch, value, path, issues);
                    return parsed;
                }
                issues.push(Issue::new(path, "Invalid input"));
                return value.clone();
            }
        }
    }
    let mut current = value.clone();
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for part in all {
            current = check(root, part, &current, path, issues);
        }
    }
    if let Some(negated) = schema.get("not")
        && matches_with_root(root, negated, &current)
    {
        issues.push(Issue::new(path, "Invalid input"));
    }
    if let Some(condition) = schema.get("if") {
        let branch = if matches_with_root(root, condition, &current) {
            schema.get("then")
        } else {
            schema.get("else")
        };
        if let Some(branch) = branch {
            current = check(root, branch, &current, path, issues);
        }
    }

    // Type gate.
    if let Some(expected) = schema.get("type") {
        let accepted = match expected {
            Value::String(name) => type_matches(name, &current),
            Value::Array(names) => names
                .iter()
                .filter_map(Value::as_str)
                .any(|name| type_matches(name, &current)),
            _ => true,
        };
        if !accepted {
            let name = match expected {
                Value::String(name) => name.as_str(),
                Value::Array(names) => names.first().and_then(Value::as_str).unwrap_or("value"),
                _ => "value",
            };
            let (label, received) = if name == "integer" && current.is_number() {
                ("int", "number")
            } else if name == "integer" {
                ("number", received_type(Some(&current)))
            } else {
                (name, received_type(Some(&current)))
            };
            issues.push(Issue::new(
                path,
                format!("Invalid input: expected {label}, received {received}"),
            ));
            return current;
        }
    }

    if let Some(constant) = schema.get("const")
        && constant != &current
    {
        issues.push(Issue::new(
            path,
            format!("Invalid input: expected {}", primitive_text(constant)),
        ));
        return current;
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array)
        && !options.contains(&current)
    {
        let message = if options.len() == 1 {
            format!("Invalid input: expected {}", primitive_text(&options[0]))
        } else {
            format!(
                "Invalid option: expected one of {}",
                options
                    .iter()
                    .map(primitive_text)
                    .collect::<Vec<_>>()
                    .join("|")
            )
        };
        issues.push(Issue::new(path, message));
        return current;
    }

    match &current {
        Value::String(text) => check_string(schema, text, path, issues),
        Value::Number(number) => {
            if let Some(number) = number.as_f64() {
                check_number(schema, number, path, issues);
            }
        }
        Value::Array(_) => {
            current = check_array(root, schema, current, path, issues);
        }
        Value::Object(_) => {
            current = check_object(root, schema, current, path, issues);
        }
        _ => {}
    }
    current
}

fn matches_with_root(root: &Value, schema: &Value, value: &Value) -> bool {
    let mut issues = Vec::new();
    check(root, schema, value, &mut Vec::new(), &mut issues);
    issues.is_empty()
}

/// Select the union branch whose constant discriminator matches the value.
fn discriminated_branch<'a>(
    root: &'a Value,
    options: &'a [Value],
    value: &Value,
) -> Option<&'a Value> {
    let object = value.as_object()?;
    let mut selected = None;
    for option in options {
        let option = resolve(root, option);
        let properties = option.get("properties").and_then(Value::as_object)?;
        let mut discriminates = false;
        let mut agrees = true;
        for (key, property) in properties {
            let property = resolve(root, property);
            if let Some(constant) = property.get("const") {
                discriminates = true;
                if object.get(key) != Some(constant) {
                    agrees = false;
                }
            }
        }
        if discriminates && agrees {
            if selected.is_some() {
                return None;
            }
            selected = Some(option);
        }
    }
    selected
}

fn check_string(schema: &Value, text: &str, path: &[String], issues: &mut Vec<Issue>) {
    let length = js_length(text);
    if let Some(minimum) = schema.get("minLength").and_then(Value::as_u64)
        && (length as u64) < minimum
    {
        issues.push(Issue::new(
            path,
            format!("Too small: expected string to have >={minimum} characters"),
        ));
    }
    if let Some(maximum) = schema.get("maxLength").and_then(Value::as_u64)
        && (length as u64) > maximum
    {
        issues.push(Issue::new(
            path,
            format!("Too big: expected string to have <={maximum} characters"),
        ));
    }
    if let Some(format) = schema.get("format").and_then(Value::as_str) {
        let valid = match format {
            "uuid" => uuid_like(text),
            "date-time" => iso_datetime(text),
            _ => true,
        };
        if !valid {
            let label = match format {
                "uuid" => "UUID",
                "date-time" => "ISO datetime",
                other => other,
            };
            issues.push(Issue::new(path, format!("Invalid {label}")));
            return;
        }
    }
    if let Some(pattern) = schema.get("pattern").and_then(Value::as_str)
        && let Some(regex) = compiled(pattern)
        && !regex.is_match(text)
    {
        issues.push(Issue::new(
            path,
            format!("Invalid string: must match pattern /{pattern}/"),
        ));
    }
}

fn check_number(schema: &Value, number: f64, path: &[String], issues: &mut Vec<Issue>) {
    if let Some(minimum) = schema.get("minimum").and_then(Value::as_f64)
        && number < minimum
    {
        issues.push(Issue::new(
            path,
            format!(
                "Too small: expected number to be >={}",
                number_text(minimum)
            ),
        ));
    }
    if let Some(minimum) = schema.get("exclusiveMinimum").and_then(Value::as_f64)
        && number <= minimum
    {
        issues.push(Issue::new(
            path,
            format!("Too small: expected number to be >{}", number_text(minimum)),
        ));
    }
    if let Some(maximum) = schema.get("maximum").and_then(Value::as_f64)
        && number > maximum
    {
        issues.push(Issue::new(
            path,
            format!("Too big: expected number to be <={}", number_text(maximum)),
        ));
    }
    if let Some(maximum) = schema.get("exclusiveMaximum").and_then(Value::as_f64)
        && number >= maximum
    {
        issues.push(Issue::new(
            path,
            format!("Too big: expected number to be <{}", number_text(maximum)),
        ));
    }
    if let Some(divisor) = schema.get("multipleOf").and_then(Value::as_f64)
        && divisor != 0.0
        && (number / divisor).fract() != 0.0
    {
        issues.push(Issue::new(
            path,
            format!(
                "Invalid number: must be a multiple of {}",
                number_text(divisor)
            ),
        ));
    }
}

fn check_array(
    root: &Value,
    schema: &Value,
    current: Value,
    path: &mut Vec<String>,
    issues: &mut Vec<Issue>,
) -> Value {
    let Value::Array(items) = current else {
        return current;
    };
    let length = items.len() as u64;
    if let Some(minimum) = schema.get("minItems").and_then(Value::as_u64)
        && length < minimum
    {
        issues.push(Issue::new(
            path,
            format!("Too small: expected array to have >={minimum} items"),
        ));
    }
    if let Some(maximum) = schema.get("maxItems").and_then(Value::as_u64)
        && length > maximum
    {
        issues.push(Issue::new(
            path,
            format!("Too big: expected array to have <={maximum} items"),
        ));
    }
    let prefix = schema
        .get("prefixItems")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rest = schema.get("items");
    let mut parsed = Vec::with_capacity(items.len());
    for (index, item) in items.into_iter().enumerate() {
        path.push(index.to_string());
        let item_schema = prefix.get(index).or(rest);
        let value = match item_schema {
            Some(item_schema) => check(root, item_schema, &item, path, issues),
            None => item,
        };
        path.pop();
        parsed.push(value);
    }
    if schema.get("uniqueItems").and_then(Value::as_bool) == Some(true) {
        for (index, item) in parsed.iter().enumerate() {
            if parsed[..index].contains(item) {
                issues.push(Issue::new(path, "Invalid input"));
                break;
            }
        }
    }
    Value::Array(parsed)
}

fn check_object(
    root: &Value,
    schema: &Value,
    current: Value,
    path: &mut Vec<String>,
    issues: &mut Vec<Issue>,
) -> Value {
    let Value::Object(object) = current else {
        return current;
    };
    let empty = Map::new();
    let properties = schema
        .get("properties")
        .and_then(Value::as_object)
        .unwrap_or(&empty);
    let required = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|required| {
            required
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut parsed = Map::new();
    // Declared shape keys first, in declaration order.
    for (key, property) in properties {
        path.push(key.clone());
        match object.get(key) {
            Some(value) => {
                let value = check(root, property, value, path, issues);
                parsed.insert(key.clone(), value);
            }
            None => {
                let property_schema = resolve(root, property);
                if let Some(default) = property_schema.get("default") {
                    parsed.insert(key.clone(), default.clone());
                } else if required.iter().any(|name| name == key) {
                    issues.push(Issue::new(path, missing_message(root, property_schema)));
                }
            }
        }
        path.pop();
    }
    // Required keys without a declared property schema.
    for key in &required {
        if !properties.contains_key(key) && !object.contains_key(key) {
            path.push(key.clone());
            issues.push(Issue::new(
                path,
                "Invalid input: expected nonoptional, received undefined",
            ));
            path.pop();
        }
    }
    let additional = schema.get("additionalProperties");
    let pattern_properties = schema.get("patternProperties").and_then(Value::as_object);
    let property_names = schema.get("propertyNames");
    let mut unknown = Vec::new();
    for (key, value) in &object {
        if properties.contains_key(key) {
            continue;
        }
        if let Some(names) = property_names {
            path.push(key.clone());
            let mut name_issues = Vec::new();
            check(
                root,
                names,
                &Value::String(key.clone()),
                &mut Vec::new(),
                &mut name_issues,
            );
            if !name_issues.is_empty() {
                issues.push(Issue::new(path, "Invalid key in record"));
            }
            path.pop();
        }
        let mut handled = false;
        if let Some(patterns) = pattern_properties {
            for (pattern, pattern_schema) in patterns {
                if compiled(pattern).is_some_and(|regex| regex.is_match(key)) {
                    path.push(key.clone());
                    let value = check(root, pattern_schema, value, path, issues);
                    path.pop();
                    parsed.insert(key.clone(), value);
                    handled = true;
                    break;
                }
            }
        }
        if handled {
            continue;
        }
        match additional {
            Some(Value::Bool(false)) => unknown.push(key.clone()),
            Some(extra @ Value::Object(_)) => {
                path.push(key.clone());
                let value = check(root, extra, value, path, issues);
                path.pop();
                parsed.insert(key.clone(), value);
            }
            _ => {
                parsed.insert(key.clone(), value.clone());
            }
        }
    }
    if !unknown.is_empty() {
        let quoted = unknown
            .iter()
            .map(|key| format!("\"{key}\""))
            .collect::<Vec<_>>()
            .join(", ");
        issues.push(Issue::new(
            path,
            format!(
                "Unrecognized key{}: {quoted}",
                if unknown.len() > 1 { "s" } else { "" }
            ),
        ));
    }
    let count = parsed.len() as u64;
    if let Some(minimum) = schema.get("minProperties").and_then(Value::as_u64)
        && count < minimum
    {
        issues.push(Issue::new(path, "Invalid input"));
    }
    if let Some(maximum) = schema.get("maxProperties").and_then(Value::as_u64)
        && count > maximum
    {
        issues.push(Issue::new(path, "Invalid input"));
    }
    Value::Object(parsed)
}

/// The original parser's message for an absent required property.
fn missing_message(root: &Value, schema: &Value) -> String {
    let schema = resolve(root, schema);
    if schema.get("anyOf").is_some() || schema.get("oneOf").is_some() {
        return "Invalid input".into();
    }
    if let Some(constant) = schema.get("const") {
        return format!("Invalid input: expected {}", primitive_text(constant));
    }
    if let Some(options) = schema.get("enum").and_then(Value::as_array) {
        return if options.len() == 1 {
            format!("Invalid input: expected {}", primitive_text(&options[0]))
        } else {
            format!(
                "Invalid option: expected one of {}",
                options
                    .iter()
                    .map(primitive_text)
                    .collect::<Vec<_>>()
                    .join("|")
            )
        };
    }
    match schema.get("type").and_then(Value::as_str) {
        Some("integer") => "Invalid input: expected number, received undefined".into(),
        Some(name) => format!("Invalid input: expected {name}, received undefined"),
        None => "Invalid input: expected nonoptional, received undefined".into(),
    }
}
