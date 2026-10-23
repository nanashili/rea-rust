//! Application-schema refinements the advertised JSON Schema cannot express.
//!
//! Compatibility owner: `src/domain/inputIssueProjection.ts`. The server
//! already validated the frozen `inputSchema` and applied defaults; the
//! original services then re-parsed with Zod schemas carrying refinements
//! (NUL-free argv strings, encoded argument budgets). Their `custom` issues
//! project as `invalid_value` with the refinement message.
use rea_core::analysis_error::InputIssue;
use serde_json::{Value, json};

/// A `custom` refinement issue at `path`.
pub fn custom(path: &[Value], message: &str) -> InputIssue {
    InputIssue {
        path: path.to_vec(),
        reason: "invalid_value",
        message: Some(message.to_owned()),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

/// The argv refinement: `!value.includes("\0")`.
pub fn argument(issues: &mut Vec<InputIssue>, path: &[&str], index: Option<usize>, value: &str) {
    if value.contains('\0') {
        let mut segments = path.iter().map(|part| json!(part)).collect::<Vec<_>>();
        if let Some(index) = index {
            segments.push(json!(index));
        }
        issues.push(custom(&segments, "NUL is not an argument character"));
    }
}

/// Unsigned integer argument accepting integral JSON numbers of either form.
pub fn uint(input: &Value, key: &str) -> Option<u64> {
    let value = input.get(key)?;
    value.as_u64().or_else(|| {
        value
            .as_f64()
            .filter(|number| {
                number.fract() == 0.0 && *number >= 0.0 && *number <= 9_007_199_254_740_991.0
            })
            .map(|number| number as u64)
    })
}

/// `JSON.parse` failure text. V8's exact token excerpt is not reproduced;
/// the position-bearing form preserves where the producer output broke.
pub fn json_parse_message(text: &str, error: &serde_json::Error) -> String {
    if error.is_eof() {
        return "Unexpected end of JSON input".to_owned();
    }
    let mut position = 0;
    for (index, current) in text.split_inclusive('\n').enumerate() {
        if index + 1 == error.line() {
            position += error.column().saturating_sub(1).min(current.len());
            break;
        }
        position += current.len();
    }
    format!("Unexpected token in JSON at position {position}")
}

/// Zod's `ZodError.message`: the issue list as two-space-indented JSON.
pub fn zod_message(code: &str, path: &[Value], message: &str, expected: Option<&str>) -> String {
    let mut issue = serde_json::Map::new();
    if let Some(expected) = expected {
        issue.insert("expected".into(), json!(expected));
    }
    issue.insert("code".into(), json!(code));
    issue.insert("path".into(), Value::Array(path.to_vec()));
    issue.insert("message".into(), json!(message));
    zod_issues(vec![Value::Object(issue)])
}

/// Zod's `ZodError.message` for prebuilt issue objects (v4 key order).
pub fn zod_issues(issues: Vec<Value>) -> String {
    serde_json::to_string_pretty(&Value::Array(issues)).unwrap_or_default()
}

/// Zod v4's received-type name for an `invalid_type` issue message.
pub fn received_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}
