//! Managed workflow adapters for shared schema facts and input-issue projection.

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::schema::resolve_schema;
pub use rea_core::schema::{Issue, IssueKind, Parser, SchemaMetadata, UnknownKeys};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

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

fn deduplicated_values(values: impl IntoIterator<Item = Value>) -> Vec<Value> {
    let mut deduplicated = Vec::new();
    for value in values {
        if !deduplicated.contains(&value) {
            deduplicated.push(value);
        }
    }
    deduplicated
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
                    projected.expected = Some(Value::Array(deduplicated_values(
                        options
                            .iter()
                            .filter(|value| is_safe_expected(value))
                            .cloned(),
                    )));
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
        IssueKind::TooSmall { minimum, .. } => {
            let mut projected = input_issue(path, "out_of_range");
            projected.minimum = minimum.filter(|value| value.is_finite());
            output.push(projected);
        }
        IssueKind::TooBig { maximum, .. } => {
            let mut projected = input_issue(path, "out_of_range");
            projected.maximum = maximum.filter(|value| value.is_finite());
            output.push(projected);
        }
        IssueKind::InvalidFormat { format, message } => {
            let mut projected = input_issue(path, "invalid_format");
            projected.expected = Some(Value::String(format.clone()));
            if !message.is_empty() {
                projected.message = Some(message.clone());
            }
            output.push(projected);
        }
        IssueKind::InvalidValue { values } => {
            let mut projected = input_issue(path, "invalid_value");
            projected.expected = Some(Value::Array(deduplicated_values(
                values
                    .iter()
                    .filter(|value| is_safe_expected(value))
                    .cloned(),
            )));
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

fn is_view_result(document: &Value, schema: &Value) -> Option<bool> {
    let schema = resolve_schema(document, schema).ok()?;
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.contains_key("parent_evidence_id"))
}

fn select_non_view_branch<'a>(document: &'a Value, resolved: &'a Value) -> Option<&'a Value> {
    let Some(options) = resolved
        .get("anyOf")
        .or_else(|| resolved.get("oneOf"))
        .and_then(Value::as_array)
    else {
        return Some(resolved);
    };

    for option in options {
        if !is_view_result(document, option)? {
            return Some(option);
        }
    }

    Some(resolved)
}

/// The complete (non-view) `normalized_result` contract of one catalog tool.
pub fn tool_result_schema(tool: &str) -> Option<Arc<Value>> {
    cached_schema(&format!("result:{tool}"), || {
        let contract = rea_mcp::catalog().tool(tool)?;
        let document = contract.output_schema()?;
        let normalized = document.get("properties")?.get("normalized_result")?;
        let resolved = resolve_schema(document, normalized).ok()?;
        let branch = select_non_view_branch(document, resolved)?;
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

/// Parse a named source contract with its explicit projection metadata.
pub fn parse_named_strict(
    root: &Value,
    value: &Value,
    metadata: SchemaMetadata,
) -> Result<Value, Vec<Issue>> {
    Parser::new(root, UnknownKeys::Reject)
        .with_metadata(metadata)
        .parse(value)
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
