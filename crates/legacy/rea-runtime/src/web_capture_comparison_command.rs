//! Standalone CLI adapter for the shared web-capture comparison workflow.

use rea_application::web;
use rea_core::failure::{Detail, Failure, InputIssue};
use serde_json::Value;
use std::collections::BTreeMap;

const DEFAULT_NORMALIZATION: &str = r#"{"rules":[]}"#;
const SCENARIO_FIELDS: [&str; 7] = [
    "browser",
    "scenario",
    "duration_ms",
    "steps",
    "events",
    "completeness",
    "limitations",
];

pub struct Arguments {
    pub before: String,
    pub after: String,
    pub normalization: String,
}

pub fn parse_arguments(arguments: &[String]) -> Result<Arguments, String> {
    let mut positional = Vec::with_capacity(2);
    let mut format = None;
    let mut normalization = DEFAULT_NORMALIZATION.to_owned();
    let mut index = 1;

    while index < arguments.len() {
        match arguments[index].as_str() {
            "--format" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err("--format requires a value; this command supports json.".into());
                };
                if format.replace(value.as_str()).is_some() {
                    return Err("--format may be supplied only once.".into());
                }
            }
            "--normalization-json" => {
                index += 1;
                let Some(value) = arguments.get(index) else {
                    return Err("--normalization-json requires a JSON value or file path.".into());
                };
                normalization = value.clone();
            }
            argument if argument.starts_with('-') => {
                return Err(format!(
                    "Unsupported compare-web-captures option: {argument}"
                ));
            }
            argument => positional.push(argument.to_owned()),
        }
        index += 1;
    }

    if format != Some("json") {
        return Err(
            "compare-web-captures requires --format json in this experimental executable.".into(),
        );
    }

    let [before, after] = positional.as_slice() else {
        return Err(
            "Usage: rea-native compare-web-captures BEFORE_JSON AFTER_JSON --format json [--normalization-json JSON_OR_PATH]"
                .into(),
        );
    };

    Ok(Arguments {
        before: before.clone(),
        after: after.clone(),
        normalization,
    })
}

pub fn invalid_arguments(message: String) -> Failure {
    input_failure(
        vec!["arguments".into()],
        "invalid_value",
        message,
        None,
        None,
    )
}

pub fn compare(arguments: &Arguments) -> Result<Value, Failure> {
    let before = read_json_input(&arguments.before, vec!["before".into()])?;
    let after = read_json_input(&arguments.after, vec!["after".into()])?;
    let normalization = read_json_input(&arguments.normalization, vec!["normalization".into()])?;
    let input = comparison_input(before, after, normalization);

    web::capture_comparison::compare(&input)
}

fn read_json_input(value: &str, path: Vec<String>) -> Result<Value, Failure> {
    match serde_json::from_str(value) {
        Ok(parsed) => Ok(parsed),
        Err(inline_error) => match std::fs::read_to_string(value) {
            Ok(contents) => serde_json::from_str(&contents).map_err(|error| {
                input_failure(
                    path,
                    "invalid_format",
                    format!("Input file {value} is not valid JSON: {error}"),
                    Some(value),
                    Some("invalid-json"),
                )
            }),
            Err(file_error) => {
                let (reason, message) =
                    if value.trim_start().starts_with('{') || value.trim_start().starts_with('[') {
                        (
                            "invalid_format",
                            format!("Input is not valid JSON: {inline_error}"),
                        )
                    } else {
                        (
                            "invalid_value",
                            format!("Unable to read input {value}: {file_error}"),
                        )
                    };
                Err(input_failure(
                    path,
                    reason,
                    message,
                    Some(value),
                    Some(if reason == "invalid_format" {
                        "invalid-json"
                    } else {
                        "read-failed"
                    }),
                ))
            }
        },
    }
}

fn comparison_input(before: Value, after: Value, normalization: Value) -> Value {
    let scenario = is_scenario_capture(&before) || is_scenario_capture(&after);

    if scenario {
        serde_json::json!({
            "before_scenario": before,
            "after_scenario": after,
            "normalization": normalization,
        })
    } else {
        serde_json::json!({"before": before, "after": after})
    }
}

fn is_scenario_capture(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    !object.contains_key("inspection")
        && object
            .keys()
            .any(|key| SCENARIO_FIELDS.contains(&key.as_str()))
}

fn input_failure(
    path: Vec<String>,
    reason: &'static str,
    message: String,
    input_path: Option<&str>,
    input_reason: Option<&str>,
) -> Failure {
    let mut details = BTreeMap::from([
        (
            "operation",
            Detail::Text(web::capture_comparison::OPERATION.into()),
        ),
        (
            "issues",
            Detail::Issues(vec![InputIssue {
                path,
                reason,
                message: message.clone(),
                expected: Some("JSON value or JSON file path"),
            }]),
        ),
    ]);
    if let Some(input_path) = input_path {
        details.insert("input_path", Detail::Text(input_path.into()));
    }
    if let Some(input_reason) = input_reason {
        details.insert("input_reason", Detail::Text(input_reason.into()));
    }
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Web capture comparison input is invalid.".into(),
        false,
        "Provide valid JSON capture inputs and retry.".into(),
        details,
    )
}
