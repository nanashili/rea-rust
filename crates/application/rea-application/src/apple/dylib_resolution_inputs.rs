//! Caller input validation for static dyld load-path resolution.
//!
//! This boundary deliberately parses `serde_json::Value` rather than deriving
//! `Deserialize`: the application adapters need the same stable, tagged input
//! issues for wrong types, unknown keys, and invalid path values.

use rea_core::failure::InputIssue;
use serde_json::{Map, Value};
use std::fmt;

/// The CPU slices selectable by the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DylibArchitecture {
    Arm64,
    Arm64e,
    X86_64,
}

impl DylibArchitecture {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::Arm64e => "arm64e",
            Self::X86_64 => "x86_64",
        }
    }
}

/// The optional caller selection. `None` means that the property was omitted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DylibResolutionInput {
    pub roots: Option<Vec<String>>,
    pub architecture: Option<DylibArchitecture>,
}

/// Structured validation failure for the dylib-resolution input boundary.
#[derive(Debug)]
pub struct DylibResolutionInputError {
    pub issues: Vec<InputIssue>,
}

impl fmt::Display for DylibResolutionInputError {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, issue) in self.issues.iter().enumerate() {
            if index != 0 {
                output.write_str(", ")?;
            }
            if !issue.path.is_empty() {
                write!(output, "{}: ", issue.path.join("."))?;
            }
            output.write_str(&issue.message)?;
        }
        Ok(())
    }
}

impl std::error::Error for DylibResolutionInputError {}

/// Parse a JSON value using the strict caller schema.
pub fn parse_dylib_resolution_input(
    value: &Value,
) -> Result<DylibResolutionInput, DylibResolutionInputError> {
    let mut parser = Parser::default();
    let Some(object) = value.as_object() else {
        parser.wrong_type(&[], "object", Some(value));
        return Err(parser.finish());
    };

    let roots = parser.roots(object.get("roots"));
    let architecture = parser.architecture(object.get("architecture"));

    parser.unknown_keys(object);

    if parser.issues.is_empty() {
        Ok(DylibResolutionInput {
            roots,
            architecture,
        })
    } else {
        Err(parser.finish())
    }
}

/// Parse a JSON document using the same strict schema.
pub fn parse_dylib_resolution_input_json(
    json: &str,
) -> Result<DylibResolutionInput, DylibResolutionInputError> {
    match serde_json::from_str(json) {
        Ok(value) => parse_dylib_resolution_input(&value),
        Err(error) => Err(DylibResolutionInputError {
            issues: vec![InputIssue {
                path: Vec::new(),
                reason: "invalid_json",
                message: format!("Invalid JSON input: {error}"),
                expected: Some("valid JSON object"),
            }],
        }),
    }
}

#[derive(Default)]
struct Parser {
    issues: Vec<InputIssue>,
}

impl Parser {
    fn finish(self) -> DylibResolutionInputError {
        DylibResolutionInputError {
            issues: self.issues,
        }
    }

    fn issue(&mut self, path: &[String], reason: &'static str, message: impl Into<String>) {
        self.issues.push(InputIssue {
            path: path.to_vec(),
            reason,
            message: message.into(),
            expected: None,
        });
    }

    fn wrong_type(&mut self, path: &[String], expected: &'static str, value: Option<&Value>) {
        let received = match value {
            None => "undefined",
            Some(Value::Null) => "null",
            Some(Value::Bool(_)) => "boolean",
            Some(Value::Number(_)) => "number",
            Some(Value::String(_)) => "string",
            Some(Value::Array(_)) => "array",
            Some(Value::Object(_)) => "object",
        };
        self.issue(
            path,
            "invalid_type",
            format!("Invalid input: expected {expected}, received {received}"),
        );
    }

    fn roots(&mut self, value: Option<&Value>) -> Option<Vec<String>> {
        let Some(value) = value else {
            return None;
        };
        let Some(items) = value.as_array() else {
            self.wrong_type(&["roots".into()], "array", Some(value));
            return None;
        };
        if items.is_empty() {
            self.issue(
                &["roots".into()],
                "too_small",
                "Too small: expected array to have >=1 items",
            );
        }

        let mut roots = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            let path = vec!["roots".to_owned(), index.to_string()];
            let Some(root) = item.as_str() else {
                self.wrong_type(&path, "string", Some(item));
                continue;
            };
            if root.is_empty() {
                self.issue(
                    &path,
                    "too_small",
                    "Too small: expected string to have >=1 characters",
                );
            } else if !is_normalized_root_relative_path(root) {
                self.issue(
                    &path,
                    "invalid_format",
                    "Use a normalized path relative to the analyzed root, without a leading or trailing '/', '//', or '.' and '..' segments",
                );
            }
            roots.push(root.to_owned());
        }
        Some(roots)
    }

    fn architecture(&mut self, value: Option<&Value>) -> Option<DylibArchitecture> {
        let Some(value) = value else {
            return None;
        };
        let Some(name) = value.as_str() else {
            self.wrong_type(&["architecture".into()], "string", Some(value));
            return None;
        };
        let architecture = match name {
            "arm64" => Some(DylibArchitecture::Arm64),
            "arm64e" => Some(DylibArchitecture::Arm64e),
            "x86_64" => Some(DylibArchitecture::X86_64),
            _ => None,
        };
        if architecture.is_none() {
            self.issue(
                &["architecture".into()],
                "invalid_value",
                "Invalid option: expected one of \"arm64\"|\"arm64e\"|\"x86_64\"",
            );
        }
        architecture
    }

    fn unknown_keys(&mut self, object: &Map<String, Value>) {
        let unknown: Vec<_> = object
            .keys()
            .filter(|key| *key != "roots" && *key != "architecture")
            .cloned()
            .collect();
        if unknown.is_empty() {
            return;
        }
        let names = unknown
            .iter()
            .map(|key| format!("\"{key}\""))
            .collect::<Vec<_>>()
            .join(", ");
        self.issue(
            &[],
            "unrecognized_keys",
            format!(
                "Unrecognized key{}: {names}",
                if unknown.len() == 1 { "" } else { "s" }
            ),
        );
    }
}

fn is_normalized_root_relative_path(path: &str) -> bool {
    if path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\\')
        || path.contains('\0')
    {
        return false;
    }

    path.split('/')
        .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn omitted_selection_is_distinct_from_present_values() {
        let omitted = parse_dylib_resolution_input(&json!({})).expect("omitted values are valid");
        assert_eq!(omitted.roots, None);
        assert_eq!(omitted.architecture, None);

        let selected = parse_dylib_resolution_input(&json!({
            "roots": ["Contents/MacOS/App"],
            "architecture": "arm64e"
        }))
        .expect("valid selection");
        assert_eq!(selected.roots, Some(vec!["Contents/MacOS/App".to_owned()]));
        assert_eq!(selected.architecture, Some(DylibArchitecture::Arm64e));
    }

    #[test]
    fn rejects_unknown_keys_and_null_optional_values() {
        let error = parse_dylib_resolution_input(&json!({
            "roots": null,
            "unexpected": true
        }))
        .expect_err("strict schema rejects both values");
        assert_eq!(error.issues[0].reason, "invalid_type");
        assert_eq!(error.issues[1].reason, "unrecognized_keys");
    }

    #[test]
    fn validates_normalized_relative_roots() {
        for root in [
            "",
            "/App",
            "App/",
            "App//Main",
            "App/./Main",
            "App/../Main",
            "App\\Main",
            "App\0Main",
        ] {
            let error = parse_dylib_resolution_input(&json!({ "roots": [root] }))
                .expect_err("invalid root");
            assert!(
                error
                    .issues
                    .iter()
                    .any(|issue| { issue.path == vec!["roots".to_owned(), "0".to_owned()] })
            );
        }
        for root in ["App", ".hidden", "..cache", "Frameworks/lib.dylib"] {
            parse_dylib_resolution_input(&json!({ "roots": [root] }))
                .expect("normalized relative root");
        }
    }

    #[test]
    fn reports_array_and_enum_bounds_with_tagged_issues() {
        let error = parse_dylib_resolution_input(&json!({
            "roots": [],
            "architecture": "mips"
        }))
        .expect_err("empty roots and unsupported architecture");
        assert_eq!(error.issues[0].reason, "too_small");
        assert_eq!(error.issues[1].reason, "invalid_value");
    }
}
