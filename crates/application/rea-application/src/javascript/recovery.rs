//! Contract boundary for derived JavaScript source recovery.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "recover_javascript_sources";
pub const MAX_ADDITIONAL_PATHS: usize = 16;
const INPUT_FIELDS: &[&str] = &[
    "path",
    "additional_paths",
    "output_directory",
    "extraction_mode",
    "rewrite_level",
];

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("JavaScript recovery input must be an object"))?;
    reject_unknown_fields(object)?;

    let path = required_path(object, "path")?;
    let output = required_path(object, "output_directory")?;
    if path == output {
        return Err(invalid(
            "output_directory must differ from the selected source",
        ));
    }

    let additional = object
        .get("additional_paths")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| invalid("additional_paths must be an array"))
        })
        .transpose()?
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    if additional.len() > MAX_ADDITIONAL_PATHS {
        return Err(invalid("additional_paths exceeds the limit of 16 files"));
    }
    let mut paths = BTreeSet::from([path]);
    for value in additional {
        let path = value
            .as_str()
            .filter(|path| !path.is_empty())
            .ok_or_else(|| invalid("additional_paths must contain non-empty paths"))?;
        validate_absolute_path(path, "additional_paths entries")?;
        if !paths.insert(path) {
            return Err(invalid("recovery source paths must be unique"));
        }
    }

    let extraction = optional_enum(object, "extraction_mode", "structural")?;
    if !matches!(extraction, "structural" | "heuristic" | "inspection") {
        return Err(invalid("extraction_mode is unsupported"));
    }
    let rewrite = optional_enum(object, "rewrite_level", "standard")?;
    if !matches!(rewrite, "minimal" | "standard" | "aggressive") {
        return Err(invalid("rewrite_level is unsupported"));
    }
    Ok(())
}

fn required_path<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
    let value = object
        .get(field)
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty path")))?;
    validate_absolute_path(value, field)?;
    Ok(value)
}

fn validate_absolute_path(path: &str, field: &str) -> Result<(), Failure> {
    if !is_absolute(path) || path.contains('\0') {
        return Err(invalid(&format!(
            "{field} must be an absolute path without NUL bytes"
        )));
    }
    Ok(())
}

fn optional_enum<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
    default: &'a str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid(&format!("{field} must be a string")))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
        || path.starts_with("\\\\")
        || (path.as_bytes().get(1).copied() == Some(b':')
            && matches!(path.as_bytes().get(2), Some(b'/') | Some(b'\\')))
}

fn reject_unknown_fields(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !INPUT_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid(&format!(
            "unknown JavaScript recovery input field: {field}"
        )));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Select absolute JavaScript source paths and an absent output directory.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_bounded_recovery_selection() {
        validate_input(&serde_json::json!({
            "path": "/tmp/app.js",
            "additional_paths": ["/tmp/runtime.js"],
            "output_directory": "/tmp/recovered",
            "extraction_mode": "structural",
            "rewrite_level": "standard"
        }))
        .expect("valid recovery selection");
    }

    #[test]
    fn rejects_duplicate_sources_and_relative_output() {
        assert!(
            validate_input(&serde_json::json!({
                "path": "/tmp/app.js",
                "additional_paths": ["/tmp/app.js"],
                "output_directory": "/tmp/recovered"
            }))
            .is_err()
        );
        assert!(
            validate_input(&serde_json::json!({
                "path": "/tmp/app.js",
                "output_directory": "recovered"
            }))
            .is_err()
        );
    }
}
