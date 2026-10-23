//! Application-owned contract boundary for provider-owned Electron scenarios.
//!
//! Process startup, action execution, event hooks, and teardown remain owned
//! by the provider adapter.  This module canonicalizes the caller's selected
//! paths and preserves the provider's bounded capture record without deriving
//! runtime claims from raw events.

use rea_core::failure::{Detail, Failure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "capture_electron_scenario";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct CaptureInput {
    pub executable_path: String,
    pub application_path: String,
    pub application_root: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub actions: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct CaptureResult {
    pub application: Value,
    pub actions: Vec<Value>,
    pub windows: Vec<Value>,
    pub processes: Value,
    pub ipc: Value,
    pub timeline: Value,
    pub retention: Value,
    pub coverage: Value,
    pub limitations: Vec<String>,
}

pub fn canonicalize_input(input: &CaptureInput) -> Result<CaptureInput, Failure> {
    validate_absolute("executable_path", &input.executable_path)?;
    validate_absolute("application_path", &input.application_path)?;
    if let Some(root) = &input.application_root {
        validate_absolute("application_root", root)?;
    }
    if input.args.iter().any(|argument| argument.contains('\0')) {
        return Err(invalid("Electron arguments must not contain NUL bytes."));
    }

    let mut canonical = input.clone();
    if canonical.application_root.is_none() {
        canonical.application_root = parent_path(&canonical.application_path);
    }
    Ok(canonical)
}

/// Preserve one provider-owned capture after validating its required sections.
pub fn project_capture(input: &CaptureInput, captured: Value) -> Result<CaptureResult, Failure> {
    let _ = canonicalize_input(input)?;
    let object = captured
        .as_object()
        .ok_or_else(|| invalid("Electron provider returned a non-object capture."))?;

    let required = [
        "application",
        "actions",
        "windows",
        "processes",
        "ipc",
        "timeline",
        "retention",
        "coverage",
        "limitations",
    ];
    for field in required {
        if !object.contains_key(field) {
            return Err(invalid(&format!(
                "Electron provider capture omitted required field {field}."
            )));
        }
    }

    Ok(CaptureResult {
        application: object["application"].clone(),
        actions: object["actions"]
            .as_array()
            .cloned()
            .ok_or_else(|| invalid("Electron capture actions must be an array."))?,
        windows: object["windows"]
            .as_array()
            .cloned()
            .ok_or_else(|| invalid("Electron capture windows must be an array."))?,
        processes: object["processes"].clone(),
        ipc: object["ipc"].clone(),
        timeline: object["timeline"].clone(),
        retention: object["retention"].clone(),
        coverage: object["coverage"].clone(),
        limitations: object["limitations"]
            .as_array()
            .ok_or_else(|| invalid("Electron capture limitations must be an array."))?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(ToOwned::to_owned)
                    .ok_or_else(|| invalid("Electron capture limitations must be strings."))
            })
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn validate_absolute(field: &str, value: &str) -> Result<(), Failure> {
    let absolute = value.starts_with('/')
        || value.starts_with("\\\\")
        || value.as_bytes().get(1).copied() == Some(b':');
    if absolute && !value.contains('\0') && !value.is_empty() {
        return Ok(());
    }
    Err(invalid(&format!("{field} must be an absolute local path.")))
}

fn parent_path(path: &str) -> Option<String> {
    path.rsplit_once('/').map(|(parent, _)| {
        if parent.is_empty() {
            "/".into()
        } else {
            parent.into()
        }
    })
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide an absolute Electron executable and application path.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_application_root_and_rejects_nul_arguments() {
        let input = CaptureInput {
            executable_path: "/Applications/Electron.app/Contents/MacOS/Electron".into(),
            application_path: "/Applications/Electron.app/Contents/Resources/app.asar".into(),
            application_root: None,
            args: vec!["--no-sandbox".into()],
            actions: vec![],
        };
        let canonical = canonicalize_input(&input).expect("absolute paths are accepted");
        assert_eq!(
            canonical.application_root.as_deref(),
            Some("/Applications/Electron.app/Contents/Resources")
        );

        let mut invalid_input = input;
        invalid_input.args = vec!["bad\0arg".into()];
        assert!(canonicalize_input(&invalid_input).is_err());
    }

    #[test]
    fn preserves_provider_capture_sections_and_limitations() {
        let input = CaptureInput {
            executable_path: "/tmp/electron".into(),
            application_path: "/tmp/app.asar".into(),
            application_root: Some("/tmp".into()),
            args: vec![],
            actions: vec![],
        };
        let result = project_capture(
            &input,
            serde_json::json!({
                "application": {"process_ownership": "provider-owned"},
                "actions": [], "windows": [], "processes": {}, "ipc": {},
                "timeline": {}, "retention": {}, "coverage": {},
                "limitations": ["cleanup state is explicit"]
            }),
        )
        .expect("capture projection succeeds");
        assert_eq!(result.limitations, vec!["cleanup state is explicit"]);
        assert_eq!(result.application["process_ownership"], "provider-owned");
    }
}
