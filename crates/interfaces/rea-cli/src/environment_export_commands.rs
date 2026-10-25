//! CLI adapter for the application-owned environment export workflow.

use rea_core::analysis_error::AnalysisError;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn export(args: &Value, options: &Value) -> Value {
    match export_inner(args, options) {
        Ok(value) => value,
        Err(error) => error.project(),
    }
}

fn export_inner(args: &Value, options: &Value) -> Result<Value, AnalysisError> {
    let manifest = absolute_argument(args, "manifest")?;
    let evidence = absolute_argument(options, "evidence")?;
    let directory = absolute_argument(args, "directory")?;
    let name = options.get("name").and_then(Value::as_str);
    let package_tarball = options
        .get("packageTarball")
        .and_then(Value::as_str)
        .map(PathBuf::from)
        .map(|path| absolute_path(&path))
        .transpose()?;
    rea_application::environment::export::export_files(
        &manifest,
        &evidence,
        &directory,
        name,
        package_tarball.as_deref(),
    )
}

fn absolute_argument(value: &Value, key: &str) -> Result<PathBuf, AnalysisError> {
    let text = value
        .get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            AnalysisError::input_message(
                "environment-export",
                format!("Supply a non-empty {key}."),
                vec![],
            )
        })?;
    absolute_path(Path::new(text))
}

fn absolute_path(path: &Path) -> Result<PathBuf, AnalysisError> {
    if path.is_absolute() {
        return Ok(path.to_owned());
    }
    let current = std::env::current_dir().map_err(|error| {
        AnalysisError::output(
            "environment-export",
            format!("Could not resolve current directory: {error}"),
        )
    })?;
    Ok(current.join(path))
}
