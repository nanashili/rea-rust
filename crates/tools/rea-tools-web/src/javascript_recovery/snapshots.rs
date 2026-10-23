//! Snapshot selected inputs into the private workspace (Linux path only).
//!
//! Compatibility owner: `snapshotRecoveryInputs` in
//! `src/javascript/recovery/RecoveryFiles.ts`. Preserves each selected file and
//! its relative input layout without concatenation, within the operation-wide
//! input budget.

use std::path::{Component, Path, PathBuf};

use rea_core::analysis_error::{AnalysisError, InputIssue};

use crate::javascript_recovery::OPERATION;
use crate::javascript_recovery::recovery_files::{
    RecoveryInputSnapshot, read_recovery_file, recovery_digest, recovery_input_failure,
};
use crate::javascript_recovery::release::RECOVERY_LIMITS;

/// Preserve each selected file and its relative input layout.
pub(crate) fn snapshot_recovery_inputs(
    paths: &[String],
    directory: &str,
) -> Result<Vec<RecoveryInputSnapshot>, AnalysisError> {
    let common_directory = common_directory(paths)?;

    let mut snapshots = Vec::with_capacity(paths.len());
    let mut remaining = RECOVERY_LIMITS.input_bytes;
    for path in paths {
        let relative_path = if paths.len() == 1 {
            "bundle.js".to_owned()
        } else {
            relative(&common_directory, &resolve(path))
        };
        if relative_path.contains('\\') {
            return Err(recovery_input_failure(
                "path",
                format!(
                    "Cannot preserve selected input path in published artifacts: {path}: Wakaru cannot preserve literal backslashes in input paths"
                ),
            ));
        }
        let snapshot = snapshot_one(
            path,
            &Path::new(directory).join(&relative_path).to_string_lossy(),
            &relative_path,
            remaining,
        )?;
        remaining = remaining.saturating_sub(snapshot.bytes);
        snapshots.push(snapshot);
    }
    Ok(snapshots)
}

fn snapshot_one(
    path: &str,
    snapshot_path: &str,
    relative_path: &str,
    maximum: u64,
) -> Result<RecoveryInputSnapshot, AnalysisError> {
    if !path.starts_with('/') {
        return Err(recovery_input_failure(
            "path",
            "Select an absolute JavaScript file path",
        ));
    }
    let bytes =
        read_recovery_file(path, maximum).map_err(|error| map_snapshot_error(error, path))?;
    if std::str::from_utf8(&bytes).is_err() {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue {
                path: vec![serde_json::Value::String("path".to_owned())],
                reason: "invalid_format",
                message: Some(format!("JavaScript input is not valid UTF-8: {path}")),
                expected: Some(serde_json::Value::String("UTF-8".to_owned())),
                minimum: None,
                maximum: None,
            }],
        ));
    }
    if let Some(parent) = Path::new(snapshot_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|cause| recovery_input_failure("path", cause.to_string()))?;
    }
    std::fs::write(snapshot_path, &bytes)
        .map_err(|cause| recovery_input_failure("path", cause.to_string()))?;
    Ok(RecoveryInputSnapshot {
        path: path.to_owned(),
        snapshot_path: snapshot_path.to_owned(),
        relative_path: relative_path.to_owned(),
        sha256: recovery_digest(&bytes),
        bytes: bytes.len() as u64,
    })
}

/// A resource constraint stays distinct from a malformed argument; other read
/// failures project as a path input failure (mirrors `snapshotRecoveryInput`).
fn map_snapshot_error(error: AnalysisError, path: &str) -> AnalysisError {
    let message = error.project()["message"].as_str().unwrap_or("").to_owned();
    if message.starts_with("File exceeds") || message.contains("no larger than") {
        return AnalysisError::resource_constraint(
            OPERATION,
            "file-size",
            format!(
                "Selected JavaScript input {path} exceeds the remaining input allowance (total {} bytes)",
                RECOVERY_LIMITS.input_bytes
            ),
            Some(serde_json::json!({ "maximum_input_bytes": RECOVERY_LIMITS.input_bytes })),
        )
        .with_remediation(
            "Select JavaScript inputs whose combined size is within maximum_input_bytes. Do not truncate required source; retrying the unchanged selection will fail again.",
        );
    }
    recovery_input_failure(
        "path",
        format!("Cannot snapshot UTF-8 JavaScript input {path}: {message}"),
    )
}

/// Node `path.resolve` for absolute POSIX paths; normalizes `.`/`..`.
fn resolve(path: &str) -> PathBuf {
    let mut buffer = PathBuf::from("/");
    for component in Path::new(path).components() {
        match component {
            Component::RootDir | Component::Prefix(_) => {}
            Component::CurDir => {}
            Component::ParentDir => {
                buffer.pop();
            }
            Component::Normal(part) => buffer.push(part),
        }
    }
    buffer
}

/// The deepest shared ancestor of every selected path.
fn common_directory(paths: &[String]) -> Result<PathBuf, AnalysisError> {
    let mut common = resolve(&paths[0])
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/"));
    for path in paths {
        let resolved = resolve(path);
        loop {
            if resolved.starts_with(&common) {
                break;
            }
            let parent = common.parent().map(Path::to_path_buf);
            match parent {
                Some(parent) if parent != common => common = parent,
                _ => {
                    return Err(recovery_input_failure(
                        "additional_paths",
                        "Selected files must share a filesystem root",
                    ));
                }
            }
        }
    }
    Ok(common)
}

fn relative(base: &Path, path: &Path) -> String {
    path.strip_prefix(base)
        .map(|rest| rest.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string_lossy().into_owned())
}
