//! Owned firmware reads: private snapshot, output inventory, report reads.
//!
//! Compatibility owner: `src/firmware/FirmwareFiles.ts`. All reads use the
//! stable-artifact reader for identity revalidation, then write private copies
//! with exclusive creation and owner-only modes.
use super::release::FIRMWARE_LIMITS;
use crate::artifact::{self, ReadError, ReaderReason};
use crate::node::{self, FsError};
use crate::producer::write_exclusive;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::SubjectTarget;
/// `AnalysisError` produced when the firmware input is empty or too large.
fn firmware_input_failure(operation: &str) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue {
            path: vec![serde_json::json!("path")],
            reason: "out_of_range",
            message: Some(format!(
                "Firmware must be a nonempty regular file no larger than {} bytes. Select a stable copy within this allowance.",
                FIRMWARE_LIMITS.input_bytes
            )),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}
/// One regular file or unpublished filesystem entry in a private extraction.
#[derive(Clone, Debug)]
pub struct FirmwareEntry {
    pub relative_path: String,
    pub path: String,
    pub size: u64,
    pub kind: EntryKind,
    pub link_target: Option<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Symlink,
    Special,
}
impl EntryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Symlink => "symlink",
            Self::Special => "special",
        }
    }
}
/// Selected byte interval and its digest.
#[derive(Clone, Debug)]
pub struct Selection {
    pub offset: u64,
    pub length: u64,
    pub sha256: String,
}
/// Result of the private firmware snapshot.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub subject: SubjectTarget,
    pub size: u64,
    pub input_path: String,
    pub selection: Selection,
}
/// Explicit extraction range parsed from caller input.
#[derive(Clone, Copy, Debug)]
pub struct Range {
    pub offset: u64,
    pub length: u64,
}
/// Map a stable-read failure the way `firmwareAdmissionFailure` would.
fn classify_read(
    operation: &str,
    error: ReadError,
    on_non_regular: impl Fn() -> AnalysisError,
) -> AnalysisError {
    match error {
        // A path/non-regular outcome keeps the input-shaped failure.
        ReadError::Reader {
            reason: ReaderReason::Path,
            ..
        } => on_non_regular(),
        ReadError::Reader {
            reason: ReaderReason::Cancelled,
            ..
        } => AnalysisError::cancelled(operation),
        other => provider_adapter_reason(operation, &other.message()),
    }
}
/// A `ProviderAdapterError` whose only diagnostic is a reason string.
fn provider_adapter_reason(operation: &str, reason: &str) -> AnalysisError {
    AnalysisError::provider_adapter("firmware", operation)
        .with_diagnostics(crate::errors::map([("reason", serde_json::json!(reason))]))
}
/// `hash`: digest one admitted regular file without retaining its bytes.
pub fn hash(path: &str, cancellation: &Cancellation) -> Result<String, ReadError> {
    artifact::read_stable(path, FIRMWARE_LIMITS.input_bytes as usize, cancellation)
        .map(|snapshot| snapshot.sha256)
}
/// `#snapshot`: copy and identify the exact bytes consumed by providers.
pub fn snapshot(
    operation: &str,
    source_path: &str,
    range: Option<Range>,
    root: &str,
    cancellation: &Cancellation,
) -> Result<Snapshot, AnalysisError> {
    // `realpath(sourcePath)` then a stable read of the resolved path.
    let source = node::realpath(source_path)
        .map_err(|error| provider_adapter_reason(operation, &error.message))?;
    let selected =
        artifact::read_stable(&source, FIRMWARE_LIMITS.input_bytes as usize, cancellation)
            .map_err(|error| {
                classify_read(operation, error, || firmware_input_failure(operation))
            })?;
    let size = selected.bytes.len() as u64;
    if size == 0 || size > FIRMWARE_LIMITS.input_bytes {
        return Err(firmware_input_failure(operation));
    }
    let sha256 = selected.sha256.clone();
    let full_path = node::join(root, "firmware.bin");
    write_exclusive(&full_path, &selected.bytes, 0o400)
        .map_err(|error| provider_adapter_reason(operation, &error.message))?;
    let offset = range.map_or(0, |range| range.offset);
    let length = range.map_or(size, |range| range.length);
    if length == 0 || offset > size || length > size - offset {
        return Err(AnalysisError::input(
            operation,
            vec![InputIssue {
                path: vec![serde_json::json!("range")],
                reason: "out_of_range",
                message: Some(format!(
                    "Selected range must be within the {size}-byte firmware file"
                )),
                expected: None,
                minimum: None,
                maximum: None,
            }],
        ));
    }
    let (input_path, selection_sha) = if range.is_some() {
        let selected_path = node::join(root, "selected.bin");
        let start = offset as usize;
        let end = start + length as usize;
        write_exclusive(&selected_path, &selected.bytes[start..end], 0o400)
            .map_err(|error| provider_adapter_reason(operation, &error.message))?;
        let digest = hash(&selected_path, cancellation).map_err(|error| {
            classify_read(operation, error, || firmware_input_failure(operation))
        })?;
        (selected_path, digest)
    } else {
        (full_path, sha256.clone())
    };
    Ok(Snapshot {
        subject: SubjectTarget {
            path: source_path.to_owned(),
            sha256,
            format: "file".to_owned(),
            architecture: None,
        },
        size,
        input_path,
        selection: Selection {
            offset,
            length,
            sha256: selection_sha,
        },
    })
}
/// Read a complete bounded report (`report`): oversized data never reports complete.
pub fn report(
    path: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<serde_json::Value, AnalysisError> {
    let snapshot = artifact::read_stable(path, FIRMWARE_LIMITS.report_bytes as usize, cancellation)
        .map_err(|error| match &error {
            ReadError::Reader {
                reason: ReaderReason::Limit,
                ..
            } => AnalysisError::output(
                operation,
                format!("Report exceeded {} bytes", FIRMWARE_LIMITS.report_bytes),
            ),
            ReadError::Reader {
                reason: ReaderReason::Cancelled,
                ..
            } => AnalysisError::cancelled(operation),
            ReadError::Reader {
                reason: ReaderReason::Path,
                ..
            } => AnalysisError::output(operation, "Report is not a regular file"),
            other => AnalysisError::output(
                operation,
                format!("Report is not a regular file: {}", other.message()),
            ),
        })?;
    let text = std::str::from_utf8(&snapshot.bytes)
        .map_err(|_| AnalysisError::output(operation, "Tool report is not valid complete JSON"))?;
    serde_json::from_str(text)
        .map_err(|_| AnalysisError::output(operation, "Tool report is not valid complete JSON"))
}
/// `inventoryFirmwareOutput`: inventory private output without following links,
/// enforcing aggregate staging budgets, sorted by Unicode code points.
pub fn inventory(
    root: &str,
    max_bytes: u64,
    max_entries: u64,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Vec<FirmwareEntry>, AnalysisError> {
    let mut entries: Vec<FirmwareEntry> = Vec::new();
    let mut pending = vec![root.to_owned()];
    let mut bytes = 0_u64;
    let mut count = 0_u64;
    while let Some(directory) = pending.pop() {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let directory_meta = match std::fs::symlink_metadata(&directory) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_failure(operation, &error, "lstat", &directory)),
        };
        if !directory_meta.is_dir() || directory_meta.file_type().is_symlink() {
            continue;
        }
        let reader = match std::fs::read_dir(&directory) {
            Ok(reader) => reader,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(io_failure(operation, &error, "scandir", &directory)),
        };
        let mut names: Vec<String> = Vec::new();
        for entry in reader {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(operation));
            }
            let entry =
                entry.map_err(|error| io_failure(operation, &error, "readdir", &directory))?;
            count += 1;
            if count > max_entries {
                return Err(AnalysisError::output(
                    operation,
                    format!("Staging entry budget exceeded ({max_entries})"),
                ));
            }
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
        // `names.sort()` is the default lexicographic order; directory descent
        // order only, not the final output order.
        names.sort();
        for name in names {
            let path = node::join(&directory, &name);
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(io_failure(operation, &error, "lstat", &path)),
            };
            let file_type = meta.file_type();
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if file_type.is_file() {
                bytes += meta.len();
            }
            if bytes > max_bytes {
                return Err(AnalysisError::output(
                    operation,
                    format!("Staging byte budget exceeded ({max_bytes})"),
                ));
            }
            let (kind, link_target) = if file_type.is_symlink() {
                let target = std::fs::read_link(&path)
                    .map_err(|error| io_failure(operation, &error, "readlink", &path))?;
                (
                    EntryKind::Symlink,
                    Some(target.to_string_lossy().into_owned()),
                )
            } else if file_type.is_file() {
                (EntryKind::File, None)
            } else {
                (EntryKind::Special, None)
            };
            entries.push(FirmwareEntry {
                relative_path: relative_slash(root, &path),
                path,
                size: meta.len(),
                kind,
                link_target,
            });
        }
    }
    entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(entries)
}
/// Rethrow a raw filesystem error as `firmwareFailure` would: a
/// `ProviderAdapterError` whose reason is the Node fs error message.
fn io_failure(operation: &str, error: &std::io::Error, syscall: &str, path: &str) -> AnalysisError {
    provider_adapter_reason(operation, &FsError::from_io(error, syscall, path).message)
}
/// `relative(root, path).split(sep).join("/")`.
fn relative_slash(root: &str, path: &str) -> String {
    let stripped = path.strip_prefix(root).unwrap_or(path);
    let stripped = stripped.trim_start_matches(std::path::MAIN_SEPARATOR);
    if cfg!(windows) {
        stripped.replace('\\', "/")
    } else {
        stripped.to_owned()
    }
}
/// `firmwareLogicalPath`: bind producer paths to the input or extraction tree.
pub fn logical_path(
    path: &str,
    input_path: &str,
    output_root: &str,
) -> Result<String, AnalysisError> {
    if path == input_path {
        return Ok("$input".to_owned());
    }
    let relative = relative_path(output_root, path);
    let outside = !node::is_absolute(path)
        || relative.as_deref() == Some("..")
        || relative.as_deref().is_some_and(|rel| {
            rel.starts_with("../") || (cfg!(windows) && rel.starts_with("..\\"))
        })
        || relative.as_deref().is_some_and(node::is_absolute)
        || relative.is_none();
    if outside {
        return Err(AnalysisError::output(
            "extract_firmware",
            format!("Provider reported a path outside its owned output: {path}"),
        ));
    }
    let relative = relative.unwrap_or_default();
    if relative.is_empty() {
        Ok("$output".to_owned())
    } else {
        let joined = if cfg!(windows) {
            relative.replace('\\', "/")
        } else {
            relative
        };
        Ok(format!("$output/{joined}"))
    }
}
/// `path.relative(from, to)` for the simple descendant case the owner needs.
fn relative_path(from: &str, to: &str) -> Option<String> {
    let separator = std::path::MAIN_SEPARATOR;
    if to == from {
        return Some(String::new());
    }
    let prefix = format!("{from}{separator}");
    if let Some(rest) = to.strip_prefix(&prefix) {
        return Some(rest.to_owned());
    }
    // Not a descendant: signal an outside path via `..`.
    Some("..".to_owned())
}
