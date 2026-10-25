//! Bounded, identity-stable reads of selected inputs and produced artifacts.
//!
//! Compatibility owner: `src/javascript/recovery/RecoveryFiles.ts`.
//!
//! `fingerprint_recovery_file` is reachable while resolving the configured
//! engine (the Linux capability path). The snapshot/inventory helpers back the
//! Linux execution pipeline.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use rea_core::analysis_error::AnalysisError;
use sha2::{Digest, Sha256};

use crate::javascript_recovery::OPERATION;
use crate::javascript_recovery::release::RECOVERY_LIMITS;

const READ_CHUNK: usize = 64 * 1024;

/// Bytes and digest of a scanned regular file.
pub(crate) struct FileFingerprint {
    pub sha256: String,
    pub bytes: u64,
}

/// A file exceeded the byte bound its caller selected.
pub(crate) struct RecoveryFileSizeError {
    pub reason: String,
}

impl From<RecoveryFileSizeError> for AnalysisError {
    fn from(error: RecoveryFileSizeError) -> Self {
        AnalysisError::output(OPERATION, error.reason)
    }
}

/// `recoveryDigest`: fingerprint exact selected or derived bytes.
pub(crate) fn recovery_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    hex(&hash.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Read a stable regular file, streaming its bytes through `consume`, with a
/// bounded size. Mirrors `scanRecoveryFile`'s identity and size checks.
fn scan_recovery_file(
    path: &str,
    maximum: u64,
    mut consume: impl FnMut(&[u8]),
) -> Result<FileFingerprint, ScanError> {
    let metadata = std::fs::symlink_metadata(path).map_err(ScanError::io)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ScanError::Output(format!(
            "Expected a regular file no larger than {maximum} bytes: {path}"
        )));
    }
    if metadata.len() > maximum {
        return Err(ScanError::Size(RecoveryFileSizeError {
            reason: format!("Expected a regular file no larger than {maximum} bytes: {path}"),
        }));
    }
    let mut file = File::open(path).map_err(ScanError::io)?;
    let mut hash = Sha256::new();
    let mut total: u64 = 0;
    let mut buffer = vec![0_u8; READ_CHUNK];
    loop {
        let read = file.read(&mut buffer).map_err(ScanError::io)?;
        if read == 0 {
            break;
        }
        total += read as u64;
        if total > maximum {
            return Err(ScanError::Size(RecoveryFileSizeError {
                reason: format!("File exceeds {maximum} bytes: {path}"),
            }));
        }
        hash.update(&buffer[..read]);
        consume(&buffer[..read]);
    }
    let after = std::fs::symlink_metadata(path).map_err(ScanError::io)?;
    if metadata.len() != total || after.len() != metadata.len() {
        return Err(ScanError::Output(format!(
            "File identity changed while reading: {path}"
        )));
    }
    Ok(FileFingerprint {
        sha256: hex(&hash.finalize()),
        bytes: total,
    })
}

/// Fingerprint a regular file incrementally with bounded memory.
pub(crate) fn fingerprint_recovery_file(
    path: &str,
    maximum: u64,
    _signal: Option<()>,
) -> Result<FileFingerprint, AnalysisError> {
    scan_recovery_file(path, maximum, |_| {}).map_err(ScanError::into_error)
}

/// Read the whole regular file through one bounded, identity-stable handle.
pub(crate) fn read_recovery_file(path: &str, maximum: u64) -> Result<Vec<u8>, AnalysisError> {
    let mut bytes = Vec::new();
    scan_recovery_file(path, maximum, |chunk| bytes.extend_from_slice(chunk))
        .map_err(ScanError::into_error)?;
    Ok(bytes)
}

/// Snapshot of one selected script within the operation-wide input budget.
pub(crate) struct RecoveryInputSnapshot {
    pub path: String,
    pub snapshot_path: String,
    pub relative_path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// One staging inventory entry.
pub(crate) struct StagedFile {
    pub relative_path: String,
    #[allow(dead_code)]
    pub bytes: u64,
}

/// Inventory staging without following symlinks or publishing special files.
pub(crate) fn inventory_recovery_files(root: &str) -> Result<Vec<StagedFile>, AnalysisError> {
    let mut files = Vec::new();
    let mut bytes: u64 = 0;
    let mut entries: u64 = 0;
    visit(Path::new(root), "", &mut files, &mut bytes, &mut entries)?;
    Ok(files)
}

fn visit(
    directory: &Path,
    prefix: &str,
    files: &mut Vec<StagedFile>,
    bytes: &mut u64,
    entries: &mut u64,
) -> Result<(), AnalysisError> {
    let metadata = std::fs::symlink_metadata(directory).map_err(io_output)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AnalysisError::output(
            OPERATION,
            format!("Unsafe staging directory: {}", directory.display()),
        ));
    }
    let mut children = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(io_output)? {
        let entry = entry.map_err(io_output)?;
        *entries += 1;
        if *entries > RECOVERY_LIMITS.output_entries {
            return Err(AnalysisError::output(
                OPERATION,
                "Recovery staging exceeds the 10000-entry resource limit",
            ));
        }
        children.push(entry.file_name());
    }
    for name in children {
        let name = name.to_string_lossy().into_owned();
        let relative_path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        let path = directory.join(&name);
        let info = std::fs::symlink_metadata(&path).map_err(io_output)?;
        if info.file_type().is_symlink() || (!info.is_dir() && !info.is_file()) {
            return Err(AnalysisError::output(
                OPERATION,
                format!("Recovery produced a symlink or special file: {relative_path}"),
            ));
        }
        if info.is_dir() {
            visit(&path, &relative_path, files, bytes, entries)?;
        } else {
            *bytes += info.len();
            if *bytes > RECOVERY_LIMITS.output_bytes {
                return Err(AnalysisError::output(
                    OPERATION,
                    "Recovery staging exceeds the 128 MiB resource limit",
                ));
            }
            files.push(StagedFile {
                relative_path,
                bytes: info.len(),
            });
        }
    }
    Ok(())
}

fn io_output(cause: std::io::Error) -> AnalysisError {
    AnalysisError::output(OPERATION, cause.to_string())
}

/// `recoveryInputFailure`: a caller-actionable path constraint.
pub(crate) fn recovery_input_failure(field: &str, message: impl Into<String>) -> AnalysisError {
    use rea_core::analysis_error::InputIssue;
    AnalysisError::input(
        OPERATION,
        vec![InputIssue::new(&[field], "invalid_value", message.into())],
    )
}

/// `recoveryFailureMessage`: one caught cause as diagnostic text.
pub(crate) fn recovery_failure_message(error: &AnalysisError) -> String {
    error.project()["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

enum ScanError {
    Io(String),
    Output(String),
    Size(RecoveryFileSizeError),
}

impl ScanError {
    fn io(cause: std::io::Error) -> Self {
        Self::Io(cause.to_string())
    }

    fn into_error(self) -> AnalysisError {
        match self {
            Self::Io(message) => recovery_input_failure("path", message),
            Self::Output(reason) => AnalysisError::output(OPERATION, reason),
            Self::Size(error) => error.into(),
        }
    }
}
