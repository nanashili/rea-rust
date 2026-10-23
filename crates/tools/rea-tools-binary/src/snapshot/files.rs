//! Read and atomically write analysis-snapshot files.
//!
//! Compatibility owners: `src/application/binary/AnalysisSnapshotFiles.ts`
//! (`readAnalysisSnapshot`, `writeAnalysisSnapshot`), `src/application/JsonFiles.ts`
//! (`readJsonObjectMembersFile`, `writeTextFile`) and
//! `src/artifacts/ArtifactResourceScope.ts` (retained staged-file cleanup).
//!
//! Reads reuse `rea_host::fs::stable_file` for identity-revalidated, bounded file
//! access (the same owner `rea_application::ledger::bundle_import` uses), with the
//! bundle size ceiling. The write path stages into the destination directory,
//! fsyncs, then renames/links atomically; a failed cleanup is retained for a
//! later `close()` retry, exactly like `ArtifactResourceScope`.
use super::model::AnalysisSnapshot;
use rea_core::analysis_error::{AnalysisError, ErrorKind, PublishedFile};
use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_file::{self, IoKind, ReadIssue};
use serde_json::Value;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Mirror of `bundle_import::MAX_BUNDLE_BYTES`; snapshots embed a bundle.
const MAX_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024;

/// Read and validate an analysis snapshot from the caller's path (TS
/// `readAnalysisSnapshot`).
///
/// # Errors
/// - `AnalysisCancelledError("read_evidence_file")` when cancelled.
/// - `EvidenceFileError{operation:"read", ...}` for file-access failures
///   (`not-file`, `missing`, `io`, `invalid-json`).
/// - `AnalysisResourceConstraintError` when the file exceeds the bundle limit.
/// - `EvidenceIntegrityError` with the TS `TypeError` message (or
///   "Analysis snapshot validation failed") for validation failures.
pub(crate) fn read_analysis_snapshot(
    path: &str,
    cancellation: &Cancellation,
) -> Result<AnalysisSnapshot, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled("read_evidence_file"));
    }
    let snapshot = read_file(path, cancellation)?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled("read_evidence_file"));
    }
    let source = String::from_utf8(snapshot.bytes).map_err(|_| invalid_json(path))?;
    let value: Value = serde_json::from_str(&source).map_err(|_| invalid_json(path))?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled("read_evidence_file"));
    }
    // The TS reader validates the required members exist before parsing.
    for member in ["target", "binding", "evidence_bundle"] {
        if value.get(member).is_none() {
            return Err(integrity(format!("Analysis snapshot {member} is missing")));
        }
    }
    if value.get("entries").and_then(Value::as_array).is_none() {
        return Err(integrity("Analysis snapshot entries is missing".to_owned()));
    }
    if value
        .get("workflow_entries")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err(integrity(
            "Analysis snapshot workflow_entries is missing".to_owned(),
        ));
    }
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled("read_evidence_file"));
    }
    // TS `parseImmutableEvidenceBundle` authenticates every record before the
    // entries are restored against them; its failure is not a TypeError.
    let authenticated = serde_json::value::to_raw_value(&value["evidence_bundle"])
        .ok()
        .is_some_and(|raw| rea_core::evidence::bundle::EvidenceBundle::parse(&raw).is_ok());
    if !authenticated {
        return Err(integrity("Analysis snapshot validation failed".to_owned()));
    }
    AnalysisSnapshot::parse(&value).map_err(snapshot_validation_error)
}

/// Read the file through the stable, bounded, identity-revalidated owner.
fn read_file(
    path: &str,
    cancellation: &Cancellation,
) -> Result<stable_file::Snapshot, AnalysisError> {
    let access = Arc::new(host_file_access());
    match stable_file::read(access, Path::new(path), MAX_SNAPSHOT_BYTES, cancellation) {
        Ok(snapshot) => Ok(snapshot),
        Err(failure) => {
            if let Some(ReadIssue::Cancelled(_)) = &failure.primary {
                return Err(AnalysisError::cancelled("read_evidence_file"));
            }
            Err(read_issue_error(failure.primary.as_ref(), path))
        }
    }
}

#[cfg(unix)]
fn host_file_access() -> rea_host::fs::unix_file::UnixFiles {
    rea_host::fs::unix_file::UnixFiles
}

#[cfg(windows)]
fn host_file_access() -> rea_host::fs::windows_file::WindowsFiles {
    rea_host::fs::windows_file::WindowsFiles
}

/// Map a `stable_file::ReadIssue` to the TS `EvidenceFileError` read reason.
fn read_issue_error(issue: Option<&ReadIssue>, path: &str) -> AnalysisError {
    match issue {
        Some(ReadIssue::InvalidPath) => evidence_file("read", "not-file", path),
        Some(ReadIssue::Limit { maximum_bytes }) => ErrorKind::ResourceConstraint {
            operation: "read_evidence_file".to_owned(),
            resource: "file-size".to_owned(),
            reason: format!("Evidence file exceeds the maximum size of {maximum_bytes} bytes"),
            reported_limits: Some(serde_json::json!({ "max_input_file_bytes": maximum_bytes })),
            remediation_action: None,
            retryable: Some(false),
        }
        .into(),
        Some(ReadIssue::Allocation { .. }) => ErrorKind::ResourceConstraint {
            operation: "read_evidence_file".to_owned(),
            resource: "memory".to_owned(),
            reason: "Reading the evidence file requires more memory than is available".to_owned(),
            reported_limits: None,
            remediation_action: None,
            retryable: Some(false),
        }
        .into(),
        Some(ReadIssue::Io { error, .. }) => {
            let reason = match error.kind {
                IoKind::NotFound | IoKind::NotDirectory => "missing",
                _ => "io",
            };
            evidence_file("read", reason, path)
        }
        Some(ReadIssue::Changed(_)) => evidence_file("read", "missing", path),
        _ => evidence_file("read", "io", path),
    }
}

/// The session's write-resource scope (TS `AnalysisSnapshotFiles` + its
/// `ArtifactResourceScope`). A failed staging cleanup is retained for retry.
#[derive(Default)]
pub(crate) struct SnapshotFiles {
    /// Staged temp files whose cleanup failed and must be retried on `close()`.
    pending: Vec<PathBuf>,
}

impl SnapshotFiles {
    /// Atomically write a deterministic analysis snapshot (TS
    /// `writeAnalysisSnapshot` = `serializeAnalysisSnapshot` + `writeTextFile`).
    ///
    /// # Errors
    /// `EvidenceIntegrityError` when serialization fails; `EvidenceFileError`
    /// for file-access failures (`not-file`, `exists`, `missing`, `io`),
    /// retaining a published receipt and cleanup resources when staging
    /// cleanup fails after a committed write.
    pub(crate) fn write(
        &mut self,
        snapshot: &AnalysisSnapshot,
        path: &str,
        overwrite: bool,
        cancellation: &Cancellation,
    ) -> Result<(String, u64), AnalysisError> {
        let encoded = snapshot.serialize().map_err(snapshot_validation_error)?;
        self.write_text(&encoded, path, overwrite, cancellation)
    }

    /// Whether any staged cleanup remains to be retried.
    pub(crate) fn has_pending(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Retry retained staging cleanup (TS `closeWriteResources`).
    ///
    /// # Errors
    /// `EvidenceFileError{operation:"write", reason:"io"}` with cleanup
    /// `{ reason, resources }` when staged resources still cannot be released.
    pub(crate) fn close(&mut self) -> Result<(), AnalysisError> {
        let mut unresolved = Vec::new();
        let mut last_reason = String::new();
        let pending = std::mem::take(&mut self.pending);
        for resource in pending {
            match fs::remove_file(&resource) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    last_reason = error.to_string();
                    unresolved.push(resource);
                }
            }
        }
        if unresolved.is_empty() {
            return Ok(());
        }
        let resources: Vec<String> = unresolved
            .iter()
            .map(|path| path.display().to_string())
            .collect();
        self.pending = unresolved;
        Err(AnalysisError::from(ErrorKind::EvidenceFile {
            operation: "write".to_owned(),
            reason: "io".to_owned(),
            path: None,
            published: None,
            user_message: None,
        })
        .with_cleanup(last_reason, resources))
    }

    /// Atomic staged write (TS `writeTextFile` / `publishFile`).
    fn write_text(
        &mut self,
        encoded: &str,
        path: &str,
        overwrite: bool,
        cancellation: &Cancellation,
    ) -> Result<(String, u64), AnalysisError> {
        let requested = absolute_caller_path(path);
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("write_evidence_file"));
        }
        #[cfg(unix)]
        if requested.ends_with('/') {
            return Err(evidence_file("write", "not-file", &requested));
        }
        let destination_path = Path::new(&requested);
        let parent = destination_path
            .parent()
            .ok_or_else(|| evidence_file("write", "not-file", &requested))?;
        let canonical_parent =
            fs::canonicalize(parent).map_err(|error| missing_or_io("write", &error, &requested))?;
        let file_name = destination_path
            .file_name()
            .ok_or_else(|| evidence_file("write", "not-file", &requested))?;
        let destination = canonical_parent.join(file_name);

        match fs::symlink_metadata(&destination) {
            Ok(metadata) => {
                if !overwrite {
                    return Err(evidence_file("write", "exists", &requested));
                }
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(evidence_file("write", "not-file", &requested));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(missing_or_io("write", &error, &requested)),
        }

        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled("write_evidence_file"));
        }

        self.publish(
            &destination,
            &canonical_parent,
            encoded,
            overwrite,
            &requested,
        )
    }

    /// Stage, fsync, and atomically publish, retaining failed cleanup.
    fn publish(
        &mut self,
        destination: &Path,
        parent: &Path,
        encoded: &str,
        overwrite: bool,
        requested: &str,
    ) -> Result<(String, u64), AnalysisError> {
        let staged = parent.join(format!(".rea-write-{}", uuid::Uuid::new_v4()));
        let bytes = encoded.len() as u64;

        let write_outcome = (|| -> std::io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged)?;
            file.write_all(encoded.as_bytes())?;
            file.sync_all()?;
            Ok(())
        })();

        if let Err(error) = write_outcome {
            // Staging failed; attempt immediate cleanup, retaining on failure.
            self.retain_on_cleanup_failure(&staged);
            if !overwrite && error.kind() == std::io::ErrorKind::AlreadyExists {
                return Err(evidence_file("write", "exists", requested));
            }
            return Err(missing_or_io("write", &error, requested));
        }

        let publish_outcome = if overwrite {
            fs::rename(&staged, destination)
        } else {
            // A hard link publishes atomically and cannot replace a name.
            fs::hard_link(&staged, destination).map(|()| ())
        };

        match publish_outcome {
            Ok(()) => {
                if overwrite {
                    // Rename consumed the staged file; nothing to clean up.
                    Ok((requested.to_owned(), bytes))
                } else {
                    // Remove the staged source after the link published.
                    match fs::remove_file(&staged) {
                        Ok(()) => Ok((requested.to_owned(), bytes)),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                            Ok((requested.to_owned(), bytes))
                        }
                        Err(error) => {
                            // Published, but cleanup failed: retain for retry.
                            self.pending.push(staged.clone());
                            Err(AnalysisError::from(ErrorKind::EvidenceFile {
                                operation: "write".to_owned(),
                                reason: "io".to_owned(),
                                path: Some(requested.to_owned()),
                                published: Some(PublishedFile {
                                    path: requested.to_owned(),
                                    bytes,
                                }),
                                user_message: None,
                            })
                            .with_cleanup(error.to_string(), vec![staged.display().to_string()]))
                        }
                    }
                }
            }
            Err(error) => {
                self.retain_on_cleanup_failure(&staged);
                if !overwrite && error.kind() == std::io::ErrorKind::AlreadyExists {
                    return Err(evidence_file("write", "exists", requested));
                }
                Err(missing_or_io("write", &error, requested))
            }
        }
    }

    fn retain_on_cleanup_failure(&mut self, staged: &Path) {
        match fs::remove_file(staged) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => self.pending.push(staged.to_path_buf()),
        }
    }
}

/// TS `absoluteCallerPath`: resolve against the current working directory.
fn absolute_caller_path(path: &str) -> String {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return path.to_owned();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(candidate).display().to_string(),
        Err(_) => path.to_owned(),
    }
}

fn evidence_file(operation: &str, reason: &str, path: &str) -> AnalysisError {
    ErrorKind::EvidenceFile {
        operation: operation.to_owned(),
        reason: reason.to_owned(),
        path: Some(path.to_owned()),
        published: None,
        user_message: None,
    }
    .into()
}

/// A missing path or parent is a selection error, not a permission failure
/// (TS `missingOrIo`).
fn missing_or_io(operation: &str, error: &std::io::Error, path: &str) -> AnalysisError {
    let reason = match error.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => "missing",
        _ => "io",
    };
    evidence_file(operation, reason, path)
}

fn invalid_json(path: &str) -> AnalysisError {
    evidence_file("read", "invalid-json", path)
}

fn integrity(message: String) -> AnalysisError {
    ErrorKind::EvidenceIntegrity {
        message,
        user_message: None,
    }
    .into()
}

/// TS `snapshotValidationMessage`: a `TypeError` message passes through, any
/// other cause becomes "Analysis snapshot validation failed".
fn snapshot_validation_error(message: String) -> AnalysisError {
    integrity(message)
}
