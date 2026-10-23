//! Carrier-read failure mapping for the in-process provider.
//!
//! Compatibility owners:
//! - `src/evm/EvmoleFailures.ts` (`evmInterfaceFailure`), the
//!   `phase === "artifact-read"` branches that apply when the engine runs
//!   in-process (no owned-command lifecycle).
//! - `src/artifacts/readStableArtifact.ts` + `src/artifacts/ArtifactReader.ts`
//!   (`ArtifactReaderFailure` reasons) — the host read failures translated
//!   here, via the native `rea_host::fs::stable_file` reader that produces the
//!   same identity/limit/integrity facts.
//!
//! The owned-command branches of `evmInterfaceFailure`
//! (`OwnedCommandFailure`, `prlimit` spawn failures, `SIGXCPU`/`SIGXFSZ`,
//! the `EFBIG` file-size marker) have no in-process analogue: the crate
//! launches no worker. Those paths are intentionally absent and are documented
//! as a non-reproduced isolation guarantee in the worker report.

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_host::fs::stable_file::{FileError, IoKind, ReadFailure, ReadIssue};

use super::release::OPERATION;

/// Translate a `stable_file::read` failure for the carrier read phase.
///
/// Mirrors `readStableArtifact`'s `ArtifactReaderFailure` reasons mapped
/// through `evmInterfaceFailure(cause, "artifact-read", path)`:
/// - cancelled → `AnalysisCancelledError`
/// - integrity (replacement / in-place change) → `AnalysisArtifactChangedError`
/// - limit → `AnalysisInputError` (`out_of_range`)
/// - path (non-regular / symlink) → `AnalysisInputError` (`invalid_format`)
/// - host `EACCES`/`EPERM` → `AnalysisAccessDeniedError`
/// - host `ENOENT`/`ENOTDIR` → `AnalysisInputError` (`invalid_value`)
/// - anything else → `ProviderAdapterError`
pub(crate) fn carrier_read_failure<F: rea_host::fs::stable_file::FileAccess>(
    failure: &ReadFailure<F>,
    path: &str,
) -> AnalysisError {
    match failure.primary.as_ref() {
        Some(ReadIssue::Cancelled(_)) => AnalysisError::cancelled(OPERATION),
        Some(ReadIssue::Changed(_)) => AnalysisError::artifact_changed(
            OPERATION,
            path,
            format!("Artifact changed during read: {path}"),
        ),
        Some(ReadIssue::Limit { maximum_bytes }) => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "out_of_range",
                format!("Selected artifact exceeds {maximum_bytes} bytes: {path}"),
            )],
        ),
        Some(ReadIssue::InvalidPath) => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                format!("Expected a regular file without a symlink: {path}"),
            )],
        ),
        Some(ReadIssue::Io { error, .. }) => map_io(error, path),
        // No `ArtifactReaderFailure` analogue; the TS tail reaches a provider
        // adapter error for any other cause.
        Some(ReadIssue::Allocation { .. }) | Some(ReadIssue::InvalidRead) | None => {
            provider_adapter(path)
        }
    }
}

fn map_io(error: &FileError, path: &str) -> AnalysisError {
    match error.kind {
        // `readStableArtifact` reclassifies these as integrity changes.
        IoKind::NotFound | IoKind::NotDirectory => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_value",
                format!(
                    "Selected bytecode carrier could not be read ({}): {path}.",
                    system_code(error)
                ),
            )],
        ),
        IoKind::SymlinkLoop => AnalysisError::artifact_changed(
            OPERATION,
            path,
            format!("Artifact changed before open: {path}"),
        ),
        IoKind::AccessDenied => {
            AnalysisError::access_denied(OPERATION, path, system_code(error).to_owned())
        }
        _ => provider_adapter(path),
    }
}

fn provider_adapter(path: &str) -> AnalysisError {
    let mut diagnostics = serde_json::Map::new();
    diagnostics.insert("phase".into(), "artifact-read".into());
    diagnostics.insert("path".into(), path.into());
    AnalysisError::provider_adapter(super::release::PROVIDER_ID, OPERATION)
        .with_diagnostics(diagnostics)
}

fn system_code(error: &FileError) -> &'static str {
    error.system_code.unwrap_or(match error.kind {
        IoKind::NotFound => "ENOENT",
        IoKind::NotDirectory => "ENOTDIR",
        IoKind::SymlinkLoop => "ELOOP",
        IoKind::NameTooLong => "ENAMETOOLONG",
        IoKind::AccessDenied => "EACCES",
        IoKind::Interrupted => "EINTR",
        IoKind::Other => "EIO",
    })
}
