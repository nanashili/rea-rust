//! Stable bounded artifact reads with the original failure classification.
//!
//! Compatibility owners: `src/artifacts/readStableArtifact.ts` and
//! `ArtifactReaderFailure`. The physical read is `rea_host::fs::stable_file`;
//! this module only names its outcomes the way the original reader did so
//! provider adapters classify them identically.
use crate::node::FsError;
use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_file::{self, IoKind, ReadIssue};
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
type HostFiles = rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
type HostFiles = rea_host::fs::windows_file::WindowsFiles;

/// Exact bytes and digest read from one stable regular file.
#[derive(Debug)]
pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// `ArtifactReaderFailure.reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReaderReason {
    Cancelled,
    Format,
    Integrity,
    Io,
    Limit,
    Path,
}

/// One failed stable read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// A typed `ArtifactReaderFailure`.
    Reader {
        reason: ReaderReason,
        message: String,
    },
    /// A raw filesystem error the original reader propagated unchanged.
    System(FsError),
    /// Descriptor cleanup could not be confirmed; the primary outcome is kept.
    Cleanup {
        primary: Option<Box<ReadError>>,
        reason: String,
        resources: Vec<String>,
    },
}

impl ReadError {
    /// The original `Error.message`.
    pub fn message(&self) -> String {
        match self {
            Self::Reader { message, .. } => message.clone(),
            Self::System(error) => error.message.clone(),
            Self::Cleanup {
                primary, reason, ..
            } => primary
                .as_ref()
                .map_or_else(|| reason.clone(), |primary| primary.message()),
        }
    }

    /// Reader reason, when this is a typed reader failure.
    pub fn reader_reason(&self) -> Option<ReaderReason> {
        match self {
            Self::Reader { reason, .. } => Some(*reason),
            _ => None,
        }
    }

    /// System error code (`EACCES`, `ENOENT`, ...), when raw.
    pub fn system_code(&self) -> Option<&'static str> {
        match self {
            Self::System(error) => error.code,
            _ => None,
        }
    }
}

fn syscall(stage: &str) -> &'static str {
    match stage {
        "before admission" | "during read" => "lstat",
        "before open" => "open",
        "read" => "read",
        _ => "fstat",
    }
}

fn issue_error(issue: ReadIssue, path: &str) -> ReadError {
    match issue {
        ReadIssue::Cancelled(_) => ReadError::Reader {
            reason: ReaderReason::Cancelled,
            message: "The operation was aborted".into(),
        },
        ReadIssue::InvalidPath => ReadError::Reader {
            reason: ReaderReason::Path,
            message: format!("Expected a regular file without a symlink: {path}"),
        },
        ReadIssue::Changed(stage) => ReadError::Reader {
            reason: ReaderReason::Integrity,
            message: format!("Artifact changed {stage}: {path}"),
        },
        ReadIssue::Limit { maximum_bytes } => ReadError::Reader {
            reason: ReaderReason::Limit,
            message: format!("Selected artifact exceeds {maximum_bytes} bytes: {path}"),
        },
        ReadIssue::Allocation { requested_bytes } => ReadError::Reader {
            reason: ReaderReason::Limit,
            message: format!("Selected artifact exceeds {requested_bytes} bytes: {path}"),
        },
        ReadIssue::InvalidRead => ReadError::Reader {
            reason: ReaderReason::Format,
            message: format!("Artifact stream did not return bytes: {path}"),
        },
        ReadIssue::Io { stage, error } => {
            if error.kind == IoKind::Interrupted {
                return ReadError::System(FsError::plain(error.to_string()));
            }
            ReadError::System(FsError::from_io(&error.source, syscall(stage), path))
        }
    }
}

/// Read one bounded regular file and reject replacement or in-place changes.
pub fn read_stable(
    path: &str,
    maximum_bytes: usize,
    cancellation: &Cancellation,
) -> Result<Snapshot, ReadError> {
    match stable_file::read(
        Arc::new(HostFiles {}),
        Path::new(path),
        maximum_bytes,
        cancellation,
    ) {
        Ok(snapshot) => Ok(Snapshot {
            bytes: snapshot.bytes,
            sha256: snapshot.sha256,
        }),
        Err(failure) => {
            let failure = *failure;
            let primary = failure.primary.map(|issue| issue_error(issue, path));
            // Any failed close is a reported cleanup failure, as the original
            // `OwnedFileHandle.close` rejection, even when POSIX released the
            // descriptor; a retained handle additionally stays owned.
            if failure.retained.is_some() || !failure.cleanup_failures.is_empty() {
                let reason = failure
                    .cleanup_failures
                    .last()
                    .map(|close| close.error.to_string())
                    .unwrap_or_else(|| "Artifact descriptor cleanup failed".into());
                return Err(ReadError::Cleanup {
                    primary: primary.map(Box::new),
                    reason,
                    resources: vec![path.to_owned()],
                });
            }
            Err(primary.unwrap_or(ReadError::Reader {
                reason: ReaderReason::Io,
                message: format!("Artifact read failed: {path}"),
            }))
        }
    }
}

/// Read with no caller cancellation (post-run integrity checks).
pub fn read_stable_uncancelled(path: &str, maximum_bytes: usize) -> Result<Snapshot, ReadError> {
    read_stable(path, maximum_bytes, &Cancellation::default())
}

/// Lowercase hexadecimal SHA-256 of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}
