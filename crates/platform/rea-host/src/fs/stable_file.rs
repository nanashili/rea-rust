//! One admission/read/finalization owner for a bounded, stable regular file.

use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};
use std::{fmt, io, path::Path, sync::Arc};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    Regular,
    Directory,
    Symlink,
    Other,
}

/// Expected host failures normalized at the native adapter, not by consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoKind {
    NotFound,
    NotDirectory,
    SymlinkLoop,
    NameTooLong,
    AccessDenied,
    Interrupted,
    Other,
}

#[derive(Debug)]
pub struct FileError {
    pub kind: IoKind,
    pub system_code: Option<&'static str>,
    pub source: io::Error,
}
impl fmt::Display for FileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(f)
    }
}
impl std::error::Error for FileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Native identity and mutation facts, normalized once by the host adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Fingerprint {
    pub kind: Kind,
    pub device: u64,
    pub file_id: u128,
    pub bytes: u64,
    pub modified_ns: i128,
    pub changed_ns: i128,
}

/// Release proof is distinct from I/O success. Never retry an already consumed
/// numeric descriptor: another process/thread may have reused that number.
pub enum CloseOutcome<Handle> {
    Released,
    ReleasedWithError(FileError),
    Retained { handle: Handle, error: FileError },
}

/// Host-specific no-follow admission and exact-handle finalization contract.
/// Implementations must never return Released without native release evidence.
pub trait FileAccess: Send + Sync + 'static {
    type Handle: Send;
    fn lstat(&self, path: &Path) -> Result<Fingerprint, FileError>;
    fn open_regular_candidate(&self, path: &Path) -> Result<Self::Handle, FileError>;
    fn stat(&self, handle: &Self::Handle) -> Result<Fingerprint, FileError>;
    fn read(&self, handle: &Self::Handle, output: &mut [u8]) -> Result<usize, FileError>;
    fn close(&self, handle: Self::Handle) -> CloseOutcome<Self::Handle>;
}

#[derive(Debug)]
pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Debug)]
pub enum ReadIssue {
    Cancelled(String),
    InvalidPath,
    Changed(&'static str),
    Limit {
        maximum_bytes: usize,
    },
    Allocation {
        requested_bytes: usize,
    },
    InvalidRead,
    Io {
        stage: &'static str,
        error: FileError,
    },
}

#[derive(Clone, Debug)]
pub struct CloseFailure {
    pub error: Arc<FileError>,
    pub resource_released: bool,
}

/// An exact retained handle. A close failure never becomes a pathname lookup.
pub struct Lease<F: FileAccess> {
    access: Arc<F>,
    handle: Option<F::Handle>,
}
impl<F: FileAccess> Lease<F> {
    fn new(access: Arc<F>, handle: F::Handle) -> Self {
        Self {
            access,
            handle: Some(handle),
        }
    }
    pub fn close(&mut self) -> Result<(), CloseFailure> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        match self.access.close(handle) {
            CloseOutcome::Released => Ok(()),
            CloseOutcome::ReleasedWithError(error) => Err(CloseFailure {
                error: Arc::new(error),
                resource_released: true,
            }),
            CloseOutcome::Retained { handle, error } => {
                self.handle = Some(handle);
                Err(CloseFailure {
                    error: Arc::new(error),
                    resource_released: false,
                })
            }
        }
    }
    pub fn retains_resource(&self) -> bool {
        self.handle.is_some()
    }
}
impl<F: FileAccess> fmt::Debug for Lease<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Lease")
            .field("retained", &self.retains_resource())
            .finish()
    }
}

/// Completed physical facts, primary reason and cleanup owner remain independent.
#[derive(Debug)]
pub struct ReadFailure<F: FileAccess> {
    pub primary: Option<ReadIssue>,
    pub completed: Option<Snapshot>,
    /// Every failed close attempt, in attempt order. Later success releases the
    /// owner but does not erase earlier cleanup diagnostics.
    pub cleanup_failures: Vec<CloseFailure>,
    pub retained: Option<Lease<F>>,
}
impl<F: FileAccess> ReadFailure<F> {
    /// Most recent failed close attempt, if cleanup has failed before.
    pub fn latest_cleanup_failure(&self) -> Option<&CloseFailure> {
        self.cleanup_failures.last()
    }

    /// Retry only a retained native owner. Historical errors and observations stay.
    pub fn retry_cleanup(&mut self) -> Result<(), CloseFailure> {
        let Some(owner) = self.retained.as_mut() else {
            return Ok(());
        };
        let result = owner.close();
        if !owner.retains_resource() {
            self.retained = None;
        }
        if let Err(error) = &result {
            self.cleanup_failures.push(error.clone());
        }
        result
    }
}

fn cancelled(cancellation: &Cancellation) -> Result<(), ReadIssue> {
    match cancellation.reason() {
        Some(reason) => Err(ReadIssue::Cancelled(reason.to_owned())),
        None => Ok(()),
    }
}
fn io_issue(stage: &'static str, error: FileError) -> ReadIssue {
    ReadIssue::Io { stage, error }
}
fn changed_io(stage: &'static str, error: FileError) -> ReadIssue {
    if matches!(
        error.kind,
        IoKind::NotFound | IoKind::NotDirectory | IoKind::SymlinkLoop
    ) {
        ReadIssue::Changed(stage)
    } else {
        io_issue(stage, error)
    }
}
fn primary_failure<F: FileAccess>(primary: ReadIssue) -> Box<ReadFailure<F>> {
    Box::new(ReadFailure {
        primary: Some(primary),
        completed: None,
        cleanup_failures: Vec::new(),
        retained: None,
    })
}

/// Read and hash once, revalidate descriptor/path identity, then settle cleanup.
/// Failure owns every unreleased handle and any fully validated completed bytes.
pub fn read<F: FileAccess>(
    access: Arc<F>,
    path: &Path,
    maximum: usize,
    cancellation: &Cancellation,
) -> Result<Snapshot, Box<ReadFailure<F>>> {
    cancelled(cancellation).map_err(primary_failure)?;
    let before = access
        .lstat(path)
        .map_err(|e| primary_failure(io_issue("before admission", e)))?;
    if before.kind != Kind::Regular {
        return Err(primary_failure(ReadIssue::InvalidPath));
    }
    if before.bytes > maximum as u64 {
        return Err(primary_failure(ReadIssue::Limit {
            maximum_bytes: maximum,
        }));
    }
    cancelled(cancellation).map_err(primary_failure)?;
    let handle = access
        .open_regular_candidate(path)
        .map_err(|e| primary_failure(changed_io("before open", e)))?;
    let mut owner = Lease::new(access, handle);
    // No external borrow of the handle escapes this operation. The owner exists
    // before any further fallible action, including the initial descriptor stat.
    let outcome = match owner.handle.as_ref() {
        Some(handle) => read_owned(
            owner.access.as_ref(),
            handle,
            path,
            before,
            maximum,
            cancellation,
        ),
        None => Err(ReadIssue::InvalidRead),
    };
    let close = owner.close();
    let (mut primary, completed) = match outcome {
        Ok(snapshot) => (None, Some(snapshot)),
        Err(error) => (Some(error), None),
    };
    // Cancellation during finalization cannot erase an earlier primary error or
    // completed observations, and cannot bypass the close attempt.
    if primary.is_none() {
        primary = cancelled(cancellation).err();
    }
    if primary.is_none() && close.is_ok() {
        if let Some(snapshot) = completed {
            return Ok(snapshot);
        }
        return Err(primary_failure(ReadIssue::InvalidRead));
    }
    let cleanup_failures = close.as_ref().err().cloned().into_iter().collect();
    Err(Box::new(ReadFailure {
        primary,
        completed,
        cleanup_failures,
        retained: owner.retains_resource().then_some(owner),
    }))
}

fn read_owned<F: FileAccess>(
    access: &F,
    handle: &F::Handle,
    path: &Path,
    before: Fingerprint,
    maximum: usize,
    cancellation: &Cancellation,
) -> Result<Snapshot, ReadIssue> {
    let initial = access
        .stat(handle)
        .map_err(|e| io_issue("initial descriptor stat", e))?;
    if initial.kind != Kind::Regular
        || initial.device != before.device
        || initial.file_id != before.file_id
    {
        return Err(ReadIssue::Changed("before open"));
    }
    if initial.bytes > maximum as u64 {
        return Err(ReadIssue::Limit {
            maximum_bytes: maximum,
        });
    }
    let mut bytes = Vec::new();
    let initial_size = initial.bytes as usize; // bounded by maximum (a usize) above
    bytes
        .try_reserve_exact(initial_size)
        .map_err(|_| ReadIssue::Allocation {
            requested_bytes: initial_size,
        })?;
    let mut hasher = Sha256::new();
    let mut scratch = [0_u8; 65536];
    loop {
        cancelled(cancellation)?;
        let count = match access.read(handle, &mut scratch) {
            Ok(count) => count,
            Err(error) if error.kind == IoKind::Interrupted => continue,
            Err(error) => return Err(io_issue("read", error)),
        };
        if count > scratch.len() {
            return Err(ReadIssue::InvalidRead);
        }
        if count == 0 {
            break;
        }
        if count > maximum - bytes.len() {
            return Err(ReadIssue::Limit {
                maximum_bytes: maximum,
            });
        }
        let needed = bytes.len() + count;
        if needed > bytes.capacity() {
            // Vec's default geometric growth may exceed the admitted byte limit.
            let capacity = needed.max(bytes.capacity().saturating_mul(2).min(maximum));
            bytes
                .try_reserve_exact(capacity - bytes.len())
                .map_err(|_| ReadIssue::Allocation {
                    requested_bytes: capacity,
                })?;
        }
        hasher.update(&scratch[..count]);
        bytes.extend_from_slice(&scratch[..count]);
    }
    let after = access
        .stat(handle)
        .map_err(|e| io_issue("final descriptor stat", e))?;
    let current = access
        .lstat(path)
        .map_err(|e| changed_io("during read", e))?;
    if after != initial || current != initial || bytes.len() as u64 != initial.bytes {
        return Err(ReadIssue::Changed("during read"));
    }
    cancelled(cancellation)?;
    Ok(Snapshot {
        bytes,
        sha256: format!("{:x}", hasher.finalize()),
    })
}
