//! Stable target identity for the Ghidra Rust host boundary.
//!
//! The caller-selected path is retained alongside the physical file identity.
//! The path is never replaced with a canonicalized display value, and a digest
//! is reported only after `stable_file::read` has revalidated the descriptor and
//! pathname identities.

use crate::fs::stable_file::{self, Fingerprint, Kind, Lease};
use rea_core::cancellation::Cancellation;
use std::{
    fmt,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const MAX_TARGET_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustTargetFingerprint {
    /// The exact path selected by the caller.
    pub selected_path: PathBuf,
    /// Physical identity observed by the host adapter after stable admission.
    pub identity: Fingerprint,
    pub sha256: String,
    pub bytes: u64,
    /// Facts that remain unavailable to this adapter or operation.
    pub unknowns: Vec<String>,
}

pub struct GhidraRustFingerprintError {
    pub selected_path: PathBuf,
    pub reason: String,
    pub unknowns: Vec<String>,
    retained_cleanup: Option<Box<dyn RetainedCleanup>>,
}

impl fmt::Debug for GhidraRustFingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GhidraRustFingerprintError")
            .field("selected_path", &self.selected_path)
            .field("reason", &self.reason)
            .field("unknowns", &self.unknowns)
            .field("retained_cleanup", &self.retained_cleanup.is_some())
            .finish()
    }
}

impl GhidraRustFingerprintError {
    /// Retry cleanup on the exact retained native owner, if one exists.
    ///
    /// A failed retry leaves the owner attached to this error for another
    /// attempt. The owner is discarded only after the host confirms release.
    pub fn retry_cleanup(&mut self) -> Result<(), String> {
        let Some(owner) = self.retained_cleanup.as_mut() else {
            return Ok(());
        };

        let result = owner.retry_cleanup();
        if !owner.retains_resource() {
            self.retained_cleanup = None;
        }
        result
    }

    pub fn retains_cleanup_owner(&self) -> bool {
        self.retained_cleanup
            .as_ref()
            .is_some_and(|owner| owner.retains_resource())
    }
}

trait RetainedCleanup: Send {
    fn retry_cleanup(&mut self) -> Result<(), String>;
    fn retains_resource(&self) -> bool;
}

struct RetainedLease<F: stable_file::FileAccess> {
    lease: Option<Lease<F>>,
}

impl<F: stable_file::FileAccess> RetainedCleanup for RetainedLease<F> {
    fn retry_cleanup(&mut self) -> Result<(), String> {
        let Some(lease) = self.lease.as_mut() else {
            return Ok(());
        };

        let result = lease.close().map_err(|failure| failure.error.to_string());
        if !lease.retains_resource() {
            self.lease = None;
        }
        result
    }

    fn retains_resource(&self) -> bool {
        self.lease
            .as_ref()
            .is_some_and(|lease| lease.retains_resource())
    }
}

impl fmt::Display for GhidraRustFingerprintError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "could not fingerprint {}: {}",
            self.selected_path.display(),
            self.reason
        )
    }
}

impl std::error::Error for GhidraRustFingerprintError {}

/// Fingerprint one caller-selected regular file using the host's stable-file
/// admission contract. The returned identity and digest describe the same
/// validated read; no path-derived identity is invented.
#[cfg(unix)]
pub fn fingerprint_target(
    selected_path: &Path,
    cancellation: &Cancellation,
) -> Result<GhidraRustTargetFingerprint, GhidraRustFingerprintError> {
    fingerprint_with_access(
        selected_path,
        cancellation,
        Arc::new(crate::fs::unix_file::UnixFiles),
    )
}

#[cfg(windows)]
pub fn fingerprint_target(
    selected_path: &Path,
    cancellation: &Cancellation,
) -> Result<GhidraRustTargetFingerprint, GhidraRustFingerprintError> {
    fingerprint_with_access(
        selected_path,
        cancellation,
        Arc::new(crate::fs::windows_file::WindowsFiles),
    )
}

#[cfg(not(any(unix, windows)))]
pub fn fingerprint_target(
    selected_path: &Path,
    _cancellation: &Cancellation,
) -> Result<GhidraRustTargetFingerprint, GhidraRustFingerprintError> {
    Err(GhidraRustFingerprintError {
        selected_path: selected_path.to_owned(),
        reason: "stable target fingerprinting is unavailable on this host".into(),
        unknowns: vec!["physical file identity and digest are unknown".into()],
        retained_cleanup: None,
    })
}

#[cfg(any(unix, windows))]
fn fingerprint_with_access<F: stable_file::FileAccess>(
    selected_path: &Path,
    cancellation: &Cancellation,
    access: Arc<F>,
) -> Result<GhidraRustTargetFingerprint, GhidraRustFingerprintError> {
    let selected_path = selected_path.to_owned();
    let before = access
        .lstat(&selected_path)
        .map_err(|error| GhidraRustFingerprintError {
            selected_path: selected_path.clone(),
            reason: format!("before admission: {error}"),
            unknowns: vec!["stable physical identity and digest are unknown".into()],
            retained_cleanup: None,
        })?;
    if before.kind != Kind::Regular {
        return Err(GhidraRustFingerprintError {
            selected_path,
            reason: "target is not a regular file".into(),
            unknowns: vec!["digest is unknown for a non-regular target".into()],
            retained_cleanup: None,
        });
    }

    let snapshot = stable_file::read(
        access.clone(),
        &selected_path,
        MAX_TARGET_BYTES,
        cancellation,
    )
    .map_err(|failure| {
        let reason = format!("stable read failed: {failure:?}");
        let retained_cleanup = failure.retained.map(|lease| {
            Box::new(RetainedLease { lease }) as Box<dyn RetainedCleanup>
        });
        let mut unknowns = vec!["verified digest is unknown".into()];
        if retained_cleanup.is_some() {
            unknowns.push("native close remains owned and requires cleanup retry".into());
        }

        GhidraRustFingerprintError {
            selected_path: selected_path.clone(),
            reason,
            unknowns,
            retained_cleanup,
        }
    })?;

    // The stable-file owner checks cancellation while hashing and during
    // close, but the caller can cancel immediately after that final check.
    // Match the TypeScript owner by observing cancellation before publishing
    // the completed fingerprint.
    if let Some(reason) = cancellation.reason() {
        return Err(GhidraRustFingerprintError {
            selected_path,
            reason: format!("fingerprinting cancelled: {reason}"),
            unknowns: vec!["fingerprint is unavailable after cancellation".into()],
            retained_cleanup: None,
        });
    }

    let identity = access
        .lstat(&selected_path)
        .map_err(|error| GhidraRustFingerprintError {
            selected_path: selected_path.clone(),
            reason: format!("after admission: {error}"),
            unknowns: vec!["physical identity after hashing is unknown".into()],
            retained_cleanup: None,
        })?;

    if let Some(reason) = cancellation.reason() {
        return Err(GhidraRustFingerprintError {
            selected_path,
            reason: format!("fingerprinting cancelled: {reason}"),
            unknowns: vec!["fingerprint is unavailable after cancellation".into()],
            retained_cleanup: None,
        });
    }

    Ok(GhidraRustTargetFingerprint {
        selected_path,
        identity,
        sha256: snapshot.sha256,
        bytes: snapshot.bytes.len() as u64,
        unknowns: Vec::new(),
    })
}
