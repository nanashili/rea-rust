//! Read-only artifact reader abstraction and typed failures.
//!
//! Compatibility owners: `src/artifacts/ArtifactReader.ts` and
//! `src/artifacts/ArtifactOperationFailure.ts`. The async streaming adapter
//! model is replaced by a synchronous, cancellation-aware trait that yields
//! each entry's metadata and, on demand, its complete bytes.
use rea_core::JsString;
use rea_core::analysis_error::{AnalysisError, ArtifactDetails, CleanupObservation};
use rea_core::cancellation::Cancellation;
use rea_host::fs::stable_file::{
    FileAccess, Lease, ReadFailure as StableReadFailure, ReadIssue, Snapshot,
};
use rea_mcp::SessionResource;
use serde_json::Value;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::{fmt, mem};

/// Archive-neutral entry metadata. Reader adapters never choose output paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactEntry {
    /// Logical archive or directory entry path, retained as UTF-16 units.
    pub path: JsString,
    /// file, directory, symlink or slice.
    pub kind: &'static str,
    pub declared_size: Option<u64>,
    pub compressed_size: Option<u64>,
    pub executable: bool,
    pub encrypted: bool,
    pub byte_offset: Option<u64>,
    pub declared_sha256: Option<String>,
    pub unpacked: bool,
    pub limitations: Vec<String>,
    /// Opaque key the owning reader uses to re-find this entry.
    pub adapter_key: JsString,
}

/// One entry or subtree deliberately excluded from a traversal.
#[derive(Clone, Debug)]
pub struct ArtifactTraversalOmission {
    /// Logical path of the omitted entry, retained as UTF-16 units.
    pub path: JsString,
    /// fifo, socket, block-device, character-device, unsupported or
    /// directory-descendants.
    pub kind: &'static str,
}

/// One `ArtifactReaderFailure` (`src/artifacts/ArtifactReader.ts`).
#[derive(Clone, Debug)]
pub struct ReaderFailure {
    /// cancelled, format, integrity, io, limit, path or unavailable.
    pub reason: &'static str,
    pub message: String,
    pub details: Option<ArtifactDetails>,
    pub cleanup: Option<CleanupObservation>,
    pub partial_observation: Option<Value>,
    pub(crate) retained_file: Option<HostFileCleanupOwner>,
    retained_readers: Vec<RetainedReader>,
    retained_resources: Vec<RetainedResource>,
}

/// Session owner for an exact stable-file lease retained after root reading.
/// The lease itself, rather than a pathname, is retained until close succeeds.
pub(crate) struct StableFileCleanupOwner<F: FileAccess> {
    resource: String,
    lease: Arc<Mutex<Option<Lease<F>>>>,
}

pub(crate) type HostFileCleanupOwner = StableFileCleanupOwner<crate::common::HostFiles>;

impl<F: FileAccess> Clone for StableFileCleanupOwner<F> {
    fn clone(&self) -> Self {
        Self {
            resource: self.resource.clone(),
            lease: Arc::clone(&self.lease),
        }
    }
}

impl<F: FileAccess> fmt::Debug for StableFileCleanupOwner<F> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StableFileCleanupOwner")
            .field("resource", &self.resource)
            .finish()
    }
}

impl<F: FileAccess> StableFileCleanupOwner<F> {
    pub(crate) fn from_failure(
        resource: String,
        failure: &mut StableReadFailure<F>,
    ) -> Option<Self> {
        failure.retained.take().map(|lease| Self {
            resource,
            lease: Arc::new(Mutex::new(Some(lease))),
        })
    }

    fn resource(&self) -> &str {
        &self.resource
    }

    fn retains_resource(&self) -> bool {
        self.lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .as_ref()
            .is_some_and(Lease::retains_resource)
    }

    fn cleanup_observation(
        &self,
        failure: &rea_host::fs::stable_file::CloseFailure,
        retains_resource: bool,
    ) -> CleanupObservation {
        CleanupObservation {
            reason: failure.error.to_string(),
            resources: if retains_resource {
                vec![self.resource.clone()]
            } else {
                Vec::new()
            },
        }
    }
}

impl<F: FileAccess> SessionResource for StableFileCleanupOwner<F> {
    fn close(&self) -> Result<(), AnalysisError> {
        let mut lease = self
            .lease
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = match lease.as_mut() {
            Some(owner) => owner.close(),
            None => return Ok(()),
        };

        let retains_resource = lease.as_ref().is_some_and(Lease::retains_resource);
        if !retains_resource {
            lease.take();
        }

        result.map_err(|failure| {
            let cleanup = self.cleanup_observation(&failure, retains_resource);
            AnalysisError::artifact_operation("artifact_reader_cleanup", "io")
                .with_cleanup(cleanup.reason, cleanup.resources)
        })
    }
}

struct StableFileReadTranslation<F: FileAccess> {
    reason: &'static str,
    message: String,
    cleanup: Option<CleanupObservation>,
    partial_observation: Option<Value>,
    retained_file: Option<StableFileCleanupOwner<F>>,
}

fn translate_stable_read_failure<F: FileAccess>(
    path: &str,
    mut failure: StableReadFailure<F>,
) -> StableFileReadTranslation<F> {
    let (reason, message) = match &failure.primary {
        Some(ReadIssue::Cancelled(_)) => ("cancelled", "Artifact inventory cancelled".to_owned()),
        Some(ReadIssue::InvalidPath) => ("path", "Root artifact is not a regular file".to_owned()),
        Some(ReadIssue::Changed(stage)) => ("integrity", format!("Root artifact changed {stage}")),
        Some(ReadIssue::Limit { maximum_bytes }) => (
            "limit",
            format!("Root artifact exceeds {maximum_bytes} bytes"),
        ),
        Some(ReadIssue::Allocation { .. }) => (
            "limit",
            "Could not allocate root artifact storage".to_owned(),
        ),
        Some(ReadIssue::Io { error, .. }) => ("io", error.to_string()),
        Some(ReadIssue::InvalidRead) => (
            "io",
            "Root artifact stream did not return admitted bytes".to_owned(),
        ),
        None if !failure.cleanup_failures.is_empty() => (
            "io",
            "Root artifact read completed but cleanup failed".to_owned(),
        ),
        None => (
            "io",
            "Root artifact stream did not return admitted bytes".to_owned(),
        ),
    };

    let cleanup = if failure.cleanup_failures.is_empty() {
        None
    } else {
        let reason = failure
            .cleanup_failures
            .iter()
            .map(|cleanup| cleanup.error.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Some(CleanupObservation {
            reason,
            resources: if failure.retained.is_some() {
                vec![format!("{path} reader lease")]
            } else {
                Vec::new()
            },
        })
    };

    let partial_observation = failure.completed.as_ref().map(|completed| {
        serde_json::json!({
            "kind": "stable-file-read",
            "path": path,
            "bytes": completed.bytes.len(),
            "sha256": completed.sha256,
        })
    });
    let retained_file =
        StableFileCleanupOwner::from_failure(format!("{path} reader lease"), &mut failure);

    StableFileReadTranslation {
        reason,
        message,
        cleanup,
        partial_observation,
        retained_file,
    }
}

/// Read one stable file while carrying exact lease ownership through the
/// artifact failure boundary for session cleanup.
pub(crate) fn read_stable_file(
    path: &str,
    maximum: usize,
    cancellation: &Cancellation,
) -> Result<Snapshot, ReaderFailure> {
    let failure = match rea_host::fs::stable_file::read(
        crate::common::host_files(),
        Path::new(path),
        maximum,
        cancellation,
    ) {
        Ok(snapshot) => return Ok(snapshot),
        Err(failure) => *failure,
    };

    let translated = translate_stable_read_failure(path, failure);
    let mut reader_failure = ReaderFailure::new(translated.reason, translated.message);
    reader_failure.cleanup = translated.cleanup;
    reader_failure.partial_observation = translated.partial_observation;
    reader_failure.retained_file = translated.retained_file;
    Err(reader_failure)
}

/// Reader ownership retained after a failed close so the owner can retry it.
#[derive(Clone)]
pub struct RetainedReader {
    resource: String,
    reader: Arc<Mutex<Option<Box<dyn ArtifactReader>>>>,
}

impl fmt::Debug for RetainedReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedReader")
            .field("resource", &self.resource)
            .finish()
    }
}

impl RetainedReader {
    pub(crate) fn new(resource: String, reader: Box<dyn ArtifactReader>) -> Self {
        Self {
            resource,
            reader: Arc::new(Mutex::new(Some(reader))),
        }
    }

    pub fn resource(&self) -> &str {
        &self.resource
    }

    pub fn retry_close(&self) -> Result<(), ReaderFailure> {
        let mut reader = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = match reader.as_mut() {
            Some(reader) => reader.close(),
            None => Ok(()),
        };
        if result.is_ok() {
            reader.take();
        }
        result
    }
}

/// Session-owned cleanup for readers that outlived a failed artifact call.
///
/// `Session::close` removes and closes each owned resource serially. The
/// internal mutex still protects the retained readers if a later retry is
/// initiated through the same owner, and failed readers are put back before
/// returning the cleanup error.
pub(crate) struct ReaderCleanupOwner {
    owners: Mutex<CleanupOwners>,
}

#[derive(Default)]
struct CleanupOwners {
    readers: Vec<RetainedReader>,
    resources: Vec<RetainedResource>,
}

impl CleanupOwners {
    fn retry(&mut self, retry: &mut CleanupRetry) {
        self.resources = retry_retained_resources(mem::take(&mut self.resources), retry);

        for reader in mem::take(&mut self.readers) {
            match reader.retry_close() {
                Ok(()) => retry.released(reader.resource()),
                Err(mut failure) => {
                    retry.reader_close_failed(reader.resource(), &failure);
                    self.retain_reader(reader);
                    self.absorb_failure(&mut failure);
                }
            }
        }
    }

    fn retain_reader(&mut self, reader: RetainedReader) {
        if !self
            .readers
            .iter()
            .any(|existing| Arc::ptr_eq(&existing.reader, &reader.reader))
        {
            self.readers.push(reader);
        }
    }

    fn retain_resource(&mut self, resource: RetainedResource) {
        if !self
            .resources
            .iter()
            .any(|existing| existing.owner.shares_owner(&resource.owner))
        {
            self.resources.push(resource);
        }
    }

    fn absorb_failure(&mut self, failure: &mut ReaderFailure) {
        if let Some(owner) = failure.retained_file.take() {
            self.retain_resource(RetainedResource {
                resource: owner.resource().to_owned(),
                owner: CleanupResource::File(owner),
            });
        }

        for reader in mem::take(&mut failure.retained_readers) {
            self.retain_reader(reader);
        }
        for resource in mem::take(&mut failure.retained_resources) {
            self.retain_resource(resource);
        }
    }
}

#[derive(Clone)]
struct RetainedResource {
    resource: String,
    owner: CleanupResource,
}

#[derive(Clone)]
enum CleanupResource {
    File(HostFileCleanupOwner),
    Session(Arc<dyn SessionResource>),
}

impl CleanupResource {
    fn close(&self) -> Result<(), AnalysisError> {
        match self {
            Self::File(owner) => owner.close(),
            Self::Session(owner) => owner.close(),
        }
    }

    fn retains_resource(&self) -> bool {
        match self {
            Self::File(owner) => owner.retains_resource(),
            Self::Session(_) => true,
        }
    }

    fn shares_owner(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::File(left), Self::File(right)) => Arc::ptr_eq(&left.lease, &right.lease),
            (Self::Session(left), Self::Session(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl fmt::Debug for RetainedResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RetainedResource")
            .field("resource", &self.resource)
            .finish()
    }
}

impl ReaderCleanupOwner {
    pub(crate) fn from_failure(failure: &mut ReaderFailure) -> Option<Arc<Self>> {
        let owners = CleanupOwners {
            readers: mem::take(&mut failure.retained_readers),
            resources: mem::take(&mut failure.retained_resources),
        };
        if owners.readers.is_empty() && owners.resources.is_empty() {
            return None;
        }
        Some(Arc::new(Self {
            owners: Mutex::new(owners),
        }))
    }
}

impl SessionResource for ReaderCleanupOwner {
    fn close(&self) -> Result<(), AnalysisError> {
        let mut owners = self
            .owners
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut retry = CleanupRetry::new(None);
        owners.retry(&mut retry);

        let Some(cleanup) = retry.finish() else {
            return Ok(());
        };

        Err(
            AnalysisError::artifact_operation("artifact_reader_cleanup", "io")
                .with_cleanup(cleanup.reason, cleanup.resources),
        )
    }
}

/// Tracks historical cleanup observations separately from the current retry.
/// A successful owner may clear only historical names; observations from the
/// current retry remain visible even when another owner shares their label.
struct CleanupRetry {
    historical_resources: Vec<String>,
    current_resources: Vec<String>,
    reasons: Vec<String>,
    diagnostic_without_resource: bool,
}

impl CleanupRetry {
    fn new(previous: Option<CleanupObservation>) -> Self {
        match previous {
            Some(observation) => Self {
                diagnostic_without_resource: observation.resources.is_empty(),
                historical_resources: observation.resources,
                current_resources: Vec::new(),
                reasons: vec![observation.reason],
            },
            None => Self {
                historical_resources: Vec::new(),
                current_resources: Vec::new(),
                reasons: Vec::new(),
                diagnostic_without_resource: false,
            },
        }
    }

    fn released(&mut self, resource: &str) {
        self.historical_resources
            .retain(|candidate| candidate != resource);
    }

    fn resource_close_failed(
        &mut self,
        resource: &str,
        error: AnalysisError,
        retains_resource: bool,
    ) {
        if retains_resource {
            self.current_resources.push(resource.to_owned());
        } else {
            self.released(resource);
            self.diagnostic_without_resource = true;
        }

        match error.cleanup {
            Some(cleanup) => {
                self.current_resources.extend(cleanup.resources);
                self.reasons.push(cleanup.reason);
            }
            None => self.reasons.push(error.to_string()),
        }
    }

    fn reader_close_failed(&mut self, resource: &str, failure: &ReaderFailure) {
        self.current_resources.push(resource.to_owned());
        self.current_resources
            .extend(failure.owned_resource_names());
        self.reasons.push(failure.message.clone());

        if let Some(cleanup) = &failure.cleanup {
            self.current_resources
                .extend(cleanup.resources.iter().cloned());
            self.reasons.push(cleanup.reason.clone());
        }
    }

    fn finish(mut self) -> Option<CleanupObservation> {
        self.historical_resources.extend(self.current_resources);
        if self.historical_resources.is_empty() && !self.diagnostic_without_resource {
            return None;
        }

        self.historical_resources.sort();
        self.historical_resources.dedup();
        self.reasons.dedup();
        let reason = if self.reasons.is_empty() {
            "Reader cleanup remains incomplete".to_owned()
        } else {
            self.reasons.join("; ")
        };

        Some(CleanupObservation {
            reason,
            resources: self.historical_resources,
        })
    }
}

fn retry_retained_resources(
    resources: Vec<RetainedResource>,
    retry: &mut CleanupRetry,
) -> Vec<RetainedResource> {
    let mut remaining = Vec::new();

    for resource in resources {
        match resource.owner.close() {
            Ok(()) => retry.released(&resource.resource),
            Err(error) => {
                let retains_resource = resource.owner.retains_resource();
                retry.resource_close_failed(&resource.resource, error, retains_resource);
                if retains_resource {
                    remaining.push(resource);
                }
            }
        }
    }

    remaining
}

impl ReaderFailure {
    pub fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
            details: None,
            cleanup: None,
            partial_observation: None,
            retained_file: None,
            retained_readers: Vec::new(),
            retained_resources: Vec::new(),
        }
    }

    pub fn with_details(mut self, details: ArtifactDetails) -> Self {
        self.details = Some(details);
        self
    }

    /// Retain cleanup uncertainty while preserving the original reader error.
    pub fn with_cleanup(mut self, reason: impl Into<String>, resources: Vec<String>) -> Self {
        self.cleanup = Some(CleanupObservation {
            reason: reason.into(),
            resources,
        });
        self
    }

    pub(crate) fn retain_reader(&mut self, reader: RetainedReader) {
        self.retained_readers.push(reader);
    }

    /// Keep an exact cleanup owner reachable after a failed artifact call.
    pub(crate) fn retain_resource(&mut self, resource: String, owner: Arc<dyn SessionResource>) {
        self.retained_resources.push(RetainedResource {
            resource,
            owner: CleanupResource::Session(owner),
        });
    }

    /// Preserve the primary failure while transferring every cleanup owner.
    pub(crate) fn with_cleanup_failure(mut self, mut cleanup: ReaderFailure) -> Self {
        let mut reasons = Vec::new();
        let mut resources = Vec::new();
        if let Some(observation) = self.cleanup.take() {
            reasons.push(observation.reason);
            resources.extend(observation.resources);
        }

        reasons.push(cleanup.message.clone());
        if let Some(observation) = cleanup.cleanup.take() {
            reasons.push(observation.reason);
            resources.extend(observation.resources);
        }
        resources.extend(cleanup.owned_resource_names());
        self.absorb_cleanup_owners(&mut cleanup);

        resources.sort();
        resources.dedup();
        reasons.dedup();
        self.cleanup = Some(CleanupObservation {
            reason: reasons.join("; "),
            resources,
        });
        self
    }

    fn owned_resource_names(&self) -> impl Iterator<Item = String> + '_ {
        self.retained_file
            .iter()
            .map(|owner| owner.resource().to_owned())
            .chain(
                self.retained_readers
                    .iter()
                    .map(|reader| reader.resource().to_owned()),
            )
            .chain(
                self.retained_resources
                    .iter()
                    .map(|resource| resource.resource.clone()),
            )
    }

    fn absorb_cleanup_owners(&mut self, cleanup: &mut ReaderFailure) {
        if let Some(owner) = cleanup.retained_file.take() {
            if self.retained_file.is_none() {
                self.retained_file = Some(owner);
            } else {
                self.retained_resources.push(RetainedResource {
                    resource: owner.resource().to_owned(),
                    owner: CleanupResource::File(owner),
                });
            }
        }
        self.retained_readers.append(&mut cleanup.retained_readers);
        self.retained_resources
            .append(&mut cleanup.retained_resources);
    }

    pub fn retry_cleanup(&mut self) -> Result<(), CleanupObservation> {
        if self.retained_file.is_none()
            && self.retained_readers.is_empty()
            && self.retained_resources.is_empty()
        {
            return match self.cleanup.clone() {
                Some(observation) => Err(observation),
                None => Ok(()),
            };
        }

        let mut retry = CleanupRetry::new(self.cleanup.take());
        self.retry_file_cleanup(&mut retry);
        let mut owners = CleanupOwners {
            readers: mem::take(&mut self.retained_readers),
            resources: mem::take(&mut self.retained_resources),
        };
        owners.retry(&mut retry);
        self.retained_readers = owners.readers;
        self.retained_resources = owners.resources;

        self.cleanup = retry.finish();
        match self.cleanup.clone() {
            Some(observation) => Err(observation),
            None => Ok(()),
        }
    }

    fn retry_file_cleanup(&mut self, retry: &mut CleanupRetry) {
        let Some(owner) = self.retained_file.take() else {
            return;
        };

        match owner.close() {
            Ok(()) => retry.released(owner.resource()),
            Err(error) => {
                let retains_resource = owner.retains_resource();
                retry.resource_close_failed(owner.resource(), error, retains_resource);
                if retains_resource {
                    self.retained_file = Some(owner);
                }
            }
        }
    }
}

/// Read-only adapter over one directory, archive or virtual container.
///
/// `format` mirrors `ArtifactReader.format`. `entries` enumerates the complete
/// traversal once (the native scan does not need lazy async iteration), and
/// `open` returns the complete bytes of one regular entry (the shared hasher
/// digests the full stream regardless, so eager reads preserve behavior while
/// honoring cancellation and the size already bounded by the entry).
pub trait ArtifactReader: Send {
    fn format(&self) -> &'static str;

    /// Whether an entry's adapter key refers to a filesystem-backed source.
    /// Archive readers retain relative or synthetic keys, so the default
    /// follows the TypeScript adapter contract and admits absolute keys only.
    fn entry_is_filesystem_backed(&self, entry: &ArtifactEntry) -> bool {
        Path::new(entry.adapter_key.as_str().unwrap_or_default()).is_absolute()
    }

    /// Enumerate entries, recording intentional omissions.
    fn entries(
        &mut self,
        cancellation: &rea_core::cancellation::Cancellation,
        omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure>;

    /// Read the complete bytes of one regular (file or slice) entry.
    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &rea_core::cancellation::Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure>;

    /// Release owned resources. Returns the retained cleanup on failure.
    fn close(&mut self) -> Result<(), ReaderFailure>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_host::fs::stable_file::{CloseOutcome, FileError, Fingerprint, IoKind, Kind};
    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    #[derive(Clone)]
    struct FaultingAccess {
        read_once: Arc<AtomicBool>,
        close_attempts: Arc<AtomicUsize>,
        release_with_error: bool,
    }

    #[derive(Debug)]
    struct Handle;

    impl FaultingAccess {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                read_once: Arc::new(AtomicBool::new(false)),
                close_attempts: Arc::new(AtomicUsize::new(0)),
                release_with_error: false,
            })
        }

        fn fingerprint() -> Fingerprint {
            Fingerprint {
                kind: Kind::Regular,
                device: 7,
                file_id: 11,
                bytes: 1,
                modified_ns: 13,
                changed_ns: 17,
            }
        }

        fn close_error(attempt: usize) -> FileError {
            FileError {
                kind: IoKind::Other,
                system_code: Some("EFAULT"),
                source: io::Error::other(format!("injected close failure {attempt}")),
            }
        }
    }

    impl FileAccess for FaultingAccess {
        type Handle = Handle;

        fn lstat(&self, _path: &Path) -> Result<Fingerprint, FileError> {
            Ok(Self::fingerprint())
        }

        fn open_regular_candidate(&self, _path: &Path) -> Result<Self::Handle, FileError> {
            Ok(Handle)
        }

        fn stat(&self, _handle: &Self::Handle) -> Result<Fingerprint, FileError> {
            Ok(Self::fingerprint())
        }

        fn read(&self, _handle: &Self::Handle, output: &mut [u8]) -> Result<usize, FileError> {
            if self.read_once.swap(true, Ordering::AcqRel) {
                return Ok(0);
            }
            output[0] = b'x';
            Ok(1)
        }

        fn close(&self, _handle: Self::Handle) -> CloseOutcome<Self::Handle> {
            let attempt = self.close_attempts.fetch_add(1, Ordering::AcqRel) + 1;
            if attempt < 3 {
                return CloseOutcome::Retained {
                    handle: Handle,
                    error: Self::close_error(attempt),
                };
            }
            if self.release_with_error && attempt == 3 {
                return CloseOutcome::ReleasedWithError(Self::close_error(attempt));
            }
            CloseOutcome::Released
        }
    }

    #[test]
    fn generic_stable_file_owner_retries_completed_read_close_failure() {
        let access = FaultingAccess::new();
        let failure = rea_host::fs::stable_file::read(
            access.clone(),
            Path::new("fixture.bin"),
            8,
            &Cancellation::default(),
        )
        .expect_err("the injected first close failure must reach the mapping boundary");
        let translation = translate_stable_read_failure("fixture.bin", *failure);

        assert_eq!(translation.reason, "io");
        assert_eq!(
            translation
                .partial_observation
                .as_ref()
                .and_then(|observation| observation["bytes"].as_u64()),
            Some(1)
        );
        assert_eq!(
            translation
                .cleanup
                .as_ref()
                .map(|cleanup| cleanup.resources.as_slice()),
            Some(["fixture.bin reader lease".to_owned()].as_slice())
        );
        let owner = translation
            .retained_file
            .expect("the exact retained lease must cross the production translator");

        let session = rea_mcp::Session::new(std::collections::HashMap::new());
        session.own(Arc::new(owner));
        let first_retry = session
            .close()
            .expect_err("the second injected close must retain the lease");
        assert_eq!(first_retry.len(), 1);
        assert_eq!(access.close_attempts.load(Ordering::Acquire), 2);
        session
            .close()
            .expect("the third close releases the exact retained lease");
        assert_eq!(access.close_attempts.load(Ordering::Acquire), 3);
    }

    #[test]
    fn released_with_error_keeps_diagnostic_without_false_owned_resource() {
        let access = Arc::new(FaultingAccess {
            read_once: Arc::new(AtomicBool::new(false)),
            close_attempts: Arc::new(AtomicUsize::new(0)),
            release_with_error: true,
        });
        let failure = rea_host::fs::stable_file::read(
            access.clone(),
            Path::new("fixture.bin"),
            8,
            &Cancellation::default(),
        )
        .expect_err("the injected first close failure must retain a lease");
        let translation = translate_stable_read_failure("fixture.bin", *failure);
        let owner = translation
            .retained_file
            .expect("the translator must transfer the retained lease");
        let session = rea_mcp::Session::new(std::collections::HashMap::new());
        session.own(Arc::new(owner));

        assert!(session.close().is_err());
        let released_with_error = session
            .close()
            .expect_err("released-with-error preserves the cleanup diagnostic");
        let cleanup = released_with_error[0]
            .cleanup
            .as_ref()
            .expect("the close diagnostic must remain observable");
        assert!(cleanup.resources.is_empty());
        assert_eq!(access.close_attempts.load(Ordering::Acquire), 3);
        session
            .close()
            .expect("after release proof, no owned resource remains to retry");
    }

    struct RetryResource {
        attempts: Arc<AtomicUsize>,
    }

    impl SessionResource for RetryResource {
        fn close(&self) -> Result<(), AnalysisError> {
            if self.attempts.fetch_add(1, Ordering::AcqRel) == 0 {
                return Err(AnalysisError::artifact_operation("nested_cleanup", "io")
                    .with_cleanup("nested resource remains open", vec!["nested lease".into()]));
            }
            Ok(())
        }
    }

    struct NestedCleanupReader {
        attempts: Arc<AtomicUsize>,
        nested: Option<Arc<RetryResource>>,
    }

    impl ArtifactReader for NestedCleanupReader {
        fn format(&self) -> &'static str {
            "test-reader"
        }

        fn entries(
            &mut self,
            _cancellation: &Cancellation,
            _omissions: &mut Vec<ArtifactTraversalOmission>,
        ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn open(
            &mut self,
            _entry: &ArtifactEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> Result<(), ReaderFailure> {
            let attempt = self.attempts.fetch_add(1, Ordering::AcqRel) + 1;
            if attempt >= 3 {
                return Ok(());
            }

            let mut failure = ReaderFailure::new("io", "reader close remains incomplete");
            if attempt == 2 {
                failure.retain_resource(
                    "nested lease".into(),
                    self.nested.take().expect("the nested lease transfers once"),
                );
            }
            Err(failure)
        }
    }

    #[test]
    fn session_retains_new_resources_returned_by_reader_cleanup_retries() {
        let reader_attempts = Arc::new(AtomicUsize::new(0));
        let nested_attempts = Arc::new(AtomicUsize::new(0));
        let mut reader = Box::new(NestedCleanupReader {
            attempts: reader_attempts.clone(),
            nested: Some(Arc::new(RetryResource {
                attempts: nested_attempts.clone(),
            })),
        });
        let mut failure = reader
            .close()
            .expect_err("initial close retains the reader");
        failure.retain_reader(RetainedReader::new("parent reader".into(), reader));

        let session = rea_mcp::Session::new(std::collections::HashMap::new());
        session.own(ReaderCleanupOwner::from_failure(&mut failure).unwrap());
        let errors = session.close().expect_err("retry transfers a nested lease");
        let resources = &errors[0].cleanup.as_ref().unwrap().resources;
        assert!(resources.iter().any(|resource| resource == "nested lease"));
        assert!(resources.iter().any(|resource| resource == "parent reader"));
        assert_eq!(reader_attempts.load(Ordering::Acquire), 2);

        let errors = session
            .close()
            .expect_err("the nested lease survives its independent close failure");
        assert_eq!(
            errors[0].cleanup.as_ref().unwrap().resources,
            vec!["nested lease"]
        );
        assert_eq!(reader_attempts.load(Ordering::Acquire), 3);
        assert_eq!(nested_attempts.load(Ordering::Acquire), 1);

        session.close().expect("the exact nested lease is retried");
        assert_eq!(nested_attempts.load(Ordering::Acquire), 2);
        assert_eq!(reader_attempts.load(Ordering::Acquire), 3);
    }

    struct SharedLabelReader {
        close_attempts: Arc<AtomicUsize>,
        fail_first_close: bool,
    }

    impl ArtifactReader for SharedLabelReader {
        fn format(&self) -> &'static str {
            "shared-label"
        }

        fn entries(
            &mut self,
            _cancellation: &Cancellation,
            _omissions: &mut Vec<ArtifactTraversalOmission>,
        ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn open(
            &mut self,
            _entry: &ArtifactEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> Result<(), ReaderFailure> {
            let attempt = self.close_attempts.fetch_add(1, Ordering::AcqRel);
            if self.fail_first_close && attempt == 0 {
                return Err(ReaderFailure::new("io", "shared-label reader close failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn same_label_readers_keep_failed_owner_after_sibling_releases() {
        let first_attempts = Arc::new(AtomicUsize::new(0));
        let second_attempts = Arc::new(AtomicUsize::new(0));
        let mut failure = ReaderFailure::new("io", "reader cleanup failed");
        failure.retain_reader(RetainedReader::new(
            "shared reader".into(),
            Box::new(SharedLabelReader {
                close_attempts: Arc::clone(&first_attempts),
                fail_first_close: true,
            }),
        ));
        failure.retain_reader(RetainedReader::new(
            "shared reader".into(),
            Box::new(SharedLabelReader {
                close_attempts: Arc::clone(&second_attempts),
                fail_first_close: false,
            }),
        ));

        let session = rea_mcp::Session::new(std::collections::HashMap::new());
        session.own(ReaderCleanupOwner::from_failure(&mut failure).unwrap());
        let first_errors = session
            .close()
            .expect_err("the failed sibling must remain observable");
        assert!(
            first_errors[0]
                .cleanup
                .as_ref()
                .unwrap()
                .resources
                .iter()
                .any(|resource| resource == "shared reader")
        );
        assert_eq!(first_attempts.load(Ordering::Acquire), 1);
        assert_eq!(second_attempts.load(Ordering::Acquire), 1);

        session
            .close()
            .expect("the retained failed reader must be retried");
        assert_eq!(first_attempts.load(Ordering::Acquire), 2);
        assert_eq!(second_attempts.load(Ordering::Acquire), 1);
    }

    struct SharedLabelResource {
        close_attempts: Arc<AtomicUsize>,
        fail_first_close: bool,
    }

    impl SessionResource for SharedLabelResource {
        fn close(&self) -> Result<(), AnalysisError> {
            let attempt = self.close_attempts.fetch_add(1, Ordering::AcqRel);
            if self.fail_first_close && attempt == 0 {
                return Err(
                    AnalysisError::artifact_operation("shared_label", "io").with_cleanup(
                        "shared-label resource close failed",
                        vec!["shared resource detail".into()],
                    ),
                );
            }
            Ok(())
        }
    }

    #[test]
    fn same_label_resources_keep_failed_owner_after_sibling_releases() {
        let first_attempts = Arc::new(AtomicUsize::new(0));
        let second_attempts = Arc::new(AtomicUsize::new(0));
        let mut failure = ReaderFailure::new("io", "resource cleanup failed");
        failure.retain_resource(
            "shared resource".into(),
            Arc::new(SharedLabelResource {
                close_attempts: Arc::clone(&first_attempts),
                fail_first_close: true,
            }),
        );
        failure.retain_resource(
            "shared resource".into(),
            Arc::new(SharedLabelResource {
                close_attempts: Arc::clone(&second_attempts),
                fail_first_close: false,
            }),
        );

        let session = rea_mcp::Session::new(std::collections::HashMap::new());
        session.own(ReaderCleanupOwner::from_failure(&mut failure).unwrap());
        let errors = session
            .close()
            .expect_err("the failed sibling must remain observable");
        let resources = &errors[0].cleanup.as_ref().unwrap().resources;
        assert_eq!(resources, &["shared resource", "shared resource detail"]);
        assert_eq!(first_attempts.load(Ordering::Acquire), 1);
        assert_eq!(second_attempts.load(Ordering::Acquire), 1);

        session
            .close()
            .expect("the retained failed resource must be retried");
        assert_eq!(first_attempts.load(Ordering::Acquire), 2);
        assert_eq!(second_attempts.load(Ordering::Acquire), 1);
    }
}
