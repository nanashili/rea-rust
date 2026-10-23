//! Read-only artifact reader abstraction and typed failures.
//!
//! Compatibility owners: `src/artifacts/ArtifactReader.ts` and
//! `src/artifacts/ArtifactOperationFailure.ts`. The async streaming adapter
//! model is replaced by a synchronous, cancellation-aware trait that yields
//! each entry's metadata and, on demand, its complete bytes.
use rea_core::analysis_error::{ArtifactDetails, CleanupObservation};

/// Archive-neutral entry metadata. Reader adapters never choose output paths.
#[derive(Clone, Debug)]
pub struct ArtifactEntry {
    pub path: String,
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
    pub adapter_key: String,
}

/// One entry or subtree deliberately excluded from a traversal.
#[derive(Clone, Debug)]
pub struct ArtifactTraversalOmission {
    pub path: String,
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
}

impl ReaderFailure {
    pub fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
            details: None,
            cleanup: None,
        }
    }

    pub fn with_details(mut self, details: ArtifactDetails) -> Self {
        self.details = Some(details);
        self
    }
}

/// Read-only adapter over one directory, archive or virtual container.
///
/// `format` mirrors `ArtifactReader.format`. `entries` enumerates the complete
/// traversal once (the native scan does not need lazy async iteration), and
/// `open` returns the complete bytes of one regular entry (the shared hasher
/// digests the full stream regardless, so eager reads preserve behavior while
/// honoring cancellation and the size already bounded by the entry).
pub trait ArtifactReader {
    fn format(&self) -> &'static str;

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
