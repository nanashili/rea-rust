//! Universal Mach-O slice reader.
//!
//! Compatibility owner: `src/artifacts/MachOSliceArtifactReader.ts`. The
//! asynchronous streaming TypeScript adapter is replaced by the synchronous,
//! cancellation-aware `crate::artifact_reader::ArtifactReader` contract: lipo
//! enumerates every slice (`lipo -detailed_info` through the shared native
//! command runner), the FAT table is parsed structurally for identity
//! cross-checks, and each slice's bytes are read as a bounded positioned range
//! with source identity re-verified before and after.
//!
//! The structural parse and positioned reads are host-specific (POSIX
//! no-follow admission plus `pread`). Off a Unix host the reader yields the
//! same `unavailable` outcome the TypeScript reader factory produces off
//! darwin, keeping the crate cross-platform compilable.

use crate::artifact_reader::{
    ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure,
};
use crate::lipo::{LipoArchitecture, parse_lipo_output};
use crate::native_command::{self, CommandCleanup, FailureReason};
use rea_core::analysis_error::CleanupObservation;
use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

/// `Number.MAX_SAFE_INTEGER`; lipo offsets/sizes must stay inside it.
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Read-only universal Mach-O slice reader backed by native lipo metadata.
///
/// The owner (artifact graph) constructs one reader per universal file, drives
/// [`entries`](ArtifactReader::entries) then [`open`](ArtifactReader::open) per
/// slice, reads [`provenance`](Self::provenance), and finally
/// [`close`](ArtifactReader::close).
pub(crate) struct MachOSliceArtifactReader {
    path: String,
    cleanup: Arc<CommandCleanup>,
    source: Option<source::StableFileSource>,
    entries: HashMap<String, ArtifactEntry>,
    command: Option<Value>,
    closed: bool,
}

impl MachOSliceArtifactReader {
    /// Create a reader for the universal Mach-O file at `path`.
    ///
    /// `cleanup` is the session-shared [`CommandCleanup`] the native command
    /// runner retains unverified process-group owners in (the owner registers
    /// it once with the session). The reader owns the source descriptor and
    /// releases it in [`close`](ArtifactReader::close).
    pub(crate) fn new(path: impl Into<String>, cleanup: Arc<CommandCleanup>) -> Self {
        Self {
            path: path.into(),
            cleanup,
            source: None,
            entries: HashMap::new(),
            command: None,
            closed: false,
        }
    }

    /// Recorded `lipo -detailed_info` invocation (`provenance()`), empty until
    /// a successful enumeration. Mirrors the TypeScript `ArtifactCommand` JSON
    /// shape: `{ tool, arguments, tool_version, executable_sha256, exit_code,
    /// effects }` with the artifact path aliased to `$ARTIFACT`.
    pub(crate) fn provenance(&self) -> Vec<Value> {
        self.command.clone().into_iter().collect()
    }

    /// Admit the source descriptor once, retaining it for reuse.
    fn ensure_source(&mut self) -> Result<(), ReaderFailure> {
        if self.closed {
            return Err(ReaderFailure::new(
                "unavailable",
                "Universal Mach-O reader is closed",
            ));
        }
        if self.source.is_some() {
            return Ok(());
        }
        let source = source::StableFileSource::open(&self.path)?;
        if self.closed {
            // Closed during acquisition: release immediately and report closed.
            let mut source = source;
            let _ = source.close();
            return Err(ReaderFailure::new(
                "unavailable",
                "Universal Mach-O reader closed during source acquisition",
            ));
        }
        self.source = Some(source);
        Ok(())
    }

    fn verify_source(&self) -> Result<(), ReaderFailure> {
        let source = self.source.as_ref().ok_or_else(|| {
            ReaderFailure::new("unavailable", "Universal Mach-O reader is closed")
        })?;
        source.verify(&self.path)
    }
}

impl ArtifactReader for MachOSliceArtifactReader {
    fn format(&self) -> &'static str {
        "file"
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
        _omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        self.entries.clear();
        self.ensure_source()?;
        self.verify_source()?;
        if self.closed {
            return Err(ReaderFailure::new(
                "unavailable",
                "Universal Mach-O reader is closed",
            ));
        }

        let captured = native_command::run(
            &self.cleanup,
            cancellation,
            "lipo",
            &["-detailed_info".to_owned(), self.path.clone()],
            false,
        )
        .map_err(lipo_command_failure)?;

        if self.closed {
            return Err(ReaderFailure::new(
                "unavailable",
                "Universal Mach-O reader closed during slice discovery",
            ));
        }

        self.command = Some(json!({
            "tool": captured.tool,
            "arguments": ["-detailed_info", "$ARTIFACT"],
            "tool_version": captured.tool_version,
            "executable_sha256": captured.executable_sha256,
            "exit_code": captured.exit_code,
            "effects": ["read"],
        }));

        self.verify_source()?;
        let file_size = self.source.as_ref().expect("source admitted above").size();

        let parsed = parse_lipo_output(&captured.stdout, Some(&self.path))
            .map_err(|reason| ReaderFailure::new("unavailable", lipo_parse_message(&reason)))?;
        let architectures = parsed.architectures;

        let structural = {
            let source = self.source.as_ref().expect("source admitted above");
            source.read_structural_slices(file_size)?
        };
        self.verify_source()?;

        match &structural {
            structural::StructuralSlices::Malformed(reason) => {
                return Err(ReaderFailure::new(
                    "integrity",
                    format!("Mach-O structural slice index is malformed: {reason}"),
                ));
            }
            structural::StructuralSlices::Unsupported(reason) => {
                // A valid universal binary can hold slices REA cannot index,
                // such as big-endian PowerPC. lipo's own ranges still
                // inventory every slice, so only an incomplete lipo range makes
                // an unsupported structural index fatal.
                if architectures
                    .iter()
                    .any(|arch| arch.file_offset.is_none() || arch.size.is_none())
                {
                    return Err(ReaderFailure::new(
                        "unavailable",
                        format!("Mach-O structural slice index is unsupported: {reason}"),
                    ));
                }
            }
            structural::StructuralSlices::NotMachO | structural::StructuralSlices::Parsed(_) => {}
        }

        let slices = match &structural {
            structural::StructuralSlices::Parsed(slices) => Some(slices.as_slice()),
            _ => None,
        };

        // Match lipo's independently parsed ranges with structural slice
        // identity. `matching[i]` is the structural slice chosen for
        // `architectures[i]`, if any.
        let mut matching: Vec<Option<&structural::Slice>> = vec![None; architectures.len()];
        if let Some(slices) = slices {
            if slices.len() != architectures.len() {
                return Err(ReaderFailure::new(
                    "integrity",
                    "lipo architecture count disagrees with the Mach-O FAT table",
                ));
            }
            let structurally_unique = slices.len() == 1;
            let mut consumed = vec![false; slices.len()];
            for (index, reported) in architectures.iter().enumerate() {
                let found = slices.iter().enumerate().find(|(slice_index, observed)| {
                    !consumed[*slice_index]
                        && lipo_matches_slice(reported, observed, structurally_unique)
                });
                let Some((slice_index, observed)) = found else {
                    return Err(ReaderFailure::new(
                        "integrity",
                        format!(
                            "lipo slice metadata disagrees with the Mach-O FAT table: {} (cputype={}, cpusubtype={}, offset={}, size={}, alignment={})",
                            reported.name,
                            optional_u64(reported.cpu_type_code),
                            optional_text(reported.cpu_subtype.as_deref()),
                            optional_u64(reported.file_offset),
                            optional_u64(reported.size),
                            optional_u64(reported.alignment),
                        ),
                    ));
                };
                consumed[slice_index] = true;
                matching[index] = Some(observed);
            }
        }

        let mut produced = Vec::with_capacity(architectures.len());
        for (index, architecture) in architectures.iter().enumerate() {
            let structural_slice = matching[index];
            let offset = architecture
                .file_offset
                .or_else(|| structural_slice.map(|slice| slice.slice_offset));
            let slice_size = architecture
                .size
                .or_else(|| structural_slice.map(|slice| slice.slice_size));
            let (Some(offset), Some(slice_size)) = (offset, slice_size) else {
                return Err(ReaderFailure::new(
                    "integrity",
                    "lipo omitted a universal slice byte range",
                ));
            };
            // `offset`/`slice_size` are `u64`; the TS safe-integer and
            // non-negative checks reduce to: size positive, sum representable
            // and within the file.
            let end = offset.checked_add(slice_size);
            if slice_size == 0
                || offset > MAX_SAFE_INTEGER
                || slice_size > MAX_SAFE_INTEGER
                || !matches!(end, Some(end) if end <= MAX_SAFE_INTEGER && end <= file_size)
            {
                return Err(ReaderFailure::new(
                    "integrity",
                    format!(
                        "lipo reported an out-of-bounds Mach-O slice: {}",
                        architecture.name
                    ),
                ));
            }

            let limitations = slice_limitations(&structural, architecture);
            let adapter_key = format!("{offset}:{slice_size}");
            let entry = ArtifactEntry {
                path: format!("slices/{}", architecture.name),
                kind: "slice",
                declared_size: Some(slice_size),
                compressed_size: None,
                executable: true,
                encrypted: false,
                byte_offset: Some(offset),
                declared_sha256: None,
                unpacked: false,
                limitations,
                adapter_key: adapter_key.clone(),
            };
            self.entries.insert(adapter_key, entry.clone());
            produced.push(entry);
        }

        Ok(produced)
    }

    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        if cancellation.reason().is_some() {
            return Err(ReaderFailure::new(
                "cancelled",
                "Mach-O slice read cancelled",
            ));
        }
        let produced = self.entries.get(&entry.adapter_key);
        let produced = match produced {
            Some(produced) if same_artifact_entry(entry, produced) => produced.clone(),
            _ => {
                return Err(ReaderFailure::new(
                    "integrity",
                    "Mach-O slice entry metadata does not match this reader's inventory",
                ));
            }
        };
        let (Some(offset), Some(size)) = (produced.byte_offset, produced.declared_size) else {
            return Err(ReaderFailure::new(
                "integrity",
                "Invalid Mach-O slice byte range",
            ));
        };
        if size == 0 || offset > MAX_SAFE_INTEGER || size > MAX_SAFE_INTEGER {
            return Err(ReaderFailure::new(
                "integrity",
                "Invalid Mach-O slice byte range",
            ));
        }

        self.ensure_source()?;
        self.verify_source()?;
        let file_size = self.source.as_ref().expect("source admitted above").size();
        let end = offset.checked_add(size);
        if !matches!(end, Some(end) if end <= MAX_SAFE_INTEGER && end <= file_size) {
            return Err(ReaderFailure::new(
                "integrity",
                format!("Mach-O slice range is outside the artifact: {}", entry.path),
            ));
        }

        let bytes = {
            let source = self.source.as_ref().expect("source admitted above");
            source.read_range(offset, size, &entry.path, cancellation)?
        };

        // Re-verify source identity after the read, matching the TS stream's
        // post-read `verifySource` and completion guards.
        if cancellation.reason().is_some() {
            return Err(ReaderFailure::new(
                "cancelled",
                "Mach-O slice read cancelled",
            ));
        }
        self.verify_source()?;
        Ok(bytes)
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        self.closed = true;

        // Retry retained native-command process-group cleanup first
        // (`retryCleanup`), then release the owned source. Each stage's failure
        // is retained for retry rather than dropped.
        let cleanup = retry_command_cleanup(&self.cleanup);

        let source_result = match self.source.as_mut() {
            Some(source) => source.close(),
            None => Ok(()),
        };
        // A released source is dropped; a retained one stays owned for retry.
        if source_result.is_ok() {
            self.source = None;
        }

        match (cleanup, source_result) {
            (None, Ok(())) => Ok(()),
            (Some(cleanup), Ok(())) => Err(ReaderFailure {
                reason: "unavailable",
                message: "Native command process cleanup remains incomplete".to_owned(),
                details: None,
                cleanup: Some(cleanup),
            }),
            (None, Err(mut failure)) => {
                failure.reason = "unavailable";
                Err(failure)
            }
            (Some(command_cleanup), Err(mut source_failure)) => {
                // Both stages failed: the source failure is primary, carrying
                // the combined retained-resource observation.
                let mut resources = command_cleanup.resources.clone();
                let mut reason = command_cleanup.reason.clone();
                if let Some(existing) = source_failure.cleanup.take() {
                    reason = format!("{reason}; {}", existing.reason);
                    resources.extend(existing.resources);
                }
                source_failure.reason = "unavailable";
                source_failure.cleanup = Some(CleanupObservation { reason, resources });
                Err(source_failure)
            }
        }
    }
}

/// Map one native-command failure to the exact TS `ArtifactReaderFailure`
/// produced for a failed `lipo -detailed_info` capture.
fn lipo_command_failure(failure: native_command::NativeCommandFailure) -> ReaderFailure {
    let reason = if failure.reason == FailureReason::Cancelled {
        "cancelled"
    } else {
        "unavailable"
    };
    let message = match failure.detail.as_deref() {
        None => "lipo could not enumerate universal Mach-O slices".to_owned(),
        Some(detail) => format!("lipo could not enumerate universal Mach-O slices: {detail}"),
    };
    let mut reader_failure = ReaderFailure::new(reason, message);
    if failure.cleanup_failure.is_some() || !failure.cleanup_resources.is_empty() {
        reader_failure.cleanup = Some(CleanupObservation {
            reason: failure
                .cleanup_failure
                .unwrap_or_else(|| "Native command cleanup remains unverified".to_owned()),
            resources: failure.cleanup_resources,
        });
    }
    reader_failure
}

/// `parse_lipo_output` surfaces malformed output as an error string. The TS
/// `parseLipoOutput` throws a typed failure consumed as `unavailable`; the
/// message is retained verbatim.
fn lipo_parse_message(reason: &str) -> String {
    reason.to_owned()
}

/// Retry the retained native command process-group owners and project a
/// combined cleanup observation when any remains. Drives the shared
/// [`CommandCleanup`] through its `SessionResource::close` retry (the exact
/// same retry the owner runs at session shutdown), adopting the failure's
/// retained-resource observation as the TS `retryCleanup` cleanup facts.
fn retry_command_cleanup(cleanup: &CommandCleanup) -> Option<CleanupObservation> {
    use rea_mcp::SessionResource;
    match SessionResource::close(cleanup) {
        Ok(()) => None,
        Err(error) => Some(error.cleanup.unwrap_or_else(|| CleanupObservation {
            reason: "Native command cleanup remains unverified".to_owned(),
            resources: Vec::new(),
        })),
    }
}

/// `sameArtifactEntry`: the caller-returned entry must match the inventory
/// copy on every field the reader produced.
fn same_artifact_entry(entry: &ArtifactEntry, produced: &ArtifactEntry) -> bool {
    entry.path == produced.path
        && entry.kind == produced.kind
        && entry.declared_size == produced.declared_size
        && entry.compressed_size == produced.compressed_size
        && entry.executable == produced.executable
        && entry.encrypted == produced.encrypted
        && entry.byte_offset == produced.byte_offset
        && entry.declared_sha256 == produced.declared_sha256
        && entry.unpacked == produced.unpacked
        && entry.limitations == produced.limitations
        && entry.adapter_key == produced.adapter_key
}

/// Per-slice limitations, in the TS field order.
fn slice_limitations(
    structural: &structural::StructuralSlices,
    architecture: &LipoArchitecture,
) -> Vec<String> {
    let mut limitations = Vec::new();
    match structural {
        structural::StructuralSlices::NotMachO => limitations.push(
            "Structural Mach-O facts were unavailable; slice range is based on lipo output."
                .to_owned(),
        ),
        structural::StructuralSlices::Unsupported(reason) => limitations.push(format!(
            "Structural Mach-O facts were unsupported ({reason}); slice range is based on lipo output."
        )),
        structural::StructuralSlices::Parsed(_) | structural::StructuralSlices::Malformed(_) => {}
    }
    if architecture.file_offset.is_none() || architecture.size.is_none() {
        limitations.push(
            "Slice range was derived from structural Mach-O facts because lipo omitted it."
                .to_owned(),
        );
    }
    if architecture.cpu_type.is_some() && architecture.cpu_type_code.is_none() {
        limitations.push(format!(
            "lipo CPU type is retained as unnormalized source text: {}",
            architecture.cpu_type.as_deref().unwrap_or_default()
        ));
    }
    if architecture.cpu_subtype.is_some() && architecture.cpu_subtype_code.is_none() {
        let capabilities = match architecture.capabilities.as_deref() {
            None => String::new(),
            Some(capabilities) => format!("; capabilities {capabilities}"),
        };
        limitations.push(format!(
            "lipo CPU subtype is retained as unnormalized source text: {}{capabilities}",
            architecture.cpu_subtype.as_deref().unwrap_or_default()
        ));
    }
    limitations
}

/// `lipoMatchesSlice`: compare lipo's independent ranges with structural slice
/// identity.
fn lipo_matches_slice(
    reported: &LipoArchitecture,
    observed: &structural::Slice,
    structurally_unique: bool,
) -> bool {
    let observed_cpu_type = observed.fat_cpu_type.unwrap_or(observed.cpu_type);
    let observed_cpu_subtype = observed.fat_cpu_subtype.unwrap_or(observed.cpu_subtype);
    let has_physical_identity = reported.file_offset.is_some()
        || reported.size.is_some()
        || reported.cpu_type_code.is_some()
        || reported.cpu_subtype_code.is_some();
    (has_physical_identity || structurally_unique)
        && lipo_name_matches(&reported.name, &observed.architecture)
        && reported
            .file_offset
            .is_none_or(|value| value == observed.slice_offset)
        && reported
            .size
            .is_none_or(|value| value == observed.slice_size)
        && reported
            .cpu_type_code
            .is_none_or(|value| value == u64::from(observed_cpu_type))
        && lipo_subtype_matches(reported, observed_cpu_subtype)
        && match (reported.alignment, observed.fat_alignment_exponent) {
            (None, _) | (_, None) => true,
            (Some(alignment), Some(exponent)) => Some(alignment) == pow2(u32::from(exponent)),
        }
}

/// `2 ** exponent` when representable; `None` guards an absurd exponent.
fn pow2(exponent: u32) -> Option<u64> {
    (exponent < 64).then(|| 1u64 << exponent)
}

/// `lipoSubtypeMatches`: compare the complete subtype when lipo printed its
/// capability byte, otherwise only the base subtype bits.
fn lipo_subtype_matches(reported: &LipoArchitecture, observed_cpu_subtype: u32) -> bool {
    if let Some(code) = reported.cpu_subtype_code {
        return code == u64::from(observed_cpu_subtype);
    }
    match reported.cpu_subtype_base {
        None => true,
        Some(base) => base == macho_cpu_subtype_base(u64::from(observed_cpu_subtype)),
    }
}

/// `machoCpuSubtypeBase`: subtype identity shared across capability flags.
fn macho_cpu_subtype_base(cpu_subtype: u64) -> u64 {
    cpu_subtype & !0xff00_0000
}

/// `lipoNameMatches`: newer lipo names an arm64e ABI variant `arm64e.<variant>`
/// while the FAT table names that slice `arm64e`.
fn lipo_name_matches(reported: &str, observed: &str) -> bool {
    if reported == observed {
        return true;
    }
    observed == "arm64e" && is_arm64e_variant(reported)
}

/// `^arm64e\.[A-Za-z0-9_]+$`.
fn is_arm64e_variant(reported: &str) -> bool {
    let Some(rest) = reported.strip_prefix("arm64e.") else {
        return false;
    };
    !rest.is_empty()
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "unknown".to_owned(), |value| value.to_string())
}

fn optional_text(value: Option<&str>) -> String {
    value.map_or_else(|| "unknown".to_owned(), ToOwned::to_owned)
}

/// Structural FAT parsing over the shared bounded Mach-O header reader.
mod structural {
    pub(super) use rea_rust_analysis::macho::dylib::Slice;

    /// Status of the structural slice index, mirroring the TS
    /// `MachoImageFacts` status union consumed by the reader.
    pub(super) enum StructuralSlices {
        Parsed(Vec<Slice>),
        Malformed(String),
        Unsupported(String),
        NotMachO,
    }

    impl From<rea_rust_analysis::macho::dylib::ImageFacts> for StructuralSlices {
        fn from(facts: rea_rust_analysis::macho::dylib::ImageFacts) -> Self {
            use rea_rust_analysis::macho::dylib::ImageFacts;
            match facts {
                ImageFacts::Parsed { slices } => Self::Parsed(slices),
                ImageFacts::Malformed { reason } => Self::Malformed(reason),
                ImageFacts::Unsupported { reason } => Self::Unsupported(reason),
                ImageFacts::NotMachO => Self::NotMachO,
            }
        }
    }
}

/// Stable, no-follow source descriptor with positioned reads and identity
/// re-verification. Replaces the TS `StableRegularFileDescriptor` /
/// `OwnedFileHandle` pair.
#[cfg(unix)]
mod source {
    use super::structural::StructuralSlices;
    use crate::artifact_reader::ReaderFailure;
    use rea_core::analysis_error::CleanupObservation;
    use rea_core::cancellation::Cancellation;
    use rea_host::fs::stable_file::{
        CloseOutcome, FileAccess, FileError, Fingerprint, IoKind, Kind,
    };
    use rea_host::fs::unix_file::UnixFiles;
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::os::unix::io::AsFd;
    use std::path::Path;

    /// Bound for one positioned read syscall.
    const READ_CHUNK_BYTES: usize = 1024 * 1024;

    pub(super) struct StableFileSource {
        access: UnixFiles,
        file: Option<File>,
        initial: Fingerprint,
    }

    impl StableFileSource {
        /// `#acquireSource`: no-follow admission, reject non-regular files,
        /// then sample the descriptor's initial identity.
        pub(super) fn open(path: &str) -> Result<Self, ReaderFailure> {
            let access = UnixFiles;
            let handle = access
                .open_regular_candidate(Path::new(path))
                .map_err(|error| admission_failure(path, &error))?;
            let initial = match access.stat(&handle) {
                Ok(initial) => initial,
                Err(error) => {
                    // Release the just-opened descriptor before reporting.
                    let _ = access.close(handle);
                    return Err(stat_failure(path, &error));
                }
            };
            if initial.kind != Kind::Regular {
                let _ = access.close(handle);
                return Err(ReaderFailure::new(
                    "format",
                    format!("Universal Mach-O source is not a regular file: {path}"),
                ));
            }
            // Convert the owned descriptor to a `File` for positioned reads.
            // `From<OwnedFd> for File` is a safe std conversion of the same fd.
            let file = File::from(handle);
            Ok(Self {
                access,
                file: Some(file),
                initial,
            })
        }

        pub(super) fn size(&self) -> u64 {
            self.initial.bytes
        }

        /// `#verifySource`: both the descriptor and the pathname must still
        /// resolve to the admitted regular-file identity.
        pub(super) fn verify(&self, path: &str) -> Result<(), ReaderFailure> {
            let file = self.file.as_ref().ok_or_else(|| {
                ReaderFailure::new("unavailable", "Universal Mach-O reader is closed")
            })?;
            let opened =
                fingerprint_file(&self.access, file).map_err(|error| stat_failure(path, &error))?;
            let current = self
                .access
                .lstat(Path::new(path))
                .map_err(|error| stat_failure(path, &error))?;
            if !same_regular_file_state(self.initial, opened)
                || !same_regular_file_state(self.initial, current)
            {
                return Err(ReaderFailure::new(
                    "integrity",
                    format!("Universal Mach-O source changed during inventory: {path}"),
                ));
            }
            Ok(())
        }

        /// `readStructuralSlices`: bounded header reads over the descriptor.
        pub(super) fn read_structural_slices(
            &self,
            size: u64,
        ) -> Result<StructuralSlices, ReaderFailure> {
            let file = self.file.as_ref().ok_or_else(|| {
                ReaderFailure::new("unavailable", "Universal Mach-O reader is closed")
            })?;
            let facts = rea_rust_analysis::macho::dylib::read_image_at(
                size,
                |offset: u64, length: usize| -> Result<Vec<u8>, std::io::Error> {
                    let mut buffer = vec![0u8; length];
                    let mut filled = 0usize;
                    while filled < length {
                        let read = file.read_at(&mut buffer[filled..], offset + filled as u64)?;
                        if read == 0 {
                            break;
                        }
                        filled += read;
                    }
                    buffer.truncate(filled);
                    Ok(buffer)
                },
            )
            .map_err(|error: std::io::Error| {
                ReaderFailure::new(
                    "integrity",
                    format!("Could not read Mach-O structural slice index: {error}"),
                )
            })?;
            Ok(StructuralSlices::from(facts))
        }

        /// Chunked positioned read of `[offset, offset + size)` with exact
        /// coverage accounting, matching the TS stream completion guards.
        pub(super) fn read_range(
            &self,
            offset: u64,
            size: u64,
            path: &str,
            cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            let file = self.file.as_ref().ok_or_else(|| {
                ReaderFailure::new("unavailable", "Universal Mach-O reader is closed")
            })?;
            let total = usize::try_from(size)
                .map_err(|_| ReaderFailure::new("integrity", "Invalid Mach-O slice byte range"))?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(total).map_err(|_| {
                ReaderFailure::new(
                    "integrity",
                    format!("Could not read Mach-O slice range: {path}"),
                )
            })?;
            bytes.resize(total, 0);
            let mut filled = 0usize;
            while filled < total {
                if cancellation.reason().is_some() {
                    return Err(ReaderFailure::new(
                        "cancelled",
                        "Mach-O slice read cancelled",
                    ));
                }
                let chunk = (total - filled).min(READ_CHUNK_BYTES);
                let read = file
                    .read_at(&mut bytes[filled..filled + chunk], offset + filled as u64)
                    .map_err(|error| {
                        ReaderFailure::new(
                            "integrity",
                            format!("Could not read Mach-O slice range: {path}: {error}"),
                        )
                    })?;
                if read == 0 {
                    // Short read: the slice range is not fully covered.
                    return Err(ReaderFailure::new(
                        "integrity",
                        format!("Mach-O slice read coverage is incomplete: {path}"),
                    ));
                }
                filled += read;
            }
            if filled as u64 != size {
                return Err(ReaderFailure::new(
                    "integrity",
                    format!("Mach-O slice size disagrees with lipo metadata: {path}"),
                ));
            }
            Ok(bytes)
        }

        /// Release the owned descriptor, retaining a cleanup observation on a
        /// close failure.
        pub(super) fn close(&mut self) -> Result<(), ReaderFailure> {
            let Some(file) = self.file.take() else {
                return Ok(());
            };
            // Dropping the `File` closes the fd; a sync error is the only
            // observable close-time failure and is surfaced as retained
            // cleanup for the owner to project. The kernel invalidates the fd
            // on close even on error, so the descriptor is not retried.
            match file.sync_all() {
                Ok(()) => Ok(()),
                Err(error) => Err(ReaderFailure {
                    reason: "unavailable",
                    message: format!("Universal Mach-O source descriptor cleanup failed: {error}"),
                    details: None,
                    cleanup: Some(CleanupObservation {
                        reason: error.to_string(),
                        resources: vec!["Universal Mach-O source descriptor".to_owned()],
                    }),
                }),
            }
        }
    }

    /// Re-stat the live descriptor through the host adapter.
    fn fingerprint_file(access: &UnixFiles, file: &File) -> Result<Fingerprint, FileError> {
        let owned = file
            .as_fd()
            .try_clone_to_owned()
            .map_err(|error| FileError {
                kind: IoKind::Other,
                system_code: None,
                source: error,
            })?;
        let fingerprint = access.stat(&owned)?;
        match access.close(owned) {
            CloseOutcome::Released
            | CloseOutcome::ReleasedWithError(_)
            | CloseOutcome::Retained { .. } => {}
        }
        Ok(fingerprint)
    }

    /// `sameRegularFileState`: identity-defining fields must be unchanged.
    fn same_regular_file_state(initial: Fingerprint, current: Fingerprint) -> bool {
        current.kind == Kind::Regular
            && initial.device == current.device
            && initial.file_id == current.file_id
            && initial.bytes == current.bytes
            && initial.modified_ns == current.modified_ns
            && initial.changed_ns == current.changed_ns
    }

    fn admission_failure(path: &str, error: &FileError) -> ReaderFailure {
        let reason = match error.kind {
            IoKind::NotFound
            | IoKind::NotDirectory
            | IoKind::SymlinkLoop
            | IoKind::NameTooLong
            | IoKind::AccessDenied => "path",
            IoKind::Interrupted | IoKind::Other => "io",
        };
        ReaderFailure::new(
            reason,
            format!("Could not open universal Mach-O source {path}: {error}"),
        )
    }

    fn stat_failure(path: &str, error: &FileError) -> ReaderFailure {
        ReaderFailure::new(
            "io",
            format!("Could not stat universal Mach-O source {path}: {error}"),
        )
    }
}

/// Non-Unix hosts cannot perform POSIX no-follow admission or positioned
/// reads. The TypeScript reader factory yields no Mach-O slice reader off
/// darwin; this stub preserves that `unavailable` outcome while keeping the
/// crate cross-platform compilable.
#[cfg(not(unix))]
mod source {
    use super::structural::StructuralSlices;
    use crate::artifact_reader::ReaderFailure;
    use rea_core::cancellation::Cancellation;

    pub(super) struct StableFileSource;

    impl StableFileSource {
        pub(super) fn open(_path: &str) -> Result<Self, ReaderFailure> {
            Err(unavailable())
        }

        pub(super) fn size(&self) -> u64 {
            0
        }

        pub(super) fn verify(&self, _path: &str) -> Result<(), ReaderFailure> {
            Err(unavailable())
        }

        pub(super) fn read_structural_slices(
            &self,
            _size: u64,
        ) -> Result<StructuralSlices, ReaderFailure> {
            Err(unavailable())
        }

        pub(super) fn read_range(
            &self,
            _offset: u64,
            _size: u64,
            _path: &str,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, ReaderFailure> {
            Err(unavailable())
        }

        pub(super) fn close(&mut self) -> Result<(), ReaderFailure> {
            Ok(())
        }
    }

    fn unavailable() -> ReaderFailure {
        ReaderFailure::new(
            "unavailable",
            "Universal Mach-O traversal is available only on macOS",
        )
    }
}
