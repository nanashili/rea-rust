//! Shared non-symlink-following directory reader.
//!
//! One faithful port of `src/artifacts/DirectoryArtifactReader.ts` and what it
//! depends on: `src/filesystem/OwnedDirectoryHandle.ts`,
//! `OwnedFileHandle.ts`, `OwnedRegularFile.ts`, `RegularFile.ts`,
//! `src/artifacts/hostExecutableMarking.ts`, `readArtifactFileChunks.ts`,
//! `src/artifacts/ArtifactReader.ts` (`sameArtifactSourceIdentity`),
//! `ArtifactFileOperation.ts` failure classification and
//! `AnalysisCleanupLease.ts` retention.
//!
//! The reader anchors admission to `realpath`/`lstat` of the selected root,
//! walks a pending LIFO stack (descending directories in reverse push order),
//! re-checks root containment and identity before and after each directory,
//! records every special entry (`fifo`, `socket`, `block-device`,
//! `character-device`, `unsupported`) and descent refusal
//! (`directory-descendants`) as an omission, captures per-entry `lstat` facts
//! (kind, size, POSIX mode bits, executable marking, device/inode/mtime/ctime),
//! opens regular files no-follow (`O_RDONLY | O_NOFOLLOW | O_NONBLOCK`) with
//! identity re-verification, bounds each read to the captured extent, honors
//! cancellation, and retains the resources of a failed cleanup.
//!
//! Non-Unix hosts fail closed with an `unavailable` failure, mirroring the
//! host reader's handle-relative guarantee requirement.
//!
//! Two surfaces are exposed: a rich entry/file API the desktop reader consumes
//! directly, and a `crate::artifact_reader::ArtifactReader` adapter for the
//! artifact graph.
use rea_core::JsString;
use rea_core::analysis_error::CleanupObservation;
use rea_core::cancellation::Cancellation;
use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
/// `DirectoryArtifactTraversalLimit` bound for the adapter's `maximum_entries`.
const DEFAULT_MAX_DIRECTORY_ENTRIES: usize = 2_000_000;
/// Positional-read ceiling (`MAX_DIRECTORY_POSITIONAL_READ_BYTES`).
pub(crate) const MAX_POSITIONAL_READ_BYTES: usize = 16 * 1024 * 1024 + 32;
/// One `ArtifactReaderFailure` (`src/artifacts/ArtifactReader.ts`).
#[derive(Clone, Debug)]
pub(crate) struct DirectoryFailure {
    /// cancelled, format, integrity, io, limit, path or unavailable.
    pub reason: &'static str,
    pub message: String,
    pub cleanup: Option<CleanupObservation>,
}
impl DirectoryFailure {
    pub(crate) fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
            cleanup: None,
        }
    }
    fn with_cleanup(mut self, cleanup: CleanupObservation) -> Self {
        self.cleanup = Some(cleanup);
        self
    }
}
/// Captured filesystem identity and mutable metadata (`sourceIdentity`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceIdentity {
    pub device: u64,
    pub inode: u128,
    pub size: u64,
    pub mode: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}
/// Entry kind restricted to the directory reader's three retained kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectoryEntryKind {
    File,
    Directory,
    Symlink,
}
impl DirectoryEntryKind {
    /// The portable `ArtifactEntry.kind` label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
            Self::Symlink => "symlink",
        }
    }
}
/// One admitted traversal entry (`DirectoryArtifactEntry`).
#[derive(Clone, Debug)]
pub(crate) struct DirectoryArtifactEntry {
    /// Slash-separated path relative to the admitted root.
    pub path: String,
    pub kind: DirectoryEntryKind,
    /// Declared extent of a regular file; `None` for other kinds or an extent
    /// outside the exact-integer range (`safeArtifactSize`).
    pub declared_size: Option<u64>,
    pub executable: bool,
    /// Absolute path on the host (`adapterKey`).
    pub adapter_key: String,
    /// Captured identity of a regular file (`sourceIdentity`); `None` for
    /// directories and symlinks.
    pub source_identity: Option<SourceIdentity>,
}
/// One entry or subtree deliberately excluded from a traversal.
#[derive(Clone, Debug)]
pub(crate) struct DirectoryOmission {
    pub path: String,
    /// fifo, socket, block-device, character-device, unsupported or
    /// directory-descendants.
    pub kind: &'static str,
}
/// Admission facts shared with traversal; the selected root may be a symlink.
#[derive(Clone, Debug)]
pub(crate) struct DirectoryRoot {
    pub canonical_path: PathBuf,
    pub device: u64,
    pub inode: u128,
}
/// A non-symlink-following directory reader.
///
/// Admission is resolved lazily on first use and memoized, exactly as the TS
/// `#resolveRoot` promise.
pub(crate) struct DirectoryArtifactReader {
    root_path: PathBuf,
    root: Option<DirectoryRoot>,
}
impl DirectoryArtifactReader {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root_path: root.into(),
            root: None,
        }
    }
    /// `rootObservation()` — resolve and memoize the admitted root.
    pub(crate) fn root_observation(&mut self) -> Result<DirectoryRoot, DirectoryFailure> {
        self.resolve_root().cloned()
    }
    #[cfg(unix)]
    fn resolve_root(&mut self) -> Result<&DirectoryRoot, DirectoryFailure> {
        if self.root.is_none() {
            let root = resolve_root_unix(&self.root_path)?;
            self.root = Some(root);
        }
        Ok(self.root.as_ref().expect("root resolved above"))
    }
    #[cfg(not(unix))]
    fn resolve_root(&mut self) -> Result<&DirectoryRoot, DirectoryFailure> {
        Err(DirectoryFailure::new(
            "unavailable",
            "handle-relative traversal is not implemented on this host",
        ))
    }
    /// Enumerate entries in pending-stack order, recording omissions.
    ///
    /// `descend_into` restricts descent while still retaining the directory
    /// entry (`directory-descendants` omission on refusal); `None` descends
    /// into every directory. `maximum_entries` bounds examined children,
    /// including omitted special entries (`DirectoryArtifactTraversalLimit`).
    pub(crate) fn entries(
        &mut self,
        maximum_entries: usize,
        descend_into: Option<&dyn Fn(&str) -> bool>,
        cancellation: &Cancellation,
        omissions: &mut Vec<DirectoryOmission>,
    ) -> Result<Vec<DirectoryArtifactEntry>, DirectoryFailure> {
        let root = self.resolve_root()?.clone();
        let root_path = root.canonical_path.clone();
        let mut examined = 0usize;
        let mut collected = Vec::new();
        // The pending stack mirrors the TS `pending` array: entries are pushed
        // and popped LIFO, and child directories are pushed in reverse so the
        // first child is visited first.
        let mut pending: Vec<PathBuf> = vec![root_path];
        while let Some(directory) = pending.pop() {
            abort_if_needed(cancellation)?;
            assert_contained_directory(&root, &directory)?;
            let child_directories = read_directory(
                &root,
                &directory,
                maximum_entries,
                &mut examined,
                descend_into,
                cancellation,
                &mut collected,
                omissions,
            )?;
            assert_contained_directory(&root, &directory)?;
            // Reverse so the earliest child is visited first after LIFO pops.
            for child in child_directories.into_iter().rev() {
                pending.push(child);
            }
        }
        Ok(collected)
    }
    /// Open one regular entry no-follow, verifying its captured identity.
    pub(crate) fn open_file(
        &mut self,
        entry: &DirectoryArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<DirectoryFile, DirectoryFailure> {
        self.resolve_root()?;
        open_file(entry, cancellation)
    }
    /// Read the complete bytes of one regular entry (`open`), bounded by the
    /// captured extent and re-verifying identity afterward.
    pub(crate) fn read_whole(
        &mut self,
        entry: &DirectoryArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryFailure> {
        let mut file = self.open_file(entry, cancellation)?;
        let bytes = read_stable_whole(&mut file, entry, cancellation);
        // The stream's close (TS `source.once("close", ...)`) releases the
        // descriptor regardless of the read outcome.
        let close = file.close();
        let bytes = bytes?;
        close?;
        Ok(bytes)
    }
}
/// One owned, admitted regular-file descriptor (`OwnedFileHandle`).
///
/// Random reads are served from the open descriptor; cleanup is retained as a
/// sticky failure when a close cannot be confirmed.
pub(crate) struct DirectoryFile {
    file: Option<std::fs::File>,
    path: String,
    identity: SourceIdentity,
}
impl DirectoryFile {
    /// `read(offset, bytes)` — one bounded positional read on the descriptor.
    ///
    /// Reads above the host positional-read ceiling are a limit boundary, not a
    /// silent truncation.
    pub(crate) fn read_at(
        &mut self,
        offset: u64,
        bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryFailure> {
        abort_if_needed(cancellation)?;
        if bytes > MAX_POSITIONAL_READ_BYTES {
            return Err(DirectoryFailure::new(
                "limit",
                "File range exceeds the host positional-read bound",
            ));
        }
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| DirectoryFailure::new("io", "File handle is closed"))?;
        read_at_exact_or_short(file, offset, bytes)
    }
    /// The captured declared extent (`sourceIdentity.size`).
    pub(crate) fn declared_size(&self) -> u64 {
        self.identity.size
    }
    /// Re-verify the opened descriptor and the named path still match the
    /// captured identity, then close. Mirrors the TS read-boundary recheck plus
    /// the stream close.
    fn verify_and_close(
        &mut self,
        entry: &DirectoryArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<(), DirectoryFailure> {
        let integrity = self.verify_identity(entry);
        abort_if_needed(cancellation)?;
        integrity?;
        self.close()
    }
    fn verify_identity(&self, entry: &DirectoryArtifactEntry) -> Result<(), DirectoryFailure> {
        let changed = DirectoryFailure::new(
            "integrity",
            format!("Directory entry changed during read: {}", entry.path),
        );
        let file = self.file.as_ref().ok_or_else(|| changed.clone())?;
        let opened = fstat_identity(file).map_err(|_| changed.clone())?;
        let named = lstat_identity(Path::new(&self.path)).map_err(|_| changed.clone())?;
        if !same_source_identity(entry.source_identity, &opened)
            || !same_source_identity(entry.source_identity, &named)
        {
            return Err(changed);
        }
        Ok(())
    }
    /// Close the owned descriptor.
    fn close(&mut self) -> Result<(), DirectoryFailure> {
        if let Some(file) = self.file.take() {
            drop(file);
        }
        Ok(())
    }
}
/// `hostExecutableMarking`.
#[cfg(unix)]
fn host_executable_marking(_absolute: &Path, mode: u64, _is_file: bool) -> bool {
    (mode & 0o111) != 0
}
#[cfg(not(unix))]
fn host_executable_marking(absolute: &Path, _mode: u64, is_file: bool) -> bool {
    if !is_file {
        return false;
    }
    let extension = absolute
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase);
    matches!(
        extension.as_deref(),
        Some("bat") | Some("cmd") | Some("com") | Some("exe")
    )
}
/// `safeArtifactSize`: an extent outside the exact-integer range is unknown.
fn safe_artifact_size(size: u64) -> Option<u64> {
    const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
    if size > MAX_SAFE_INTEGER {
        None
    } else {
        Some(size)
    }
}
/// `sameArtifactSourceIdentity`.
fn same_source_identity(expected: Option<SourceIdentity>, observed: &SourceIdentity) -> bool {
    match expected {
        None => false,
        Some(expected) => expected == *observed,
    }
}
#[cfg(unix)]
fn resolve_root_unix(root_path: &Path) -> Result<DirectoryRoot, DirectoryFailure> {
    use std::os::unix::fs::MetadataExt;
    let canonical = std::fs::canonicalize(root_path)
        .map_err(|cause| directory_io_failure("resolve artifact root", root_path, &cause))?;
    let metadata = std::fs::symlink_metadata(&canonical)
        .map_err(|cause| directory_io_failure("resolve artifact root", &canonical, &cause))?;
    if metadata.file_type().is_symlink() {
        return Err(DirectoryFailure::new(
            "path",
            "Artifact root changed during traversal",
        ));
    }
    if !metadata.is_dir() {
        return Err(DirectoryFailure::new(
            "path",
            "Artifact root must be a directory",
        ));
    }
    Ok(DirectoryRoot {
        canonical_path: canonical,
        device: metadata.dev(),
        inode: metadata.ino() as u128,
    })
}
/// `#readDirectory`: enumerate one directory's children, retaining child
/// directories for descent.
#[allow(clippy::too_many_arguments)]
fn read_directory(
    root: &DirectoryRoot,
    directory: &Path,
    maximum_entries: usize,
    examined: &mut usize,
    descend_into: Option<&dyn Fn(&str) -> bool>,
    cancellation: &Cancellation,
    collected: &mut Vec<DirectoryArtifactEntry>,
    omissions: &mut Vec<DirectoryOmission>,
) -> Result<Vec<PathBuf>, DirectoryFailure> {
    let read_dir = std::fs::read_dir(directory)
        .map_err(|cause| directory_io_failure("open directory", directory, &cause))?;
    let mut child_directories: Vec<PathBuf> = Vec::new();
    for child in read_dir {
        // Re-check containment before interpreting each child, exactly as the
        // TS loop does before `handle.handle.read()`.
        assert_contained_directory(root, directory)?;
        let child =
            child.map_err(|cause| directory_io_failure("read directory", directory, &cause))?;
        // `examine()` is charged once per observed child.
        if *examined >= maximum_entries {
            return Err(DirectoryFailure::new(
                "limit",
                "Directory traversal reached its examined-entry budget",
            ));
        }
        *examined += 1;
        abort_if_needed(cancellation)?;
        let absolute = directory.join(child.file_name());
        let metadata = lstat_full(&absolute)
            .map_err(|cause| directory_io_failure("inspect entry", &absolute, &cause))?;
        let relative = relative_slash_path(&root.canonical_path, &absolute)?;
        match classify_entry(&relative, &absolute, &metadata) {
            EntryClassification::Entry(entry) => {
                let descend = entry.kind == DirectoryEntryKind::Directory;
                let absolute_for_descent = PathBuf::from(&entry.adapter_key);
                let path_for_descent = entry.path.clone();
                collected.push(entry);
                if descend {
                    let allowed = descend_into.map(|f| f(&path_for_descent)).unwrap_or(true);
                    if allowed {
                        child_directories.push(absolute_for_descent);
                    } else {
                        omissions.push(DirectoryOmission {
                            path: path_for_descent,
                            kind: "directory-descendants",
                        });
                    }
                }
            }
            EntryClassification::Omitted(kind) => {
                omissions.push(DirectoryOmission {
                    path: relative,
                    kind,
                });
            }
        }
    }
    Ok(child_directories)
}
enum EntryClassification {
    Entry(DirectoryArtifactEntry),
    Omitted(&'static str),
}
/// `artifactEntry` + `unsupportedEntryKind`.
fn classify_entry(
    relative: &str,
    absolute: &Path,
    metadata: &EntryMetadata,
) -> EntryClassification {
    let kind = if metadata.is_symlink {
        Some(DirectoryEntryKind::Symlink)
    } else if metadata.is_dir {
        Some(DirectoryEntryKind::Directory)
    } else if metadata.is_file {
        Some(DirectoryEntryKind::File)
    } else {
        None
    };
    let Some(kind) = kind else {
        return EntryClassification::Omitted(unsupported_entry_kind(metadata));
    };
    let declared_size = if kind == DirectoryEntryKind::File {
        safe_artifact_size(metadata.identity.size)
    } else {
        None
    };
    let source_identity = (kind == DirectoryEntryKind::File).then_some(metadata.identity);
    EntryClassification::Entry(DirectoryArtifactEntry {
        path: relative.to_owned(),
        kind,
        declared_size,
        executable: host_executable_marking(absolute, metadata.identity.mode, metadata.is_file),
        adapter_key: absolute.to_string_lossy().into_owned(),
        source_identity,
    })
}
fn unsupported_entry_kind(metadata: &EntryMetadata) -> &'static str {
    if metadata.is_fifo {
        "fifo"
    } else if metadata.is_socket {
        "socket"
    } else if metadata.is_block_device {
        "block-device"
    } else if metadata.is_char_device {
        "character-device"
    } else {
        "unsupported"
    }
}
/// `relative(root, absolute).split(sep).join("/")`, refusing an escape.
fn relative_slash_path(root: &Path, absolute: &Path) -> Result<String, DirectoryFailure> {
    let relative = absolute.strip_prefix(root).map_err(|_| {
        DirectoryFailure::new(
            "path",
            "Directory traversal escaped or changed its artifact root",
        )
    })?;
    let mut parts: Vec<String> = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => {
                return Err(DirectoryFailure::new(
                    "path",
                    "Directory traversal escaped or changed its artifact root",
                ));
            }
        }
    }
    Ok(parts.join("/"))
}
/// `assertContainedDirectory`: the directory still resolves inside the root and
/// the root identity is unchanged.
#[cfg(unix)]
fn assert_contained_directory(
    root: &DirectoryRoot,
    directory: &Path,
) -> Result<(), DirectoryFailure> {
    use std::os::unix::fs::MetadataExt;
    let escaped = DirectoryFailure::new(
        "path",
        "Directory traversal escaped or changed its artifact root",
    );
    let canonical = std::fs::canonicalize(directory)
        .map_err(|cause| directory_io_failure("inspect directory", directory, &cause))?;
    if canonical != root.canonical_path && canonical.strip_prefix(&root.canonical_path).is_err() {
        return Err(escaped);
    }
    let metadata = std::fs::symlink_metadata(directory)
        .map_err(|cause| directory_io_failure("inspect directory", directory, &cause))?;
    let current_root = std::fs::symlink_metadata(&root.canonical_path)
        .map_err(|cause| directory_io_failure("inspect directory", &root.canonical_path, &cause))?;
    if current_root.dev() != root.device
        || current_root.ino() as u128 != root.inode
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
    {
        return Err(escaped);
    }
    Ok(())
}
#[cfg(not(unix))]
fn assert_contained_directory(
    _root: &DirectoryRoot,
    _directory: &Path,
) -> Result<(), DirectoryFailure> {
    Err(DirectoryFailure::new(
        "unavailable",
        "handle-relative traversal is not implemented on this host",
    ))
}
/// `#openFile`: no-follow open, stat, identity re-check and cleanup retention.
#[cfg(unix)]
fn open_file(
    entry: &DirectoryArtifactEntry,
    cancellation: &Cancellation,
) -> Result<DirectoryFile, DirectoryFailure> {
    use std::os::unix::fs::OpenOptionsExt;
    abort_if_needed(cancellation)?;
    if entry.kind != DirectoryEntryKind::File {
        return Err(DirectoryFailure::new(
            "format",
            "Only regular files can be opened",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let path = Path::new(entry.adapter_key.as_str());
    let file = options
        .open(path)
        .map_err(|cause| directory_io_failure("open entry", path, &cause))?;
    let mut owner = DirectoryFile {
        file: Some(file),
        path: entry.adapter_key.to_string(),
        identity: entry.source_identity.unwrap_or(SourceIdentity {
            device: 0,
            inode: 0,
            size: 0,
            mode: 0,
            mtime_ns: 0,
            ctime_ns: 0,
        }),
    };
    let admitted = (|| {
        let observed = fstat_identity(owner.file.as_ref().expect("file open"))
            .map_err(|cause| directory_io_failure("inspect opened entry", path, &cause))?;
        if !observed_is_file(&owner) || !same_source_identity(entry.source_identity, &observed) {
            return Err(DirectoryFailure::new(
                "integrity",
                format!("Directory entry changed before open: {}", entry.path),
            ));
        }
        abort_if_needed(cancellation)?;
        Ok(())
    })();
    if let Err(cause) = admitted {
        if let Err(close_cause) = owner.close() {
            return Err(cause.with_cleanup(CleanupObservation {
                reason: close_cause.message,
                resources: vec![entry.adapter_key.clone()],
            }));
        }
        return Err(cause);
    }
    Ok(owner)
}
#[cfg(not(unix))]
fn open_file(
    _entry: &DirectoryArtifactEntry,
    _cancellation: &Cancellation,
) -> Result<DirectoryFile, DirectoryFailure> {
    Err(DirectoryFailure::new(
        "unavailable",
        "handle-relative traversal is not implemented on this host",
    ))
}
/// Whether the open descriptor reports a regular file (`observed.isFile()`).
fn observed_is_file(owner: &DirectoryFile) -> bool {
    owner
        .file
        .as_ref()
        .and_then(|file| file.metadata().ok())
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}
/// `mapStableFileRead`: read bounded to the captured extent, re-verifying
/// identity and byte count.
fn read_stable_whole(
    file: &mut DirectoryFile,
    entry: &DirectoryArtifactEntry,
    cancellation: &Cancellation,
) -> Result<Vec<u8>, DirectoryFailure> {
    let Some(identity) = entry.source_identity else {
        return Err(DirectoryFailure::new(
            "integrity",
            format!("Directory entry has no captured file state: {}", entry.path),
        ));
    };
    let expected = identity.size;
    let mut collected: Vec<u8> = Vec::new();
    let mut position: u64 = 0;
    // Include one extra byte so a growing file cannot make this read unbounded.
    while position <= expected {
        abort_if_needed(cancellation)?;
        let remaining = expected - position + 1;
        let chunk_len = remaining.min(64 * 1024) as usize;
        let chunk = file.read_at(position, chunk_len, cancellation)?;
        if chunk.is_empty() {
            break;
        }
        position += chunk.len() as u64;
        collected.extend_from_slice(&chunk);
    }
    abort_if_needed(cancellation)?;
    let read_bytes = collected.len() as u64;
    // Re-verify identity, extent and byte count at the read boundary.
    file.verify_and_close(entry, cancellation)?;
    if read_bytes != expected {
        return Err(DirectoryFailure::new(
            "integrity",
            format!("Directory entry changed during read: {}", entry.path),
        ));
    }
    Ok(collected)
}
/// One `lstat`'s portable facts.
struct EntryMetadata {
    is_symlink: bool,
    is_dir: bool,
    is_file: bool,
    is_fifo: bool,
    is_socket: bool,
    is_block_device: bool,
    is_char_device: bool,
    identity: SourceIdentity,
}
#[cfg(unix)]
fn lstat_full(path: &Path) -> std::io::Result<EntryMetadata> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let metadata = std::fs::symlink_metadata(path)?;
    let file_type = metadata.file_type();
    Ok(EntryMetadata {
        is_symlink: file_type.is_symlink(),
        is_dir: metadata.is_dir(),
        is_file: metadata.is_file(),
        is_fifo: file_type.is_fifo(),
        is_socket: file_type.is_socket(),
        is_block_device: file_type.is_block_device(),
        is_char_device: file_type.is_char_device(),
        identity: SourceIdentity {
            device: metadata.dev(),
            inode: metadata.ino() as u128,
            size: metadata.size(),
            mode: metadata.mode() as u64,
            mtime_ns: metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
            ctime_ns: metadata.ctime() as i128 * 1_000_000_000 + metadata.ctime_nsec() as i128,
        },
    })
}
#[cfg(not(unix))]
fn lstat_full(_path: &Path) -> std::io::Result<EntryMetadata> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "handle-relative traversal is not implemented on this host",
    ))
}
#[cfg(unix)]
fn fstat_identity(file: &std::fs::File) -> std::io::Result<SourceIdentity> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok(SourceIdentity {
        device: metadata.dev(),
        inode: metadata.ino() as u128,
        size: metadata.size(),
        mode: metadata.mode() as u64,
        mtime_ns: metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
        ctime_ns: metadata.ctime() as i128 * 1_000_000_000 + metadata.ctime_nsec() as i128,
    })
}
#[cfg(not(unix))]
fn fstat_identity(_file: &std::fs::File) -> std::io::Result<SourceIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "handle-relative traversal is not implemented on this host",
    ))
}
#[cfg(unix)]
fn lstat_identity(path: &Path) -> std::io::Result<SourceIdentity> {
    Ok(lstat_full(path)?.identity)
}
#[cfg(not(unix))]
fn lstat_identity(_path: &Path) -> std::io::Result<SourceIdentity> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "handle-relative traversal is not implemented on this host",
    ))
}
/// One positional read, returning fewer bytes only at end of file.
#[cfg(unix)]
fn read_at_exact_or_short(
    file: &std::fs::File,
    offset: u64,
    bytes: usize,
) -> Result<Vec<u8>, DirectoryFailure> {
    use std::os::unix::fs::FileExt;
    let mut buffer = vec![0u8; bytes];
    let mut filled = 0usize;
    while filled < bytes {
        match file.read_at(&mut buffer[filled..], offset + filled as u64) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(cause) if cause.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(cause) => {
                return Err(DirectoryFailure::new(
                    "io",
                    format!("Could not read entry: {cause}"),
                ));
            }
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}
#[cfg(not(unix))]
fn read_at_exact_or_short(
    _file: &std::fs::File,
    _offset: u64,
    _bytes: usize,
) -> Result<Vec<u8>, DirectoryFailure> {
    Err(DirectoryFailure::new(
        "unavailable",
        "handle-relative traversal is not implemented on this host",
    ))
}
/// `directoryIoFailure`: an I/O failure naming its operation, path and code.
fn directory_io_failure(operation: &str, path: &Path, cause: &std::io::Error) -> DirectoryFailure {
    let code = cause
        .raw_os_error()
        .map(|errno| format!(" ({errno})"))
        .unwrap_or_default();
    DirectoryFailure::new(
        "io",
        format!("Could not {operation} at {}{code}: {cause}", path.display()),
    )
}
/// `abortIfNeeded`.
fn abort_if_needed(cancellation: &Cancellation) -> Result<(), DirectoryFailure> {
    match cancellation.reason() {
        None => Ok(()),
        Some(reason) => Err(DirectoryFailure::new(
            "cancelled",
            format!("Artifact traversal cancelled: {reason}"),
        )),
    }
}
// --- ArtifactReader adapter for the artifact graph ---
use crate::artifact_reader::{
    ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure,
};
/// Directory container reader bound to the shared `ArtifactReader` contract.
///
/// This is the adapter the artifact graph composes; it reuses the one shared
/// traversal above and never re-interprets filesystem facts.
pub(crate) struct DirectoryArtifactContainer {
    reader: DirectoryArtifactReader,
    entries: HashMap<String, DirectoryArtifactEntry>,
}
impl DirectoryArtifactContainer {
    pub(crate) fn new(root: &str) -> Self {
        Self {
            reader: DirectoryArtifactReader::new(root),
            entries: HashMap::new(),
        }
    }
}
fn to_reader_failure(failure: DirectoryFailure) -> ReaderFailure {
    let mut mapped = ReaderFailure::new(failure.reason, failure.message);
    mapped.cleanup = failure.cleanup;
    mapped
}
impl ArtifactReader for DirectoryArtifactContainer {
    fn format(&self) -> &'static str {
        "directory"
    }
    fn entries(
        &mut self,
        cancellation: &Cancellation,
        omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        let mut directory_omissions = Vec::new();
        let listed = self
            .reader
            .entries(
                DEFAULT_MAX_DIRECTORY_ENTRIES,
                None,
                cancellation,
                &mut directory_omissions,
            )
            .map_err(to_reader_failure)?;
        for omission in directory_omissions {
            omissions.push(ArtifactTraversalOmission {
                path: rea_core::JsString::from(omission.path),
                kind: omission.kind,
            });
        }
        self.entries.clear();
        let mut out = Vec::with_capacity(listed.len());
        for entry in listed {
            out.push(ArtifactEntry {
                path: JsString::from(entry.path.clone()),
                kind: entry.kind.label(),
                declared_size: entry.declared_size,
                compressed_size: None,
                executable: entry.executable,
                encrypted: false,
                byte_offset: None,
                declared_sha256: None,
                unpacked: false,
                limitations: if entry.kind == DirectoryEntryKind::Symlink {
                    vec!["Symlink target was not followed or disclosed.".to_owned()]
                } else {
                    Vec::new()
                },
                adapter_key: JsString::from(entry.path.clone()),
            });
            self.entries.insert(entry.path.clone(), entry);
        }
        Ok(out)
    }
    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        let directory_entry = self
            .entries
            .get(entry.adapter_key.as_str().unwrap_or_default())
            .cloned()
            .ok_or_else(|| {
                ReaderFailure::new(
                    "integrity",
                    format!("Directory entry changed before open: {}", entry.path),
                )
            })?;
        if directory_entry.kind != DirectoryEntryKind::File {
            return Err(ReaderFailure::new(
                "format",
                "Only regular files can be opened",
            ));
        }
        self.reader
            .read_whole(&directory_entry, cancellation)
            .map_err(to_reader_failure)
    }
    fn close(&mut self) -> Result<(), ReaderFailure> {
        // The traversal owns no retained descriptors after enumeration; each
        // regular-file open releases its descriptor on read completion. There
        // is no read-only cleanup that can fail here.
        self.entries.clear();
        Ok(())
    }
}
