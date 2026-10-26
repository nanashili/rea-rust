//! Bounded, read-only access to a directory tree.
//!
//! On Unix, the reader anchors traversal to an open root directory and uses
//! descriptor-relative operations for every child. A path is never trusted
//! after a separate symlink check. Other hosts fail closed until they can
//! provide the same handle-relative guarantees.

use crate::fs::stable_file::{Fingerprint, Kind};
use rea_core::cancellation::Cancellation;
use std::{
    fmt, fs,
    io::{self, Read},
    path::{Component, Path, PathBuf},
};

const MAX_DIRECTORY_PREFIX_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_POSITIONAL_READ_BYTES: usize = 16 * 1024 * 1024 + 32;
const HASH_CHUNK_BYTES: usize = 64 * 1024;

#[cfg(unix)]
use std::{
    ffi::{CStr, CString, OsString},
    os::{
        fd::AsRawFd,
        unix::ffi::{OsStrExt, OsStringExt},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryEntryKind {
    Regular,
    Directory,
    Symlink,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryEntryPolicy {
    pub retain: bool,
    pub descend: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryEntry {
    /// Slash-separated path relative to the admitted root.
    pub path: String,
    pub kind: DirectoryEntryKind,
    pub identity: Fingerprint,
    /// Raw host `st_mode` (type and permission bits) observed with `identity`.
    pub mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirectoryRoot {
    pub canonical_path: PathBuf,
    pub identity: Fingerprint,
}

#[derive(Debug)]
pub enum DirectoryError {
    InvalidRoot,
    InvalidRelativePath,
    Cancelled(String),
    Limit {
        maximum_entries: usize,
    },
    LimitBytes {
        maximum_bytes: usize,
    },
    Unsupported(&'static str),
    Cleanup {
        primary: Option<Box<DirectoryError>>,
        stage: &'static str,
        source: io::Error,
    },
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Changed(&'static str),
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRoot => write!(f, "directory root is not an owned directory"),
            Self::InvalidRelativePath => write!(f, "path is not a safe relative path"),
            Self::Cancelled(reason) => write!(f, "directory operation cancelled: {reason}"),
            Self::Limit { maximum_entries } => {
                write!(f, "directory entry limit exceeded: {maximum_entries}")
            }
            Self::LimitBytes { maximum_bytes } => {
                write!(f, "directory file byte limit exceeded: {maximum_bytes}")
            }
            Self::Unsupported(reason) => write!(f, "directory access unavailable: {reason}"),
            Self::Cleanup {
                primary: Some(primary),
                stage,
                source,
            } => write!(f, "{primary}; directory {stage}: {source}"),
            Self::Cleanup {
                primary: None,
                stage,
                source,
            } => write!(f, "directory {stage}: {source}"),
            Self::Io { stage, source } => write!(f, "directory {stage}: {source}"),
            Self::Changed(stage) => write!(f, "directory changed during {stage}"),
        }
    }
}

impl std::error::Error for DirectoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Cleanup {
                primary: Some(primary),
                ..
            } => Some(primary.as_ref()),
            Self::Cleanup {
                primary: None,
                source,
                ..
            } => Some(source),
            _ => None,
        }
    }
}

pub struct DirectoryReader {
    root: DirectoryRoot,
    #[cfg(unix)]
    root_handle: fs::File,
}

impl DirectoryReader {
    #[cfg(unix)]
    pub fn open(path: &Path) -> Result<Self, DirectoryError> {
        let input_metadata =
            fs::symlink_metadata(path).map_err(|source| io_error("admitting root", source))?;
        if input_metadata.file_type().is_symlink() || !input_metadata.is_dir() {
            return Err(DirectoryError::InvalidRoot);
        }

        let canonical_path =
            fs::canonicalize(path).map_err(|source| io_error("canonicalizing root", source))?;
        let canonical_metadata = fs::symlink_metadata(&canonical_path)
            .map_err(|source| io_error("stating root", source))?;
        if canonical_metadata.file_type().is_symlink() || !canonical_metadata.is_dir() {
            return Err(DirectoryError::InvalidRoot);
        }

        let root_handle = open_directory_path(&canonical_path)
            .map_err(|source| io_error("opening root", source))?;
        let opened_metadata = root_handle
            .metadata()
            .map_err(|source| io_error("stating opened root", source))?;
        let identity = fingerprint(&opened_metadata, Kind::Directory);
        if !opened_metadata.is_dir()
            || identity != fingerprint(&canonical_metadata, Kind::Directory)
        {
            return Err(DirectoryError::Changed("admitting root"));
        }

        Ok(Self {
            root: DirectoryRoot {
                canonical_path,
                identity,
            },
            root_handle,
        })
    }

    #[cfg(not(unix))]
    pub fn open(_path: &Path) -> Result<Self, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    pub fn root(&self) -> &DirectoryRoot {
        &self.root
    }

    /// Inspect one root-relative child without following the final component.
    /// Missing path components are absent entries; other host failures retain
    /// their original error category.
    #[cfg(unix)]
    pub fn inspect_entry(
        &self,
        relative_path: &str,
        cancellation: &Cancellation,
    ) -> Result<Option<DirectoryEntry>, DirectoryError> {
        let relative = safe_relative_path(relative_path)?;
        check_cancelled(cancellation)?;
        self.verify_root_path("inspecting entry")?;

        let (parent_path, file_name) = split_parent_and_name(relative)?;
        let parent = match self.open_relative_directory(parent_path) {
            Ok(parent) => parent,
            Err(error) if is_missing_path_error(&error) => return Ok(None),
            Err(error) => return Err(error),
        };
        let metadata = match metadata_at(&parent, file_name) {
            Ok(metadata) => metadata,
            Err(error) if is_missing_io_error(&error) => return Ok(None),
            Err(source) => return Err(io_error("inspecting entry", source)),
        };
        let Some(kind) = entry_kind(&metadata) else {
            return Ok(None);
        };

        let entry = DirectoryEntry {
            path: relative_path.to_owned(),
            kind,
            identity: fingerprint_stat(&metadata, kind_fingerprint(kind)),
            mode: u32::from(metadata.st_mode),
        };
        check_cancelled(cancellation)?;
        self.verify_root_path("inspecting entry")?;

        Ok(Some(entry))
    }

    #[cfg(not(unix))]
    pub fn inspect_entry(
        &self,
        _relative_path: &str,
        _cancellation: &Cancellation,
    ) -> Result<Option<DirectoryEntry>, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    #[cfg(unix)]
    pub fn entries(
        &self,
        maximum_entries: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError> {
        self.entries_filtered(maximum_entries, cancellation, |_| true)
    }

    /// Enumerate entries while deciding whether each admitted directory's
    /// descendants should be visited. The directory itself is always retained
    /// in the result, so callers can record an exclusion without pretending
    /// that the directory was absent. The predicate runs after no-follow
    /// metadata and identity admission, before any child enumeration.
    #[cfg(unix)]
    pub fn entries_filtered<F>(
        &self,
        maximum_entries: usize,
        cancellation: &Cancellation,
        should_descend: F,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError>
    where
        F: Fn(&DirectoryEntry) -> bool,
    {
        self.entries_with_policy(maximum_entries, maximum_entries, cancellation, |entry| {
            DirectoryEntryPolicy {
                retain: true,
                descend: entry.kind == DirectoryEntryKind::Directory && should_descend(entry),
            }
        })
    }

    /// Enumerate with separate budgets for examined names and retained entries.
    /// This lets a caller inspect a large package while retaining only the
    /// format-specific candidates it can safely decode.
    #[cfg(unix)]
    pub fn entries_with_policy<F>(
        &self,
        maximum_retained_entries: usize,
        maximum_examined_entries: usize,
        cancellation: &Cancellation,
        policy: F,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError>
    where
        F: Fn(&DirectoryEntry) -> DirectoryEntryPolicy,
    {
        check_cancelled(cancellation)?;
        self.verify_root_path("enumerating")?;

        let mut pending = vec![(PathBuf::new(), self.root.identity)];
        let mut entries = Vec::new();
        let mut examined = 0usize;

        while let Some((directory_path, expected_identity)) = pending.pop() {
            check_cancelled(cancellation)?;
            let directory = self.open_relative_directory(&directory_path)?;
            verify_directory_identity(&directory, expected_identity, "opening directory")?;

            let mut children = read_children(&directory)?;
            children.sort();

            for name in children {
                check_cancelled(cancellation)?;
                examined = examined.saturating_add(1);
                if examined > maximum_examined_entries {
                    return Err(DirectoryError::Limit {
                        maximum_entries: maximum_examined_entries,
                    });
                }

                let child_path = directory_path.join(&name);
                let relative_path = path_as_utf8(&child_path)?;
                let metadata = metadata_at(&directory, &name)
                    .map_err(|source| io_error("examining entry", source))?;
                let Some(kind) = entry_kind(&metadata) else {
                    continue;
                };

                let identity = fingerprint_stat(&metadata, kind_fingerprint(kind));
                let entry = DirectoryEntry {
                    path: relative_path,
                    kind,
                    identity,
                    mode: u32::from(metadata.st_mode),
                };
                let decision = policy(&entry);
                // The predicate may perform policy work that observes
                // cancellation. Do not publish an admitted entry or continue
                // identity checks after that request has won.
                check_cancelled(cancellation)?;
                if decision.retain {
                    if entries.len() >= maximum_retained_entries {
                        return Err(DirectoryError::Limit {
                            maximum_entries: maximum_retained_entries,
                        });
                    }
                    entries.push(entry);
                }

                if decision.descend && kind == DirectoryEntryKind::Directory {
                    pending.push((child_path, identity));
                }
            }

            verify_directory_identity(&directory, expected_identity, "enumerating directory")?;
            self.verify_root_path("enumerating")?;
        }

        Ok(entries)
    }

    #[cfg(not(unix))]
    pub fn entries_with_policy<F>(
        &self,
        _maximum_retained_entries: usize,
        _maximum_examined_entries: usize,
        _cancellation: &Cancellation,
        _policy: F,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError>
    where
        F: Fn(&DirectoryEntry) -> DirectoryEntryPolicy,
    {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    #[cfg(not(unix))]
    pub fn entries(
        &self,
        _maximum_entries: usize,
        _cancellation: &Cancellation,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    #[cfg(not(unix))]
    pub fn entries_filtered<F>(
        &self,
        _maximum_entries: usize,
        _cancellation: &Cancellation,
        _should_descend: F,
    ) -> Result<Vec<DirectoryEntry>, DirectoryError>
    where
        F: Fn(&DirectoryEntry) -> bool,
    {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    #[cfg(unix)]
    pub fn open_entry(
        &self,
        entry: &DirectoryEntry,
        cancellation: &Cancellation,
    ) -> Result<DirectoryFile, DirectoryError> {
        if entry.kind != DirectoryEntryKind::Regular || entry.identity.kind != Kind::Regular {
            return Err(DirectoryError::InvalidRelativePath);
        }
        let relative = safe_relative_path(&entry.path)?;
        check_cancelled(cancellation)?;
        self.verify_root_path("opening file")?;

        let (parent_path, file_name) = split_parent_and_name(relative)?;
        let parent = self.open_relative_directory(parent_path)?;
        let file =
            open_file_at(&parent, file_name).map_err(|source| io_error("opening file", source))?;
        check_cancelled(cancellation)?;

        let metadata = file
            .metadata()
            .map_err(|source| io_error("stating opened file", source))?;
        let identity = fingerprint(&metadata, Kind::Regular);
        if !metadata.is_file() || identity != entry.identity {
            return Err(DirectoryError::Changed("opening file"));
        }

        Ok(DirectoryFile {
            path: entry.path.clone(),
            identity,
            file,
        })
    }

    /// Revalidate that the root-relative name still refers to the enumerated
    /// no-follow entry. This complements descriptor identity checks after a
    /// read, which alone cannot detect replacement of the name while open.
    #[cfg(unix)]
    pub fn revalidate_entry(
        &self,
        entry: &DirectoryEntry,
        cancellation: &Cancellation,
    ) -> Result<(), DirectoryError> {
        let relative = safe_relative_path(&entry.path)?;
        check_cancelled(cancellation)?;
        self.verify_root_path("revalidating entry")?;

        let (parent_path, file_name) = split_parent_and_name(relative)?;
        let parent = self.open_relative_directory(parent_path)?;
        let metadata = metadata_at(&parent, file_name)
            .map_err(|source| io_error("revalidating entry", source))?;
        let Some(kind) = entry_kind(&metadata) else {
            return Err(DirectoryError::Changed("revalidating entry"));
        };
        if kind != entry.kind
            || fingerprint_stat(&metadata, kind_fingerprint(kind)) != entry.identity
        {
            return Err(DirectoryError::Changed("revalidating entry"));
        }

        check_cancelled(cancellation)?;
        self.verify_root_path("revalidating entry")
    }

    #[cfg(not(unix))]
    pub fn revalidate_entry(
        &self,
        _entry: &DirectoryEntry,
        _cancellation: &Cancellation,
    ) -> Result<(), DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    /// Read a bounded prefix through a no-follow descriptor and then verify
    /// that its directory entry name still identifies the opened file.
    #[cfg(unix)]
    pub fn read_entry_prefix(
        &self,
        entry: &DirectoryEntry,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        let mut file = self.open_entry(entry, cancellation)?;
        let bytes = file.read_prefix(maximum_bytes, cancellation)?;
        self.revalidate_entry(entry, cancellation)?;
        Ok(bytes)
    }

    #[cfg(not(unix))]
    pub fn read_entry_prefix(
        &self,
        _entry: &DirectoryEntry,
        _maximum_bytes: usize,
        _cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    /// Read a bounded file through a no-follow descriptor and verify both the
    /// opened inode and the directory entry name before returning its bytes.
    #[cfg(unix)]
    pub fn read_entry_bounded(
        &self,
        entry: &DirectoryEntry,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        let mut file = self.open_entry(entry, cancellation)?;
        let bytes = file.read_bounded(maximum_bytes, cancellation)?;
        self.revalidate_entry(entry, cancellation)?;
        Ok(bytes)
    }

    #[cfg(not(unix))]
    pub fn read_entry_bounded(
        &self,
        _entry: &DirectoryEntry,
        _maximum_bytes: usize,
        _cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    /// Read a symlink target without following it, with bounded allocation and
    /// identity checks before and after the read.
    #[cfg(unix)]
    pub fn read_symlink_target(
        &self,
        entry: &DirectoryEntry,
        cancellation: &Cancellation,
    ) -> Result<String, DirectoryError> {
        const MAX_SYMLINK_TARGET_BYTES: usize = 64 * 1024;

        if entry.kind != DirectoryEntryKind::Symlink || entry.identity.kind != Kind::Symlink {
            return Err(DirectoryError::InvalidRelativePath);
        }
        let relative = safe_relative_path(&entry.path)?;
        check_cancelled(cancellation)?;
        self.verify_root_path("reading symlink")?;

        let (parent_path, file_name) = split_parent_and_name(relative)?;
        let parent = self.open_relative_directory(parent_path)?;
        let before = metadata_at(&parent, file_name)
            .map_err(|source| io_error("examining symlink", source))?;
        if entry_kind(&before) != Some(DirectoryEntryKind::Symlink)
            || fingerprint_stat(&before, Kind::Symlink) != entry.identity
        {
            return Err(DirectoryError::Changed("reading symlink"));
        }

        let target = readlink_at(&parent, file_name, MAX_SYMLINK_TARGET_BYTES)?;
        check_cancelled(cancellation)?;

        let after = metadata_at(&parent, file_name)
            .map_err(|source| io_error("verifying symlink", source))?;
        if entry_kind(&after) != Some(DirectoryEntryKind::Symlink)
            || fingerprint_stat(&after, Kind::Symlink) != entry.identity
        {
            return Err(DirectoryError::Changed("reading symlink"));
        }
        self.verify_root_path("reading symlink")?;

        String::from_utf8(target).map_err(|_| DirectoryError::InvalidRelativePath)
    }

    #[cfg(not(unix))]
    pub fn read_symlink_target(
        &self,
        _entry: &DirectoryEntry,
        _cancellation: &Cancellation,
    ) -> Result<String, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    #[cfg(not(unix))]
    pub fn open_entry(
        &self,
        _entry: &DirectoryEntry,
        _cancellation: &Cancellation,
    ) -> Result<DirectoryFile, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    #[cfg(unix)]
    fn open_relative_directory(&self, relative_path: &Path) -> Result<fs::File, DirectoryError> {
        let mut current = self
            .root_handle
            .try_clone()
            .map_err(|source| io_error("duplicating root handle", source))?;

        for component in relative_path.components() {
            let Component::Normal(name) = component else {
                return Err(DirectoryError::InvalidRelativePath);
            };
            current = open_directory_at(&current, name)
                .map_err(|source| io_error("opening directory component", source))?;
        }

        Ok(current)
    }

    fn verify_root_path(&self, stage: &'static str) -> Result<(), DirectoryError> {
        let metadata = fs::symlink_metadata(&self.root.canonical_path)
            .map_err(|source| io_error(stage, source))?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || fingerprint(&metadata, Kind::Directory) != self.root.identity
        {
            return Err(DirectoryError::Changed(stage));
        }
        Ok(())
    }
}

#[cfg(unix)]
fn verify_directory_identity(
    directory: &fs::File,
    expected: Fingerprint,
    stage: &'static str,
) -> Result<(), DirectoryError> {
    let metadata = directory
        .metadata()
        .map_err(|source| io_error(stage, source))?;
    if !metadata.is_dir() || fingerprint(&metadata, Kind::Directory) != expected {
        return Err(DirectoryError::Changed(stage));
    }
    Ok(())
}

pub struct DirectoryFile {
    pub path: String,
    pub identity: Fingerprint,
    file: fs::File,
}

impl DirectoryFile {
    /// Read a bounded file range without changing the descriptor's cursor.
    /// A short range means the requested bytes extend beyond the current file.
    #[cfg(unix)]
    pub fn read_at(
        &mut self,
        offset: u64,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        use std::os::unix::fs::FileExt;

        if maximum_bytes > MAX_DIRECTORY_POSITIONAL_READ_BYTES {
            return Err(DirectoryError::LimitBytes {
                maximum_bytes: MAX_DIRECTORY_POSITIONAL_READ_BYTES,
            });
        }
        check_cancelled(cancellation)?;

        let available = self.identity.bytes.saturating_sub(offset);
        let requested = usize::try_from(available)
            .unwrap_or(usize::MAX)
            .min(maximum_bytes);
        let mut bytes = vec![0; requested];
        let mut read_bytes = 0usize;

        while read_bytes < requested {
            check_cancelled(cancellation)?;
            let read = self
                .file
                .read_at(&mut bytes[read_bytes..], offset + read_bytes as u64)
                .map_err(|source| io_error("reading file range", source))?;
            if read == 0 {
                break;
            }
            read_bytes += read;
        }
        bytes.truncate(read_bytes);

        self.verify_identity("reading file range")?;
        Ok(bytes)
    }

    #[cfg(not(unix))]
    pub fn read_at(
        &mut self,
        _offset: u64,
        _maximum_bytes: usize,
        _cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    /// Hash the complete observed extent while retaining the admitted file
    /// descriptor and checking cancellation between bounded reads.
    #[cfg(unix)]
    pub fn sha256(&mut self, cancellation: &Cancellation) -> Result<String, DirectoryError> {
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::FileExt;

        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        let mut buffer = [0u8; HASH_CHUNK_BYTES];

        while offset < self.identity.bytes {
            check_cancelled(cancellation)?;
            let remaining = self.identity.bytes - offset;
            let requested = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(buffer.len());
            let read = self
                .file
                .read_at(&mut buffer[..requested], offset)
                .map_err(|source| io_error("hashing file", source))?;
            if read == 0 {
                return Err(DirectoryError::Changed("hashing file"));
            }

            hasher.update(&buffer[..read]);
            offset = offset.saturating_add(read as u64);
        }

        self.verify_identity("hashing file")?;
        Ok(format!("{:x}", hasher.finalize()))
    }

    #[cfg(not(unix))]
    pub fn sha256(&mut self, _cancellation: &Cancellation) -> Result<String, DirectoryError> {
        Err(DirectoryError::Unsupported(
            "handle-relative traversal is not implemented on this host",
        ))
    }

    fn verify_identity(&self, stage: &'static str) -> Result<(), DirectoryError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|source| io_error(stage, source))?;
        if fingerprint(&metadata, Kind::Regular) != self.identity {
            return Err(DirectoryError::Changed(stage));
        }
        Ok(())
    }

    pub fn read_prefix(
        &mut self,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        if maximum_bytes > MAX_DIRECTORY_PREFIX_BYTES {
            return Err(DirectoryError::LimitBytes {
                maximum_bytes: MAX_DIRECTORY_PREFIX_BYTES,
            });
        }
        check_cancelled(cancellation)?;
        let mut bytes = vec![0; maximum_bytes];
        let mut offset = 0;

        while offset < maximum_bytes {
            check_cancelled(cancellation)?;
            let read = self
                .file
                .read(&mut bytes[offset..])
                .map_err(|source| io_error("reading file prefix", source))?;
            if read == 0 {
                break;
            }
            offset += read;
        }
        bytes.truncate(offset);

        let after = self
            .file
            .metadata()
            .map_err(|source| io_error("verifying file prefix", source))?;
        if fingerprint(&after, Kind::Regular) != self.identity {
            return Err(DirectoryError::Changed("reading file prefix"));
        }

        Ok(bytes)
    }

    pub fn read_bounded(
        &mut self,
        maximum_bytes: usize,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, DirectoryError> {
        check_cancelled(cancellation)?;
        let mut bytes = Vec::new();
        let mut buffer = [0u8; 16 * 1024];

        loop {
            check_cancelled(cancellation)?;
            let read = self
                .file
                .read(&mut buffer)
                .map_err(|source| io_error("reading file", source))?;
            if read == 0 {
                break;
            }
            if bytes.len().saturating_add(read) > maximum_bytes {
                return Err(DirectoryError::LimitBytes { maximum_bytes });
            }
            bytes.extend_from_slice(&buffer[..read]);
        }

        let after = self
            .file
            .metadata()
            .map_err(|source| io_error("verifying read", source))?;
        if fingerprint(&after, Kind::Regular) != self.identity {
            return Err(DirectoryError::Changed("reading file"));
        }

        Ok(bytes)
    }
}

#[cfg(unix)]
fn open_directory_path(path: &Path) -> io::Result<fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(unix)]
fn open_directory_at(parent: &fs::File, name: &std::ffi::OsStr) -> io::Result<fs::File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )
}

#[cfg(unix)]
fn open_file_at(parent: &fs::File, name: &std::ffi::OsStr) -> io::Result<fs::File> {
    open_at(
        parent,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
    )
}

#[cfg(unix)]
fn readlink_at(
    parent: &fs::File,
    name: &std::ffi::OsStr,
    maximum_bytes: usize,
) -> Result<Vec<u8>, DirectoryError> {
    let name = CString::new(name.as_bytes()).map_err(|_| {
        io_error(
            "reading symlink",
            io::Error::from(io::ErrorKind::InvalidInput),
        )
    })?;
    let buffer_size = maximum_bytes.saturating_add(1);
    let mut target = vec![0u8; buffer_size];
    // SAFETY: `parent` remains borrowed for the call, `name` is a live
    // NUL-terminated CString, and `target` owns writable storage of the
    // length passed to readlinkat.
    let read = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    if read < 0 {
        return Err(io_error("reading symlink", io::Error::last_os_error()));
    }

    let read = read as usize;
    if read > maximum_bytes {
        return Err(DirectoryError::LimitBytes { maximum_bytes });
    }
    target.truncate(read);
    Ok(target)
}

#[cfg(unix)]
fn open_at(parent: &fs::File, name: &std::ffi::OsStr, flags: i32) -> io::Result<fs::File> {
    use std::os::fd::FromRawFd;

    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    // SAFETY: `parent` remains borrowed for the call and `name` is a live
    // NUL-terminated CString. On success the returned descriptor is owned by
    // this function and is transferred exactly once to `File` below.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `descriptor` is a successful, uniquely owned openat result.
    Ok(unsafe { fs::File::from_raw_fd(descriptor) })
}

#[cfg(unix)]
fn read_children(directory: &fs::File) -> Result<Vec<OsString>, DirectoryError> {
    use std::os::fd::IntoRawFd;

    // `dup` would share a directory stream offset with the source handle.
    // Opening `.` relative to the held descriptor creates an independent
    // stream while retaining the same directory identity.
    let stream_handle = open_at(
        directory,
        std::ffi::OsStr::new("."),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )
    .map_err(|source| io_error("opening directory stream handle", source))?;
    let stream_descriptor = stream_handle.into_raw_fd();

    // SAFETY: `stream_descriptor` is the unique descriptor returned by
    // `open_at`; fdopendir takes ownership of it on success.
    let stream = unsafe { libc::fdopendir(stream_descriptor) };
    if stream.is_null() {
        let primary = io_error("opening directory stream", io::Error::last_os_error());
        // SAFETY: fdopendir returned null, so ownership of the descriptor was
        // not transferred and it remains ours to close exactly once.
        return match unsafe { libc::close(stream_descriptor) } {
            0 => Err(primary),
            _ => Err(cleanup_error(
                Some(primary),
                "releasing directory descriptor",
                io::Error::last_os_error(),
            )),
        };
    }

    // SAFETY: the non-null pointer came from a successful fdopendir call and
    // is now owned by DirectoryStream until close or Drop.
    let stream = unsafe { DirectoryStream::from_raw(stream) };
    let children = collect_children(&stream);
    let close_result = stream.close();

    match (children, close_result) {
        (Ok(children), Ok(())) => Ok(children),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(source)) => Err(cleanup_error(None, "closing directory stream", source)),
        (Err(primary), Err(source)) => Err(cleanup_error(
            Some(primary),
            "closing directory stream",
            source,
        )),
    }
}

#[cfg(unix)]
fn collect_children(stream: &DirectoryStream) -> Result<Vec<OsString>, DirectoryError> {
    let mut names = Vec::new();
    loop {
        clear_readdir_error()?;
        // SAFETY: `stream` owns a live DIR pointer and remains alive for the
        // duration of this call; readdir returns either null or an entry owned
        // by that stream, which is consumed before the next iteration.
        let entry = unsafe { libc::readdir(stream.as_ptr()) };
        if entry.is_null() {
            match io::Error::last_os_error().raw_os_error() {
                Some(code) if code != 0 => {
                    return Err(io_error(
                        "reading directory entry",
                        io::Error::last_os_error(),
                    ));
                }
                _ => break,
            }
        }

        // SAFETY: a non-null readdir result points to a dirent owned by the
        // live stream, and d_name is the NUL-terminated name field provided by
        // the platform ABI.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        if name.to_bytes() == b"." || name.to_bytes() == b".." {
            continue;
        }
        names.push(OsString::from_vec(name.to_bytes().to_vec()));
    }

    Ok(names)
}

#[cfg(unix)]
struct DirectoryStream(Option<*mut libc::DIR>);

#[cfg(unix)]
impl DirectoryStream {
    unsafe fn from_raw(stream: *mut libc::DIR) -> Self {
        Self(Some(stream))
    }

    fn as_ptr(&self) -> *mut libc::DIR {
        self.0.expect("directory stream is open")
    }

    fn close(mut self) -> io::Result<()> {
        let Some(stream) = self.0.take() else {
            return Ok(());
        };
        // SAFETY: `stream` is the unique DIR pointer obtained from fdopendir;
        // taking it above prevents close and Drop from running twice.
        if unsafe { libc::closedir(stream) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        if let Some(stream) = self.0.take() {
            // SAFETY: the pointer was obtained from fdopendir and is uniquely
            // owned by this wrapper; taking it prevents a second close.
            unsafe {
                libc::closedir(stream);
            }
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn clear_readdir_error() -> Result<(), DirectoryError> {
    // SAFETY: libc exposes the calling thread's errno slot through this
    // accessor, so the returned pointer is valid for one integer write.
    unsafe {
        *libc::__errno_location() = 0;
    }
    Ok(())
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn clear_readdir_error() -> Result<(), DirectoryError> {
    // SAFETY: libc exposes the calling thread's errno slot through this
    // accessor, so the returned pointer is valid for one integer write.
    unsafe {
        *libc::__error() = 0;
    }
    Ok(())
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
fn clear_readdir_error() -> Result<(), DirectoryError> {
    // Directory-stream error reporting requires a platform errno accessor.
    // Fail closed on Unix hosts that do not provide one here.
    Err(DirectoryError::Unsupported(
        "directory-stream error reporting is not available on this Unix host",
    ))
}

#[cfg(unix)]
fn metadata_at(directory: &fs::File, name: &std::ffi::OsStr) -> io::Result<libc::stat> {
    use std::mem::MaybeUninit;

    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut metadata = MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `directory` remains borrowed, `name` is a live CString, and
    // `metadata` points to writable storage. fstatat initializes it on success.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: the successful fstatat call above initialized every field.
    Ok(unsafe { metadata.assume_init() })
}

#[cfg(unix)]
fn entry_kind(metadata: &libc::stat) -> Option<DirectoryEntryKind> {
    let mode = metadata.st_mode & libc::S_IFMT;
    match mode {
        libc::S_IFLNK => Some(DirectoryEntryKind::Symlink),
        libc::S_IFDIR => Some(DirectoryEntryKind::Directory),
        libc::S_IFREG => Some(DirectoryEntryKind::Regular),
        _ => None,
    }
}

#[cfg(unix)]
fn fingerprint_stat(metadata: &libc::stat, kind: Kind) -> Fingerprint {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let (modified_ns, changed_ns) = (
        i128::from(metadata.st_mtime) * 1_000_000_000 + i128::from(metadata.st_mtime_nsec),
        i128::from(metadata.st_ctime) * 1_000_000_000 + i128::from(metadata.st_ctime_nsec),
    );
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let (modified_ns, changed_ns) = (
        i128::from(metadata.st_mtim.tv_sec) * 1_000_000_000 + i128::from(metadata.st_mtim.tv_nsec),
        i128::from(metadata.st_ctim.tv_sec) * 1_000_000_000 + i128::from(metadata.st_ctim.tv_nsec),
    );

    Fingerprint {
        kind,
        device: metadata.st_dev as u64,
        file_id: metadata.st_ino as u128,
        bytes: metadata.st_size.max(0) as u64,
        modified_ns,
        changed_ns,
    }
}

#[cfg(unix)]
fn fingerprint(metadata: &fs::Metadata, kind: Kind) -> Fingerprint {
    use std::os::unix::fs::MetadataExt;

    Fingerprint {
        kind,
        device: metadata.dev(),
        file_id: metadata.ino() as u128,
        bytes: metadata.size(),
        modified_ns: metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128,
        changed_ns: metadata.ctime() as i128 * 1_000_000_000 + metadata.ctime_nsec() as i128,
    }
}

#[cfg(not(unix))]
fn fingerprint(_metadata: &fs::Metadata, kind: Kind) -> Fingerprint {
    Fingerprint {
        kind,
        device: 0,
        file_id: 0,
        bytes: 0,
        modified_ns: 0,
        changed_ns: 0,
    }
}

#[cfg(unix)]
fn safe_relative_path(path: &str) -> Result<&Path, DirectoryError> {
    let relative = Path::new(path);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative.components().any(|component| {
            matches!(
                component,
                Component::CurDir
                    | Component::ParentDir
                    | Component::RootDir
                    | Component::Prefix(_)
            )
        })
    {
        return Err(DirectoryError::InvalidRelativePath);
    }
    Ok(relative)
}

#[cfg(unix)]
fn split_parent_and_name(relative: &Path) -> Result<(&Path, &std::ffi::OsStr), DirectoryError> {
    let name = relative
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or(DirectoryError::InvalidRelativePath)?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    Ok((parent, name))
}

#[cfg(unix)]
fn path_as_utf8(path: &Path) -> Result<String, DirectoryError> {
    let mut rendered = Vec::new();
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(DirectoryError::InvalidRelativePath);
        };
        let name = name.to_str().ok_or(DirectoryError::InvalidRelativePath)?;
        rendered.push(name);
    }
    Ok(rendered.join("/"))
}

#[cfg(unix)]
fn kind_fingerprint(kind: DirectoryEntryKind) -> Kind {
    match kind {
        DirectoryEntryKind::Regular => Kind::Regular,
        DirectoryEntryKind::Directory => Kind::Directory,
        DirectoryEntryKind::Symlink => Kind::Symlink,
    }
}

#[cfg(not(unix))]
fn kind_fingerprint(kind: DirectoryEntryKind) -> Kind {
    match kind {
        DirectoryEntryKind::Regular => Kind::Regular,
        DirectoryEntryKind::Directory => Kind::Directory,
        DirectoryEntryKind::Symlink => Kind::Symlink,
    }
}

fn check_cancelled(cancellation: &Cancellation) -> Result<(), DirectoryError> {
    match cancellation.reason() {
        Some(reason) => Err(DirectoryError::Cancelled(reason.to_owned())),
        None => Ok(()),
    }
}

fn io_error(stage: &'static str, source: io::Error) -> DirectoryError {
    DirectoryError::Io { stage, source }
}

fn is_missing_io_error(error: &io::Error) -> bool {
    // No-follow traversal through a symlink can report NotADirectory. Preserve
    // that failure rather than turning an unreadable path into absent evidence.
    error.kind() == io::ErrorKind::NotFound
}

fn is_missing_path_error(error: &DirectoryError) -> bool {
    matches!(error, DirectoryError::Io { source, .. } if is_missing_io_error(source))
}

fn cleanup_error(
    primary: Option<DirectoryError>,
    stage: &'static str,
    source: io::Error,
) -> DirectoryError {
    DirectoryError::Cleanup {
        primary: primary.map(Box::new),
        stage,
        source,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{DirectoryEntryKind, DirectoryEntryPolicy, DirectoryError, DirectoryReader};
    use rea_core::cancellation::Cancellation;
    use std::{collections::BTreeSet, fs};

    #[test]
    fn enumerates_nested_entries_and_reads_through_rooted_handles() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::create_dir(temporary.path().join("Resources")).expect("create resource directory");
        fs::write(temporary.path().join("Resources/Main.nib"), b"archive").expect("write archive");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();
        let entries = reader.entries(10, &cancellation).expect("enumerate root");
        let paths = entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();

        assert_eq!(paths, BTreeSet::from(["Resources", "Resources/Main.nib"]));
        assert_eq!(entries[0].kind, DirectoryEntryKind::Directory);

        let entry = entries
            .iter()
            .find(|entry| entry.path == "Resources/Main.nib")
            .expect("archive entry exists");
        let mut archive = reader
            .open_entry(entry, &cancellation)
            .expect("open archive");
        assert_eq!(archive.read_bounded(16, &cancellation).unwrap(), b"archive");
    }

    #[test]
    fn separates_retained_candidates_from_examined_names() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::write(temporary.path().join("ignored.txt"), b"ignored").expect("write ignored");
        fs::write(temporary.path().join("kept.nib"), b"archive").expect("write candidate");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();
        let entries = reader
            .entries_with_policy(1, 10, &cancellation, |entry| DirectoryEntryPolicy {
                retain: entry.path.ends_with(".nib"),
                descend: entry.kind == DirectoryEntryKind::Directory,
            })
            .expect("enumerate candidates");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "kept.nib");

        let error = reader
            .entries_with_policy(1, 1, &cancellation, |_| DirectoryEntryPolicy {
                retain: false,
                descend: false,
            })
            .expect_err("examined-name budget should remain enforced");
        assert!(matches!(
            error,
            DirectoryError::Limit { maximum_entries: 1 }
        ));

        cancellation.cancel("policy test cancellation");
        let error = reader
            .entries_with_policy(1, 10, &cancellation, |_| DirectoryEntryPolicy {
                retain: true,
                descend: true,
            })
            .expect_err("policy traversal should honor cancellation");
        assert!(matches!(
            error,
            DirectoryError::Cancelled(reason) if reason == "policy test cancellation"
        ));
    }

    #[test]
    fn rejects_unsafe_paths_and_symlink_traversal() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        let outside = tempfile::tempdir().expect("create external directory");
        fs::write(outside.path().join("secret.txt"), b"secret").expect("write external file");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), temporary.path().join("external"))
            .expect("create directory symlink");
        std::os::unix::fs::symlink(
            outside.path().join("secret.txt"),
            temporary.path().join("secret-link.txt"),
        )
        .expect("create file symlink");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();

        let entries = reader
            .entries(10, &cancellation)
            .expect("enumerate symlinks");
        assert!(entries.iter().any(|entry| {
            entry.path == "external" && entry.kind == DirectoryEntryKind::Symlink
        }));
        assert!(
            !entries
                .iter()
                .any(|entry| entry.path == "external/secret.txt")
        );
        assert!(
            reader
                .inspect_entry("external/secret.txt", &cancellation)
                .is_err()
        );
        assert!(
            reader
                .inspect_entry("missing/secret.txt", &cancellation)
                .expect("missing parent remains an absent entry")
                .is_none()
        );

        let external_identity = super::fingerprint(
            &fs::metadata(outside.path().join("secret.txt")).expect("stat external file"),
            super::Kind::Regular,
        );
        let forged_entries = [
            super::DirectoryEntry {
                path: "../secret.txt".into(),
                kind: DirectoryEntryKind::Regular,
                identity: external_identity,
                mode: 0o100_644,
            },
            super::DirectoryEntry {
                path: "/secret.txt".into(),
                kind: DirectoryEntryKind::Regular,
                identity: external_identity,
                mode: 0o100_644,
            },
            super::DirectoryEntry {
                path: "external/secret.txt".into(),
                kind: DirectoryEntryKind::Regular,
                identity: external_identity,
                mode: 0o100_644,
            },
        ];
        for entry in &forged_entries {
            assert!(reader.open_entry(entry, &cancellation).is_err());
        }
        let file_symlink = entries
            .iter()
            .find(|entry| entry.path == "secret-link.txt")
            .expect("file symlink exists");
        assert!(reader.open_entry(file_symlink, &cancellation).is_err());
    }

    #[test]
    fn reports_entry_limits_and_cancellation() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::write(temporary.path().join("one"), b"1").expect("write first file");
        fs::write(temporary.path().join("two"), b"2").expect("write second file");
        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();

        assert!(matches!(
            reader.entries(1, &cancellation),
            Err(DirectoryError::Limit { maximum_entries: 1 })
        ));

        cancellation.cancel("request ended");
        assert!(matches!(
            reader.entries(10, &cancellation),
            Err(DirectoryError::Cancelled(reason)) if reason == "request ended"
        ));
    }

    #[test]
    fn filtered_entries_admit_excluded_directories_without_enumerating_descendants() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        let excluded = temporary.path().join("excluded");
        let outside = tempfile::tempdir().expect("create external directory");
        fs::create_dir(&excluded).expect("create excluded directory");
        fs::write(excluded.join("large-source.js"), b"source").expect("write excluded file");
        fs::write(outside.path().join("secret"), b"secret").expect("write external file");
        std::os::unix::fs::symlink(outside.path().join("secret"), excluded.join("secret-link"))
            .expect("create excluded symlink");
        fs::write(temporary.path().join("kept.js"), b"kept").expect("write retained file");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();
        let entries = reader
            .entries_filtered(100, &cancellation, |entry| entry.path != "excluded")
            .expect("enumerate with pruning");
        let paths = entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<BTreeSet<_>>();

        assert!(paths.contains("excluded"));
        assert!(paths.contains("kept.js"));
        assert!(!paths.contains("excluded/large-source.js"));
        assert!(!paths.contains("excluded/secret-link"));

        let cancellation = Cancellation::default();
        let cancellation_from_predicate = cancellation.clone();
        fs::write(temporary.path().join("second.js"), b"second").expect("write second file");
        let reader = DirectoryReader::open(temporary.path()).expect("admit changed root");
        assert!(matches!(
            reader.entries_filtered(100, &cancellation, move |_| {
                cancellation_from_predicate.cancel("request ended");
                true
            }),
            Err(DirectoryError::Cancelled(reason)) if reason == "request ended"
        ));
    }

    #[test]
    fn binds_opened_file_to_enumerated_identity_and_enforces_read_bound() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::write(temporary.path().join("data"), b"original").expect("write source file");
        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();
        let entries = reader.entries(10, &cancellation).expect("enumerate source");
        let entry = entries
            .iter()
            .find(|entry| entry.path == "data")
            .expect("source entry exists");

        fs::write(temporary.path().join("data"), b"replacement is larger")
            .expect("replace source file");
        assert!(matches!(
            reader.open_entry(entry, &cancellation),
            Err(DirectoryError::Changed("opening file"))
        ));

        let fresh_entries = reader.entries(10, &cancellation).expect("re-enumerate");
        let fresh_entry = fresh_entries
            .iter()
            .find(|entry| entry.path == "data")
            .expect("replacement entry exists");
        let mut file = reader
            .open_entry(fresh_entry, &cancellation)
            .expect("open replacement");
        assert!(matches!(
            file.read_bounded(4, &cancellation),
            Err(DirectoryError::LimitBytes { maximum_bytes: 4 })
        ));
    }

    #[test]
    fn reads_prefix_and_symlink_targets_through_the_admitted_directory() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::write(temporary.path().join("image"), b"\xcf\xfa\xed\xfe rest").expect("write image");
        std::os::unix::fs::symlink("image", temporary.path().join("current"))
            .expect("create relative symlink");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();
        let entries = reader.entries(10, &cancellation).expect("enumerate root");
        let image = entries
            .iter()
            .find(|entry| entry.path == "image")
            .expect("image entry exists");
        let link = entries
            .iter()
            .find(|entry| entry.path == "current")
            .expect("symlink entry exists");

        assert_eq!(
            reader
                .read_entry_prefix(image, 4, &cancellation)
                .expect("read image magic"),
            b"\xcf\xfa\xed\xfe"
        );
        assert_eq!(
            reader
                .read_symlink_target(link, &cancellation)
                .expect("read symlink without following it"),
            "image"
        );
    }

    #[test]
    fn inspects_one_path_and_reads_ranges_and_digest_from_the_opened_file() {
        use sha2::{Digest, Sha256};

        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::create_dir(temporary.path().join("Frameworks")).expect("create framework directory");
        fs::write(
            temporary.path().join("Frameworks/libsample.dylib"),
            b"macho payload",
        )
        .expect("write image");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();

        assert!(
            reader
                .inspect_entry("missing.dylib", &cancellation)
                .expect("inspect missing entry")
                .is_none()
        );
        let image = reader
            .inspect_entry("Frameworks/libsample.dylib", &cancellation)
            .expect("inspect image")
            .expect("image exists");
        assert_eq!(image.kind, DirectoryEntryKind::Regular);

        let mut file = reader
            .open_entry(&image, &cancellation)
            .expect("open image");
        assert_eq!(
            file.read_at(6, 4, &cancellation)
                .expect("read bounded image range"),
            b"payl"
        );
        assert!(
            file.read_at(99, 4, &cancellation)
                .expect("read beyond end")
                .is_empty()
        );
        assert_eq!(
            file.sha256(&cancellation).expect("hash image"),
            format!("{:x}", Sha256::digest(b"macho payload"))
        );
        reader
            .revalidate_entry(&image, &cancellation)
            .expect("name still refers to the admitted image");
    }

    #[test]
    fn revalidation_detects_replaced_file_and_symlink_names() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        fs::write(temporary.path().join("image"), b"first").expect("write first image");
        std::os::unix::fs::symlink("image", temporary.path().join("current"))
            .expect("create initial symlink");

        let reader = DirectoryReader::open(temporary.path()).expect("admit root");
        let cancellation = Cancellation::default();
        let entries = reader.entries(10, &cancellation).expect("enumerate root");
        let image = entries
            .iter()
            .find(|entry| entry.path == "image")
            .expect("image entry exists");
        let link = entries
            .iter()
            .find(|entry| entry.path == "current")
            .expect("symlink entry exists");

        fs::write(
            temporary.path().join("image"),
            b"replacement with a different size",
        )
        .expect("replace image");
        fs::remove_file(temporary.path().join("current")).expect("remove old symlink");
        std::os::unix::fs::symlink("elsewhere", temporary.path().join("current"))
            .expect("replace symlink");

        assert!(matches!(
            reader.revalidate_entry(image, &cancellation),
            Err(DirectoryError::Changed("revalidating entry"))
        ));
        assert!(matches!(
            reader.read_symlink_target(link, &cancellation),
            Err(DirectoryError::Changed("reading symlink"))
        ));
    }

    #[test]
    fn detects_replaced_root_before_enumeration() {
        let temporary = tempfile::tempdir().expect("create temporary root");
        let root_path = temporary.path().join("bundle");
        let moved_path = temporary.path().join("bundle-moved");
        let outside = temporary.path().join("outside");
        fs::create_dir(&root_path).expect("create bundle");
        fs::create_dir(&outside).expect("create outside directory");
        fs::write(outside.join("secret"), b"secret").expect("write outside file");

        let reader = DirectoryReader::open(&root_path).expect("admit root");
        fs::rename(&root_path, &moved_path).expect("move admitted root");
        std::os::unix::fs::symlink(&outside, &root_path).expect("replace root with symlink");

        assert!(matches!(
            reader.entries(10, &Cancellation::default()),
            Err(DirectoryError::Changed("enumerating"))
        ));
    }
}
