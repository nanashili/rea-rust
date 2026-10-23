//! Stable regular-file admission, hashing and immutable snapshots.
//!
//! Compatibility owners: `src/filesystem/RegularFile.ts`,
//! `src/filesystem/StableFileHash.ts` and the snapshot copy in
//! `src/android/AndroidTargetSnapshot.ts`. A file is read through one
//! admitted descriptor and its identity, extent and timestamps are verified
//! against both the descriptor and the path after the read.
//!
//! Rust's `File` releases its descriptor on drop and cannot report a failed
//! close, so the original retained-descriptor path has no native analogue.
use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Physical file failure at a stable-read boundary.
#[derive(Debug)]
pub enum StableFileError {
    /// Cancellation observed at a checkpoint (`RegularFileOperationCancelled`).
    Cancelled(String),
    /// The admitted file changed (`RegularFileChangedError`).
    Changed { path: String },
    /// The selected path is not one regular file (`NonRegularFileReadError`).
    NotRegular { path: String, directory: bool },
    /// Host I/O failure.
    Io { path: String, error: io::Error },
}

impl fmt::Display for StableFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled(_) => formatter.write_str("Regular file operation cancelled"),
            Self::Changed { path } => {
                write!(formatter, "Selected input changed while being read: {path}")
            }
            Self::NotRegular { path, .. } => {
                write!(formatter, "Selected input must be a regular file: {path}")
            }
            Self::Io { path, error } => {
                write!(formatter, "{}", node_io_message(error, "open", path))
            }
        }
    }
}

impl StableFileError {
    /// Node-style error code of the physical failure.
    pub fn code(&self) -> Option<&'static str> {
        match self {
            Self::Changed { .. } => Some("ESTALE"),
            Self::NotRegular { directory, .. } => {
                Some(if *directory { "EISDIR" } else { "ENOTFILE" })
            }
            Self::Io { error, .. } => io_code(error),
            Self::Cancelled(_) => None,
        }
    }
}

/// Node-style errno name of a host I/O error.
pub fn io_code(error: &io::Error) -> Option<&'static str> {
    #[cfg(unix)]
    if let Some(code) = error.raw_os_error() {
        let errno = rustix::io::Errno::from_raw_os_error(code);
        return Some(match errno {
            rustix::io::Errno::NOENT => "ENOENT",
            rustix::io::Errno::NOTDIR => "ENOTDIR",
            rustix::io::Errno::ACCESS => "EACCES",
            rustix::io::Errno::PERM => "EPERM",
            rustix::io::Errno::ISDIR => "EISDIR",
            rustix::io::Errno::LOOP => "ELOOP",
            rustix::io::Errno::EXIST => "EEXIST",
            rustix::io::Errno::NAMETOOLONG => "ENAMETOOLONG",
            rustix::io::Errno::NOSPC => "ENOSPC",
            rustix::io::Errno::ROFS => "EROFS",
            rustix::io::Errno::BUSY => "EBUSY",
            rustix::io::Errno::MFILE => "EMFILE",
            rustix::io::Errno::NFILE => "ENFILE",
            rustix::io::Errno::XDEV => "EXDEV",
            rustix::io::Errno::NOTEMPTY => "ENOTEMPTY",
            rustix::io::Errno::INVAL => "EINVAL",
            rustix::io::Errno::IO => "EIO",
            rustix::io::Errno::NXIO => "ENXIO",
            rustix::io::Errno::OPNOTSUPP => "EOPNOTSUPP",
            rustix::io::Errno::AGAIN => "EAGAIN",
            rustix::io::Errno::MLINK => "EMLINK",
            _ => return io_kind_code(error),
        });
    }
    io_kind_code(error)
}

fn io_kind_code(error: &io::Error) -> Option<&'static str> {
    match error.kind() {
        io::ErrorKind::NotFound => Some("ENOENT"),
        io::ErrorKind::PermissionDenied => Some("EACCES"),
        io::ErrorKind::AlreadyExists => Some("EEXIST"),
        io::ErrorKind::IsADirectory => Some("EISDIR"),
        io::ErrorKind::NotADirectory => Some("ENOTDIR"),
        io::ErrorKind::DirectoryNotEmpty => Some("ENOTEMPTY"),
        io::ErrorKind::StorageFull => Some("ENOSPC"),
        io::ErrorKind::ReadOnlyFilesystem => Some("EROFS"),
        io::ErrorKind::CrossesDevices => Some("EXDEV"),
        io::ErrorKind::InvalidInput => Some("EINVAL"),
        _ => None,
    }
}

/// libuv's description for an errno name.
fn uv_description(code: &str) -> &'static str {
    match code {
        "ENOENT" => "no such file or directory",
        "ENOTDIR" => "not a directory",
        "EACCES" => "permission denied",
        "EPERM" => "operation not permitted",
        "EISDIR" => "illegal operation on a directory",
        "ELOOP" => "too many symbolic links encountered",
        "EEXIST" => "file already exists",
        "ENAMETOOLONG" => "name too long",
        "ENOSPC" => "no space left on device",
        "EROFS" => "read-only file system",
        "EBUSY" => "resource busy or locked",
        "EMFILE" => "too many open files",
        "ENFILE" => "file table overflow",
        "EXDEV" => "cross-device link not permitted",
        "ENOTEMPTY" => "directory not empty",
        "EINVAL" => "invalid argument",
        "EIO" => "i/o error",
        "ENXIO" => "no such device or address",
        "EOPNOTSUPP" => "operation not supported on socket",
        "EAGAIN" => "resource temporarily unavailable",
        "EMLINK" => "too many links",
        _ => "unknown error",
    }
}

/// Node's `fs` error message: `CODE: description, syscall 'path'`.
pub fn node_io_message(error: &io::Error, syscall: &str, path: &str) -> String {
    match io_code(error) {
        Some(code) => format!("{code}: {}, {syscall} '{path}'", uv_description(code)),
        None => error.to_string(),
    }
}

/// Comparable identity and mutation facts of one regular file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileState {
    pub regular: bool,
    pub directory: bool,
    pub device: u64,
    pub file_id: u64,
    pub size: u64,
    pub mode: u32,
    pub modified_ns: i128,
    pub changed_ns: i128,
}

impl FileState {
    pub fn of(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Self {
                regular: metadata.file_type().is_file(),
                directory: metadata.file_type().is_dir(),
                device: metadata.dev(),
                file_id: metadata.ino(),
                size: metadata.size(),
                mode: metadata.mode(),
                modified_ns: i128::from(metadata.mtime()) * 1_000_000_000
                    + i128::from(metadata.mtime_nsec()),
                changed_ns: i128::from(metadata.ctime()) * 1_000_000_000
                    + i128::from(metadata.ctime_nsec()),
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            Self {
                regular: metadata.file_type().is_file(),
                directory: metadata.file_type().is_dir(),
                device: 0,
                file_id: 0,
                size: metadata.file_size(),
                mode: metadata.file_attributes(),
                modified_ns: i128::from(metadata.last_write_time()) * 100,
                changed_ns: i128::from(metadata.creation_time()) * 100,
            }
        }
    }

    /// `sameRegularFileState(expected, observed)`.
    pub fn same_regular(&self, observed: &Self) -> bool {
        observed.regular
            && self.device == observed.device
            && self.file_id == observed.file_id
            && self.size == observed.size
            && self.mode == observed.mode
            && self.modified_ns == observed.modified_ns
            && self.changed_ns == observed.changed_ns
    }
}

fn checkpoint(cancellation: &Cancellation) -> Result<(), StableFileError> {
    match cancellation.reason() {
        Some(reason) => Err(StableFileError::Cancelled(reason.to_owned())),
        None => Ok(()),
    }
}

fn io_error(path: &Path, error: io::Error) -> StableFileError {
    StableFileError::Io {
        path: path.display().to_string(),
        error,
    }
}

/// `openRegularFile(path, { symlinks })`: open without blocking on pipes and
/// require one regular file on the admitted descriptor.
pub fn open_regular(
    path: &Path,
    follow_symlinks: bool,
    cancellation: &Cancellation,
) -> Result<(File, FileState), StableFileError> {
    checkpoint(cancellation)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
        if !follow_symlinks {
            flags |= rustix::fs::OFlags::NOFOLLOW;
        }
        options.custom_flags(flags.bits() as i32);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) => {
            // Unopenable non-regular files (sockets) are reported by type.
            let metadata = if follow_symlinks {
                std::fs::metadata(path)
            } else {
                std::fs::symlink_metadata(path)
            };
            if let Ok(metadata) = metadata
                && !metadata.is_file()
                && matches!(io_code(&error), Some("ENXIO" | "EOPNOTSUPP"))
            {
                return Err(StableFileError::NotRegular {
                    path: path.display().to_string(),
                    directory: metadata.is_dir(),
                });
            }
            return Err(io_error(path, error));
        }
    };
    checkpoint(cancellation)?;
    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    let state = FileState::of(&metadata);
    if !state.regular {
        return Err(StableFileError::NotRegular {
            path: path.display().to_string(),
            directory: state.directory,
        });
    }
    #[cfg(windows)]
    if !follow_symlinks {
        let named = std::fs::symlink_metadata(path).map_err(|error| io_error(path, error))?;
        if named.file_type().is_symlink() {
            return Err(StableFileError::NotRegular {
                path: path.display().to_string(),
                directory: false,
            });
        }
        if !state.same_regular(&FileState::of(&named)) {
            return Err(StableFileError::Changed {
                path: path.display().to_string(),
            });
        }
    }
    checkpoint(cancellation)?;
    Ok((file, state))
}

/// Digest of one stable regular file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileDigest {
    pub sha256: String,
    pub bytes: u64,
}

/// `hashStableFile(path)`: hash through one descriptor (following symlinks)
/// and verify the descriptor and path still name the same unchanged file.
pub fn hash_stable_file(
    path: &Path,
    cancellation: &Cancellation,
) -> Result<FileDigest, StableFileError> {
    let (mut file, initial) = open_regular(path, true, cancellation)?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut position: u64 = 0;
    loop {
        checkpoint(cancellation)?;
        let read = match file.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_error(path, error)),
        };
        if position + read as u64 > initial.size || (read == 0 && position < initial.size) {
            return Err(StableFileError::Changed {
                path: path.display().to_string(),
            });
        }
        checkpoint(cancellation)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        position += read as u64;
    }
    checkpoint(cancellation)?;
    let opened = FileState::of(&file.metadata().map_err(|error| io_error(path, error))?);
    let current = FileState::of(&std::fs::metadata(path).map_err(|error| io_error(path, error))?);
    if position != initial.size || !initial.same_regular(&opened) || !initial.same_regular(&current)
    {
        return Err(StableFileError::Changed {
            path: path.display().to_string(),
        });
    }
    checkpoint(cancellation)?;
    Ok(FileDigest {
        sha256: format!("{:x}", hasher.finalize()),
        bytes: position,
    })
}

/// Lower-case SHA-256 of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Failure of one immutable snapshot copy.
#[derive(Debug)]
pub enum SnapshotError {
    /// The source changed or did not match its admitted digest.
    Changed(String),
    /// A physical failure at the source or destination.
    File(StableFileError),
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Changed(message) => formatter.write_str(message),
            Self::File(error) => error.fmt(formatter),
        }
    }
}

/// `copyAndroidSnapshot`: copy admitted source bytes into a new private file,
/// verify the source stayed unchanged and the copy matches `expected_sha256`.
/// A failed copy removes the partially written destination.
pub fn copy_snapshot(
    source_path: &Path,
    destination_path: &Path,
    expected_sha256: &str,
    cancellation: &Cancellation,
) -> Result<String, SnapshotError> {
    let (mut source, initial) =
        open_regular(source_path, true, cancellation).map_err(SnapshotError::File)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut destination = options
        .open(destination_path)
        .map_err(|error| SnapshotError::File(io_error(destination_path, error)))?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut chunk = vec![0u8; 64 * 1024];
        let mut copied: u64 = 0;
        loop {
            checkpoint(cancellation).map_err(SnapshotError::File)?;
            let read = match source.read(&mut chunk) {
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(SnapshotError::File(io_error(source_path, error))),
            };
            if read == 0 {
                break;
            }
            copied += read as u64;
            if copied > initial.size {
                return Err(SnapshotError::Changed(format!(
                    "Android input grew while being copied: {}",
                    source_path.display()
                )));
            }
            hasher.update(&chunk[..read]);
            destination
                .write_all(&chunk[..read])
                .map_err(|error| SnapshotError::File(io_error(destination_path, error)))?;
        }
        destination
            .flush()
            .map_err(|error| SnapshotError::File(io_error(destination_path, error)))?;
        checkpoint(cancellation).map_err(SnapshotError::File)?;
        let opened = FileState::of(
            &source
                .metadata()
                .map_err(|error| SnapshotError::File(io_error(source_path, error)))?,
        );
        let current = FileState::of(
            &std::fs::metadata(source_path)
                .map_err(|error| SnapshotError::File(io_error(source_path, error)))?,
        );
        if copied != initial.size
            || !initial.same_regular(&opened)
            || !initial.same_regular(&current)
        {
            return Err(SnapshotError::Changed(format!(
                "Android input changed while being read: {}",
                source_path.display()
            )));
        }
        let observed = format!("{:x}", hasher.finalize());
        if observed != expected_sha256 {
            return Err(SnapshotError::Changed(format!(
                "Android snapshot digest mismatch for {}",
                source_path.display()
            )));
        }
        Ok(observed)
    })();
    drop(destination);
    drop(source);
    if result.is_err() {
        let _ = std::fs::remove_file(destination_path);
    }
    result
}

/// `chmod(path, 0o400)`; on Windows this sets the read-only attribute.
pub fn make_read_only(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o400))
    }
    #[cfg(windows)]
    {
        let mut permissions = std::fs::metadata(path)?.permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(path, permissions)
    }
}

/// Write a new file exclusively (`open(path, "wx", 0o600)`).
pub fn write_new_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let written = file.write_all(bytes).and_then(|()| file.flush());
    if written.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    written
}
