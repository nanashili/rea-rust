//! Filesystem boundary: positioned reads, symlink-rejecting open, stat/lstat,
//! realpath, and the regular-file identity check.
//!
//! Ports `src/filesystem/RegularFile.ts` (`openRegularFile` with
//! `symlinks: "reject"`, `sameRegularFileState`), `src/filesystem/callerPath.ts`
//! (`absoluteCallerPath`), and the Node `fs/promises` syscalls used by
//! `BinaryTargetResolver.ts` (access, realpath, stat, lstat, open, read).
//!
//! Node error codes and message text are reproduced as closely as the
//! `std::io::Error` facts allow; residual differences are reported in the
//! final report.

use std::fs::File;
use std::io;
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

/// The Node error `code` string for a failed syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeCode {
    Enoent,
    Enotdir,
    Eacces,
    Eperm,
    Eisdir,
    Eloop,
    /// A non-regular-file selection (`NonRegularFileReadError` ENOTFILE).
    Enotfile,
    /// Any other errno; carries the Node code string.
    Other(&'static str),
}

impl NodeCode {
    fn as_str(self) -> &'static str {
        match self {
            NodeCode::Enoent => "ENOENT",
            NodeCode::Enotdir => "ENOTDIR",
            NodeCode::Eacces => "EACCES",
            NodeCode::Eperm => "EPERM",
            NodeCode::Eisdir => "EISDIR",
            NodeCode::Eloop => "ELOOP",
            NodeCode::Enotfile => "ENOTFILE",
            NodeCode::Other(code) => code,
        }
    }
}

/// A classified filesystem failure carrying the Node-style `code` and a
/// `message` that reproduces Node's `${CODE}: ${description}, ${syscall} '${path}'`.
#[derive(Clone, Debug)]
pub(crate) struct FsError {
    pub code: NodeCode,
    pub message: String,
}

/// Map a `std::io::Error` to its Node error code, using `raw_os_error` first
/// and `ErrorKind` as a fallback.
fn node_code(error: &io::Error) -> NodeCode {
    if let Some(errno) = error.raw_os_error() {
        return node_code_from_errno(errno);
    }
    match error.kind() {
        io::ErrorKind::NotFound => NodeCode::Enoent,
        io::ErrorKind::PermissionDenied => NodeCode::Eacces,
        _ => NodeCode::Other("UNKNOWN"),
    }
}

#[cfg(unix)]
fn node_code_from_errno(errno: i32) -> NodeCode {
    use errno_value as e;
    if errno == e::ENOENT {
        NodeCode::Enoent
    } else if errno == e::ENOTDIR {
        NodeCode::Enotdir
    } else if errno == e::EACCES {
        NodeCode::Eacces
    } else if errno == e::EPERM {
        NodeCode::Eperm
    } else if errno == e::EISDIR {
        NodeCode::Eisdir
    } else if errno == e::ELOOP {
        NodeCode::Eloop
    } else {
        NodeCode::Other("EUNKNOWN")
    }
}

#[cfg(not(unix))]
fn node_code_from_errno(errno: i32) -> NodeCode {
    // Windows: translate common Win32 error codes to the POSIX-style code
    // libuv reports (uv_translate_sys_error).
    match errno {
        2 | 3 => NodeCode::Enoent, // FILE_NOT_FOUND / PATH_NOT_FOUND
        5 => NodeCode::Eacces,     // ACCESS_DENIED
        267 => NodeCode::Enotdir,  // DIRECTORY
        _ => NodeCode::Other("EUNKNOWN"),
    }
}

/// Values of the errno constants this module distinguishes. They differ per
/// target OS; the host build selects the correct set. Avoids a `libc` crate.
#[cfg(unix)]
mod errno_value {
    #[cfg(target_os = "linux")]
    pub const ENOENT: i32 = 2;
    #[cfg(target_os = "linux")]
    pub const ENOTDIR: i32 = 20;
    #[cfg(target_os = "linux")]
    pub const EACCES: i32 = 13;
    #[cfg(target_os = "linux")]
    pub const EPERM: i32 = 1;
    #[cfg(target_os = "linux")]
    pub const EISDIR: i32 = 21;
    #[cfg(target_os = "linux")]
    pub const ELOOP: i32 = 40;

    #[cfg(not(target_os = "linux"))]
    pub const ENOENT: i32 = 2;
    #[cfg(not(target_os = "linux"))]
    pub const ENOTDIR: i32 = 20;
    #[cfg(not(target_os = "linux"))]
    pub const EACCES: i32 = 13;
    #[cfg(not(target_os = "linux"))]
    pub const EPERM: i32 = 1;
    #[cfg(not(target_os = "linux"))]
    pub const EISDIR: i32 = 21;
    // macOS/BSD ELOOP is 62.
    #[cfg(not(target_os = "linux"))]
    pub const ELOOP: i32 = 62;
}

/// The Node description text for a given code, used to build `error.message`.
fn node_description(code: NodeCode) -> &'static str {
    match code {
        NodeCode::Enoent => "no such file or directory",
        NodeCode::Enotdir => "not a directory",
        NodeCode::Eacces => "permission denied",
        NodeCode::Eperm => "operation not permitted",
        NodeCode::Eisdir => "illegal operation on a directory",
        NodeCode::Eloop => "too many symbolic links encountered",
        NodeCode::Enotfile => "not a regular file",
        NodeCode::Other(_) => "i/o error",
    }
}

/// Build an `FsError` reproducing Node's message for one failed syscall.
fn classify(error: &io::Error, syscall: &str, path: &str) -> FsError {
    let code = node_code(error);
    let message = format!(
        "{}: {}, {syscall} '{path}'",
        code.as_str(),
        node_description(code)
    );
    FsError { code, message }
}

/// Mutable metadata identifying one regular file across a read.
///
/// Mirrors the `Stats` fields `sameRegularFileState` compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RegularFileState {
    pub is_file: bool,
    pub dev: u64,
    pub ino: u128,
    pub size: u64,
    pub mode: u32,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
}

/// TS `sameRegularFileState`: identity and mutable metadata must all agree, and
/// the observed entry must still be a regular file.
pub(crate) fn same_regular_file_state(
    expected: &RegularFileState,
    observed: &RegularFileState,
) -> bool {
    observed.is_file
        && expected.dev == observed.dev
        && expected.ino == observed.ino
        && expected.size == observed.size
        && expected.mode == observed.mode
        && expected.mtime_ns == observed.mtime_ns
        && expected.ctime_ns == observed.ctime_ns
}

#[cfg(unix)]
fn state_from_metadata(metadata: &std::fs::Metadata) -> RegularFileState {
    use std::os::unix::fs::MetadataExt;
    RegularFileState {
        is_file: metadata.is_file(),
        dev: metadata.dev(),
        ino: u128::from(metadata.ino()),
        size: metadata.size(),
        mode: metadata.mode(),
        mtime_ns: i128::from(metadata.mtime()) * 1_000_000_000 + i128::from(metadata.mtime_nsec()),
        ctime_ns: i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
    }
}

#[cfg(windows)]
fn state_from_metadata(metadata: &std::fs::Metadata) -> RegularFileState {
    use std::os::windows::fs::MetadataExt;
    // std exposes size and the 100ns FILETIME timestamps. Identity relies on
    // size + times + regular-file kind, the mutable-state subset Node checks.
    RegularFileState {
        is_file: metadata.is_file(),
        dev: 0,
        ino: 0,
        size: metadata.file_size(),
        mode: 0,
        mtime_ns: i128::from(metadata.last_write_time()) * 100,
        ctime_ns: i128::from(metadata.creation_time()) * 100,
    }
}

/// An admitted, symlink-rejected, read-only descriptor and its initial identity.
pub(crate) struct RegularFile {
    file: File,
    path: String,
    pub initial: RegularFileState,
}

impl RegularFile {
    /// TS `handle.stat()` on the owned descriptor.
    pub fn stat(&self) -> Result<RegularFileState, FsError> {
        let metadata = self
            .file
            .metadata()
            .map_err(|error| classify(&error, "fstat", &self.path))?;
        Ok(state_from_metadata(&metadata))
    }

    /// Positioned read: fill `buffer` from `offset`, returning bytes read.
    ///
    /// Mirrors `handle.read(buf, 0, len, position)`; a single positioned read,
    /// which may return fewer bytes than requested.
    pub fn read_at(&self, buffer: &mut [u8], offset: u64) -> Result<usize, FsError> {
        positioned_read(&self.file, buffer, offset)
            .map_err(|error| classify(&error, "read", &self.path))
    }
}

#[cfg(unix)]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn positioned_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset)
}

/// `O_NOFOLLOW` value for the host; selected per target OS. std does not expose
/// the constant, and no `libc` dependency is available to this crate.
#[cfg(all(unix, target_os = "linux"))]
const O_NOFOLLOW: i32 = 0o400000;
#[cfg(all(unix, not(target_os = "linux")))]
const O_NOFOLLOW: i32 = 0x0100; // macOS / BSD

/// TS `openRegularFile(path, { symlinks: "reject" })`.
///
/// On Unix the open uses `O_NOFOLLOW`; on Windows (no `O_NOFOLLOW`) the name is
/// rechecked via lstat after opening, exactly as the TS fallback does.
pub(crate) fn open_regular_file_reject(path: &str) -> Result<RegularFile, FsError> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
            .map_err(|error| classify(&error, "open", path))?
    };
    #[cfg(windows)]
    let file = std::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| classify(&error, "open", path))?;

    let metadata = file
        .metadata()
        .map_err(|error| classify(&error, "fstat", path))?;
    if !metadata.is_file() {
        // TS NonRegularFileReadError: EISDIR for directories, else ENOTFILE.
        return Err(non_regular_error(path, metadata.is_dir()));
    }
    let initial = state_from_metadata(&metadata);

    // O_NOFOLLOW is unavailable on Windows: recheck the name with lstat.
    #[cfg(windows)]
    {
        let named = lstat(path)?;
        if named.is_symlink {
            return Err(non_regular_error(path, false));
        }
        if !same_regular_file_state(&initial, &named.state) {
            return Err(FsError {
                code: NodeCode::Other("ESTALE"),
                message: format!("Selected input changed while being read: {path}"),
            });
        }
    }

    Ok(RegularFile {
        file,
        path: path.to_owned(),
        initial,
    })
}

fn non_regular_error(path: &str, directory: bool) -> FsError {
    // TS NonRegularFileReadError message/code.
    let code = if directory {
        NodeCode::Eisdir
    } else {
        NodeCode::Enotfile
    };
    FsError {
        code,
        message: format!("Selected input must be a regular file: {path}"),
    }
}

/// TS `access(candidate, R_OK)`.
pub(crate) fn access_read(path: &str) -> Result<(), FsError> {
    // std has no access(2); a read-open is the closest faithful R_OK probe, and
    // BinaryTargetResolver immediately follows access with realpath + open.
    match std::fs::OpenOptions::new().read(true).open(path) {
        Ok(_) => Ok(()),
        Err(error) => Err(classify(&error, "access", path)),
    }
}

/// TS `realpath(path)`.
pub(crate) fn realpath(path: &str) -> Result<String, FsError> {
    let canonical =
        std::fs::canonicalize(path).map_err(|error| classify(&error, "realpath", path))?;
    Ok(path_to_string(&canonical))
}

/// TS `stat(path)`.
pub(crate) struct StatResult {
    pub is_directory: bool,
}

pub(crate) fn stat(path: &str) -> Result<StatResult, FsError> {
    let metadata = std::fs::metadata(path).map_err(|error| classify(&error, "stat", path))?;
    Ok(StatResult {
        is_directory: metadata.is_dir(),
    })
}

/// TS `lstat(path)`.
pub(crate) struct LstatResult {
    #[cfg(windows)]
    pub is_symlink: bool,
    pub state: RegularFileState,
}

pub(crate) fn lstat(path: &str) -> Result<LstatResult, FsError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|error| classify(&error, "lstat", path))?;
    Ok(LstatResult {
        #[cfg(windows)]
        is_symlink: metadata.file_type().is_symlink(),
        state: state_from_metadata(&metadata),
    })
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

// ----- callerPath.ts (absoluteCallerPath) -----

/// TS `absoluteCallerPath(input, { cwd: process.cwd() })`.
pub(crate) fn absolute_caller_path(input: &str) -> Result<String, FsError> {
    #[cfg(windows)]
    {
        windows_absolute(input)
    }
    #[cfg(not(windows))]
    {
        posix_absolute(input)
    }
}

#[cfg(not(windows))]
fn posix_absolute(input: &str) -> Result<String, FsError> {
    let absolute = if input.starts_with('/') {
        input.to_owned()
    } else {
        let cwd = current_dir_string()?;
        format!("{cwd}/{input}")
    };
    let segments: Vec<&str> = absolute
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect();
    let directory = (absolute.ends_with('/') || absolute.ends_with("/.")) && !segments.is_empty();
    Ok(format!(
        "/{}{}",
        segments.join("/"),
        if directory { "/" } else { "" }
    ))
}

#[cfg(windows)]
fn windows_absolute(input: &str) -> Result<String, FsError> {
    let candidate = PathBuf::from(input);
    let joined = if candidate.is_absolute() {
        candidate
    } else {
        let cwd = PathBuf::from(current_dir_string()?);
        cwd.join(candidate)
    };
    let normalized = lexical_normalize_windows(&joined);
    Ok(path_to_string(&normalized))
}

#[cfg(windows)]
fn lexical_normalize_windows(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut stack: Vec<Component> = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                if matches!(stack.last(), Some(Component::Normal(_))) {
                    stack.pop();
                } else if !matches!(
                    stack.last(),
                    Some(Component::RootDir) | Some(Component::Prefix(_))
                ) {
                    stack.push(component);
                }
            }
            Component::CurDir => {}
            other => stack.push(other),
        }
    }
    let mut result = PathBuf::new();
    for component in stack {
        result.push(component.as_os_str());
    }
    result
}

fn current_dir_string() -> Result<String, FsError> {
    match std::env::current_dir() {
        Ok(dir) => Ok(path_to_string(&dir)),
        Err(error) => Err(classify(&error, "getcwd", ".")),
    }
}
