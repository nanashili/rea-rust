//! Host facts the original runtime exposed through Node's platform layer.
//!
//! Compatibility owners: Node's `path.isAbsolute`, `os.tmpdir`, the libuv
//! error names/descriptions embedded in `fs` and `child_process` error
//! messages, and `crypto.randomUUID`. Callers see these strings verbatim in
//! typed failure reasons, so they are reproduced once here.
use std::collections::HashMap;
use std::io;

/// Node's `path.isAbsolute` for the host platform.
pub fn is_absolute(path: &str) -> bool {
    if cfg!(windows) {
        let bytes = path.as_bytes();
        match bytes.first() {
            Some(b'/' | b'\\') => true,
            Some(letter) if letter.is_ascii_alphabetic() => {
                bytes.get(1) == Some(&b':') && matches!(bytes.get(2), Some(b'/' | b'\\'))
            }
            _ => false,
        }
    } else {
        path.starts_with('/')
    }
}

/// libuv error name for one host error, when the platform reports one.
pub fn error_code(error: &io::Error) -> Option<&'static str> {
    error.raw_os_error().and_then(code_for_raw)
}

#[cfg(unix)]
fn code_for_raw(raw: i32) -> Option<&'static str> {
    Some(match raw {
        libc::E2BIG => "E2BIG",
        libc::EACCES => "EACCES",
        libc::EAGAIN => "EAGAIN",
        libc::EBADF => "EBADF",
        libc::EBUSY => "EBUSY",
        libc::ECANCELED => "ECANCELED",
        libc::EDQUOT => "EDQUOT",
        libc::EEXIST => "EEXIST",
        libc::EFBIG => "EFBIG",
        libc::EINTR => "EINTR",
        libc::EINVAL => "EINVAL",
        libc::EIO => "EIO",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::EMFILE => "EMFILE",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENFILE => "ENFILE",
        libc::ENODEV => "ENODEV",
        libc::ENOENT => "ENOENT",
        libc::ENOEXEC => "ENOEXEC",
        libc::ENOMEM => "ENOMEM",
        libc::ENOSPC => "ENOSPC",
        libc::ENOSYS => "ENOSYS",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENOTEMPTY => "ENOTEMPTY",
        libc::ENOTSUP => "ENOTSUP",
        libc::ENXIO => "ENXIO",
        libc::EPERM => "EPERM",
        libc::EPIPE => "EPIPE",
        libc::EROFS => "EROFS",
        libc::ESRCH => "ESRCH",
        libc::ETXTBSY => "ETXTBSY",
        libc::EXDEV => "EXDEV",
        _ => return None,
    })
}

#[cfg(windows)]
fn code_for_raw(raw: i32) -> Option<&'static str> {
    // libuv's uv_translate_sys_error for the Win32 codes file operations report.
    Some(match raw {
        2 | 3 | 15 | 123 | 161 => "ENOENT",
        5 => "EPERM",
        19 => "EROFS",
        32 | 33 => "EBUSY",
        80 | 183 => "EEXIST",
        112 => "ENOSPC",
        145 => "ENOTEMPTY",
        206 => "ENAMETOOLONG",
        267 => "ENOTDIR",
        1920 => "ELOOP",
        8 | 14 => "ENOMEM",
        87 => "EINVAL",
        995 => "ECANCELED",
        _ => return None,
    })
}

/// libuv's description for an error name (`uv_strerror`).
pub fn describe(code: &str) -> &'static str {
    match code {
        "E2BIG" => "argument list too long",
        "EACCES" => "permission denied",
        "EAGAIN" => "resource temporarily unavailable",
        "EBADF" => "bad file descriptor",
        "EBUSY" => "resource busy or locked",
        "ECANCELED" => "operation canceled",
        "EDQUOT" => "disk quota exceeded",
        "EEXIST" => "file already exists",
        "EFBIG" => "file too large",
        "EINTR" => "interrupted system call",
        "EINVAL" => "invalid argument",
        "EIO" => "i/o error",
        "EISDIR" => "illegal operation on a directory",
        "ELOOP" => "too many symbolic links encountered",
        "EMFILE" => "too many open files",
        "ENAMETOOLONG" => "name too long",
        "ENFILE" => "file table overflow",
        "ENODEV" => "no such device",
        "ENOENT" => "no such file or directory",
        "ENOEXEC" => "exec format error",
        "ENOMEM" => "not enough memory",
        "ENOSPC" => "no space left on device",
        "ENOSYS" => "function not implemented",
        "ENOTDIR" => "not a directory",
        "ENOTEMPTY" => "directory not empty",
        "ENOTSUP" => "operation not supported on socket",
        "ENXIO" => "no such device or address",
        "EPERM" => "operation not permitted",
        "EPIPE" => "broken pipe",
        "EROFS" => "read-only file system",
        "ESRCH" => "no such process",
        "ETXTBSY" => "text file is busy",
        "EXDEV" => "cross-device link not permitted",
        _ => "unknown error",
    }
}

/// A failed filesystem call with Node's caller-visible message and code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FsError {
    pub code: Option<&'static str>,
    pub message: String,
}

impl std::fmt::Display for FsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for FsError {}

impl FsError {
    /// `CODE: description, syscall 'path'`, exactly as Node's fs layer.
    pub fn from_io(error: &io::Error, syscall: &str, path: &str) -> Self {
        let code = error_code(error);
        let message = match code {
            Some(code) => format!("{code}: {}, {syscall} '{path}'", describe(code)),
            None => format!("UNKNOWN: unknown error, {syscall} '{path}'"),
        };
        Self { code, message }
    }

    /// A non-system failure raised by the original owner with its own text.
    pub fn plain(message: impl Into<String>) -> Self {
        Self {
            code: None,
            message: message.into(),
        }
    }
}

/// Node's `child_process` spawn failure text: `spawn COMMAND CODE`.
pub fn spawn_message(command: &str, error: &io::Error) -> (Option<&'static str>, String) {
    let code = error_code(error);
    let message = match code {
        Some(code) => format!("spawn {command} {code}"),
        None => format!("spawn {command} UNKNOWN"),
    };
    (code, message)
}

/// `fs.realpath`, returning Node's message on failure.
pub fn realpath(path: &str) -> Result<String, FsError> {
    match std::fs::canonicalize(path) {
        Ok(resolved) => {
            let text = resolved.to_string_lossy().into_owned();
            Ok(strip_verbatim(text))
        }
        Err(error) => Err(FsError::from_io(&error, "realpath", path)),
    }
}

fn strip_verbatim(text: String) -> String {
    if cfg!(windows) {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return rest.to_owned();
        }
    }
    text
}

/// Access modes accepted by [`access`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessMode {
    Execute,
    ReadExecute,
}

/// `fs.access(path, mode)`, returning Node's message on failure.
pub fn access(path: &str, mode: AccessMode) -> Result<(), FsError> {
    #[cfg(unix)]
    {
        use rustix::fs::Access;
        let flags = match mode {
            AccessMode::Execute => Access::EXEC_OK,
            AccessMode::ReadExecute => Access::READ_OK | Access::EXEC_OK,
        };
        rustix::fs::access(path, flags)
            .map_err(|errno| FsError::from_io(&io::Error::from(errno), "access", path))
    }
    #[cfg(not(unix))]
    {
        // Windows has no execute bit; libuv reports existence and readability.
        let _ = mode;
        std::fs::metadata(path)
            .map(|_| ())
            .map_err(|error| FsError::from_io(&error, "access", path))
    }
}

/// `fs.stat(path)` regular-file test with Node's failure text.
pub fn stat_is_file(path: &str) -> Result<bool, FsError> {
    std::fs::metadata(path)
        .map(|metadata| metadata.is_file())
        .map_err(|error| FsError::from_io(&error, "stat", path))
}

/// Node's `os.tmpdir()` over the session environment snapshot.
pub fn tmpdir(environment: &HashMap<String, String>) -> String {
    let lookup = |key: &str| {
        environment
            .get(key)
            .filter(|value| !value.is_empty())
            .cloned()
    };
    if cfg!(windows) {
        let mut path = lookup("TEMP").or_else(|| lookup("TMP")).unwrap_or_else(|| {
            format!(
                "{}\\temp",
                lookup("SystemRoot")
                    .or_else(|| lookup("windir"))
                    .unwrap_or_default()
            )
        });
        if path.len() > 1 && path.ends_with('\\') && !path.ends_with(":\\") {
            path.pop();
        }
        path
    } else {
        let mut path = lookup("TMPDIR")
            .or_else(|| lookup("TMP"))
            .or_else(|| lookup("TEMP"))
            .unwrap_or_else(|| "/tmp".to_owned());
        if path.len() > 1 && path.ends_with('/') {
            path.pop();
        }
        path
    }
}

/// `crypto.randomUUID()`: an RFC 9562 version 4 UUID in lowercase text.
pub fn random_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `path.join(directory, name)` for the simple single-segment joins callers use.
pub fn join(directory: &str, name: &str) -> String {
    let separator = if cfg!(windows) { '\\' } else { '/' };
    if directory.ends_with('/') || (cfg!(windows) && directory.ends_with('\\')) {
        format!("{directory}{name}")
    } else {
        format!("{directory}{separator}{name}")
    }
}

/// JavaScript `String.prototype.toLowerCase` for Unicode text.
pub fn lowercase(text: &str) -> String {
    text.to_lowercase()
}

/// UTF-16 code-unit length, the JavaScript string length.
pub fn utf16_length(text: &str) -> usize {
    text.encode_utf16().count()
}
