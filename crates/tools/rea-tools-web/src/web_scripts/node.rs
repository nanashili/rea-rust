//! Host facts the TS runtime exposed through Node's platform layer.
//!
//! Compatibility owners: Node's `path.isAbsolute`, `path.join`,
//! `fs.realpath`, `crypto.randomUUID` and the libuv error names embedded in
//! `fs` error messages. Callers see these strings verbatim in typed failures,
//! so they are reproduced once here.
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
        libc::EACCES => "EACCES",
        libc::EEXIST => "EEXIST",
        libc::EINTR => "EINTR",
        libc::EISDIR => "EISDIR",
        libc::ELOOP => "ELOOP",
        libc::ENAMETOOLONG => "ENAMETOOLONG",
        libc::ENOENT => "ENOENT",
        libc::ENOTDIR => "ENOTDIR",
        libc::ENXIO => "ENXIO",
        libc::EPERM => "EPERM",
        _ => return None,
    })
}

#[cfg(not(unix))]
fn code_for_raw(_raw: i32) -> Option<&'static str> {
    None
}

/// `fs.realpath`, resolving symlinks and returning the canonical path.
pub fn realpath(path: &str) -> io::Result<String> {
    let resolved = std::fs::canonicalize(path)?;
    Ok(resolved.to_string_lossy().into_owned())
}

/// `crypto.randomUUID`.
pub fn random_uuid() -> String {
    let mut bytes = [0_u8; 16];
    getrandom(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(unix)]
fn getrandom(buffer: &mut [u8]) {
    use std::io::Read;
    // `/dev/urandom` is always available on the supported POSIX hosts; a
    // staging-directory name never needs cryptographic strength.
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        if file.read_exact(buffer).is_ok() {
            return;
        }
    }
    fallback_random(buffer);
}

#[cfg(not(unix))]
fn getrandom(buffer: &mut [u8]) {
    fallback_random(buffer);
}

fn fallback_random(buffer: &mut [u8]) {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let mut state = (nanos as u64) ^ 0x9e37_79b9_7f4a_7c15;
    for slot in buffer.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *slot = (state & 0xff) as u8;
    }
}

/// `path.join(directory, name)` for the host separator, simplified for the
/// two-argument case publication needs.
pub fn join(directory: &str, name: &str) -> String {
    let separator = std::path::MAIN_SEPARATOR;
    if directory.is_empty() {
        return name.to_owned();
    }
    if directory.ends_with(separator) {
        format!("{directory}{name}")
    } else {
        format!("{directory}{separator}{name}")
    }
}

/// Split an absolute path into (parent, basename) like Node `dirname`/`basename`.
pub fn split_parent(path: &str) -> (String, String) {
    let candidate = std::path::Path::new(path);
    let parent = candidate
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .unwrap_or_default();
    let name = candidate
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    (parent, name)
}
