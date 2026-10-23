//! Environment-snapshot facts used by the Android-family providers.
//!
//! Handlers never read the ambient process environment; every value comes
//! from the session snapshot taken at startup (`Session::environment`).
use std::collections::HashMap;
use std::path::PathBuf;

/// One environment value with the host's key semantics (case-insensitive on
/// Windows, exact elsewhere), as Node's `process.env` resolves it.
pub fn lookup<'a>(environment: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    #[cfg(windows)]
    {
        if let Some(value) = environment.get(key) {
            return Some(value.as_str());
        }
        environment
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(key))
            .map(|(_, value)| value.as_str())
    }
    #[cfg(not(windows))]
    {
        environment.get(key).map(String::as_str)
    }
}

/// Node `os.tmpdir()` evaluated over the session snapshot.
pub fn temporary_directory(environment: &HashMap<String, String>) -> PathBuf {
    let present = |key: &str| lookup(environment, key).filter(|value| !value.is_empty());
    #[cfg(windows)]
    {
        let value = present("TEMP")
            .or_else(|| present("TMP"))
            .map(str::to_owned)
            .unwrap_or_else(|| {
                format!(
                    "{}\\temp",
                    present("SystemRoot")
                        .or_else(|| present("windir"))
                        .unwrap_or_default()
                )
            });
        let trimmed = if value.len() > 1 && value.ends_with('\\') && !value.ends_with(":\\") {
            &value[..value.len() - 1]
        } else {
            value.as_str()
        };
        PathBuf::from(trimmed)
    }
    #[cfg(not(windows))]
    {
        let value = present("TMPDIR")
            .or_else(|| present("TMP"))
            .or_else(|| present("TEMP"))
            .unwrap_or("/tmp");
        let trimmed = if value.len() > 1 && value.ends_with('/') {
            &value[..value.len() - 1]
        } else {
            value
        };
        PathBuf::from(trimmed)
    }
}

/// Node `path.isAbsolute` for the host platform.
pub fn is_absolute(path: &str) -> bool {
    #[cfg(windows)]
    {
        let bytes = path.as_bytes();
        if bytes
            .first()
            .is_some_and(|byte| *byte == b'\\' || *byte == b'/')
        {
            return true;
        }
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && (bytes[2] == b'\\' || bytes[2] == b'/')
    }
    #[cfg(not(windows))]
    {
        path.starts_with('/')
    }
}

/// Host PATH delimiter (`path.delimiter`).
pub const PATH_DELIMITER: char = if cfg!(windows) { ';' } else { ':' };

/// Host platform name as Node reports `process.platform`.
pub fn platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "freebsd") {
        "freebsd"
    } else if cfg!(target_os = "openbsd") {
        "openbsd"
    } else {
        std::env::consts::OS
    }
}

/// Host architecture as Node reports `process.arch`.
pub fn architecture() -> &'static str {
    match std::env::consts::ARCH {
        "x86_64" => "x64",
        "aarch64" => "arm64",
        "x86" => "ia32",
        "arm" => "arm",
        other => other,
    }
}
