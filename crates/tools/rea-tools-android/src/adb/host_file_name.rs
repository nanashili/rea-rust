//! Derive a host file name from a device POSIX path without normalizing it.
//!
//! Compatibility owner: `src/adb/AdbHostFileName.ts`.
use std::sync::OnceLock;

/// Why a device-reported path cannot be used as a host file name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostFileNameReason {
    EmptyFileName,
    NotAbsolutePath,
    DotSegment,
    UnsupportedCharacter,
    ReservedName,
    TrailingDotOrSpace,
}

impl HostFileNameReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EmptyFileName => "empty_file_name",
            Self::NotAbsolutePath => "not_absolute_path",
            Self::DotSegment => "dot_segment",
            Self::UnsupportedCharacter => "unsupported_character",
            Self::ReservedName => "reserved_name",
            Self::TrailingDotOrSpace => "trailing_dot_or_space",
        }
    }
}

fn windows_reserved_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)^(?:con|prn|aux|nul|com[1-9¹²³]|lpt[1-9¹²³])(?:\.|$)").unwrap()
    })
}

fn has_windows_control(file_name: &str) -> bool {
    file_name.chars().any(|character| {
        let code = character as u32;
        code > 0 && code < 0x20
    })
}

/// `adbHostFileName(devicePath, platform)`: derive the final path component
/// for the host platform (defaults to the current platform).
pub fn adb_host_file_name(device_path: &str) -> Result<String, HostFileNameReason> {
    adb_host_file_name_for(device_path, cfg!(windows))
}

/// Platform-explicit variant so parsers can stay deterministic in tests.
pub fn adb_host_file_name_for(
    device_path: &str,
    windows: bool,
) -> Result<String, HostFileNameReason> {
    if device_path.is_empty() || device_path.ends_with('/') {
        return Err(HostFileNameReason::EmptyFileName);
    }
    if device_path.contains('\0') {
        return Err(HostFileNameReason::UnsupportedCharacter);
    }
    if !device_path.starts_with('/') {
        return Err(HostFileNameReason::NotAbsolutePath);
    }
    let file_name = &device_path[device_path.rfind('/').map_or(0, |index| index + 1)..];
    if file_name == "." || file_name == ".." {
        return Err(HostFileNameReason::DotSegment);
    }
    if windows {
        let has_bad_char = file_name
            .chars()
            .any(|c| matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'));
        if has_bad_char || has_windows_control(file_name) {
            return Err(HostFileNameReason::UnsupportedCharacter);
        }
        if windows_reserved_regex().is_match(file_name) {
            return Err(HostFileNameReason::ReservedName);
        }
        if file_name.ends_with('.') || file_name.ends_with(' ') {
            return Err(HostFileNameReason::TrailingDotOrSpace);
        }
    }
    Ok(file_name.to_owned())
}
