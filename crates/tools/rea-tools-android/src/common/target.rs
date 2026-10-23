//! Caller-selected local target admission and stable identity.
//!
//! Compatibility owner: `parseBinaryTarget` in
//! `src/application/BinaryTargetResolver.ts` (without load-selection hints).
//! Artifact classification (ZIP package families, plist, ASAR, PKG, DMG,
//! source maps, JavaScript, WASM rejection) is ported exactly. Executable
//! classification reports the container format from its magic; the original
//! architecture and header-consistency checks are not repeated here because
//! the Android-family tools accept only artifact formats and reject every
//! executable by its format name.
use super::files::{self, FileState, StableFileError};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

const RESOLVE_OPERATION: &str = "resolve_binary_target";
const MAX_XML_PLIST_PROBE_BYTES: usize = 1024 * 1024;

/// Resolved target identity (`BinaryTarget`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BinaryTarget {
    /// Canonical path of the admitted file.
    pub path: String,
    /// Caller-selected spelling used for admission on Windows.
    pub source_path: String,
    pub sha256: String,
    /// executable, archive, artifact or database.
    pub kind: &'static str,
    pub format: String,
    pub architecture: Option<String>,
}

fn cancelled() -> AnalysisError {
    AnalysisError::cancelled(RESOLVE_OPERATION)
}

fn checkpoint(cancellation: &Cancellation) -> Result<(), AnalysisError> {
    if cancellation.reason().is_some() {
        Err(cancelled())
    } else {
        Ok(())
    }
}

fn binary_target_error(
    path: &str,
    reason: impl Into<String>,
    constraint: Option<&str>,
    system_code: Option<&str>,
) -> AnalysisError {
    ErrorKind::BinaryTarget {
        path: path.to_owned(),
        reason: reason.into(),
        constraint: constraint.map(str::to_owned),
        system_code: system_code.map(str::to_owned),
    }
    .into()
}

/// `targetFailureReason(code, detail)`.
fn failure_reason(code: &str, detail: &str) -> String {
    match code {
        "ENOENT" | "ENOTDIR" => {
            format!("target does not exist or a path component is not a directory: {detail}")
        }
        "EACCES" | "EPERM" => format!("permission denied while reading target: {detail}"),
        "EISDIR" => format!("target is a directory, not a readable file: {detail}"),
        "ENOTFILE" => "target is not a regular file".into(),
        "ELOOP" => format!("target changed while being opened: {detail}"),
        _ => format!("target could not be read ({code}): {detail}"),
    }
}

/// `classifyBinaryTargetFilesystemFailure` for one coded failure.
fn filesystem_failure(path: &str, code: &str, detail: &str) -> AnalysisError {
    let system_code = matches!(code, "EACCES" | "EPERM").then_some(code);
    binary_target_error(path, failure_reason(code, detail), None, system_code)
}

fn stable_file_failure(path: &str, error: StableFileError) -> AnalysisError {
    match &error {
        StableFileError::Cancelled(_) => cancelled(),
        StableFileError::Changed { .. } => filesystem_failure(path, "ESTALE", &error.to_string()),
        StableFileError::NotRegular { .. } | StableFileError::Io { .. } => match error.code() {
            Some(code) => filesystem_failure(path, code, &error.to_string()),
            None => binary_target_error(path, error.to_string(), None, None),
        },
    }
}

/// `absoluteCallerPath(input)`.
pub fn absolute_caller_path(input: &str) -> Result<String, AnalysisError> {
    #[cfg(unix)]
    {
        rea_host::fs::caller_path::absolute(input)
            .map_err(|error| binary_target_error(input, error.to_string(), None, None))
    }
    #[cfg(not(unix))]
    {
        std::path::absolute(input)
            .map(|path| path.display().to_string())
            .map_err(|error| binary_target_error(input, error.to_string(), None, None))
    }
}

/// Strip the Windows verbatim prefix from a canonical local path.
pub fn display_canonical(path: PathBuf) -> String {
    let text = path.display().to_string();
    #[cfg(windows)]
    {
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = text.strip_prefix(r"\\?\")
            && rest.as_bytes().get(1) == Some(&b':')
        {
            return rest.to_owned();
        }
    }
    text
}

/// `hasZipSignature`.
pub fn has_zip_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 4
        && bytes[0] == 0x50
        && bytes[1] == 0x4b
        && matches!(
            (bytes[2], bytes[3]),
            (0x03, 0x04) | (0x05, 0x06) | (0x07, 0x08)
        )
}

/// `zipPackageFormatForPath`.
pub fn zip_package_format_for_path(path: &str) -> Option<&'static str> {
    let lower = path.to_lowercase();
    if lower.ends_with(".zip") {
        Some("zip")
    } else if lower.ends_with(".ipa") {
        Some("ipa")
    } else if lower.ends_with(".apk") {
        Some("apk")
    } else if lower.ends_with(".msix") || lower.ends_with(".msixbundle") {
        Some("msix")
    } else if lower.ends_with(".appx") || lower.ends_with(".appxbundle") {
        Some("appx")
    } else if lower.ends_with(".hap") {
        Some("hap")
    } else if lower.ends_with(".hsp") {
        Some("hsp")
    } else {
        None
    }
}

const ZIP_PACKAGE_FORMATS: [&str; 8] = [
    "zip", "ipa", "apk", "msix", "appx", "hap", "hsp", "app-pack",
];

fn has_binary_plist_signature(bytes: &[u8]) -> bool {
    bytes.len() >= 8
        && &bytes[..6] == b"bplist"
        && bytes[6].is_ascii_digit()
        && bytes[7].is_ascii_digit()
}

/// Bounded XML plist prolog probe (`createXmlPlistSignatureProbe`): skip an
/// optional BOM, XML declaration, comments, processing instructions and
/// whitespace, then require a `<!DOCTYPE plist` or `<plist` element.
#[derive(Default)]
struct XmlPlistProbe {
    buffer: Vec<u8>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ProbeState {
    Pending,
    Matched,
    Rejected,
}

impl XmlPlistProbe {
    fn write(&mut self, bytes: &[u8]) -> ProbeState {
        self.buffer.extend_from_slice(bytes);
        let mut text = self.buffer.as_slice();
        if text.starts_with(&[0xef, 0xbb, 0xbf]) {
            text = &text[3..];
        }
        loop {
            let trimmed = trim_start_whitespace(text);
            if trimmed.is_empty() {
                return ProbeState::Pending;
            }
            if trimmed.starts_with(b"<?") {
                match find(trimmed, b"?>") {
                    Some(end) => text = &trimmed[end + 2..],
                    None => return ProbeState::Pending,
                }
                continue;
            }
            if trimmed.starts_with(b"<!--") {
                match find(&trimmed[4..], b"-->") {
                    Some(end) => text = &trimmed[4 + end + 3..],
                    None => return ProbeState::Pending,
                }
                continue;
            }
            for candidate in [b"<!DOCTYPE plist".as_slice(), b"<plist".as_slice()] {
                let length = candidate.len().min(trimmed.len());
                if trimmed[..length] == candidate[..length] {
                    return if trimmed.len() >= candidate.len() {
                        ProbeState::Matched
                    } else {
                        ProbeState::Pending
                    };
                }
            }
            return ProbeState::Rejected;
        }
    }
}

fn trim_start_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn named_artifact_format(lower: &str) -> Option<&'static str> {
    if lower.ends_with(".asar") {
        Some("asar")
    } else if lower.ends_with(".plist") {
        Some("plist")
    } else if lower.ends_with(".map") {
        Some("source-map")
    } else if lower.ends_with(".js") || lower.ends_with(".mjs") || lower.ends_with(".cjs") {
        Some("javascript")
    } else {
        None
    }
}

fn read_at(file: &mut File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    file.seek(SeekFrom::Start(offset))?;
    let mut total = 0;
    while total < buffer.len() {
        let read = file.read(&mut buffer[total..])?;
        if read == 0 {
            break;
        }
        total += read;
    }
    Ok(total)
}

/// `detectArtifactFormat`.
fn detect_artifact_format(
    path: &str,
    file: &mut File,
    size: u64,
    cancellation: &Cancellation,
) -> Result<Option<&'static str>, AnalysisError> {
    checkpoint(cancellation)?;
    let lower = path.to_lowercase();
    let mut magic = vec![0u8; 4096];
    let observed =
        read_at(file, &mut magic, 0).map_err(|error| io_failure(path, &error, "read"))?;
    checkpoint(cancellation)?;
    let magic = &magic[..observed];
    if observed >= 8 && magic[..8] == [0, 0x61, 0x73, 0x6d, 1, 0, 0, 0] {
        return Err(binary_target_error(
            path,
            "WebAssembly v1 artifacts are not supported by the native opening route",
            Some("wasm_requires_static_inspection"),
            None,
        ));
    }
    if has_zip_signature(magic) {
        if lower.ends_with(".app") {
            return Ok(Some("app-pack"));
        }
        return Ok(Some(zip_package_format_for_path(&lower).unwrap_or("zip")));
    }
    if has_binary_plist_signature(magic) {
        return Ok(Some("plist"));
    }
    if let Some(named) = named_artifact_format(&lower) {
        return Ok(Some(named));
    }
    if lower.ends_with(".pkg") && observed >= 4 && &magic[..4] == b"xar!" {
        return Ok(Some("pkg"));
    }
    if lower.ends_with(".dmg") && size >= 512 {
        checkpoint(cancellation)?;
        let mut trailer = [0u8; 4];
        let read = read_at(file, &mut trailer, size - 512)
            .map_err(|error| io_failure(path, &error, "read"))?;
        checkpoint(cancellation)?;
        if read == 4 && &trailer == b"koly" {
            return Ok(Some("dmg"));
        }
    }
    let mut probe = XmlPlistProbe::default();
    let mut state = probe.write(magic);
    if state == ProbeState::Matched {
        return Ok(Some("plist"));
    }
    let mut read_total = observed;
    let mut chunk = vec![0u8; 64 * 1024];
    while state == ProbeState::Pending && read_total < MAX_XML_PLIST_PROBE_BYTES {
        checkpoint(cancellation)?;
        let want = chunk.len().min(MAX_XML_PLIST_PROBE_BYTES - read_total);
        let read = read_at(file, &mut chunk[..want], read_total as u64)
            .map_err(|error| io_failure(path, &error, "read"))?;
        checkpoint(cancellation)?;
        if read == 0 {
            break;
        }
        read_total += read;
        state = probe.write(&chunk[..read]);
        if state == ProbeState::Matched {
            return Ok(Some("plist"));
        }
    }
    if read_total == MAX_XML_PLIST_PROBE_BYTES && size > read_total as u64 {
        return Err(binary_target_error(
            path,
            "XML plist prolog was not found within the 1 MiB format probe limit",
            Some("file_format_rejected"),
            None,
        ));
    }
    Ok(None)
}

fn io_failure(path: &str, error: &std::io::Error, syscall: &str) -> AnalysisError {
    let detail = files::node_io_message(error, syscall, path);
    match files::io_code(error) {
        Some(code) => filesystem_failure(path, code, &detail),
        None => binary_target_error(path, detail, None, None),
    }
}

/// Executable container format by magic (`parseExecutableHeader` format names).
fn executable_format(bytes: &[u8]) -> Result<(&'static str, Option<&'static str>), &'static str> {
    if bytes.len() < 8 {
        return Err("truncated or unsupported binary header");
    }
    let be = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    match be {
        0xfeed_face | 0xcefa_edfe | 0xfeed_facf | 0xcffa_edfe => return Ok(("mach-o", None)),
        0xcafe_babe | 0xcafe_babf | 0xbeba_feca | 0xbfba_feca => {
            return Ok(("mach-o-universal", None));
        }
        _ => {}
    }
    if bytes[..4] == [0x7f, b'E', b'L', b'F'] {
        return Ok(("elf", None));
    }
    if bytes[0] == b'M' && bytes[1] == b'Z' {
        if bytes.len() >= 64 {
            let offset = u32::from_le_bytes([bytes[60], bytes[61], bytes[62], bytes[63]]) as usize;
            if offset >= 64 && offset + 4 <= bytes.len() && &bytes[offset..offset + 4] == b"PE\0\0"
            {
                return Ok(("pe", None));
            }
        }
        return Ok(("dos-mz", Some("x86")));
    }
    Err("unsupported binary format")
}

fn sha256_handle(
    path: &str,
    file: &mut File,
    initial: &FileState,
    cancellation: &Cancellation,
) -> Result<String, AnalysisError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| io_failure(path, &error, "read"))?;
    let mut hasher = Sha256::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut position: u64 = 0;
    loop {
        checkpoint(cancellation)?;
        let read = match file.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(io_failure(path, &error, "read")),
        };
        checkpoint(cancellation)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        position += read as u64;
        if position > initial.size {
            return Err(binary_target_error(
                path,
                "target grew while being read",
                None,
                None,
            ));
        }
    }
    checkpoint(cancellation)?;
    let opened = file
        .metadata()
        .map_err(|error| io_failure(path, &error, "fstat"))?;
    let current =
        std::fs::symlink_metadata(path).map_err(|error| io_failure(path, &error, "lstat"))?;
    if !initial.same_regular(&FileState::of(&opened))
        || !initial.same_regular(&FileState::of(&current))
        || position != initial.size
    {
        return Err(binary_target_error(
            path,
            "target changed while being read",
            None,
            None,
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn readable(candidate: &str) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        rustix::fs::access(candidate, rustix::fs::Access::READ_OK).map_err(std::io::Error::from)
    }
    #[cfg(not(unix))]
    {
        std::fs::metadata(candidate).map(|_| ())
    }
}

/// `parseBinaryTarget(input)` without load-selection hints.
pub fn parse_binary_target(
    input: &str,
    cancellation: &Cancellation,
) -> Result<BinaryTarget, AnalysisError> {
    let candidate = absolute_caller_path(input)?;
    checkpoint(cancellation)?;
    readable(&candidate).map_err(|error| io_failure(&candidate, &error, "access"))?;
    checkpoint(cancellation)?;
    let canonical = std::fs::canonicalize(&candidate)
        .map(display_canonical)
        .map_err(|error| io_failure(&candidate, &error, "realpath"))?;
    let source_path = if cfg!(windows) {
        candidate.clone()
    } else {
        canonical.clone()
    };
    checkpoint(cancellation)?;
    let metadata =
        std::fs::metadata(&canonical).map_err(|error| io_failure(&candidate, &error, "stat"))?;
    let path = if metadata.is_dir() {
        let is_app = Path::new(&canonical)
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("app"));
        if !is_app {
            return Err(binary_target_error(
                &canonical,
                "this opening route requires a file or app bundle",
                Some("directory_requires_file"),
                None,
            ));
        }
        let resolved =
            rea_application::apple::app_bundle_executable::resolve(Path::new(&canonical))
                .map_err(|reason| binary_target_error(&canonical, reason, None, None))?;
        resolved.executable.display().to_string()
    } else {
        canonical
    };
    checkpoint(cancellation)?;
    let (mut file, initial) = files::open_regular(Path::new(&path), false, cancellation)
        .map_err(|error| stable_file_failure(&candidate, error))?;
    checkpoint(cancellation)?;
    let artifact = detect_artifact_format(&path, &mut file, initial.size, cancellation)?;
    if path.to_lowercase().ends_with(".hop") {
        let sha256 = sha256_handle(&path, &mut file, &initial, cancellation)?;
        return Ok(BinaryTarget {
            path,
            source_path,
            sha256,
            kind: "database",
            format: "analysis-database".into(),
            architecture: None,
        });
    }
    if let Some(format) = artifact {
        let sha256 = sha256_handle(&path, &mut file, &initial, cancellation)?;
        let archive =
            ZIP_PACKAGE_FORMATS.contains(&format) || matches!(format, "asar" | "dmg" | "pkg");
        return Ok(BinaryTarget {
            path,
            source_path,
            sha256,
            kind: if archive { "archive" } else { "artifact" },
            format: format.into(),
            architecture: None,
        });
    }
    let mut prefix = vec![0u8; 4096];
    let read =
        read_at(&mut file, &mut prefix, 0).map_err(|error| io_failure(&path, &error, "read"))?;
    checkpoint(cancellation)?;
    let (format, architecture) = executable_format(&prefix[..read])
        .map_err(|reason| binary_target_error(&path, reason, Some("file_format_rejected"), None))?;
    let sha256 = sha256_handle(&path, &mut file, &initial, cancellation)?;
    Ok(BinaryTarget {
        path,
        source_path,
        sha256,
        kind: "executable",
        format: format.into(),
        architecture: architecture.map(str::to_owned),
    })
}

/// SHA-256 of bytes already in memory.
pub fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
