//! Local `file:` URL authorization for Electron pages and V8 Inspector scripts.
//!
//! Compatibility owner: `src/browser/ElectronFileScope.ts`
//! (`authorizedElectronFile`) and the ASAR extent rules of
//! `src/artifacts/AsarHeader.ts`. A URL authorizes a path only when it names a
//! regular host file (canonicalized after symlink resolution) or a regular
//! member of a local ASAR archive. Parsed archive headers are retained in one
//! process-wide bounded cache keyed by canonical path and file identity.
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value};
use std::collections::VecDeque;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{MAIN_SEPARATOR, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// `MAX_ASAR_HEADER_BYTES`: retained JSON budget and header admission limit.
const MAX_ASAR_HEADER_BYTES: u64 = 16 * 1024 * 1024;
/// `MAX_CACHED_HEADERS`.
const MAX_CACHED_HEADERS: usize = 8;
const READ_CHUNK_BYTES: usize = 64 * 1024;

/// `authorizedElectronFile`: `Ok(None)` when the URL authorizes no file.
/// Cancellation is the operation's typed cancellation error.
pub(crate) fn authorized_file(
    value: &str,
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Option<String>, AnalysisError> {
    active(cancellation, operation)?;
    let lower = value.to_ascii_lowercase();
    if lower.contains("%2f") || lower.contains("%5c") {
        return Ok(None);
    }
    let Ok(url) = url::Url::parse(value) else {
        return Ok(None);
    };
    if url.scheme() != "file"
        || url.host_str().is_some_and(|host| !host.is_empty())
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Ok(None);
    }
    let Ok(path) = url.to_file_path() else {
        return Ok(None);
    };
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().contains(&0) {
        return Ok(None);
    }
    if let Ok(metadata) = fs::metadata(&path) {
        active(cancellation, operation)?;
        if metadata.is_file() {
            return match fs::canonicalize(&path) {
                Ok(canonical) => {
                    active(cancellation, operation)?;
                    Ok(canonical.to_str().map(str::to_owned))
                }
                // `realpath` rejection falls through to archive resolution.
                Err(_) => {
                    active(cancellation, operation)?;
                    authorized_asar_member(&path, cancellation, operation)
                }
            };
        }
    }
    active(cancellation, operation)?;
    authorized_asar_member(&path, cancellation, operation)
}

fn active(cancellation: &Cancellation, operation: &str) -> Result<(), AnalysisError> {
    match cancellation.reason() {
        Some(_) => Err(AnalysisError::cancelled(operation)),
        None => Ok(()),
    }
}

/// `authorizedAsarMember`: the first `.asar` component that is a regular file
/// is the archive; the remainder must name a regular file in its header.
fn authorized_asar_member(
    path: &Path,
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Option<String>, AnalysisError> {
    let Some(text) = path.to_str() else {
        return Ok(None);
    };
    let segments: Vec<&str> = text.split(MAIN_SEPARATOR).collect();
    for index in 1..segments.len().saturating_sub(1) {
        active(cancellation, operation)?;
        if !segments[index].to_lowercase().ends_with(".asar") {
            continue;
        }
        let archive = PathBuf::from(segments[..=index].join(&MAIN_SEPARATOR.to_string()));
        let member: Vec<String> = segments[index + 1..]
            .iter()
            .map(|part| (*part).to_owned())
            .collect();
        if member
            .iter()
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Ok(None);
        }
        let Ok(metadata) = fs::metadata(&archive) else {
            active(cancellation, operation)?;
            return Ok(None);
        };
        active(cancellation, operation)?;
        if !metadata.is_file() {
            continue;
        }
        let Ok(canonical) = fs::canonicalize(&archive) else {
            active(cancellation, operation)?;
            return Ok(None);
        };
        active(cancellation, operation)?;
        let Some(regular) =
            archive_member_is_regular(&canonical, &metadata, &member, cancellation, operation)?
        else {
            return Ok(None);
        };
        active(cancellation, operation)?;
        if !regular {
            return Ok(None);
        }
        let mut joined = canonical;
        for part in &member {
            joined.push(part);
        }
        return Ok(joined.to_str().map(str::to_owned));
    }
    Ok(None)
}

#[derive(Clone, PartialEq, Eq)]
struct Identity {
    device: u64,
    inode: u64,
    size: u64,
    modified_nanos: Option<i128>,
}

fn identity(metadata: &Metadata) -> Identity {
    #[cfg(unix)]
    let (device, inode) = {
        use std::os::unix::fs::MetadataExt;
        (metadata.dev(), metadata.ino())
    };
    #[cfg(not(unix))]
    let (device, inode) = (0, 0);
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos() as i128);
    Identity {
        device,
        inode,
        size: metadata.len(),
        modified_nanos,
    }
}

struct Cached {
    archive: PathBuf,
    identity: Identity,
    files: Value,
    bytes: u64,
}

fn cache() -> &'static Mutex<VecDeque<Cached>> {
    static CACHE: OnceLock<Mutex<VecDeque<Cached>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VecDeque::new()))
}

/// `asarFiles` + `isAsarRegularFile`; `Ok(None)` when the archive header
/// cannot be admitted (it then authorizes no member).
fn archive_member_is_regular(
    archive: &Path,
    metadata: &Metadata,
    member: &[String],
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Option<bool>, AnalysisError> {
    let expected = identity(metadata);
    {
        let entries = cache()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(cached) = entries
            .iter()
            .find(|entry| entry.archive == archive && entry.identity == expected)
        {
            return Ok(Some(is_regular_member(&cached.files, member)));
        }
    }
    let Some((files, bytes)) = read_header(archive, &expected, cancellation, operation)? else {
        return Ok(None);
    };
    active(cancellation, operation)?;
    let regular = is_regular_member(&files, member);
    let mut entries = cache()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    entries.retain(|entry| entry.archive != archive);
    entries.push_back(Cached {
        archive: archive.to_path_buf(),
        identity: expected,
        files,
        bytes,
    });
    while entries.len() > MAX_CACHED_HEADERS
        || entries.iter().map(|entry| entry.bytes).sum::<u64>() > MAX_ASAR_HEADER_BYTES
    {
        entries.pop_front();
    }
    Ok(Some(regular))
}

fn read_header(
    archive: &Path,
    expected: &Identity,
    cancellation: &Cancellation,
    operation: &str,
) -> Result<Option<(Value, u64)>, AnalysisError> {
    let Ok(mut file) = File::open(archive) else {
        return Ok(None);
    };
    active(cancellation, operation)?;
    let Ok(opened) = file.metadata() else {
        return Ok(None);
    };
    if !opened.is_file() || &identity(&opened) != expected {
        return Ok(None);
    }
    let mut prefix = [0_u8; 16];
    if !read_exact(&mut file, &mut prefix, cancellation, operation)? {
        return Ok(None);
    }
    let word = |index: usize| {
        u32::from_le_bytes([
            prefix[index],
            prefix[index + 1],
            prefix[index + 2],
            prefix[index + 3],
        ])
    };
    let (header_bytes, payload_bytes, json_bytes) = (word(4), word(8), word(12));
    if word(0) != 4
        || header_bytes < 8
        || payload_bytes != header_bytes - 4
        || json_bytes > payload_bytes - 4
        || opened.len() < 8
        || u64::from(header_bytes) > opened.len() - 8
        || u64::from(header_bytes) > MAX_ASAR_HEADER_BYTES
    {
        return Ok(None);
    }
    let mut json = vec![0_u8; json_bytes as usize];
    if !read_exact(&mut file, &mut json, cancellation, operation)? {
        return Ok(None);
    }
    let Ok(after) = file.metadata() else {
        return Ok(None);
    };
    if &identity(&after) != expected {
        return Ok(None);
    }
    let Ok(Value::Object(mut root)) = serde_json::from_slice::<Value>(&json) else {
        return Ok(None);
    };
    match root.remove("files") {
        Some(files @ Value::Object(_)) => Ok(Some((files, u64::from(json_bytes)))),
        _ => Ok(None),
    }
}

fn read_exact(
    file: &mut File,
    buffer: &mut [u8],
    cancellation: &Cancellation,
    operation: &str,
) -> Result<bool, AnalysisError> {
    for chunk in buffer.chunks_mut(READ_CHUNK_BYTES) {
        active(cancellation, operation)?;
        if file.read_exact(chunk).is_err() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `isAsarRegularFile`.
fn is_regular_member(files: &Value, member: &[String]) -> bool {
    let mut children: Option<&Map<String, Value>> = files.as_object();
    let mut node: Option<&Value> = None;
    for part in member {
        let Some(child) = children.and_then(|entries| entries.get(part)) else {
            return false;
        };
        node = Some(child);
        children = child.get("files").and_then(Value::as_object);
    }
    node.and_then(Value::as_object).is_some_and(|entry| {
        entry.get("size").is_some_and(Value::is_number)
            && !entry.contains_key("files")
            && !entry.contains_key("link")
    })
}
