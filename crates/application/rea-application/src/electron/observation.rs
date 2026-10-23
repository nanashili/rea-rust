//! Application-owned projection for passive Electron CDP target discovery.
//!
//! Transport remains an adapter concern.  The application layer receives the
//! two validated discovery documents and owns filtering, ordering, and the
//! explicit excluded-target counts exposed by the public contract.

use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub const OPERATION: &str = "list_electron_targets";
pub const PAGE_OPERATION: &str = "inspect_electron_page";

const MAX_ASAR_HEADER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_CACHED_ASAR_HEADERS: usize = 8;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BrowserVersion {
    pub product: String,
    pub protocol_version: String,
    pub revision: String,
    pub user_agent: String,
    pub js_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredTarget {
    pub id: String,
    pub target_type: String,
    pub title: String,
    pub url: String,
    pub attached: Option<bool>,
    pub has_validated_transport: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ElectronTarget {
    pub target_id: String,
    #[serde(rename = "type")]
    pub target_type: String,
    pub title: String,
    pub file_path: String,
    pub attached: Option<bool>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ExcludedTargets {
    pub unsupported_url: usize,
    pub non_page: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TargetList {
    pub browser: BrowserVersion,
    pub targets: Vec<ElectronTarget>,
    pub excluded: ExcludedTargets,
    pub limitations: Vec<String>,
}

/// Validate the strict input shape used by the public target-list operation.
pub fn validate_target_list_input(input: &Value) -> Result<String, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("Electron target-list input must be an object."))?;
    if object.len() != 1 || !object.contains_key("cdp_endpoint") {
        return Err(invalid_input(
            "Electron target-list input accepts only cdp_endpoint.",
        ));
    }

    let endpoint = object
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .filter(|endpoint| !endpoint.trim().is_empty())
        .ok_or_else(|| invalid_input("cdp_endpoint must be a non-empty string."))?;

    validate_endpoint(endpoint)
}

/// Validate and retain the exact result projection for the selected endpoint.
pub fn retain_target_list(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_target_list_input(input)?;
    if !result.is_object() {
        return Err(invalid_output(
            "Electron target-list result must be an object.",
        ));
    }

    Ok(result)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PageTarget {
    pub target_id: String,
    #[serde(rename = "type")]
    pub target_type: String,
    pub title: String,
    pub file_path: String,
    pub attached: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Frame {
    pub frame_id: String,
    pub parent_frame_id: Option<String>,
    pub file_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DomNode {
    pub index: usize,
    pub parent_index: isize,
    pub node_type: u32,
    pub node_name: String,
    pub node_value_length: usize,
    pub attribute_names: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Script {
    pub script_key: String,
    pub frame_id: Option<String>,
    pub file_path: String,
    pub cdp_hash: Option<String>,
    pub length: Option<usize>,
    pub is_module: Option<bool>,
    pub language: Option<String>,
    pub source: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Resource {
    pub resource_key: String,
    pub file_path: String,
    #[serde(rename = "type")]
    pub resource_type: String,
    pub mime_type: String,
    pub content_size: Option<f64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Worker {
    pub target_id: String,
    #[serde(rename = "type")]
    pub worker_type: String,
    pub file_path: String,
    pub attached: bool,
    pub opener_target_id: Option<String>,
    pub parent_frame_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct PageInspection {
    pub browser: BrowserVersion,
    pub target: PageTarget,
    pub capture_window: serde_json::Value,
    pub completeness: serde_json::Value,
    pub frames: Vec<Frame>,
    pub dom: DomSummary,
    pub scripts: ScriptSummary,
    pub resources: Vec<Resource>,
    pub workers: Vec<Worker>,
    pub limitations: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DomSummary {
    pub total_nodes: usize,
    pub nodes: Vec<DomNode>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ScriptSummary {
    pub total: usize,
    pub items: Vec<Script>,
}

/// Transport-owned CDP facts projected into the strict page inspection result.
pub fn project_page_inspection(
    browser: BrowserVersion,
    target: PageTarget,
    capture_window: serde_json::Value,
    completeness: serde_json::Value,
    frames: Vec<Frame>,
    dom: DomSummary,
    scripts: Vec<Script>,
    resources: Vec<Resource>,
    workers: Vec<Worker>,
    limitations: Vec<String>,
) -> Result<PageInspection, Failure> {
    if target.target_id.trim().is_empty() || target.file_path.trim().is_empty() {
        return Err(Failure::new(
            "invalid_request",
            "invalid_output",
            "Electron CDP returned a page without target identity or local file path.".into(),
            false,
            "Retry after selecting a local file page target.".into(),
            BTreeMap::from([("operation", Detail::Text(PAGE_OPERATION.into()))]),
        ));
    }

    Ok(PageInspection {
        browser,
        target,
        capture_window,
        completeness,
        frames,
        dom,
        scripts: ScriptSummary {
            total: scripts.len(),
            items: scripts,
        },
        resources,
        workers,
        limitations,
    })
}

/// Project the raw `/json/version` and `/json/list` documents into the public
/// list operation.  The caller retains the transport and cancellation owner.
pub fn project_target_list(
    browser: BrowserVersion,
    discovered: &[DiscoveredTarget],
) -> Result<TargetList, Failure> {
    project_target_list_with_cancellation(browser, discovered, &Cancellation::default())
}

pub fn project_target_list_with_cancellation(
    browser: BrowserVersion,
    discovered: &[DiscoveredTarget],
    cancellation: &Cancellation,
) -> Result<TargetList, Failure> {
    validate_browser_version(&browser)?;
    ensure_active(cancellation, OPERATION)?;

    let mut targets = Vec::new();
    let mut asar_headers = AsarHeaderCache::default();
    let mut unsupported_url = 0;
    let mut non_page = 0;
    let mut unconnectable = 0;

    for target in discovered {
        ensure_active(cancellation, OPERATION)?;
        validate_discovered_target(target)?;

        if target.target_type != "page" {
            non_page += 1;
            continue;
        }

        let file_path = match authorized_local_file_path_with_cancellation(
            &target.url,
            &mut asar_headers,
            cancellation,
            OPERATION,
        )? {
            Some(file_path) => file_path,
            None => {
                unsupported_url += 1;
                continue;
            }
        };

        if !target.has_validated_transport {
            unconnectable += 1;
            continue;
        }

        targets.push(ElectronTarget {
            target_id: target.id.clone(),
            target_type: target.target_type.clone(),
            title: sanitize_target_title(&target.title),
            file_path,
            attached: target.attached,
        });
    }

    targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
    ensure_active(cancellation, OPERATION)?;

    let mut limitations = vec![
        "Every local file page exposed by the selected loopback CDP endpoint is eligible for listing."
            .into(),
    ];
    if unconnectable > 0 {
        limitations.push(format!(
            "{unconnectable} otherwise allowed page target(s) lacked a validated direct CDP WebSocket and were excluded."
        ));
    }
    if targets.iter().any(|target| target.attached.is_none()) {
        limitations.push(
            "CDP discovery omitted attachment state for one or more targets; attached is reported as unknown."
                .into(),
        );
    }

    Ok(TargetList {
        browser,
        targets,
        excluded: ExcludedTargets {
            unsupported_url,
            non_page,
        },
        limitations,
    })
}

/// Validate the caller-selected passive CDP endpoint before transport use.
pub fn validate_endpoint(endpoint: &str) -> Result<String, Failure> {
    normalize_endpoint_origin(endpoint).map_err(|reason| invalid_endpoint(endpoint, reason))
}

fn normalize_endpoint_origin(endpoint: &str) -> Result<String, &'static str> {
    let value = endpoint.trim();
    let (scheme, authority_and_path) = value.split_once("://").ok_or("expected an HTTP URL")?;
    if !scheme.eq_ignore_ascii_case("http") {
        return Err("expected a loopback origin with an explicit port");
    }

    let (authority, path_and_suffix) = authority_and_path
        .find(['/', '?', '#'])
        .map_or((authority_and_path, ""), |separator| {
            authority_and_path.split_at(separator)
        });
    if !matches!(path_and_suffix, "" | "/") {
        return Err("expected a loopback origin with no path, query, or fragment");
    }
    if authority.contains('@') {
        return Err("credentials are not allowed in the CDP endpoint");
    }

    let (host, port) = authority
        .rsplit_once(':')
        .ok_or("expected an explicit port")?;
    let valid_host = host == "127.0.0.1" || host.eq_ignore_ascii_case("[::1]");
    if !valid_host {
        return Err("expected 127.0.0.1 or ::1 with a valid port");
    }

    let normalized_port =
        parse_non_default_port(port).ok_or("expected 127.0.0.1 or ::1 with a valid port")?;
    let normalized_host = normalized_loopback_host(host);

    Ok(format!("http://{normalized_host}:{normalized_port}"))
}

fn parse_non_default_port(port: &str) -> Option<u16> {
    if port.is_empty() || !port.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }

    let port = port.parse::<u16>().ok()?;
    (port != 0 && port != 80).then_some(port)
}

fn normalized_loopback_host(host: &str) -> &'static str {
    if host.starts_with('[') {
        "[::1]"
    } else {
        "127.0.0.1"
    }
}

fn validate_browser_version(browser: &BrowserVersion) -> Result<(), Failure> {
    let fields = [
        browser.product.as_str(),
        browser.protocol_version.as_str(),
        browser.revision.as_str(),
        browser.user_agent.as_str(),
        browser.js_version.as_str(),
    ];
    if fields.iter().all(|field| !field.trim().is_empty()) {
        return Ok(());
    }

    Err(invalid_endpoint_response(
        "Electron CDP version response omitted required browser metadata.",
    ))
}

fn validate_discovered_target(target: &DiscoveredTarget) -> Result<(), Failure> {
    if target.id.trim().is_empty() || target.target_type.trim().is_empty() {
        return Err(invalid_endpoint_response(
            "Electron CDP target response omitted target identity or type.",
        ));
    }

    Ok(())
}

pub fn sanitize_target_title(title: &str) -> String {
    let Some((scheme, _)) = title.trim().split_once("://") else {
        return title.to_owned();
    };
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return title.to_owned();
    }

    strip_url_user_info(title)
}

fn strip_url_user_info(url: &str) -> String {
    let Some((scheme, remainder)) = url.split_once("://") else {
        return url.to_owned();
    };
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let Some(user_info_end) = authority.rfind('@') else {
        return url.to_owned();
    };

    format!(
        "{scheme}://{}{}",
        &authority[user_info_end + 1..],
        &remainder[authority_end..]
    )
}

#[cfg(test)]
fn authorized_local_file_path(url: &str, asar_headers: &mut AsarHeaderCache) -> Option<String> {
    authorized_local_file_path_with_cancellation(
        url,
        asar_headers,
        &Cancellation::default(),
        OPERATION,
    )
    .ok()
    .flatten()
}

fn authorized_local_file_path_with_cancellation(
    url: &str,
    asar_headers: &mut AsarHeaderCache,
    cancellation: &Cancellation,
    operation: &'static str,
) -> Result<Option<String>, Failure> {
    ensure_active(cancellation, operation)?;
    let Some(encoded_path) = file_url_path(url) else {
        return Ok(None);
    };
    let Some(path) = decode_file_url_path(encoded_path) else {
        return Ok(None);
    };
    let selected_path = Path::new(&path);

    if let Some(canonical) = canonical_regular_file(selected_path) {
        ensure_active(cancellation, operation)?;
        return Ok(canonical.to_str().map(str::to_owned));
    }

    authorized_asar_member(selected_path, asar_headers, cancellation, operation)
}

/// Reuse parsed archive headers while authorizing local Electron file URLs.
#[derive(Default)]
pub struct ElectronFileAuthorizer {
    asar_headers: AsarHeaderCache,
}

impl ElectronFileAuthorizer {
    /// Resolve a direct regular file or a regular member of a local ASAR.
    pub fn authorize(
        &mut self,
        url: &str,
        cancellation: &Cancellation,
    ) -> Result<Option<String>, Failure> {
        authorized_local_file_path_with_cancellation(
            url,
            &mut self.asar_headers,
            cancellation,
            PAGE_OPERATION,
        )
    }
}

fn canonical_regular_file(path: &Path) -> Option<PathBuf> {
    let canonical = fs::canonicalize(path).ok()?;
    fs::metadata(&canonical)
        .ok()?
        .is_file()
        .then_some(canonical)
}

fn authorized_asar_member(
    path: &Path,
    cache: &mut AsarHeaderCache,
    cancellation: &Cancellation,
    operation: &'static str,
) -> Result<Option<String>, Failure> {
    let Some(path_text) = path.to_str() else {
        return Ok(None);
    };
    let separator = std::path::MAIN_SEPARATOR;
    let segments = split_path_segments(path_text).collect::<Vec<_>>();

    for archive_index in 1..segments.len().saturating_sub(1) {
        ensure_active(cancellation, operation)?;
        if !segments[archive_index]
            .to_ascii_lowercase()
            .ends_with(".asar")
        {
            continue;
        }

        let Some(member) = segments[archive_index + 1..]
            .iter()
            .map(|part| {
                (!part.is_empty() && *part != "." && *part != "..").then(|| (*part).to_owned())
            })
            .collect::<Option<Vec<_>>>()
        else {
            return Ok(None);
        };
        let archive_path = PathBuf::from(segments[..=archive_index].join(&separator.to_string()));
        if !fs::metadata(&archive_path)
            .ok()
            .is_some_and(|metadata| metadata.is_file())
        {
            continue;
        }

        let Ok(canonical_archive) = fs::canonicalize(&archive_path) else {
            return Ok(None);
        };
        if !cache.authorizes(&canonical_archive, &member, cancellation, operation)? {
            return Ok(None);
        }

        return Ok(asar_member_path(&canonical_archive, &member));
    }

    Ok(None)
}

fn split_path_segments(path: &str) -> impl Iterator<Item = &str> {
    #[cfg(windows)]
    {
        path.split(['\\', '/'])
    }

    #[cfg(not(windows))]
    {
        path.split('/')
    }
}

fn asar_member_path(archive: &Path, member: &[String]) -> Option<String> {
    let mut path = archive.to_path_buf();
    for part in member {
        path.push(part);
    }
    path.to_str().map(str::to_owned)
}

#[derive(Default)]
struct AsarHeaderCache {
    entries: BTreeMap<PathBuf, CachedAsarHeader>,
    retained_json_bytes: usize,
}

struct CachedAsarHeader {
    identity: ArchiveIdentity,
    files: Value,
    json_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArchiveIdentity {
    length: u64,
    #[cfg(not(windows))]
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    last_write_time: u64,
}

impl ArchiveIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            Self {
                length: metadata.len(),
                modified: metadata.modified().ok(),
                device: metadata.dev(),
                inode: metadata.ino(),
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;

            Self {
                length: metadata.len(),
                creation_time: metadata.creation_time(),
                last_write_time: metadata.last_write_time(),
            }
        }

        #[cfg(not(any(unix, windows)))]
        Self {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        }
    }
}

fn reliable_cache_identity(metadata: &Metadata) -> Option<ArchiveIdentity> {
    #[cfg(unix)]
    {
        Some(ArchiveIdentity::from_metadata(metadata))
    }

    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

impl AsarHeaderCache {
    fn authorizes(
        &mut self,
        archive: &Path,
        member: &[String],
        cancellation: &Cancellation,
        operation: &'static str,
    ) -> Result<bool, Failure> {
        ensure_active(cancellation, operation)?;
        let Ok(opening_metadata) = fs::metadata(archive) else {
            return Ok(false);
        };
        if !opening_metadata.is_file() {
            return Ok(false);
        }

        let identity = reliable_cache_identity(&opening_metadata);
        if let Some(identity) = &identity {
            if let Some(cached) = self.entries.get(archive) {
                if &cached.identity == identity {
                    ensure_active(cancellation, operation)?;
                    return Ok(is_asar_regular_file(&cached.files, member));
                }
            }
            self.remove(archive);
        }

        let Some((files, json_bytes)) =
            read_asar_header(archive, &opening_metadata, cancellation, operation)?
        else {
            return Ok(false);
        };
        let authorized = is_asar_regular_file(&files, member);
        if let Some(identity) = identity {
            self.insert(archive.to_path_buf(), identity, files, json_bytes);
        }

        ensure_active(cancellation, operation)?;
        Ok(authorized)
    }

    fn insert(
        &mut self,
        archive: PathBuf,
        identity: ArchiveIdentity,
        files: Value,
        json_bytes: usize,
    ) {
        self.remove(&archive);
        self.retained_json_bytes += json_bytes;
        self.entries.insert(
            archive.clone(),
            CachedAsarHeader {
                identity,
                files,
                json_bytes,
            },
        );

        while self.entries.len() > MAX_CACHED_ASAR_HEADERS
            || self.retained_json_bytes > MAX_ASAR_HEADER_BYTES as usize
        {
            let Some(eviction) = self
                .entries
                .keys()
                .find(|candidate| candidate.as_path() != archive.as_path())
                .cloned()
            else {
                break;
            };
            self.remove(&eviction);
        }
    }

    fn remove(&mut self, archive: &Path) {
        if let Some(removed) = self.entries.remove(archive) {
            self.retained_json_bytes -= removed.json_bytes;
        }
    }
}

fn read_asar_header(
    archive: &Path,
    expected: &Metadata,
    cancellation: &Cancellation,
    operation: &'static str,
) -> Result<Option<(Value, usize)>, Failure> {
    ensure_active(cancellation, operation)?;
    let Ok(mut file) = File::open(archive) else {
        return Ok(None);
    };
    let Ok(opened) = file.metadata() else {
        return Ok(None);
    };
    if !opened.is_file()
        || ArchiveIdentity::from_metadata(&opened) != ArchiveIdentity::from_metadata(expected)
    {
        return Ok(None);
    }

    let mut prefix = [0_u8; 16];
    if !read_exact_cancellable(&mut file, &mut prefix, cancellation, operation)? {
        return Ok(None);
    }
    let Some((header_bytes, json_bytes)) = parse_asar_header_extents(&prefix, opened.len()) else {
        return Ok(None);
    };
    if u64::from(header_bytes) > MAX_ASAR_HEADER_BYTES {
        return Ok(None);
    }

    let Ok(json_length) = usize::try_from(json_bytes) else {
        return Ok(None);
    };
    let mut encoded_json = vec![0_u8; json_length];
    if !read_exact_cancellable(&mut file, &mut encoded_json, cancellation, operation)? {
        return Ok(None);
    }

    let Ok(finished) = file.metadata() else {
        return Ok(None);
    };
    if ArchiveIdentity::from_metadata(&opened) != ArchiveIdentity::from_metadata(&finished) {
        return Ok(None);
    }

    ensure_active(cancellation, operation)?;
    let Ok(mut document) = serde_json::from_slice::<Value>(&encoded_json) else {
        return Ok(None);
    };
    ensure_active(cancellation, operation)?;
    let Some(root) = document.as_object_mut() else {
        return Ok(None);
    };
    let Some(files) = root.remove("files") else {
        return Ok(None);
    };
    if !files.is_object() {
        return Ok(None);
    }

    Ok(Some((files, json_length)))
}

fn read_exact_cancellable(
    file: &mut File,
    buffer: &mut [u8],
    cancellation: &Cancellation,
    operation: &'static str,
) -> Result<bool, Failure> {
    const READ_CHUNK_BYTES: usize = 64 * 1024;

    for chunk in buffer.chunks_mut(READ_CHUNK_BYTES) {
        ensure_active(cancellation, operation)?;
        if file.read_exact(chunk).is_err() {
            return Ok(false);
        }
    }

    Ok(true)
}

fn parse_asar_header_extents(prefix: &[u8; 16], archive_bytes: u64) -> Option<(u32, u32)> {
    let pickle_bytes = u32::from_le_bytes(prefix[0..4].try_into().ok()?);
    let header_bytes = u32::from_le_bytes(prefix[4..8].try_into().ok()?);
    let payload_bytes = u32::from_le_bytes(prefix[8..12].try_into().ok()?);
    let json_bytes = u32::from_le_bytes(prefix[12..16].try_into().ok()?);

    if pickle_bytes != 4
        || header_bytes < 8
        || payload_bytes != header_bytes.checked_sub(4)?
        || json_bytes > payload_bytes.checked_sub(4)?
        || archive_bytes < 8
        || u64::from(header_bytes) > archive_bytes - 8
    {
        return None;
    }

    Some((header_bytes, json_bytes))
}

fn is_asar_regular_file(files: &Value, member: &[String]) -> bool {
    let Some(mut children) = files.as_object() else {
        return false;
    };
    let mut node = None;

    for (index, part) in member.iter().enumerate() {
        let Some(child) = children.get(part) else {
            return false;
        };
        node = Some(child);

        if index + 1 < member.len() {
            let Some(nested_files) = child.get("files").and_then(Value::as_object) else {
                return false;
            };
            children = nested_files;
        }
    }

    node.and_then(Value::as_object).is_some_and(|entry| {
        entry.get("size").is_some_and(Value::is_number)
            && !entry.contains_key("files")
            && !entry.contains_key("link")
    })
}

fn ensure_active(cancellation: &Cancellation, operation: &'static str) -> Result<(), Failure> {
    let Some(reason) = cancellation.reason() else {
        return Ok(());
    };

    Err(Failure::new(
        "cancelled",
        "cancelled",
        format!("Electron operation {operation} was cancelled: {reason}"),
        false,
        "Retry the Electron inspection if the selected endpoint is still available.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    ))
}

fn file_url_path(url: &str) -> Option<&str> {
    let (scheme, path_and_authority) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("file") {
        return None;
    }

    let path = path_and_authority.split(['?', '#']).next()?;
    #[cfg(windows)]
    {
        let drive_path = path.strip_prefix('/')?;
        let bytes = drive_path.as_bytes();
        let is_drive_rooted = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'/';
        is_drive_rooted.then_some(drive_path)
    }

    #[cfg(not(windows))]
    {
        (path.starts_with('/') && !path.starts_with("//") && !path.is_empty()).then_some(path)
    }
}

fn decode_file_url_path(encoded_path: &str) -> Option<String> {
    let encoded_bytes = encoded_path.as_bytes();
    let mut decoded_bytes = Vec::with_capacity(encoded_bytes.len());
    let mut cursor = 0;

    while cursor < encoded_bytes.len() {
        let byte = encoded_bytes[cursor];
        if byte == b'%' {
            let high = *encoded_bytes.get(cursor + 1)?;
            let low = *encoded_bytes.get(cursor + 2)?;
            let decoded = (hex_digit(high)? << 4) | hex_digit(low)?;
            if matches!(decoded, b'/' | b'\\' | 0) {
                return None;
            }
            decoded_bytes.push(decoded);
            cursor += 3;
            continue;
        }

        if byte == b'\\' || byte == 0 {
            return None;
        }

        decoded_bytes.push(byte);
        cursor += 1;
    }

    String::from_utf8(decoded_bytes).ok()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide one explicit-port loopback Electron CDP endpoint.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_output(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_output",
        reason.to_owned(),
        false,
        "Retry after confirming the native Electron target-list contract.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_endpoint_response(reason: &str) -> Failure {
    Failure::new(
        "invalid_endpoint_response",
        "invalid_output",
        reason.to_owned(),
        false,
        "Retry against a compatible Electron CDP endpoint.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid_endpoint(endpoint: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Unable to use Electron CDP endpoint {endpoint}: {reason}"),
        false,
        "Select an explicit-port loopback HTTP CDP endpoint.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn projects_authorized_local_pages_in_target_id_order() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let app_file = directory.path().join("app.js");
        std::fs::write(&app_file, b"export {};").expect("create app file");
        let result = project_target_list(
            browser_version(),
            &[
                DiscoveredTarget {
                    id: "z".into(),
                    target_type: "page".into(),
                    title: "https://viewer:secret@example.test/private".into(),
                    url: format!("file://{}", app_file.display()),
                    attached: None,
                    has_validated_transport: true,
                },
                DiscoveredTarget {
                    id: "a".into(),
                    target_type: "page".into(),
                    title: "remote".into(),
                    url: "https://example.test".into(),
                    attached: Some(false),
                    has_validated_transport: false,
                },
                DiscoveredTarget {
                    id: "worker".into(),
                    target_type: "worker".into(),
                    title: "worker".into(),
                    url: "file:///tmp/worker.js".into(),
                    attached: Some(false),
                    has_validated_transport: false,
                },
                DiscoveredTarget {
                    id: "unconnectable".into(),
                    target_type: "page".into(),
                    title: "local but unconnectable".into(),
                    url: format!("file://{}", app_file.display()),
                    attached: Some(false),
                    has_validated_transport: false,
                },
            ],
        )
        .expect("projection succeeds");

        assert_eq!(result.targets[0].target_id, "z");
        assert_eq!(result.targets[0].title, "https://example.test/private");
        assert_eq!(
            result.targets[0].file_path,
            app_file.canonicalize().unwrap().display().to_string()
        );
        assert_eq!(result.excluded.unsupported_url, 1);
        assert_eq!(result.excluded.non_page, 1);
        assert!(
            result
                .limitations
                .iter()
                .any(|item| item.contains("unknown"))
        );
        assert!(
            result
                .limitations
                .iter()
                .any(|item| item.contains("lacked a validated"))
        );
    }

    #[test]
    fn validates_exact_loopback_http_input() {
        validate_target_list_input(&serde_json::json!({
            "cdp_endpoint": "http://127.0.0.1:9223"
        }))
        .expect("valid input");
        assert!(
            validate_target_list_input(&serde_json::json!({
                "cdp_endpoint": "http://127.0.0.1:9223",
                "ignored": true
            }))
            .is_err()
        );
        assert!(
            validate_target_list_input(&serde_json::json!({
                "cdp_endpoint": "http://user@127.0.0.1:9223"
            }))
            .is_err()
        );
        assert!(
            validate_target_list_input(&serde_json::json!({
                "cdp_endpoint": "http://127.0.0.1:0"
            }))
            .is_err()
        );
    }

    #[test]
    fn authorizes_file_urls_only_for_existing_regular_local_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let app_file = directory.path().join("application entry.js");
        std::fs::write(&app_file, b"export {};").expect("create app file");
        let encoded_path = app_file.display().to_string().replace(' ', "%20");
        let mut asar_headers = AsarHeaderCache::default();

        assert_eq!(
            authorized_local_file_path(&format!("file://{encoded_path}"), &mut asar_headers),
            Some(app_file.canonicalize().unwrap().display().to_string())
        );
        assert_eq!(
            authorized_local_file_path(
                &format!("file://localhost{encoded_path}"),
                &mut asar_headers
            ),
            None
        );
        assert_eq!(
            authorized_local_file_path("file://remote.example/tmp/app.js", &mut asar_headers),
            None
        );
        assert_eq!(
            authorized_local_file_path(
                "file:///tmp/missing-native-electron-file.js",
                &mut asar_headers
            ),
            None
        );
        assert_eq!(
            authorized_local_file_path("file:///tmp/%2fetc/passwd", &mut asar_headers),
            None
        );
        assert_eq!(
            authorized_local_file_path("file:///tmp/%zz", &mut asar_headers),
            None
        );
    }

    #[test]
    fn authorizes_regular_members_inside_asar_headers() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = directory.path().join("packaged app.asar");
        write_asar_archive(
            &archive,
            serde_json::json!({
                "index.html": {"size": 12, "offset": "0"},
                "assets": {
                    "files": {
                        "renderer.js": {"size": 20, "offset": "12"}
                    }
                },
                "directory": {"files": {}},
                "link.js": {"size": 12, "link": "index.html"}
            }),
        );

        let archive_url = archive.display().to_string().replace(' ', "%20");
        let member_url = format!("file://{archive_url}/assets/renderer.js");
        let mut cache = AsarHeaderCache::default();

        assert_eq!(
            authorized_local_file_path(&member_url, &mut cache),
            Some(format!(
                "{}/assets/renderer.js",
                archive.canonicalize().unwrap().display()
            ))
        );
        assert_eq!(
            authorized_local_file_path(&format!("file://{archive_url}/directory"), &mut cache),
            None
        );
        assert_eq!(
            authorized_local_file_path(&format!("file://{archive_url}/link.js"), &mut cache),
            None
        );
        assert_eq!(
            authorized_local_file_path(&format!("file://{archive_url}/missing.js"), &mut cache),
            None
        );
        assert_eq!(
            authorized_local_file_path(
                &format!("file://{archive_url}//assets/renderer.js"),
                &mut cache
            ),
            None
        );
    }

    #[test]
    fn refreshes_asar_header_cache_when_archive_identity_changes() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = directory.path().join("application.asar");
        let replacement = directory.path().join("replacement.asar");
        write_asar_archive(
            &archive,
            serde_json::json!({"old.js": {"size": 1, "offset": "0"}}),
        );
        write_asar_archive(
            &replacement,
            serde_json::json!({"new.js": {"size": 1, "offset": "0"}}),
        );

        let archive_url = archive.display().to_string();
        let mut cache = AsarHeaderCache::default();
        assert!(
            authorized_local_file_path(&format!("file://{archive_url}/old.js"), &mut cache)
                .is_some()
        );

        fs::remove_file(&archive).expect("remove original archive");
        fs::rename(&replacement, &archive).expect("replace original archive");

        assert_eq!(
            authorized_local_file_path(&format!("file://{archive_url}/old.js"), &mut cache),
            None
        );
        assert!(
            authorized_local_file_path(&format!("file://{archive_url}/new.js"), &mut cache)
                .is_some()
        );
    }

    #[test]
    fn rejects_asar_headers_over_the_decode_budget_before_reading_json() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let archive = directory.path().join("large-header.asar");
        let header_bytes = u32::try_from(MAX_ASAR_HEADER_BYTES + 1).expect("test bound fits u32");
        let payload_bytes = header_bytes - 4;
        let json_bytes = 1_u32;
        let mut prefix = Vec::with_capacity(16);
        prefix.extend_from_slice(&4_u32.to_le_bytes());
        prefix.extend_from_slice(&header_bytes.to_le_bytes());
        prefix.extend_from_slice(&payload_bytes.to_le_bytes());
        prefix.extend_from_slice(&json_bytes.to_le_bytes());
        fs::write(&archive, prefix).expect("write oversized ASAR prefix");
        File::options()
            .write(true)
            .open(&archive)
            .expect("open sparse oversized archive")
            .set_len(u64::from(header_bytes) + 8)
            .expect("size sparse archive");

        let mut cache = AsarHeaderCache::default();
        assert_eq!(
            authorized_local_file_path(
                &format!("file://{}/member.js", archive.display()),
                &mut cache
            ),
            None
        );
    }

    fn write_asar_archive(path: &Path, files: Value) {
        let encoded_json = serde_json::to_vec(&serde_json::json!({"files": files}))
            .expect("serialize ASAR file tree");
        let json_bytes = u32::try_from(encoded_json.len()).expect("fixture is within u32");
        let header_bytes = json_bytes.checked_add(8).expect("header length");
        let payload_bytes = header_bytes.checked_sub(4).expect("payload length");

        let mut archive = Vec::with_capacity(16 + encoded_json.len());
        archive.extend_from_slice(&4_u32.to_le_bytes());
        archive.extend_from_slice(&header_bytes.to_le_bytes());
        archive.extend_from_slice(&payload_bytes.to_le_bytes());
        archive.extend_from_slice(&json_bytes.to_le_bytes());
        archive.extend_from_slice(&encoded_json);
        fs::write(path, archive).expect("write ASAR header fixture");
    }

    #[test]
    fn rejects_malformed_browser_and_target_identity() {
        let mut browser = browser_version();
        browser.product.clear();
        assert_eq!(
            project_target_list(browser, &[])
                .expect_err("missing browser product is invalid")
                .code(),
            "invalid_endpoint_response"
        );

        let target = DiscoveredTarget {
            id: " ".into(),
            target_type: "page".into(),
            title: String::new(),
            url: String::new(),
            attached: None,
            has_validated_transport: true,
        };
        assert_eq!(
            project_target_list(browser_version(), &[target])
                .expect_err("missing target id is invalid")
                .code(),
            "invalid_endpoint_response"
        );
    }

    #[test]
    fn target_projection_stops_when_cancelled() {
        let cancellation = Cancellation::default();
        cancellation.cancel("test cancellation");

        let error = project_target_list_with_cancellation(browser_version(), &[], &cancellation)
            .expect_err("cancelled target projection must stop");

        assert_eq!(error.code(), "cancelled");
    }

    fn browser_version() -> BrowserVersion {
        BrowserVersion {
            product: "Electron/1".into(),
            protocol_version: "1.3".into(),
            revision: "r".into(),
            user_agent: "ua".into(),
            js_version: "v".into(),
        }
    }

    #[test]
    fn rejects_non_loopback_or_path_endpoints() {
        assert!(validate_endpoint("http://127.0.0.1:9223").is_ok());
        assert!(validate_endpoint("http://example.test:9223").is_err());
        assert!(validate_endpoint("http://127.0.0.1:9223/json").is_err());
    }

    #[test]
    fn preserves_page_facts_and_counts_scripts_from_projected_items() {
        let page = project_page_inspection(
            browser_version(),
            PageTarget {
                target_id: "target".into(),
                target_type: "page".into(),
                title: "Example".into(),
                file_path: "/tmp/index.html".into(),
                attached: None,
            },
            serde_json::json!({"observation_ms": 100}),
            serde_json::json!({"status": "complete_within_window"}),
            vec![],
            DomSummary {
                total_nodes: 0,
                nodes: vec![],
            },
            vec![Script {
                script_key: "scr_abc".into(),
                frame_id: None,
                file_path: "/tmp/main.js".into(),
                cdp_hash: None,
                length: Some(10),
                is_module: None,
                language: None,
                source: serde_json::json!({"included": false, "reason": "not_requested"}),
            }],
            vec![],
            vec![],
            vec!["Sources were not requested.".into()],
        )
        .expect("projection succeeds");

        assert_eq!(page.target.file_path, "/tmp/index.html");
        assert_eq!(page.scripts.total, 1);
        assert_eq!(page.scripts.items[0].file_path, "/tmp/main.js");
    }
}
