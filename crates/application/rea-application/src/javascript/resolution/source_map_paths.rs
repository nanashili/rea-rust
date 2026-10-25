//! Source-map `sources` declarations: URL resolution exactly as the pinned
//! `@jridgewell/trace-mapping` 0.3.31 (`@jridgewell/resolve-uri` 3.1.2)
//! computes `resolvedSources`, then one interpretation of each resolved
//! reference as an artifact-relative path, a path suffix, or an explicit
//! unresolved reason.
//!
//! Compatibility owner: `javascriptSourceMapPaths.ts`.
use super::syntax::{
    contains_percent_escape, decode_uri_component, posix_dirname, posix_join, posix_normalize,
    posix_relative,
};
use super::web_url::{self, WebUrl};
use crate::javascript::semantic::value_types::JsString;
use serde::ser::{Serialize, SerializeStruct, Serializer};

/// How one source declaration maps onto the inventoried artifact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceMapResolution {
    ArtifactRelative { path: String },
    Suffix { path: String },
    Unresolved { reason: &'static str },
}

impl Serialize for SourceMapResolution {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Field order follows the TypeScript producer.
        let mut out = serializer.serialize_struct("SourceMapResolution", 2)?;
        match self {
            Self::ArtifactRelative { path } => {
                out.serialize_field("path", path)?;
                out.serialize_field("kind", "artifact-relative")?;
            }
            Self::Suffix { path } => {
                out.serialize_field("path", path)?;
                out.serialize_field("kind", "suffix")?;
            }
            Self::Unresolved { reason } => {
                out.serialize_field("kind", "unresolved")?;
                out.serialize_field("reason", reason)?;
            }
        }
        out.end()
    }
}

/// Map-scoped source declaration and its path interpretation for matching.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SourceMapReference {
    pub source_name: String,
    pub source_root: Option<String>,
    pub map_path: String,
    pub resolution: SourceMapResolution,
}

/// UTF-16-preserving form used by JavaScript artifact graph observations.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct SourceMapReferenceExact {
    pub source_name: JsString,
    pub source_root: Option<JsString>,
    pub map_path: String,
    pub resolution: SourceMapResolution,
}

/// `resolveJavaScriptSourceMapReferences`: interpret all declarations of one
/// map at its ingestion boundary. `None` entries stay `None`.
pub fn resolve_source_map_references(
    source_names: &[Option<String>],
    source_root: Option<&str>,
    map_path: &str,
) -> Vec<Option<SourceMapReference>> {
    source_names
        .iter()
        .map(|source_name| {
            let source_name = source_name.as_ref()?;
            let reference = trace_map_resolved_source(Some(source_name), source_root, "");
            Some(SourceMapReference {
                source_name: source_name.clone(),
                source_root: source_root.map(str::to_owned),
                map_path: map_path.to_owned(),
                resolution: resolve_source_map_path(&reference, map_path),
            })
        })
        .collect()
}

/// Resolve source declarations while preserving JavaScript UTF-16 strings.
///
/// A source name or root can contain an unpaired surrogate after JSON parsing.
/// Such a value has no lossless filesystem/URL interpretation, but its
/// identity still belongs in the observation.  The reference therefore keeps
/// the original `JsString` values and records an unresolved interpretation.
pub fn resolve_source_map_references_exact(
    source_names: &[Option<JsString>],
    source_root: Option<&JsString>,
    map_path: &str,
) -> Vec<Option<SourceMapReferenceExact>> {
    source_names
        .iter()
        .map(|source_name| {
            let source_name = source_name.as_ref()?;
            let resolution = match (source_name.as_str(), source_root.and_then(JsString::as_str)) {
                (Some(source_name), Some(source_root)) => {
                    let reference =
                        trace_map_resolved_source(Some(source_name), Some(source_root), "");
                    resolve_source_map_path(&reference, map_path)
                }
                (Some(source_name), None) if source_root.is_none() => {
                    let reference = trace_map_resolved_source(Some(source_name), None, "");
                    resolve_source_map_path(&reference, map_path)
                }
                _ => SourceMapResolution::Unresolved {
                    reason: UNRESOLVED_INVALID,
                },
            };
            Some(SourceMapReferenceExact {
                source_name: source_name.clone(),
                source_root: source_root.cloned(),
                map_path: map_path.to_owned(),
                resolution,
            })
        })
        .collect()
}

/// `resolveJavaScriptSourceMapUrl`: one declaration through the pinned
/// format implementation used by map consumers.
pub fn resolve_source_map_url(
    source: Option<&str>,
    source_root: Option<&str>,
    map_url: &str,
) -> String {
    trace_map_resolved_source(source, source_root, map_url)
}

/// `TraceMap#resolvedSources[i]` for one declaration.
fn trace_map_resolved_source(
    source: Option<&str>,
    source_root: Option<&str>,
    map_url: &str,
) -> String {
    let from = match map_url.rfind('/') {
        Some(index) => &map_url[..=index],
        None => "",
    };
    let prefix = match source_root {
        Some(root) if !root.is_empty() => format!("{root}/"),
        _ => String::new(),
    };
    resolve_uri(&format!("{prefix}{}", source.unwrap_or_default()), from)
}

const UNRESOLVED_INVALID: &str = "Source reference is not a valid URL or filesystem path.";
const UNRESOLVED_OPAQUE: &str =
    "Source reference uses a non-hierarchical URL without a file pathname.";
const UNRESOLVED_DIRECTORY: &str = "Source reference names a directory rather than a file.";
const UNRESOLVED_SEPARATOR: &str = "Source reference contains an encoded path separator.";
const UNRESOLVED_ENCODING: &str =
    "Source reference has malformed URL encoding or an invalid file URL.";
const UNRESOLVED_OUTSIDE: &str = "Source reference resolves outside the inventoried artifact.";

/// Resolve one URL reference without changing its recorded identity.
fn resolve_source_map_path(source: &str, map_path: &str) -> SourceMapResolution {
    let portable = source.replace('\\', "/");
    let windows_path = is_drive_slash(&portable) || source.starts_with("\\\\");
    // Preserve parent traversal rather than letting URL resolution clamp at '/'.
    let anchor = format!("/{}", "source/".repeat(portable.split('/').count() + 1));
    let directory = posix_join(&[&anchor, posix_dirname(map_path)]);
    let base = posix_file_url(&format!("{directory}/"));
    let absolute = if windows_path {
        windows_file_url(source)
    } else {
        web_url::parse(source, None)
    };
    let resolved = if windows_path {
        absolute.clone()
    } else {
        base.and_then(|base| web_url::parse(source, Some(&base)))
    };
    let Some(resolved) = resolved else {
        return SourceMapResolution::Unresolved {
            reason: UNRESOLVED_INVALID,
        };
    };
    if !resolved.pathname().starts_with('/') {
        return SourceMapResolution::Unresolved {
            reason: UNRESOLVED_OPAQUE,
        };
    }
    if resolved.pathname().ends_with('/') {
        return SourceMapResolution::Unresolved {
            reason: UNRESOLVED_DIRECTORY,
        };
    }
    // Reject separators in declarations, not escaped literal names in the owned base.
    let declared_path = if windows_path {
        absolute
            .as_ref()
            .map(|url| url.pathname().to_owned())
            .unwrap_or_default()
    } else {
        web_url::parse("file:///", None)
            .and_then(|base| web_url::parse(source, Some(&base)))
            .map(|url| url.pathname().to_owned())
            .unwrap_or_default()
    };
    if contains_percent_escape(&declared_path, &["2f", "5c"]) {
        return SourceMapResolution::Unresolved {
            reason: UNRESOLVED_SEPARATOR,
        };
    }
    let relative = match &absolute {
        None => !portable.starts_with('/'),
        Some(absolute) => absolute.href() != resolved.href(),
    };
    let Some(path) = decoded_url_path(&resolved) else {
        return SourceMapResolution::Unresolved {
            reason: UNRESOLVED_ENCODING,
        };
    };
    let value = if relative {
        posix_relative(&anchor, &path)
    } else {
        path.trim_start_matches('/').to_owned()
    };
    if value.is_empty() || value == ".." || value.starts_with("../") {
        return SourceMapResolution::Unresolved {
            reason: UNRESOLVED_OUTSIDE,
        };
    }
    if relative {
        SourceMapResolution::ArtifactRelative { path: value }
    } else {
        SourceMapResolution::Suffix { path: value }
    }
}

/// `/^[a-z]:\//iu`.
fn is_drive_slash(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/'
}

/// Node `pathToFileURL` path escaping (`node_url.cc` lookup table).
fn encode_file_path(path: &str, windows: bool) -> String {
    let mut out = String::with_capacity(path.len());
    for &byte in path.as_bytes() {
        let escape = byte <= 0x20
            || byte >= 0x7F
            || matches!(
                byte,
                b'"' | b'#'
                    | b'%'
                    | b'<'
                    | b'>'
                    | b'?'
                    | b'['
                    | b']'
                    | b'^'
                    | b'`'
                    | b'{'
                    | b'|'
                    | b'}'
                    | b'~'
            )
            || (byte == b'\\' && !windows);
        if byte == b'\\' && windows {
            out.push('/');
        } else if escape {
            out.push_str(&format!("%{byte:02X}"));
        } else {
            out.push(char::from(byte));
        }
    }
    out
}

/// `pathToFileURL(path, { windows: false })` for an absolute POSIX path.
fn posix_file_url(path: &str) -> Option<WebUrl> {
    let mut resolved = posix_normalize(path);
    if resolved.len() > 1 && resolved.ends_with('/') {
        resolved.pop();
    }
    if path.ends_with('/') && !resolved.ends_with('/') {
        resolved.push('/');
    }
    web_url::parse(
        &format!("file://{}", encode_file_path(&resolved, false)),
        None,
    )
}

/// URL delimiters/escapes rejected before IDNA can truncate or decode a host.
fn unusable_host(host: &str) -> bool {
    host.chars().any(|character| {
        matches!(
            character,
            '\0' | '\t'
                | '\n'
                | '\r'
                | ' '
                | '#'
                | '/'
                | ':'
                | '<'
                | '>'
                | '?'
                | '@'
                | '['
                | '\\'
                | ']'
                | '^'
                | '|'
                | '%'
        )
    })
}

/// `domainToASCII(host) !== ""`.
fn domain_to_ascii_nonempty(host: &str) -> bool {
    // Node's `domainToASCII` parses `ws://x` and sets the hostname.
    web_url::parse(&format!("ws://{host}/"), None).is_some_and(|url| !url.hostname().is_empty())
}

/// `pathToFileURL(path, { windows: true })` for drive and UNC paths;
/// `None` where the TypeScript caller declines or Node throws.
fn windows_file_url(path: &str) -> Option<WebUrl> {
    if let Some(rest) = path.strip_prefix("\\\\") {
        let host = rest.split('\\').next().unwrap_or_default();
        if unusable_host(host) || !domain_to_ascii_nonempty(host) {
            return None;
        }
        let host_end = rest.find('\\')?;
        if host_end == 0 {
            return None;
        }
        let resource = &rest[host_end..];
        return web_url::parse(
            &format!("file://{host}{}", encode_file_path(resource, true)),
            None,
        );
    }
    let resolved = win32_resolve_drive_absolute(path);
    let last = path.as_bytes().last().copied();
    let mut resolved = resolved;
    if matches!(last, Some(b'/' | b'\\')) && !resolved.ends_with('\\') {
        resolved.push('\\');
    }
    web_url::parse(
        &format!("file:///{}", encode_file_path(&resolved, true)),
        None,
    )
}

/// `path.win32.resolve` for a drive-absolute path (`X:` followed by a separator).
fn win32_resolve_drive_absolute(path: &str) -> String {
    let (drive, rest) = path.split_at(2);
    let mut stack: Vec<&str> = Vec::new();
    for segment in rest.split(['/', '\\']) {
        match segment {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            other => stack.push(other),
        }
    }
    format!("{drive}\\{}", stack.join("\\"))
}

/// The decoded path of a resolved reference; `None` for malformed encoding
/// or a file URL that `fileURLToPath` rejects.
fn decoded_url_path(url: &WebUrl) -> Option<String> {
    let hostname = url.hostname();
    if url.protocol() == "file:" {
        let windows = !hostname.is_empty() && hostname != "localhost";
        let pathname = url.pathname();
        if windows {
            if contains_percent_escape(pathname, &["2f", "5c"]) {
                return None;
            }
            let decoded = decode_uri_component(&pathname.replace('/', "\\"))?;
            let unicode_host = ada_url::Idna::unicode(hostname);
            return Some(format!("\\\\{unicode_host}{decoded}").replace('\\', "/"));
        }
        if !hostname.is_empty() || contains_percent_escape(pathname, &["2f"]) {
            return None;
        }
        return decode_uri_component(pathname);
    }
    Some(format!(
        "{}{}",
        url.host(),
        decode_uri_component(url.pathname())?
    ))
}

// ---------------------------------------------------------------------------
// `@jridgewell/resolve-uri` 3.1.2.

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum UrlType {
    Empty = 1,
    Hash = 2,
    Query = 3,
    RelativePath = 4,
    AbsolutePath = 5,
    SchemeRelative = 6,
    Absolute = 7,
}

#[derive(Clone, Debug)]
struct ParsedUri {
    scheme: String,
    user: String,
    host: String,
    port: String,
    path: String,
    query: String,
    hash: String,
    kind: UrlType,
}

fn is_word_scheme_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'.' | b'-')
}

/// ECMAScript `.` excludes line terminators.
fn take_until_line_terminator(value: &str) -> &str {
    let end = value
        .find(['\n', '\r', '\u{2028}', '\u{2029}'])
        .unwrap_or(value.len());
    &value[..end]
}

/// `/^[\w+.-]+:\/\//`.
fn is_absolute_uri(input: &str) -> bool {
    let bytes = input.as_bytes();
    let scheme = bytes
        .iter()
        .take_while(|byte| is_word_scheme_byte(**byte))
        .count();
    scheme > 0 && input[scheme..].starts_with("://")
}

/// `/^[.?#]/`.
fn is_relative_uri(input: &str) -> bool {
    matches!(input.as_bytes().first(), Some(b'.' | b'?' | b'#'))
}

/// Split `?query` and `#hash` exactly as `(\?[^#]*)?(#.*)?` does after a path.
fn query_and_hash(rest: &str) -> (String, String) {
    let mut rest = rest;
    let mut query = String::new();
    if rest.starts_with('?') {
        let end = rest.find('#').unwrap_or(rest.len());
        query = rest[..end].to_owned();
        rest = &rest[end..];
    }
    let hash = if rest.starts_with('#') {
        take_until_line_terminator(rest).to_owned()
    } else {
        String::new()
    };
    (query, hash)
}

/// `urlRegex` match of an absolute URL.
fn parse_absolute_uri(input: &str) -> ParsedUri {
    let scheme_end = input
        .bytes()
        .take_while(|byte| is_word_scheme_byte(*byte))
        .count();
    let scheme = format!("{}:", &input[..scheme_end]);
    let mut rest = &input[scheme_end + 3..];
    let mut user = String::new();
    let user_end = rest.find(['@', '/', '#', '?']);
    if let Some(end) = user_end
        && rest.as_bytes()[end] == b'@'
    {
        user = rest[..=end].to_owned();
        rest = &rest[end + 1..];
    }
    let host_end = rest.find([':', '/', '#', '?']).unwrap_or(rest.len());
    let host = rest[..host_end].to_owned();
    rest = &rest[host_end..];
    let mut port = String::new();
    if let Some(after) = rest.strip_prefix(':') {
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            port = rest[..=digits].to_owned();
            rest = &rest[digits + 1..];
        }
    }
    let mut path = "/".to_owned();
    if rest.starts_with('/') {
        let end = rest.find(['#', '?']).unwrap_or(rest.len());
        path = rest[..end].to_owned();
        rest = &rest[end..];
    }
    let (query, hash) = if rest.starts_with(['?', '#']) {
        query_and_hash(rest)
    } else {
        (String::new(), String::new())
    };
    ParsedUri {
        scheme,
        user,
        host,
        port,
        path,
        query,
        hash,
        kind: UrlType::Absolute,
    }
}

/// `fileRegex` (case-insensitive) match of a `file:` URL.
fn parse_file_uri(input: &str) -> ParsedUri {
    let mut rest = &input[5..];
    let mut host = String::new();
    if let Some(after) = rest.strip_prefix("//") {
        rest = after;
        let bytes = rest.as_bytes();
        let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
        if !drive {
            let end = rest.find(['/', '#', '?']).unwrap_or(rest.len());
            host = rest[..end].to_owned();
            rest = &rest[end..];
        }
    }
    let end = rest.find(['#', '?']).unwrap_or(rest.len());
    let raw_path = &rest[..end];
    let (query, hash) = query_and_hash(&rest[end..]);
    let path = if raw_path.starts_with('/') {
        raw_path.to_owned()
    } else {
        format!("/{raw_path}")
    };
    ParsedUri {
        scheme: "file:".into(),
        user: String::new(),
        host,
        port: String::new(),
        path,
        query,
        hash,
        kind: UrlType::Absolute,
    }
}

fn parse_uri(input: &str) -> ParsedUri {
    if input.starts_with("//") {
        let mut url = parse_absolute_uri(&format!("http:{input}"));
        url.scheme = String::new();
        url.kind = UrlType::SchemeRelative;
        return url;
    }
    if input.starts_with('/') {
        let mut url = parse_absolute_uri(&format!("http://foo.com{input}"));
        url.scheme = String::new();
        url.host = String::new();
        url.kind = UrlType::AbsolutePath;
        return url;
    }
    if input.starts_with("file:") {
        return parse_file_uri(input);
    }
    if is_absolute_uri(input) {
        return parse_absolute_uri(input);
    }
    let mut url = parse_absolute_uri(&format!("http://foo.com/{input}"));
    url.scheme = String::new();
    url.host = String::new();
    url.kind = if input.is_empty() {
        UrlType::Empty
    } else if input.starts_with('?') {
        UrlType::Query
    } else if input.starts_with('#') {
        UrlType::Hash
    } else {
        UrlType::RelativePath
    };
    url
}

fn strip_path_filename(path: &str) -> String {
    if path.ends_with("/..") {
        return path.to_owned();
    }
    match path.rfind('/') {
        Some(index) => path[..=index].to_owned(),
        None => String::new(),
    }
}

fn merge_paths(url: &mut ParsedUri, base: &mut ParsedUri) {
    let kind = base.kind;
    normalize_uri_path(base, kind);
    if url.path == "/" {
        url.path.clone_from(&base.path);
    } else {
        url.path = format!("{}{}", strip_path_filename(&base.path), url.path);
    }
}

fn normalize_uri_path(url: &mut ParsedUri, kind: UrlType) {
    let relative = kind <= UrlType::RelativePath;
    let mut pieces: Vec<String> = url.path.split('/').map(str::to_owned).collect();
    let mut pointer = 1;
    let mut positive = 0_usize;
    let mut add_trailing_slash = false;
    for index in 1..pieces.len() {
        let piece = pieces[index].clone();
        if piece.is_empty() {
            add_trailing_slash = true;
            continue;
        }
        add_trailing_slash = false;
        if piece == "." {
            continue;
        }
        if piece == ".." {
            if positive > 0 {
                add_trailing_slash = true;
                positive -= 1;
                pointer -= 1;
            } else if relative {
                pieces[pointer] = piece;
                pointer += 1;
            }
            continue;
        }
        pieces[pointer] = piece;
        pointer += 1;
        positive += 1;
    }
    let mut path = String::new();
    for piece in &pieces[1..pointer] {
        path.push('/');
        path.push_str(piece);
    }
    if path.is_empty() || (add_trailing_slash && !path.ends_with("/..")) {
        path.push('/');
    }
    url.path = path;
}

/// `@jridgewell/resolve-uri` default export.
pub fn resolve_uri(input: &str, base: &str) -> String {
    if input.is_empty() && base.is_empty() {
        return String::new();
    }
    let mut url = parse_uri(input);
    let mut input_kind = url.kind;
    if !base.is_empty() && input_kind != UrlType::Absolute {
        let mut base_url = parse_uri(base);
        let base_kind = base_url.kind;
        let kind = input_kind;
        if kind == UrlType::Empty {
            url.hash.clone_from(&base_url.hash);
        }
        if kind <= UrlType::Hash {
            url.query.clone_from(&base_url.query);
        }
        if kind <= UrlType::RelativePath {
            merge_paths(&mut url, &mut base_url);
        }
        if kind <= UrlType::AbsolutePath {
            url.user.clone_from(&base_url.user);
            url.host.clone_from(&base_url.host);
            url.port.clone_from(&base_url.port);
        }
        if kind <= UrlType::SchemeRelative {
            url.scheme.clone_from(&base_url.scheme);
        }
        if base_kind > input_kind {
            input_kind = base_kind;
        }
    }
    normalize_uri_path(&mut url, input_kind);
    let query_hash = format!("{}{}", url.query, url.hash);
    match input_kind {
        UrlType::Hash | UrlType::Query => query_hash,
        UrlType::RelativePath => {
            let path = &url.path[1..];
            if path.is_empty() {
                return if query_hash.is_empty() {
                    ".".into()
                } else {
                    query_hash
                };
            }
            let anchor = if base.is_empty() { input } else { base };
            if is_relative_uri(anchor) && !is_relative_uri(path) {
                return format!("./{path}{query_hash}");
            }
            format!("{path}{query_hash}")
        }
        UrlType::AbsolutePath => format!("{}{query_hash}", url.path),
        _ => format!(
            "{}//{}{}{}{}{query_hash}",
            url.scheme, url.user, url.host, url.port, url.path
        ),
    }
}
