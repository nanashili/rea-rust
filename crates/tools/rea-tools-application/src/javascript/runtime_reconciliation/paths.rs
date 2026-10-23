//! Lexical path and URL helpers with the exact semantics the original takes
//! from Node's `path.posix`, `path.win32` and the WHATWG `URL` API.
//!
//! Compatibility owners: `normalizeJoinedLogicalPath` and
//! `logicalPathEscapesRoot` (`src/domain/artifactIdentity.ts`), and the
//! private path helpers of `javascriptRuntimeStaticCandidates.ts`.
use unicode_normalization::UnicodeNormalization;

/// Node `normalizeString` over already-split segments.
fn normalize_segments<'a>(
    segments: impl Iterator<Item = &'a str>,
    allow_above_root: bool,
) -> Vec<&'a str> {
    let mut stack: Vec<&str> = Vec::new();
    for segment in segments {
        match segment {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|last| *last != "..") {
                    stack.pop();
                } else if allow_above_root {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    stack
}

/// `path.posix.normalize`.
pub fn posix_normalize(path: &str) -> String {
    if path.is_empty() {
        return ".".into();
    }
    let absolute = path.starts_with('/');
    let trailing = path.ends_with('/');
    let joined = normalize_segments(path.split('/'), !absolute).join("/");
    if joined.is_empty() {
        if absolute {
            return "/".into();
        }
        return if trailing { "./".into() } else { ".".into() };
    }
    let mut out = if absolute {
        format!("/{joined}")
    } else {
        joined
    };
    if trailing {
        out.push('/');
    }
    out
}

/// `path.posix.join(left, right)`.
pub fn posix_join(left: &str, right: &str) -> String {
    let joined = match (left.is_empty(), right.is_empty()) {
        (true, true) => return ".".into(),
        (true, false) => right.to_owned(),
        (false, true) => left.to_owned(),
        (false, false) => format!("{left}/{right}"),
    };
    posix_normalize(&joined)
}

/// `path.posix.relative(from, to)` for absolute operands.
pub fn posix_relative(from: &str, to: &str) -> String {
    let from = normalize_segments(from.split('/'), false);
    let to = normalize_segments(to.split('/'), false);
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut parts: Vec<&str> = std::iter::repeat_n("..", from.len() - common).collect();
    parts.extend(&to[common..]);
    parts.join("/")
}

/// Split a Windows absolute path into its root and remaining segments.
fn win32_split(path: &str) -> (String, Vec<String>) {
    let unified = path.replace('/', "\\");
    if let Some(rest) = unified.strip_prefix("\\\\") {
        let mut parts = rest.split('\\');
        let server = parts.next().unwrap_or_default();
        let share = parts.next().unwrap_or_default();
        let segments = normalize_segments(parts, false);
        return (
            format!("\\\\{server}\\{share}"),
            segments.into_iter().map(str::to_owned).collect(),
        );
    }
    let (root, rest) = unified.split_at(unified.len().min(2));
    let segments = normalize_segments(rest.split('\\'), false);
    (
        root.to_owned(),
        segments.into_iter().map(str::to_owned).collect(),
    )
}

/// `path.win32.relative(from, to)` for absolute operands: case-insensitive
/// comparison; differing roots return the resolved destination.
pub fn win32_relative(from: &str, to: &str) -> String {
    let (from_root, from_parts) = win32_split(from);
    let (to_root, to_parts) = win32_split(to);
    if !from_root.eq_ignore_ascii_case(&to_root) {
        let mut out = to_root;
        out.push('\\');
        out.push_str(&to_parts.join("\\"));
        return out;
    }
    let common = from_parts
        .iter()
        .zip(&to_parts)
        .take_while(|(left, right)| left.to_lowercase() == right.to_lowercase())
        .count();
    let mut parts: Vec<&str> = std::iter::repeat_n("..", from_parts.len() - common).collect();
    parts.extend(to_parts[common..].iter().map(String::as_str));
    parts.join("\\")
}

/// `path.win32.isAbsolute`.
pub fn win32_is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    match bytes.first() {
        Some(b'/' | b'\\') => true,
        Some(letter) if letter.is_ascii_alphabetic() => {
            bytes.get(1) == Some(&b':') && matches!(bytes.get(2), Some(b'/' | b'\\'))
        }
        _ => false,
    }
}

/// `/^[a-z]:/iu`.
pub fn starts_with_drive(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':')
}

/// `normalizeJoinedLogicalPath`.
pub fn normalize_joined_logical_path(value: &str) -> String {
    if value.contains('\0') {
        return value.to_owned();
    }
    let normalized = posix_normalize(value);
    let stripped = normalized.strip_prefix("./").unwrap_or(&normalized);
    stripped.nfc().collect()
}

/// `logicalPathEscapesRoot`.
pub fn logical_path_escapes_root(path: &str) -> bool {
    path.contains('\0') || path == ".." || path.starts_with("../") || path.starts_with('/')
}

/// `relativeLogicalPath`.
pub fn relative_logical_path(value: &str) -> Option<String> {
    let normalized = normalize_joined_logical_path(value);
    (!normalized.is_empty() && normalized != "." && !logical_path_escapes_root(&normalized))
        .then_some(normalized)
}

/// `absoluteFilePathStyle`.
pub fn absolute_file_path_style(path: &str) -> Option<&'static str> {
    let bytes = path.as_bytes();
    let drive = bytes.first().is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(1) == Some(&b':')
        && matches!(bytes.get(2), Some(b'/' | b'\\'));
    if drive || is_unc(path) {
        return Some("windows");
    }
    path.starts_with('/').then_some("posix")
}

/// `/^(?:\\\\|\/\/)[^\\/]+[\\/][^\\/]+(?:[\\/]|$)/u`.
fn is_unc(path: &str) -> bool {
    let Some(rest) = path
        .strip_prefix("\\\\")
        .or_else(|| path.strip_prefix("//"))
    else {
        return false;
    };
    let separator = |c: char| c == '/' || c == '\\';
    let Some(server_end) = rest.find(separator) else {
        return false;
    };
    if server_end == 0 {
        return false;
    }
    let share = &rest[server_end + 1..];
    let share_len = share.find(separator).unwrap_or(share.len());
    share_len > 0
}

/// `isPortableAbsolutePath` in `JavaScriptRuntimeReconciliationService.ts`.
pub fn is_portable_absolute_path(path: &str) -> bool {
    absolute_file_path_style(path).is_some()
}

/// `pathBelowRoot`.
pub fn path_below_root(root: &str, value: &str) -> Option<String> {
    let style = absolute_file_path_style(root)?;
    if absolute_file_path_style(value) != Some(style) {
        return None;
    }
    let windows = style == "windows";
    let remainder = if windows {
        win32_relative(root, value)
    } else {
        posix_relative(root, value)
    };
    let portable = if windows {
        remainder.replace('\\', "/")
    } else {
        remainder.clone()
    };
    if remainder.is_empty()
        || (windows && win32_is_absolute(&remainder))
        || portable == ".."
        || portable.starts_with("../")
    {
        return None;
    }
    relative_logical_path(&portable)
}

/// `decodeURIComponent`; `None` for malformed escapes or invalid UTF-8.
fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            let text = std::str::from_utf8(hex).ok()?;
            out.push(u8::from_str_radix(text, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// `pathBelowUrlPrefix`.
pub fn path_below_url_prefix(prefix: &str, value: &str) -> Option<String> {
    let base = url::Url::parse(prefix).ok()?;
    let candidate = url::Url::parse(value).ok()?;
    if base.origin().ascii_serialization() != candidate.origin().ascii_serialization()
        || !candidate.path().starts_with(base.path())
    {
        return None;
    }
    relative_logical_path(&decode_uri_component(
        &candidate.path()[base.path().len()..],
    )?)
}

/// `urlDeclaresQueryOrFragment`.
pub fn declares_query_or_fragment(url: &url::Url) -> bool {
    url.as_str().contains('?') || url.as_str().contains('#')
}

/// `normalizeRuntimeUrlPrefix`.
pub fn normalize_runtime_url_prefix(value: &str) -> Option<String> {
    let mut url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || declares_query_or_fragment(&url)
    {
        return None;
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Some(url.as_str().to_owned())
}

/// `isLiteralLoopbackHostname`.
fn loopback(url: &url::Url) -> bool {
    matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
}

fn plain_authority(url: &url::Url) -> bool {
    url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none_or(str::is_empty)
        && !declares_query_or_fragment(url)
}

/// `httpDiscoveryOrigin`.
pub fn http_discovery_origin(url: &url::Url) -> bool {
    url.scheme() == "http" && loopback(url) && plain_authority(url) && url.path() == "/"
}

/// `browserSocketAuthority(url) !== undefined` with the redacted path.
pub fn redacted_browser_socket(url: &url::Url) -> bool {
    url.scheme() == "ws"
        && loopback(url)
        && plain_authority(url)
        && url.path() == "/devtools/browser/[REDACTED]"
}

/// `parseExactOrigin`.
pub fn exact_origin(value: &str) -> Option<String> {
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_some_and(|host| host.contains('*'))
        || !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || url.path() != "/"
        || declares_query_or_fragment(&url)
    {
        return None;
    }
    Some(url.origin().ascii_serialization())
}

/// `isPathWithinRoot` on a POSIX host.
pub fn is_path_within_root(root: &str, path: &str) -> bool {
    let value = posix_relative(root, path);
    value.is_empty() || (value != ".." && !value.starts_with("../") && !value.starts_with('/'))
}
