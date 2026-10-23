//! WHATWG URL facts shared by CDP endpoint, origin and target projections.
//!
//! Compatibility owners: `src/domain/browserObservation.ts`
//! (`sanitizeBrowserUrl`, `browserOriginSchema`, `isLiteralLoopbackHostname`),
//! `src/domain/recordedTransportUrl.ts` (credential span of
//! `parseRecordedTransportUrl`) and `src/domain/urlComponents.ts`.
use regex::Regex;
use std::sync::OnceLock;
use url::Url;

/// `URL.parse(value)`: an absolute WHATWG URL or nothing.
pub(crate) fn parse(value: &str) -> Option<Url> {
    Url::parse(value).ok()
}

/// `new URL(value, base)`: the base must itself parse.
#[cfg(feature = "browser")]
pub(crate) fn parse_with_base(value: &str, base: &str) -> Option<Url> {
    let base = Url::parse(base).ok()?;
    Url::options().base_url(Some(&base)).parse(value).ok()
}

/// `url.origin`, including the literal `"null"` of opaque origins.
pub(crate) fn origin(url: &Url) -> String {
    url.origin().ascii_serialization()
}

/// `url.port`: empty when absent or the scheme default.
pub(crate) fn port(url: &Url) -> String {
    url.port().map(|port| port.to_string()).unwrap_or_default()
}

/// `url.host`: hostname plus an explicit non-default port.
pub(crate) fn host(url: &Url) -> String {
    let hostname = url.host_str().unwrap_or_default();
    match url.port() {
        Some(port) => format!("{hostname}:{port}"),
        None => hostname.to_owned(),
    }
}

/// `urlDeclaresQueryOrFragment`: the serialized href spells `?` or `#`.
pub(crate) fn declares_query_or_fragment(url: &Url) -> bool {
    url.as_str().contains('?') || url.as_str().contains('#')
}

/// `isLiteralLoopbackHostname`.
pub(crate) fn is_literal_loopback_hostname(hostname: &str) -> bool {
    matches!(hostname, "127.0.0.1" | "[::1]" | "::1")
}

/// `parseExactOrigin`: one exact HTTP(S) origin without path or wildcard.
pub(crate) fn exact_origin(value: &str) -> Option<String> {
    let url = parse(value)?;
    let hostname = url.host_str().unwrap_or_default();
    if !matches!(url.scheme(), "http" | "https")
        || hostname.contains('*')
        || !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || url.path() != "/"
        || declares_query_or_fragment(&url)
    {
        return None;
    }
    Some(origin(&url))
}

fn has_credentials(url: &Url) -> bool {
    !url.username().is_empty() || url.password().is_some_and(|password| !password.is_empty())
}

/// `sanitizeBrowserUrl(value)`: the credential-free URL and its origin.
pub(crate) struct SanitizedUrl {
    pub url: String,
    pub origin: Option<String>,
}

/// Preserve local URL data while removing only URL userinfo credentials.
pub(crate) fn sanitize_browser_url(value: &str) -> SanitizedUrl {
    let Some(parsed) = parse(value) else {
        return SanitizedUrl {
            url: value.to_owned(),
            origin: None,
        };
    };
    let serialized = origin(&parsed);
    let url = if has_credentials(&parsed) {
        remove_url_user_info(value, &parsed)
    } else {
        value.to_owned()
    };
    SanitizedUrl {
        url,
        origin: (serialized != "null").then_some(serialized),
    }
}

fn remove_url_user_info(value: &str, parsed: &Url) -> String {
    match credential_span(value, parsed) {
        Some((start, end)) => format!("{}{}", &value[..start], &value[end..]),
        None => {
            let mut stripped = parsed.clone();
            let _ = stripped.set_username("");
            let _ = stripped.set_password(None);
            stripped.as_str().to_owned()
        }
    }
}

/// The raw credential span of `parseRecordedTransportUrl` for an absolute
/// URL with parsed credentials; `None` is its `"ambiguous"` outcome.
fn credential_span(value: &str, parsed: &Url) -> Option<(usize, usize)> {
    static PREFIX: OnceLock<Regex> = OnceLock::new();
    let prefix = PREFIX.get_or_init(|| {
        Regex::new(r"^[\x00-\x20]*(?:([A-Za-z][A-Za-z0-9+.\-]*):)?//").expect("prefix")
    });
    let matched = prefix.find(value)?;
    let authority_start = matched.end();
    let special = matches!(
        parsed.scheme(),
        "ftp" | "file" | "http" | "https" | "ws" | "wss"
    );
    let bytes = value.as_bytes();
    let mut authority_end = authority_start;
    while authority_end < bytes.len()
        && !matches!(bytes[authority_end], b'/' | b'?' | b'#')
        && !(special && bytes[authority_end] == b'\\')
    {
        authority_end += 1;
    }
    let authority = &value[authority_start..authority_end];
    let stable = !authority.is_empty() && !authority.contains(['\t', '\n', '\r']);
    if !stable {
        return None;
    }
    authority
        .rfind('@')
        .map(|at| (authority_start, authority_start + at + 1))
}
