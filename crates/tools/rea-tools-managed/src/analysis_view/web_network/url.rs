//! Recorded transport-URL coordinates for grouping views.
//!
//! Compatibility owner: `src/domain/recordedTransportUrl.ts`
//! (`parseRecordedTransportUrl`, `parseUrlQueryParameterNames`). Views consume
//! only the origin, the raw recorded path and the WHATWG query spelling; the
//! credential span is owned by the capture producer and is not re-derived here.
//! WHATWG parsing (`URL.parse`) is the `url` crate, which implements the same
//! URL Standard.
use std::sync::OnceLock;
use url::Url;

/// Raw coordinates independent of WHATWG's normalized pathname.
pub struct RecordedUrl {
    pub origin: Option<String>,
    pub path: Option<String>,
    /// WHATWG query spelling, retaining an explicit empty delimiter; only on request.
    pub query: Option<String>,
}

/// `^[\x00-\x20]*(?:([A-Za-z][A-Za-z0-9+.-]*):)?\/\/`: prefix length and scheme.
fn match_prefix(value: &str) -> Option<(usize, Option<String>)> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] <= 0x20 {
        index += 1;
    }
    let mut scheme = None;
    if index < bytes.len() && bytes[index].is_ascii_alphabetic() {
        let mut end = index + 1;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'+' | b'.' | b'-'))
        {
            end += 1;
        }
        if bytes.get(end) == Some(&b':')
            && bytes.get(end + 1) == Some(&b'/')
            && bytes.get(end + 2) == Some(&b'/')
        {
            scheme = Some(value[index..end].to_owned());
            index = end + 1;
        }
    }
    if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
        Some((index + 2, scheme))
    } else {
        None
    }
}

/// `/^[A-Za-z][A-Za-z0-9+.-]*:\/\//u.test(value)`.
fn explicit_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    let mut end = 1;
    while end < bytes.len()
        && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'+' | b'.' | b'-'))
    {
        end += 1;
    }
    bytes.get(end) == Some(&b':')
        && bytes.get(end + 1) == Some(&b'/')
        && bytes.get(end + 2) == Some(&b'/')
}

fn reference_base() -> &'static Option<Url> {
    static BASE: OnceLock<Option<Url>> = OnceLock::new();
    BASE.get_or_init(|| Url::parse("https://rea.invalid").ok())
}

/// `URL.prototype.search`: `""` for an absent or empty query.
fn search(url: &Url) -> String {
    match url.query() {
        Some(query) if !query.is_empty() => format!("?{query}"),
        _ => String::new(),
    }
}

/// `parseRecordedTransportUrl(value, { includeQuery })` (origin/path/query only).
pub fn parse_recorded_transport_url(value: &str, include_query: bool) -> RecordedUrl {
    let prefix = match_prefix(value);
    let absolute = Url::parse(value).ok();
    let parsed = absolute.clone().or_else(|| {
        reference_base()
            .as_ref()
            .and_then(|base| base.join(value).ok())
    });
    let origin = absolute
        .as_ref()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null");
    let Some((authority_start, scheme)) = prefix else {
        return RecordedUrl {
            origin,
            path: None,
            query: None,
        };
    };
    let protocol = match &parsed {
        Some(url) => format!("{}:", url.scheme()),
        None => format!(
            "{}:",
            scheme.map_or_else(|| "https".to_owned(), |text| text.to_ascii_lowercase())
        ),
    };
    let special = matches!(
        protocol.as_str(),
        "ftp:" | "file:" | "http:" | "https:" | "ws:" | "wss:"
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
    let stable_authority = !authority.is_empty() && !authority.contains(['\t', '\n', '\r']);
    if origin.is_none()
        || !explicit_scheme(value)
        || !stable_authority
        || (special && bytes.get(authority_end) == Some(&b'\\'))
    {
        return RecordedUrl {
            origin,
            path: None,
            query: None,
        };
    }
    let hash = value[authority_end..]
        .find('#')
        .map(|at| at + authority_end);
    let question = value[authority_end..]
        .find('?')
        .map(|at| at + authority_end);
    let has_query = question.is_some_and(|question| hash.is_none_or(|hash| question < hash));
    let query = include_query.then(|| {
        let spelled = absolute.as_ref().map(search).unwrap_or_default();
        if spelled.is_empty() && has_query {
            "?".to_owned()
        } else {
            spelled
        }
    });
    if bytes.get(authority_end) != Some(&b'/') {
        return RecordedUrl {
            origin,
            path: Some("/".into()),
            query,
        };
    }
    let mut path_end = authority_end;
    while path_end < bytes.len() && !matches!(bytes[path_end], b'?' | b'#') {
        path_end += 1;
    }
    RecordedUrl {
        origin,
        path: Some(value[authority_end..path_end].to_owned()),
        query,
    }
}

/// `formComponent`: WHATWG `application/x-www-form-urlencoded` decoding of one
/// component (`+` is a space, malformed escapes stay literal, invalid UTF-8
/// becomes U+FFFD).
fn form_component(raw: &str) -> String {
    if !raw.contains(['%', '+']) {
        return raw.to_owned();
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'+' {
            decoded.push(b' ');
            index += 1;
            continue;
        }
        if byte == b'%'
            && let (Some(high), Some(low)) = (
                bytes
                    .get(index + 1)
                    .and_then(|digit| (*digit as char).to_digit(16)),
                bytes
                    .get(index + 2)
                    .and_then(|digit| (*digit as char).to_digit(16)),
            )
        {
            decoded.push((high * 16 + low) as u8);
            index += 3;
            continue;
        }
        decoded.push(byte);
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// `parseUrlQueryParameterNames`: names in order, keeping repeats and empty names.
pub fn query_parameter_names(query: &str) -> Vec<String> {
    let mut names = Vec::new();
    let bytes = query.as_bytes();
    let mut start = usize::from(query.starts_with('?'));
    let find = |byte: u8, from: usize| {
        bytes[from.min(bytes.len())..]
            .iter()
            .position(|item| *item == byte)
            .map(|at| at + from)
    };
    let mut equals = find(b'=', start);
    while start < bytes.len() {
        let end = find(b'&', start).unwrap_or(bytes.len());
        if end > start {
            let name_end = match equals {
                Some(at) if at >= start && at < end => at,
                _ => end,
            };
            names.push(form_component(&query[start..name_end]));
        }
        start = end + 1;
        if equals.is_some_and(|at| at < start) {
            equals = find(b'=', start);
        }
    }
    names
}
