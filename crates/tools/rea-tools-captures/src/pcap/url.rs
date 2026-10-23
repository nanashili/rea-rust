//! Transport-URL credential parsing used for HTTP request-URI redaction.
//!
//! Compatibility owner: `src/domain/recordedTransportUrl.ts`. Only the
//! `credentials` disposition is consumed by `parseTsharkJsonOutput`: either a
//! redactable `{ start, end }` byte span, the sentinel `ambiguous`, or `null`
//! when no transport credentials are present. The WHATWG spellings that the
//! original recognizes through `URL.parse` are approximated here with an
//! authority scan; see the deviations note in the family report.

/// Credential disposition of one recorded transport URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Credentials {
    /// Parsed credentials exist but no safe raw span can be projected.
    Ambiguous,
    /// A redactable `[start, end)` byte span within the original string.
    Span { start: usize, end: usize },
    /// No transport credentials present.
    None,
}

/// Length in bytes of the leading `[\x00-\x20]*(scheme:)?//` prefix, and the
/// recognized scheme (lowercased) when one was present before `//`.
struct Prefix {
    length: usize,
    scheme: Option<String>,
}

/// Match the WHATWG-style special-authority prefix the original regex matched:
/// `^[\x00-\x20]*(?:([A-Za-z][A-Za-z0-9+.-]*):)?\/\/`.
fn match_prefix(value: &str) -> Option<Prefix> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && bytes[index] <= 0x20 {
        index += 1;
    }
    let scheme_start = index;
    let mut scheme: Option<String> = None;
    // Optional scheme followed by a colon.
    if index < bytes.len() && bytes[index].is_ascii_alphabetic() {
        let mut end = index + 1;
        while end < bytes.len()
            && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'+' | b'.' | b'-'))
        {
            end += 1;
        }
        if end < bytes.len() && bytes[end] == b':' {
            scheme = Some(value[scheme_start..end].to_ascii_lowercase());
            index = end + 1;
        }
    }
    // Require `//`.
    if bytes.get(index) == Some(&b'/') && bytes.get(index + 1) == Some(&b'/') {
        Some(Prefix {
            length: index + 2,
            scheme,
        })
    } else {
        None
    }
}

/// `^[A-Za-z][A-Za-z0-9+.-]*:\/\/` — an explicit, unpadded scheme://authority.
fn has_explicit_scheme_authority(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_alphabetic() {
        return false;
    }
    let mut index = 1;
    while index < bytes.len()
        && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'+' | b'.' | b'-'))
    {
        index += 1;
    }
    bytes.get(index) == Some(&b':')
        && bytes.get(index + 1) == Some(&b'/')
        && bytes.get(index + 2) == Some(&b'/')
}

/// Return the credential disposition of a recorded transport URL value.
///
/// The original also projects an `origin`/`path`; only `credentials` is used
/// by the capture inventory, so the port computes just that.
pub fn credentials(value: &str) -> Credentials {
    let Some(prefix) = match_prefix(value) else {
        // No `//` authority: credentials can only be WHATWG-ambiguous, which
        // this approximation never recognizes without a reference parser.
        return Credentials::None;
    };

    let authority_start = prefix.length;
    let scheme = prefix.scheme.as_deref();
    let special = matches!(
        scheme,
        Some("ftp" | "file" | "http" | "https" | "ws" | "wss")
    ) || scheme.is_none();

    let bytes = value.as_bytes();
    let mut authority_end = authority_start;
    while authority_end < bytes.len() {
        let byte = bytes[authority_end];
        if matches!(byte, b'/' | b'?' | b'#') {
            break;
        }
        if special && byte == b'\\' {
            break;
        }
        authority_end += 1;
    }
    let authority = &value[authority_start..authority_end.min(value.len())];
    let stable_authority = !authority.is_empty() && !authority.contains(['\t', '\n', '\r']);
    let at = authority.rfind('@');

    // Without a reference parser the port treats a stable authority containing
    // `user[:pass]@` as the only recognizable credential form.
    match (stable_authority, at) {
        (true, Some(at)) => Credentials::Span {
            start: authority_start,
            end: authority_start + at + 1,
        },
        _ => {
            // An unstable authority with recognizable credentials would be
            // ambiguous, but credential presence cannot be established here
            // without WHATWG resolution; treat as none. See report deviations.
            let _ = has_explicit_scheme_authority(value);
            Credentials::None
        }
    }
}
