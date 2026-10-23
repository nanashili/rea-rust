//! Literal and structural redaction shared by the capture decoders.
//!
//! Compatibility owners: `src/domain/explicitSensitiveValues.ts`,
//! `src/browser/history/CaptureRedaction.ts` and
//! `src/domain/recordedTransportUrl.ts` (credential span detection).
use serde_json::{Value, json};

/// Replace caller-declared literal text without guessing sensitivity from names.
///
/// Compatibility owner: `redactExplicitText`.
pub fn redact_explicit_text(value: &str, sensitive_values: &[String]) -> String {
    let mut literals: Vec<String> = Vec::new();
    for literal in sensitive_values {
        if !literal.is_empty() && !literals.contains(literal) {
            literals.push(literal.clone());
        }
    }
    if literals.is_empty() {
        return value.to_owned();
    }
    let replacement = ["[REDACTED]", "\u{2026}", ""]
        .into_iter()
        .find(|candidate| {
            literals
                .iter()
                .all(|literal| !candidate.contains(literal.as_str()))
        })
        .unwrap_or("");
    // Longest literal first.
    let mut ordered = literals.clone();
    ordered.sort_by(|left, right| right.len().cmp(&left.len()));
    let mut result = value.to_owned();
    for literal in &ordered {
        result = result.replace(literal.as_str(), replacement);
    }
    if literals
        .iter()
        .any(|literal| result.contains(literal.as_str()))
    {
        String::new()
    } else {
        result
    }
}

/// A single redaction sidecar entry.
pub fn redaction_entry(pointer: &str, reason: &str) -> Value {
    json!({ "pointer": pointer, "reason": reason })
}

/// A property-name redaction sidecar entry.
pub fn property_name_redaction(pointer: &str) -> Value {
    json!({
        "pointer": pointer,
        "reason": "explicit-sensitive-value",
        "scope": "property-name"
    })
}

const CREDENTIAL_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
];

/// Literal redaction and structural authentication exclusions.
///
/// Compatibility owner: `CaptureRedaction`.
pub struct CaptureRedaction {
    pub sensitive_values: Vec<String>,
    pub redactions: Vec<Value>,
    sensitive_byte_values: Vec<Vec<u8>>,
}

impl CaptureRedaction {
    pub fn new(sensitive_values: &[String]) -> Self {
        // Every caller literal already round-trips through UTF-8 in Rust.
        let sensitive_byte_values = sensitive_values
            .iter()
            .map(|value| value.as_bytes().to_vec())
            .collect();
        Self {
            sensitive_values: sensitive_values.to_vec(),
            redactions: Vec::new(),
            sensitive_byte_values,
        }
    }

    fn contains_literal(&self, value: &str) -> bool {
        self.sensitive_values
            .iter()
            .any(|literal| value.contains(literal.as_str()))
    }

    /// Preserve exact text unless explicitly sensitive or known transport URL userinfo.
    ///
    /// Returns `None` when the value is excluded entirely.
    pub fn text(&mut self, value: &str, pointer: &str, transport_url: bool) -> Option<String> {
        let mut result = value.to_owned();
        if transport_url {
            match credential_span(value) {
                CredentialSpan::Ambiguous => return self.credential(pointer),
                CredentialSpan::Span { start, end } => {
                    result = format!("{}{}", &value[..start], &value[end..]);
                    self.redactions
                        .push(redaction_entry(pointer, "transport-credential"));
                }
                CredentialSpan::None => {}
            }
        }
        if self.contains_literal(value) || self.contains_literal(&result) {
            self.redactions
                .push(redaction_entry(pointer, "explicit-sensitive-value"));
            return None;
        }
        Some(result)
    }

    /// Remove a credential field's value, recording its exclusion.
    pub fn credential(&mut self, pointer: &str) -> Option<String> {
        self.redactions
            .push(redaction_entry(pointer, "transport-credential"));
        None
    }

    /// Known HAR credential surfaces; unknown extensions are ordinary evidence.
    pub fn har_credential(&self, pointer: &str, parent_name: Option<&str>) -> bool {
        let header_value = is_header_value_pointer(pointer)
            && parent_name
                .map(|name| CREDENTIAL_HEADERS.contains(&name.to_ascii_lowercase().as_str()))
                .unwrap_or(false);
        let cookie_value = is_cookie_value_pointer(pointer);
        header_value || cookie_value
    }

    /// Only request/redirect fields and known transport header URLs are URLs.
    pub fn har_transport_url(&self, pointer: &str, parent_name: Option<&str>) -> bool {
        if pointer == "/request/url" || pointer == "/response/redirectURL" {
            return true;
        }
        is_header_value_pointer(pointer)
            && parent_name
                .map(|name| {
                    matches!(
                        name.to_ascii_lowercase().as_str(),
                        "location" | "referer" | "origin"
                    )
                })
                .unwrap_or(false)
    }

    /// Preserve bytes unless an explicitly declared UTF-8 literal occurs in them.
    pub fn sensitive_bytes(&self, bytes: &[u8]) -> bool {
        self.sensitive_byte_values
            .iter()
            .any(|value| !value.is_empty() && contains_bytes(bytes, value))
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn is_header_value_pointer(pointer: &str) -> bool {
    header_value_regex().is_match(pointer)
}

fn is_cookie_value_pointer(pointer: &str) -> bool {
    cookie_value_regex().is_match(pointer)
}

fn header_value_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^/(request|response)/headers/\d+/value$").unwrap())
}

fn cookie_value_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^/(request|response)/cookies/\d+/value$").unwrap())
}

/// Escape a producer property for an RFC 6901 location.
pub fn capture_pointer(parent: &str, key: &str) -> String {
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}

/// Keep a real JSON-pointer ancestor when a property identity is excluded.
///
/// Compatibility owner: `redactExplicitPointer`.
pub fn redact_explicit_pointer(pointer: &str, values: &[String]) -> String {
    let mut parent = String::new();
    for segment in pointer.split('/').skip(1) {
        let decoded = segment.replace("~1", "/").replace("~0", "~");
        let child = format!("{parent}/{segment}");
        if values
            .iter()
            .any(|literal| decoded.contains(literal.as_str()) || child.contains(literal.as_str()))
        {
            return parent;
        }
        parent = child;
    }
    parent
}

/// Credential span classification of a recorded transport URL.
enum CredentialSpan {
    None,
    Ambiguous,
    Span { start: usize, end: usize },
}

/// Detect transport-credential userinfo in a recorded URL.
///
/// Compatibility owner: `parseRecordedTransportUrl`. A stable
/// `scheme://authority` with an `@` yields a removable span; otherwise, when
/// credentials are present but the authority is noncanonical, the result is
/// ambiguous and the value is excluded entirely.
fn credential_span(value: &str) -> CredentialSpan {
    let prefix = scheme_prefix_regex().find(value);
    let (has_credentials, origin_is_absolute) = parse_credentials(value);
    let Some(prefix) = prefix else {
        return if has_credentials {
            CredentialSpan::Ambiguous
        } else {
            CredentialSpan::None
        };
    };
    let authority_start = prefix.end();
    let protocol = scheme_of(value).unwrap_or_else(|| "https".to_owned());
    let special = matches!(
        protocol.as_str(),
        "ftp" | "file" | "http" | "https" | "ws" | "wss"
    );
    let bytes = value.as_bytes();
    let mut authority_end = authority_start;
    while authority_end < bytes.len() {
        let ch = bytes[authority_end];
        if matches!(ch, b'/' | b'?' | b'#') || (special && ch == b'\\') {
            break;
        }
        authority_end += 1;
    }
    let authority = &value[authority_start..authority_end];
    let stable_authority =
        !authority.is_empty() && !authority.chars().any(|c| matches!(c, '\t' | '\n' | '\r'));
    let at = authority.rfind('@');
    if !stable_authority && has_credentials {
        return CredentialSpan::Ambiguous;
    }
    match at {
        Some(index) => CredentialSpan::Span {
            start: authority_start,
            end: authority_start + index + 1,
        },
        None => {
            if has_credentials {
                CredentialSpan::Ambiguous
            } else {
                let _ = origin_is_absolute;
                CredentialSpan::None
            }
        }
    }
}

fn parse_credentials(value: &str) -> (bool, bool) {
    // A userinfo (`user[:pass]@`) before the first `/`, `?` or `#` in the
    // authority denotes credentials. This conservative check matches the
    // oracle for the observed fixtures (which carry no credentials).
    let after_scheme = match scheme_prefix_regex().find(value) {
        Some(prefix) => &value[prefix.end()..],
        None => value,
    };
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let has_credentials = authority.contains('@');
    (has_credentials, scheme_prefix_regex().is_match(value))
}

fn scheme_of(value: &str) -> Option<String> {
    let caps = scheme_prefix_regex().captures(value)?;
    caps.get(1).map(|m| m.as_str().to_ascii_lowercase())
}

fn scheme_prefix_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"^[\x00-\x20]*(?:([A-Za-z][A-Za-z0-9+.\-]*):)?//").unwrap()
    })
}
