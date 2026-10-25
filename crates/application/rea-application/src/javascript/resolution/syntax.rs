//! Lexical path, URL-text and JSON helpers with the exact semantics the
//! resolver takes from Node's `path.posix`, ECMAScript URI functions and the
//! shared artifact path predicates.
//!
//! Compatibility owners: `src/domain/artifactPathSyntax.ts` and
//! `normalizeJoinedLogicalPath`/`logicalPathEscapesRoot` in
//! `src/domain/artifactIdentity.ts`. Rust strings cannot hold unpaired UTF-16
//! surrogates, so the TypeScript paths that only exist for them are absent.
use unicode_normalization::UnicodeNormalization;

/// Node `normalizeString` over split segments.
fn normalize_segments(path: &str, allow_above_root: bool) -> Vec<&str> {
    let mut stack: Vec<&str> = Vec::new();
    for segment in path.split('/') {
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
    let joined = normalize_segments(path, !absolute).join("/");
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

/// `path.posix.join(...parts)`.
pub fn posix_join(parts: &[&str]) -> String {
    let joined = parts
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return ".".into();
    }
    posix_normalize(&joined)
}

/// `path.posix.dirname`.
pub fn posix_dirname(path: &str) -> &str {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return ".";
    }
    let has_root = bytes[0] == b'/';
    let mut end = None;
    let mut matched_slash = true;
    for index in (1..bytes.len()).rev() {
        if bytes[index] == b'/' {
            if !matched_slash {
                end = Some(index);
                break;
            }
        } else {
            matched_slash = false;
        }
    }
    match end {
        None => {
            if has_root {
                "/"
            } else {
                "."
            }
        }
        Some(1) if has_root => "//",
        Some(end) => &path[..end],
    }
}

/// `path.posix.basename` without an extension argument.
pub fn posix_basename(path: &str) -> &str {
    let bytes = path.as_bytes();
    let mut start = 0;
    let mut end = None;
    let mut matched_slash = true;
    for index in (0..bytes.len()).rev() {
        if bytes[index] == b'/' {
            if !matched_slash {
                start = index + 1;
                break;
            }
        } else if end.is_none() {
            matched_slash = false;
            end = Some(index + 1);
        }
    }
    end.map_or("", |end| &path[start..end])
}

/// `path.posix.extname`.
pub fn posix_extname(path: &str) -> &str {
    let bytes = path.as_bytes();
    let mut start_dot: Option<usize> = None;
    let mut start_part = 0;
    let mut end: Option<usize> = None;
    let mut matched_slash = true;
    let mut pre_dot_state = 0_i8;
    for index in (0..bytes.len()).rev() {
        let code = bytes[index];
        if code == b'/' {
            if !matched_slash {
                start_part = index + 1;
                break;
            }
            continue;
        }
        if end.is_none() {
            matched_slash = false;
            end = Some(index + 1);
        }
        if code == b'.' {
            if start_dot.is_none() {
                start_dot = Some(index);
            } else if pre_dot_state != 1 {
                pre_dot_state = 1;
            }
        } else if start_dot.is_some() {
            pre_dot_state = -1;
        }
    }
    let (Some(start_dot), Some(end)) = (start_dot, end) else {
        return "";
    };
    if pre_dot_state == 0
        || (pre_dot_state == 1 && start_dot == end - 1 && start_dot == start_part + 1)
    {
        return "";
    }
    &path[start_dot..end]
}

/// `path.posix.relative(from, to)` for absolute operands.
pub fn posix_relative(from: &str, to: &str) -> String {
    let from = normalize_segments(from, false);
    let to = normalize_segments(to, false);
    let common = from
        .iter()
        .zip(&to)
        .take_while(|(left, right)| left == right)
        .count();
    let mut parts: Vec<&str> = std::iter::repeat_n("..", from.len() - common).collect();
    parts.extend(&to[common..]);
    parts.join("/")
}

/// `normalizeJoinedLogicalPath`: lexical NFC normalization; NUL is preserved
/// so `logical_path_escapes_root` can report it.
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

/// `hasScheme`: `/^[A-Za-z][A-Za-z0-9+.-]*:/u`.
pub fn has_scheme(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_alphabetic) {
        return false;
    }
    for &byte in &bytes[1..] {
        if byte == b':' {
            return true;
        }
        if !(byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-')) {
            return false;
        }
    }
    false
}

/// `looksExternal`: scheme-qualified or protocol-relative.
pub fn looks_external(value: &str) -> bool {
    has_scheme(value) || value.starts_with("//")
}

/// `stripQueryAndFragment`.
pub fn strip_query_and_fragment(value: &str) -> &str {
    let before_hash = value.split('#').next().unwrap_or_default();
    before_hash.split('?').next().unwrap_or_default()
}

/// True when `value` contains `%XX` where `XX` is one of `encoded` (lowercase).
pub fn contains_percent_escape(value: &str, encoded: &[&str]) -> bool {
    let bytes = value.as_bytes();
    bytes.windows(3).any(|window| {
        window[0] == b'%'
            && encoded.iter().any(|code| {
                code.as_bytes()
                    .iter()
                    .zip(&window[1..])
                    .all(|(expected, actual)| actual.to_ascii_lowercase() == *expected)
            })
    })
}

/// `admitsCanonicalPathSyntax`.
pub fn admits_canonical_path_syntax(value: &str) -> bool {
    !value.contains('\0')
        && !value.contains('\\')
        && !contains_percent_escape(value, &["2e", "2f", "5c"])
}

/// `htmlUrlText`: trim C0 controls and space, then remove tab/LF/CR.
pub fn html_url_text(value: &str) -> String {
    value
        .trim_matches(|character: char| u32::from(character) <= 0x20)
        .chars()
        .filter(|character| !matches!(character, '\t' | '\n' | '\r'))
        .collect()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn percent_byte(bytes: &[u8], index: usize) -> Option<u8> {
    if bytes.get(index) != Some(&b'%') {
        return None;
    }
    let high = hex_value(*bytes.get(index + 1)?)?;
    let low = hex_value(*bytes.get(index + 2)?)?;
    Some(high << 4 | low)
}

/// `percentDecodeUrlPath`: URL-standard percent decoding, then strict UTF-8.
/// `None` when the bytes are not UTF-8 or contain NUL.
pub fn percent_decode_url_path(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    if !(0..bytes.len()).any(|index| percent_byte(bytes, index).is_some()) {
        return Some(value.to_owned());
    }
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some(byte) = percent_byte(bytes, index) {
            decoded.push(byte);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let text = String::from_utf8(decoded).ok()?;
    (!text.contains('\0')).then_some(text)
}

/// ECMAScript `decodeURIComponent`; `None` stands for `URIError`.
pub fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            let character = value[index..].chars().next()?;
            out.push(character);
            index += character.len_utf8();
            continue;
        }
        let first = percent_byte(bytes, index)?;
        index += 3;
        if first < 0x80 {
            out.push(char::from(first));
            continue;
        }
        let (length, minimum, initial) = match first {
            0xC0..=0xDF => (2, 0x80, u32::from(first & 0x1F)),
            0xE0..=0xEF => (3, 0x800, u32::from(first & 0x0F)),
            0xF0..=0xF7 => (4, 0x1_0000, u32::from(first & 0x07)),
            _ => return None,
        };
        let mut code = initial;
        for _ in 1..length {
            let next = percent_byte(bytes, index)?;
            if next & 0xC0 != 0x80 {
                return None;
            }
            code = code << 6 | u32::from(next & 0x3F);
            index += 3;
        }
        if code < minimum {
            return None;
        }
        out.push(char::from_u32(code)?);
    }
    Some(out)
}

/// ECMAScript `encodeURIComponent` (infallible without lone surrogates).
pub fn encode_uri_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
            )
        {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `JSON.stringify` of a string.
pub fn json_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// `JSON.stringify` of an arbitrary JSON value with ECMAScript number text.
pub fn json_stringify(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "null".into(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => js_number_text(number),
        Value::String(text) => json_string(text),
        Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(json_stringify)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Value::Object(map) => format!(
            "{{{}}}",
            js_own_keys(map)
                .into_iter()
                .map(|key| format!("{}:{}", json_string(key), json_stringify(&map[key])))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

/// ECMAScript `Number#toString` of a parsed JSON number.
pub fn js_number_text(number: &serde_json::Number) -> String {
    let value = number.as_f64().unwrap_or(f64::NAN);
    js_f64_text(value)
}

/// ECMAScript `Number#toString`.
pub fn js_f64_text(value: f64) -> String {
    if value.is_nan() {
        return "NaN".into();
    }
    if value.is_infinite() {
        return if value > 0.0 { "Infinity" } else { "-Infinity" }.into();
    }
    let mut buffer = ryu_js::Buffer::new();
    buffer.format(value).to_owned()
}

/// Whether a property key is an ECMAScript array index (canonical integer < 2^32 - 1).
fn array_index(key: &str) -> Option<u32> {
    let parsed: u32 = key.parse().ok()?;
    (parsed != u32::MAX && parsed.to_string() == key).then_some(parsed)
}

/// `Object.keys` order of a parsed JSON object: array-index keys ascending,
/// then the remaining keys in first-insertion order.
pub fn js_own_keys(map: &serde_json::Map<String, serde_json::Value>) -> Vec<&str> {
    let mut indexes: Vec<(u32, &str)> = Vec::new();
    let mut names: Vec<&str> = Vec::new();
    for key in map.keys() {
        match array_index(key) {
            Some(index) => indexes.push((index, key)),
            None => names.push(key),
        }
    }
    indexes.sort_by_key(|(index, _)| *index);
    indexes
        .into_iter()
        .map(|(_, key)| key)
        .chain(names)
        .collect()
}

/// `String(Number(key)) === key && Number(key) >= 0 && Number(key) < 0xffffffff`.
pub fn is_numeric_condition_key(key: &str) -> bool {
    let Some(value) = js_string_to_number(key) else {
        return false;
    };
    js_f64_text(value) == key && value >= 0.0 && value < f64::from(u32::MAX)
}

/// ECMAScript `Number(string)` restricted to what a canonical round trip can
/// match: decimal literals and `Infinity`. Other forms never round-trip.
fn js_string_to_number(key: &str) -> Option<f64> {
    if key == "Infinity" {
        return Some(f64::INFINITY);
    }
    let valid = !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'.' | b'e' | b'+' | b'-'));
    if !valid {
        return None;
    }
    key.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn posix_helpers_match_node() {
        assert_eq!(posix_dirname("a/b"), "a");
        assert_eq!(posix_dirname("a"), ".");
        assert_eq!(posix_dirname("/a"), "/");
        assert_eq!(posix_dirname("//a"), "//");
        assert_eq!(posix_basename("a/b/"), "b");
        assert_eq!(posix_extname("a/.b"), "");
        assert_eq!(posix_extname("a/b.c.d"), ".d");
        assert_eq!(posix_join(&["a", "../.."]), "..");
        assert_eq!(posix_normalize("./"), "./");
    }

    #[test]
    fn uri_component_round_trip() {
        assert_eq!(decode_uri_component("%E2%82%AC").as_deref(), Some("€"));
        assert_eq!(decode_uri_component("%C0%80"), None);
        assert_eq!(decode_uri_component("%"), None);
        assert_eq!(encode_uri_component("a b/€"), "a%20b%2F%E2%82%AC");
        assert!(is_numeric_condition_key("0.5"));
        assert!(!is_numeric_condition_key("-0"));
        assert!(!is_numeric_condition_key("01"));
    }
}
