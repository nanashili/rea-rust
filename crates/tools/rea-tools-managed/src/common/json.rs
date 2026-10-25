//! Small JSON, string-ordering and digest helpers with ECMAScript semantics.
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;

/// ECMAScript `String.prototype.length` (UTF-16 code units).
pub fn js_len(text: &str) -> usize {
    text.encode_utf16().count()
}

/// Default ECMAScript `Array.prototype.sort()` order for strings (UTF-16 units).
pub fn cmp_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// `uniqueSorted`: deduplicate and sort by Unicode code point.
///
/// Rust `str` ordering is UTF-8 byte order, which equals code-point order.
pub fn unique_sorted<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut values: Vec<String> = values.into_iter().map(Into::into).collect();
    values.sort();
    values.dedup();
    values
}

/// `jsonStringByteLength`: UTF-8 JSON bytes of a string, including quotes.
/// Above `budget`, the count only establishes overflow.
pub fn json_string_byte_length(value: &str, budget: Option<usize>) -> usize {
    let budget = budget.unwrap_or(usize::MAX);
    let mut bytes = 2usize;
    for character in value.chars() {
        if bytes > budget {
            break;
        }
        let code = character as u32;
        bytes += match code {
            0x22 | 0x5c => 2,
            0x08 | 0x09 | 0x0a | 0x0c | 0x0d => 2,
            0x00..=0x1f => 6,
            0x20..=0x7f => 1,
            0x80..=0x7ff => 2,
            0x800..=0xffff => 3,
            _ => 4,
        };
    }
    bytes
}

/// Lowercase hexadecimal SHA-256 of bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// `digestCanonicalValue`: SHA-256 of the RFC 8785 canonical JSON form.
pub fn canonical_digest(value: &Value, context: &str) -> Result<String, AnalysisError> {
    rea_core::canonical_json::digest(value).map_err(|error| {
        AnalysisError::output(
            "inspect_analysis_view",
            format!("{context} could not canonicalize data: {error}"),
        )
    })
}

/// Object member as a string.
pub fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// Object member as an array slice (empty when absent or not an array).
pub fn array_at<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Build an object from ordered entries.
pub fn object<I, K>(entries: I) -> Value
where
    I: IntoIterator<Item = (K, Value)>,
    K: Into<String>,
{
    let mut map = Map::new();
    for (key, value) in entries {
        map.insert(key.into(), value);
    }
    Value::Object(map)
}

/// `{ ...base, ...overrides }` with ECMAScript spread semantics: existing keys
/// keep their position and take the later value; new keys are appended.
pub fn spread(base: &Value, overrides: &Value) -> Value {
    let mut map = base.as_object().cloned().unwrap_or_default();
    if let Some(overrides) = overrides.as_object() {
        for (key, value) in overrides {
            map.insert(key.clone(), value.clone());
        }
    }
    Value::Object(map)
}

/// Remove the named keys from an object copy (`const { a, b, ...rest } = value`).
pub fn without(value: &Value, keys: &[&str]) -> Map<String, Value> {
    let mut map = value.as_object().cloned().unwrap_or_default();
    for key in keys {
        map.shift_remove(*key);
    }
    map
}

/// Strings of an array value, skipping non-string members.
pub fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
