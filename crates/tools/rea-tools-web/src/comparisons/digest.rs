//! Canonical JSON hashing and Unicode code-point ordering.
//!
//! Compatibility owners: `src/domain/canonicalDigest.ts`,
//! `src/domain/unicodeCodePointOrder.ts`. Object keys follow RFC 8785 UTF-16
//! code-unit order; strings order by Unicode code point.
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Streaming SHA-256 over canonical JSON (`digestCanonicalValue`).
///
/// The native boundary only ever hashes finite JSON values, so the TS
/// `TypeError`/`Error` guards for non-finite numbers, `undefined` roots and
/// circular references cannot be reached here.
pub fn digest_canonical_value(value: &Value) -> String {
    let mut hasher = Sha256::new();
    let mut buffer = String::new();
    emit_canonical(value, &mut hasher, &mut buffer);
    if !buffer.is_empty() {
        hasher.update(buffer.as_bytes());
    }
    hex(&hasher.finalize())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit((byte >> 4) as u32, 16).expect("nibble"));
        out.push(char::from_digit((byte & 0x0f) as u32, 16).expect("nibble"));
    }
    out
}

fn emit(hasher: &mut Sha256, buffer: &mut String, part: &str) {
    buffer.push_str(part);
    if buffer.len() >= 8192 {
        hasher.update(buffer.as_bytes());
        buffer.clear();
    }
}

fn emit_canonical(value: &Value, hasher: &mut Sha256, buffer: &mut String) {
    match value {
        Value::Null => emit(hasher, buffer, "null"),
        Value::Bool(flag) => emit(hasher, buffer, if *flag { "true" } else { "false" }),
        Value::Number(number) => emit(hasher, buffer, &number.to_string()),
        Value::String(text) => emit(hasher, buffer, &encode_json_string(text)),
        Value::Array(items) => {
            emit(hasher, buffer, "[");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    emit(hasher, buffer, ",");
                }
                emit_canonical(item, hasher, buffer);
            }
            emit(hasher, buffer, "]");
        }
        Value::Object(map) => {
            emit(hasher, buffer, "{");
            let mut keys: Vec<&String> = map.keys().collect();
            // RFC 8785 / canonicalize: sort object keys by UTF-16 code unit.
            keys.sort_by(|left, right| compare_utf16_code_units(left, right));
            let mut first = true;
            for key in keys {
                if !first {
                    emit(hasher, buffer, ",");
                }
                first = false;
                emit(hasher, buffer, &encode_json_string(key));
                emit(hasher, buffer, ":");
                emit_canonical(&map[key], hasher, buffer);
            }
            emit(hasher, buffer, "}");
        }
    }
}

/// `JSON.stringify(string)` — escape per the ECMAScript JSON grammar.
fn encode_json_string(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Compare two strings by their UTF-16 code units (RFC 8785 key order).
fn compare_utf16_code_units(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_units = left.encode_utf16();
    let mut right_units = right.encode_utf16();
    loop {
        match (left_units.next(), right_units.next()) {
            (Some(left_unit), Some(right_unit)) => match left_unit.cmp(&right_unit) {
                std::cmp::Ordering::Equal => {}
                other => return other,
            },
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

/// `compareUnicodeCodePoints` — lexicographic order by Unicode code point.
pub fn compare_unicode_code_points(left: &str, right: &str) -> std::cmp::Ordering {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();
    loop {
        match (left_chars.next(), right_chars.next()) {
            (Some(left_char), Some(right_char)) => {
                match (left_char as u32).cmp(&(right_char as u32)) {
                    std::cmp::Ordering::Equal => {}
                    other => return other,
                }
            }
            (Some(_), None) => return std::cmp::Ordering::Greater,
            (None, Some(_)) => return std::cmp::Ordering::Less,
            (None, None) => return std::cmp::Ordering::Equal,
        }
    }
}

/// `compositeKey(parts)` — JSON tuple of the parts (collision free).
pub fn composite_key(parts: &[Value]) -> String {
    Value::Array(parts.to_vec()).to_string()
}
