//! Locale-independent code-point ordering and composite keys.
//!
//! Compatibility owner: `src/domain/unicodeCodePointOrder.ts`.
use serde_json::Value;
use std::cmp::Ordering;

/// `compareUnicodeCodePoints`: lexicographic order by Unicode code point.
///
/// Rust `str` ordering compares UTF-8 bytes, which equals code-point order, so
/// it matches the TypeScript scalar comparison exactly.
pub fn compare(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

/// `compositeKey(parts)`: a collision-free JSON-tuple key.
///
/// The original joins the parts with `JSON.stringify`; the same canonical JSON
/// string gives identical keys for identical component tuples.
pub fn composite_key(parts: &[Value]) -> String {
    Value::Array(parts.to_vec()).to_string()
}
