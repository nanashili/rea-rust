//! Locale-independent Unicode code-point string ordering.
//!
//! Compatibility owner: `src/domain/unicodeCodePointOrder.ts`.
//! `compareUnicodeCodePoints` compares by Unicode scalar value. Rust `str`
//! iteration by `char` yields scalar values directly, matching the original
//! UTF-16 code-point comparison for valid Unicode.
use std::cmp::Ordering;

/// Compare two strings by Unicode code point.
pub fn compare_code_points(left: &str, right: &str) -> Ordering {
    let mut left_chars = left.chars();
    let mut right_chars = right.chars();
    loop {
        match (left_chars.next(), right_chars.next()) {
            (Some(l), Some(r)) => match (l as u32).cmp(&(r as u32)) {
                Ordering::Equal => continue,
                other => return other,
            },
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}
