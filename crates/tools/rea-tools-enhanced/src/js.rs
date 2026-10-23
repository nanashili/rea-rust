//! JavaScript value semantics the original workflows rely on.
//!
//! - `compareUnicodeCodePoints` equals Rust's `str` ordering (UTF-8 byte order
//!   is code-point order).
//! - The `<`/`>` operators and the default `Array.prototype.sort` compare
//!   UTF-16 code units; [`compare_utf16`] reproduces that.
//! - Objects built from dynamic keys enumerate canonical array-index keys
//!   first, in ascending numeric order, then the remaining keys in insertion
//!   order; [`JsObject`] reproduces that property order.
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// JavaScript `<` on strings (UTF-16 code-unit order).
pub fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// `compareUnicodeCodePoints`.
pub fn compare_code_points(left: &str, right: &str) -> Ordering {
    left.cmp(right)
}

/// `[...new Set(values)].sort(compareUnicodeCodePoints)`.
pub fn unique_sorted(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values = values.into_iter().collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

/// `[...new Set(values)]` preserving first-insertion order.
pub fn unique_in_order(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

/// Whether `key` is a canonical array index (`0` … `2^32 - 2`).
fn array_index(key: &str) -> Option<u32> {
    if key.is_empty() || key.len() > 10 || !key.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if key.len() > 1 && key.starts_with('0') {
        return None;
    }
    key.parse::<u64>()
        .ok()
        .filter(|index| *index < u64::from(u32::MAX))
        .map(|index| index as u32)
}

/// An object whose enumeration order follows JavaScript property order.
#[derive(Default, Clone, Debug)]
pub struct JsObject {
    map: Map<String, Value>,
}

impl JsObject {
    pub fn new() -> Self {
        Self::default()
    }

    /// Assign `object[key] = value` (an existing key keeps its position).
    pub fn insert(&mut self, key: impl Into<String>, value: Value) {
        let key = key.into();
        if let Some(existing) = self.map.get_mut(&key) {
            *existing = value;
        } else {
            self.map.insert(key, value);
        }
    }

    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        self.map.get_mut(key)
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.map.contains_key(key)
    }

    /// The object value in JavaScript enumeration order.
    pub fn into_value(self) -> Value {
        let mut indexed = Vec::new();
        let mut named = Vec::new();
        for (key, value) in self.map {
            match array_index(&key) {
                Some(index) => indexed.push((index, key, value)),
                None => named.push((key, value)),
            }
        }
        if indexed.is_empty() {
            return Value::Object(named.into_iter().collect());
        }
        indexed.sort_by_key(|(index, _, _)| *index);
        let mut map = Map::new();
        for (_, key, value) in indexed {
            map.insert(key, value);
        }
        for (key, value) in named {
            map.insert(key, value);
        }
        Value::Object(map)
    }
}

/// `Object.fromEntries(entries)` with JavaScript property order.
pub fn from_entries(entries: impl IntoIterator<Item = (String, Value)>) -> Value {
    let mut object = JsObject::new();
    for (key, value) in entries {
        object.insert(key, value);
    }
    object.into_value()
}

/// `JSON.stringify` of a string array (used for composite keys).
pub fn composite_key(parts: &[&str]) -> String {
    serde_json::to_string(parts).unwrap_or_default()
}

/// Shallow object accessor.
pub fn object(value: &Value) -> Option<&Map<String, Value>> {
    value.as_object()
}

/// `typeof value === "string"` accessor.
pub fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}
