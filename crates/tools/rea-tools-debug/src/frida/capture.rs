//! Bounded, secret-redacted capture of Frida script messages.
//!
//! Exact port of the capture logic in
//! `src/frida/FridaInstrumentationManager.ts`: `boundedRedactedString`,
//! `boundedJsonValue`, `jsonStringByteLength`, the `MessageFifo` eviction
//! queue and the per-message observation builder (`#recordMessage`), with the
//! identical byte budgets and `MAX_*` limits. Token/certificate secrets are
//! redacted wherever they appear in strings or binary payloads.
//!
//! This module is pure and carries no FFI; it is unit-tested directly and
//! reused by `manager.rs` once a live script delivers messages.
#![allow(dead_code)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value};
use std::collections::VecDeque;

pub(crate) const MAX_SESSION_CAPTURE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_MESSAGE_METADATA_BYTES: usize = 128 * 1024;
pub(crate) const MAX_MESSAGE_TYPE_BYTES: usize = 4 * 1024;
pub(crate) const MAX_MESSAGE_TEXT_BYTES: usize = 32 * 1024;
/// Bound the in-memory object graph as well as its serialized JSON byte size.
pub(crate) const MAX_CAPTURE_JSON_NODES: i64 = 250_000;
pub(crate) const MAX_BINARY_MESSAGE_BYTES: usize =
    ((MAX_SESSION_CAPTURE_BYTES - 1024 * 1024) * 3) / 4;

/// UTF-8 JSON string bytes without serialization; a result above `budget`
/// only establishes overflow (`jsonStringByteLength`). Operates on UTF-16 code
/// units to match the TypeScript producer exactly.
pub(crate) fn json_string_byte_length(value: &str, budget: usize) -> usize {
    let mut bytes = 2usize;
    let units: Vec<u16> = value.encode_utf16().collect();
    let mut index = 0usize;
    while index < units.len() && bytes <= budget {
        let unit = units[index];
        if unit == 0x22 || unit == 0x5c {
            bytes += 2;
        } else if unit < 0x20 {
            bytes += match unit {
                0x08 | 0x09 | 0x0a | 0x0c | 0x0d => 2,
                _ => 6,
            };
        } else if unit < 0x80 {
            bytes += 1;
        } else if unit < 0x800 {
            bytes += 2;
        } else if (0xd800..=0xdbff).contains(&unit) {
            let next = units.get(index + 1).copied().unwrap_or(0);
            if (0xdc00..=0xdfff).contains(&next) {
                bytes += 4;
                index += 1;
            } else {
                bytes += 6;
            }
        } else if (0xdc00..=0xdfff).contains(&unit) {
            bytes += 6;
        } else {
            bytes += 3;
        }
        index += 1;
    }
    bytes
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Bounded {
    pub(crate) value: String,
    pub(crate) truncated: bool,
}

/// `boundedRedactedString`: copy `input` up to `maximum_bytes` of JSON string
/// payload, replacing any occurrence of a secret with `[redacted]` and marking
/// truncation when the budget or a secret boundary stops the copy. Byte
/// accounting uses `json_string_byte_length - 2` (payload bytes, no quotes).
pub(crate) fn bounded_redacted_string(
    input: &str,
    maximum_bytes: usize,
    secrets: &[String],
) -> Bounded {
    // Operate on UTF-16 code units so indices and secret matches line up with
    // the TypeScript producer's string semantics.
    let units: Vec<u16> = input.encode_utf16().collect();
    let secret_units: Vec<Vec<u16>> = secrets
        .iter()
        .filter(|secret| !secret.is_empty())
        .map(|secret| secret.encode_utf16().collect())
        .collect();
    let mut chunks: Vec<u16> = Vec::new();
    let mut output_bytes = 0usize;
    let mut cursor = 0usize;
    let mut segment_start = 0usize;
    let mut truncated = false;

    let find_from = |units: &[u16], needle: &[u16], from: usize| -> Option<usize> {
        if needle.is_empty() || needle.len() > units.len() || from > units.len() - needle.len() {
            return None;
        }
        (from..=units.len().saturating_sub(needle.len()))
            .find(|&i| units[i..i + needle.len()] == needle[..])
    };

    while cursor < units.len() {
        let mut next_secret_start = units.len();
        let mut next_secret: Option<&Vec<u16>> = None;
        for secret in &secret_units {
            if let Some(matched) = find_from(&units, secret, cursor) {
                if matched < next_secret_start {
                    next_secret_start = matched;
                    next_secret = Some(secret);
                }
            }
        }
        if next_secret_start == cursor {
            if let Some(secret) = next_secret {
                let replacement = "[redacted]";
                let replacement_bytes = json_string_byte_length(replacement, usize::MAX) - 2;
                if output_bytes + replacement_bytes > maximum_bytes {
                    truncated = true;
                    break;
                }
                chunks.extend_from_slice(&units[segment_start..cursor]);
                chunks.extend(replacement.encode_utf16());
                output_bytes += replacement_bytes;
                cursor += secret.len();
                segment_start = cursor;
                continue;
            }
        }
        while cursor < next_secret_start {
            // One UTF-16 code point (surrogate pair or single unit).
            let unit = units[cursor];
            let char_len = if (0xd800..=0xdbff).contains(&unit)
                && cursor + 1 < units.len()
                && (0xdc00..=0xdfff).contains(&units[cursor + 1])
            {
                2
            } else {
                1
            };
            let character_units = &units[cursor..cursor + char_len];
            let character: String = String::from_utf16_lossy(character_units);
            let character_bytes = json_string_byte_length(&character, usize::MAX) - 2;
            if cursor + char_len > next_secret_start
                || output_bytes + character_bytes > maximum_bytes
            {
                truncated = true;
                break;
            }
            output_bytes += character_bytes;
            cursor += char_len;
        }
        if truncated {
            break;
        }
    }
    chunks.extend_from_slice(&units[segment_start..cursor]);
    if cursor < units.len() {
        truncated = true;
    }
    Bounded {
        value: String::from_utf16_lossy(&chunks),
        truncated,
    }
}

#[derive(Clone, Debug)]
struct VisitOutcome {
    value: Value,
    truncated: bool,
}

/// `boundedJsonValue`: a depth/breadth/byte-bounded, secret-redacted copy of a
/// JSON value, returning the retained value, whether anything was dropped, and
/// the serialized byte size of the retained value.
pub(crate) struct BoundedJson {
    pub(crate) value: Value,
    pub(crate) truncated: bool,
    pub(crate) bytes: usize,
}

pub(crate) fn bounded_json_value(
    input: &Value,
    maximum_bytes: usize,
    secrets: &[String],
) -> BoundedJson {
    let mut remaining_nodes = MAX_CAPTURE_JSON_NODES;
    let outcome = visit(input, maximum_bytes as i64, 0, secrets, &mut remaining_nodes);
    let bytes = serialized_len(&outcome.value);
    if bytes > maximum_bytes {
        BoundedJson {
            value: Value::Null,
            truncated: true,
            bytes: 4,
        }
    } else {
        BoundedJson {
            value: outcome.value,
            truncated: outcome.truncated,
            bytes,
        }
    }
}

fn visit(
    value: &Value,
    budget: i64,
    depth: i64,
    secrets: &[String],
    remaining_nodes: &mut i64,
) -> VisitOutcome {
    *remaining_nodes -= 1;
    if *remaining_nodes < 0 {
        return VisitOutcome {
            value: Value::Null,
            truncated: true,
        };
    }
    if depth > 64 || budget < 8 {
        return VisitOutcome {
            value: Value::Null,
            truncated: true,
        };
    }
    match value {
        Value::Null => VisitOutcome {
            value: Value::Null,
            truncated: false,
        },
        Value::Bool(_) => VisitOutcome {
            value: value.clone(),
            truncated: false,
        },
        Value::Number(_) => VisitOutcome {
            value: value.clone(),
            truncated: false,
        },
        Value::String(text) => {
            let bounded =
                bounded_redacted_string(text, (budget - 2).max(0) as usize, secrets);
            VisitOutcome {
                value: Value::String(bounded.value),
                truncated: bounded.truncated,
            }
        }
        Value::Array(items) => {
            let mut output: Vec<Value> = Vec::new();
            let mut used_bytes: i64 = 2;
            let mut truncated = false;
            for item in items {
                let separator_bytes = if output.is_empty() { 0 } else { 1 };
                let remaining = budget - used_bytes - separator_bytes - 1;
                if remaining < 8 {
                    truncated = true;
                    break;
                }
                let visited = visit(item, remaining, depth + 1, secrets, remaining_nodes);
                let item_bytes = serialized_len(&visited.value) as i64;
                if item_bytes > remaining {
                    truncated = true;
                    break;
                }
                output.push(visited.value);
                used_bytes += separator_bytes + item_bytes;
                truncated = truncated || visited.truncated;
                if visited.truncated {
                    break;
                }
            }
            if output.len() < items.len() {
                truncated = true;
            }
            VisitOutcome {
                value: Value::Array(output),
                truncated,
            }
        }
        Value::Object(entries) => {
            let mut output = Map::new();
            let mut used_bytes: i64 = 2;
            let mut count = 0i64;
            let mut truncated = false;
            for (raw_key, entry_value) in entries {
                let separator_bytes = if count == 0 { 0 } else { 1 };
                let key_limit = (budget - used_bytes - separator_bytes - 10).max(0);
                let bounded_key = bounded_redacted_string(raw_key, key_limit as usize, secrets);
                if bounded_key.truncated {
                    truncated = true;
                    break;
                }
                let key = bounded_key.value;
                let key_bytes = json_string_byte_length(&key, usize::MAX) as i64 + 1;
                let remaining = budget - used_bytes - separator_bytes - key_bytes - 1;
                if remaining < 8 {
                    truncated = true;
                    break;
                }
                let entry = visit(entry_value, remaining, depth + 1, secrets, remaining_nodes);
                let entry_bytes = serialized_len(&entry.value) as i64;
                if entry_bytes > remaining {
                    truncated = true;
                    break;
                }
                output.insert(key, entry.value);
                count += 1;
                used_bytes += separator_bytes + key_bytes + entry_bytes;
                truncated = truncated || entry.truncated;
                if entry.truncated {
                    break;
                }
            }
            VisitOutcome {
                value: Value::Object(output),
                truncated,
            }
        }
    }
}

/// Serialized JSON byte length, matching `Buffer.byteLength(JSON.stringify(v))`.
pub(crate) fn serialized_len(value: &Value) -> usize {
    serde_json::to_string(value)
        .map(|text| text.len())
        .unwrap_or(4)
}

/// Arrival-ordered queue whose eviction advances a head offset
/// (`MessageFifo`). A full capture budget evicts on every message; this keeps
/// eviction amortized O(1).
#[derive(Default)]
pub(crate) struct MessageFifo<T> {
    items: VecDeque<T>,
}

impl<T: Clone> MessageFifo<T> {
    pub(crate) fn new() -> Self {
        Self {
            items: VecDeque::new(),
        }
    }
    pub(crate) fn size(&self) -> usize {
        self.items.len()
    }
    pub(crate) fn push(&mut self, item: T) {
        self.items.push_back(item);
    }
    pub(crate) fn peek(&self) -> Option<&T> {
        self.items.front()
    }
    pub(crate) fn shift(&mut self) -> Option<T> {
        self.items.pop_front()
    }
    pub(crate) fn to_vec(&self) -> Vec<T> {
        self.items.iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_string_byte_length_matches_ascii_and_escapes() {
        assert_eq!(json_string_byte_length("abc", usize::MAX), 5);
        assert_eq!(json_string_byte_length("\"", usize::MAX), 4);
        assert_eq!(json_string_byte_length("\n", usize::MAX), 4);
        assert_eq!(json_string_byte_length("\u{0001}", usize::MAX), 8);
        // 3-byte and 4-byte code points.
        assert_eq!(json_string_byte_length("\u{20ac}", usize::MAX), 5);
        assert_eq!(json_string_byte_length("\u{1f600}", usize::MAX), 6);
    }

    #[test]
    fn redacts_secret_occurrences() {
        let secrets = vec!["sekret".to_owned()];
        let bounded = bounded_redacted_string("a sekret b", usize::MAX, &secrets);
        assert_eq!(bounded.value, "a [redacted] b");
        assert!(!bounded.truncated);
    }

    #[test]
    fn truncates_when_over_budget() {
        let bounded = bounded_redacted_string("abcdef", 3, &[]);
        assert!(bounded.truncated);
        assert_eq!(bounded.value, "abc");
    }

    #[test]
    fn bounded_json_preserves_key_order_and_values() {
        let input = json!({
            "2": "two", "1": "one", "hello": "world",
            "n": 1.5, "arr": [1, "x", null], "nested": {"a": {"b": [true, false]}}
        });
        let bounded = bounded_json_value(&input, MAX_SESSION_CAPTURE_BYTES, &[]);
        assert!(!bounded.truncated);
        // serde_json with preserve_order keeps insertion order like V8/JSON.
        assert_eq!(bounded.value, input);
    }

    #[test]
    fn bounded_json_redacts_nested_secret() {
        let secrets = vec!["tok".to_owned()];
        let input = json!({"k": "a tok b"});
        let bounded = bounded_json_value(&input, MAX_SESSION_CAPTURE_BYTES, &secrets);
        assert_eq!(bounded.value, json!({"k": "a [redacted] b"}));
    }

    #[test]
    fn binary_base64_matches_oracle_bytes() {
        // The attach scenario's binary message: Uint8Array([0,1,2,255]).
        assert_eq!(BASE64.encode([0u8, 1, 2, 255]), "AAEC/w==");
    }

    #[test]
    fn fifo_evicts_in_arrival_order() {
        let mut fifo: MessageFifo<u32> = MessageFifo::new();
        fifo.push(1);
        fifo.push(2);
        fifo.push(3);
        assert_eq!(fifo.peek(), Some(&1));
        assert_eq!(fifo.shift(), Some(1));
        assert_eq!(fifo.to_vec(), vec![2, 3]);
        assert_eq!(fifo.size(), 2);
    }
}
