//! REA canonical JSON: UTF-16 key order, ECMAScript numbers, lossless strings.
//!
//! Byte-for-byte compatibility owner: `src/domain/canonicalDigest.ts`.
//! The caller owns input/output size admission. Nesting follows JsonValue's
//! existing 1000-level limit. Traversal does not recurse on the Rust call stack.

use crate::JsonText;
use serde::{Deserialize, Deserializer, Serialize, de};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    fmt,
    io::{self, Write},
};

/// Canonicalization failed rather than silently changing source meaning.
#[derive(Debug)]
pub enum Error {
    /// Invalid JSON syntax or a value outside the numeric representation.
    Json(serde_json::Error),
    /// Output could not be written.
    Io(io::Error),
    /// The existing JSON value depth limit was exceeded.
    Depth,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => e.fmt(f),
            Self::Io(e) => e.fmt(f),
            Self::Depth => f.write_str("JSON value exceeds maximum nesting depth of 1000"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Depth => None,
        }
    }
}

struct Key {
    text: JsonText,
    units: Vec<u16>,
}
impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.units == other.units
    }
}
impl Eq for Key {}
impl PartialOrd for Key {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Key {
    fn cmp(&self, other: &Self) -> Ordering {
        self.units.cmp(&other.units)
    }
}

struct Object<'a>(BTreeMap<Key, &'a RawValue>);
impl<'de> Deserialize<'de> for Object<'de> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Object<'de>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_map<M: de::MapAccess<'de>>(
                self,
                mut access: M,
            ) -> Result<Self::Value, M::Error> {
                let mut fields = BTreeMap::new();
                while let Some((text, value)) = access.next_entry::<JsonText, &'de RawValue>()? {
                    let units = text.utf16_units().map_err(de::Error::custom)?;
                    // JSON.parse's duplicate-key rule is last value wins.
                    fields.insert(Key { text, units }, value);
                }
                Ok(Object(fields))
            }
        }
        deserializer.deserialize_map(Visitor)
    }
}

enum Pending<'a> {
    Value(&'a RawValue, usize),
    Bytes(&'static [u8]),
    Text(JsonText),
}

/// Write canonical JSON, preserving escaped lone surrogates in keys and values.
///
/// # Errors
/// Invalid JSON, non-finite numbers, depth overflow or writer failure are errors.
/// Whitespace and duplicate-key source spelling are normalized as JSON.parse does.
pub fn write(raw: &RawValue, mut output: impl Write) -> Result<(), Error> {
    let mut pending = vec![Pending::Value(raw, 0)];
    let mut numbers = ryu_js::Buffer::new();
    while let Some(next) = pending.pop() {
        match next {
            Pending::Bytes(bytes) => output.write_all(bytes).map_err(Error::Io)?,
            Pending::Text(text) => {
                serde_json::to_writer(&mut output, &text).map_err(Error::Json)?
            }
            Pending::Value(raw, depth) => {
                if depth > 1000 {
                    return Err(Error::Depth);
                }
                match raw.get().as_bytes().first() {
                    Some(b'{') => {
                        let Object(fields) =
                            serde_json::from_str(raw.get()).map_err(Error::Json)?;
                        output.write_all(b"{").map_err(Error::Io)?;
                        pending.push(Pending::Bytes(b"}"));
                        let length = fields.len();
                        for (index, (key, value)) in fields.into_iter().rev().enumerate() {
                            pending.push(Pending::Value(value, depth + 1));
                            pending.push(Pending::Bytes(b":"));
                            pending.push(Pending::Text(key.text));
                            if index + 1 < length {
                                pending.push(Pending::Bytes(b","));
                            }
                        }
                    }
                    Some(b'[') => {
                        let values: Vec<&RawValue> =
                            serde_json::from_str(raw.get()).map_err(Error::Json)?;
                        output.write_all(b"[").map_err(Error::Io)?;
                        pending.push(Pending::Bytes(b"]"));
                        let length = values.len();
                        for (index, value) in values.into_iter().rev().enumerate() {
                            pending.push(Pending::Value(value, depth + 1));
                            if index + 1 < length {
                                pending.push(Pending::Bytes(b","));
                            }
                        }
                    }
                    Some(b'"') => {
                        let text: JsonText =
                            serde_json::from_str(raw.get()).map_err(Error::Json)?;
                        serde_json::to_writer(&mut output, &text).map_err(Error::Json)?;
                    }
                    Some(b't' | b'f' | b'n') => {
                        output.write_all(raw.get().as_bytes()).map_err(Error::Io)?
                    }
                    _ => {
                        let number: f64 = serde_json::from_str(raw.get()).map_err(Error::Json)?;
                        output
                            .write_all(numbers.format(number).as_bytes())
                            .map_err(Error::Io)?;
                    }
                }
            }
        }
    }
    Ok(())
}

struct HashWriter(Sha256);
impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// SHA-256 over canonical JSON without assembling the canonical output string.
///
/// # Errors
/// Returns the same representation/depth failures as [`write`].
pub fn digest_raw(raw: &RawValue) -> Result<String, Error> {
    let mut output = HashWriter(Sha256::new());
    write(raw, &mut output)?;
    Ok(format!("{:x}", output.0.finalize()))
}

/// Serialize a typed value losslessly, then digest its canonical semantics.
///
/// # Errors
/// Rejects serialization and canonicalization failures. Caller-owned size limits
/// must be admitted before this allocates the intermediate serialized source.
pub fn digest<T: Serialize>(value: &T) -> Result<String, Error> {
    let raw = serde_json::value::to_raw_value(value).map_err(Error::Json)?;
    digest_raw(&raw)
}
