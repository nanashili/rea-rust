//! Lossless JSON string ownership, including unpaired UTF-16 surrogate escapes.

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use serde_json::value::RawValue;
use std::fmt;

/// Failure to interpret or preserve a JSON string's exact code units.
#[derive(Debug)]
pub enum JsonTextError {
    /// The source is not a valid JSON string.
    InvalidString,
    /// The decoded representation cannot be encoded losslessly.
    InvalidEncoding(&'static str),
}

impl fmt::Display for JsonTextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidString => formatter.write_str("invalid JSON string"),
            Self::InvalidEncoding(reason) => formatter.write_str(reason),
        }
    }
}
impl std::error::Error for JsonTextError {}

/// A JSON string that may not be representable as Unicode scalar values.
///
/// Ordinary text uses a Rust String. Unpaired UTF-16 code units retain a
/// canonical escaped JSON string rather than replacement characters. Consumers
/// must serialize this value or explicitly handle `as_str() == None`.
#[derive(Debug)]
pub struct JsonText(Text);

#[derive(Debug)]
enum Text {
    Unicode(String),
    Unpaired(Box<RawValue>),
}

impl JsonText {
    /// Construct a JSON string from its exact UTF-16 code units.
    pub fn from_utf16_units(units: &[u16]) -> Result<Self, JsonTextError> {
        if let Ok(value) = String::from_utf16(units) {
            return Ok(Self(Text::Unicode(value)));
        }

        let mut json = String::from("\"");
        let mut index = 0;

        while index < units.len() {
            let unit = units[index];
            if (0xd800..=0xdbff).contains(&unit)
                && units
                    .get(index + 1)
                    .is_some_and(|next| (0xdc00..=0xdfff).contains(next))
            {
                let low = units[index + 1];
                let code_point =
                    0x1_0000 + ((u32::from(unit) - 0xd800) << 10) + (u32::from(low) - 0xdc00);
                let character = char::from_u32(code_point)
                    .ok_or(JsonTextError::InvalidEncoding("invalid surrogate pair"))?;
                append_escaped(&mut json, &character.to_string())
                    .map_err(JsonTextError::InvalidEncoding)?;
                index += 2;
                continue;
            }

            if (0xd800..=0xdfff).contains(&unit) {
                json.push_str(&format!("\\u{unit:04x}"));
            } else {
                let character = char::from_u32(u32::from(unit))
                    .ok_or(JsonTextError::InvalidEncoding("invalid UTF-16 code unit"))?;
                append_escaped(&mut json, &character.to_string())
                    .map_err(JsonTextError::InvalidEncoding)?;
            }
            index += 1;
        }

        json.push('"');
        let raw = RawValue::from_string(json)
            .map_err(|_| JsonTextError::InvalidEncoding("invalid escaped JSON string"))?;
        // `RawValue` has already validated the complete JSON string. Keep the
        // escaped representation directly: deserializing it again asks the
        // serde JSON reader to materialize surrogate escapes as a Rust string,
        // which can reject adjacent unpaired units even though the JSON text
        // is valid and lossless for JavaScript.
        Ok(Self(Text::Unpaired(raw)))
    }

    /// Unicode text when all code units are paired; otherwise explicitly unknown.
    pub fn as_str(&self) -> Option<&str> {
        match &self.0 {
            Text::Unicode(value) => Some(value),
            Text::Unpaired(_) => None,
        }
    }

    /// Decode a validated raw JSON value without losing UTF-16 code units.
    ///
    /// # Errors
    /// Rejects non-string values and any invalid decoded representation.
    pub fn parse(raw: &RawValue) -> Result<Self, JsonTextError> {
        let units = decode_json_string_units(raw.get())?;
        Self::from_utf16_units(&units)
    }

    /// Exact UTF-16 key ordering used by ECMAScript and REA canonical digests.
    ///
    /// # Errors
    /// Returns an explicit failure if a retained escaped value is invalid.
    pub fn utf16_units(&self) -> Result<Vec<u16>, JsonTextError> {
        match &self.0 {
            Text::Unicode(text) => Ok(text.encode_utf16().collect()),
            Text::Unpaired(raw) => decode_json_string_units(raw.get()),
        }
    }

    fn from_wtf8(decoded: Vec<u8>) -> Result<Self, &'static str> {
        match String::from_utf8(decoded) {
            Ok(value) => Ok(Self(Text::Unicode(value))),
            Err(error) => {
                let bytes = error.into_bytes();
                let mut json = String::from("\"");
                visit_wtf8(&bytes, |part| {
                    match part {
                        Part::Unicode(text) => append_escaped(&mut json, text)?,
                        Part::Surrogate(code) => {
                            json.push_str("\\u");
                            const HEX: &[u8; 16] = b"0123456789abcdef";
                            for shift in [12, 8, 4, 0] {
                                json.push(char::from(HEX[usize::from((code >> shift) & 15)]));
                            }
                        }
                    }
                    Ok(())
                })?;
                json.push('"');
                let raw = RawValue::from_string(json).map_err(|_| "invalid escaped JSON string")?;
                Ok(Self(Text::Unpaired(raw)))
            }
        }
    }
}

fn decode_json_string_units(raw: &str) -> Result<Vec<u16>, JsonTextError> {
    let bytes = raw.as_bytes();
    if bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return Err(JsonTextError::InvalidString);
    }

    let mut units = Vec::new();
    let mut index = 1;
    while index < bytes.len() - 1 {
        if bytes[index] == b'\\' {
            index += 1;
            let escape = *bytes.get(index).ok_or(JsonTextError::InvalidString)?;
            if escape == b'u' {
                let digits = bytes
                    .get(index + 1..index + 5)
                    .ok_or(JsonTextError::InvalidString)?;
                let mut unit = 0u16;
                for digit in digits {
                    let nibble = match digit {
                        b'0'..=b'9' => digit - b'0',
                        b'a'..=b'f' => digit - b'a' + 10,
                        b'A'..=b'F' => digit - b'A' + 10,
                        _ => return Err(JsonTextError::InvalidString),
                    };
                    unit = (unit << 4) | u16::from(nibble);
                }
                units.push(unit);
                index += 5;
                continue;
            }
            let character = match escape {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                _ => return Err(JsonTextError::InvalidString),
            };
            let mut encoded = [0; 2];
            units.extend(character.encode_utf16(&mut encoded).iter().copied());
            index += 1;
            continue;
        }

        if bytes[index] < 0x20 {
            return Err(JsonTextError::InvalidString);
        }
        let text = &raw[index..raw.len() - 1];
        let character = text.chars().next().ok_or(JsonTextError::InvalidString)?;
        if character == '"' {
            return Err(JsonTextError::InvalidString);
        }
        let mut encoded = [0; 2];
        units.extend(character.encode_utf16(&mut encoded).iter().copied());
        index += character.len_utf8();
    }
    Ok(units)
}

enum Part<'a> {
    Unicode(&'a str),
    Surrogate(u16),
}

fn visit_wtf8(
    mut remaining: &[u8],
    mut visit: impl FnMut(Part<'_>) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    while !remaining.is_empty() {
        let valid = match std::str::from_utf8(remaining) {
            Ok(text) => {
                visit(Part::Unicode(text))?;
                break;
            }
            Err(error) => error.valid_up_to(),
        };
        visit(Part::Unicode(
            std::str::from_utf8(&remaining[..valid]).map_err(|_| "invalid UTF-8 prefix")?,
        ))?;
        remaining = &remaining[valid..];
        // serde_json's byte-string reader emits WTF-8 only for escaped unpaired
        // surrogates; arbitrary invalid source UTF-8 is never admitted here.
        let [0xed, middle @ 0xa0..=0xbf, low @ 0x80..=0xbf, ..] = remaining else {
            return Err("invalid WTF-8 string");
        };
        visit(Part::Surrogate(
            0xd000 | (u16::from(*middle & 0x3f) << 6) | u16::from(*low & 0x3f),
        ))?;
        remaining = &remaining[3..];
    }
    Ok(())
}

impl<'de> Deserialize<'de> for JsonText {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let decoded = Wtf8::deserialize(deserializer)?;
        Self::from_wtf8(decoded.0).map_err(de::Error::custom)
    }
}

fn append_escaped(output: &mut String, text: &str) -> Result<(), &'static str> {
    if text.is_empty() {
        return Ok(());
    }
    let encoded = serde_json::to_string(text).map_err(|_| "could not encode JSON text")?;
    output.push_str(&encoded[1..encoded.len() - 1]);
    Ok(())
}

impl Serialize for JsonText {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Text::Unicode(value) => serializer.serialize_str(value),
            Text::Unpaired(raw) => raw.serialize(serializer),
        }
    }
}

struct Wtf8(Vec<u8>);
impl<'de> Deserialize<'de> for Wtf8 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Wtf8;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON string")
            }
            fn visit_str<E: de::Error>(self, text: &str) -> Result<Wtf8, E> {
                Ok(Wtf8(text.as_bytes().to_vec()))
            }
            fn visit_borrowed_str<E: de::Error>(self, text: &'de str) -> Result<Wtf8, E> {
                Ok(Wtf8(text.as_bytes().to_vec()))
            }
            fn visit_string<E: de::Error>(self, text: String) -> Result<Wtf8, E> {
                Ok(Wtf8(text.into_bytes()))
            }
            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Wtf8, E> {
                Ok(Wtf8(bytes.to_vec()))
            }
            fn visit_borrowed_bytes<E: de::Error>(self, bytes: &'de [u8]) -> Result<Wtf8, E> {
                Ok(Wtf8(bytes.to_vec()))
            }
        }
        deserializer.deserialize_bytes(Visitor)
    }
}
