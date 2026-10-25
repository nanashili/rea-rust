//! Self-contained ASAR (Electron archive) classification probe and reader.
//!
//! Compatibility owners: `src/artifacts/AsarHeader.ts` (Pickle extents and the
//! bounded signature probe), `src/artifacts/AsarListing.ts` (header tree
//! expansion and budgets) and `src/artifacts/AsarArtifactReader.ts` (packed and
//! unpacked member ranges). An ASAR file is a two-Pickle prefix (`4` + the
//! JSON header pickle) followed by the packed payload; member `offset` values
//! are relative to `8 + headerBytes`.
use super::classify::AsarProbe;
use super::reader::{ArtifactEntry, ArtifactReader, ArtifactTraversalOmission, ReaderFailure};
use rea_core::JsString;
use rea_core::cancellation::Cancellation;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Number;
#[cfg(test)]
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

const MAX_ASAR_HEADER_BYTES: u64 = 16 * 1024 * 1024;
const MAX_ASAR_HEADER_PROBE_BYTES: u64 = MAX_ASAR_HEADER_BYTES + 8;
const MAX_LISTING_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_ASAR_JSON_DEPTH: usize = 1024;
const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

struct Extents {
    header_bytes: u64,
    json_bytes: u64,
}

/// Lossless JSON value used only while decoding the ASAR header.
///
/// `serde_json::Value` stores object keys and strings as Rust `String`s. That
/// representation rejects escaped unpaired UTF-16 surrogates, so ASAR header
/// decoding must retain JavaScript strings until the logical-path boundary.
#[derive(Debug)]
enum AsarValue {
    Null,
    Bool(bool),
    Number(Number),
    String(JsString),
    Array(Vec<Self>),
    Object(Vec<(JsString, Self)>),
}

impl AsarValue {
    fn parse_json(input: &[u8]) -> Result<Self, String> {
        let mut parser = JsonParser {
            input,
            index: 0,
            depth: 0,
        };
        let value = parser.value()?;
        parser.whitespace();
        if parser.index != input.len() {
            return Err("trailing bytes after ASAR JSON header".to_owned());
        }
        Ok(value)
    }
}

struct JsonParser<'a> {
    input: &'a [u8],
    index: usize,
    depth: usize,
}

impl<'a> JsonParser<'a> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.index)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.index += 1;
        }
    }

    fn value(&mut self) -> Result<AsarValue, String> {
        if self.depth >= MAX_ASAR_JSON_DEPTH {
            return Err(format!(
                "ASAR JSON nesting exceeds the {MAX_ASAR_JSON_DEPTH}-level decode limit"
            ));
        }
        self.depth += 1;
        self.whitespace();
        let result = match self.input.get(self.index).copied() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(AsarValue::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(AsarValue::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(AsarValue::Bool(false))
            }
            Some(b'"') => Ok(AsarValue::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            _ => Err("invalid JSON value in ASAR header".to_owned()),
        };
        self.depth -= 1;
        result
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), String> {
        if self.input.get(self.index..self.index + literal.len()) == Some(literal) {
            self.index += literal.len();
            Ok(())
        } else {
            Err("invalid JSON literal in ASAR header".to_owned())
        }
    }

    fn string(&mut self) -> Result<JsString, String> {
        if self.input.get(self.index) != Some(&b'"') {
            return Err("ASAR JSON string must begin with a quote".to_owned());
        }
        self.index += 1;
        let mut units = Vec::new();
        while let Some(byte) = self.input.get(self.index).copied() {
            self.index += 1;
            match byte {
                b'"' => return Ok(JsString::from_utf16(units)),
                b'\\' => self.escape(&mut units)?,
                0..=0x1f => return Err("control character in ASAR JSON string".to_owned()),
                _ => {
                    let start = self.index - 1;
                    let width = utf8_width(byte)?;
                    let end = start + width;
                    let character = std::str::from_utf8(
                        self.input
                            .get(start..end)
                            .ok_or_else(|| "truncated UTF-8 in ASAR JSON string".to_owned())?,
                    )
                    .map_err(|_| "invalid UTF-8 in ASAR JSON string".to_owned())?;
                    units.extend(character.encode_utf16());
                    self.index = end;
                }
            }
        }
        Err("unterminated ASAR JSON string".to_owned())
    }

    fn escape(&mut self, units: &mut Vec<u16>) -> Result<(), String> {
        let escaped = self
            .input
            .get(self.index)
            .copied()
            .ok_or_else(|| "truncated escape in ASAR JSON string".to_owned())?;
        self.index += 1;
        match escaped {
            b'"' => units.push(u16::from(b'"')),
            b'\\' => units.push(u16::from(b'\\')),
            b'/' => units.push(u16::from(b'/')),
            b'b' => units.push(8),
            b'f' => units.push(12),
            b'n' => units.push(10),
            b'r' => units.push(13),
            b't' => units.push(9),
            b'u' => units.push(self.hex_escape()?),
            _ => return Err("invalid escape in ASAR JSON string".to_owned()),
        }
        Ok(())
    }

    fn hex_escape(&mut self) -> Result<u16, String> {
        let digits = self
            .input
            .get(self.index..self.index + 4)
            .ok_or_else(|| "truncated Unicode escape in ASAR JSON string".to_owned())?;
        self.index += 4;
        digits.iter().try_fold(0u16, |value, digit| {
            let nibble = match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err("invalid Unicode escape in ASAR JSON string".to_owned()),
            };
            Ok((value << 4) | u16::from(nibble))
        })
    }

    fn array(&mut self) -> Result<AsarValue, String> {
        self.index += 1;
        let mut values = Vec::new();
        self.whitespace();
        if self.input.get(self.index) == Some(&b']') {
            self.index += 1;
            return Ok(AsarValue::Array(values));
        }
        loop {
            values.push(self.value()?);
            self.whitespace();
            match self.input.get(self.index).copied() {
                Some(b',') => self.index += 1,
                Some(b']') => {
                    self.index += 1;
                    return Ok(AsarValue::Array(values));
                }
                _ => return Err("invalid ASAR JSON array".to_owned()),
            }
        }
    }

    fn object(&mut self) -> Result<AsarValue, String> {
        self.index += 1;
        let mut values = Vec::new();
        self.whitespace();
        if self.input.get(self.index) == Some(&b'}') {
            self.index += 1;
            return Ok(AsarValue::Object(values));
        }
        loop {
            self.whitespace();
            let key = self.string()?;
            self.whitespace();
            if self.input.get(self.index) != Some(&b':') {
                return Err("invalid ASAR JSON object".to_owned());
            }
            self.index += 1;
            values.push((key, self.value()?));
            self.whitespace();
            match self.input.get(self.index).copied() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    return Ok(AsarValue::Object(values));
                }
                _ => return Err("invalid ASAR JSON object".to_owned()),
            }
        }
    }

    fn number(&mut self) -> Result<AsarValue, String> {
        let start = self.index;
        while self
            .input
            .get(self.index)
            .is_some_and(|byte| matches!(byte, b'+' | b'-' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.index += 1;
        }
        let text = std::str::from_utf8(&self.input[start..self.index])
            .map_err(|_| "invalid ASAR JSON number".to_owned())?;
        let number = serde_json::from_str::<Number>(text)
            .map_err(|_| "invalid ASAR JSON number".to_owned())?;
        Ok(AsarValue::Number(number))
    }
}

fn utf8_width(first: u8) -> Result<usize, String> {
    match first {
        0x00..=0x7f => Ok(1),
        0xc2..=0xdf => Ok(2),
        0xe0..=0xef => Ok(3),
        0xf0..=0xf4 => Ok(4),
        _ => Err("invalid UTF-8 in ASAR JSON string".to_owned()),
    }
}

impl<'de> Deserialize<'de> for AsarValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct AsarValueVisitor;

        impl<'de> Visitor<'de> for AsarValueVisitor {
            type Value = AsarValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON value with lossless UTF-16 strings")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AsarValue::Null)
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AsarValue::Bool(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AsarValue::Number(Number::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AsarValue::Number(Number::from(value)))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Number::from_f64(value)
                    .map(AsarValue::Number)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AsarValue::String(JsString::from(value)))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(AsarValue::String(JsString::from(value)))
            }

            fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = access.next_element()? {
                    values.push(value);
                }
                Ok(AsarValue::Array(values))
            }

            fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some((key, value)) = access.next_entry::<JsString, AsarValue>()? {
                    values.push((key, value));
                }
                Ok(AsarValue::Object(values))
            }
        }

        deserializer.deserialize_any(AsarValueVisitor)
    }
}

/// `parseAsarHeaderExtents` over the fixed 16-byte prefix. `archive_bytes` is
/// the observed container size when known.
fn parse_extents(prefix: &[u8], archive_bytes: Option<u64>) -> Result<Extents, ReaderFailure> {
    if prefix.len() < 16 {
        return Err(ReaderFailure::new(
            "format",
            "Truncated ASAR Pickle extent prefix",
        ));
    }
    let read = |o: usize| {
        u32::from_le_bytes([prefix[o], prefix[o + 1], prefix[o + 2], prefix[o + 3]]) as u64
    };
    let header_bytes = read(4);
    let payload_bytes = read(8);
    let json_bytes = read(12);
    if read(0) != 4
        || header_bytes < 8
        || payload_bytes != header_bytes.wrapping_sub(4)
        || json_bytes > payload_bytes.wrapping_sub(4)
    {
        return Err(ReaderFailure::new(
            "format",
            "ASAR header has invalid Pickle extents",
        ));
    }
    if let Some(archive_bytes) = archive_bytes
        && (archive_bytes < 8 || header_bytes > archive_bytes - 8)
    {
        return Err(ReaderFailure::new(
            "format",
            "ASAR header leaves its observed container",
        ));
    }
    Ok(Extents {
        header_bytes,
        json_bytes,
    })
}

fn is_json_ws(value: u8) -> bool {
    value == 0x20 || value == 0x09 || value == 0x0a || value == 0x0d
}

/// Finalized ASAR signature probe over the retained prefix.
pub fn asar_header_matches(prefix: &[u8], archive_bytes: u64) -> AsarProbe {
    let extents = match parse_extents(prefix, Some(archive_bytes)) {
        Ok(extents) => extents,
        Err(_) => return AsarProbe::Rejected,
    };
    if extents.json_bytes == 0 {
        return AsarProbe::Rejected;
    }
    if extents.header_bytes > MAX_ASAR_HEADER_BYTES {
        return AsarProbe::Limit;
    }
    let json_start = 16usize;
    let mut scanned: u64 = 0;
    while scanned < extents.json_bytes {
        if 16 + scanned >= MAX_ASAR_HEADER_PROBE_BYTES {
            return AsarProbe::Limit;
        }
        let index = json_start + scanned as usize;
        if index >= prefix.len() {
            return AsarProbe::Limit;
        }
        let value = prefix[index];
        if !is_json_ws(value) {
            return if value == 0x7b {
                AsarProbe::Matched
            } else {
                AsarProbe::Rejected
            };
        }
        scanned += 1;
    }
    AsarProbe::Rejected
}

/// One expanded header-tree entry.
struct ListedEntry {
    path: JsString,
    kind: &'static str,
    declared_size: Option<u64>,
    executable: bool,
    declared_sha256: Option<String>,
    unpacked: bool,
    offset: Option<u64>,
    codesign_empty: bool,
}

struct ParsedIntegrity {
    algorithm: String,
    hash: String,
}

struct ParsedNode {
    files: Option<Vec<(JsString, AsarValue)>>,
    link: Option<JsString>,
    size: Option<u64>,
    offset: Option<JsString>,
    unpacked: Option<bool>,
    executable: Option<bool>,
    integrity: Option<ParsedIntegrity>,
    /// The observed Figma code-signing metadata uses `size: -1000` alongside
    /// an explicit SHA-256 digest of the empty payload. Keep this marker until
    /// the logical path and the other fields are available so this compatibility
    /// exception cannot be applied to arbitrary entries.
    codesign_empty: bool,
}

fn javascript_array_index(name: &JsString) -> Option<u32> {
    let name = name.as_str()?;
    if name == "0" {
        return Some(0);
    }
    if name.starts_with('0') {
        return None;
    }

    if !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    name.parse::<u32>()
        .ok()
        .filter(|index| *index < u32::MAX && index.to_string() == name)
}

fn owned_children(map: Vec<(JsString, AsarValue)>) -> std::vec::IntoIter<(JsString, AsarValue)> {
    let mut children = map;
    children.sort_by(|(left, _), (right, _)| {
        match (javascript_array_index(left), javascript_array_index(right)) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    children.into_iter()
}

fn remove_field(object: &mut Vec<(JsString, AsarValue)>, field: &str) -> Option<AsarValue> {
    object
        .iter()
        .rposition(|(name, _)| name == field)
        .map(|index| object.swap_remove(index).1)
}

fn optional_string(
    object: &mut Vec<(JsString, AsarValue)>,
    field: &str,
) -> Result<Option<JsString>, ReaderFailure> {
    remove_field(object, field)
        .map(|value| match value {
            AsarValue::String(value) => Ok(value),
            _ => Err(ReaderFailure::new(
                "format",
                format!("ASAR entry {field} metadata is not a string"),
            )),
        })
        .transpose()
}

fn optional_boolean(
    object: &mut Vec<(JsString, AsarValue)>,
    field: &str,
) -> Result<Option<bool>, ReaderFailure> {
    remove_field(object, field)
        .map(|value| match value {
            AsarValue::Bool(value) => Ok(value),
            _ => Err(ReaderFailure::new(
                "format",
                format!("ASAR entry {field} metadata is not a boolean"),
            )),
        })
        .transpose()
}

fn optional_size(
    object: &mut Vec<(JsString, AsarValue)>,
) -> Result<(Option<u64>, bool), ReaderFailure> {
    remove_field(object, "size")
        .map(|value| {
            let AsarValue::Number(number) = value else {
                return Err(ReaderFailure::new(
                    "format",
                    "ASAR entry size metadata is not a non-negative safe integer",
                ));
            };
            if number.as_i64() == Some(-1000) {
                return Ok((Some(0), true));
            }
            if let Some(size) = number.as_u64() {
                if size <= MAX_SAFE_INTEGER {
                    return Ok((Some(size), false));
                }
                return Err(ReaderFailure::new(
                    "format",
                    "ASAR entry size metadata is not a non-negative safe integer",
                ));
            }
            let size = number.as_f64().ok_or_else(|| {
                ReaderFailure::new(
                    "format",
                    "ASAR entry size metadata is not a non-negative safe integer",
                )
            })?;
            if !size.is_finite()
                || size < 0.0
                || size.fract() != 0.0
                || size > MAX_SAFE_INTEGER as f64
            {
                return Err(ReaderFailure::new(
                    "format",
                    "ASAR entry size metadata is not a non-negative safe integer",
                ));
            }
            Ok((Some(size as u64), false))
        })
        .transpose()
        .map(|value| value.unwrap_or((None, false)))
}

fn optional_integrity(
    object: &mut Vec<(JsString, AsarValue)>,
) -> Result<Option<ParsedIntegrity>, ReaderFailure> {
    remove_field(object, "integrity")
        .map(|value| {
            let AsarValue::Object(integrity) = value else {
                return Err(ReaderFailure::new(
                    "format",
                    "ASAR entry integrity metadata is not an object",
                ));
            };
            let field = |name: &str| {
                integrity
                    .iter()
                    .rev()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value)
            };
            let algorithm = match field("algorithm") {
                Some(AsarValue::String(value)) => value.try_to_string().map_err(|_| {
                    ReaderFailure::new(
                        "format",
                        "ASAR entry integrity algorithm contains invalid UTF-16",
                    )
                })?,
                _ => {
                    return Err(ReaderFailure::new(
                        "format",
                        "ASAR entry integrity algorithm is not a string",
                    ));
                }
            };
            let hash = match field("hash") {
                Some(AsarValue::String(value)) => value.try_to_string().map_err(|_| {
                    ReaderFailure::new(
                        "format",
                        "ASAR entry integrity hash contains invalid UTF-16",
                    )
                })?,
                _ => {
                    return Err(ReaderFailure::new(
                        "format",
                        "ASAR entry integrity hash is not a string",
                    ));
                }
            };
            Ok(ParsedIntegrity { algorithm, hash })
        })
        .transpose()
}

impl ParsedNode {
    fn parse(raw: AsarValue) -> Result<Self, ReaderFailure> {
        let mut object = match raw {
            AsarValue::Object(object) => object,
            _ => {
                return Err(ReaderFailure::new(
                    "format",
                    "ASAR entry metadata is not an object",
                ));
            }
        };

        let files = object
            .iter()
            .rposition(|(name, _)| name == "files")
            .map(|index| object.swap_remove(index).1)
            .map(|value| match value {
                AsarValue::Object(files) => Ok(files),
                _ => Err(ReaderFailure::new(
                    "format",
                    "ASAR entry files metadata is not an object",
                )),
            })
            .transpose()?;
        let link = optional_string(&mut object, "link")?;
        let (size, codesign_empty) = optional_size(&mut object)?;
        let offset = optional_string(&mut object, "offset")?;
        let unpacked = optional_boolean(&mut object, "unpacked")?;
        let executable = optional_boolean(&mut object, "executable")?;
        let integrity = optional_integrity(&mut object)?;

        Ok(Self {
            files,
            link,
            size,
            offset,
            unpacked,
            executable,
            integrity,
            codesign_empty,
        })
    }
}

impl ListedEntry {
    fn artifact_entry(&self) -> ArtifactEntry {
        ArtifactEntry {
            path: self.path.clone(),
            kind: self.kind,
            declared_size: self.declared_size,
            compressed_size: None,
            executable: self.executable,
            encrypted: false,
            byte_offset: None,
            declared_sha256: self.declared_sha256.clone(),
            unpacked: self.unpacked,
            limitations: if self.kind == "symlink" {
                vec!["ASAR symlink target was not followed or disclosed.".to_owned()]
            } else if self.codesign_empty {
                vec![
                    "ASAR .codesign entry declared size -1000 and the observed empty SHA-256; interpreted payload bytes as empty."
                        .to_owned(),
                ]
            } else {
                Vec::new()
            },
            adapter_key: self.path.clone(),
        }
    }

    fn packed_range(
        &self,
        header_bytes: u64,
        archive_bytes: usize,
    ) -> Result<std::ops::Range<usize>, ReaderFailure> {
        let invalid_range = || {
            ReaderFailure::new(
                "format",
                format!("ASAR entry range is outside its container: {}", self.path),
            )
        };
        let size = self.declared_size.ok_or_else(invalid_range)?;
        let offset = self.offset.ok_or_else(invalid_range)?;
        let start = header_bytes
            .checked_add(8)
            .and_then(|start| start.checked_add(offset))
            .filter(|start| *start <= MAX_SAFE_INTEGER)
            .ok_or_else(invalid_range)?;

        let archive_bytes = archive_bytes as u64;
        if size > MAX_SAFE_INTEGER || start > archive_bytes || size > archive_bytes - start {
            return Err(invalid_range());
        }

        Ok(start as usize..(start + size) as usize)
    }
}

/// Offsets use the same canonical decimal and safe-integer rules as Electron's
/// JavaScript adapter; a Rust integer accepting more values does not expand the
/// archive format's admitted range.
fn parse_archive_offset(value: &JsString) -> Option<u64> {
    let value = value.as_str()?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }

    value
        .parse()
        .ok()
        .filter(|offset| *offset <= MAX_SAFE_INTEGER)
}

fn node_integrity_sha256(integrity: Option<&ParsedIntegrity>) -> Option<String> {
    let integrity = integrity?;
    if integrity.algorithm != "SHA256" {
        return None;
    }
    let hash = &integrity.hash;
    if hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        Some(hash.to_owned())
    } else {
        None
    }
}

/// `readAsarListing`: depth-first expansion with path-component admission and a
/// bounded representation budget. Returns entries sorted by logical path.
fn read_listing(
    header: AsarValue,
    cancellation: &Cancellation,
) -> Result<Vec<ListedEntry>, ReaderFailure> {
    let root = ParsedNode::parse(header)?;
    let root_files = root
        .files
        .ok_or_else(|| ReaderFailure::new("format", "ASAR root has no files table"))?;
    // Frames own their `(name, node)` pairs so subtrees can be pushed without
    // borrowing the parent map.
    struct Frame {
        parent: JsString,
        children: std::vec::IntoIter<(JsString, AsarValue)>,
    }
    let mut entries: Vec<ListedEntry> = Vec::new();
    let mut pending = vec![Frame {
        parent: JsString::from(""),
        children: owned_children(root_files),
    }];
    let mut retained_bytes: u64 = 0;
    let mut examined: u64 = 0;
    loop {
        if pending.is_empty() {
            break;
        }

        if examined % 128 == 0 && cancellation.reason().is_some() {
            return Err(ReaderFailure::new("cancelled", "ASAR operation cancelled"));
        }
        examined += 1;
        let (parent, name, raw) = {
            let frame = pending.last_mut().expect("listing frame exists");
            let Some((name, raw)) = frame.children.next() else {
                pending.pop();
                continue;
            };
            (frame.parent.clone(), name, raw)
        };
        if name.is_empty()
            || name == "."
            || name == ".."
            || name.units().iter().any(|unit| {
                *unit == u16::from(b'/')
                    || *unit == 0
                    || (cfg!(windows) && *unit == u16::from(b'\\'))
            })
        {
            return Err(ReaderFailure::new(
                "path",
                "ASAR header has an unsafe path component",
            ));
        }
        let units = parent.len() + name.len() + if parent.is_empty() { 0 } else { 1 };
        retained_bytes += units as u64 * 2 + 256;
        if retained_bytes > MAX_LISTING_BYTES {
            return Err(ReaderFailure::new(
                "limit",
                "ASAR expanded listing exceeds its 64 MiB representation budget",
            ));
        }
        let path = if parent.is_empty() {
            name.clone()
        } else {
            parent.concat_str("/").concat(&name)
        };
        let node = ParsedNode::parse(raw)?;
        if node.codesign_empty && !is_observed_empty_codesign(&path, &node) {
            return Err(ReaderFailure::new(
                "format",
                "ASAR size -1000 marker requires an observed empty .codesign entry",
            ));
        }
        if node.files.is_none() && node.link.is_none() && node.size.is_none() {
            return Err(ReaderFailure::new(
                "format",
                "ASAR entry has no directory, link or file metadata",
            ));
        }
        let kind = if node.files.is_some() {
            "directory"
        } else if node.link.is_some() {
            "symlink"
        } else {
            "file"
        };
        entries.push(ListedEntry {
            path: path.clone(),
            kind,
            declared_size: node.size,
            executable: node.executable == Some(true),
            declared_sha256: node_integrity_sha256(node.integrity.as_ref()),
            unpacked: node.unpacked == Some(true),
            offset: node.offset.as_ref().and_then(parse_archive_offset),
            codesign_empty: node.codesign_empty,
        });
        if let Some(files) = node.files {
            pending.push(Frame {
                parent: path,
                children: owned_children(files),
            });
        }
    }
    entries.sort_by(|a, b| a.path.compare_code_points(&b.path));
    Ok(entries)
}

fn is_observed_empty_codesign(path: &JsString, node: &ParsedNode) -> bool {
    let is_codesign_path = path
        .as_str()
        .is_some_and(|path| path == ".codesign" || path.ends_with("/.codesign"));
    let has_empty_integrity = node
        .integrity
        .as_ref()
        .is_some_and(|integrity| integrity.algorithm == "SHA256" && integrity.hash == EMPTY_SHA256);
    is_codesign_path
        && node.offset.as_ref().and_then(JsString::as_str) == Some("0")
        && node.files.is_none()
        && node.link.is_none()
        && node.unpacked != Some(true)
        && has_empty_integrity
}

/// ASAR reader over an in-memory capture of the whole container.
pub struct AsarArtifactReader {
    bytes: Arc<[u8]>,
    header_bytes: u64,
    listing: Vec<ListedEntry>,
    prepared: bool,
}

impl AsarArtifactReader {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self::new_shared(bytes.into())
    }

    pub fn new_shared(bytes: Arc<[u8]>) -> Self {
        Self {
            bytes,
            header_bytes: 0,
            listing: Vec::new(),
            prepared: false,
        }
    }

    fn prepare(&mut self, cancellation: &Cancellation) -> Result<(), ReaderFailure> {
        if cancellation.reason().is_some() {
            return Err(ReaderFailure::new("cancelled", "ASAR operation cancelled"));
        }

        if self.prepared {
            return Ok(());
        }
        let archive_bytes = self.bytes.len() as u64;
        if self.bytes.len() < 16 {
            return Err(ReaderFailure::new("format", "Truncated ASAR size pickle"));
        }
        let extents = parse_extents(&self.bytes[..16], Some(archive_bytes))?;
        if extents.header_bytes > MAX_ASAR_HEADER_BYTES {
            return Err(ReaderFailure::new(
                "limit",
                format!("ASAR header exceeds the {MAX_ASAR_HEADER_BYTES} byte decode budget"),
            ));
        }
        self.header_bytes = extents.header_bytes;
        let json_start = 16usize;
        let json_end = json_start + extents.json_bytes as usize;
        if json_end > self.bytes.len() {
            return Err(ReaderFailure::new("format", "ASAR header is truncated"));
        }
        let header = AsarValue::parse_json(&self.bytes[json_start..json_end]).map_err(|error| {
            ReaderFailure::new("format", format!("ASAR header is not valid JSON: {error}"))
        })?;
        self.listing = read_listing(header, cancellation)?;
        self.prepared = true;
        Ok(())
    }
}

impl ArtifactReader for AsarArtifactReader {
    fn format(&self) -> &'static str {
        "asar"
    }

    fn entries(
        &mut self,
        cancellation: &Cancellation,
        _omissions: &mut Vec<ArtifactTraversalOmission>,
    ) -> Result<Vec<ArtifactEntry>, ReaderFailure> {
        self.prepare(cancellation)?;
        Ok(self
            .listing
            .iter()
            .map(ListedEntry::artifact_entry)
            .collect())
    }

    fn open(
        &mut self,
        entry: &ArtifactEntry,
        cancellation: &Cancellation,
    ) -> Result<Vec<u8>, ReaderFailure> {
        self.prepare(cancellation)?;
        let listed = self
            .listing
            .iter()
            .find(|listed| listed.path == entry.adapter_key && listed.kind == "file")
            .ok_or_else(|| {
                if entry.kind != "file" {
                    ReaderFailure::new("format", "ASAR entry is not a regular file")
                } else {
                    ReaderFailure::new(
                        "integrity",
                        format!("ASAR entry was not produced by this reader: {}", entry.path),
                    )
                }
            })?;
        if *entry != listed.artifact_entry() {
            return Err(ReaderFailure::new(
                "integrity",
                format!(
                    "ASAR entry metadata changed since inventory: {}",
                    listed.path
                ),
            ));
        }

        if listed.unpacked {
            return Err(ReaderFailure::new(
                "unavailable",
                format!(
                    "ASAR unpacked companion bytes are unavailable for {}",
                    entry.path
                ),
            ));
        }
        let range = listed.packed_range(self.header_bytes, self.bytes.len())?;
        Ok(self.bytes[range].to_vec())
    }

    fn close(&mut self) -> Result<(), ReaderFailure> {
        self.bytes = Arc::from([]);
        self.listing = Vec::new();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_parser_matches_json_whitespace_and_exponent_rules() {
        assert!(AsarValue::parse_json(br#"1e+2"#).is_ok());
        assert!(AsarValue::parse_json(b"\x0b1").is_err());
        assert!(AsarValue::parse_json(b"\x0c1").is_err());
    }

    #[test]
    fn duplicate_metadata_fields_follow_last_property_wins() {
        let parsed = ParsedNode::parse(
            AsarValue::parse_json(br#"{"size":1,"size":2}"#).expect("valid JSON"),
        )
        .expect("valid ASAR metadata");
        assert_eq!(parsed.size, Some(2));
    }

    #[test]
    fn json_parser_rejects_excessive_nesting_before_stack_growth() {
        let mut input = vec![b'['; MAX_ASAR_JSON_DEPTH + 1];
        input.extend(std::iter::repeat(b']').take(MAX_ASAR_JSON_DEPTH + 1));
        let failure = AsarValue::parse_json(&input).expect_err("depth limit must apply");
        assert!(failure.contains("nesting"));
    }

    fn archive_with_header(header_value: Value, payload: &[u8]) -> AsarArtifactReader {
        let header = serde_json::to_vec(&header_value).expect("fixture header serializes");
        archive_with_serialized_header(&header, payload)
    }

    fn archive_with_serialized_header(header: &[u8], payload: &[u8]) -> AsarArtifactReader {
        let padded_header_bytes = (header.len() + 3) & !3;
        let header_bytes = u32::try_from(8 + padded_header_bytes).expect("small fixture header");
        let mut bytes = Vec::new();
        for extent in [
            4,
            header_bytes,
            header_bytes - 4,
            u32::try_from(header.len()).expect("small fixture JSON"),
        ] {
            bytes.extend_from_slice(&extent.to_le_bytes());
        }
        bytes.extend_from_slice(header);
        bytes.resize(16 + padded_header_bytes, 0);
        bytes.extend_from_slice(payload);

        AsarArtifactReader::new(bytes)
    }

    fn archive_with_file(metadata: Value, payload: &[u8]) -> AsarArtifactReader {
        archive_with_file_path("main.js", metadata, payload)
    }

    fn archive_with_file_path(path: &str, metadata: Value, payload: &[u8]) -> AsarArtifactReader {
        let mut files = serde_json::Map::new();
        files.insert(path.to_owned(), metadata);
        archive_with_header(json!({"files": files}), payload)
    }

    fn file_entry(reader: &mut AsarArtifactReader) -> ArtifactEntry {
        reader
            .entries(&Cancellation::default(), &mut Vec::new())
            .expect("fixture listing is valid")
            .pop()
            .expect("fixture has one entry")
    }

    #[test]
    fn member_open_rejects_changed_inventory_metadata() {
        let mut reader = archive_with_file(json!({"size": 3, "offset": "0"}), b"abc");
        let entry = file_entry(&mut reader);
        let changes: &[(&str, fn(&mut ArtifactEntry))] = &[
            ("path", |entry| entry.path = JsString::from("other.js")),
            ("kind", |entry| entry.kind = "directory"),
            ("declared_size", |entry| entry.declared_size = Some(2)),
            ("compressed_size", |entry| entry.compressed_size = Some(3)),
            ("executable", |entry| entry.executable = true),
            ("encrypted", |entry| entry.encrypted = true),
            ("byte_offset", |entry| entry.byte_offset = Some(0)),
            ("declared_sha256", |entry| {
                entry.declared_sha256 = Some("0".repeat(64));
            }),
            ("unpacked", |entry| entry.unpacked = true),
            ("limitations", |entry| {
                entry.limitations.push("changed".to_owned());
            }),
        ];

        for (field, change) in changes {
            let mut changed = entry.clone();
            change(&mut changed);
            let failure = reader
                .open(&changed, &Cancellation::default())
                .expect_err(field);
            assert_eq!(failure.reason, "integrity", "{field}");
        }

        assert_eq!(
            reader.open(&entry, &Cancellation::default()).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn member_ranges_reject_noncanonical_and_unrepresentable_offsets() {
        for offset in [
            "",
            "00",
            "+0",
            "-1",
            " 0",
            "1.0",
            "9007199254740992",
            "18446744073709551615",
            "18446744073709551616",
        ] {
            let mut reader = archive_with_file(json!({"size": 1, "offset": offset}), b"x");
            let entry = file_entry(&mut reader);
            let failure = reader
                .open(&entry, &Cancellation::default())
                .expect_err(offset);
            assert_eq!(failure.reason, "format", "{offset:?}");
        }
    }

    #[test]
    fn listing_rejects_sizes_outside_the_javascript_integer_contract() {
        for size in [
            json!(null),
            json!("3"),
            json!(-1),
            json!(1.25),
            json!(9_007_199_254_740_992_u64),
            json!(u64::MAX),
        ] {
            let mut reader = archive_with_file(json!({"size": size, "offset": "0"}), b"abc");
            let failure = reader
                .entries(&Cancellation::default(), &mut Vec::new())
                .expect_err("unsafe declared size must fail during listing");
            assert_eq!(failure.reason, "format", "{size}");
        }

        let mut reader = archive_with_file(json!({"size": 3.0, "offset": "0"}), b"abc");
        let entry = file_entry(&mut reader);
        assert_eq!(entry.declared_size, Some(3));
        assert_eq!(
            reader.open(&entry, &Cancellation::default()).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn listing_accepts_observed_empty_codesign_marker() {
        let mut reader = archive_with_file_path(
            ".codesign",
            json!({
                "size": -1000,
                "offset": "0",
                "integrity": {
                    "algorithm": "SHA256",
                    "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                }
            }),
            b"",
        );
        let entry = file_entry(&mut reader);

        assert_eq!(entry.declared_size, Some(0));
        assert_eq!(entry.limitations.len(), 1);
        assert!(entry.limitations[0].contains("declared size -1000"));
        assert_eq!(reader.open(&entry, &Cancellation::default()).unwrap(), b"");
    }

    #[test]
    fn listing_rejects_codesign_sentinel_on_other_entries() {
        let mut reader = archive_with_file(json!({"size": -1000, "offset": "0"}), b"");
        let failure = reader
            .entries(&Cancellation::default(), &mut Vec::new())
            .expect_err("the observed marker must remain scoped to .codesign");

        assert_eq!(failure.reason, "format");
    }

    #[test]
    fn listing_rejects_codesign_marker_without_observed_empty_integrity() {
        for integrity in [
            json!({"algorithm": "SHA256", "hash": "00"}),
            json!({"algorithm": "SHA256", "hash": "f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
        ] {
            let mut reader = archive_with_file_path(
                ".codesign",
                json!({"size": -1000, "offset": "0", "integrity": integrity}),
                b"",
            );
            let failure = reader
                .entries(&Cancellation::default(), &mut Vec::new())
                .expect_err("a non-empty or malformed integrity claim must fail closed");
            assert_eq!(failure.reason, "format");
        }
    }

    #[test]
    fn listing_preserves_nonfile_metadata_without_allowing_member_reads() {
        for (kind, metadata) in [
            ("directory", json!({"files": {}, "size": 7})),
            ("symlink", json!({"link": "other.js", "size": 7})),
        ] {
            let mut reader = archive_with_file(metadata, b"");
            let entry = file_entry(&mut reader);
            assert_eq!(entry.kind, kind);
            assert_eq!(entry.declared_size, Some(7));

            let failure = reader
                .open(&entry, &Cancellation::default())
                .expect_err("only regular files supply member bytes");
            assert_eq!(failure.reason, "format", "{kind}");
        }
    }

    #[test]
    fn listing_rejects_invalid_known_metadata_at_root_and_member_boundaries() {
        let cases = [
            (
                "root executable",
                json!({"files": {}, "executable": "true"}),
            ),
            ("member files", json!({"size": 1, "files": []})),
            ("member link", json!({"size": 1, "link": 7})),
            ("member offset", json!({"size": 1, "offset": 0})),
            ("member unpacked", json!({"size": 1, "unpacked": "true"})),
            ("member executable", json!({"size": 1, "executable": 1})),
            (
                "member integrity object",
                json!({"size": 1, "integrity": "sha256"}),
            ),
            (
                "member integrity algorithm",
                json!({
                    "size": 1,
                    "integrity": {"algorithm": 256, "hash": "00"}
                }),
            ),
            (
                "member integrity hash",
                json!({"size": 1, "integrity": {"algorithm": "SHA256"}}),
            ),
        ];

        for (label, metadata) in cases {
            let header = if label == "root executable" {
                metadata
            } else {
                json!({"files": {"main.js": metadata}})
            };
            let mut reader = archive_with_header(header, b"x");
            let failure = reader
                .entries(&Cancellation::default(), &mut Vec::new())
                .expect_err(label);
            assert_eq!(failure.reason, "format", "{label}");
        }
    }

    #[test]
    fn listing_preserves_loose_schema_admission_for_unknown_metadata() {
        let header = json!({
            "files": {
                "main.js": {
                    "size": 1,
                    "offset": "0",
                    "futureField": {"meaning": "owned by a newer producer"}
                }
            },
            "futureRootField": ["ignored"]
        });
        let mut reader = archive_with_header(header, b"x");

        let entry = file_entry(&mut reader);
        assert_eq!(entry.path, JsString::from("main.js"));
        assert_eq!(reader.open(&entry, &Cancellation::default()).unwrap(), b"x");
    }

    #[test]
    fn listing_preserves_unpaired_surrogate_in_member_name() {
        let header = br#"{"files":{"x\ud800.js":{"size":1,"offset":"0"}}}"#;
        let mut reader = archive_with_serialized_header(header, b"x");

        let entry = file_entry(&mut reader);
        assert_eq!(
            entry.path,
            JsString::from_utf16([b'x' as u16, 0xd800, b'.' as u16, b'j' as u16, b's' as u16])
        );
        assert_eq!(reader.open(&entry, &Cancellation::default()).unwrap(), b"x");
    }

    #[test]
    fn child_iteration_matches_javascript_own_property_order() {
        let mut files = serde_json::Map::new();
        files.insert("z".to_owned(), json!({"size": 1}));
        files.insert("10".to_owned(), json!({"size": 1}));
        files.insert("2".to_owned(), json!({"size": 1}));
        files.insert("01".to_owned(), json!({"size": 1}));
        files.insert("+1".to_owned(), json!({"size": 1}));
        files.insert(" 3".to_owned(), json!({"size": 1}));

        let files = files
            .into_iter()
            .map(|(name, value)| {
                (
                    JsString::from(name),
                    serde_json::from_value(value).expect("fixture value is lossless JSON"),
                )
            })
            .collect();
        let names: Vec<_> = owned_children(files)
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        assert_eq!(
            names,
            [
                JsString::from("2"),
                JsString::from("10"),
                JsString::from("z"),
                JsString::from("01"),
                JsString::from("+1"),
                JsString::from(" 3"),
            ]
        );
    }

    #[test]
    fn listing_admits_numeric_children_before_later_inserted_children() {
        let header = json!({
            "files": {
                "2": {"files": {"bad/name": {"size": 1}}},
                "10": {"link": 9}
            }
        });
        let mut reader = archive_with_header(header, b"");

        let failure = reader
            .entries(&Cancellation::default(), &mut Vec::new())
            .expect_err("the first JavaScript child reaches its nested unsafe path");
        assert_eq!(failure.reason, "path");
    }

    #[test]
    fn packed_members_observe_container_end_including_empty_members() {
        let mut reader = archive_with_file(json!({"size": 2, "offset": "1"}), b"abc");
        let entry = file_entry(&mut reader);
        assert_eq!(
            reader.open(&entry, &Cancellation::default()).unwrap(),
            b"bc"
        );

        let mut reader = archive_with_file(json!({"size": 0, "offset": "3"}), b"abc");
        let entry = file_entry(&mut reader);
        assert!(
            reader
                .open(&entry, &Cancellation::default())
                .unwrap()
                .is_empty()
        );

        let mut reader = archive_with_file(json!({"size": 2, "offset": "2"}), b"abc");
        let entry = file_entry(&mut reader);
        let failure = reader
            .open(&entry, &Cancellation::default())
            .expect_err("member extends past captured payload");
        assert_eq!(failure.reason, "format");
    }

    #[test]
    fn cancellation_still_applies_after_the_listing_is_prepared() {
        let mut reader = archive_with_file(json!({"size": 3, "offset": "0"}), b"abc");
        let entry = file_entry(&mut reader);
        let cancellation = Cancellation::default();
        assert!(cancellation.cancel("caller cancelled after inventory"));

        let failure = reader
            .open(&entry, &cancellation)
            .expect_err("prepared bytes do not bypass cancellation");
        assert_eq!(failure.reason, "cancelled");

        let failure = reader
            .entries(&cancellation, &mut Vec::new())
            .expect_err("prepared listing does not bypass cancellation");
        assert_eq!(failure.reason, "cancelled");
    }
}
