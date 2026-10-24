//! Bounded, read-only Apple property-list decoding.
//!
//! The decoder deliberately returns JSON-compatible values so the application
//! layer can retain the same contract as the TypeScript native provider.
use serde::Serialize;
use serde_json::{Map, Value};
use std::{borrow::Cow, fmt};

pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_DATA_BYTES: usize = MAX_INPUT_BYTES;
const MAX_DEPTH: usize = 128;
const MAX_NODES: usize = 1_000_000;
const MAX_KEYED_ARCHIVE_OBJECTS: usize = 200_000;
const KEYED_ARCHIVE_DECODE_BUDGET: usize = MAX_INPUT_BYTES * 8;
const PREFLIGHT_OBJECT_BYTES: usize = 144;
const PREFLIGHT_EXPANDED_NODE_BYTES: usize = 224;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Xml,
    Binary,
    OpenStep,
}

#[derive(Debug, Serialize)]
pub struct Bundle {
    pub identifier: Option<String>,
    pub executable: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub short_version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub format: Format,
    pub value: Value,
    pub bundle: Bundle,
    pub source_path: String,
    pub limitations: Vec<String>,
}

/// A path into a decoded plist value, retaining source type information that
/// a JSON-compatible projection alone cannot carry.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ValuePathSegment {
    Key(String),
    Index(usize),
}

/// Additional facts produced by the parser for consumers that interpret plist
/// scalar types. This metadata does not alter the serialized property-list
/// report.
#[derive(Debug)]
pub struct ReadWithProvenance {
    pub report: Report,
    /// Paths emitted as parser-owned typed scalar wrappers in `report.value`.
    /// Consumers can avoid treating those JSON objects as source dictionaries.
    pub typed_scalar_paths: Vec<Vec<ValuePathSegment>>,
    pub binary_uid_paths: Vec<Vec<ValuePathSegment>>,
}

#[derive(Debug)]
pub enum Error {
    InputTooLarge,
    Invalid(String),
    Depth,
    Capacity,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge => f.write_str("property list exceeds the 64 MiB read limit"),
            Self::Invalid(s) => f.write_str(s),
            Self::Depth => f.write_str("property list exceeds 128 nesting levels"),
            Self::Capacity => f.write_str("property list exceeds the supported object capacity"),
        }
    }
}
impl std::error::Error for Error {}

pub fn read(bytes: &[u8], source_path: String) -> Result<Report, Error> {
    read_with_provenance(bytes, source_path).map(|decoded| decoded.report)
}

/// Decode a plist while preserving the locations of binary UID scalars.
///
/// Binary UIDs are represented in `Report::value` by a tagged JSON object for
/// compatibility with the common plist projection. The sidecar paths let
/// consumers distinguish those parser-created scalar wrappers from ordinary
/// dictionaries that happen to contain the same keys.
pub fn read_with_provenance(
    bytes: &[u8],
    source_path: String,
) -> Result<ReadWithProvenance, Error> {
    read_with_provenance_inner(bytes, source_path, None)
}

/// Decode a keyed archive after reserving the same bounded expanded
/// representation budget used by the TypeScript Foundation archive reader.
pub fn read_keyed_archive_with_provenance(
    bytes: &[u8],
    source_path: String,
) -> Result<ReadWithProvenance, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputTooLarge);
    }

    if bytes.starts_with(b"bplist00") {
        preflight_binary_expansion(bytes)?;
        return read_with_provenance_inner(bytes, source_path, None);
    }

    if first_openstep_byte(bytes).is_some_and(|byte| byte == b'{' || byte == b'(') {
        return read_with_provenance_inner(bytes, source_path, None);
    }

    let xml = decode_xml_text(bytes)?;
    preflight_xml_expansion(&xml)?;
    read_with_provenance_inner(bytes, source_path, Some(xml))
}

fn read_with_provenance_inner<'a>(
    bytes: &'a [u8],
    source_path: String,
    decoded_xml: Option<Cow<'a, str>>,
) -> Result<ReadWithProvenance, Error> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputTooLarge);
    }
    let (format, decoded) = if bytes.starts_with(b"bplist00") {
        (Format::Binary, Binary::new(bytes).decode()?)
    } else if first_openstep_byte(bytes).is_some_and(|byte| byte == b'{' || byte == b'(') {
        (
            Format::OpenStep,
            DecodedValue::plain(OpenStep::new(bytes)?.decode()?),
        )
    } else {
        let xml = match decoded_xml {
            Some(text) => Xml::from_text(text),
            None => Xml::new(bytes)?,
        };
        (Format::Xml, xml.decode()?)
    };
    let (value, mut limitations) = normalize(decoded.value);
    let bundle = bundle(&value);
    limitations.push("Values are decoded read-only from the selected property-list bytes; signatures and code identity are not authenticated.".into());
    Ok(ReadWithProvenance {
        report: Report {
            format,
            value,
            bundle,
            source_path,
            limitations,
        },
        typed_scalar_paths: decoded.typed_scalar_paths,
        binary_uid_paths: decoded.typed_uid_paths,
    })
}

fn first_openstep_byte(bytes: &[u8]) -> Option<u8> {
    let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
}

fn preflight_binary_expansion(bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() < 40 {
        return Err(Error::Invalid(
            "binary property list trailer is truncated".into(),
        ));
    }

    let trailer = bytes.len() - 32;
    let offset_size = usize::from(bytes[trailer + 6]);
    let reference_size = usize::from(bytes[trailer + 7]);
    if !matches!(offset_size, 1 | 2 | 4 | 8) || !matches!(reference_size, 1 | 2 | 4 | 8) {
        return Err(Error::Invalid(
            "binary property list trailer integer sizes are invalid".into(),
        ));
    }

    let object_count = preflight_usize(bytes, trailer + 8, 8, bytes.len())?;
    let top_object = preflight_usize(bytes, trailer + 16, 8, bytes.len())?;
    let offset_table = preflight_usize(bytes, trailer + 24, 8, bytes.len())?;
    let table_bytes = object_count
        .checked_mul(offset_size)
        .ok_or(Error::Capacity)?;
    let table_end = offset_table
        .checked_add(table_bytes)
        .ok_or(Error::Capacity)?;

    if object_count == 0 || top_object >= object_count || offset_table < 8 || table_end > trailer {
        return Err(Error::Invalid(
            "binary property list trailer or object table is invalid".into(),
        ));
    }
    if object_count > MAX_KEYED_ARCHIVE_OBJECTS {
        return Err(Error::Capacity);
    }

    let mut estimate = 0;
    reserve_preflight(
        &mut estimate,
        bytes
            .len()
            .checked_mul(3)
            .and_then(|total| {
                object_count
                    .checked_mul(PREFLIGHT_OBJECT_BYTES)
                    .and_then(|objects| total.checked_add(objects))
            })
            .ok_or(Error::Capacity)?,
    )?;

    let mut active = vec![false; object_count];
    let mut pending = vec![BinaryVisit::Enter {
        object: top_object,
        depth: 0,
        dictionary_key: false,
    }];
    let mut pending_object_count = 1_usize;

    while let Some(visit) = pending.pop() {
        let BinaryVisit::Enter {
            object,
            depth,
            dictionary_key,
        } = visit
        else {
            let BinaryVisit::Exit { object } = visit else {
                unreachable!();
            };
            active[object] = false;
            continue;
        };

        pending_object_count -= 1;
        if depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        if active[object] {
            return Err(Error::Invalid(
                "binary property list object references form a cycle".into(),
            ));
        }

        reserve_preflight(&mut estimate, PREFLIGHT_EXPANDED_NODE_BYTES)?;

        let offset_entry = offset_table
            .checked_add(object.checked_mul(offset_size).ok_or(Error::Capacity)?)
            .ok_or(Error::Capacity)?;
        let object_offset = preflight_usize(bytes, offset_entry, offset_size, trailer)?;
        if !(8..offset_table).contains(&object_offset) {
            return Err(Error::Invalid(
                "binary property list object offset is invalid".into(),
            ));
        }

        let marker = bytes[object_offset];
        let object_type = marker >> 4;
        if dictionary_key && !matches!(object_type, 5 | 6) {
            return Err(Error::Invalid(
                "binary property list dictionary key is not a string".into(),
            ));
        }

        let (size, cursor) = preflight_object_size(bytes, object_offset, marker, offset_table)?;
        if matches!(object_type, 4 | 5 | 6 | 7) {
            let byte_length = if object_type == 6 {
                size.checked_mul(2).ok_or(Error::Capacity)?
            } else {
                size
            };
            let scalar_end = cursor.checked_add(byte_length).ok_or(Error::Capacity)?;
            if scalar_end > offset_table {
                return Err(Error::Invalid(
                    "binary property list scalar object is truncated".into(),
                ));
            }

            let scalar_expansion = if object_type == 4 {
                size.checked_add(3)
                    .and_then(|rounded| rounded.checked_div(3))
                    .and_then(|groups| groups.checked_mul(4))
                    .and_then(|encoded| size.checked_add(encoded))
                    .ok_or(Error::Capacity)?
            } else {
                byte_length.checked_mul(2).ok_or(Error::Capacity)?
            };
            reserve_preflight(&mut estimate, scalar_expansion)?;
            continue;
        }

        let child_count = match object_type {
            0xA | 0xB | 0xC | 0xE => size,
            0xD => size.checked_mul(2).ok_or(Error::Capacity)?,
            _ => continue,
        };
        let refs_bytes = child_count
            .checked_mul(reference_size)
            .ok_or(Error::Capacity)?;
        let refs_end = cursor.checked_add(refs_bytes).ok_or(Error::Capacity)?;
        if refs_end > offset_table {
            return Err(Error::Invalid(
                "binary property list reference table is truncated".into(),
            ));
        }

        let remaining_nodes =
            KEYED_ARCHIVE_DECODE_BUDGET.saturating_sub(estimate) / PREFLIGHT_EXPANDED_NODE_BYTES;
        if child_count > remaining_nodes.saturating_sub(pending_object_count) {
            return Err(Error::Capacity);
        }

        active[object] = true;
        pending.push(BinaryVisit::Exit { object });
        pending_object_count = pending_object_count
            .checked_add(child_count)
            .ok_or(Error::Capacity)?;

        for child_index in (0..child_count).rev() {
            let child_offset = cursor
                .checked_add(
                    child_index
                        .checked_mul(reference_size)
                        .ok_or(Error::Capacity)?,
                )
                .ok_or(Error::Capacity)?;
            let child = preflight_usize(bytes, child_offset, reference_size, offset_table)?;
            if child >= object_count {
                return Err(Error::Invalid(
                    "binary property list object reference is invalid".into(),
                ));
            }
            pending.push(BinaryVisit::Enter {
                object: child,
                depth: depth + 1,
                dictionary_key: object_type == 0xD && child_index < size,
            });
        }
    }

    Ok(())
}

enum BinaryVisit {
    Enter {
        object: usize,
        depth: usize,
        dictionary_key: bool,
    },
    Exit {
        object: usize,
    },
}

fn preflight_xml_expansion(xml: &str) -> Result<(), Error> {
    let source_bytes = xml
        .encode_utf16()
        .count()
        .checked_mul(2)
        .ok_or(Error::Capacity)?;
    let mut estimate = source_bytes.checked_mul(2).ok_or(Error::Capacity)?;
    if estimate > KEYED_ARCHIVE_DECODE_BUDGET {
        return Err(Error::Capacity);
    }

    let bytes = xml.as_bytes();
    let mut cursor = 0;
    while let Some(relative_start) = memchr::memchr(b'<', &bytes[cursor..]) {
        let start = cursor + relative_start;
        if let Some((terminator, prefix_length)) = xml_opaque_terminator(bytes, start) {
            let content_start = start + prefix_length;
            let Some(relative_end) = find_bytes(&bytes[content_start..], terminator) else {
                break;
            };
            cursor = content_start + relative_end + terminator.len();
            continue;
        }

        let is_doctype = bytes[start..].starts_with(b"<!DOCTYPE");
        let is_element = bytes
            .get(start + 1)
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'/');
        let Some(end) = xml_markup_end(bytes, start) else {
            break;
        };

        if is_doctype {
            if xml_doctype_has_internal_subset(&bytes[start..=end]) {
                return Err(Error::Capacity);
            }
        } else if is_element {
            reserve_preflight(&mut estimate, 256)?;
        }
        cursor = end + 1;
    }

    Ok(())
}

fn xml_opaque_terminator(bytes: &[u8], start: usize) -> Option<(&'static [u8], usize)> {
    let remaining = &bytes[start..];
    if remaining.starts_with(b"<!--") {
        Some((b"-->", 4))
    } else if remaining.starts_with(b"<![CDATA[") {
        Some((b"]]>", 9))
    } else if remaining.starts_with(b"<?") {
        Some((b"?>", 2))
    } else {
        None
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    memchr::memmem::find(haystack, needle)
}

fn xml_markup_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        match (quote, byte) {
            (Some(active), value) if active == value => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'>') => return Some(start + offset),
            _ => {}
        }
    }
    None
}

fn xml_doctype_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut quote = None;
    let mut subset_depth = 0_usize;

    for (offset, byte) in bytes[start..].iter().copied().enumerate() {
        match (quote, byte) {
            (Some(active), value) if active == value => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'[') => subset_depth = subset_depth.saturating_add(1),
            (None, b']') => subset_depth = subset_depth.saturating_sub(1),
            (None, b'>') if subset_depth == 0 => return Some(start + offset + 1),
            _ => {}
        }
    }

    None
}

fn xml_doctype_has_internal_subset(doctype: &[u8]) -> bool {
    let mut quote = None;
    for byte in doctype.iter().copied() {
        match (quote, byte) {
            (Some(active), value) if active == value => quote = None,
            (Some(_), _) => {}
            (None, b'\'' | b'"') => quote = Some(byte),
            (None, b'[') => return true,
            _ => {}
        }
    }
    false
}

fn preflight_object_size(
    bytes: &[u8],
    object_offset: usize,
    marker: u8,
    object_end: usize,
) -> Result<(usize, usize), Error> {
    let size = usize::from(marker & 0x0f);
    let cursor = object_offset.checked_add(1).ok_or(Error::Capacity)?;
    let object_type = marker >> 4;
    if size != 0x0f || matches!(object_type, 0 | 8) {
        return Ok((size, cursor));
    }

    let extended_marker = *bytes.get(cursor).ok_or_else(|| {
        Error::Invalid("binary property list extended object size is truncated".into())
    })?;
    if extended_marker >> 4 != 1 || extended_marker & 0x0f > 3 {
        return Err(Error::Invalid(
            "binary property list extended object size is invalid".into(),
        ));
    }
    let integer_width = 1_usize << (extended_marker & 0x0f);
    let length_offset = cursor.checked_add(1).ok_or(Error::Capacity)?;
    let length = preflight_usize(bytes, length_offset, integer_width, object_end)?;
    let payload_offset = length_offset
        .checked_add(integer_width)
        .ok_or(Error::Capacity)?;
    Ok((length, payload_offset))
}

fn preflight_usize(
    bytes: &[u8],
    offset: usize,
    width: usize,
    boundary: usize,
) -> Result<usize, Error> {
    let end = offset.checked_add(width).ok_or(Error::Capacity)?;
    if width == 0 || width > 8 || end > boundary {
        return Err(Error::Invalid(
            "binary property list integer is out of bounds".into(),
        ));
    }

    let mut value = 0_u64;
    for byte in bytes
        .get(offset..end)
        .ok_or_else(|| Error::Invalid("binary property list integer is out of bounds".into()))?
    {
        value = (value << 8) | u64::from(*byte);
    }
    usize::try_from(value).map_err(|_| Error::Capacity)
}

fn reserve_preflight(estimate: &mut usize, bytes: usize) -> Result<(), Error> {
    *estimate = estimate.checked_add(bytes).ok_or(Error::Capacity)?;
    if *estimate > KEYED_ARCHIVE_DECODE_BUDGET {
        return Err(Error::Capacity);
    }
    Ok(())
}

fn normalize(value: Value) -> (Value, Vec<String>) {
    fn walk(
        value: Value,
        omitted: &mut usize,
        unknown_dates: &mut usize,
        signed_zero: &mut usize,
    ) -> Value {
        if let Value::Number(number) = &value {
            if number.to_string() == "-0" {
                *signed_zero += 1;
                return typed_real("-0");
            }
        }
        match value {
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|v| walk(v, omitted, unknown_dates, signed_zero))
                    .collect(),
            ),
            Value::Object(mut object) => {
                if object.get("$plist_type").and_then(Value::as_str) == Some("date")
                    && object
                        .get("iso8601")
                        .and_then(Value::as_str)
                        .is_some_and(str::is_empty)
                {
                    object.insert("iso8601".into(), Value::Null);
                    *unknown_dates += 1;
                }
                let keys = object.keys().cloned().collect::<Vec<_>>();
                for key in keys {
                    if key == "__proto__" {
                        object.remove(&key);
                        *omitted += 1;
                        continue;
                    }
                    if let Some(child) = object.remove(&key) {
                        object.insert(key, walk(child, omitted, unknown_dates, signed_zero));
                    }
                }
                Value::Object(object)
            }
            other => other,
        }
    }
    let mut omitted = 0;
    let mut unknown_dates = 0;
    let mut signed_zero = 0;
    let result = walk(value, &mut omitted, &mut unknown_dates, &mut signed_zero);
    let mut limitations = Vec::new();
    if omitted > 0 {
        limitations.push(format!("{omitted} dictionary {} keyed __proto__ {} omitted because REA results cannot represent that key.", if omitted == 1 { "entry" } else { "entries" }, if omitted == 1 { "was" } else { "were" }));
    }
    if unknown_dates > 0 {
        limitations.push(format!("{unknown_dates} date value(s) are reported as {{ \"$plist_type\": \"date\", \"iso8601\": null }} because the decoder could not represent their timestamps."));
    }
    if signed_zero > 0 {
        limitations.push(format!("{signed_zero} negative-zero real value(s) are reported as {{ \"$plist_type\": \"real\", \"value\": \"-0\" }} because a JSON number cannot carry the sign of zero."));
    }
    (result, limitations)
}

fn bundle(value: &Value) -> Bundle {
    let get = |names: &[&str]| {
        names
            .iter()
            .find_map(|name| value.get(*name).and_then(Value::as_str).map(str::to_owned))
    };
    Bundle {
        identifier: get(&["CFBundleIdentifier"]),
        executable: get(&["CFBundleExecutable"]),
        name: get(&["CFBundleName"]),
        version: get(&["CFBundleVersion"]),
        short_version: get(&["CFBundleShortVersionString"]),
    }
}

fn decode_xml_text(bytes: &[u8]) -> Result<Cow<'_, str>, Error> {
    let (encoding, payload) = if bytes.starts_with(&[0xff, 0xfe]) {
        ("utf-16le", &bytes[2..])
    } else if bytes.starts_with(&[0xfe, 0xff]) {
        ("utf-16be", &bytes[2..])
    } else {
        ("utf-8", bytes)
    };

    let text = if encoding == "utf-8" {
        let text = std::str::from_utf8(payload)
            .map_err(|_| Error::Invalid("XML text bytes are invalid for UTF-8".into()))?;
        Cow::Borrowed(text.strip_prefix('\u{feff}').unwrap_or(text))
    } else {
        if payload.len() % 2 != 0 {
            return Err(Error::Invalid(
                "XML text bytes are invalid for BOM-marked UTF-16".into(),
            ));
        }
        let words = payload
            .chunks_exact(2)
            .map(|chunk| {
                if encoding == "utf-16le" {
                    u16::from_le_bytes([chunk[0], chunk[1]])
                } else {
                    u16::from_be_bytes([chunk[0], chunk[1]])
                }
            })
            .collect::<Vec<_>>();
        Cow::Owned(decode_utf16_text(&words))
    };

    if let Some(declared) = xml_declared_encoding(&text) {
        let supported = matches!(
            declared.as_str(),
            "utf-8" | "utf-16" | "utf-16le" | "utf-16be"
        );
        if !supported {
            return Err(Error::Invalid(format!(
                "unsupported XML encoding declaration: {declared}"
            )));
        }
        let matches_bytes = declared == encoding || (encoding != "utf-8" && declared == "utf-16");
        if !matches_bytes {
            return Err(Error::Invalid(
                "XML encoding declaration disagrees with its BOM bytes".into(),
            ));
        }
    }

    Ok(text)
}

fn decode_utf16_text(units: &[u16]) -> String {
    let mut text = String::new();
    let mut index = 0;

    while index < units.len() {
        let unit = units[index];
        if (0xD800..=0xDBFF).contains(&unit) {
            if let Some(&low) = units.get(index + 1) {
                if (0xDC00..=0xDFFF).contains(&low) {
                    let high = (unit as u32) - 0xD800;
                    let low = (low as u32) - 0xDC00;
                    let scalar = 0x10000 + (high << 10) + low;
                    if let Some(character) = char::from_u32(scalar) {
                        text.push(character);
                        index += 2;
                        continue;
                    }
                }
            }
            text.push_str(&format!("\\u{unit:04X}"));
        } else if (0xDC00..=0xDFFF).contains(&unit) {
            text.push_str(&format!("\\u{unit:04X}"));
        } else if let Some(character) = char::from_u32(unit as u32) {
            text.push(character);
        }
        index += 1;
    }

    text
}

fn xml_declared_encoding(text: &str) -> Option<String> {
    let declaration = text.strip_prefix("<?xml")?.split_once("?>")?.0;
    let lower = declaration.to_ascii_lowercase();
    let encoding_start = lower.find("encoding")? + "encoding".len();
    let remainder = &declaration[encoding_start..];
    let equals = remainder.find('=')?;
    let quoted = remainder[equals + 1..].trim_start();
    let quote = quoted.chars().next()?;
    if quote != '\'' && quote != '"' {
        return None;
    }
    let value = quoted[quote.len_utf8()..].split(quote).next()?;
    Some(value.to_ascii_lowercase())
}

struct OpenStep {
    text: String,
    pos: usize,
    depth: usize,
    nodes: usize,
}

impl OpenStep {
    fn new(bytes: &[u8]) -> Result<Self, Error> {
        let decoded = std::str::from_utf8(bytes)
            .map_err(|_| Error::Invalid("OpenStep plist text is not valid UTF-8".into()))?;
        let text = decoded
            .strip_prefix('\u{feff}')
            .unwrap_or(decoded)
            .to_owned();
        Ok(Self {
            text,
            pos: 0,
            depth: 0,
            nodes: 0,
        })
    }

    fn decode(mut self) -> Result<Value, Error> {
        self.skip_trivia();
        let value = self.parse_value()?;
        self.skip_trivia();
        if self.pos != self.text.len() {
            return Err(Error::Invalid(format!(
                "OpenStep plist has trailing content at source offset {}",
                self.pos
            )));
        }
        Ok(value)
    }

    fn parse_value(&mut self) -> Result<Value, Error> {
        self.skip_trivia();
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error::Capacity);
        }

        let Some(character) = self.text[self.pos..].chars().next() else {
            return Err(Error::Invalid("OpenStep plist has no value".into()));
        };
        match character {
            '{' => self.parse_dictionary(),
            '(' => self.parse_array(),
            '"' => self.parse_quoted_string(),
            '<' => self.parse_data(),
            _ => self.parse_bare_value(),
        }
    }

    fn parse_dictionary(&mut self) -> Result<Value, Error> {
        self.enter_container()?;
        self.pos += 1;
        let mut output = Map::new();
        loop {
            self.skip_trivia();
            if self.take('}') {
                self.leave_container();
                return Ok(Value::Object(output));
            }
            let key_value = self.parse_value()?;
            let key = openstep_key_string(&key_value);
            self.skip_trivia();
            if !self.take('=') {
                return Err(Error::Invalid(
                    "OpenStep dictionary key has no value".into(),
                ));
            }
            let value = self.parse_value()?;
            output.insert(key, value);
            self.skip_trivia();
            // The pinned TypeScript decoder accepts adjacent dictionary
            // assignments, even when the optional semicolon is omitted.
            self.take(';');
        }
    }

    fn parse_array(&mut self) -> Result<Value, Error> {
        self.enter_container()?;
        self.pos += 1;
        let mut output = Vec::new();
        loop {
            self.skip_trivia();
            if self.take(')') {
                self.leave_container();
                return Ok(Value::Array(output));
            }
            output.push(self.parse_value()?);
            self.skip_trivia();
            if self.take(',') || self.text[self.pos..].starts_with(')') {
                continue;
            }
            return Err(Error::Invalid(
                "OpenStep array item is not terminated".into(),
            ));
        }
    }

    fn parse_quoted_string(&mut self) -> Result<Value, Error> {
        self.pos += 1;
        let mut value = String::new();
        while self.pos < self.text.len() {
            let character = self.text[self.pos..]
                .chars()
                .next()
                .ok_or_else(|| Error::Invalid("OpenStep string is unterminated".into()))?;
            self.pos += character.len_utf8();
            match character {
                '"' => return Ok(Value::String(value)),
                '\\' => {
                    let escaped = self.text[self.pos..].chars().next().ok_or_else(|| {
                        Error::Invalid("OpenStep string escape is unterminated".into())
                    })?;
                    self.pos += escaped.len_utf8();
                    value.push(match escaped {
                        'n' => '\n',
                        'r' => '\r',
                        't' => '\t',
                        'b' => '\u{0008}',
                        'f' => '\u{000c}',
                        other => other,
                    });
                }
                other => value.push(other),
            }
        }
        Err(Error::Invalid("OpenStep string is unterminated".into()))
    }

    fn parse_data(&mut self) -> Result<Value, Error> {
        self.pos += 1;
        let start = self.pos;
        let end = self.text[self.pos..]
            .find('>')
            .map(|offset| self.pos + offset)
            .ok_or_else(|| Error::Invalid("OpenStep data is unterminated".into()))?;
        let hex = self.text[start..end]
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        if hex.len() % 2 != 0 || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
            return Err(Error::Invalid(
                "OpenStep data contains invalid hexadecimal".into(),
            ));
        }
        let mut bytes = Vec::with_capacity(hex.len() / 2);
        for pair in hex.as_bytes().chunks_exact(2) {
            let text = std::str::from_utf8(pair).expect("hex pairs are ASCII");
            bytes.push(u8::from_str_radix(text, 16).expect("validated hexadecimal"));
        }
        self.pos = end + 1;
        Ok(typed_data(&base64_encode(&bytes)))
    }

    fn parse_bare_value(&mut self) -> Result<Value, Error> {
        let start = self.pos;
        while let Some(character) = self.text[self.pos..].chars().next() {
            if character.is_ascii_whitespace() || matches!(character, ';' | '=' | ',' | ')' | '}') {
                break;
            }
            self.pos += character.len_utf8();
        }
        if self.pos == start {
            return Err(Error::Invalid(
                "OpenStep plist has an unexpected delimiter".into(),
            ));
        }
        let literal = &self.text[start..self.pos];
        match literal {
            "YES" => Ok(Value::Bool(true)),
            "NO" => Ok(Value::Bool(false)),
            _ => Ok(Value::String(literal.to_owned())),
        }
    }

    fn enter_container(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        Ok(())
    }

    fn leave_container(&mut self) {
        self.depth -= 1;
    }

    fn take(&mut self, expected: char) -> bool {
        if self.text[self.pos..].starts_with(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn skip_trivia(&mut self) {
        loop {
            let start = self.pos;
            while let Some(character) = self.text[self.pos..].chars().next() {
                if !character.is_ascii_whitespace() {
                    break;
                }
                self.pos += character.len_utf8();
            }
            if self.text[self.pos..].starts_with("//") {
                self.pos += 2;
                while let Some(character) = self.text[self.pos..].chars().next() {
                    self.pos += character.len_utf8();
                    if character == '\n' {
                        break;
                    }
                }
            } else if self.text[self.pos..].starts_with("/*") {
                self.pos += 2;
                if let Some(end) = self.text[self.pos..].find("*/") {
                    self.pos += end + 2;
                } else {
                    self.pos = self.text.len();
                }
            }
            if self.pos == start {
                break;
            }
        }
    }
}

fn openstep_key_string(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values
            .iter()
            .map(openstep_key_string)
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

struct Xml<'a> {
    text: Cow<'a, str>,
    pos: usize,
    depth: usize,
    nodes: usize,
    path: Vec<ValuePathSegment>,
    typed_scalar_paths: Vec<Vec<ValuePathSegment>>,
}
impl<'a> Xml<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, Error> {
        Ok(Self::from_text(decode_xml_text(bytes)?))
    }

    fn from_text(text: Cow<'a, str>) -> Self {
        Self {
            text,
            pos: 0,
            depth: 0,
            nodes: 0,
            path: Vec::new(),
            typed_scalar_paths: Vec::new(),
        }
    }
    fn decode(mut self) -> Result<DecodedValue, Error> {
        if self.text.is_empty() {
            return Err(Error::Invalid(
                "property list is not valid UTF-8 XML".into(),
            ));
        }
        self.skip();
        let remaining = &self.text[self.pos..];
        let root = remaining.strip_prefix("<plist").ok_or_else(|| {
            Error::Invalid("malformed document. First element should be <plist>".into())
        })?;
        if !root.starts_with('>')
            && !root.starts_with('/')
            && !root.chars().next().is_some_and(char::is_whitespace)
        {
            return Err(Error::Invalid(
                "malformed document. First element should be <plist>".into(),
            ));
        }
        let end = remaining
            .find('>')
            .ok_or_else(|| Error::Invalid("property list XML root is truncated".into()))?;
        if remaining[..=end].ends_with("/>") {
            self.pos += end + 1;
            self.skip();
            if self.pos != self.text.len() {
                return Err(Error::Invalid(
                    "property list XML has content after the root plist element".into(),
                ));
            }
            return Ok(DecodedValue::plain(Value::Array(Vec::new())));
        }
        self.pos += end + 1;
        let mut decoded = self.plist_value()?;
        self.skip();
        if self.pos != self.text.len() {
            return Err(Error::Invalid(
                "property list XML has content after the root plist element".into(),
            ));
        }
        if let Value::Array(mut values) = decoded.value {
            if values.len() == 1 {
                for path in &mut decoded.typed_scalar_paths {
                    if path.first() == Some(&ValuePathSegment::Index(0)) {
                        path.remove(0);
                    }
                }
                return Ok(DecodedValue {
                    value: values.remove(0),
                    typed_scalar_paths: decoded.typed_scalar_paths,
                    typed_uid_paths: decoded.typed_uid_paths,
                });
            }
            decoded.value = Value::Array(values);
            return Ok(decoded);
        }
        Ok(decoded)
    }
    fn skip(&mut self) {
        while self.pos < self.text.len() {
            if self.text.as_bytes()[self.pos].is_ascii_whitespace() {
                self.pos += 1;
                continue;
            }
            if self.text[self.pos..].starts_with("<!--") {
                if let Some(end) = self.text[self.pos + 4..].find("-->") {
                    self.pos += end + 7;
                    continue;
                }
            }
            if self.text[self.pos..].starts_with("<?") {
                if let Some(end) = self.text[self.pos..].find("?>") {
                    self.pos += end + 2;
                    continue;
                }
            }
            if self.text[self.pos..].starts_with("<!DOCTYPE") {
                if let Some(end) = xml_doctype_end(self.text.as_bytes(), self.pos) {
                    self.pos = end;
                    continue;
                }
            }
            break;
        }
    }
    fn parse_value(&mut self) -> Result<Value, Error> {
        self.skip();
        let tag_start = self.pos;
        let rest = &self.text[self.pos..];
        let tag = rest
            .strip_prefix('<')
            .and_then(|s| s.split_once('>').map(|x| x.0))
            .ok_or_else(|| Error::Invalid("property list XML has no value".into()))?
            .to_owned();
        let tag = tag.trim().to_owned();
        if tag.starts_with('/') {
            return Err(Error::Invalid("unexpected closing XML tag".into()));
        }
        let self_closing = tag.ends_with('/');
        let name = tag
            .split_whitespace()
            .next()
            .unwrap_or(tag.as_str())
            .trim_end_matches('/')
            .to_owned();
        self.pos += tag.len() + 2;
        let scalar_requires_closing =
            !self_closing && !matches!(name.as_str(), "plist" | "dict" | "array");
        if scalar_requires_closing {
            let end = find_scalar_closing_tag(&self.text, self.pos, &name).ok_or_else(|| {
                Error::Invalid(format!("property list XML element {name} is unterminated"))
            })?;
            validate_xml_entities(&self.text[self.pos..end], self.pos)?;
        }
        self.depth += 1;
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error::Capacity);
        }
        if self.depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let result = match name.as_str() {
            "plist" => {
                let decoded = self.plist_value()?;
                self.typed_scalar_paths.extend(decoded.typed_scalar_paths);
                Ok(decoded.value)
            }
            // Self-closing containers are complete empty values; they own no
            // closing tag, so the enclosing container keeps its own `</dict>`.
            "dict" if self_closing => Ok(Value::Object(serde_json::Map::new())),
            "array" if self_closing => Ok(Value::Array(Vec::new())),
            "dict" => self.dict(),
            "array" => self.array(),
            "string" | "key" => Ok(Value::String(self.text_until(&name))),
            "integer" => {
                let raw = self.raw_text_until(&name);
                let literal = decode_entities(&strip_cdata(&raw));
                if raw.contains('<') || raw.contains('>') {
                    Ok(unknown("integer", raw, "unsupported-markup"))
                } else {
                    match parse_integer_literal(&literal) {
                        Ok(canonical) => match canonical.parse::<i128>() {
                            Ok(number) if number.unsigned_abs() <= 9_007_199_254_740_991 => Ok(
                                Value::Number(serde_json::Number::from_i128(number).ok_or_else(
                                    || Error::Invalid("plist integer is out of range".into()),
                                )?),
                            ),
                            _ => Ok(json_integer_text(&canonical)),
                        },
                        Err(reason) => Ok(unknown("integer", literal, reason)),
                    }
                }
            }
            "real" => self.real_value(&name),
            "true" if self_closing => Ok(Value::Bool(true)),
            "true" => self.boolean_value(&name, true),
            "false" if self_closing => Ok(Value::Bool(false)),
            "false" => self.boolean_value(&name, false),
            "data" => self.data_value(&name),
            "date" => self.date_value(&name),
            "null" => Ok(Value::Null),
            _ => {
                self.text_until(&name);
                Err(Error::Invalid(format!(
                    "Invalid PLIST tag {name} at source offset {tag_start}"
                )))
            }
        };
        self.depth -= 1;
        let value = result?;
        if xml_value_is_generated_scalar_wrapper(name.as_str(), &value) {
            self.typed_scalar_paths.push(self.path.clone());
        }
        Ok(value)
    }

    fn plist_value(&mut self) -> Result<DecodedValue, Error> {
        let mut values = Vec::new();
        loop {
            self.skip();
            if self.text[self.pos..].starts_with("</plist>") {
                self.pos += 8;
                return Ok(DecodedValue {
                    value: Value::Array(values),
                    typed_scalar_paths: std::mem::take(&mut self.typed_scalar_paths),
                    typed_uid_paths: Vec::new(),
                });
            }
            let index = values.len();
            self.path.push(ValuePathSegment::Index(index));
            let result = self.parse_value();
            self.path.pop();
            values.push(result?);
        }
    }
    fn text_until(&mut self, name: &str) -> String {
        let start = self.pos;
        let endpos = find_scalar_closing_tag(&self.text, self.pos, name).unwrap_or(self.text.len());
        let end = format!("</{name}>");
        self.pos = endpos.saturating_add(end.len()).min(self.text.len());
        let raw = &self.text[start..endpos];
        decode_entities(&strip_nested_markup(&strip_cdata(raw)))
    }
    fn raw_text_until(&mut self, name: &str) -> String {
        let start = self.pos;
        let end = format!("</{name}>");
        let endpos = find_scalar_closing_tag(&self.text, self.pos, name).unwrap_or(self.text.len());
        self.pos = endpos.saturating_add(end.len()).min(self.text.len());
        self.text[start..endpos].to_owned()
    }
    fn data_value(&mut self, name: &str) -> Result<Value, Error> {
        let end = format!("</{name}>");
        let start = self.pos;
        let endpos = self.text[self.pos..]
            .find(&end)
            .unwrap_or(self.text.len() - self.pos);
        let raw = &self.text[start..start + endpos];
        self.pos += endpos + end.len();
        if raw.contains('<') || raw.contains('>') {
            let offset = raw
                .char_indices()
                .find(|(_, character)| *character == '<' || *character == '>')
                .map_or(0, |(offset, _)| offset);
            return Err(Error::Invalid(format!(
                "property list data contains markup at source offset {offset}"
            )));
        }
        // CFPropertyList scans the raw XML data spelling: entity names,
        // punctuation, and other nonalphabet bytes are simply skipped.
        decode_data(raw)
    }
    fn date_value(&mut self, name: &str) -> Result<Value, Error> {
        let end = format!("</{name}>");
        let start = self.pos;
        let endpos = self.text[self.pos..]
            .find(&end)
            .unwrap_or(self.text.len() - self.pos);
        let raw = &self.text[start..start + endpos];
        self.pos += endpos + end.len();

        if raw.contains('<') || raw.contains('>') {
            return Ok(unknown("date", raw.to_owned(), "unsupported-markup"));
        }

        let literal = decode_entities(&strip_cdata(raw));
        match parse_date_literal(&literal) {
            Ok(iso8601) => Ok(typed_date(&iso8601)),
            Err("unrepresentable") => Ok(typed_unrepresentable_date()),
            Err(reason) => Ok(unknown("date", literal, reason)),
        }
    }
    fn real_value(&mut self, name: &str) -> Result<Value, Error> {
        let raw = self.raw_text_until(name);
        let literal = decode_entities(&strip_cdata(&raw));
        if literal.contains('<') || literal.contains('>') {
            return Ok(unknown("real", raw, "unsupported-markup"));
        }
        match parse_real_literal(&literal) {
            Ok(RealValue::Finite(number)) if number == 0.0 && number.is_sign_negative() => {
                Ok(typed_real("-0"))
            }
            Ok(RealValue::Finite(number)) => Ok(Value::Number(
                serde_json::Number::from_f64(number)
                    .ok_or_else(|| Error::Invalid("real value is not JSON-representable".into()))?,
            )),
            Ok(RealValue::NonFinite(label)) => Ok(typed_real(label)),
            Err(reason) => Ok(unknown("real", raw, reason)),
        }
    }
    fn boolean_value(&mut self, name: &str, value: bool) -> Result<Value, Error> {
        let raw = self.raw_text_until(name);
        if raw.is_empty() {
            return Ok(Value::Bool(value));
        }
        let literal = decode_entities(&strip_cdata(&raw));
        let reason = if literal.contains('<') || literal.contains('>') {
            "unsupported-markup"
        } else {
            "invalid-literal"
        };
        Ok(unknown(name, literal, reason))
    }
    fn dict(&mut self) -> Result<Value, Error> {
        let mut out = Map::new();
        loop {
            self.skip();
            if self.text[self.pos..].starts_with("</dict>") {
                self.pos += 7;
                break;
            }
            let key = self.dictionary_key()?;
            self.skip();
            if self.text[self.pos..].starts_with("</dict>") {
                self.pos += 7;
                out.insert(key, Value::String(String::new()));
                break;
            }
            let mut child_path = self.path.clone();
            child_path.push(ValuePathSegment::Key(key.clone()));
            self.typed_scalar_paths
                .retain(|path| !path.starts_with(&child_path));
            self.path.push(ValuePathSegment::Key(key.clone()));
            let result = self.parse_value();
            self.path.pop();
            let val = result?;
            // XML decoding follows Object.fromEntries semantics: repeated
            // keys remain valid and the last value replaces the earlier one.
            out.insert(key, val);
        }
        Ok(Value::Object(out))
    }

    fn dictionary_key(&mut self) -> Result<String, Error> {
        self.skip();
        let remaining = &self.text[self.pos..];
        if !remaining.starts_with("<key") {
            return Err(Error::Invalid(
                "plist dictionary key is not a string".into(),
            ));
        }
        let opening_end = remaining
            .find('>')
            .ok_or_else(|| Error::Invalid("property list XML key is truncated".into()))?;
        if remaining[..=opening_end].ends_with("/>") {
            self.pos += opening_end + 1;
            return Ok(String::new());
        }
        let content_start = self.pos + opening_end + 1;
        let closing = self.text[content_start..]
            .find("</key>")
            .ok_or_else(|| Error::Invalid("property list XML key is unterminated".into()))?;
        let content_end = content_start + closing;
        if contains_element_markup(&self.text[content_start..content_end]) {
            self.pos = content_end + 6;
            return Ok("null".into());
        }
        let key = self
            .parse_value()?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| Error::Invalid("plist dictionary key is not a string".into()))?;
        Ok(key)
    }
    fn array(&mut self) -> Result<Value, Error> {
        let mut out = Vec::new();
        loop {
            self.skip();
            if self.text[self.pos..].starts_with("</array>") {
                self.pos += 8;
                break;
            }
            let index = out.len();
            self.path.push(ValuePathSegment::Index(index));
            let result = self.parse_value();
            self.path.pop();
            let value = result?;
            if !value.is_null() {
                out.push(value);
            }
            if out.len() > 1_000_000 {
                return Err(Error::Capacity);
            }
        }
        Ok(Value::Array(out))
    }
}
fn validate_xml_entities(input: &str, source_base: usize) -> Result<(), Error> {
    let mut cursor = 0;
    while cursor < input.len() {
        let remainder = &input[cursor..];
        let next_entity = remainder.find('&');
        let next_cdata = remainder.find("<![CDATA[");
        let next_comment = remainder.find("<!--");
        let next_instruction = remainder.find("<?");
        let next_markup = [next_cdata, next_comment, next_instruction]
            .into_iter()
            .flatten()
            .filter(|index| next_entity.is_none_or(|entity| *index < entity))
            .min();
        if let Some(markup) = next_markup {
            let marker = &remainder[markup..];
            let (content_offset, terminator) = if marker.starts_with("<![CDATA[") {
                (9, "]]>")
            } else if marker.starts_with("<!--") {
                (4, "-->")
            } else {
                (2, "?>")
            };
            let start = cursor + markup + content_offset;
            let Some(end) = input[start..].find(terminator) else {
                return Err(Error::Invalid(format!(
                    "XML markup section at source offset {} is unterminated",
                    source_base + start
                )));
            };
            cursor = start + end + terminator.len();
            continue;
        }
        let Some(relative) = next_entity else {
            break;
        };
        let start = cursor + relative;
        let Some(end_relative) = input[start..].find(';') else {
            return Err(Error::Invalid(format!(
                "XML entity reference at source offset {} is unterminated",
                source_base + start
            )));
        };
        let end = start + end_relative;
        let token = &input[start + 1..end];
        let valid = match token {
            "amp" | "lt" | "gt" | "apos" | "quot" => true,
            _ => parse_xml_character_reference(token),
        };
        if !valid {
            return Err(Error::Invalid(format!(
                "XML entity reference at source offset {} is invalid: &{token};",
                source_base + start
            )));
        }
        cursor = end + 1;
    }
    Ok(())
}

fn xml_value_is_generated_scalar_wrapper(element: &str, value: &Value) -> bool {
    if !matches!(
        element,
        "integer" | "real" | "true" | "false" | "data" | "date"
    ) {
        return false;
    }

    value
        .as_object()
        .and_then(|fields| fields.get("$plist_type"))
        .and_then(Value::as_str)
        .is_some()
}

fn parse_xml_character_reference(token: &str) -> bool {
    let number = token
        .strip_prefix("#x")
        .or_else(|| token.strip_prefix("#X"))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| {
            token
                .strip_prefix('#')
                .and_then(|decimal| decimal.parse().ok())
        });
    number.is_some_and(is_xml_character)
}

fn is_xml_character(value: u32) -> bool {
    matches!(value, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

fn decode_entities(input: &str) -> String {
    let mut output = input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    let mut cursor = 0;
    while let Some(start_rel) = output[cursor..].find("&#") {
        let start = cursor + start_rel;
        let Some(end_rel) = output[start..].find(';') else {
            break;
        };
        let end = start + end_rel;
        let token = &output[start + 2..end];
        let parsed = if let Some(hex) = token.strip_prefix('x').or_else(|| token.strip_prefix('X'))
        {
            u32::from_str_radix(hex, 16).ok()
        } else {
            token.parse::<u32>().ok()
        };
        let Some(codepoint) = parsed.and_then(char::from_u32) else {
            cursor = end + 1;
            continue;
        };
        output.replace_range(start..=end, &codepoint.to_string());
        cursor = start + codepoint.len_utf8();
    }
    output
}
fn strip_cdata(input: &str) -> String {
    let mut value = input.to_owned();
    while let Some(start) = value.find("<![CDATA[") {
        let Some(end_rel) = value[start + 9..].find("]]>") else {
            break;
        };
        let end = start + 9 + end_rel;
        let content = value[start + 9..end].to_owned();
        value.replace_range(start..end + 3, &content);
    }
    value
}

fn strip_nested_markup(input: &str) -> String {
    let mut output = String::new();
    let mut cursor = 0;
    while let Some(relative_start) = input[cursor..].find('<') {
        let start = cursor + relative_start;
        output.push_str(&input[cursor..start]);
        if input[start..].starts_with("<!--") {
            cursor = input[start + 4..]
                .find("-->")
                .map_or(input.len(), |end| start + end + 7);
            continue;
        }
        if input[start..].starts_with("<?") {
            cursor = input[start + 2..]
                .find("?>")
                .map_or(input.len(), |end| start + end + 4);
            continue;
        }
        if input[start..].starts_with("<![CDATA[") {
            let content_start = start + 9;
            if let Some(end) = input[content_start..].find("]]>") {
                output.push_str(&input[content_start..content_start + end]);
                cursor = content_start + end + 3;
                continue;
            }
            output.push_str(&input[content_start..]);
            cursor = input.len();
            continue;
        }
        let Some(tag_end_relative) = input[start..].find('>') else {
            break;
        };
        let tag_end = start + tag_end_relative;
        let tag = input[start + 1..tag_end].trim();
        if tag.starts_with('/') || tag.ends_with('/') {
            cursor = tag_end + 1;
            continue;
        }
        let name = tag.split_whitespace().next().unwrap_or(tag);
        let closing = format!("</{name}>");
        cursor = input[tag_end + 1..]
            .find(&closing)
            .map_or(input.len(), |end| tag_end + 1 + end + closing.len());
    }
    output.push_str(&input[cursor..]);
    output
}

fn find_scalar_closing_tag(text: &str, start: usize, name: &str) -> Option<usize> {
    let closing = format!("</{name}>");
    let mut cursor = start;
    while let Some(relative) = text[cursor..].find('<') {
        let position = cursor + relative;
        if text[position..].starts_with("<!--") {
            cursor = text[position + 4..]
                .find("-->")
                .map_or(text.len(), |end| position + end + 7);
            continue;
        }
        if text[position..].starts_with("<![CDATA[") {
            cursor = text[position + 9..]
                .find("]]>")
                .map_or(text.len(), |end| position + end + 12);
            continue;
        }
        if text[position..].starts_with("<?") {
            cursor = text[position + 2..]
                .find("?>")
                .map_or(text.len(), |end| position + end + 4);
            continue;
        }
        if text[position..].starts_with(&closing) {
            return Some(position);
        }
        cursor = position + 1;
    }
    None
}

fn contains_element_markup(input: &str) -> bool {
    let mut cursor = 0;
    while let Some(relative) = input[cursor..].find('<') {
        let position = cursor + relative;
        if input[position..].starts_with("<!--") {
            cursor = input[position + 4..]
                .find("-->")
                .map_or(input.len(), |end| position + end + 7);
            continue;
        }
        if input[position..].starts_with("<?") {
            cursor = input[position + 2..]
                .find("?>")
                .map_or(input.len(), |end| position + end + 4);
            continue;
        }
        if input[position..].starts_with("<![CDATA[") {
            cursor = input[position + 9..]
                .find("]]>")
                .map_or(input.len(), |end| position + end + 12);
            continue;
        }
        return true;
    }
    false
}
fn typed_data(value: &str) -> Value {
    let mut m = Map::new();
    m.insert("$plist_type".into(), Value::String("data".into()));
    m.insert(
        "base64".into(),
        Value::String(value.split_whitespace().collect()),
    );
    Value::Object(m)
}
fn decode_data(text: &str) -> Result<Value, Error> {
    decode_data_with_limit(text, MAX_DATA_BYTES)
}

fn decode_data_with_limit(text: &str, maximum: usize) -> Result<Value, Error> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut quartet = 0u32;
    let mut digits = 0usize;
    let mut padding = 0usize;
    let mut output = Vec::new();
    for (index, character) in text.char_indices() {
        if character as u32 >= 128 {
            return Err(Error::Invalid(format!(
                "property list data contains non-ASCII character at offset {index}"
            )));
        }
        if character == '=' {
            padding += 1;
        } else if !character.is_ascii_whitespace() {
            padding = 0;
        }
        let digit = if character == '=' {
            Some(0)
        } else {
            ALPHABET.iter().position(|item| *item as char == character)
        };
        let Some(digit) = digit else {
            continue;
        };
        quartet = ((quartet << 6) | digit as u32) & 0x00ff_ffff;
        digits += 1;
        if digits % 4 == 0 {
            let byte_count = if padding >= 2 {
                1
            } else if padding == 1 {
                2
            } else {
                3
            };
            if output
                .len()
                .checked_add(byte_count)
                .is_none_or(|size| size > maximum)
            {
                return Err(Error::Invalid(format!(
                    "property list data exceeds the decoded byte limit of {maximum} at source offset {index}"
                )));
            }
            output.push((quartet >> 16) as u8);
            if padding < 2 {
                output.push((quartet >> 8) as u8);
            }
            if padding == 0 {
                output.push(quartet as u8);
            }
            quartet = 0;
            padding = 0;
        }
    }
    Ok(typed_data(&base64_encode(&output)))
}
fn typed_date(value: &str) -> Value {
    let mut m = Map::new();
    m.insert("$plist_type".into(), Value::String("date".into()));
    m.insert("iso8601".into(), Value::String(value.to_owned()));
    Value::Object(m)
}
fn typed_unrepresentable_date() -> Value {
    typed_date("")
}

fn parse_date_literal(raw: &str) -> Result<String, &'static str> {
    let Some((date, time_and_zone)) = raw.split_once('T') else {
        return Err("invalid-literal");
    };
    let Some(time) = time_and_zone.strip_suffix('Z') else {
        return Err("invalid-literal");
    };
    let Some(day_separator) = date.rfind('-') else {
        return Err("invalid-literal");
    };
    let Some(month_separator) = date[..day_separator].rfind('-') else {
        return Err("invalid-literal");
    };
    let year_text = &date[..month_separator];
    let month_text = &date[month_separator + 1..day_separator];
    let day_text = &date[day_separator + 1..];
    let Some((hour_text, minute_second)) = time.split_once(':') else {
        return Err("invalid-literal");
    };
    let Some((minute_text, second_text)) = minute_second.split_once(':') else {
        return Err("invalid-literal");
    };

    let (negative, unsigned_year) = year_text
        .strip_prefix('-')
        .map_or((false, year_text), |year| (true, year));
    if unsigned_year.is_empty()
        || !unsigned_year
            .chars()
            .all(|character| character.is_ascii_digit())
        || month_text.len() != 2
        || day_text.len() != 2
        || hour_text.len() != 2
        || minute_text.len() != 2
        || second_text.len() != 2
        || !month_text
            .chars()
            .all(|character| character.is_ascii_digit())
        || !day_text.chars().all(|character| character.is_ascii_digit())
        || !hour_text
            .chars()
            .all(|character| character.is_ascii_digit())
        || !minute_text
            .chars()
            .all(|character| character.is_ascii_digit())
        || !second_text
            .chars()
            .all(|character| character.is_ascii_digit())
    {
        return Err("invalid-literal");
    }

    let year_magnitude = unsigned_year
        .parse::<i64>()
        .map_err(|_| "unrepresentable")?;
    let year = if negative {
        year_magnitude.checked_neg().ok_or("unrepresentable")?
    } else {
        year_magnitude
    };
    // Bound civil-date arithmetic before converting to milliseconds. JavaScript
    // Date rejects values far outside its representable range, and this guard
    // prevents hostile year literals from overflowing intermediate arithmetic.
    if !(-1_000_000..=1_000_000).contains(&year) {
        return Err("unrepresentable");
    }
    let month = month_text.parse::<u32>().unwrap_or(0);
    let day = day_text.parse::<u32>().unwrap_or(0);
    let hour = hour_text.parse::<u32>().unwrap_or(0);
    let minute = minute_text.parse::<u32>().unwrap_or(0);
    let second = second_text.parse::<u32>().unwrap_or(0);
    if month == 0
        || month > 12
        || hour > 23
        || minute > 59
        || second > 59
        || day == 0
        || day > days_in_month(year, month)
    {
        return Err("unrepresentable");
    }

    let days = days_from_civil(year, month, day);
    let milliseconds = days
        .checked_mul(86_400_000)
        .and_then(|value| value.checked_add(i64::from(hour * 3_600_000)))
        .and_then(|value| value.checked_add(i64::from(minute * 60_000)))
        .and_then(|value| value.checked_add(i64::from(second * 1_000)));
    let Some(milliseconds) = milliseconds else {
        return Err("unrepresentable");
    };
    if !(-8_640_000_000_000_000..=8_640_000_000_000_000).contains(&milliseconds) {
        return Err("unrepresentable");
    }

    Ok(format!(
        "{}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z",
        format_year(year)
    ))
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year / 400
    } else {
        (adjusted_year - 399) / 400
    };
    let year_of_era = adjusted_year - era * 400;
    let month_index = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146097 + day_of_era - 719468
}

fn format_year(year: i64) -> String {
    if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{abs:06}", abs = year.unsigned_abs())
    } else {
        format!("+{year:06}")
    }
}
fn typed_real(value: &str) -> Value {
    let mut m = Map::new();
    m.insert("$plist_type".into(), Value::String("real".into()));
    m.insert("value".into(), Value::String(value.to_owned()));
    Value::Object(m)
}

enum RealValue {
    Finite(f64),
    NonFinite(&'static str),
}

fn parse_real_literal(raw: &str) -> Result<RealValue, &'static str> {
    let lower = raw.to_ascii_lowercase();
    match lower.as_str() {
        "nan" => return Ok(RealValue::NonFinite("nan")),
        "+infinity" | "infinity" | "+inf" | "inf" => {
            return Ok(RealValue::NonFinite("+infinity"));
        }
        "-infinity" | "-inf" => return Ok(RealValue::NonFinite("-infinity")),
        _ => {}
    }

    let numeric = trim_real_leading_whitespace(raw);
    if numeric.is_empty() || !is_real_syntax(numeric) {
        return Err("invalid-literal");
    }
    let value = numeric.parse::<f64>().map_err(|_| "invalid-literal")?;
    if !value.is_finite() {
        return Err("unrepresentable");
    }
    Ok(RealValue::Finite(value))
}

fn trim_real_leading_whitespace(raw: &str) -> &str {
    raw.trim_start_matches(|character: char| {
        matches!(
            character as u32,
            0x0000..=0x0020
                | 0x007f..=0x00a0
                | 0x2000..=0x200b
                | 0x3000
                | 0xfeff
        )
    })
}

fn is_real_syntax(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        index += 1;
    }
    let integer_start = index;
    while matches!(bytes.get(index), Some(b'0'..=b'9')) {
        index += 1;
    }
    let integer_digits = index > integer_start;
    let mut fraction_digits = false;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let fraction_start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        fraction_digits = index > fraction_start;
    }
    if !integer_digits && !fraction_digits {
        return false;
    }
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let exponent_start = index;
        while matches!(bytes.get(index), Some(b'0'..=b'9')) {
            index += 1;
        }
        if index == exponent_start {
            return false;
        }
    }
    index == bytes.len()
}

fn typed_uid(value: u128) -> Value {
    let mut m = Map::new();
    m.insert("$plist_type".into(), Value::String("uid".into()));
    m.insert("value".into(), Value::String(value.to_string()));
    Value::Object(m)
}

#[derive(Clone, Debug)]
struct DecodedValue {
    value: Value,
    typed_scalar_paths: Vec<Vec<ValuePathSegment>>,
    typed_uid_paths: Vec<Vec<ValuePathSegment>>,
}

impl DecodedValue {
    fn plain(value: Value) -> Self {
        Self {
            value,
            typed_scalar_paths: Vec::new(),
            typed_uid_paths: Vec::new(),
        }
    }
}

fn prepend_path_segment(
    segment: ValuePathSegment,
    paths: Vec<Vec<ValuePathSegment>>,
) -> Vec<Vec<ValuePathSegment>> {
    paths
        .into_iter()
        .map(|mut path| {
            path.insert(0, segment.clone());
            path
        })
        .collect()
}

fn utf16_value(units: &[u16]) -> Value {
    match String::from_utf16(units) {
        Ok(value) => Value::String(value),
        Err(_) => {
            let mut object = Map::new();
            object.insert("$plist_type".into(), Value::String("string".into()));
            object.insert(
                "utf16_units".into(),
                Value::Array(
                    units
                        .iter()
                        .map(|unit| Value::Number(serde_json::Number::from(*unit)))
                        .collect(),
                ),
            );
            Value::Object(object)
        }
    }
}

fn binary_key(value: Value) -> Result<String, Error> {
    if let Some(key) = value.as_str() {
        return Ok(key.to_owned());
    }
    let units = value
        .get("utf16_units")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Invalid("binary dictionary key is not a string".into()))?;
    let mut escaped = String::new();
    for unit in units {
        let unit = unit
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| {
                Error::Invalid("binary dictionary key has invalid UTF-16 units".into())
            })?;
        escaped.push_str(&format!("\\u{unit:04X}"));
    }
    Ok(escaped)
}

fn parse_integer_literal(raw: &str) -> Result<String, &'static str> {
    let raw = raw.trim_matches(is_integer_whitespace);
    let (negative, digits) = match raw.strip_prefix('-') {
        Some(value) => (true, value.trim_matches(is_integer_whitespace)),
        None => (
            false,
            raw.strip_prefix('+')
                .unwrap_or(raw)
                .trim_matches(is_integer_whitespace),
        ),
    };
    if digits.is_empty() {
        return Err("invalid-literal");
    }
    if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
            return Err("invalid-literal");
        }
        let magnitude = u128::from_str_radix(hex, 16).map_err(|_| "unrepresentable")?;
        if negative {
            if magnitude == (1_u128 << 127) {
                return Ok(i128::MIN.to_string());
            }
            let signed = i128::try_from(magnitude).map_err(|_| "unrepresentable")?;
            return Ok((-signed).to_string());
        }
        return Ok(magnitude.to_string());
    }
    if !digits.chars().all(|character| character.is_ascii_digit()) {
        return Err("invalid-literal");
    }
    let canonical_digits = digits.trim_start_matches('0');
    if canonical_digits.is_empty() {
        return Ok("0".into());
    }
    let canonical = if negative {
        format!("-{canonical_digits}")
    } else {
        canonical_digits.to_owned()
    };
    Ok(canonical)
}

fn is_integer_whitespace(character: char) -> bool {
    character <= '\u{20}'
        || character == '\u{7f}'
        || ('\u{2000}'..='\u{200b}').contains(&character)
        || character == '\u{205f}'
        || character == '\u{3000}'
}

fn unknown(element: &str, literal: String, reason: &str) -> Value {
    let mut m = Map::new();
    m.insert("$plist_type".into(), Value::String("unknown".into()));
    m.insert("element".into(), Value::String(element.to_owned()));
    m.insert("literal".into(), Value::String(literal));
    m.insert("reason".into(), Value::String(reason.to_owned()));
    Value::Object(m)
}
fn json_integer(value: i128) -> Value {
    if value.unsigned_abs() <= 9_007_199_254_740_991 {
        return Value::Number(
            serde_json::Number::from_i128(value)
                .expect("JSON-safe plist integers must fit serde_json numbers"),
        );
    }
    json_integer_text(&value.to_string())
}

/// Byte width encoded by a bplist00 integer/real/date marker nibble (`2^n`).
fn binary_scalar_width(nibble: usize) -> usize {
    1_usize.checked_shl(nibble as u32).unwrap_or(usize::MAX)
}

/// bplist00 integers of 1, 2 and 4 bytes are unsigned; 8 bytes are signed.
fn binary_integer(raw: u64, width: usize) -> Value {
    if width == 8 {
        json_integer(i128::from(raw as i64))
    } else {
        json_integer(i128::from(raw))
    }
}
fn json_integer_text(value: &str) -> Value {
    let mut m = Map::new();
    m.insert("$plist_type".into(), Value::String("integer".into()));
    m.insert("decimal".into(), Value::String(value.to_owned()));
    Value::Object(m)
}

fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0] as u32;
        let b = chunk.get(1).copied().unwrap_or(0) as u32;
        let c = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (a << 16) | (b << 8) | c;
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn format_binary_date(seconds: f64) -> String {
    // Binary plists count seconds from 2001-01-01 UTC. Round only at the
    // millisecond boundary used by JavaScript Date#toISOString, carrying a
    // rounded fractional second into the next second when necessary.
    if !seconds.is_finite() {
        return "".into();
    }
    let unix = seconds + 978_307_200.0;
    let milliseconds = (unix * 1000.0).round();
    if !milliseconds.is_finite()
        || !(-8_640_000_000_000_000.0..=8_640_000_000_000_000.0).contains(&milliseconds)
    {
        return "".into();
    }
    let milliseconds = milliseconds as i64;
    let whole = milliseconds.div_euclid(1000);
    let millis = milliseconds.rem_euclid(1000);
    let days = whole.div_euclid(86_400);
    let rem = whole.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        format_year(year),
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let d = doy - (153 * mp + 2).div_euclid(5) + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_openstep_dictionary_arrays_strings_and_data() {
        let bytes = br#"{
            CFBundleIdentifier = "org.example.App";
            Enabled = YES;
            Payload = (alpha, "quoted\nvalue", <4142>);
        }"#;
        let report = read(bytes, "/tmp/openstep-info.plist".into()).unwrap();
        assert!(matches!(report.format, Format::OpenStep));
        assert_eq!(report.bundle.identifier.as_deref(), Some("org.example.App"));
        assert_eq!(report.value["Enabled"], true);
        assert_eq!(report.value["Payload"][0], "alpha");
        assert_eq!(report.value["Payload"][1], "quoted\nvalue");
        assert_eq!(report.value["Payload"][2]["$plist_type"], "data");
        assert_eq!(report.value["Payload"][2]["base64"], "QUI=");
    }

    #[test]
    fn coerces_openstep_compound_dictionary_keys_like_javascript() {
        let bytes = br#"{ ("__proto__") = dropped; ("__pro", "to__") = joined; }"#;
        let report = read(bytes, "/tmp/openstep-keys.plist".into()).unwrap();
        assert!(!report.value.as_object().unwrap().contains_key("__proto__"));
        assert_eq!(report.value["__pro,to__"], "joined");
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("keyed __proto__"))
        );
    }

    #[test]
    fn accepts_adjacent_openstep_dictionary_assignments() {
        let report = read(
            br#"{ key = x next = (y,); }"#,
            "/tmp/openstep-adjacent.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value["key"], "x");
        assert_eq!(report.value["next"][0], "y");
    }

    #[test]
    fn accepts_openstep_trailing_trivia() {
        let report = read(
            br#"{ key = value; } /* trailing comment */ // end
            "#,
            "/tmp/openstep-trailing-trivia.plist".into(),
        )
        .unwrap();

        assert_eq!(report.value["key"], "value");
    }

    #[test]
    fn rejects_openstep_trailing_content_with_source_offset() {
        let error = read(
            br#"{ key = value; } trailing"#,
            "/tmp/openstep-trailing-content.plist".into(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("trailing content at source offset")
        ));
    }

    #[test]
    fn detects_openstep_after_a_utf8_bom() {
        let mut bytes = vec![0xef, 0xbb, 0xbf];
        bytes.extend_from_slice(br#"(one, two)"#);
        let report = read(&bytes, "/tmp/openstep-bom.plist".into()).unwrap();
        assert!(matches!(report.format, Format::OpenStep));
        assert_eq!(report.value, serde_json::json!(["one", "two"]));
    }

    #[test]
    fn decodes_xml_bundle_metadata_and_typed_values() {
        let xml = br#"<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key><string>org.example.App</string><key>CFBundleExecutable</key><string>app</string><key>__proto__</key><string>drop</string><key>Payload</key><array><integer>9007199254740992</integer><real>-0</real><data>AA==</data><date>not-a-date</date></array></dict></plist>"#;
        let report = read(xml, "/tmp/Info.plist".into()).unwrap();
        assert!(matches!(report.format, Format::Xml));
        assert_eq!(report.bundle.identifier.as_deref(), Some("org.example.App"));
        assert_eq!(report.value["Payload"][0]["decimal"], "9007199254740992");
        assert_eq!(report.value["Payload"][1]["$plist_type"], "real");
        assert_eq!(report.value["Payload"][2]["$plist_type"], "data");
        assert!(report.value.get("__proto__").is_none());
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("__proto__"))
        );
    }

    #[test]
    fn duplicate_xml_dictionary_keys_keep_the_last_value() {
        let xml = br#"<plist><dict><key>name</key><string>first</string><key>name</key><string>last</string></dict></plist>"#;
        let report = read(xml, "/tmp/duplicate-key.plist".into()).unwrap();
        assert_eq!(report.value["name"], "last");
    }

    #[test]
    fn preserves_xml_dictionary_key_without_value_as_empty_string() {
        let xml = br#"<plist><dict><key>missing</key></dict></plist>"#;
        let report = read(xml, "/tmp/missing-value.plist".into()).unwrap();
        assert_eq!(report.value["missing"], "");
    }

    #[test]
    fn preserves_nonempty_xml_boolean_bodies_as_unknowns() {
        let xml = br#"<plist><array><true>yes</true><false><![CDATA[no]]></false><true><string>x</string></true></array></plist>"#;
        let report = read(xml, "/tmp/boolean-bodies.plist".into()).unwrap();
        assert_eq!(report.value[0]["$plist_type"], "unknown");
        assert_eq!(report.value[0]["reason"], "invalid-literal");
        assert_eq!(report.value[1]["literal"], "no");
        assert_eq!(report.value[1]["reason"], "invalid-literal");
        assert_eq!(report.value[2]["reason"], "unsupported-markup");
    }

    #[test]
    fn decodes_nested_xml_plist_envelopes_as_arrays() {
        let xml = br#"<plist><array><plist><null/></plist><plist><string>two</string><integer>3</integer></plist></array></plist>"#;
        let report = read(xml, "/tmp/nested-plist.plist".into()).unwrap();
        assert_eq!(report.value[0], serde_json::json!([null]));
        assert_eq!(report.value[1], serde_json::json!(["two", 3]));
    }

    #[test]
    fn rejects_xml_documents_whose_first_element_is_not_plist() {
        let xml = br#"<dict><key>name</key><string>wrong-root</string></dict><plist><string>later</string></plist>"#;
        let error = read(xml, "/tmp/wrong-root.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("First element should be <plist>")
        ));
    }

    #[test]
    fn decodes_self_closing_xml_plist_as_empty_array() {
        let report = read(br#"<plist/>"#, "/tmp/empty.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!([]));
    }

    #[test]
    fn rejects_nontrivia_after_the_xml_root() {
        let error = read(
            br#"<plist><string>value</string></plist>trailing"#,
            "/tmp/trailing.plist".into(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("content after the root")
        ));
    }

    #[test]
    fn rejects_unterminated_xml_scalar_elements() {
        let error = read(
            br#"<plist><string>value</plist>"#,
            "/tmp/unterminated-string.plist".into(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("element string is unterminated")
        ));
    }

    #[test]
    fn accepts_xml_comments_and_processing_instructions_after_the_root() {
        let report = read(
            br#"<plist><string>value</string></plist><!-- comment --><?ignored?>"#,
            "/tmp/trailing-trivia.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value, "value");
    }

    #[test]
    fn decodes_xml_null_values_as_json_null() {
        let report = read(
            br#"<plist><array><null/><dict><key>empty</key><null/></dict></array></plist>"#,
            "/tmp/null.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value.as_array().unwrap().len(), 1);
        assert!(report.value[0]["empty"].is_null());
    }

    #[test]
    fn rejects_unsupported_xml_tags_at_the_parser_boundary() {
        let error = read(
            br#"<plist><unsupported/></plist>"#,
            "/tmp/unsupported-tag.plist".into(),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("Invalid PLIST tag unsupported")
                    && reason.contains("source offset 7")
        ));
    }

    #[test]
    fn preserves_xml_integer_markup_as_unsupported() {
        let report = read(
            br#"<plist><array><integer><![CDATA[42]]></integer><integer>0x2A<!-- comment --></integer></array></plist>"#,
            "/tmp/integer-markup.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value[0]["$plist_type"], "unknown");
        assert_eq!(report.value[0]["reason"], "unsupported-markup");
        assert_eq!(report.value[1]["reason"], "unsupported-markup");
    }

    #[test]
    fn distinguishes_xml_real_cdata_from_unsupported_markup() {
        let report = read(
            br#"<plist><array><real>1<![CDATA[.25]]></real><real>1<!-- comment -->.25</real></array></plist>"#,
            "/tmp/real-markup.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value[0], 1.25);
        assert_eq!(report.value[1]["$plist_type"], "unknown");
        assert_eq!(report.value[1]["reason"], "unsupported-markup");
    }

    #[test]
    fn coerces_xml_dictionary_keys_with_nested_elements_like_typescript() {
        let report = read(
            br#"<plist><dict><key><real>9007199254740992</real></key><integer>7</integer></dict></plist>"#,
            "/tmp/nested-key.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value["null"], 7);
    }

    #[test]
    fn ignores_nested_xml_markup_inside_string_content() {
        let report = read(
            br#"<plist><array><string>text<integer>42</integer><![CDATA[more]]><!-- ignored --></string></array></plist>"#,
            "/tmp/string-markup.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value[0], "textmore");
    }

    #[test]
    fn decodes_utf8_and_bom_marked_utf16_xml_inputs() {
        let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist><string>hé</string></plist>";
        let utf8 = read(xml.as_bytes(), "/tmp/utf8.plist".into()).unwrap();
        assert_eq!(utf8.value, "hé");

        let utf16_xml =
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?><plist><string>hé</string></plist>";
        let utf16le = utf16_fixture(utf16_xml, true);
        let little = read(&utf16le, "/tmp/utf16le.plist".into()).unwrap();
        assert_eq!(little.value, "hé");

        let utf16be = utf16_fixture(utf16_xml, false);
        let big = read(&utf16be, "/tmp/utf16be.plist".into()).unwrap();
        assert_eq!(big.value, "hé");
    }

    #[test]
    fn preserves_unpaired_utf16_units_in_xml_text() {
        let mut units = "<plist><string>".encode_utf16().collect::<Vec<_>>();
        units.push(0xD800);
        units.extend("</string></plist>".encode_utf16());

        let bytes = utf16_units_fixture(&units, true);
        let report = read(&bytes, "/tmp/unpaired-xml.plist".into()).unwrap();

        assert_eq!(report.value, "\\uD800");
    }

    #[test]
    fn preserves_binary_utf16_units_and_paired_scalars() {
        let paired = read(
            &binary_utf16_fixture(&[0xD83D, 0xDE80]),
            "/tmp/paired-binary.plist".into(),
        )
        .unwrap();
        assert_eq!(paired.value, "🚀");

        for unit in [0xD800, 0xDC00] {
            let report = read(
                &binary_utf16_fixture(&[unit]),
                "/tmp/unpaired-binary.plist".into(),
            )
            .unwrap();
            assert_eq!(report.value["$plist_type"], "string");
            assert_eq!(report.value["utf16_units"][0], unit);

            let encoded = serde_json::to_vec(&report.value).unwrap();
            let round_tripped: Value = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(round_tripped["utf16_units"][0], unit);
        }
    }

    #[test]
    fn rejects_truncated_binary_utf16_payload_with_source_offset() {
        let bytes = binary_fixture(&[0x61, 0xff], &[8]);
        let error = read(&bytes, "/tmp/truncated-binary-utf16.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary UTF-16 string at object offset 8")
                    && reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn rejects_xml_encoding_failures_at_the_byte_boundary() {
        assert!(matches!(
            read(&[0xff, 0xfe, b'<'], "/tmp/odd.plist".into()),
            Err(Error::Invalid(reason)) if reason.contains("invalid for BOM-marked UTF-16")
        ));
        assert!(matches!(
            read(
                br#"<?xml version="1.0" encoding="UTF-16"?><plist/>"#,
                "/tmp/mismatch.plist".into()
            ),
            Err(Error::Invalid(reason)) if reason.contains("disagrees")
        ));
        assert!(matches!(
            read(
                br#"<?xml version="1.0" encoding="ISO-8859-1"?><plist/>"#,
                "/tmp/unsupported.plist".into()
            ),
            Err(Error::Invalid(reason)) if reason.contains("unsupported XML encoding")
        ));
    }

    #[test]
    fn accepts_all_supported_binary_offset_widths() {
        for width in 1..=8 {
            let bytes = binary_scalar_with_width(width);
            let report = read(&bytes, format!("/tmp/width-{width}.plist")).unwrap();
            assert_eq!(report.value, "x");
        }
    }

    #[test]
    fn rejects_binary_offset_tables_that_escape_the_payload() {
        let mut bytes = binary_scalar_with_width(1);
        let trailer = bytes.len() - 32;
        bytes[trailer + 31] = 0xff;
        assert!(matches!(
            read(&bytes, "/tmp/bad-offset.plist".into()),
            Err(Error::Invalid(reason)) if reason.contains("offset table")
        ));
    }

    fn utf16_fixture(text: &str, little_endian: bool) -> Vec<u8> {
        utf16_units_fixture(&text.encode_utf16().collect::<Vec<_>>(), little_endian)
    }

    fn utf16_units_fixture(units: &[u16], little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        for unit in units {
            let encoded = if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    fn binary_utf16_fixture(units: &[u16]) -> Vec<u8> {
        assert!(units.len() < 15);

        let mut bytes = b"bplist00".to_vec();
        bytes.push(0x60 | units.len() as u8);
        for unit in units {
            bytes.extend_from_slice(&unit.to_be_bytes());
        }

        let offset_table = bytes.len();
        bytes.push(8);

        let mut trailer = [0_u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[15] = 1;
        trailer[23] = 0;
        trailer[31] = offset_table as u8;
        bytes.extend_from_slice(&trailer);
        bytes
    }

    fn binary_scalar_with_width(width: usize) -> Vec<u8> {
        let mut bytes = b"bplist00\x51x".to_vec();
        let offset_table = bytes.len();
        bytes.extend(std::iter::repeat(0).take(width));
        let offset = 8_u64.to_be_bytes();
        bytes[offset_table..offset_table + width].copy_from_slice(&offset[8 - width..]);
        let mut trailer = [0_u8; 32];
        trailer[6] = width as u8;
        trailer[7] = 1;
        trailer[15] = 1;
        trailer[23] = 0;
        let table_offset = (offset_table as u64).to_be_bytes();
        trailer[24..32].copy_from_slice(&table_offset);
        bytes.extend_from_slice(&trailer);
        bytes
    }

    #[test]
    fn joins_cdata_segments_and_retains_unrepresentable_reals() {
        let xml = br#"<plist><dict><key>user<![CDATA[ID]]></key><integer>42</integer><key>Overflow</key><real>1e999</real></dict></plist>"#;
        let report = read(xml, "/tmp/Info.plist".into()).unwrap();
        assert_eq!(report.value["userID"], 42);
        assert_eq!(report.value["Overflow"]["$plist_type"], "unknown");
        assert_eq!(report.value["Overflow"]["literal"], "1e999");
    }

    #[test]
    fn matches_cfpropertylist_raw_data_scanning() {
        let cases = [
            ("&#65;QID", "65QI"),
            ("&amp;AQID", "ampA"),
            ("AQ&#10;ID", "AQ10"),
            ("&#xE9;AQID", "xE9A"),
            ("====", "AA=="),
            ("=AQI", "AAQI"),
            ("AQI=Z", "AQI="),
            ("AQ=!==", "AQA="),
        ];
        for (literal, expected) in cases {
            let xml = format!("<plist><data>{literal}</data></plist>");
            let report = read(xml.as_bytes(), "/tmp/data.plist".into()).unwrap();
            assert_eq!(report.value["base64"], expected);
        }
    }

    #[test]
    fn reports_data_source_offsets_and_decoded_limits() {
        let xml = "<plist><data>AQ<!-- source -->ID</data></plist>";
        assert!(matches!(
            read(xml.as_bytes(), "/tmp/data-markup.plist".into()),
            Err(Error::Invalid(reason)) if reason.contains("markup at source offset 2")
        ));

        assert!(matches!(
            decode_data_with_limit("AQID", 2),
            Err(Error::Invalid(reason)) if reason.contains("decoded byte limit of 2")
        ));
        assert_eq!(decode_data_with_limit("AQID", 3).unwrap()["base64"], "AQID");
    }

    #[test]
    fn rejects_non_ascii_and_markup_in_data() {
        for literal in ["AQéID", "A<!-- omitted -->QID", "<![CDATA[AQID]]>"] {
            let xml = format!("<plist><data>{literal}</data></plist>");
            assert!(matches!(
                read(xml.as_bytes(), "/tmp/data.plist".into()),
                Err(Error::Invalid(_))
            ));
        }
    }

    #[test]
    fn matches_xml_date_literal_boundaries() {
        let cases = [
            ("2001-02-03T04:05:06Z", "2001-02-03T04:05:06.000Z"),
            ("0000-02-29T00:00:00Z", "0000-02-29T00:00:00.000Z"),
            ("1-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z"),
            ("-0001-01-01T00:00:00Z", "-000001-01-01T00:00:00.000Z"),
            ("10000-01-01T00:00:00Z", "+010000-01-01T00:00:00.000Z"),
        ];
        for (literal, expected) in cases {
            assert_eq!(parse_date_literal(literal), Ok(expected.to_owned()));
        }
    }

    #[test]
    fn preserves_invalid_and_unsupported_xml_dates() {
        let cases = [
            ("2026-10-17T12:00:00+02:00", "invalid-literal"),
            ("2026-10-17T12:00:00.5Z", "invalid-literal"),
            ("2026-10-17T12:00:00", "invalid-literal"),
            ("2026-13-17T12:00:00Z", "unrepresentable"),
            ("2026-02-31T12:00:00Z", "unrepresentable"),
        ];
        for (literal, reason) in cases {
            let xml = format!("<plist><date>{literal}</date></plist>");
            let report = read(xml.as_bytes(), "/tmp/date.plist".into()).unwrap();
            if reason == "unrepresentable" {
                assert_eq!(report.value["$plist_type"], "date");
                assert!(report.value["iso8601"].is_null());
            } else {
                assert_eq!(report.value["$plist_type"], "unknown");
                assert_eq!(report.value["literal"], literal);
                assert_eq!(report.value["reason"], reason);
            }
        }

        let xml = "<plist><date><![CDATA[2026-10-17T12:00:00Z]]></date></plist>";
        let report = read(xml.as_bytes(), "/tmp/date.plist".into()).unwrap();
        assert_eq!(report.value["$plist_type"], "unknown");
        assert_eq!(report.value["reason"], "unsupported-markup");
    }

    #[test]
    fn decodes_xml_date_entities_before_validation() {
        let report = read(
            br#"<plist><date>2026-10-17T12:00:00&#x5A;</date></plist>"#,
            "/tmp/entity-date.plist".into(),
        )
        .unwrap();
        assert_eq!(
            report.value,
            serde_json::json!({
                "$plist_type": "date",
                "iso8601": "2026-10-17T12:00:00.000Z"
            })
        );

        let malformed = read(
            br#"<plist><date>2026-10-17T12:00:00&#x5A</date></plist>"#,
            "/tmp/malformed-entity-date.plist".into(),
        )
        .unwrap_err();
        assert!(matches!(
            malformed,
            Error::Invalid(reason)
                if reason.contains("entity reference at source offset")
                    && reason.contains("is unterminated")
        ));
    }

    #[test]
    fn preserves_huge_xml_date_year_as_unrepresentable() {
        let xml = "<plist><date>999999999999999999999-01-01T00:00:00Z</date></plist>";
        let report = read(xml.as_bytes(), "/tmp/huge-date.plist".into()).unwrap();
        assert_eq!(report.value["$plist_type"], "date");
        assert!(report.value["iso8601"].is_null());
        assert!(
            report
                .limitations
                .iter()
                .any(|item| item.contains("date value"))
        );
    }

    #[test]
    fn matches_xml_real_literal_projection_edges() {
        let cases = [
            ("nan", "nan"),
            ("+inf", "+infinity"),
            ("-Infinity", "-infinity"),
            ("\u{2003}42.5", "42.5"),
            ("<![CDATA[-0.0]]>", "-0"),
        ];
        for (literal, expected) in cases {
            let xml = format!("<plist><real>{literal}</real></plist>");
            let report = read(xml.as_bytes(), "/tmp/real.plist".into()).unwrap();
            if expected == "42.5" {
                assert_eq!(report.value, 42.5);
            } else {
                assert_eq!(report.value["value"], expected);
            }
        }

        for (literal, reason) in [("1e", "invalid-literal"), ("1e999", "unrepresentable")] {
            let xml = format!("<plist><real>{literal}</real></plist>");
            let report = read(xml.as_bytes(), "/tmp/real.plist".into()).unwrap();
            assert_eq!(report.value["$plist_type"], "unknown");
            assert_eq!(report.value["literal"], literal);
            assert_eq!(report.value["reason"], reason);
        }
    }

    #[test]
    fn matches_typescript_integer_whitespace_rules() {
        for prefix in ["\u{0000}", "\u{007f}", "\u{2003}", "\u{205f}", "\u{3000}"] {
            let xml = format!("<plist><integer>{prefix}42</integer></plist>");
            assert_eq!(
                read(xml.as_bytes(), "/tmp/integer-space.plist".into())
                    .unwrap()
                    .value,
                42
            );
        }

        let xml = "<plist><integer>-\u{2003}42\u{3000}</integer></plist>";
        assert_eq!(
            read(xml.as_bytes(), "/tmp/integer-sign-space.plist".into())
                .unwrap()
                .value,
            -42
        );

        let xml = "<plist><integer>\u{202f}42</integer></plist>";
        let report = read(xml.as_bytes(), "/tmp/integer-invalid-space.plist".into()).unwrap();
        assert_eq!(report.value["$plist_type"], "unknown");
        assert_eq!(report.value["reason"], "invalid-literal");
    }

    #[test]
    fn reports_xml_data_limits_and_source_offsets() {
        assert!(matches!(
            decode_data_with_limit("AAAA", 2),
            Err(Error::Invalid(reason))
                if reason.contains("decoded byte limit of 2") && reason.contains("offset 3")
        ));
        assert!(matches!(
            decode_data("AAéA"),
            Err(Error::Invalid(reason))
                if reason.contains("non-ASCII character") && reason.contains("offset 2")
        ));
    }

    #[test]
    fn preserves_xml_integer_precision_beyond_machine_widths() {
        let xml = br#"<plist><array><integer>9223372036854775808</integer><integer>-9223372036854775809</integer><integer>00000000000000000042</integer><integer>0xFFFFFFFFFFFFFFFF</integer></array></plist>"#;
        let report = read(xml, "/tmp/integers.plist".into()).unwrap();
        assert_eq!(report.value[0]["decimal"], "9223372036854775808");
        assert_eq!(report.value[1]["decimal"], "-9223372036854775809");
        assert_eq!(report.value[2], 42);
        assert_eq!(report.value[3]["decimal"], "18446744073709551615");

        let preserved = read(
            b"<plist><integer>0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF</integer></plist>",
            "/tmp/max-integer.plist".into(),
        )
        .unwrap();
        assert_eq!(
            preserved.value["decimal"],
            "340282366920938463463374607431768211455"
        );

        for (literal, reason) in [
            ("42suffix", "invalid-literal"),
            ("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "unrepresentable"),
        ] {
            let xml = format!("<plist><integer>{literal}</integer></plist>");
            let report = read(xml.as_bytes(), "/tmp/bad-integer.plist".into()).unwrap();
            assert_eq!(report.value["$plist_type"], "unknown");
            assert_eq!(report.value["literal"], literal);
            assert_eq!(report.value["reason"], reason);
        }
    }

    #[test]
    fn formats_binary_dates_at_millisecond_and_range_boundaries() {
        assert_eq!(format_binary_date(0.0), "2001-01-01T00:00:00.000Z");
        assert_eq!(format_binary_date(0.1234), "2001-01-01T00:00:00.123Z");
        assert_eq!(format_binary_date(0.9996), "2001-01-01T00:00:01.000Z");
        assert_eq!(format_binary_date(-0.5), "2000-12-31T23:59:59.500Z");
        assert!(format_binary_date(f64::INFINITY).is_empty());
        assert!(format_binary_date(9.0e15).is_empty());
    }

    #[test]
    fn rejects_binary_date_widths_with_object_offsets() {
        let bytes = binary_integer_fixture(0x31, &[0, 0]);
        let error = read(&bytes, "/tmp/unsupported-date-width.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary date at object offset 8")
                    && reason.contains("unsupported width 2")
        ));
    }

    #[test]
    fn rejects_truncated_binary_date_payload_with_source_offset() {
        let bytes = binary_integer_fixture(0x33, &[0, 0, 0, 0]);
        let error = read(&bytes, "/tmp/truncated-binary-date.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary date at object offset 8")
                    && reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn rejects_excessive_nesting() {
        let mut xml = String::from("<plist>");
        for _ in 0..130 {
            xml.push_str("<array>");
        }
        xml.push_str("<string>x</string>");
        for _ in 0..130 {
            xml.push_str("</array>");
        }
        xml.push_str("</plist>");
        assert!(matches!(
            read(xml.as_bytes(), "/tmp/x".into()),
            Err(Error::Depth)
        ));
    }

    #[test]
    fn accepts_maximum_supported_nesting() {
        let mut xml = String::from("<plist>");
        for _ in 0..127 {
            xml.push_str("<array>");
        }
        xml.push_str("<string>x</string>");
        for _ in 0..127 {
            xml.push_str("</array>");
        }
        xml.push_str("</plist>");
        assert!(read(xml.as_bytes(), "/tmp/deep.plist".into()).is_ok());
    }

    #[test]
    fn decodes_binary_uid_without_numeric_loss() {
        let mut bytes = b"bplist00\x80\x08\x08".to_vec();
        bytes.extend_from_slice(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]);
        let end = bytes.len();
        bytes[end - 32 + 6] = 1;
        bytes[end - 32 + 7] = 1;
        bytes[end - 32 + 15] = 1;
        bytes[end - 32 + 23] = 0;
        bytes[end - 32 + 31] = 10;
        let report = read(&bytes, "/tmp/uid.plist".into()).unwrap();
        assert_eq!(report.value["$plist_type"], "uid");
        assert_eq!(report.value["value"], "8");
    }

    #[test]
    fn decodes_binary_uids_at_each_supported_width() {
        let cases = [
            (0x80, vec![0xff], "255"),
            (0x81, vec![0xff, 0xff], "65535"),
            (0x82, vec![0xff, 0xff, 0xff], "16777215"),
            (0x83, vec![0xff, 0xff, 0xff, 0xff], "4294967295"),
            (
                0x87,
                vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                "18446744073709551615",
            ),
        ];
        for (marker, payload, expected) in cases {
            let bytes = binary_uid_fixture(marker, &payload);
            let report = read(&bytes, "/tmp/uid-width.plist".into()).unwrap();
            assert_eq!(report.value["$plist_type"], "uid");
            assert_eq!(report.value["value"], expected);
        }
    }

    #[test]
    fn decodes_sixteen_byte_binary_uid_without_numeric_loss() {
        let payload = vec![0xff; 16];
        let bytes = binary_uid_fixture(0x8f, &payload);
        let report = read(&bytes, "/tmp/uid-sixteen-byte.plist".into()).unwrap();
        assert_eq!(
            report.value["value"],
            "340282366920938463463374607431768211455"
        );
    }

    #[test]
    fn rejects_reserved_binary_simple_markers() {
        let bytes = binary_uid_fixture(0x01, &[]);
        let error = read(&bytes, "/tmp/reserved-simple.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("reserved simple marker 0x01")
        ));
    }

    #[test]
    fn rejects_binary_extended_length_that_reaches_the_offset_table() {
        let bytes = binary_integer_fixture(0x4f, &[]);
        let error = read(&bytes, "/tmp/truncated-extended-data.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn decodes_extended_lengths_for_binary_collections_and_data() {
        let array = binary_fixture(
            &[0xaf, 0x10, 0x02, 0x00, 0x01, 0x00, 0x02, 0x00, 0x51, b'x'],
            &[8, 15, 16],
        );
        let report = read(&array, "/tmp/extended-array.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!([null, "x"]));

        let dictionary = binary_fixture(
            &[
                0xdf, 0x10, 0x01, 0x00, 0x01, 0x00, 0x02, 0x51, b'k', 0x51, b'v',
            ],
            &[8, 15, 17],
        );
        let report = read(&dictionary, "/tmp/extended-dictionary.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!({ "k": "v" }));

        let data = binary_fixture(&[0x4f, 0x10, 0x03, b'a', b'b', b'c'], &[8]);
        let report = read(&data, "/tmp/extended-data.plist".into()).unwrap();
        assert_eq!(report.value["$plist_type"], "data");
        assert_eq!(report.value["base64"], "YWJj");
    }

    #[test]
    fn rejects_malformed_binary_extended_length_markers_with_offsets() {
        let non_integer = binary_fixture(&[0x4f, 0x51, 0x01, b'x'], &[8]);
        let error = read(&non_integer, "/tmp/non-integer-length.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("extended length at offset 9 is not an integer")
        ));

        let unsupported_width = binary_fixture(&[0x4f, 0x14, 0, 0, 0, 0, 0, 0, 0, 1], &[8]);
        let error = read(&unsupported_width, "/tmp/large-length-width.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("extended length at offset 9 has unsupported width")
        ));

        let overflowing_count = binary_fixture(&[0xaf, 0x11, 0xff, 0xff], &[8]);
        let error = read(&overflowing_count, "/tmp/overflowing-count.plist".into()).unwrap_err();
        assert!(matches!(error, Error::Invalid(reason) if reason.contains("references")));
    }

    #[test]
    fn preserves_scalar_closing_tags_inside_xml_markup() {
        let xml = br#"<plist><array><integer>4<!-- </integer> -->2</integer><integer>4<![CDATA[</integer>]]>2</integer></array></plist>"#;
        let report = read(xml, "/tmp/scalar-closing-tag.plist".into()).unwrap();
        for value in report.value.as_array().unwrap() {
            assert_eq!(value["$plist_type"], "unknown");
            assert_eq!(value["reason"], "unsupported-markup");
        }
    }

    #[test]
    fn accepts_document_level_processing_instructions_before_xml_root() {
        let report = read(
            br#"<?rea ignored?><?xml version="1.0"?><plist><string>value</string></plist>"#,
            "/tmp/document-pi.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value, "value");
    }

    #[test]
    fn keyed_archive_reader_skips_external_doctype_without_resolving_it() {
        let xml = br#"<?xml version="1.0"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://example.invalid/PropertyList-1.0.dtd">
<plist><dict><key>value</key><string>observed</string></dict></plist>"#;
        let decoded = read_keyed_archive_with_provenance(xml, "/tmp/archive.plist".into())
            .expect("external DTD declarations should not trigger network access");

        assert_eq!(decoded.report.value["value"], "observed");
    }

    #[test]
    fn xml_provenance_marks_generated_scalars_but_not_matching_dictionaries() {
        let xml = br#"<plist><dict>
<key>typed</key><data>AQ==</data>
<key>lookalike</key><dict><key>$plist_type</key><string>data</string><key>base64</key><string>AQ==</string></dict>
</dict></plist>"#;
        let decoded = read_with_provenance(xml, "/tmp/provenance.plist".into()).unwrap();

        assert_eq!(
            decoded.typed_scalar_paths,
            vec![vec![ValuePathSegment::Key("typed".into())]]
        );
        assert!(decoded.binary_uid_paths.is_empty());
        assert_eq!(decoded.report.value["lookalike"]["$plist_type"], "data");
    }

    #[test]
    fn keyed_archive_reader_rejects_internal_doctype_expansion() {
        let xml = br#"<!DOCTYPE plist [<!ENTITY nested "expanded">]><plist><string>&nested;</string></plist>"#;
        let error = read_keyed_archive_with_provenance(xml, "/tmp/archive.plist".into())
            .expect_err("internal entity declarations have no bounded expansion model");

        assert!(matches!(error, Error::Capacity));
    }

    #[test]
    fn keyed_archive_reader_rejects_binary_reference_cycles_before_decode() {
        let bytes = binary_fixture(&[0xA1, 0, 0], &[8]);
        let error = read_keyed_archive_with_provenance(&bytes, "/tmp/archive.plist".into())
            .expect_err("cyclic object references cannot form a property list archive");

        assert!(matches!(error, Error::Invalid(reason) if reason.contains("cycle")));
    }

    #[test]
    fn preserves_xml_string_and_key_whitespace() {
        let report = read(
            br#"<plist><dict><key>  spaced key  </key><string>  spaced value  </string></dict></plist>"#,
            "/tmp/whitespace.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value["  spaced key  "], "  spaced value  ");
    }

    #[test]
    fn joins_xml_string_text_and_adjacent_cdata_segments() {
        let report = read(
            br#"<plist><dict><key>a<![CDATA[b]]>c</key><string>x<![CDATA[y]]>z</string></dict></plist>"#,
            "/tmp/cdata-segments.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value["abc"], "xyz");
    }

    #[test]
    fn decodes_predefined_and_numeric_xml_entities() {
        let report = read(
            br#"<plist><string>&amp;&lt;&gt;&apos;&quot;&#65;&#x42;</string></plist>"#,
            "/tmp/entities.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value, "&<>\'\"AB");
    }

    #[test]
    fn rejects_invalid_and_unterminated_xml_entities() {
        for literal in ["&#xD800;", "&unknown;", "unterminated &amp"] {
            let xml = format!("<plist><string>{literal}</string></plist>");
            let error = read(xml.as_bytes(), "/tmp/invalid-entity.plist".into()).unwrap_err();
            assert!(matches!(error, Error::Invalid(reason) if reason.contains("XML entity")));
        }
    }

    #[test]
    fn reports_xml_entity_source_offsets() {
        let xml = b"<plist><string>&unknown;</string></plist>";
        let error = read(xml, "/tmp/entity-offset.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("XML entity reference at source offset 15")
                    && reason.contains("invalid")
        ));
    }

    #[test]
    fn ignores_xml_trivia_inside_dictionary_keys() {
        let report = read(
            br#"<plist><dict><key><!-- comment -->name<?ignored?></key><string>value</string></dict></plist>"#,
            "/tmp/key-trivia.plist".into(),
        )
        .unwrap();
        assert_eq!(report.value["name"], "value");
    }

    #[test]
    fn preserves_binary_integer_sign_and_precision() {
        // The marker nibble is log2 of the width: 0x13 is an 8-byte signed integer.
        let negative = binary_integer_fixture(0x13, &[0xff; 8]);
        let report = read(&negative, "/tmp/negative.plist".into()).unwrap();
        assert_eq!(report.value, -1);

        // 1, 2 and 4 byte bplist00 integers are unsigned.
        let byte = binary_integer_fixture(0x10, &[0xff]);
        let report = read(&byte, "/tmp/byte.plist".into()).unwrap();
        assert_eq!(report.value, 255);
        let word = binary_integer_fixture(0x11, &[0x01, 0x00]);
        let report = read(&word, "/tmp/word.plist".into()).unwrap();
        assert_eq!(report.value, 256);

        let large = binary_integer_fixture(0x13, &0x0020_0000_0000_0000_u64.to_be_bytes());
        let report = read(&large, "/tmp/large.plist".into()).unwrap();
        assert_eq!(report.value["$plist_type"], "integer");
        assert_eq!(report.value["decimal"], "9007199254740992");
    }

    #[test]
    fn decodes_one_byte_binary_integer_dictionary_values() {
        // Regression: Dictionary.app ImageWindow.nib stores `0x10 0x01`, a
        // one-byte integer whose marker nibble is log2(width) = 0.
        // { "k": 1 } with 2-byte references — dict@8, "k"@13, 1@15.
        let bytes = binary_fixture(
            &[0xd1, 0x00, 0x01, 0x00, 0x02, 0x51, b'k', 0x10, 0x01],
            &[8, 13, 15],
        );
        let report = read(&bytes, "/tmp/one-byte-integer.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!({ "k": 1 }));
    }

    #[test]
    fn decodes_self_closing_xml_containers_without_consuming_parent_close() {
        // Regression: Calculator.app Info.plist nests `<dict/>` before the
        // parent's `</dict>` and later top-level keys.
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>Scene</key><dict><key>Configs</key><dict/><key>List</key><array/></dict>
<key>CFBundleExecutable</key><string>Calculator</string>
</dict></plist>"#;
        let report = read(xml, "/tmp/Info.plist".into()).unwrap();
        assert_eq!(
            report.value,
            serde_json::json!({
                "Scene": { "Configs": {}, "List": [] },
                "CFBundleExecutable": "Calculator"
            })
        );
    }

    #[test]
    fn rejects_binary_integer_widths_with_object_offsets() {
        let bytes = binary_integer_fixture(0x15, &[]);
        let error = read(&bytes, "/tmp/unsupported-integer-width.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary integer at object offset 8")
                    && reason.contains("unsupported width 32")
        ));
    }

    #[test]
    fn rejects_binary_integer_payload_that_reaches_the_offset_table() {
        let bytes = binary_integer_fixture(0x12, &[0x00]);
        let error = read(&bytes, "/tmp/truncated-integer.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary integer at object offset 8")
                    && reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn rejects_binary_data_payload_that_reaches_the_offset_table() {
        let bytes = binary_integer_fixture(0x42, &[0x00]);
        let error = read(&bytes, "/tmp/truncated-data.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary data at object offset 8")
                    && reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn preserves_binary_non_finite_reals_as_typed_values() {
        let mut bytes = b"bplist00\x23".to_vec();
        bytes.extend_from_slice(&f64::INFINITY.to_bits().to_be_bytes());
        let offset_table = bytes.len();
        bytes.push(8);
        let mut trailer = [0_u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[15] = 1;
        trailer[24..32].copy_from_slice(&(offset_table as u64).to_be_bytes());
        bytes.extend_from_slice(&trailer);

        let report = read(&bytes, "/tmp/Info.plist".into()).unwrap();

        assert_eq!(report.value["$plist_type"], "real");
        assert_eq!(report.value["value"], "+infinity");
    }

    #[test]
    fn rejects_binary_real_widths_with_object_offsets() {
        let bytes = binary_integer_fixture(0x21, &[0, 0]);
        let error = read(&bytes, "/tmp/unsupported-real-width.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary real at object offset 8")
                    && reason.contains("unsupported width 2")
        ));
    }

    #[test]
    fn rejects_truncated_binary_real_payload_with_source_offset() {
        let bytes = binary_integer_fixture(0x23, &[0, 0, 0, 0]);
        let error = read(&bytes, "/tmp/truncated-binary-real.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary real at object offset 8")
                    && reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn rejects_binary_uid_widths_and_truncation_with_object_offsets() {
        let malformed = binary_uid_fixture(0x8f, &[1, 2, 3]);
        assert!(matches!(
            read(&malformed, "/tmp/uid-malformed.plist".into()),
            Err(Error::Invalid(reason)) if reason.contains("UID at object offset 8") && reason.contains("truncated for width 16")
        ));

        let truncated = binary_uid_fixture(0x83, &[1, 2]);
        assert!(matches!(
            read(&truncated, "/tmp/uid-truncated.plist".into()),
            Err(Error::Invalid(reason)) if reason.contains("UID at object offset 8") && reason.contains("truncated")
        ));
    }

    #[test]
    fn preserves_shared_binary_object_references() {
        let bytes = binary_fixture(&[0xA2, 0, 1, 0, 1, 0x51, b'x'], &[8, 13, 13]);
        let report = read(&bytes, "/tmp/shared.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!(["x", "x"]));
    }

    #[test]
    fn reports_binary_uid_source_paths_separately_from_matching_dictionaries() {
        let objects = [
            0xA2, 0x00, 0x01, 0x00, 0x02, // root array: object 1, object 2
            0x80, 0x01, // object 1: UID(1)
            0xD2, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, // object 2: dictionary
            0x5B, b'$', b'p', b'l', b'i', b's', b't', b'_', b't', b'y', b'p', b'e', 0x55, b'v',
            b'a', b'l', b'u', b'e', 0x53, b'u', b'i', b'd', 0x51, b'1',
        ];
        let bytes = binary_fixture(&objects, &[8, 13, 15, 24, 36, 42, 46]);

        let decoded = read_with_provenance(&bytes, "/tmp/uid-provenance.plist".into()).unwrap();

        assert_eq!(
            decoded.report.value,
            serde_json::json!([
                {"$plist_type": "uid", "value": "1"},
                {"$plist_type": "uid", "value": "1"}
            ])
        );
        assert_eq!(
            decoded.binary_uid_paths,
            vec![vec![ValuePathSegment::Index(0)]]
        );
    }

    #[test]
    fn caches_shared_binary_null_references() {
        let bytes = binary_fixture(&[0xA2, 0, 1, 0, 1, 0x00], &[8, 13]);
        let report = read(&bytes, "/tmp/shared-null.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!([null, null]));
    }

    #[test]
    fn decodes_binary_set_collections_as_ordered_values() {
        for marker in [0xC2, 0xE2] {
            let bytes = binary_fixture(&[marker, 0, 1, 0, 1, 0x51, b'x'], &[8, 13, 13]);
            let report = read(&bytes, "/tmp/set.plist".into()).unwrap();
            assert_eq!(report.value, serde_json::json!(["x", "x"]));
        }
    }

    #[test]
    fn decodes_binary_ordered_set_collections_as_ordered_values() {
        let bytes = binary_fixture(&[0xB2, 0, 1, 0, 1, 0x51, b'x'], &[8, 13, 13]);
        let report = read(&bytes, "/tmp/ordered-set.plist".into()).unwrap();
        assert_eq!(report.value, serde_json::json!(["x", "x"]));
    }

    #[test]
    fn rejects_truncated_binary_set_references() {
        let bytes = binary_fixture(&[0xC3, 0, 1], &[8]);
        let error = read(&bytes, "/tmp/truncated-set.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("collection references")
        ));
    }

    #[test]
    fn rejects_truncated_binary_ordered_set_references_with_source_offset() {
        let bytes = binary_fixture(&[0xB3, 0, 1], &[8]);
        let error = read(&bytes, "/tmp/truncated-ordered-set.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("marker 0xb3 at offset 8")
                    && reason.contains("collection references")
        ));
    }

    #[test]
    fn decodes_binary_utf8_string_markers() {
        let bytes = binary_fixture(&[0x72, 0xc3, 0xa9], &[8]);
        let report = read(&bytes, "/tmp/utf8-string.plist".into()).unwrap();
        assert_eq!(report.value, "é");
    }

    #[test]
    fn rejects_malformed_binary_utf8_string_markers() {
        let bytes = binary_fixture(&[0x72, 0xff, 0xff], &[8]);
        let error = read(&bytes, "/tmp/malformed-utf8-string.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("string at object offset 8")
                    && reason.contains("invalid UTF-8")
        ));
    }

    #[test]
    fn rejects_truncated_binary_string_payload_with_source_offset() {
        let bytes = binary_fixture(&[0x52, b'x'], &[8]);
        let error = read(&bytes, "/tmp/truncated-binary-string.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("binary string at object offset 8")
                    && reason.contains("scalar is truncated before the offset table")
        ));
    }

    #[test]
    fn rejects_binary_offset_tables_inside_the_header() {
        let mut bytes = binary_fixture(&[0x51, b'x'], &[8]);
        let trailer_start = bytes.len() - 32;
        bytes[trailer_start + 31] = 7;
        let error = read(&bytes, "/tmp/header-offset-table.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("starts inside the header")
        ));
    }

    #[test]
    fn rejects_referenced_binary_fill_markers_explicitly() {
        let bytes = binary_integer_fixture(0x0F, &[]);
        let error = read(&bytes, "/tmp/referenced-fill-marker.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("fill marker cannot be referenced")
        ));
    }

    #[test]
    fn rejects_binary_objects_that_start_inside_the_header() {
        let bytes = binary_fixture(&[0x51, b'x'], &[7]);
        let error = read(&bytes, "/tmp/header-object-offset.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason) if reason.contains("object offset 7") && reason.contains("inside the header")
        ));
    }

    #[test]
    fn terminates_binary_cycles_with_an_explicit_reference_value() {
        let bytes = binary_fixture(&[0xA1, 0, 0], &[8]);
        let report = read(&bytes, "/tmp/cyclic.plist".into()).unwrap();
        assert_eq!(report.value[0]["$plist_type"], "unknown");
        assert_eq!(report.value[0]["element"], "reference");
        assert_eq!(report.value[0]["literal"], "object 0");
        assert_eq!(report.value[0]["reason"], "cyclic-reference");
    }

    #[test]
    fn rejects_binary_collection_references_with_source_offsets() {
        let bytes = binary_fixture(&[0xA1, 0, 2], &[8]);
        let error = read(&bytes, "/tmp/invalid-array-reference.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("collection marker 0xa1 at offset 8 reference 0")
                    && reason.contains("object reference is invalid")
        ));
    }

    #[test]
    fn rejects_binary_dictionary_key_references_with_source_offsets() {
        let bytes = binary_fixture(&[0xD1, 0, 2, 0, 0], &[8]);
        let error = read(&bytes, "/tmp/invalid-dictionary-reference.plist".into()).unwrap_err();
        assert!(matches!(
            error,
            Error::Invalid(reason)
                if reason.contains("dictionary marker 0xd1 at offset 8 key reference 0")
                    && reason.contains("object reference is invalid")
        ));
    }

    fn binary_fixture(objects: &[u8], offsets: &[u8]) -> Vec<u8> {
        let mut bytes = b"bplist00".to_vec();
        bytes.extend_from_slice(objects);
        let offset_table = bytes.len();
        bytes.extend_from_slice(offsets);
        let mut trailer = [0_u8; 32];
        trailer[6] = 1;
        trailer[7] = 2;
        trailer[15] = offsets.len() as u8;
        trailer[23] = 0;
        trailer[31] = offset_table as u8;
        bytes.extend_from_slice(&trailer);
        bytes
    }

    fn binary_uid_fixture(marker: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = b"bplist00".to_vec();
        bytes.push(marker);
        bytes.extend_from_slice(payload);
        let offset_table = bytes.len();
        bytes.push(8);
        let mut trailer = [0_u8; 32];
        trailer[6] = 1;
        trailer[7] = 1;
        trailer[15] = 1;
        trailer[23] = 0;
        trailer[24..32].copy_from_slice(&(offset_table as u64).to_be_bytes());
        bytes.extend_from_slice(&trailer);
        bytes
    }

    fn binary_integer_fixture(marker: u8, payload: &[u8]) -> Vec<u8> {
        binary_uid_fixture(marker, payload)
    }
}

struct Binary<'a> {
    bytes: &'a [u8],
    objects: Vec<DecodedValue>,
    decoded: Vec<bool>,
    offsets: Vec<usize>,
    active: Vec<bool>,
    ref_size: usize,
    payload_end: usize,
    top: usize,
    nodes: usize,
}
impl<'a> Binary<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            objects: Vec::new(),
            decoded: Vec::new(),
            offsets: Vec::new(),
            active: Vec::new(),
            ref_size: 0,
            payload_end: 0,
            top: 0,
            nodes: 0,
        }
    }
    fn decode(mut self) -> Result<DecodedValue, Error> {
        if self.bytes.len() < 40 {
            return Err(Error::Invalid(
                "binary property list trailer is truncated".into(),
            ));
        }
        let trailer = &self.bytes[self.bytes.len() - 32..];
        let offset_size = trailer[6] as usize;
        let ref_size = trailer[7] as usize;
        if !(1..=8).contains(&offset_size) || !(1..=8).contains(&ref_size) {
            return Err(Error::Invalid(
                "binary property list trailer has unsupported offset or reference width".into(),
            ));
        }
        let count = u64::from_be_bytes(trailer[8..16].try_into().unwrap());
        let top = u64::from_be_bytes(trailer[16..24].try_into().unwrap());
        let offset = u64::from_be_bytes(trailer[24..32].try_into().unwrap());
        let count = usize::try_from(count).map_err(|_| Error::Capacity)?;
        self.top = usize::try_from(top).map_err(|_| {
            Error::Invalid("binary property list top object offset overflows usize".into())
        })?;
        let offset = usize::try_from(offset).map_err(|_| {
            Error::Invalid("binary property list offset table location overflows usize".into())
        })?;
        if offset < 8 {
            return Err(Error::Invalid(
                "binary property list offset table starts inside the header".into(),
            ));
        }
        if count > 1_000_000 {
            return Err(Error::Capacity);
        }
        if self.top >= count {
            return Err(Error::Invalid(format!(
                "binary property list top object index {} is outside {} objects",
                self.top, count
            )));
        }
        self.ref_size = ref_size;
        self.payload_end = offset;
        let table_size = count
            .checked_mul(offset_size)
            .ok_or_else(|| Error::Capacity)?;
        let table_end = offset.checked_add(table_size).ok_or_else(|| {
            Error::Invalid("binary property list offset table location overflows usize".into())
        })?;
        if table_end > self.bytes.len() - 32 {
            return Err(Error::Invalid(format!(
                "binary property list offset table [{offset}, {table_end}) exceeds payload boundary {}",
                self.bytes.len() - 32
            )));
        }
        for i in 0..count {
            let entry = offset + i * offset_size;
            let raw = self.uint(entry, offset_size)?;
            let object_offset = usize::try_from(raw).map_err(|_| {
                Error::Invalid(format!(
                    "binary property list object offset at table offset {entry} overflows usize"
                ))
            })?;
            if object_offset < 8 {
                return Err(Error::Invalid(format!(
                    "binary property list object offset {object_offset} at table offset {entry} starts inside the header"
                )));
            }
            if object_offset >= offset {
                return Err(Error::Invalid(format!(
                    "binary property list object offset {object_offset} at table offset {entry} overlaps the offset table"
                )));
            }
            self.offsets.push(object_offset);
        }
        self.objects = (0..count)
            .map(|_| DecodedValue::plain(Value::Null))
            .collect();
        self.decoded = vec![false; count];
        self.active = vec![false; count];
        self.object(self.top, 0)
    }
    fn uint(&self, p: usize, n: usize) -> Result<u64, Error> {
        if n > 8 || p.checked_add(n).is_none_or(|e| e > self.bytes.len()) {
            return Err(Error::Invalid(
                "binary property list integer is out of bounds".into(),
            ));
        }
        let mut v = 0;
        for b in &self.bytes[p..p + n] {
            v = (v << 8) | u64::from(*b);
        }
        Ok(v)
    }

    fn uint128(&self, p: usize, n: usize) -> Result<u128, Error> {
        if n > 16 || p.checked_add(n).is_none_or(|e| e > self.bytes.len()) {
            return Err(Error::Invalid(
                "binary property list integer is out of bounds".into(),
            ));
        }
        let mut value = 0_u128;
        for byte in &self.bytes[p..p + n] {
            value = (value << 8) | u128::from(*byte);
        }
        Ok(value)
    }

    fn payload_uint(&self, p: usize, n: usize) -> Result<u64, Error> {
        if n > 8 || p.checked_add(n).is_none_or(|e| e > self.payload_end) {
            return Err(Error::Invalid(
                "binary property list scalar is truncated before the offset table".into(),
            ));
        }
        self.uint(p, n)
    }

    fn payload_slice(&self, start: usize, length: usize) -> Result<&[u8], Error> {
        let end = start.checked_add(length).ok_or_else(|| {
            Error::Invalid("binary property list scalar range overflows usize".into())
        })?;
        self.bytes
            .get(start..end)
            .filter(|_| end <= self.payload_end)
            .ok_or_else(|| {
                Error::Invalid(
                    "binary property list scalar is truncated before the offset table".into(),
                )
            })
    }
    fn object(&mut self, idx: usize, depth: usize) -> Result<DecodedValue, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        if idx >= self.offsets.len() {
            return Err(Error::Invalid(
                "binary property list object reference is invalid".into(),
            ));
        }
        if self.decoded[idx] {
            return Ok(self.objects[idx].clone());
        }
        if self.active[idx] {
            return Ok(DecodedValue::plain(unknown(
                "reference",
                format!("object {idx}"),
                "cyclic-reference",
            )));
        }
        self.active[idx] = true;
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err(Error::Capacity);
        }
        let p = self.offsets[idx];
        if p >= self.bytes.len() - 32 {
            return Err(Error::Invalid(format!(
                "binary property list object {idx} starts at offset {p} outside the payload"
            )));
        }
        let marker = *self
            .bytes
            .get(p)
            .ok_or_else(|| Error::Invalid("binary property list object is truncated".into()))?;
        let ty = marker >> 4;
        let (len, cursor) = self.object_length(idx, p, marker)?;
        let mut typed_scalar_paths = Vec::new();
        let mut typed_uid_paths = Vec::new();
        let value = match ty {
            0x0 => match marker {
                0x00 => Value::Null,
                0x08 => Value::Bool(false),
                0x09 => Value::Bool(true),
                0x0F => {
                    return Err(Error::Invalid(
                        "binary property list fill marker cannot be referenced as an object".into(),
                    ));
                }
                _ => {
                    return Err(Error::Invalid(format!(
                        "binary property list has reserved simple marker 0x{marker:02x}"
                    )));
                }
            },
            0x8 => {
                let width = len + 1;
                if width > 16 {
                    return Err(Error::Invalid(format!(
                        "binary property list UID at object offset {p} has unsupported width {width}"
                    )));
                }
                let uid_end = cursor.checked_add(width).ok_or_else(|| {
                    Error::Invalid(format!(
                        "binary property list UID at object offset {p} range overflows usize"
                    ))
                })?;
                if uid_end > self.payload_end {
                    return Err(Error::Invalid(format!(
                        "binary property list UID at object offset {p} is truncated for width {width}"
                    )));
                }
                let value = self.uint128(cursor, width).map_err(|_| {
                    Error::Invalid(format!(
                        "binary property list UID at object offset {p} is truncated for width {width}"
                    ))
                })?;
                typed_scalar_paths.push(Vec::new());
                typed_uid_paths.push(Vec::new());
                typed_uid(value)
            }
            0x1 => {
                // The marker nibble is log2 of the byte width (bplist00).
                let width = binary_scalar_width(len);
                if !matches!(width, 1 | 2 | 4 | 8 | 16) {
                    return Err(Error::Invalid(format!(
                        "binary integer at object offset {p} has an unsupported width {width}"
                    )));
                }
                let integer_error = |error| match error {
                    Error::Invalid(reason) => {
                        Error::Invalid(format!("binary integer at object offset {p}: {reason}"))
                    }
                    other => other,
                };
                if width == 16 {
                    let end = cursor.checked_add(width).ok_or(Error::Capacity)?;
                    if end > self.payload_end {
                        return Err(integer_error(Error::Invalid(
                            "binary property list scalar is truncated before the offset table"
                                .into(),
                        )));
                    }
                    json_integer(self.uint128(cursor, width).map_err(integer_error)? as i128)
                } else {
                    let raw = self.payload_uint(cursor, width).map_err(integer_error)?;
                    binary_integer(raw, width)
                }
            }
            0x2 => {
                let len = binary_scalar_width(len);
                if len != 4 && len != 8 {
                    return Err(Error::Invalid(format!(
                        "binary real at object offset {p} has an unsupported width {len}"
                    )));
                }
                let raw = self
                    .payload_uint(cursor, len)
                    .map_err(|error| match error {
                        Error::Invalid(reason) => {
                            Error::Invalid(format!("binary real at object offset {p}: {reason}"))
                        }
                        other => other,
                    })?;
                let number = if len == 4 {
                    f32::from_bits(raw as u32) as f64
                } else {
                    f64::from_bits(raw)
                };
                if number == 0.0 && number.is_sign_negative() {
                    typed_real("-0")
                } else if number.is_nan() {
                    typed_real("nan")
                } else if number == f64::INFINITY {
                    typed_real("+infinity")
                } else if number == f64::NEG_INFINITY {
                    typed_real("-infinity")
                } else {
                    Value::Number(
                        serde_json::Number::from_f64(number)
                            .ok_or_else(|| Error::Invalid("binary real is non-finite".into()))?,
                    )
                }
            }
            0x3 => {
                let len = binary_scalar_width(len);
                if len != 8 {
                    return Err(Error::Invalid(format!(
                        "binary date at object offset {p} has an unsupported width {len}"
                    )));
                }
                let seconds =
                    f64::from_bits(self.payload_uint(cursor, len).map_err(
                        |error| match error {
                            Error::Invalid(reason) => Error::Invalid(format!(
                                "binary date at object offset {p}: {reason}"
                            )),
                            other => other,
                        },
                    )?);
                typed_date(&format_binary_date(seconds))
            }
            0x4 => {
                let raw = self
                    .payload_slice(cursor, len)
                    .map_err(|error| match error {
                        Error::Invalid(reason) => {
                            Error::Invalid(format!("binary data at object offset {p}: {reason}"))
                        }
                        other => other,
                    })?;
                typed_data(&base64_encode(raw))
            }
            0x5 | 0x7 => {
                let raw = self
                    .payload_slice(cursor, len)
                    .map_err(|error| match error {
                        Error::Invalid(reason) => {
                            Error::Invalid(format!("binary string at object offset {p}: {reason}"))
                        }
                        other => other,
                    })?;
                Value::String(String::from_utf8(raw.to_vec()).map_err(|_| {
                    Error::Invalid(format!(
                        "binary string at object offset {p} has invalid UTF-8"
                    ))
                })?)
            }
            0x6 => {
                let code_units = len.checked_mul(2).ok_or_else(|| Error::Capacity)?;
                let raw = self
                    .payload_slice(cursor, code_units)
                    .map_err(|error| match error {
                        Error::Invalid(reason) => Error::Invalid(format!(
                            "binary UTF-16 string at object offset {p}: {reason}"
                        )),
                        other => other,
                    })?;
                let units = raw
                    .chunks_exact(2)
                    .map(|x| u16::from_be_bytes([x[0], x[1]]))
                    .collect::<Vec<_>>();
                utf16_value(&units)
            }
            0xA | 0xB | 0xC | 0xE => {
                let mut a = Vec::new();
                let references_end = cursor
                    .checked_add(
                        len.checked_mul(self.ref_size)
                            .ok_or_else(|| Error::Capacity)?,
                    )
                    .ok_or_else(|| {
                        Error::Invalid("binary array reference range overflows usize".into())
                    })?;
                if references_end > self.payload_end {
                    return Err(Error::Invalid(format!(
                        "binary collection marker 0x{marker:02x} at offset {p} collection references [{cursor}, {references_end}) exceed payload boundary"
                    )));
                }
                for i in 0..len {
                    let reference_offset = cursor + i * self.ref_size;
                    let r = usize::try_from(self.uint(reference_offset, self.ref_size)?).map_err(
                        |_| Error::Invalid("binary array reference overflows usize".into()),
                    )?;
                    let child = self.object(r, depth + 1).map_err(|error| match error {
                        Error::Invalid(reason) => Error::Invalid(format!(
                            "binary collection marker 0x{marker:02x} at offset {p} reference {i}: {reason}"
                        )),
                        other => other,
                    })?;
                    typed_scalar_paths.extend(prepend_path_segment(
                        ValuePathSegment::Index(i),
                        child.typed_scalar_paths.clone(),
                    ));
                    typed_uid_paths.extend(prepend_path_segment(
                        ValuePathSegment::Index(i),
                        child.typed_uid_paths,
                    ));
                    a.push(child.value);
                }
                Value::Array(a)
            }
            0xD => {
                let mut m = Map::new();
                let mut typed_scalar_paths_by_key = std::collections::BTreeMap::new();
                let mut typed_uid_paths_by_key = std::collections::BTreeMap::new();
                let key_bytes = len
                    .checked_mul(self.ref_size)
                    .ok_or_else(|| Error::Capacity)?;
                let value_start = cursor.checked_add(key_bytes).ok_or_else(|| {
                    Error::Invalid("binary dictionary value range overflows usize".into())
                })?;
                let values_end = value_start.checked_add(key_bytes).ok_or_else(|| {
                    Error::Invalid("binary dictionary range overflows usize".into())
                })?;
                if values_end > self.payload_end {
                    return Err(Error::Invalid(format!(
                        "binary dictionary marker 0x{marker:02x} at offset {p} dictionary references [{cursor}, {values_end}) exceed payload boundary"
                    )));
                }
                for i in 0..len {
                    let key_offset = cursor + i * self.ref_size;
                    let value_offset = value_start + i * self.ref_size;
                    let k =
                        usize::try_from(self.uint(key_offset, self.ref_size)?).map_err(|_| {
                            Error::Invalid("binary dictionary key reference overflows usize".into())
                        })?;
                    let v =
                        usize::try_from(self.uint(value_offset, self.ref_size)?).map_err(|_| {
                            Error::Invalid(
                                "binary dictionary value reference overflows usize".into(),
                            )
                        })?;
                    let key_value = self.object(k, depth + 1).map_err(|error| match error {
                        Error::Invalid(reason) => Error::Invalid(format!(
                            "binary dictionary marker 0x{marker:02x} at offset {p} key reference {i}: {reason}"
                        )),
                        other => other,
                    })?;
                    let key = binary_key(key_value.value).map_err(|error| match error {
                        Error::Invalid(reason) => Error::Invalid(format!(
                            "binary dictionary marker 0x{marker:02x} at offset {p} key reference {i}: {reason}"
                        )),
                        other => other,
                    })?;
                    let child = self.object(v, depth + 1).map_err(|error| match error {
                        Error::Invalid(reason) => Error::Invalid(format!(
                            "binary dictionary marker 0x{marker:02x} at offset {p} value reference {i}: {reason}"
                        )),
                        other => other,
                    })?;
                    let child_scalar_paths = prepend_path_segment(
                        ValuePathSegment::Key(key.clone()),
                        child.typed_scalar_paths.clone(),
                    );
                    if child_scalar_paths.is_empty() {
                        typed_scalar_paths_by_key.remove(&key);
                    } else {
                        typed_scalar_paths_by_key.insert(key.clone(), child_scalar_paths);
                    }

                    let child_uid_paths = prepend_path_segment(
                        ValuePathSegment::Key(key.clone()),
                        child.typed_uid_paths,
                    );
                    if child_uid_paths.is_empty() {
                        typed_uid_paths_by_key.remove(&key);
                    } else {
                        typed_uid_paths_by_key.insert(key.clone(), child_uid_paths);
                    }
                    m.insert(key, child.value);
                }
                typed_scalar_paths.extend(typed_scalar_paths_by_key.into_values().flatten());
                typed_uid_paths.extend(typed_uid_paths_by_key.into_values().flatten());
                Value::Object(m)
            }
            _ => {
                return Err(Error::Invalid(
                    "unsupported binary property-list type".into(),
                ));
            }
        };
        self.active[idx] = false;
        self.decoded[idx] = true;
        let type_marker = value
            .as_object()
            .and_then(|fields| fields.get("$plist_type"))
            .and_then(Value::as_str);
        let is_generated_scalar_wrapper =
            matches!(ty, 0x1 | 0x2 | 0x3 | 0x4 | 0x6 | 0x8) && type_marker.is_some();
        if is_generated_scalar_wrapper && typed_scalar_paths.is_empty() {
            typed_scalar_paths.push(Vec::new());
        }

        let decoded = DecodedValue {
            value,
            typed_scalar_paths,
            typed_uid_paths,
        };
        self.objects[idx] = decoded.clone();
        Ok(decoded)
    }

    fn object_length(
        &self,
        idx: usize,
        object_offset: usize,
        marker: u8,
    ) -> Result<(usize, usize), Error> {
        let marker_end = object_offset.checked_add(1).ok_or_else(|| {
            Error::Invalid(format!(
                "binary property list object {idx} offset overflows usize"
            ))
        })?;
        let inline_length = (marker & 15) as usize;
        let object_type = marker >> 4;
        if inline_length != 15 || matches!(object_type, 0x0 | 0x8) {
            return Ok((inline_length, marker_end));
        }

        let length_marker = self.payload_uint(marker_end, 1)? as u8;
        if length_marker >> 4 != 0x1 {
            return Err(Error::Invalid(format!(
                "binary property list object {idx} extended length at offset {marker_end} is not an integer"
            )));
        }
        let width_power = length_marker & 15;
        if width_power > 3 {
            return Err(Error::Invalid(format!(
                "binary property list object {idx} extended length at offset {marker_end} has unsupported width"
            )));
        }
        let width = 1usize << width_power;
        let length_start = marker_end.checked_add(1).ok_or_else(|| {
            Error::Invalid(format!(
                "binary property list object {idx} length offset overflows usize"
            ))
        })?;
        let raw_length = self.payload_uint(length_start, width)?;
        let length = usize::try_from(raw_length).map_err(|_| Error::Capacity)?;
        let payload_start = length_start.checked_add(width).ok_or_else(|| {
            Error::Invalid(format!(
                "binary property list object {idx} payload offset overflows usize"
            ))
        })?;
        Ok((length, payload_start))
    }
}
