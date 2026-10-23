//! Bounded, read-only decoding of Apple's serialized NIBArchive format.
//!
//! The parser retains archive indices and serialized references. It never loads
//! or instantiates Interface Builder classes.

use serde::Serialize;
use serde_json::{Map, Value};
use std::fmt;

const HEADER_SIZE: usize = 50;
const DEFAULT_BUDGET_BYTES: usize = 128 * 1024 * 1024;
const MAX_CLASS_EXTENSIONS: u32 = 16;
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NibArchiveError {
    Malformed(String),
    Limit { code: &'static str, message: String },
}

impl fmt::Display for NibArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(message) => f.write_str(message),
            Self::Limit { message, .. } => f.write_str(message),
        }
    }
}

impl std::error::Error for NibArchiveError {}

#[derive(Debug, Clone, Copy)]
pub struct DecodeBudget {
    limit: usize,
    used: usize,
}

impl DecodeBudget {
    pub const fn new(limit: usize) -> Self {
        Self { limit, used: 0 }
    }

    fn reserve(&mut self, amount: usize, message: &'static str) -> Result<(), NibArchiveError> {
        let next = self
            .used
            .checked_add(amount)
            .ok_or_else(|| limit_error(message))?;
        if next > self.limit {
            return Err(limit_error(message));
        }
        self.used = next;
        Ok(())
    }
}

impl Default for DecodeBudget {
    fn default() -> Self {
        Self::new(DEFAULT_BUDGET_BYTES)
    }
}

fn limit_error(message: &'static str) -> NibArchiveError {
    NibArchiveError::Limit {
        code: "aggregate_decode_budget_exhausted",
        message: message.to_owned(),
    }
}

#[derive(Debug, Serialize)]
pub struct NibArchiveDocument {
    pub format_version: u32,
    pub coder_version: u32,
    pub object_count: u32,
    pub connection_object_count: u32,
    pub objects: Vec<NibObject>,
    pub classes: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct NibObject {
    pub id: u32,
    pub class_name: String,
    pub values: Map<String, Value>,
}

pub fn decode_nib_archive(bytes: &[u8]) -> Result<NibArchiveDocument, NibArchiveError> {
    decode_nib_archive_with_budget(bytes, DecodeBudget::default())
}

pub fn decode_nib_archive_with_budget(
    bytes: &[u8],
    mut budget: DecodeBudget,
) -> Result<NibArchiveDocument, NibArchiveError> {
    if bytes.len() < HEADER_SIZE || &bytes[..10] != b"NIBArchive" {
        return Err(malformed("NIBArchive magic or header is invalid"));
    }

    let format_version = read_u32(bytes, 10, "header")?;
    let coder_version = read_u32(bytes, 14, "header")?;
    if format_version != 1 {
        return Err(malformed(format!(
            "Unsupported NIBArchive format version {format_version}"
        )));
    }

    let object_count = read_count(bytes, 18, "object")?;
    let objects_offset = read_offset(bytes, 22, "object")?;
    let key_count = read_count(bytes, 26, "key")?;
    let keys_offset = read_offset(bytes, 30, "key")?;
    let value_count = read_count(bytes, 34, "value")?;
    let values_offset = read_offset(bytes, 38, "value")?;
    let class_count = read_count(bytes, 42, "class")?;
    let classes_offset = read_offset(bytes, 46, "class")?;
    assert_ordered_offsets(
        bytes.len(),
        [objects_offset, keys_offset, values_offset, classes_offset],
    )?;

    let object_records = parse_objects(
        bytes,
        objects_offset,
        keys_offset,
        object_count,
        value_count,
        class_count,
        &mut budget,
    )?;
    let keys = parse_strings(
        bytes,
        keys_offset,
        values_offset,
        key_count,
        "key",
        &mut budget,
    )?;
    let classes = parse_classes(bytes, classes_offset, bytes.len(), class_count, &mut budget)?;
    let needed = value_indexes(&object_records, value_count)?;
    let values = parse_values(
        bytes,
        values_offset,
        classes_offset,
        value_count,
        key_count,
        &needed,
        object_count,
        &mut budget,
    )?;

    let mut objects = Vec::with_capacity(object_records.len());
    let mut connection_object_count = 0;
    for (id, record) in object_records.iter().enumerate() {
        let class_name = classes
            .get(record.class_index as usize)
            .ok_or_else(|| malformed("NIBArchive object class index is invalid"))?
            .clone();
        if is_connection_class(&class_name) {
            connection_object_count += 1;
        }
        let mut fields = Map::new();
        for index in record.value_start..record.value_start + record.value_count {
            let Some(value) = values.get(&(index as usize)) else {
                continue;
            };
            let Some(key) = keys.get(value.key_index as usize) else {
                continue;
            };
            fields.insert(key.clone(), value.value.clone());
        }
        objects.push(NibObject {
            id: id as u32,
            class_name,
            values: fields,
        });
    }

    Ok(NibArchiveDocument {
        format_version,
        coder_version,
        object_count,
        connection_object_count,
        objects,
        classes,
        limitations: vec![
            "NIBArchive class extensions and unsupported value encodings are retained as unavailable fields.".to_owned(),
            "NIBArchive object relationships are decoded from serialized references; runtime object creation and execution are not performed.".to_owned(),
        ],
    })
}

#[derive(Debug)]
struct ObjectRecord {
    class_index: u32,
    value_start: u32,
    value_count: u32,
}

#[derive(Debug)]
struct ValueRecord {
    key_index: u32,
    value: Value,
}

fn parse_objects(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: u32,
    value_count: u32,
    class_count: u32,
    budget: &mut DecodeBudget,
) -> Result<Vec<ObjectRecord>, NibArchiveError> {
    budget.reserve(
        (count as usize).checked_mul(96).ok_or_else(|| {
            limit_error(
                "NIBArchive object count exceeds the aggregate Interface Builder decode budget",
            )
        })?,
        "NIBArchive object count exceeds the aggregate Interface Builder decode budget",
    )?;
    let mut cursor = Cursor::new(start);
    let mut records = Vec::with_capacity(count as usize);
    for index in 0..count {
        let class_index = cursor.varint(bytes, end)?;
        let value_start = cursor.varint(bytes, end)?;
        let value_count_for_object = cursor.varint(bytes, end)?;
        if class_index >= class_count
            || value_start > value_count
            || value_count_for_object > value_count - value_start
        {
            return Err(malformed(format!(
                "NIBArchive object {index} references an invalid table range"
            )));
        }
        records.push(ObjectRecord {
            class_index,
            value_start,
            value_count: value_count_for_object,
        });
    }
    Ok(records)
}

fn parse_strings(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: u32,
    label: &str,
    budget: &mut DecodeBudget,
) -> Result<Vec<String>, NibArchiveError> {
    let mut cursor = Cursor::new(start);
    let mut output = Vec::with_capacity(count as usize);
    for index in 0..count {
        let length = cursor.varint(bytes, end)? as usize;
        let next = cursor.checked_end(length, end, &format!("{label} {index}"))?;
        budget.reserve(
            32 + length.saturating_mul(2),
            "NIBArchive strings exceed the aggregate Interface Builder decode budget",
        )?;
        output.push(decode_utf8(
            &bytes[cursor.offset..next],
            &format!("{label} {index}"),
        )?);
        cursor.offset = next;
    }
    Ok(output)
}

fn parse_classes(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: u32,
    budget: &mut DecodeBudget,
) -> Result<Vec<String>, NibArchiveError> {
    let mut cursor = Cursor::new(start);
    let mut output = Vec::with_capacity(count as usize);
    for index in 0..count {
        let length = cursor.varint(bytes, end)? as usize;
        let extensions = cursor.varint(bytes, end)?;
        if extensions > MAX_CLASS_EXTENSIONS {
            return Err(malformed(format!(
                "NIBArchive class {index} has too many extension values"
            )));
        }
        cursor.checked_end(
            (extensions as usize) * 4,
            end,
            &format!("class {index} extensions"),
        )?;
        cursor.offset += (extensions as usize) * 4;
        let next = cursor.checked_end(length, end, &format!("class {index}"))?;
        budget.reserve(
            32 + length.saturating_mul(2),
            "NIBArchive class names exceed the aggregate Interface Builder decode budget",
        )?;
        let mut name =
            decode_utf8(&bytes[cursor.offset..next], &format!("class {index}"))?.to_owned();
        while name.ends_with('\0') {
            name.pop();
        }
        output.push(name);
        cursor.offset = next;
    }
    Ok(output)
}

fn parse_values(
    bytes: &[u8],
    start: usize,
    end: usize,
    count: u32,
    key_count: u32,
    needed: &std::collections::BTreeSet<usize>,
    object_count: u32,
    budget: &mut DecodeBudget,
) -> Result<std::collections::BTreeMap<usize, ValueRecord>, NibArchiveError> {
    let mut cursor = Cursor::new(start);
    let mut output = std::collections::BTreeMap::new();
    for index in 0..count as usize {
        let key_index = cursor.varint(bytes, end)?;
        if key_index >= key_count {
            return Err(malformed(format!(
                "NIBArchive value {index} references an invalid key"
            )));
        }
        let ty = cursor.byte(bytes, end)?;
        let value = if needed.contains(&index) {
            budget.reserve(
                64,
                "NIBArchive decoded values exceed the aggregate Interface Builder decode budget",
            )?;
            read_value(bytes, &mut cursor, end, ty, index, object_count, budget)?
        } else {
            skip_value(bytes, &mut cursor, end, ty, index)?;
            continue;
        };
        output.insert(index, ValueRecord { key_index, value });
    }
    Ok(output)
}

fn read_value(
    bytes: &[u8],
    cursor: &mut Cursor,
    end: usize,
    ty: u8,
    index: usize,
    object_count: u32,
    budget: &mut DecodeBudget,
) -> Result<Value, NibArchiveError> {
    match ty {
        0 => Ok(Value::from(cursor.take_i8(bytes, end, index)?)),
        1 => Ok(Value::from(cursor.take_i16(bytes, end, index)?)),
        2 => Ok(Value::from(cursor.take_i32(bytes, end, index)?)),
        3 => {
            let value = cursor.take_i64(bytes, end, index)?;
            if value.unsigned_abs() <= 9_007_199_254_740_991 {
                Ok(Value::from(value))
            } else {
                Ok(Value::from(value.to_string()))
            }
        }
        4 => Ok(Value::Bool(true)),
        5 => Ok(Value::Bool(false)),
        6 => Ok(finite_number(cursor.take_f32(bytes, end, index)? as f64)),
        7 => Ok(finite_number(cursor.take_f64(bytes, end, index)?)),
        8 => {
            let length = cursor.varint(bytes, end)? as usize;
            let next = cursor.checked_end(length, end, &format!("value {index} data"))?;
            budget.reserve(
                32 + (length / 3 + 1) * 4,
                "NIBArchive data values exceed the aggregate Interface Builder decode budget",
            )?;
            let mut map = Map::new();
            map.insert(
                "$nib_data_base64".to_owned(),
                Value::String(encode_base64(&bytes[cursor.offset..next])),
            );
            cursor.offset = next;
            Ok(Value::Object(map))
        }
        9 => Ok(Value::Null),
        10 => {
            let reference = cursor.take_u32(bytes, end, index)?;
            if reference >= object_count {
                return Err(malformed(
                    "NIBArchive object reference is outside the object table",
                ));
            }
            let mut map = Map::new();
            map.insert("$nib_object_ref".to_owned(), Value::from(reference));
            Ok(Value::Object(map))
        }
        _ => Err(malformed(format!(
            "NIBArchive value {index} has unsupported type {ty}"
        ))),
    }
}

fn skip_value(
    bytes: &[u8],
    cursor: &mut Cursor,
    end: usize,
    ty: u8,
    index: usize,
) -> Result<(), NibArchiveError> {
    let size = match ty {
        0 => 1,
        1 => 2,
        2 | 6 | 10 => 4,
        3 | 7 => 8,
        4 | 5 | 9 => 0,
        8 => {
            let length = cursor.varint(bytes, end)? as usize;
            cursor.checked_end(length, end, &format!("value {index} data"))? - cursor.offset
        }
        _ => {
            return Err(malformed(format!(
                "NIBArchive value {index} has unsupported type {ty}"
            )));
        }
    };
    cursor.checked_end(size, end, &format!("value {index}"))?;
    cursor.offset += size;
    Ok(())
}

fn value_indexes(
    records: &[ObjectRecord],
    total: u32,
) -> Result<std::collections::BTreeSet<usize>, NibArchiveError> {
    let mut result = std::collections::BTreeSet::new();
    for record in records {
        for index in record.value_start..record.value_start + record.value_count {
            result.insert(index as usize);
        }
    }
    if result.iter().any(|index| *index >= total as usize) {
        return Err(malformed(
            "NIBArchive object value ranges exceed the value table",
        ));
    }
    Ok(result)
}

fn is_connection_class(name: &str) -> bool {
    ["Outlet", "Connection", "Segue", "ActionConnection"]
        .iter()
        .any(|part| {
            name.to_ascii_lowercase()
                .contains(&part.to_ascii_lowercase())
        })
}
/// Archived floats are JSON numbers: an integral value is the same number as
/// the integer and serializes without a fractional part (`-0` becomes `0`).
/// Project a decoded real as JavaScript `JSON.stringify` would emit it:
/// integral values as integers, non-finite values as `null`.
pub fn finite_number(value: f64) -> Value {
    const EXACT_I64: f64 = 9_223_372_036_854_775_808.0;
    if value.is_finite() && value.fract() == 0.0 && value.abs() < EXACT_I64 {
        Value::from(value as i64)
    } else if value.is_finite() {
        Value::from(value)
    } else {
        Value::Null
    }
}
fn decode_utf8(bytes: &[u8], label: &str) -> Result<String, NibArchiveError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| malformed(format!("NIBArchive {label} is not valid UTF-8")))
}
fn malformed(message: impl Into<String>) -> NibArchiveError {
    NibArchiveError::Malformed(message.into())
}
fn read_count(bytes: &[u8], offset: usize, label: &str) -> Result<u32, NibArchiveError> {
    let value = read_u32(bytes, offset, "header")?;
    if value as usize > bytes.len() {
        return Err(malformed(format!(
            "NIBArchive {label} count exceeds the archive length"
        )));
    }
    Ok(value)
}
fn read_offset(bytes: &[u8], offset: usize, label: &str) -> Result<usize, NibArchiveError> {
    let value = read_u32(bytes, offset, "header")? as usize;
    if !(HEADER_SIZE..=bytes.len()).contains(&value) {
        return Err(malformed(format!(
            "NIBArchive {label} table offset is invalid"
        )));
    }
    Ok(value)
}
fn read_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, NibArchiveError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| malformed(format!("NIBArchive {label} is truncated")))?;
    let array = <[u8; 4]>::try_from(slice)
        .map_err(|_| malformed(format!("NIBArchive {label} is truncated")))?;
    Ok(u32::from_le_bytes(array))
}
fn assert_ordered_offsets(length: usize, offsets: [usize; 4]) -> Result<(), NibArchiveError> {
    let mut previous = HEADER_SIZE;
    for offset in offsets {
        if offset < previous || offset > length {
            return Err(malformed("NIBArchive table offsets are out of order"));
        }
        previous = offset;
    }
    Ok(())
}

struct Cursor {
    offset: usize,
}
impl Cursor {
    fn new(offset: usize) -> Self {
        Self { offset }
    }
    fn byte(&mut self, bytes: &[u8], end: usize) -> Result<u8, NibArchiveError> {
        let byte = *bytes
            .get(self.offset)
            .ok_or_else(|| malformed("NIBArchive value table is truncated"))?;
        if self.offset >= end {
            return Err(malformed("NIBArchive value table overlaps the next table"));
        }
        self.offset += 1;
        Ok(byte)
    }
    fn varint(&mut self, bytes: &[u8], end: usize) -> Result<u32, NibArchiveError> {
        let mut value = 0u32;
        for shift in (0..35).step_by(7) {
            let byte = self.byte(bytes, end)?;
            if shift == 28 && byte & 0x7f > 0x07 {
                return Err(malformed("NIBArchive variable integer is out of range"));
            }
            value |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 != 0 {
                return Ok(value);
            }
        }
        Err(malformed("NIBArchive variable integer is too long"))
    }
    fn checked_end(
        &self,
        length: usize,
        end: usize,
        label: &str,
    ) -> Result<usize, NibArchiveError> {
        self.offset
            .checked_add(length)
            .filter(|next| *next <= end)
            .ok_or_else(|| malformed(format!("NIBArchive {label} exceeds its table")))
    }
    fn take<const N: usize>(
        &mut self,
        bytes: &[u8],
        end: usize,
        label: usize,
    ) -> Result<[u8; N], NibArchiveError> {
        let next = self.checked_end(N, end, &format!("value {label}"))?;
        let result = bytes
            .get(self.offset..next)
            .and_then(|slice| slice.try_into().ok())
            .ok_or_else(|| malformed(format!("NIBArchive value {label} is truncated")))?;
        self.offset = next;
        Ok(result)
    }
    fn take_i8(&mut self, b: &[u8], e: usize, i: usize) -> Result<i8, NibArchiveError> {
        Ok(i8::from_le_bytes(self.take(b, e, i)?))
    }
    fn take_i16(&mut self, b: &[u8], e: usize, i: usize) -> Result<i16, NibArchiveError> {
        Ok(i16::from_le_bytes(self.take(b, e, i)?))
    }
    fn take_i32(&mut self, b: &[u8], e: usize, i: usize) -> Result<i32, NibArchiveError> {
        Ok(i32::from_le_bytes(self.take(b, e, i)?))
    }
    fn take_i64(&mut self, b: &[u8], e: usize, i: usize) -> Result<i64, NibArchiveError> {
        Ok(i64::from_le_bytes(self.take(b, e, i)?))
    }
    fn take_u32(&mut self, b: &[u8], e: usize, i: usize) -> Result<u32, NibArchiveError> {
        Ok(u32::from_le_bytes(self.take(b, e, i)?))
    }
    fn take_f32(&mut self, b: &[u8], e: usize, i: usize) -> Result<f32, NibArchiveError> {
        Ok(f32::from_le_bytes(self.take(b, e, i)?))
    }
    fn take_f64(&mut self, b: &[u8], e: usize, i: usize) -> Result<f64, NibArchiveError> {
        Ok(f64::from_le_bytes(self.take(b, e, i)?))
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_objects_keys_values_and_classes() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[..10].copy_from_slice(b"NIBArchive");
        put_u32(&mut bytes, 10, 1);
        put_u32(&mut bytes, 14, 7);
        put_u32(&mut bytes, 18, 1);
        put_u32(&mut bytes, 22, 50);
        put_u32(&mut bytes, 26, 1);
        put_u32(&mut bytes, 30, 53);
        put_u32(&mut bytes, 34, 1);
        put_u32(&mut bytes, 38, 59);
        put_u32(&mut bytes, 42, 1);
        put_u32(&mut bytes, 46, 65);
        bytes.extend_from_slice(&[0x80, 0x80, 0x81]);
        bytes.extend_from_slice(&[0x85, b't', b'i', b't', b'l', b'e']);
        bytes.extend_from_slice(&[0x80, 8, 0x83, b'a', b'b', b'c']);
        bytes.extend_from_slice(&[0x86, 0x80, b'O', b'u', b't', b'l', b'e', b't']);

        let document = decode_nib_archive(&bytes).expect("fixture should decode");
        assert_eq!(document.object_count, 1);
        assert_eq!(document.connection_object_count, 1);
        assert_eq!(document.objects[0].class_name, "Outlet");
        assert_eq!(
            document.objects[0].values["title"]["$nib_data_base64"],
            Value::from("YWJj")
        );
    }

    #[test]
    fn rejects_invalid_utf8_as_malformed() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[..10].copy_from_slice(b"NIBArchive");
        put_u32(&mut bytes, 10, 1);
        put_u32(&mut bytes, 22, 50);
        put_u32(&mut bytes, 30, 50);
        put_u32(&mut bytes, 38, 50);
        put_u32(&mut bytes, 42, 1);
        put_u32(&mut bytes, 46, 50);
        bytes.extend_from_slice(&[0x81, 0x80, 0xff]);
        assert!(matches!(
            decode_nib_archive(&bytes),
            Err(NibArchiveError::Malformed(_))
        ));
    }

    #[test]
    fn distinguishes_budget_exhaustion() {
        let mut bytes = vec![0u8; HEADER_SIZE];
        bytes[..10].copy_from_slice(b"NIBArchive");
        put_u32(&mut bytes, 10, 1);
        put_u32(&mut bytes, 18, 1);
        put_u32(&mut bytes, 22, 50);
        put_u32(&mut bytes, 30, 53);
        put_u32(&mut bytes, 38, 53);
        put_u32(&mut bytes, 46, 53);
        bytes.extend_from_slice(&[0, 0, 0]);
        assert!(matches!(
            decode_nib_archive_with_budget(&bytes, DecodeBudget::new(1)),
            Err(NibArchiveError::Limit { .. })
        ));
    }

    fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
