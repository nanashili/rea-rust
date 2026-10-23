//! Bounded projection of IL2CPP string-literal rows and their data section.
//!
//! The metadata reader owns the binary metadata layout.  This module joins
//! already decoded rows with caller-supplied bytes, retaining every row even
//! when its span is malformed or its bytes are not UTF-8.

use base64::Engine;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "project_il2cpp_string_literals";
const MAX_ROWS: usize = 200_000;
const MAX_DATA_BYTES: usize = 256 * 1024 * 1024;

/// Project literal rows against a caller-supplied data section.
///
/// Rows may be supplied as `literals`, `string_literals`, or under a
/// `metadata` object. Data may be `data_base64`, `literal_data_base64`, or a
/// `binary` object's `data_base64`. A row's `data_index`/`offset` and
/// `length`/`byte_length` identify a byte span; decimal and hexadecimal text
/// spellings are accepted without replacing the original source values.
/// Every input row is represented in the output, including duplicate and
/// invalid spans.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let rows = find_rows(metadata)
        .ok_or_else(|| invalid("literals", "Supply an array of IL2CPP string-literal rows"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid("literals", "Literal row limit exceeded"));
    }

    let bytes = decode_data(root, metadata, binary)?;
    let mut items = Vec::with_capacity(rows.len());
    let mut valid = 0usize;
    let mut malformed = 0usize;
    let mut invalid_utf8 = 0usize;
    let mut invalid_encoding = 0usize;
    let mut unsupported_encoding = 0usize;
    let mut invalid_spans = 0usize;
    let mut incomplete_bytes = 0usize;
    let mut spans = Vec::new();

    for (row_index, row) in rows.iter().enumerate() {
        let mut item = Map::new();
        item.insert("row_index".into(), Value::from(row_index));
        item.insert("row".into(), row.clone());

        let outcome = match literal_span(row) {
            Ok((offset, length)) => match checked_span(offset, length, bytes.len()) {
                Ok(end) => {
                    spans.push((row_index, offset, end));
                    let slice = &bytes[offset..end];
                    let encoded = base64::engine::general_purpose::STANDARD.encode(slice);
                    let mut literal = Map::new();
                    literal.insert("offset".into(), Value::from(offset));
                    literal.insert("length".into(), Value::from(length));
                    literal.insert("end".into(), Value::from(end));
                    literal.insert("bytes_base64".into(), Value::from(encoded));
                    match requested_decoding(row) {
                        DecodingRequest::Utf8 => {
                            literal.insert("decoding".into(), Value::from("utf8"));
                            match std::str::from_utf8(slice) {
                                Ok(text) => {
                                    valid += 1;
                                    literal.insert("utf8".into(), Value::from(text));
                                }
                                Err(error) => {
                                    invalid_utf8 += 1;
                                    literal.insert("decoding".into(), Value::from("invalid_utf8"));
                                    literal.insert("utf8".into(), Value::Null);
                                    literal.insert(
                                        "utf8_error".into(),
                                        json!({
                                            "valid_up_to": error.valid_up_to(),
                                            "error_len": error.error_len(),
                                        }),
                                    );
                                }
                            }
                        }
                        DecodingRequest::Invalid(reason) => {
                            invalid_encoding += 1;
                            literal.insert("decoding".into(), Value::from("invalid_encoding"));
                            literal.insert("encoding_error".into(), Value::from(reason));
                            literal.insert("utf8".into(), Value::Null);
                        }
                        DecodingRequest::Unsupported(encoding) => {
                            unsupported_encoding += 1;
                            // The decoder cannot establish an encoding outside
                            // UTF-8. Preserve that uncertainty as `unknown`;
                            // an unsupported label is not proof of malformed
                            // bytes and is the public contract's unavailable
                            // state.
                            literal.insert("decoding".into(), Value::from("unknown"));
                            literal.insert("requested_encoding".into(), Value::from(encoding));
                            literal.insert("utf8".into(), Value::Null);
                        }
                    }
                    Value::Object(literal)
                }
                Err(reason) => {
                    malformed += 1;
                    invalid_spans += 1;
                    if reason == "literal span exceeds supplied data" {
                        incomplete_bytes += 1;
                    }
                    let mut malformed_literal = Map::new();
                    malformed_literal.insert("decoding".into(), Value::from("malformed_span"));
                    malformed_literal.insert("error".into(), Value::from(reason));
                    malformed_literal.insert("offset".into(), Value::from(offset));
                    malformed_literal.insert("length".into(), Value::from(length));
                    Value::Object(malformed_literal)
                }
            },
            Err(reason) => {
                malformed += 1;
                invalid_spans += 1;
                let mut malformed_literal = Map::new();
                malformed_literal.insert("decoding".into(), Value::from("malformed_row"));
                malformed_literal.insert("error".into(), Value::from(reason));
                Value::Object(malformed_literal)
            }
        };
        if let Some(identity) = literal_identity(row, row_index) {
            item.insert("identity".into(), identity);
        }
        item.insert("literal".into(), outcome);
        items.push(Value::Object(item));
    }

    let diagnostics = span_diagnostics(&spans);
    Ok(json!({
        // A row whose bytes are intact but whose requested encoding cannot be
        // established is still represented below. It does, however, leave
        // the projection incomplete in the same way as a malformed span.
        "status": if malformed == 0 && invalid_encoding == 0 && unsupported_encoding == 0 {
            "complete"
        } else {
            "partial"
        },
        "items": items,
        "coverage": {
            "rows": rows.len(),
            "valid_utf8": valid,
            "invalid_utf8": invalid_utf8,
            "invalid_encoding": invalid_encoding,
            "unsupported_encoding": unsupported_encoding,
            "malformed": malformed,
            "invalid_spans": invalid_spans,
            "incomplete_bytes": incomplete_bytes,
            "data_bytes": bytes.len(),
        },
        "diagnostics": diagnostics,
    }))
}

pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn find_rows<'a>(object: &'a Map<String, Value>) -> Option<&'a [Value]> {
    [
        "literals",
        "string_literals",
        "string_literal_rows",
        "stringLiteralRows",
        "stringLiterals",
    ]
    .iter()
    .find_map(|name| {
        object
            .get(*name)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    })
}

fn decode_data(
    root: &Map<String, Value>,
    metadata: &Map<String, Value>,
    binary: &Map<String, Value>,
) -> Result<Vec<u8>, Failure> {
    let aliases = [
        "data_base64",
        "literal_data_base64",
        "string_literal_data_base64",
        "stringLiteralDataBase64",
        "bytes_base64",
    ];
    let sources = [root, metadata, binary];
    let mut decoded: Option<Vec<u8>> = None;

    for source in sources {
        for alias in aliases {
            let Some(value) = source.get(alias) else {
                continue;
            };
            let encoded = value
                .as_str()
                .ok_or_else(|| invalid(alias, "Literal data must be a base64 string"))?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .map_err(|_| invalid(alias, "Literal data is not valid base64"))?;
            if bytes.len() > MAX_DATA_BYTES {
                return Err(invalid(alias, "Literal data exceeds the size limit"));
            }

            if let Some(existing) = decoded.as_ref() {
                if existing != &bytes {
                    return Err(invalid("data_base64", "Literal data aliases disagree"));
                }
            } else {
                decoded = Some(bytes);
            }
        }
    }

    decoded.ok_or_else(|| invalid("data_base64", "Literal data bytes are required"))
}

fn literal_span(row: &Value) -> Result<(usize, usize), &'static str> {
    let object = row.as_object().ok_or("row must be an object")?;
    let offset = consistent_u64(object, &["data_index", "dataIndex", "offset", "start"])
        .ok_or("row is missing a non-negative data_index")?;
    let length = consistent_u64(object, &["byte_length", "byteLength", "length"])
        .ok_or("row is missing a non-negative length")?;
    let offset = usize::try_from(offset).map_err(|_| "data_index exceeds platform bounds")?;
    let length = usize::try_from(length).map_err(|_| "length exceeds platform bounds")?;
    Ok((offset, length))
}

fn consistent_u64(object: &Map<String, Value>, names: &[&str]) -> Option<u64> {
    let mut value = None;
    for name in names {
        let Some(candidate) = object.get(*name).and_then(parse_u64) else {
            continue;
        };
        if value.is_some_and(|existing| existing != candidate) {
            return None;
        }
        value = Some(candidate);
    }
    value
}

/// Parse the numeric spellings emitted by metadata readers while retaining
/// each row's original value through `source_offset` and `source_length`.
fn parse_u64(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse::<u64>().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

enum DecodingRequest {
    Utf8,
    Unsupported(String),
    Invalid(String),
}

fn selected_encoding(row: &Value) -> Option<&Value> {
    let object = row.as_object()?;
    match (object.get("decoding"), object.get("encoding")) {
        (Some(decoding), Some(encoding)) if !encoding_aliases_agree(decoding, encoding) => None,
        (Some(decoding), _) => Some(decoding),
        (_, Some(encoding)) => Some(encoding),
        (None, None) => None,
    }
}

fn encoding_aliases_agree(left: &Value, right: &Value) -> bool {
    let Some(left) = left.as_str().map(str::trim) else {
        return false;
    };
    let Some(right) = right.as_str().map(str::trim) else {
        return false;
    };
    left.eq_ignore_ascii_case(right) || (is_utf8_label(left) && is_utf8_label(right))
}

fn is_utf8_label(value: &str) -> bool {
    value.eq_ignore_ascii_case("utf8") || value.eq_ignore_ascii_case("utf-8")
}

fn requested_decoding(row: &Value) -> DecodingRequest {
    let Some(object) = row.as_object() else {
        return DecodingRequest::Utf8;
    };
    if let (Some(decoding), Some(encoding)) = (object.get("decoding"), object.get("encoding")) {
        if !encoding_aliases_agree(decoding, encoding) {
            return DecodingRequest::Invalid("decoding and encoding aliases disagree".into());
        }
    }
    let Some(value) = selected_encoding(row) else {
        return DecodingRequest::Utf8;
    };

    let Some(encoding) = value.as_str() else {
        return DecodingRequest::Invalid("encoding must be a string".into());
    };
    let encoding = encoding.trim();
    if encoding.is_empty() {
        return DecodingRequest::Invalid("encoding must not be empty".into());
    }
    if encoding.eq_ignore_ascii_case("utf8") || encoding.eq_ignore_ascii_case("utf-8") {
        DecodingRequest::Utf8
    } else {
        DecodingRequest::Unsupported(encoding.to_owned())
    }
}

fn literal_identity(row: &Value, row_index: usize) -> Option<Value> {
    let object = row.as_object()?;
    let source_index = match metadata_index(object) {
        Some(index) => Value::from(index),
        None if has_metadata_index_alias(object) => return None,
        None => Value::from(row_index),
    };
    let mut identity = Map::new();
    identity.insert("kind".into(), Value::from("il2cpp_string_literal"));
    identity.insert("index".into(), source_index);
    if let Some(token) = consistent_token(object) {
        identity.insert("token".into(), token.clone());
    }
    Some(Value::Object(identity))
}

/// Resolve the metadata row identity only when every supplied alias agrees.
///
/// Captured metadata can be reordered by a producer, so the physical row
/// position is not a safe identity once an explicit index is present.  A
/// conflicting alias is retained in `row` but deliberately omitted from the
/// derived identity, leaving the join unresolved instead of selecting one
/// representation arbitrarily.
fn metadata_index(object: &Map<String, Value>) -> Option<u64> {
    consistent_u64(
        object,
        &[
            "metadata_index",
            "metadataIndex",
            "index",
            "string_literal_index",
            "stringLiteralIndex",
        ],
    )
}

fn has_metadata_index_alias(object: &Map<String, Value>) -> bool {
    [
        "metadata_index",
        "metadataIndex",
        "index",
        "string_literal_index",
        "stringLiteralIndex",
    ]
    .iter()
    .any(|name| object.contains_key(*name))
}

fn consistent_token(object: &Map<String, Value>) -> Option<&Value> {
    let aliases = ["token", "metadata_token"];
    let mut selected = None;
    for name in aliases {
        let Some(candidate) = object.get(name) else {
            continue;
        };
        if selected.is_some_and(|existing: &Value| existing != candidate) {
            return None;
        }
        selected = Some(candidate);
    }
    selected
}

fn span_diagnostics(spans: &[(usize, usize, usize)]) -> Vec<Value> {
    let mut diagnostics = Vec::new();
    for (position, &(row, start, end)) in spans.iter().enumerate() {
        for &(other_row, other_start, other_end) in spans.iter().skip(position + 1) {
            if start == other_start && end == other_end {
                diagnostics.push(json!({
                    "kind": "duplicate_span",
                    "rows": [row, other_row],
                    "offset": start,
                    "end": end,
                }));
            } else if start < other_end && other_start < end {
                diagnostics.push(json!({
                    "kind": "overlapping_span",
                    "rows": [row, other_row],
                    "intersection": {
                        "offset": start.max(other_start),
                        "end": end.min(other_end),
                    },
                }));
            }
        }
    }
    diagnostics
}

fn checked_span(offset: usize, length: usize, data_len: usize) -> Result<usize, &'static str> {
    let end = offset.checked_add(length).ok_or("literal span overflows")?;
    if end > data_len {
        return Err("literal span exceeds supplied data");
    }
    Ok(end)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP string-literal input is invalid.".into(),
        false,
        "Supply bounded literal rows and caller-captured data bytes and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
