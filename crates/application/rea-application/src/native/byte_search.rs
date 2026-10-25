//! Deterministic, offline byte-pattern search over caller-supplied memory blocks.
//!
//! Providers own the interpretation of a target and its memory map.  This
//! module only consumes that retained representation, applies the shared
//! pattern semantics, and emits the provider-neutral page and coverage shape.

use rea_core::failure::Failure;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "search_bytes";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_MATCHES: usize = 1_000;

/// Validate a complete caller-supplied search request.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_request(input).map(|_| ())
}

/// Search retained memory blocks and return one page in the shared contract.
pub fn search(input: &Value) -> Result<Value, Failure> {
    let request = parse_request(input)?;
    let pattern = parse_pattern(&request.pattern, request.mask.as_deref())?;
    let cursor = request.cursor.as_deref().map(parse_cursor).transpose()?;
    let mut matches = Vec::new();
    let mut searched = Vec::new();
    let mut skipped_uninitialized = Vec::new();
    let mut skipped_not_loaded = Vec::new();
    let mut ordinal = 0usize;

    for block in &request.blocks {
        let Some(window) = block.window(request.start.as_deref(), request.end.as_deref())? else {
            continue;
        };

        // A provider can retain an initialized block while the corresponding
        // bytes are not loaded in the current image.  Bounds do not make that
        // data searchable: reporting matches from it would turn incomplete
        // coverage into a false positive.
        if !block.loaded {
            skipped_not_loaded.push(block.coverage(window));
            continue;
        }
        if !block.initialized {
            skipped_uninitialized.push(block.coverage(window));
            continue;
        }

        searched.push(block.coverage(window.clone()));
        let first = window.start_index;
        let last = window
            .end_index
            .saturating_sub(pattern.len().saturating_sub(1));
        if last < first {
            continue;
        }
        for index in first..=last {
            let current = ordinal;
            ordinal = ordinal.saturating_add(1);
            if cursor.is_some_and(|value| current < value) {
                continue;
            }
            if !matches_pattern(&block.bytes, index, &pattern) {
                continue;
            }
            if matches.len() == request.limit {
                break;
            }
            matches.push(match_value(block, index, &request.procedures));
        }
        if matches.len() == request.limit {
            break;
        }
    }

    let complete = matches.len() < request.limit;
    let next_cursor = (!complete).then(|| ordinal.to_string());
    let searched_bytes = searched
        .iter()
        .filter_map(|block| block.get("bytes").and_then(Value::as_u64))
        .sum::<u64>();
    Ok(result_value(
        matches,
        searched,
        searched_bytes,
        skipped_uninitialized,
        skipped_not_loaded,
        complete,
        next_cursor,
    ))
}

pub fn project(input: &Value) -> Result<Value, Failure> {
    search(input)
}

struct Request {
    pattern: String,
    mask: Option<String>,
    start: Option<String>,
    end: Option<String>,
    limit: usize,
    cursor: Option<String>,
    blocks: Vec<Block>,
    procedures: Vec<Procedure>,
}

struct Block {
    segment: String,
    start: Address,
    end: Address,
    bytes: Vec<u8>,
    file_offset: Option<u64>,
    initialized: bool,
    loaded: bool,
}

struct Procedure {
    address: String,
    name: String,
    start: Address,
    end: Address,
}

#[derive(Clone)]
struct Address {
    space: String,
    offset: u64,
}

#[derive(Clone)]
struct Window {
    start_index: usize,
    end_index: usize,
    start: Address,
    end: Address,
}

fn parse_request(input: &Value) -> Result<Request, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("byte search input must be an object"))?;
    reject_unknown(
        object,
        &[
            "pattern",
            "mask",
            "document",
            "start",
            "end",
            "limit",
            "cursor",
            "blocks",
            "procedures",
        ],
    )?;
    let pattern = required_string(object, "pattern")?;
    let mask = optional_string(object, "mask")?;
    let start = optional_string(object, "start")?;
    let end = optional_string(object, "end")?;
    let limit = object
        .get("limit")
        .map(parse_limit)
        .transpose()?
        .unwrap_or(100);
    let cursor = optional_string(object, "cursor")?;
    let blocks = parse_blocks(
        object
            .get("blocks")
            .ok_or_else(|| invalid("blocks are required"))?,
    )?;
    let procedures = object
        .get("procedures")
        .map(parse_procedures)
        .transpose()?
        .unwrap_or_default();
    if let (Some(start), Some(end)) = (&start, &end) {
        let start_address = parse_address(start)?;
        let end_address = parse_address(end)?;
        if start_address.space != end_address.space || start_address.offset > end_address.offset {
            return Err(invalid(
                "start and end must form an inclusive range in one address space",
            ));
        }
    }
    Ok(Request {
        pattern,
        mask,
        start,
        end,
        limit,
        cursor,
        blocks,
        procedures,
    })
}

fn parse_blocks(value: &Value) -> Result<Vec<Block>, Failure> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid("blocks must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid(&format!("blocks[{index}] must be an object")))?;
            reject_unknown(
                object,
                &[
                    "segment",
                    "start",
                    "end",
                    "bytes_hex",
                    "bytes",
                    "file_offset",
                    "initialized",
                    "loaded",
                ],
            )?;
            let segment = required_string(object, "segment")?;
            let start = parse_address(&required_string(object, "start")?)?;
            let end = parse_address(&required_string(object, "end")?)?;
            if start.space != end.space || start.offset > end.offset {
                return Err(invalid(
                    "memory block range must be ordered and use one address space",
                ));
            }
            let bytes = if let Some(value) = object.get("bytes_hex") {
                parse_hex_bytes(value)?
            } else {
                let value = object
                    .get("bytes")
                    .ok_or_else(|| invalid("block bytes are required"))?;
                parse_byte_array(value)?
            };
            let expected = end
                .offset
                .checked_sub(start.offset)
                .and_then(|span| span.checked_add(1))
                .ok_or_else(|| invalid("memory block address range overflows"))?;
            if expected != bytes.len() as u64 {
                return Err(invalid(
                    "memory block bytes must equal its inclusive address range",
                ));
            }
            let file_offset = object
                .get("file_offset")
                .map(parse_nonnegative_u64)
                .transpose()?;
            let initialized = object
                .get("initialized")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true);
            let loaded = object
                .get("loaded")
                .map(parse_bool)
                .transpose()?
                .unwrap_or(true);
            Ok(Block {
                segment,
                start,
                end,
                bytes,
                file_offset,
                initialized,
                loaded,
            })
        })
        .collect()
}

fn parse_procedures(value: &Value) -> Result<Vec<Procedure>, Failure> {
    let array = value
        .as_array()
        .ok_or_else(|| invalid("procedures must be an array"))?;
    array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid(&format!("procedures[{index}] must be an object")))?;
            reject_unknown(object, &["address", "name", "start", "end"])?;
            let address = required_string(object, "address")?;
            let name = required_string(object, "name")?;
            let start = parse_address(&required_string(object, "start")?)?;
            let end = parse_address(&required_string(object, "end")?)?;
            if start.space != end.space || start.offset > end.offset {
                return Err(invalid(
                    "procedure range must be ordered and use one address space",
                ));
            }
            Ok(Procedure {
                address,
                name,
                start,
                end,
            })
        })
        .collect()
}

fn parse_pattern(pattern: &str, mask: Option<&str>) -> Result<Vec<(u8, u8)>, Failure> {
    let pattern = parse_pairs(pattern, true)
        .ok_or_else(|| invalid("pattern must contain hexadecimal pairs or ?? wildcards"))?;
    let mask = mask
        .map(|value| {
            parse_pairs(value, false).ok_or_else(|| invalid("mask must contain hexadecimal pairs"))
        })
        .transpose()?;
    if mask
        .as_ref()
        .is_some_and(|value| value.len() != pattern.len())
    {
        return Err(invalid("mask length must equal pattern length"));
    }
    let pairs = pattern
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            let selected = mask.as_ref().map_or(255, |value| value[index].1);
            (value.0, if value.1 == 0 { 0 } else { selected })
        })
        .collect::<Vec<_>>();
    if !pairs.iter().any(|(_, mask)| *mask != 0) {
        return Err(invalid("pattern must constrain at least one bit"));
    }
    Ok(pairs)
}

fn parse_pairs(value: &str, wildcards: bool) -> Option<Vec<(u8, u8)>> {
    let mut result = Vec::new();
    let mut index = 0;
    while index < value.len() {
        let bytes = value.as_bytes();
        let pair = if wildcards && bytes.get(index..index + 2) == Some(b"??") {
            (0, 0)
        } else {
            let high = hex(bytes.get(index).copied()?)?;
            let low = hex(bytes.get(index + 1).copied()?)?;
            (high << 4 | low, 255)
        };
        result.push(pair);
        index += 2;
        if index == value.len() {
            break;
        }
        let mut next = index;
        while value
            .as_bytes()
            .get(next)
            .is_some_and(|byte| (*byte as char).is_ascii_whitespace())
        {
            next += 1;
        }
        if next == value.len() {
            return None;
        }
        index = next;
    }
    (!result.is_empty()).then_some(result)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn matches_pattern(bytes: &[u8], index: usize, pattern: &[(u8, u8)]) -> bool {
    pattern
        .iter()
        .enumerate()
        .all(|(offset, (expected, mask))| bytes[index + offset] & mask == expected & mask)
}

fn match_value(block: &Block, index: usize, procedures: &[Procedure]) -> Value {
    let address = format_address(&block.start, block.start.offset + index as u64);
    let procedure = procedures
        .iter()
        .find(|value| {
            value.start.space == block.start.space
                && value.start.offset <= block.start.offset + index as u64
                && block.start.offset + index as u64 <= value.end.offset
        })
        .map(|value| serde_json::json!({"address": value.address, "name": value.name}))
        .unwrap_or(Value::Null);
    let file_offset = block
        .file_offset
        .and_then(|offset| offset.checked_add(index as u64));
    serde_json::json!({"address": address, "segment": block.segment, "file_offset": file_offset, "procedure": procedure})
}

fn result_value(
    matches: Vec<Value>,
    blocks: Vec<Value>,
    bytes: u64,
    skipped_uninitialized: Vec<Value>,
    skipped_not_loaded: Vec<Value>,
    complete: bool,
    next_cursor: Option<String>,
) -> Value {
    serde_json::json!({"matches": matches, "searched": {"blocks": blocks, "bytes": bytes, "skipped_uninitialized": skipped_uninitialized, "skipped_not_loaded": skipped_not_loaded}, "complete": complete, "next_cursor": next_cursor})
}

impl Block {
    fn window(&self, start: Option<&str>, end: Option<&str>) -> Result<Option<Window>, Failure> {
        let lower = start
            .map(parse_address)
            .transpose()?
            .unwrap_or_else(|| self.start.clone());
        let upper = end
            .map(parse_address)
            .transpose()?
            .unwrap_or_else(|| self.end.clone());
        if lower.space != self.start.space
            || upper.space != self.start.space
            || lower.offset > self.end.offset
            || upper.offset < self.start.offset
        {
            return Ok(None);
        }
        let actual_start = lower.offset.max(self.start.offset);
        let actual_end = upper.offset.min(self.end.offset);
        let window_length = actual_end
            .checked_sub(actual_start)
            .and_then(|span| span.checked_add(1))
            .ok_or_else(|| invalid("memory block window overflows"))?;
        if window_length > usize::MAX as u64 {
            return Err(invalid("memory block window exceeds addressable memory"));
        }
        Ok(Some(Window {
            start_index: (actual_start - self.start.offset) as usize,
            end_index: (actual_end - self.start.offset + 1) as usize,
            start: Address {
                space: self.start.space.clone(),
                offset: actual_start,
            },
            end: Address {
                space: self.start.space.clone(),
                offset: actual_end,
            },
        }))
    }
    fn coverage(&self, window: Window) -> Value {
        serde_json::json!({
            "segment": self.segment,
            "start": format_address(&window.start, window.start.offset),
            "end": format_address(&window.end, window.end.offset),
            "bytes": window.end.offset - window.start.offset + 1,
        })
    }
}

fn parse_cursor(value: &str) -> Result<usize, Failure> {
    value
        .parse::<usize>()
        .map_err(|_| invalid("cursor must be a valid continuation token"))
}

fn parse_address(value: &str) -> Result<Address, Failure> {
    let (space, number) = value
        .rsplit_once(':')
        .map_or(("ram", value), |(space, number)| {
            let has_hex_prefix = number.starts_with("0x") || number.starts_with("0X");
            if !valid_address_space(space) || !has_hex_prefix {
                return ("", "");
            }
            (space, number)
        });
    let number = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
        .unwrap_or(number);
    if space.is_empty() || number.is_empty() {
        return Err(invalid("address must contain hexadecimal digits"));
    }
    Ok(Address {
        space: space.to_owned(),
        offset: u64::from_str_radix(number, 16)
            .map_err(|_| invalid("address must contain hexadecimal digits"))?,
    })
}

fn valid_address_space(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }

    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
            index += 1;
            continue;
        }

        let is_encoded_byte = byte == b'%'
            && index + 2 < bytes.len()
            && hex(bytes[index + 1]).is_some()
            && hex(bytes[index + 2]).is_some();
        if is_encoded_byte {
            index += 3;
            continue;
        }

        return false;
    }

    true
}

fn format_address(address: &Address, offset: u64) -> String {
    if address.space == "ram" {
        format!("0x{offset:x}")
    } else {
        format!("{}:0x{offset:x}", address.space)
    }
}

fn parse_hex_bytes(value: &Value) -> Result<Vec<u8>, Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid("bytes_hex must be a string"))?;
    if text.len() % 2 != 0 {
        return Err(invalid("bytes_hex must contain complete byte pairs"));
    }
    (0..text.len())
        .step_by(2)
        .map(|index| {
            let high = hex(text.as_bytes()[index])
                .ok_or_else(|| invalid("bytes_hex must contain hexadecimal pairs"))?;
            let low = hex(text.as_bytes()[index + 1])
                .ok_or_else(|| invalid("bytes_hex must contain hexadecimal pairs"))?;
            Ok(high << 4 | low)
        })
        .collect()
}

fn parse_byte_array(value: &Value) -> Result<Vec<u8>, Failure> {
    value
        .as_array()
        .ok_or_else(|| invalid("bytes must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|byte| *byte <= 255)
                .map(|byte| byte as u8)
                .ok_or_else(|| invalid("bytes must contain integers from 0 through 255"))
        })
        .collect()
}

fn parse_limit(value: &Value) -> Result<usize, Failure> {
    let limit = value
        .as_u64()
        .ok_or_else(|| invalid("limit must be an integer"))?;
    if !(1..=MAX_MATCHES as u64).contains(&limit) {
        return Err(invalid("limit must be between 1 and 1000"));
    }
    Ok(limit as usize)
}

fn parse_nonnegative_u64(value: &Value) -> Result<u64, Failure> {
    value
        .as_u64()
        .filter(|value| *value <= MAX_SAFE_INTEGER)
        .ok_or_else(|| invalid("file_offset must be a safe non-negative integer"))
}

fn parse_bool(value: &Value) -> Result<bool, Failure> {
    value
        .as_bool()
        .ok_or_else(|| invalid("field must be boolean"))
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>, Failure> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
        })
        .transpose()
}

fn reject_unknown(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown byte search field: {field}")));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Supply a valid retained byte search request.".into(),
        BTreeMap::new(),
    )
}
