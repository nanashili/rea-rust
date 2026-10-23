//! Deterministic projection for provider-backed `read_bytes` observations.
//!
//! Providers own target loading and memory interpretation.  This boundary
//! consumes their retained initialized memory blocks, performs the requested
//! range read, and emits the provider-neutral byte result.  A missing or
//! uninitialized byte ends the read; it is never represented by synthetic
//! zeroes.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "read_bytes";

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_BLOCKS: usize = 200_000;

/// Validate a caller-selected read request and its retained memory blocks.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    parse_request(input).map(|_| ())
}

/// Read the longest initialized, loaded prefix of the requested range.
pub fn read(input: &Value) -> Result<Value, Failure> {
    let request = parse_request(input)?;
    let mut bytes = Vec::new();
    let mut cursor = request.address.offset;

    while (bytes.len() as u64) < request.length {
        let Some(block) = request
            .blocks
            .iter()
            .find(|block| block.contains(&request.address.space, cursor))
        else {
            break;
        };

        if !block.initialized || !block.loaded {
            break;
        }

        let block_offset = usize::try_from(cursor - block.start.offset)
            .map_err(|_| invalid("memory block offset exceeds the host index limit"))?;
        let remaining_request = request.length - bytes.len() as u64;
        let available = block.bytes.len().saturating_sub(block_offset);
        let count = available.min(usize::try_from(remaining_request).unwrap_or(usize::MAX));
        if count == 0 {
            break;
        }

        bytes.extend_from_slice(&block.bytes[block_offset..block_offset + count]);
        cursor = cursor
            .checked_add(count as u64)
            .ok_or_else(|| invalid("read address overflows u64"))?;

        if (count as u64) < remaining_request {
            break;
        }
    }

    let returned_bytes = bytes.len();
    Ok(json!({
        "address": request.address.canonical(),
        "requested_bytes": request.length,
        "returned_bytes": returned_bytes,
        "bytes_hex": encode_hex(&bytes),
        "complete": returned_bytes as u64 == request.length,
    }))
}

/// Validate a provider result before it is wrapped in Evidence.
pub fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("read_bytes result must be an object"))?;
    reject_unknown_fields(
        object,
        &[
            "address",
            "requested_bytes",
            "returned_bytes",
            "bytes_hex",
            "complete",
        ],
        "read_bytes result",
    )?;

    let address = object
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("read_bytes result address must be a string"))?;
    let parsed_address = parse_address(address)?;
    if parsed_address.canonical() != address {
        return Err(invalid(
            "read_bytes result address must be a canonical lowercase address",
        ));
    }

    let requested = positive_integer(object.get("requested_bytes"), "requested_bytes")?;
    let returned = nonnegative_integer(object.get("returned_bytes"), "returned_bytes")?;
    if returned > requested {
        return Err(invalid("returned_bytes cannot exceed requested_bytes"));
    }

    let bytes_hex = object
        .get("bytes_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("bytes_hex must be a string"))?;
    validate_hex(bytes_hex, "bytes_hex")?;
    if returned != (bytes_hex.len() / 2) as u64 {
        return Err(invalid(
            "returned_bytes must equal the decoded bytes_hex length",
        ));
    }

    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("complete must be a boolean"))?;
    if complete != (returned == requested) {
        return Err(invalid(
            "complete must equal returned_bytes == requested_bytes",
        ));
    }
    Ok(())
}

/// Validate and return a provider result without changing its representation.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

struct Request {
    address: Address,
    length: u64,
    blocks: Vec<Block>,
}

struct Block {
    start: Address,
    end: Address,
    bytes: Vec<u8>,
    initialized: bool,
    loaded: bool,
}

#[derive(Clone)]
struct Address {
    space: String,
    offset: u64,
}

impl Address {
    fn canonical(&self) -> String {
        if self.space == "ram" {
            format!("0x{:x}", self.offset)
        } else {
            format!("{}:0x{:x}", encode_space(&self.space), self.offset)
        }
    }
}

impl Block {
    fn contains(&self, space: &str, offset: u64) -> bool {
        self.start.space == space && offset >= self.start.offset && offset <= self.end.offset
    }
}

fn parse_request(input: &Value) -> Result<Request, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("read_bytes input must be an object"))?;
    reject_unknown_fields(object, &["address", "length", "blocks"], "read_bytes input")?;

    let address = parse_address(
        object
            .get("address")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("address must be a string"))?,
    )?;
    let length = positive_integer(object.get("length"), "length")?;
    let blocks = object
        .get("blocks")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("blocks must be an array"))?;
    if blocks.len() > MAX_BLOCKS {
        return Err(invalid("blocks exceed the 200000 block limit"));
    }

    let blocks = blocks
        .iter()
        .enumerate()
        .map(|(index, value)| parse_block(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Request {
        address,
        length,
        blocks,
    })
}

fn parse_block(value: &Value, index: usize) -> Result<Block, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid(&format!("blocks[{index}] must be an object")))?;
    reject_unknown_fields(
        object,
        &[
            "start",
            "end",
            "bytes_hex",
            "bytes_base64",
            "initialized",
            "loaded",
        ],
        &format!("blocks[{index}]"),
    )?;

    let start = parse_address(required_text(object, "start", index)?)?;
    let end = parse_address(required_text(object, "end", index)?)?;
    if start.space != end.space || end.offset < start.offset {
        return Err(invalid(&format!(
            "blocks[{index}] has a reversed address range"
        )));
    }

    let bytes = match (object.get("bytes_hex"), object.get("bytes_base64")) {
        (Some(_), Some(_)) => return Err(invalid("a block must use one byte representation")),
        (Some(value), None) => decode_hex(value, "bytes_hex")?,
        (None, Some(value)) => decode_base64(value, "bytes_base64")?,
        (None, None) => return Err(invalid("a block requires bytes_hex or bytes_base64")),
    };
    let expected = end
        .offset
        .checked_sub(start.offset)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| invalid("block address range overflows u64"))?;
    if expected != bytes.len() as u64 {
        return Err(invalid(&format!(
            "blocks[{index}] bytes do not cover its inclusive address range"
        )));
    }

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
        start,
        end,
        bytes,
        initialized,
        loaded,
    })
}

fn parse_address(value: &str) -> Result<Address, Failure> {
    let (space, digits) = value
        .rsplit_once(':')
        .map_or(("ram", value), |(space, digits)| (space, digits));
    if space.is_empty() || !valid_space(space) {
        return Err(invalid("address has an invalid address-space name"));
    }
    let digits = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
        .ok_or_else(|| invalid("address must use hexadecimal digits with an optional 0x prefix"))?;
    if digits.is_empty()
        || digits.len() > 16
        || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid(
            "address must use hexadecimal digits with an optional 0x prefix",
        ));
    }
    let offset = u64::from_str_radix(digits, 16).map_err(|_| invalid("address exceeds u64"))?;
    Ok(Address {
        space: space.to_owned(),
        offset,
    })
}

fn valid_space(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
            index += 1;
            continue;
        }
        if byte == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
            index += 3;
            continue;
        }
        return false;
    }
    true
}

fn encode_space(value: &str) -> String {
    value.to_owned()
}

fn required_text<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    index: usize,
) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("blocks[{index}].{key} must be non-empty text")))
}

fn positive_integer(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    let value = nonnegative_integer(value, field)?;
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(invalid(&format!(
            "{field} must be between 1 and Number.MAX_SAFE_INTEGER"
        )));
    }
    Ok(value)
}

fn nonnegative_integer(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(&format!("{field} must be a non-negative integer")))
}

fn parse_bool(value: &Value) -> Result<bool, Failure> {
    value
        .as_bool()
        .ok_or_else(|| invalid("block flags must be booleans"))
}

fn decode_hex(value: &Value, field: &str) -> Result<Vec<u8>, Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a string")))?;
    validate_hex(text, field)?;
    Ok(text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (hex(pair[0]) << 4) | hex(pair[1]))
        .collect())
}

fn decode_base64(value: &Value, field: &str) -> Result<Vec<u8>, Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a string")))?;
    BASE64
        .decode(text)
        .map_err(|_| invalid(&format!("{field} is malformed base64")))
}

fn validate_hex(value: &str, field: &str) -> Result<(), Failure> {
    if value.len() % 2 != 0 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(&format!("{field} must be hexadecimal byte pairs")));
    }
    Ok(())
}

fn hex(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => unreachable!("validated hexadecimal byte"),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), Failure> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(field.as_str()))
    {
        return Err(invalid(&format!(
            "{context} contains unknown field {field}"
        )));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        false,
        "Provide a valid initialized memory range and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
