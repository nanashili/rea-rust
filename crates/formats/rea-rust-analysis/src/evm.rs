//! Bounded, offline EVM bytecode interface candidate recovery.
//!
//! This reader intentionally reports dispatch candidates as inferences. It
//! never executes bytecode, resolves signatures, or contacts a chain.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fmt;

pub const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_METADATA_DEPTH: usize = 64;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InputLimit,
    InvalidHex(&'static str),
    UnsupportedContainer,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputLimit => formatter.write_str("selected EVM carrier exceeds 4 MiB"),
            Self::InvalidHex(reason) => formatter.write_str(reason),
            Self::UnsupportedContainer => formatter.write_str(
                "Container marker EF00 is outside the verified flat-bytecode interface profile.",
            ),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    Raw,
    Hex,
}

#[derive(Debug, Serialize)]
pub struct Function {
    pub selector: String,
    pub bytecode_offset: usize,
    pub dispatch: &'static str,
    pub inferred_arguments: Option<String>,
    pub inferred_state_mutability: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct Metadata {
    pub profile: &'static str,
    pub status: &'static str,
    pub bytecode_offset: Option<usize>,
    pub cbor_bytes: Option<usize>,
    pub entries: Vec<MetadataEntry>,
    pub compiler_version: Option<CompilerVersion>,
    pub diagnostic: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct MetadataEntry {
    pub key: MetadataScalar,
    pub value: MetadataScalar,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum MetadataScalar {
    #[serde(rename = "text")]
    Text { value: String },
    #[serde(rename = "integer")]
    Integer { value: String },
    #[serde(rename = "bytes")]
    Bytes { value: String },
    #[serde(rename = "boolean")]
    Boolean { value: bool },
    #[serde(rename = "null")]
    Null,
    #[serde(rename = "uninterpreted")]
    Uninterpreted { container: &'static str },
}

#[derive(Debug, Serialize, Clone)]
pub struct CompilerVersion {
    pub representation: &'static str,
    pub value: String,
}

#[derive(Debug, Serialize)]
pub struct Interface {
    pub sha256: String,
    pub bytes: usize,
    pub hex: String,
    pub metadata: Metadata,
    pub functions: Vec<Function>,
}

/// Standard Solidity revert payloads. Unknown selectors retain their exact
/// bytes and are never assigned a guessed custom error name.
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum Revert {
    #[serde(rename = "error")]
    Error { message: Option<String> },
    #[serde(rename = "panic")]
    Panic { code: Option<String> },
    #[serde(rename = "custom")]
    Custom { selector: String, data_hex: String },
    #[serde(rename = "unknown")]
    Unknown { data_hex: String },
}

/// Decode the two Solidity-standard revert selectors while retaining unknowns.
/// The decoder is bounded by the same carrier budget and does not infer custom
/// error signatures without an ABI.
pub fn decode_revert(data: &[u8]) -> Result<Revert, Error> {
    if data.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    if data.len() < 4 {
        return Ok(Revert::Unknown {
            data_hex: hex(data),
        });
    }
    let selector = hex(&data[..4]);
    match selector.as_str() {
        "08c379a0" => match decode_error_string(&data[4..]) {
            Some(message) => Ok(Revert::Error {
                message: Some(message),
            }),
            None => Ok(Revert::Unknown {
                data_hex: hex(data),
            }),
        },
        "4e487b71" => match decode_panic_word(&data[4..]) {
            Some(code) => Ok(Revert::Panic { code: Some(code) }),
            None => Ok(Revert::Unknown {
                data_hex: hex(data),
            }),
        },
        _ => Ok(Revert::Custom {
            selector: format!("0x{selector}"),
            data_hex: hex(&data[4..]),
        }),
    }
}

fn decode_panic_word(data: &[u8]) -> Option<String> {
    (data.len() == 32).then(|| format!("0x{}", hex(data)))
}

fn decode_error_string(data: &[u8]) -> Option<String> {
    if data.len() < 64 {
        return None;
    }
    let offset = abi_word_usize(data.get(..32)?)?;
    if offset != 32 {
        return None;
    }
    let length_end = offset.checked_add(32)?;
    let length = abi_word_usize(data.get(offset..length_end)?)?;
    let start = offset.checked_add(32)?;
    let padded_length = length.checked_add(31)? / 32 * 32;
    let end = start.checked_add(padded_length)?;
    if end != data.len() || data.get(start + length..end)?.iter().any(|byte| *byte != 0) {
        return None;
    }
    std::str::from_utf8(data.get(start..start + length)?)
        .ok()
        .map(str::to_owned)
}

fn abi_word_usize(word: &[u8]) -> Option<usize> {
    if word.len() != 32 || word[..24].iter().any(|byte| *byte != 0) {
        return None;
    }
    usize::try_from(u64::from_be_bytes(word[24..].try_into().ok()?)).ok()
}

/// Decode the caller-selected carrier and recover common PUSH4/EQ dispatches.
pub fn inspect(carrier: &[u8], encoding: Encoding) -> Result<Interface, Error> {
    let bytes = decode_carrier(carrier, encoding)?;
    if bytes.starts_with(&[0xef, 0x00]) {
        return Err(Error::UnsupportedContainer);
    }

    let metadata = inspect_metadata(&bytes);
    // A terminal candidate that failed the admission profile is still raw
    // bytecode. Only an admitted metadata map establishes a code/metadata
    // boundary for dispatch recovery.
    let code_end = match metadata.status {
        "decoded" | "partial" => metadata.bytecode_offset.unwrap_or(bytes.len()),
        _ => bytes.len(),
    };
    let functions = recover_dispatch_candidates(&bytes[..code_end]);

    let mut digest = Sha256::new();
    digest.update(&bytes);
    Ok(Interface {
        sha256: format!("{:x}", digest.finalize()),
        bytes: bytes.len(),
        hex: hex(&bytes),
        metadata,
        functions,
    })
}

/// Decode a caller-selected raw or hexadecimal carrier under the EVM input bound.
pub fn decode_carrier(carrier: &[u8], encoding: Encoding) -> Result<Vec<u8>, Error> {
    if carrier.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    let bytes = match encoding {
        Encoding::Raw => carrier.to_vec(),
        Encoding::Hex => decode_hex(carrier)?,
    };
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(Error::InputLimit);
    }
    Ok(bytes)
}

fn recover_dispatch_candidates(bytes: &[u8]) -> Vec<Function> {
    let mut functions = Vec::new();
    let mut index = 0;
    let mut dispatch_end = bytes.len();

    while index < dispatch_end {
        let opcode = bytes[index];
        let next_index = instruction_end(bytes, index);

        if opcode == 0x63 && next_index == index + 5 {
            let selector_hex = hex(&bytes[index + 1..index + 5]);
            let target_offset = dispatch_target(bytes, next_index);
            if let Some(target_offset) = target_offset {
                dispatch_end = dispatch_end.min(target_offset);
            }
            let analysis_start = target_offset.unwrap_or(next_index);
            functions.push(Function {
                selector: format!("0x{selector_hex}"),
                bytecode_offset: target_offset.unwrap_or(index),
                dispatch: classify_dispatch(bytes, next_index),
                inferred_arguments: known_arguments(&selector_hex).or_else(|| {
                    inferred_arguments_from_calldata(bytes, analysis_start)
                        .or_else(|| inferred_arguments_from_calldata(bytes, next_index))
                }),
                inferred_state_mutability: known_mutability(&selector_hex).or_else(|| {
                    target_offset.and_then(|target| inferred_mutability(bytes, target))
                }),
            });
        }

        index = next_index;
    }

    functions
}

fn dispatch_target(bytes: &[u8], selector_end: usize) -> Option<usize> {
    let mut offset = selector_end;
    let scan_end = bytes.len().min(selector_end.saturating_add(16));
    let mut saw_eq = false;

    while offset < scan_end {
        let opcode = bytes[offset];
        if opcode == 0x14 {
            saw_eq = true;
        } else if saw_eq && (0x60..=0x7f).contains(&opcode) {
            let target_end = instruction_end(bytes, offset);
            let target = bytes.get(offset + 1..target_end)?;
            let mut value = 0usize;
            for byte in target {
                value = value.checked_mul(256)?.checked_add(usize::from(*byte))?;
            }
            if bytes.get(target_end) == Some(&0x57) && value < bytes.len() {
                return Some(value);
            }
        }
        offset = instruction_end(bytes, offset);
    }

    None
}

fn inferred_arguments_from_calldata(bytes: &[u8], selector_end: usize) -> Option<String> {
    let scan_end = bytes.len().min(selector_end.saturating_add(96));
    let mut offset = selector_end;
    let mut arguments: Vec<Option<&'static str>> = Vec::new();

    while offset < scan_end {
        let opcode = bytes[offset];
        if opcode == 0x63 {
            break;
        }

        if opcode == 0x35 {
            let argument_index = calldata_argument_index(bytes, selector_end, offset)?;
            if argument_index >= 16 {
                return None;
            }
            if arguments.len() <= argument_index {
                arguments.resize(argument_index + 1, None);
            }

            let argument_type = calldata_argument_type(bytes, offset)?;
            if arguments[argument_index].is_some_and(|existing| existing != argument_type) {
                return None;
            }
            arguments[argument_index] = Some(argument_type);
        }

        offset = instruction_end(bytes, offset);
    }

    if arguments.is_empty() || arguments.iter().any(Option::is_none) {
        return None;
    }

    Some(
        arguments
            .into_iter()
            .map(Option::unwrap_or_default)
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn calldata_argument_index(bytes: &[u8], start: usize, load_offset: usize) -> Option<usize> {
    if let Some((calldata_offset, _)) = previous_push_value(bytes, start, load_offset) {
        return calldata_offset
            .checked_sub(4)
            .filter(|value| value % 32 == 0)
            .map(|value| value / 32);
    }

    let previous = previous_instruction(bytes, start, load_offset)?;
    let duplicate = *bytes.get(previous)?;
    (0x83..=0x8f)
        .contains(&duplicate)
        .then(|| usize::from(duplicate - 0x83))
}

fn calldata_argument_type(bytes: &[u8], load_offset: usize) -> Option<&'static str> {
    let after_load = instruction_end(bytes, load_offset);
    if let Some(argument_type) = calldata_word_type(bytes, after_load) {
        return Some(argument_type);
    }

    let mut offset = after_load;
    let scan_end = bytes.len().min(offset.saturating_add(20));
    while offset < scan_end {
        let opcode = bytes[offset];
        if (0x60..=0x7f).contains(&opcode) {
            let immediate_end = instruction_end(bytes, offset);
            let immediate = bytes.get(offset + 1..immediate_end)?;
            if bytes.get(immediate_end) == Some(&0x16) {
                if let Some(argument_type) = masked_integer_type(immediate) {
                    return Some(argument_type);
                }
            }
            if immediate.len() == 1
                && immediate[0] == 0xa0
                && bytes.get(immediate_end) == Some(&0x1b)
            {
                return Some("address");
            }
        }
        offset = instruction_end(bytes, offset);
    }

    None
}

fn previous_instruction(bytes: &[u8], start: usize, target: usize) -> Option<usize> {
    let mut offset = start;
    let mut previous = None;
    while offset < target {
        previous = Some(offset);
        offset = instruction_end(bytes, offset);
    }
    previous
}

fn previous_push_value(
    bytes: &[u8],
    start: usize,
    calldata_offset: usize,
) -> Option<(usize, usize)> {
    let mut offset = start;
    let mut previous = None;
    while offset < calldata_offset {
        previous = Some(offset);
        offset = instruction_end(bytes, offset);
    }
    let push_offset = previous?;
    let opcode = bytes[push_offset];
    if !(0x60..=0x7f).contains(&opcode) || instruction_end(bytes, push_offset) != calldata_offset {
        return None;
    }
    let value = bytes.get(push_offset + 1..calldata_offset)?;
    let mut decoded = 0usize;
    for byte in value {
        decoded = decoded.checked_mul(256)?.checked_add(usize::from(*byte))?;
    }
    Some((decoded, calldata_offset + 1))
}

fn calldata_word_type(bytes: &[u8], after_load: usize) -> Option<&'static str> {
    let next = *bytes.get(after_load)?;
    if next == 0x15 && bytes.get(after_load + 1) == Some(&0x15) {
        return Some("bool");
    }

    if (0x60..=0x7f).contains(&next) {
        let immediate_end = instruction_end(bytes, after_load);
        let immediate = bytes.get(after_load + 1..immediate_end)?;
        let following = *bytes.get(immediate_end)?;

        if following == 0x1c {
            if let Some(byte_width) = aligned_byte_width(immediate) {
                return Some(fixed_bytes_type(byte_width));
            }
        }

        if following == 0x16 {
            return masked_integer_type(immediate);
        }

        if following == 0x0b && immediate.len() == 1 {
            let width = usize::from(immediate[0]).checked_add(1)?.checked_mul(8)?;
            if width <= 248 {
                return Some(signed_integer_type(width));
            }
        }
    }

    if matches!(next, 0x10..=0x1d | 0x01..=0x0b) {
        return Some("uint256");
    }
    None
}

fn aligned_byte_width(shift: &[u8]) -> Option<usize> {
    let mut value = 0usize;
    for byte in shift {
        value = value.checked_mul(256)?.checked_add(usize::from(*byte))?;
    }
    if value > 248 || value % 8 != 0 {
        return None;
    }
    Some(32 - value / 8)
}

fn fixed_bytes_type(width: usize) -> &'static str {
    match width {
        1 => "bytes1",
        2 => "bytes2",
        3 => "bytes3",
        4 => "bytes4",
        5 => "bytes5",
        6 => "bytes6",
        7 => "bytes7",
        8 => "bytes8",
        9 => "bytes9",
        10 => "bytes10",
        11 => "bytes11",
        12 => "bytes12",
        13 => "bytes13",
        14 => "bytes14",
        15 => "bytes15",
        16 => "bytes16",
        17 => "bytes17",
        18 => "bytes18",
        19 => "bytes19",
        20 => "bytes20",
        21 => "bytes21",
        22 => "bytes22",
        23 => "bytes23",
        24 => "bytes24",
        25 => "bytes25",
        26 => "bytes26",
        27 => "bytes27",
        28 => "bytes28",
        29 => "bytes29",
        30 => "bytes30",
        31 => "bytes31",
        _ => "bytes32",
    }
}

fn masked_integer_type(mask: &[u8]) -> Option<&'static str> {
    if mask.len() == 20 && mask.iter().all(|byte| *byte == 0xff) {
        return Some("address");
    }
    if mask.len() == 32 || mask.is_empty() || !mask.iter().all(|byte| *byte == 0xff) {
        return None;
    }

    let width = mask.len().checked_mul(8)?;
    Some(unsigned_integer_type(width))
}

fn unsigned_integer_type(width: usize) -> &'static str {
    match width {
        8 => "uint8",
        16 => "uint16",
        32 => "uint32",
        64 => "uint64",
        128 => "uint128",
        160 => "uint160",
        192 => "uint192",
        224 => "uint224",
        _ => "uint256",
    }
}

fn signed_integer_type(width: usize) -> &'static str {
    match width {
        8 => "int8",
        16 => "int16",
        32 => "int32",
        64 => "int64",
        128 => "int128",
        160 => "int160",
        192 => "int192",
        224 => "int224",
        _ => "int256",
    }
}

fn instruction_end(bytes: &[u8], offset: usize) -> usize {
    let immediate_bytes = match bytes[offset] {
        0x60..=0x7f => usize::from(bytes[offset] - 0x5f),
        _ => 0,
    };

    bytes
        .len()
        .min(offset.saturating_add(1).saturating_add(immediate_bytes))
}

fn classify_dispatch(bytes: &[u8], selector_end: usize) -> &'static str {
    let mut offset = selector_end;
    let scan_end = bytes.len().min(selector_end.saturating_add(16));
    let mut saw_eq = false;

    while offset < scan_end {
        let opcode = bytes[offset];
        if opcode == 0x14 {
            saw_eq = true;
        }
        if opcode == 0x57 {
            return if saw_eq { "abi" } else { "fallback" };
        }
        offset = instruction_end(bytes, offset);
    }

    if saw_eq { "abi" } else { "fallback" }
}

fn known_arguments(selector: &str) -> Option<String> {
    match selector {
        "a9059cbb" | "095ea7b3" => Some("address,uint256".into()),
        "23b872dd" | "42842e0e" => Some("address,address,uint256".into()),
        "b88d4fde" => Some("address,address,uint256,bytes".into()),
        "70a08231" => Some("address".into()),
        "dd62ed3e" => Some("address,address".into()),
        "39509351" | "a457c2d7" => Some("address,uint256".into()),
        "d505accf" => Some("address,address,uint256,uint256,uint8,bytes32,bytes32".into()),
        // ERC-2612 permit domain and nonce reads.
        "7ecebe00" => Some("address".into()),
        "3644e515" | "30adf81f" => Some(String::new()),
        // ERC-4494 uses a token-id nonce overload alongside the shared
        // EIP-712 domain helpers.
        "141a468c" => Some("uint256".into()),
        "7ac2ff7b" => Some("address,uint256,uint256,uint8,bytes32,bytes32".into()),
        // ERC-1271 contract signature validation (bytes32 and bytes forms).
        "1626ba7e" => Some("bytes32,bytes".into()),
        "20c13b0b" => Some("bytes,bytes".into()),
        // ERC-2981 royalty query.
        "2a55205a" => Some("uint256,uint256".into()),
        // ERC-4907 user-rental state.
        "e030565e" => Some("uint256,address,uint64".into()),
        "c2f1f14a" | "8fc88c48" => Some("uint256".into()),
        // ERC-1822 and ERC-2771 forwarding/upgradeability queries.
        "52d1902d" => Some(String::new()),
        "572b6c05" => Some("address".into()),
        // ERC-20 Votes delegation and historical voting power.
        "5c19a95c" | "587cde1e" | "9ab24eb0" => Some("address".into()),
        "3a46b1a8" => Some("address,uint256".into()),
        "8e539e8c" => Some("uint256".into()),
        // EIP-5267 exposes a zero-argument EIP-712 domain query. The current
        // Function model has no return-type field, so only its input fact is
        // represented here; no tuple output is guessed.
        "84b0196e" => Some(String::new()),
        // ERC-721/ERC-1155 receiver acceptance hooks.
        "150b7a02" => Some("address,address,uint256,bytes".into()),
        "f23a6e61" => Some("address,address,uint256,uint256,bytes".into()),
        "bc197c81" => Some("address,address,uint256[],uint256[],bytes".into()),
        // ERC-1820 registry and ERC-165 cache operations.
        "aabbb8ca" => Some("address,bytes32".into()),
        "29965a1d" => Some("address,bytes32,address".into()),
        "65ba36c1" => Some("string".into()),
        "a41e7d51" | "f712f3e8" | "b7056765" => Some("address,bytes4".into()),
        // EIP-2535 diamond loupe queries and the diamondCut operation.
        "7a0ed627" | "52ef6b2c" => Some(String::new()),
        "adfca15e" => Some("address".into()),
        "cdffacc6" => Some("bytes4".into()),
        "1f931c1c" => Some("tuple[],address,bytes".into()),
        // ERC-1363 transfer and approval callbacks.
        "1296ee62" | "3177029f" => Some("address,uint256".into()),
        "4000aea0" | "cae9ca51" => Some("address,uint256,bytes".into()),
        "d8fbe994" => Some("address,address,uint256".into()),
        "c1d34b89" => Some("address,address,uint256,bytes".into()),
        // OpenZeppelin ERC-1155Supply extension queries.
        "bd85b039" | "4f558e79" => Some("uint256".into()),
        // ERC-5192 soulbound-token status query.
        "b45a3c0e" => Some("uint256".into()),
        // EIP-3009 signed authorization lifecycle.
        "e3ee160e" | "ef55bec6" => {
            Some("address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32".into())
        }
        "e4e94023" | "e94a0102" => Some("address,bytes32".into()),
        "6352211e" | "081812fc" | "c87b56dd" => Some("uint256".into()),
        "a22cb465" => Some("address,bool".into()),
        "e985e9c5" => Some("address,address".into()),
        "01ffc9a7" => Some("bytes4".into()),
        // ERC-777 operator and token movement functions.
        "06e48538" => Some(String::new()),
        "d95b6371" => Some("address,address".into()),
        "959b8c3f" | "fad8b32a" => Some("address".into()),
        "9bd9bbc6" => Some("address,uint256,bytes".into()),
        "62ad1b83" => Some("address,address,uint256,bytes,bytes".into()),
        "fe9d9303" => Some("uint256,bytes".into()),
        "fc673c4f" => Some("address,uint256,bytes,bytes".into()),
        // The ERC-3156 receiver interface is encoded as an address.
        "613255ab" => Some("address".into()),
        "d9d98ce4" => Some("address,uint256".into()),
        "5cffe9de" => Some("address,address,uint256,bytes".into()),
        "23e30c8b" => Some("address,address,uint256,uint256,bytes".into()),
        "2f745c59" => Some("address,uint256".into()),
        "4f6ccce7" => Some("uint256".into()),
        "00fdd58e" => Some("address,uint256".into()),
        "4e1273f4" => Some("address[],uint256[]".into()),
        "0e89341c" => Some("uint256".into()),
        "f242432a" => Some("address,address,uint256,uint256,bytes".into()),
        "2eb2c2d6" => Some("address,address,uint256[],uint256[],bytes".into()),
        "f2fde38b" => Some("address".into()),
        "91d14854" => Some("bytes32,address".into()),
        "248a9ca3" => Some("bytes32".into()),
        "2f2ff15d" | "d547741f" | "36568abe" => Some("bytes32,address".into()),
        // ERC-4626's complete callable surface.  The report intentionally
        // carries only the proven ABI argument types; it does not invent a
        // recovered function name from a selector alone.
        "38d52e0f" | "01e1d114" => Some(String::new()),
        "c6e6f592" | "07a2d13a" => Some("uint256".into()),
        "402d267d" | "c63d75b6" | "ce96cb77" | "d905777e" => Some("address".into()),
        "6e553f65" => Some("uint256,address".into()),
        "94bf804d" => Some("uint256,address".into()),
        "b460af94" | "ba087652" => Some("uint256,address,address".into()),
        "ef8b30f7" | "b3d7f6b9" | "0a28a477" | "4cdad506" => Some("uint256".into()),
        "18160ddd" | "06fdde03" | "313ce567" | "95d89b41" | "8da5cb5b" | "715018a6" => {
            Some(String::new())
        }
        _ => None,
    }
}

fn inferred_mutability(bytes: &[u8], target: usize) -> Option<String> {
    let end = bytes.len().min(target.saturating_add(256));
    let mut offset = target;
    let mut saw_read = false;
    let mut saw_write = false;
    let mut saw_instruction = false;

    while offset < end {
        let opcode = bytes[offset];
        saw_instruction = true;
        match opcode {
            0x31 | 0x3a | 0x40..=0x4a | 0x54 => saw_read = true,
            0x55 | 0x5d | 0xa0..=0xa4 | 0xf0 | 0xf1 | 0xf2 | 0xf4 | 0xf5 | 0xfa | 0xfd | 0xff => {
                saw_write = true
            }
            _ => {}
        }
        offset = instruction_end(bytes, offset);
    }

    if saw_write {
        Some("nonpayable".into())
    } else if saw_read {
        Some("view".into())
    } else if saw_instruction {
        Some("pure".into())
    } else {
        None
    }
}

fn known_mutability(selector: &str) -> Option<String> {
    match selector {
        "06fdde03" | "18160ddd" | "70a08231" | "313ce567" | "95d89b41" | "6352211e"
        | "081812fc" | "c87b56dd" | "01ffc9a7" | "00fdd58e" | "4e1273f4" | "e985e9c5"
        | "0e89341c" | "dd62ed3e" | "2f745c59" | "4f6ccce7" | "8da5cb5b" | "91d14854"
        | "248a9ca3" | "7ecebe00" | "141a468c" | "3644e515" | "30adf81f" | "1626ba7e"
        | "20c13b0b" | "2a55205a" | "c2f1f14a" | "8fc88c48" | "52d1902d" | "572b6c05"
        | "587cde1e" | "9ab24eb0" | "3a46b1a8" | "8e539e8c" | "84b0196e" | "e94a0102"
        | "06e48538" | "d95b6371" | "613255ab" | "d9d98ce4" | "38d52e0f" | "01e1d114"
        | "c6e6f592" | "07a2d13a" | "402d267d" | "c63d75b6" | "ce96cb77" | "d905777e"
        | "ef8b30f7" | "b3d7f6b9" | "0a28a477" | "4cdad506" | "7a0ed627" | "adfca15e"
        | "52ef6b2c" | "cdffacc6" | "bd85b039" | "4f558e79" | "b45a3c0e" => Some("view".into()),
        "150b7a02" | "f23a6e61" | "bc197c81" | "65ba36c1" => Some("pure".into()),
        "29965a1d" | "a41e7d51" => Some("nonpayable".into()),
        "aabbb8ca" | "f712f3e8" | "b7056765" => Some("view".into()),
        "095ea7b3" | "a9059cbb" | "23b872dd" | "42842e0e" | "b88d4fde" | "a22cb465"
        | "f242432a" | "2eb2c2d6" | "f2fde38b" | "2f2ff15d" | "d547741f" | "36568abe"
        | "715018a6" | "39509351" | "a457c2d7" | "d505accf" | "6e553f65" | "94bf804d"
        | "b460af94" | "ba087652" | "959b8c3f" | "fad8b32a" | "9bd9bbc6" | "62ad1b83"
        | "e030565e" | "7ac2ff7b" | "5c19a95c" | "e3ee160e" | "ef55bec6" | "e4e94023"
        | "fe9d9303" | "fc673c4f" | "5cffe9de" | "23e30c8b" => Some("nonpayable".into()),
        "1f931c1c" => Some("nonpayable".into()),
        "1296ee62" | "4000aea0" | "3177029f" | "cae9ca51" | "d8fbe994" | "c1d34b89" => {
            Some("nonpayable".into())
        }
        // EVMole omits mutability when it cannot prove it. Keep that unknown
        // instead of treating an unrecognized selector as nonpayable.
        _ => None,
    }
}

fn inspect_metadata(bytes: &[u8]) -> Metadata {
    let unavailable = || {
        Metadata {
        profile: "terminal-cbor-scalars-v1",
        status: "unavailable",
        bytecode_offset: None,
        cbor_bytes: None,
        entries: Vec::new(),
        compiler_version: None,
        diagnostic: Some("No plausible terminal CBOR map was identified; Solidity origin and metadata absence remain unknown.".into()),
    }
    };
    if bytes.len() < 3 {
        return unavailable();
    }
    let length = usize::from(u16::from_be_bytes([
        bytes[bytes.len() - 2],
        bytes[bytes.len() - 1],
    ]));
    let Some(offset) = bytes.len().checked_sub(length + 2) else {
        return unavailable();
    };
    if length == 0 || bytes[offset] >> 5 != 5 {
        return unavailable();
    }
    let not_decoded = |diagnostic: &str| Metadata {
        profile: "terminal-cbor-scalars-v1",
        status: "not-decoded",
        bytecode_offset: Some(offset),
        cbor_bytes: Some(length),
        entries: Vec::new(),
        compiler_version: None,
        diagnostic: Some(diagnostic.chars().take(512).collect()),
    };
    let mut cursor = offset;
    let Ok((_, count)) = cbor_head(bytes, &mut cursor) else {
        return not_decoded("Terminal CBOR root map could not be decoded.");
    };
    let Some(minimum_children) = count.checked_mul(2) else {
        return not_decoded("Declared CBOR collection exceeds the encoded item-byte bound.");
    };
    if minimum_children > bytes.len().saturating_sub(cursor) {
        return not_decoded("Declared CBOR collection exceeds the encoded item-byte bound.");
    }
    let mut entries = Vec::new();
    let mut compiler_version = None;
    let mut partial = false;
    let mut keys = Vec::new();
    for _ in 0..count {
        let Ok(key) = scalar(bytes, &mut cursor, 0) else {
            return not_decoded("Terminal CBOR candidate could not be decoded.");
        };
        if keys.iter().any(|existing| existing == &key) {
            return not_decoded("Terminal CBOR root map contains duplicate keys.");
        }
        keys.push(key.clone());
        let Ok(value) = scalar(bytes, &mut cursor, 0) else {
            return not_decoded("Terminal CBOR candidate could not be decoded.");
        };
        if matches!(&key, MetadataScalar::Uninterpreted { .. })
            || matches!(&value, MetadataScalar::Uninterpreted { .. })
        {
            partial = true;
        }
        if let MetadataScalar::Text { value: name } = &key {
            if name == "solc" {
                compiler_version = match &value {
                    MetadataScalar::Bytes { value } if value.len() == 6 => Some(CompilerVersion {
                        representation: "release-bytes",
                        value: format!(
                            "{}.{}.{}",
                            u8::from_str_radix(&value[0..2], 16).unwrap_or(0),
                            u8::from_str_radix(&value[2..4], 16).unwrap_or(0),
                            u8::from_str_radix(&value[4..6], 16).unwrap_or(0)
                        ),
                    }),
                    MetadataScalar::Text { value } if !value.is_empty() => Some(CompilerVersion {
                        representation: "prerelease-text",
                        value: value.clone(),
                    }),
                    _ => None,
                };
            }
        }
        entries.push(MetadataEntry { key, value });
    }
    if cursor != bytes.len() - 2 {
        return not_decoded("Terminal CBOR candidate contains trailing bytes.");
    }
    Metadata {
        profile: "terminal-cbor-scalars-v1",
        status: if partial { "partial" } else { "decoded" },
        bytecode_offset: Some(offset),
        cbor_bytes: Some(length),
        entries,
        compiler_version,
        diagnostic: if partial {
            Some("Nested containers are uninterpreted; their exact bytes remain at the recorded range in original bytecode.".into())
        } else {
            None
        },
    }
}

fn cbor_head(bytes: &[u8], cursor: &mut usize) -> Result<(u8, usize), ()> {
    let byte = *bytes.get(*cursor).ok_or(())?;
    *cursor += 1;
    let major = byte >> 5;
    let info = byte & 31;
    let value = match info {
        0..=23 => usize::from(info),
        24 => usize::from(*bytes.get(*cursor).ok_or(())?),
        25 => usize::from(u16::from_be_bytes(
            bytes
                .get(*cursor..*cursor + 2)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?,
        )),
        26 => usize::try_from(u32::from_be_bytes(
            bytes
                .get(*cursor..*cursor + 4)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?,
        ))
        .map_err(|_| ())?,
        27 => usize::try_from(u64::from_be_bytes(
            bytes
                .get(*cursor..*cursor + 8)
                .ok_or(())?
                .try_into()
                .map_err(|_| ())?,
        ))
        .map_err(|_| ())?,
        _ => return Err(()),
    };
    *cursor += match info {
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => 0,
    };
    Ok((major, value))
}
fn scalar(bytes: &[u8], cursor: &mut usize, depth: usize) -> Result<MetadataScalar, ()> {
    if depth >= MAX_METADATA_DEPTH {
        return Err(());
    }
    let (major, value) = cbor_head(bytes, cursor)?;
    match major {
        0 => Ok(MetadataScalar::Integer {
            value: value.to_string(),
        }),
        1 => Ok(MetadataScalar::Integer {
            value: format!("-{}", (value as u128) + 1),
        }),
        2 => {
            let raw = bytes.get(*cursor..*cursor + value).ok_or(())?;
            *cursor += value;
            Ok(MetadataScalar::Bytes { value: hex(raw) })
        }
        3 => {
            let raw = bytes.get(*cursor..*cursor + value).ok_or(())?;
            *cursor += value;
            Ok(MetadataScalar::Text {
                value: String::from_utf8(raw.to_vec()).map_err(|_| ())?,
            })
        }
        4 => {
            if depth >= MAX_METADATA_DEPTH {
                return Err(());
            }
            if value > bytes.len().saturating_sub(*cursor) {
                return Err(());
            }
            for _ in 0..value {
                scalar(bytes, cursor, depth + 1)?;
            }
            Ok(MetadataScalar::Uninterpreted { container: "array" })
        }
        5 => {
            if depth >= MAX_METADATA_DEPTH {
                return Err(());
            }
            let Some(minimum_children) = value.checked_mul(2) else {
                return Err(());
            };
            if minimum_children > bytes.len().saturating_sub(*cursor) {
                return Err(());
            }

            let mut keys = Vec::new();
            for _ in 0..value {
                let key = scalar(bytes, cursor, depth + 1)?;
                if keys.iter().any(|existing| existing == &key) {
                    return Err(());
                }
                keys.push(key);
                scalar(bytes, cursor, depth + 1)?;
            }
            Ok(MetadataScalar::Uninterpreted { container: "map" })
        }
        7 if value == 20 => Ok(MetadataScalar::Boolean { value: false }),
        7 if value == 21 => Ok(MetadataScalar::Boolean { value: true }),
        7 if value == 22 => Ok(MetadataScalar::Null),
        _ => Err(()),
    }
}

fn decode_hex(input: &[u8]) -> Result<Vec<u8>, Error> {
    let text = std::str::from_utf8(input)
        .map_err(|_| Error::InvalidHex("Hex carrier must be valid UTF-8."))?;
    // TypeScript sets ignoreBOM=true, so a BOM remains data and fails the
    // hexadecimal grammar rather than being silently discarded.
    let text = trim_ascii_hex_whitespace(text);
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if text.len() % 2 != 0 {
        return Err(Error::InvalidHex(
            "Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid.",
        ));
    }
    let mut output = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let high =
            nibble(pair[0]).ok_or(Error::InvalidHex(
                "Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid.",
            ))?;
        let low =
            nibble(pair[1]).ok_or(Error::InvalidHex(
                "Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid.",
            ))?;
        output.push((high << 4) | low);
    }
    Ok(output)
}

fn trim_ascii_hex_whitespace(text: &str) -> &str {
    text.trim_matches(|character| matches!(character, '\u{0009}'..='\u{000d}' | ' '))
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[usize::from(byte >> 4)] as char);
        output.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_hex_and_preserves_repeated_dispatch_candidates() {
        let report = inspect(b" 0x6312345678146312345678 ", Encoding::Hex).unwrap();
        assert_eq!(report.bytes, 11);
        assert_eq!(report.functions.len(), 2);
        assert_eq!(report.functions[0].selector, "0x12345678");
        assert_eq!(report.functions[0].inferred_state_mutability, None);
        assert_eq!(report.functions[0].dispatch, "abi");
        assert_eq!(report.functions[1].bytecode_offset, 6);
        assert_eq!(report.functions[1].dispatch, "fallback");
    }

    #[test]
    fn recovers_evmole_entry_offsets_from_dispatch_targets() {
        let bytecode = decode_hex(b"6080604052348015600e575f80fd5b50600436106030575f3560e01c80632125b65b146034578063b69ef8a8146044575b5f80fd5b6044603f3660046046565b505050565b005b5f805f606084860312156057575f80fd5b833563ffffffff811681146069575f80fd5b925060208401356001600160a01b03811681146083575f80fd5b915060408401356001600160e01b0381168114609d575f80fd5b80915050925092509256").unwrap();
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), 2);
        assert_eq!(report.functions[0].selector, "0x2125b65b");
        assert_eq!(report.functions[0].bytecode_offset, 52);
        assert_eq!(report.functions[1].selector, "0xb69ef8a8");
        assert_eq!(report.functions[1].bytecode_offset, 68);
    }

    #[test]
    fn leaves_out_of_range_dispatch_destinations_unresolved() {
        let bytecode = [0x63, 0xca, 0xfe, 0xba, 0xbe, 0x14, 0x61, 0xff, 0xff, 0x57];
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions[0].bytecode_offset, 0);
        assert_eq!(report.functions[0].dispatch, "abi");
        assert_eq!(report.functions[0].inferred_state_mutability, None);
    }

    #[test]
    fn infers_unknown_selector_mutability_from_entry_opcodes() {
        let pure = [
            0x63, 0xca, 0xfe, 0xba, 0xbe, 0x14, 0x60, 0x0a, 0x57, 0x00, 0x5b, 0x60, 0x00, 0x60,
            0x00, 0xf3,
        ];
        let view = [
            0x63, 0xca, 0xfe, 0xba, 0xbe, 0x14, 0x60, 0x0a, 0x57, 0x00, 0x5b, 0x54, 0x50, 0xf3,
        ];
        let nonpayable = [
            0x63, 0xca, 0xfe, 0xba, 0xbe, 0x14, 0x60, 0x0a, 0x57, 0x00, 0x5b, 0x60, 0x00, 0x55,
            0x00,
        ];

        assert_eq!(
            inspect(&pure, Encoding::Raw).unwrap().functions[0]
                .inferred_state_mutability
                .as_deref(),
            Some("pure")
        );
        assert_eq!(
            inspect(&view, Encoding::Raw).unwrap().functions[0]
                .inferred_state_mutability
                .as_deref(),
            Some("view")
        );
        assert_eq!(
            inspect(&nonpayable, Encoding::Raw).unwrap().functions[0]
                .inferred_state_mutability
                .as_deref(),
            Some("nonpayable")
        );
    }

    #[test]
    fn preserves_fallback_dispatch_and_unknown_signature() {
        let report = inspect(&[0x63, 0xde, 0xad, 0xbe, 0xef, 0x60, 0x00], Encoding::Raw).unwrap();
        assert_eq!(report.functions[0].dispatch, "fallback");
        assert_eq!(report.functions[0].inferred_arguments, None);
        assert_eq!(report.functions[0].inferred_state_mutability, None);
    }

    #[test]
    fn follows_push_immediates_and_classifies_conditional_routes() {
        let mut bytecode = vec![
            0x61, 0x63, 0xa9, // PUSH2 data containing a fake PUSH4
            0x63, 0xa9, 0x05, 0x9c, 0xbb, // transfer selector
            0x14, 0x60, 0x20, 0x57, // EQ, destination, JUMPI
            0x63, 0xca, 0xfe, 0xba, 0xbe, // fallback selector
            0x60, 0x00,
        ];
        bytecode.extend(std::iter::repeat_n(0x00, 13));
        bytecode.push(0x5b);
        let report = inspect(&bytecode, Encoding::Raw).unwrap();

        assert_eq!(report.functions.len(), 2);
        assert_eq!(report.functions[0].bytecode_offset, 32);
        assert_eq!(report.functions[0].dispatch, "abi");
        assert_eq!(report.functions[1].bytecode_offset, 12);
        assert_eq!(report.functions[1].dispatch, "fallback");
    }

    #[test]
    fn infers_generic_argument_types_from_bounded_calldata_use() {
        let mut bytecode = vec![0x63, 0xca, 0xfe, 0xba, 0xbe, 0x14, 0x60, 0x20, 0x57];
        bytecode.extend([0x60, 0x04, 0x35, 0x10]);
        bytecode.extend([0x60, 0x24, 0x35, 0x73]);
        bytecode.extend([0xff; 20]);
        bytecode.push(0x16);

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), 1);
        assert_eq!(
            report.functions[0].inferred_arguments.as_deref(),
            Some("uint256,address")
        );
    }

    #[test]
    fn infers_stack_offset_arguments_from_evmole_mask_patterns() {
        let bytecode = [
            0x63, 0xca, 0xfe, 0xba, 0xbe, // selector
            0x83, 0x35, // DUP4, CALLDATALOAD
            0x63, 0xff, 0xff, 0xff, 0xff, 0x16, // uint32 mask
        ];
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(
            report.functions[0].inferred_arguments.as_deref(),
            Some("uint32")
        );
    }

    #[test]
    fn leaves_stack_offset_arguments_unknown_without_type_proof() {
        let bytecode = [0x63, 0xca, 0xfe, 0xba, 0xbe, 0x83, 0x35];
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions[0].inferred_arguments, None);
    }

    #[test]
    fn leaves_generic_arguments_unknown_when_word_type_is_ambiguous() {
        let bytecode = [0x63, 0xca, 0xfe, 0xba, 0xbe, 0x60, 0x04, 0x35];
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions[0].inferred_arguments, None);
    }

    #[test]
    fn infers_bool_fixed_width_unsigned_and_signed_arguments_from_opcode_proofs() {
        let mut bytecode = Vec::new();
        let mut append_candidate = |selector: [u8; 4], body: &[u8]| {
            bytecode.push(0x63);
            bytecode.extend(selector);
            bytecode.extend(body);
        };

        append_candidate([0xca, 0xfe, 0xba, 0xbe], &[0x60, 0x04, 0x35, 0x15, 0x15]);
        append_candidate(
            [0xde, 0xad, 0xbe, 0xef],
            &[0x60, 0x04, 0x35, 0x60, 0xff, 0x16],
        );
        append_candidate(
            [0xba, 0xad, 0xf0, 0x0d],
            &[0x60, 0x04, 0x35, 0x61, 0xff, 0xff, 0x16],
        );
        append_candidate(
            [0xab, 0xad, 0x1d, 0xea],
            &[0x60, 0x04, 0x35, 0x60, 0x00, 0x0b],
        );

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), 4);
        assert_eq!(
            report.functions[0].inferred_arguments.as_deref(),
            Some("bool")
        );
        assert_eq!(
            report.functions[1].inferred_arguments.as_deref(),
            Some("uint8")
        );
        assert_eq!(
            report.functions[2].inferred_arguments.as_deref(),
            Some("uint16")
        );
        assert_eq!(
            report.functions[3].inferred_arguments.as_deref(),
            Some("int8")
        );
    }

    #[test]
    fn retains_unknown_for_non_proving_masks() {
        let bytecode = [
            0x63, 0xca, 0xfe, 0xba, 0xbe, 0x60, 0x04, 0x35, 0x60, 0x03, 0x16,
        ];
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions[0].inferred_arguments, None);
    }

    #[test]
    fn infers_fixed_bytes_width_from_explicit_abi_alignment() {
        let mut bytecode = Vec::new();
        let mut append_candidate = |selector: [u8; 4], shift: u8| {
            bytecode.push(0x63);
            bytecode.extend(selector);
            bytecode.extend([0x60, 0x04, 0x35, 0x60, shift, 0x1c]);
        };

        append_candidate([0xca, 0xfe, 0xba, 0xbe], 248);
        append_candidate([0xde, 0xad, 0xbe, 0xef], 224);
        append_candidate([0xba, 0xad, 0xf0, 0x0d], 0);

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), 3);
        assert_eq!(
            report.functions[0].inferred_arguments.as_deref(),
            Some("bytes1")
        );
        assert_eq!(
            report.functions[1].inferred_arguments.as_deref(),
            Some("bytes4")
        );
        assert_eq!(
            report.functions[2].inferred_arguments.as_deref(),
            Some("bytes32")
        );
    }

    #[test]
    fn leaves_fixed_bytes_unknown_without_byte_aligned_shift() {
        let bytecode = [
            0x63, 0xca, 0xfe, 0xba, 0xbe, 0x60, 0x04, 0x35, 0x60, 0xe1, 0x1c,
        ];
        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions[0].inferred_arguments, None);
    }

    #[test]
    fn reports_known_erc20_candidates_without_guessing_unknown_mutability() {
        let report = inspect(
            &[
                0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x14, // transfer(address,uint256)
                0x63, 0x70, 0xa0, 0x82, 0x31, 0x14, // balanceOf(address)
                0x63, 0xca, 0xfe, 0xba, 0xbe, 0x14, // unknown selector
            ],
            Encoding::Raw,
        )
        .unwrap();

        assert_eq!(report.functions.len(), 3);
        assert_eq!(
            report.functions[0].inferred_arguments.as_deref(),
            Some("address,uint256")
        );
        assert_eq!(
            report.functions[1].inferred_arguments.as_deref(),
            Some("address")
        );
        assert_eq!(
            report.functions[1].inferred_state_mutability.as_deref(),
            Some("view")
        );
        assert_eq!(report.functions[2].inferred_arguments, None);
        assert_eq!(report.functions[2].inferred_state_mutability, None);
    }

    #[test]
    fn reports_common_token_and_access_control_signatures() {
        let selectors = [
            "6352211e", // ERC-721 ownerOf(uint256)
            "a22cb465", // ERC-721/ERC-1155 setApprovalForAll(address,bool)
            "f242432a", // ERC-1155 safeTransferFrom
            "91d14854", // AccessControl hasRole
            "38d52e0f", // ERC-4626 asset()
            "6e553f65", // ERC-4626 deposit
        ];
        let mut bytecode = Vec::new();
        for selector in selectors {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), selectors.len());
        assert_eq!(
            report.functions[0].inferred_arguments.as_deref(),
            Some("uint256")
        );
        assert_eq!(
            report.functions[0].inferred_state_mutability.as_deref(),
            Some("view")
        );
        assert_eq!(
            report.functions[2].inferred_arguments.as_deref(),
            Some("address,address,uint256,uint256,bytes")
        );
        assert_eq!(
            report.functions[3].inferred_state_mutability.as_deref(),
            Some("view")
        );
        assert_eq!(
            report.functions[5].inferred_arguments.as_deref(),
            Some("uint256,address")
        );
        assert_eq!(
            report.functions[5].inferred_state_mutability.as_deref(),
            Some("nonpayable")
        );
    }

    #[test]
    fn reports_complete_erc165_and_erc4626_selector_facts() {
        let cases = [
            ("01ffc9a7", "bytes4", "view"),
            ("38d52e0f", "", "view"),
            ("01e1d114", "", "view"),
            ("c6e6f592", "uint256", "view"),
            ("07a2d13a", "uint256", "view"),
            ("402d267d", "address", "view"),
            ("c63d75b6", "address", "view"),
            ("ce96cb77", "address", "view"),
            ("d905777e", "address", "view"),
            ("ef8b30f7", "uint256", "view"),
            ("b3d7f6b9", "uint256", "view"),
            ("0a28a477", "uint256", "view"),
            ("4cdad506", "uint256", "view"),
            ("6e553f65", "uint256,address", "nonpayable"),
            ("94bf804d", "uint256,address", "nonpayable"),
            ("b460af94", "uint256,address,address", "nonpayable"),
            ("ba087652", "uint256,address,address", "nonpayable"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());

        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn leaves_custom_selector_without_recovered_name_or_facts() {
        let report = inspect(&[0x63, 0xca, 0xfe, 0xba, 0xbe], Encoding::Raw).unwrap();

        let function = &report.functions[0];
        assert_eq!(function.selector, "0xcafebabe");
        assert_eq!(function.inferred_arguments, None);
        assert_eq!(function.inferred_state_mutability, None);
    }

    #[test]
    fn reports_erc777_and_erc3156_selector_facts() {
        let cases = [
            ("06e48538", "", "view"),
            ("d95b6371", "address,address", "view"),
            ("959b8c3f", "address", "nonpayable"),
            ("fad8b32a", "address", "nonpayable"),
            ("9bd9bbc6", "address,uint256,bytes", "nonpayable"),
            (
                "62ad1b83",
                "address,address,uint256,bytes,bytes",
                "nonpayable",
            ),
            ("fe9d9303", "uint256,bytes", "nonpayable"),
            ("fc673c4f", "address,uint256,bytes,bytes", "nonpayable"),
            ("613255ab", "address", "view"),
            ("d9d98ce4", "address,uint256", "view"),
            ("5cffe9de", "address,address,uint256,bytes", "nonpayable"),
            (
                "23e30c8b",
                "address,address,uint256,uint256,bytes",
                "nonpayable",
            ),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_canonical_erc20_and_erc721_fact_signatures() {
        let selectors = [
            ([0xdd, 0x62, 0xed, 0x3e], "address,address", "view"), // allowance
            ([0xa2, 0x2c, 0xb4, 0x65], "address,bool", "nonpayable"), // setApprovalForAll
            ([0x0e, 0x89, 0x34, 0x1c], "uint256", "view"),         // uri
            (
                [0xd5, 0x05, 0xac, 0xcf],
                "address,address,uint256,uint256,uint8,bytes32,bytes32",
                "nonpayable",
            ), // permit
        ];
        let mut bytecode = Vec::new();
        for (selector, _, _) in selectors {
            bytecode.push(0x63);
            bytecode.extend(selector);
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), selectors.len());
        for (index, (_, arguments, mutability)) in selectors.into_iter().enumerate() {
            assert_eq!(
                report.functions[index].inferred_arguments.as_deref(),
                Some(arguments)
            );
            assert_eq!(
                report.functions[index].inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc2612_erc1271_and_erc2981_selector_facts() {
        let cases = [
            (
                "d505accf",
                "address,address,uint256,uint256,uint8,bytes32,bytes32",
                "nonpayable",
            ),
            ("7ecebe00", "address", "view"),
            ("3644e515", "", "view"),
            ("30adf81f", "", "view"),
            ("1626ba7e", "bytes32,bytes", "view"),
            ("20c13b0b", "bytes,bytes", "view"),
            ("2a55205a", "uint256,uint256", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc721_enumerable_and_erc4494_selector_facts() {
        let cases = [
            ("18160ddd", "", "view"),
            ("2f745c59", "address,uint256", "view"),
            ("4f6ccce7", "uint256", "view"),
            ("141a468c", "uint256", "view"),
            (
                "7ac2ff7b",
                "address,uint256,uint256,uint8,bytes32,bytes32",
                "nonpayable",
            ),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc721_metadata_and_transfer_overloads() {
        let cases = [
            ("06fdde03", "", "view"),
            ("95d89b41", "", "view"),
            ("c87b56dd", "uint256", "view"),
            ("23b872dd", "address,address,uint256", "nonpayable"),
            ("42842e0e", "address,address,uint256", "nonpayable"),
            ("b88d4fde", "address,address,uint256,bytes", "nonpayable"),
            ("095ea7b3", "address,uint256", "nonpayable"),
            ("6352211e", "uint256", "view"),
            ("081812fc", "uint256", "view"),
            ("a22cb465", "address,bool", "nonpayable"),
            ("e985e9c5", "address,address", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc4907_user_rental_selector_facts() {
        let cases = [
            ("e030565e", "uint256,address,uint64", "nonpayable"),
            ("c2f1f14a", "uint256", "view"),
            ("8fc88c48", "uint256", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_proxy_and_forwarder_selector_facts() {
        let cases = [("52d1902d", "", "view"), ("572b6c05", "address", "view")];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_access_control_selector_facts() {
        let cases = [
            ("91d14854", "bytes32,address", "view"),
            ("248a9ca3", "bytes32", "view"),
            ("2f2ff15d", "bytes32,address", "nonpayable"),
            ("d547741f", "bytes32,address", "nonpayable"),
            ("36568abe", "bytes32,address", "nonpayable"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_votes_selector_facts() {
        let cases = [
            ("5c19a95c", "address", "nonpayable"),
            ("587cde1e", "address", "view"),
            ("9ab24eb0", "address", "view"),
            ("3a46b1a8", "address,uint256", "view"),
            ("8e539e8c", "uint256", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_eip3009_authorization_selector_facts() {
        let authorization = "address,address,uint256,uint256,uint256,bytes32,uint8,bytes32,bytes32";
        let cases = [
            ("e3ee160e", authorization, "nonpayable"),
            ("ef55bec6", authorization, "nonpayable"),
            ("e4e94023", "address,bytes32", "nonpayable"),
            ("e94a0102", "address,bytes32", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_eip5267_domain_selector_without_guessing_tuple_outputs() {
        let report = inspect(&[0x63, 0x84, 0xb0, 0x19, 0x6e], Encoding::Raw).unwrap();

        assert_eq!(report.functions.len(), 1);
        assert_eq!(report.functions[0].selector, "0x84b0196e");
        assert_eq!(report.functions[0].inferred_arguments.as_deref(), Some(""));
        assert_eq!(
            report.functions[0].inferred_state_mutability.as_deref(),
            Some("view")
        );
    }

    #[test]
    fn reports_token_receiver_hook_selector_facts() {
        let cases = [
            ("150b7a02", "address,address,uint256,bytes", "pure"),
            ("f23a6e61", "address,address,uint256,uint256,bytes", "pure"),
            (
                "bc197c81",
                "address,address,uint256[],uint256[],bytes",
                "pure",
            ),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc1155_function_selector_facts() {
        let cases = [
            ("00fdd58e", "address,uint256", "view"),
            ("4e1273f4", "address[],uint256[]", "view"),
            ("a22cb465", "address,bool", "nonpayable"),
            ("e985e9c5", "address,address", "view"),
            (
                "f242432a",
                "address,address,uint256,uint256,bytes",
                "nonpayable",
            ),
            (
                "2eb2c2d6",
                "address,address,uint256[],uint256[],bytes",
                "nonpayable",
            ),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc1820_registry_selector_facts() {
        let cases = [
            ("aabbb8ca", "address,bytes32", "view"),
            ("29965a1d", "address,bytes32,address", "nonpayable"),
            ("65ba36c1", "string", "pure"),
            ("a41e7d51", "address,bytes4", "nonpayable"),
            ("f712f3e8", "address,bytes4", "view"),
            ("b7056765", "address,bytes4", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc2535_diamond_loupe_and_cut_selector_facts() {
        let cases = [
            ("7a0ed627", "", "view"),
            ("adfca15e", "address", "view"),
            ("52ef6b2c", "", "view"),
            ("cdffacc6", "bytes4", "view"),
            ("1f931c1c", "tuple[],address,bytes", "nonpayable"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc1363_callback_selector_facts() {
        let cases = [
            ("1296ee62", "address,uint256", "nonpayable"),
            ("4000aea0", "address,uint256,bytes", "nonpayable"),
            ("3177029f", "address,uint256", "nonpayable"),
            ("cae9ca51", "address,uint256,bytes", "nonpayable"),
            ("d8fbe994", "address,address,uint256", "nonpayable"),
            ("c1d34b89", "address,address,uint256,bytes", "nonpayable"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc1155_supply_extension_selector_facts() {
        let cases = [
            ("bd85b039", "uint256", "view"),
            ("4f558e79", "uint256", "view"),
        ];
        let mut bytecode = Vec::with_capacity(cases.len() * 5);
        for (selector, _, _) in cases {
            bytecode.push(0x63);
            bytecode.extend(
                (0..4).map(|index| {
                    u8::from_str_radix(&selector[index * 2..index * 2 + 2], 16).unwrap()
                }),
            );
        }

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.functions.len(), cases.len());
        for (function, (_, arguments, mutability)) in report.functions.iter().zip(cases) {
            assert_eq!(function.inferred_arguments.as_deref(), Some(arguments));
            assert_eq!(
                function.inferred_state_mutability.as_deref(),
                Some(mutability)
            );
        }
    }

    #[test]
    fn reports_erc5192_locked_selector_fact() {
        let report = inspect(&[0x63, 0xb4, 0x5a, 0x3c, 0x0e], Encoding::Raw).unwrap();
        let function = &report.functions[0];
        assert_eq!(function.inferred_arguments.as_deref(), Some("uint256"));
        assert_eq!(function.inferred_state_mutability.as_deref(), Some("view"));
    }

    #[test]
    fn decodes_terminal_solidity_metadata_and_compiler_version() {
        let mut bytecode = vec![0xa1, 0x64, b's', b'o', b'l', b'c', 0x43, 0x00, 0x08, 0x00];
        bytecode.extend([0x00, 0x0a]);

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.metadata.status, "decoded");
        assert_eq!(report.metadata.bytecode_offset, Some(0));
        assert_eq!(
            report
                .metadata
                .compiler_version
                .as_ref()
                .map(|version| version.value.as_str()),
            Some("0.8.0")
        );
    }

    #[test]
    fn rejects_cbor_values_outside_the_solidity_metadata_profile() {
        let mut cases = vec![
            vec![0xa1, 0x61, b'x', 0x61, 0xff], // invalid UTF-8
            vec![0xa1, 0x61, b'x'],             // truncated value
            vec![0xa1, 0x61, b'x', 0xc0, 0x00], // tag
            vec![0xa1, 0x61, b'x', 0xfa, 0x3f, 0x80, 0x00, 0x00], // float
            vec![0xa1, 0x61, b'x', 0x9f, 0x00, 0xff], // indefinite array
            vec![0xa2, 0x61, b'x', 0x01, 0x61, b'x', 0x02], // duplicate key
            vec![0xa1, 0x61, b'x', 0x8a, 0x00], // impossible collection
        ];
        let mut nested = vec![0xa1, 0x61, b'x'];
        nested.extend(std::iter::repeat(0x81).take(MAX_METADATA_DEPTH + 1));
        nested.push(0x00);
        cases.push(nested);

        for payload in cases {
            let mut bytecode = vec![0x00];
            bytecode.extend(&payload);
            bytecode.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());

            let report = inspect(&bytecode, Encoding::Raw).unwrap();
            assert_eq!(report.metadata.status, "not-decoded");
            assert_eq!(report.metadata.bytecode_offset, Some(1));
            assert_eq!(report.metadata.cbor_bytes, Some(payload.len()));
            assert!(report.metadata.entries.is_empty());
            assert!(report.metadata.compiler_version.is_none());
            assert!(
                report
                    .metadata
                    .diagnostic
                    .as_ref()
                    .is_some_and(|message| message.len() <= 512)
            );
        }
    }

    #[test]
    fn rejects_metadata_container_at_exact_depth_limit() {
        let mut payload = vec![0xa1, 0x61, b'x'];
        payload.extend(std::iter::repeat(0x81).take(MAX_METADATA_DEPTH));
        payload.push(0x00);

        let mut bytecode = vec![0x00];
        bytecode.extend(&payload);
        bytecode.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.metadata.status, "not-decoded");
        assert_eq!(report.metadata.bytecode_offset, Some(1));
        assert_eq!(report.metadata.cbor_bytes, Some(payload.len()));
    }

    #[test]
    fn rejects_duplicate_keys_inside_uninterpreted_metadata_maps() {
        let payload = [
            0xa1, 0x66, b'n', b'e', b's', b't', b'e', b'd', 0xa2, 0x61, b'x', 0x01, 0x61, b'x',
            0x02,
        ];
        let mut bytecode = vec![0x00];
        bytecode.extend(payload);
        bytecode.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.metadata.status, "not-decoded");
        assert_eq!(report.metadata.bytecode_offset, Some(1));
        assert!(report.metadata.entries.is_empty());
        assert!(report.metadata.compiler_version.is_none());
        assert_eq!(
            report.metadata.diagnostic.as_deref(),
            Some("Terminal CBOR candidate could not be decoded.")
        );
    }

    #[test]
    fn rejects_nested_collections_that_exceed_remaining_metadata_bytes() {
        let payload = [0xa1, 0x61, b'x', 0x82, 0x00];
        let mut bytecode = vec![0x00];
        bytecode.extend(payload);
        bytecode.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.metadata.status, "not-decoded");
        assert_eq!(report.metadata.bytecode_offset, Some(1));
        assert_eq!(report.metadata.cbor_bytes, Some(payload.len()));
        assert!(report.metadata.entries.is_empty());
    }

    #[test]
    fn retains_full_width_cbor_integer_precision() {
        let payload = [
            0xa1, 0x00, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let mut bytecode = vec![0x00];
        bytecode.extend(payload);
        bytecode.extend(u16::try_from(payload.len()).unwrap().to_be_bytes());

        let report = inspect(&bytecode, Encoding::Raw).unwrap();
        assert_eq!(report.metadata.status, "decoded");
        assert_eq!(
            report.metadata.entries[0].value,
            MetadataScalar::Integer {
                value: "18446744073709551615".into()
            }
        );
    }

    #[test]
    fn rejects_odd_or_invalid_hex() {
        assert!(matches!(
            inspect(b"0x1", Encoding::Hex),
            Err(Error::InvalidHex(_))
        ));
        assert!(matches!(
            inspect(b"0xz0", Encoding::Hex),
            Err(Error::InvalidHex(_))
        ));
    }

    #[test]
    fn rejects_utf8_bom_before_hex_carrier() {
        let error = decode_carrier("\u{feff} 0x63  ".as_bytes(), Encoding::Hex)
            .expect_err("ignoreBOM=true preserves the BOM for validation");
        assert_eq!(
            error.to_string(),
            "Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid."
        );
    }

    #[test]
    fn accepts_uppercase_hex_prefix() {
        let report = inspect(b" 0X63 ", Encoding::Hex).unwrap();
        assert_eq!(report.hex, "63");
        assert_eq!(report.bytes, 1);
    }

    #[test]
    fn rejects_eof_style_container_marker_like_typescript_worker() {
        assert!(matches!(
            inspect(&[0xef, 0x00, 0x01], Encoding::Raw),
            Err(Error::UnsupportedContainer)
        ));
    }

    #[test]
    fn rejects_non_ascii_outer_whitespace_like_typescript() {
        let error = decode_carrier("\u{00a0}63\u{00a0}".as_bytes(), Encoding::Hex)
            .expect_err("non-ASCII whitespace must not be accepted as outer padding");
        assert_eq!(
            error.to_string(),
            "Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid."
        );
    }

    #[test]
    fn decodes_standard_reverts_and_preserves_custom_payloads() {
        let mut error = vec![0x08, 0xc3, 0x79, 0xa0];
        error.extend([0u8; 24]);
        error.extend(32u64.to_be_bytes());
        error.extend([0u8; 24]);
        error.extend(2u64.to_be_bytes());
        error.extend(b"no");
        error.extend([0u8; 30]);
        assert_eq!(
            decode_revert(&error),
            Ok(Revert::Error {
                message: Some("no".into())
            })
        );

        let custom = decode_revert(&[0xde, 0xad, 0xbe, 0xef, 1, 2]).unwrap();
        assert_eq!(
            custom,
            Revert::Custom {
                selector: "0xdeadbeef".into(),
                data_hex: "0102".into()
            }
        );
    }

    #[test]
    fn decodes_canonical_empty_error_string() {
        let mut payload = vec![0x08, 0xc3, 0x79, 0xa0];
        payload.extend([0u8; 24]);
        payload.extend(32u64.to_be_bytes());
        payload.extend([0u8; 32]);

        assert_eq!(
            decode_revert(&payload),
            Ok(Revert::Error {
                message: Some(String::new())
            })
        );
    }

    #[test]
    fn preserves_malformed_standard_reverts_as_unknown_payloads() {
        let noncanonical_offset = [
            0x08, 0xc3, 0x79, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64,
        ];
        assert_eq!(
            decode_revert(&noncanonical_offset),
            Ok(Revert::Unknown {
                data_hex: hex(&noncanonical_offset)
            })
        );

        let truncated_panic = [0x4e, 0x48, 0x7b, 0x71, 0x00];
        assert_eq!(
            decode_revert(&truncated_panic),
            Ok(Revert::Unknown {
                data_hex: hex(&truncated_panic)
            })
        );

        let mut oversized = vec![0x08, 0xc3, 0x79, 0xa0];
        oversized.extend([0u8; 31]);
        oversized.push(0x20);
        oversized.extend([0u8; 31]);
        oversized.push(0x20);
        assert_eq!(
            decode_revert(&oversized),
            Ok(Revert::Unknown {
                data_hex: hex(&oversized)
            })
        );

        let mut overflowing_offset = vec![0x08, 0xc3, 0x79, 0xa0];
        overflowing_offset.extend([0xff; 32]);
        assert_eq!(
            decode_revert(&overflowing_offset),
            Ok(Revert::Unknown {
                data_hex: hex(&overflowing_offset)
            })
        );
    }
}
