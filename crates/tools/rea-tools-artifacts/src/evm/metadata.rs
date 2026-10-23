//! Terminal Solidity CBOR metadata candidate decoding and the EVMole raw
//! metadata representation.
//!
//! Compatibility owners:
//! - `src/evm/SolidityMetadata.ts` (`inspectSolidityMetadata`,
//!   `BoundedMetadataTokenizer`, `scalar`) — the independent strict decoder
//!   that produces `bytecode.metadata`.
//! - `src/domain/evm/solidityMetadata.ts` (`solidityMetadataSchema`) — the
//!   value shape and ordering retained here.
//! - `~/.cargo/.../evmole-0.9.3/src/metadata.rs` + its `interface_js`
//!   serialization (`CborMetadata`, `CborValue`, `serialize_hex`) — the
//!   `raw_result.metadata` (`reportedMetadata`) representation.
//!
//! The TypeScript worker decodes CBOR with the `cborg` library under strict
//! options: `useMaps`, `allowBigInt`, `allowIndefinite: false`,
//! `allowUndefined: false`, `allowInfinity: false`, `allowNaN: false`,
//! `rejectDuplicateMapKeys: true`, `retainStringBytes: true`, and the
//! `BoundedMetadataTokenizer` additionally rejects CBOR tags and
//! floating-point values, bounds declared collection sizes by the encoded
//! item-byte length, and caps nesting at 64 levels. No CBOR crate is reachable
//! from this crate (adding one would edit the forbidden `Cargo.toml`), so the
//! exact admitted subset is reimplemented here.

use serde_json::{Map, Value, json};

const PROFILE: &str = "terminal-cbor-scalars-v1";
const MAX_DEPTH: usize = 64;

/// One decoded or uninterpreted CBOR scalar (`solidityMetadataScalarSchema`).
#[derive(Clone, Debug)]
enum Scalar {
    Text(String),
    Integer(String),
    Bytes(String),
    Boolean(bool),
    Null,
    Uninterpreted { container: &'static str },
}

impl Scalar {
    fn is_uninterpreted(&self) -> bool {
        matches!(self, Self::Uninterpreted { .. })
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Text(value) => json!({ "kind": "text", "value": value }),
            Self::Integer(value) => json!({ "kind": "integer", "value": value }),
            Self::Bytes(value) => json!({ "kind": "bytes", "value": value }),
            Self::Boolean(value) => json!({ "kind": "boolean", "value": value }),
            Self::Null => json!({ "kind": "null" }),
            Self::Uninterpreted { container } => {
                json!({ "kind": "uninterpreted", "container": container })
            }
        }
    }
}

/// A CBOR value admitted by the bounded strict decoder.
#[derive(Clone, Debug)]
enum Decoded {
    Text(String),
    Integer(i128),
    Bytes(Vec<u8>),
    Boolean(bool),
    Null,
    Map(Vec<(Decoded, Decoded)>),
    Array(Vec<Decoded>),
}

/// `scalar(value)` — the terminal scalar view; nested containers stay
/// uninterpreted, retaining their original byte range in the bytecode.
fn scalar(value: &Decoded) -> Result<Scalar, &'static str> {
    match value {
        Decoded::Text(text) => Ok(Scalar::Text(text.clone())),
        Decoded::Integer(integer) => Ok(Scalar::Integer(integer.to_string())),
        Decoded::Boolean(boolean) => Ok(Scalar::Boolean(*boolean)),
        Decoded::Null => Ok(Scalar::Null),
        Decoded::Bytes(bytes) => Ok(Scalar::Bytes(hex_lower(bytes))),
        Decoded::Map(_) => Ok(Scalar::Uninterpreted { container: "map" }),
        Decoded::Array(_) => Ok(Scalar::Uninterpreted { container: "array" }),
    }
}

/// `inspectSolidityMetadata(bytes)` — parse only a plausible terminal root-map
/// candidate; absence is never established. Returns the ordered
/// `solidityMetadataSchema` value.
pub(crate) fn inspect_solidity_metadata(bytes: &[u8]) -> Value {
    // `empty`: unavailable candidate with no range.
    let empty = || metadata_value(MetadataFacts::unavailable());

    if bytes.len() < 3 {
        return empty();
    }
    let length = usize::from(bytes[bytes.len() - 2]) * 256 + usize::from(bytes[bytes.len() - 1]);
    // `offset = bytes.length - 2 - length` with a non-negative check.
    let Some(offset) = (bytes.len() - 2).checked_sub(length) else {
        return empty();
    };
    // `length === 0 || offset < 0 || bytes[offset] >> 5 !== 5` (major type 5 = map).
    if length == 0 || bytes[offset] >> 5 != 5 {
        return empty();
    }
    let selected = &bytes[offset..bytes.len() - 2];

    let mut facts = MetadataFacts::candidate(offset, length);
    match decode_terminal_map(selected) {
        Ok(entries) => {
            let uninterpreted = entries
                .iter()
                .any(|(key, value)| key.is_uninterpreted() || value.is_uninterpreted());
            facts.status = if uninterpreted { "partial" } else { "decoded" };
            facts.diagnostic = if uninterpreted {
                Some(
                    "Nested containers are uninterpreted; their exact bytes remain at the recorded range in original bytecode."
                        .to_owned(),
                )
            } else {
                None
            };
            facts.compiler_version = compiler_version(&entries);
            facts.entries = entries;
            metadata_value(facts)
        }
        Err(message) => {
            // `status: "not-decoded"`, cleared entries/compiler, truncated diagnostic.
            facts.status = "not-decoded";
            facts.entries = Vec::new();
            facts.compiler_version = None;
            facts.diagnostic = Some(slice_chars(message, 512));
            metadata_value(facts)
        }
    }
}

/// `raw.get("solc")` projection: three release bytes, else non-empty text.
fn compiler_version(entries: &[(Scalar, Scalar)]) -> Option<CompilerVersion> {
    // cborg's Map with `rejectDuplicateMapKeys` keeps distinct keys; the first
    // matching `solc` entry is used (`Map.get` returns the inserted value).
    let value = entries
        .iter()
        .find(|(key, _)| matches!(key, Scalar::Text(text) if text == "solc"))
        .map(|(_, value)| value)?;
    match value {
        // `version instanceof Uint8Array && version.length === 3`.
        Scalar::Bytes(hex) if hex.len() == 6 => {
            let parts: Vec<String> = hex
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    let high = (pair[0] as char).to_digit(16).unwrap_or(0);
                    let low = (pair[1] as char).to_digit(16).unwrap_or(0);
                    (high * 16 + low).to_string()
                })
                .collect();
            Some(CompilerVersion {
                representation: "release-bytes",
                value: parts.join("."),
            })
        }
        // `typeof version === "string" && version.length > 0`.
        Scalar::Text(text) if !text.is_empty() => Some(CompilerVersion {
            representation: "prerelease-text",
            value: text.clone(),
        }),
        _ => None,
    }
}

struct CompilerVersion {
    representation: &'static str,
    value: String,
}

/// The ordered `solidityMetadataSchema` facts.
struct MetadataFacts {
    status: &'static str,
    bytecode_offset: Option<usize>,
    cbor_bytes: Option<usize>,
    entries: Vec<(Scalar, Scalar)>,
    compiler_version: Option<CompilerVersion>,
    diagnostic: Option<String>,
}

impl MetadataFacts {
    fn unavailable() -> Self {
        Self {
            status: "unavailable",
            bytecode_offset: None,
            cbor_bytes: None,
            entries: Vec::new(),
            compiler_version: None,
            diagnostic: Some(
                "No plausible terminal CBOR map was identified; Solidity origin and metadata absence remain unknown."
                    .to_owned(),
            ),
        }
    }

    fn candidate(offset: usize, length: usize) -> Self {
        Self {
            status: "not-decoded",
            bytecode_offset: Some(offset),
            cbor_bytes: Some(length),
            entries: Vec::new(),
            compiler_version: None,
            diagnostic: None,
        }
    }
}

fn metadata_value(facts: MetadataFacts) -> Value {
    let mut object = Map::new();
    object.insert("profile".into(), Value::String(PROFILE.into()));
    object.insert("status".into(), Value::String(facts.status.into()));
    object.insert(
        "bytecode_offset".into(),
        facts
            .bytecode_offset
            .map_or(Value::Null, |offset| json!(offset)),
    );
    object.insert(
        "cbor_bytes".into(),
        facts.cbor_bytes.map_or(Value::Null, |bytes| json!(bytes)),
    );
    object.insert(
        "entries".into(),
        Value::Array(
            facts
                .entries
                .iter()
                .map(|(key, value)| json!({ "key": key.to_json(), "value": value.to_json() }))
                .collect(),
        ),
    );
    object.insert(
        "compiler_version".into(),
        facts.compiler_version.map_or(
            Value::Null,
            |version| json!({ "representation": version.representation, "value": version.value }),
        ),
    );
    object.insert(
        "diagnostic".into(),
        facts.diagnostic.map_or(Value::Null, Value::String),
    );
    Value::Object(object)
}

/// First `max` Unicode scalar values, matching JavaScript `String.slice` on
/// the common (non-surrogate-splitting) metadata diagnostics; Rust strings are
/// already valid UTF-8 so this bounds by characters.
fn slice_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}

// ----------------------------------------------------------------------------
// Bounded strict CBOR decoder (the admitted `cborg`/`BoundedMetadataTokenizer`
// subset). Decodes exactly one top-level item and requires the whole candidate
// to be consumed.
// ----------------------------------------------------------------------------

struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.position
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        if count > self.remaining() {
            return Err("CBOR item extends past the encoded candidate bytes.");
        }
        let slice = &self.data[self.position..self.position + count];
        self.position += count;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, &'static str> {
        Ok(self.take(1)?[0])
    }
}

/// Decode and validate the terminal root map; the whole candidate must parse.
fn decode_terminal_map(candidate: &[u8]) -> Result<Vec<(Scalar, Scalar)>, &'static str> {
    let mut reader = Reader::new(candidate);
    let value = decode_item(&mut reader, 0, candidate.len())?;
    if reader.remaining() != 0 {
        return Err("Terminal CBOR candidate has trailing bytes after the root value.");
    }
    let Decoded::Map(pairs) = value else {
        return Err("Terminal CBOR candidate did not decode to a root map.");
    };
    let mut entries = Vec::with_capacity(pairs.len());
    for (key, value) in &pairs {
        entries.push((scalar(key)?, scalar(value)?));
    }
    Ok(entries)
}

/// Decode one CBOR item under the admitted strict profile.
///
/// `depth` is the number of open collections (the 64-level cap), and `bound`
/// is the encoded item-byte length used to reject declared collection sizes
/// that exceed the candidate (`BoundedMetadataTokenizer`).
fn decode_item(
    reader: &mut Reader<'_>,
    depth: usize,
    bound: usize,
) -> Result<Decoded, &'static str> {
    let initial = reader.byte()?;
    let major = initial >> 5;
    let minor = initial & 0x1f;
    match major {
        // Unsigned integer.
        0 => Ok(Decoded::Integer(i128::from(read_unsigned(reader, minor)?))),
        // Negative integer: -1 - n.
        1 => {
            let magnitude = read_unsigned(reader, minor)?;
            Ok(Decoded::Integer(-1 - i128::from(magnitude)))
        }
        // Byte string.
        2 => Ok(Decoded::Bytes(read_bytes(reader, minor)?)),
        // Text string (strict UTF-8).
        3 => {
            let raw = read_bytes(reader, minor)?;
            let text = String::from_utf8(raw)
                .map_err(|_| "CBOR text bytes were unavailable for strict UTF-8 validation.")?;
            Ok(Decoded::Text(text))
        }
        // Array.
        4 => decode_array(reader, minor, depth, bound),
        // Map.
        5 => decode_map(reader, minor, depth, bound),
        // Tags (major 6) and simple/float (major 7).
        6 => Err("CBOR tags and floating-point values are outside this metadata profile."),
        7 => decode_simple(minor),
        _ => Err("Unknown CBOR major type."),
    }
}

/// Read an unsigned argument; indefinite length is rejected.
fn read_unsigned(reader: &mut Reader<'_>, minor: u8) -> Result<u64, &'static str> {
    match minor {
        0..=23 => Ok(u64::from(minor)),
        24 => Ok(u64::from(reader.byte()?)),
        25 => {
            let bytes = reader.take(2)?;
            Ok(u64::from(u16::from_be_bytes([bytes[0], bytes[1]])))
        }
        26 => {
            let bytes = reader.take(4)?;
            Ok(u64::from(u32::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3],
            ])))
        }
        27 => {
            let bytes = reader.take(8)?;
            Ok(u64::from_be_bytes([
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
            ]))
        }
        // 28–30 are reserved; 31 is indefinite length (rejected: allowIndefinite false).
        31 => Err("Indefinite-length CBOR items are outside this metadata profile."),
        _ => Err("Reserved CBOR additional-information value."),
    }
}

/// Read a definite-length byte or text payload.
fn read_bytes(reader: &mut Reader<'_>, minor: u8) -> Result<Vec<u8>, &'static str> {
    if minor == 31 {
        return Err("Indefinite-length CBOR strings are outside this metadata profile.");
    }
    let length = read_unsigned(reader, minor)?;
    let length = usize::try_from(length)
        .map_err(|_| "Declared CBOR string length exceeds the encoded candidate.")?;
    Ok(reader.take(length)?.to_vec())
}

fn decode_array(
    reader: &mut Reader<'_>,
    minor: u8,
    depth: usize,
    bound: usize,
) -> Result<Decoded, &'static str> {
    if minor == 31 {
        return Err("Indefinite-length CBOR arrays are outside this metadata profile.");
    }
    let count = read_unsigned(reader, minor)?;
    let children = enter_collection(count, 1, depth, bound)?;
    let mut items = Vec::with_capacity(children.min(bound));
    for _ in 0..count {
        items.push(decode_item(reader, depth + 1, bound)?);
    }
    Ok(Decoded::Array(items))
}

fn decode_map(
    reader: &mut Reader<'_>,
    minor: u8,
    depth: usize,
    bound: usize,
) -> Result<Decoded, &'static str> {
    if minor == 31 {
        return Err("Indefinite-length CBOR maps are outside this metadata profile.");
    }
    let count = read_unsigned(reader, minor)?;
    enter_collection(count, 2, depth, bound)?;
    let mut pairs: Vec<(Decoded, Decoded)> = Vec::new();
    for _ in 0..count {
        let key = decode_item(reader, depth + 1, bound)?;
        // `rejectDuplicateMapKeys: true`.
        if pairs
            .iter()
            .any(|(existing, _)| decoded_equal(existing, &key))
        {
            return Err("Duplicate CBOR map key is rejected by the metadata profile.");
        }
        let value = decode_item(reader, depth + 1, bound)?;
        pairs.push((key, value));
    }
    Ok(Decoded::Map(pairs))
}

/// `BoundedMetadataTokenizer`: bound the declared child count by the encoded
/// item-byte length and the 64-level nesting cap.
fn enter_collection(
    count: u64,
    per_item: u64,
    depth: usize,
    bound: usize,
) -> Result<usize, &'static str> {
    let children = count
        .checked_mul(per_item)
        .filter(|children| *children <= bound as u64)
        .ok_or("Declared CBOR collection exceeds the encoded item-byte bound.")?;
    if depth >= MAX_DEPTH {
        return Err("CBOR nesting exceeds the 64-level metadata profile.");
    }
    usize::try_from(children)
        .map_err(|_| "Declared CBOR collection exceeds the encoded item-byte bound.")
}

/// Major type 7: only `false`/`true`/`null` are admitted; `undefined`,
/// floats, NaN and Infinity are rejected (`allowUndefined`/`allowInfinity`/
/// `allowNaN` all false, and the tokenizer rejects floats).
fn decode_simple(minor: u8) -> Result<Decoded, &'static str> {
    match minor {
        20 => Ok(Decoded::Boolean(false)),
        21 => Ok(Decoded::Boolean(true)),
        22 => Ok(Decoded::Null),
        23 => Err("CBOR undefined is outside this metadata profile."),
        25 | 26 | 27 => {
            Err("CBOR tags and floating-point values are outside this metadata profile.")
        }
        _ => Err("Unsupported CBOR simple value in the metadata profile."),
    }
}

/// Structural equality for duplicate-map-key detection.
fn decoded_equal(left: &Decoded, right: &Decoded) -> bool {
    match (left, right) {
        (Decoded::Text(a), Decoded::Text(b)) => a == b,
        (Decoded::Integer(a), Decoded::Integer(b)) => a == b,
        (Decoded::Bytes(a), Decoded::Bytes(b)) => a == b,
        (Decoded::Boolean(a), Decoded::Boolean(b)) => a == b,
        (Decoded::Null, Decoded::Null) => true,
        (Decoded::Array(a), Decoded::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(x, y)| decoded_equal(x, y))
        }
        (Decoded::Map(a), Decoded::Map(b)) => {
            a.len() == b.len()
                && a.iter()
                    .zip(b)
                    .all(|((ak, av), (bk, bv))| decoded_equal(ak, bk) && decoded_equal(av, bv))
        }
        _ => false,
    }
}

// ----------------------------------------------------------------------------
// EVMole raw metadata representation (`reportedMetadata` in the adapter).
// ----------------------------------------------------------------------------

/// Project EVMole's own `CborMetadata` into the exact JSON the JS binding
/// returns (`interface_js` with the `javascript` feature): byte and undecoded
/// values become lowercase hex strings. Our dependency enables only the
/// `serde` feature, so the hex encoding is reproduced here rather than relying
/// on the feature-gated `serialize_hex`.
pub(crate) fn reported_metadata(metadata: &evmole::CborMetadata) -> Value {
    let entries: Vec<Value> = metadata
        .entries
        .iter()
        .map(|entry| {
            json!({
                "key": entry.key,
                "value": reported_value(&entry.value),
            })
        })
        .collect();
    json!({
        "bytecodeOffset": metadata.bytecode_offset,
        "cborLength": metadata.cbor_length,
        "entries": entries,
    })
}

fn reported_value(value: &evmole::CborValue) -> Value {
    match value {
        evmole::CborValue::String(text) => json!({ "type": "string", "value": text }),
        evmole::CborValue::Integer(integer) => json!({ "type": "integer", "value": integer }),
        evmole::CborValue::Bool(boolean) => json!({ "type": "bool", "value": boolean }),
        evmole::CborValue::Bytes(bytes) => {
            json!({ "type": "bytes", "value": hex_lower(bytes) })
        }
        evmole::CborValue::Undecoded(bytes) => {
            json!({ "type": "undecoded", "value": hex_lower(bytes) })
        }
    }
}
