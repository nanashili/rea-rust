//! Explicit carrier-representation decoding.
//!
//! Compatibility owner: `src/evm/EvmBytecodeCarrier.ts`
//! (`decodeEvmBytecodeCarrier`, `EvmCarrierFailure`).
//!
//! `raw` returns the selected bytes verbatim. `hex` validates the carrier as
//! strict UTF-8 (fatal, BOM retained as content), trims only outer ASCII
//! whitespace (`\x09`–`\x0d`, `\x20`), strips a single optional leading
//! case-insensitive `0x`, requires complete lowercase/uppercase hex byte
//! pairs with no interior separators, and decodes the pairs.

/// `EvmCarrierFailure` (`EvmBytecodeCarrier.ts`): an expected carrier encoding
/// failure, independent of the analysis engine.
#[derive(Debug)]
pub(crate) struct CarrierFailure {
    pub message: &'static str,
}

impl CarrierFailure {
    const fn new(message: &'static str) -> Self {
        Self { message }
    }
}

/// `decodeEvmBytecodeCarrier(bytes, encoding)`.
pub(crate) fn decode_evm_bytecode_carrier(
    bytes: &[u8],
    encoding: Encoding,
) -> Result<Vec<u8>, CarrierFailure> {
    match encoding {
        Encoding::Raw => Ok(bytes.to_vec()),
        Encoding::Hex => decode_hex(bytes),
    }
}

/// Explicitly selected carrier representation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Encoding {
    Raw,
    Hex,
}

impl Encoding {
    /// Stable lowercase display used in Evidence (`input.encoding`).
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Hex => "hex",
        }
    }
}

fn decode_hex(bytes: &[u8]) -> Result<Vec<u8>, CarrierFailure> {
    // `new TextDecoder("utf-8", { fatal: true, ignoreBOM: true })`.
    let text = std::str::from_utf8(bytes)
        .map_err(|_| CarrierFailure::new("Hex carrier must be valid UTF-8."))?;
    // Trim only outer ASCII whitespace `\x09`–`\x0d` and `\x20`
    // (`/^[\x09-\x0d\x20]+|[\x09-\x0d\x20]+$/g`).
    let trimmed = text.trim_matches(is_outer_whitespace);
    // Strip a single optional leading `0x`/`0X` (`/^0x/i`).
    let code = strip_hex_prefix(trimmed);
    // `/^(?:[a-fA-F0-9]{2})*$/`: complete hex byte pairs, no interior separators.
    let code_bytes = code.as_bytes();
    if code_bytes.len() % 2 != 0 || !code_bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(CarrierFailure::new(
            "Hex carrier requires complete hexadecimal byte pairs, an optional 0x prefix and outer ASCII whitespace; interior separators are invalid.",
        ));
    }
    let mut decoded = Vec::with_capacity(code_bytes.len() / 2);
    for pair in code_bytes.chunks_exact(2) {
        let high = hex_value(pair[0]);
        let low = hex_value(pair[1]);
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

/// ASCII whitespace class `[\x09-\x0d\x20]` used by the outer trim.
fn is_outer_whitespace(character: char) -> bool {
    matches!(character, '\u{09}'..='\u{0d}' | '\u{20}')
}

/// Remove at most one leading case-insensitive `0x`, matching `/^0x/i`.
fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}

/// Value of a validated ASCII hex digit.
fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        // Unreachable: callers validate `is_ascii_hexdigit` first.
        _ => 0,
    }
}
