//! Local port of `nativeAddressInputSchema` used by reference comparison.
//!
//! Compatibility owner: `domain/native/nativeAddress.ts` `nativeAddressInputSchema`.
//! Pattern: `^(?:(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$`.
//! On success returns `"<space>0x<lowercase-hex>"` with the space's `%XX`
//! escapes upper-cased. Kept local so the module does not couple to the
//! concurrently-edited investigation tools.

use num_bigint::BigUint;

/// `nativeAddressInputSchema.safeParse(input)` (string).
pub fn parse_native_address(input: &str) -> Option<String> {
    let separator = input.rfind(':').map(|index| index + 1).unwrap_or(0);
    let space_segment = &input[..separator];
    let offset_segment = &input[separator..];
    if !address_space_valid(space_segment) {
        return None;
    }
    let digits = offset_segment
        .strip_prefix("0x")
        .or_else(|| offset_segment.strip_prefix("0X"))?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let value = BigUint::parse_bytes(digits.as_bytes(), 16)?;
    let space = uppercase_percent_escapes(space_segment);
    Some(format!("{space}0x{value:x}"))
}

fn address_space_valid(space: &str) -> bool {
    if space.is_empty() {
        return true;
    }
    let Some(body) = space.strip_suffix(':') else {
        return false;
    };
    if body.is_empty() {
        return false;
    }
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len()
                || !bytes[index + 1].is_ascii_hexdigit()
                || !bytes[index + 2].is_ascii_hexdigit()
            {
                return false;
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-') {
            index += 1;
        } else {
            return false;
        }
    }
    true
}

fn uppercase_percent_escapes(space: &str) -> String {
    let bytes = space.as_bytes();
    let mut output = String::with_capacity(space.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            output.push('%');
            output.push((bytes[index + 1] as char).to_ascii_uppercase());
            output.push((bytes[index + 2] as char).to_ascii_uppercase());
            index += 3;
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}
