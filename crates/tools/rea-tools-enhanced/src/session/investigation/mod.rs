//! Shared domain derivations for the Evidence-composed investigation tools
//! (`build_call_path`, `find_changed_behavior`, `correlate_static_and_runtime`,
//! `verify_reconstruction`).
//!
//! Compatibility owners: `src/domain/callPath.ts`, `src/domain/changedBehavior.ts`,
//! `src/domain/staticRuntimeCorrelation.ts`, `src/domain/reconstructionVerification.ts`
//! and the schema and helper modules they consume. The TypeScript source is the
//! oracle; each function below reproduces its parse order, ordering rules,
//! messages and error kinds.

pub(crate) mod call_path;
pub(crate) mod changed_behavior;
pub(crate) mod reconstruction;
pub(crate) mod schemas;
pub(crate) mod static_runtime;

use num_bigint::BigUint;
use serde_json::Value;

/// `nativeAddressInputSchema`: accept equivalent hexadecimal spellings without
/// changing address-space identity, then canonicalize to lowercase `0x…`.
///
/// Pattern: `^(?:(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+:)?0[xX][0-9a-fA-F]+$`.
/// On success returns `"<space>0x<lowercase-hex>"` where the space segment has
/// its `%XX` escapes upper-cased.
pub(crate) fn parse_native_address(input: &str) -> Option<String> {
    // Separator is the character after the last ':'.
    let separator = input.rfind(':').map(|index| index + 1).unwrap_or(0);
    let space_segment = &input[..separator];
    let offset_segment = &input[separator..];
    if !address_space_valid(space_segment) {
        return None;
    }
    // Offset must be 0x/0X followed by one or more hex digits.
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

/// `nativeAddressInputSchema.parse` for a JSON value (string required).
pub(crate) fn parse_native_address_value(value: &Value) -> Option<String> {
    parse_native_address(value.as_str()?)
}

/// The address-space prefix (everything up to and including the final ':', or
/// empty) must match `(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+:` or be empty.
fn address_space_valid(space: &str) -> bool {
    if space.is_empty() {
        return true;
    }
    let body = match space.strip_suffix(':') {
        Some(body) => body,
        None => return false,
    };
    if body.is_empty() {
        return false;
    }
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            if index + 2 >= bytes.len() + 1 {
                return false;
            }
            if index + 3 > bytes.len() {
                return false;
            }
            if !bytes[index + 1].is_ascii_hexdigit() || !bytes[index + 2].is_ascii_hexdigit() {
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

/// Upper-case every `%XX` escape in the address-space segment, as the input
/// schema's `.replace(/%[0-9a-fA-F]{2}/gu, …toUpperCase())` does.
fn uppercase_percent_escapes(space: &str) -> String {
    let bytes = space.as_bytes();
    let mut output = String::with_capacity(space.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit()
        {
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

/// `nativeAddressSchema`: canonical hexadecimal coordinate, retaining its
/// optional address space.
///
/// Pattern: `^(?:(?:[A-Za-z0-9._~-]|%[0-9A-F]{2})+:)?0x(?:0|[1-9a-f][0-9a-f]*)$`.
pub(crate) fn is_canonical_native_address(value: &str) -> bool {
    let separator = value.rfind(':').map(|index| index + 1).unwrap_or(0);
    let space_segment = &value[..separator];
    let offset_segment = &value[separator..];
    if !space_segment.is_empty() {
        let body = match space_segment.strip_suffix(':') {
            Some(body) if !body.is_empty() => body,
            _ => return false,
        };
        let bytes = body.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let byte = bytes[index];
            if byte == b'%' {
                if index + 3 > bytes.len()
                    || !is_upper_hex(bytes[index + 1])
                    || !is_upper_hex(bytes[index + 2])
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
    }
    let Some(digits) = offset_segment.strip_prefix("0x") else {
        return false;
    };
    if digits == "0" {
        return true;
    }
    let bytes = digits.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    if !matches!(bytes[0], b'1'..=b'9' | b'a'..=b'f') {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_upper_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'A'..=b'F')
}

/// `prefixedDigestSchema(prefix)` predicate: `^<prefix>_[a-f0-9]{64}$`.
pub(crate) fn is_prefixed_digest(value: &str, prefix: &str) -> bool {
    let Some(rest) = value.strip_prefix(prefix) else {
        return false;
    };
    let Some(hex) = rest.strip_prefix('_') else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}
