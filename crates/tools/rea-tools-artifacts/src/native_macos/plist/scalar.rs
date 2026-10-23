//! XML plist scalar literal parsing.
//!
//! Compatibility owners: `src/domain/propertyListXmlScalar.ts`
//! (`parseXmlPlistIntegerLiteral`, `decodeXmlPlistDateLiteral`,
//! `parseXmlPlistRealLiteral`) and `src/domain/propertyListXmlData.ts`
//! (`decodeXmlPlistData`).

use super::value::UnknownScalarReason;

/// Characters the integer scanner treats as leading whitespace, matching the
/// `INTEGER_WHITESPACE` set. plutil's host rejects U+202F, so it is excluded.
fn is_integer_whitespace(code: u32) -> bool {
    (0x0000..=0x0020).contains(&code)
        || code == 0x007f
        || (0x2000..=0x200b).contains(&code)
        || code == 0x205f
        || code == 0x3000
}

/// Characters the real scanner treats as leading whitespace
/// (`REAL_WHITESPACE`).
fn is_real_whitespace(code: u32) -> bool {
    (0x0000..=0x0020).contains(&code)
        || (0x007f..=0x00a0).contains(&code)
        || (0x2000..=0x200b).contains(&code)
        || code == 0x3000
        || code == 0xfeff
}

fn trim_leading<F: Fn(u32) -> bool>(text: &str, accept: F) -> &str {
    let mut cursor = 0;
    for (index, character) in text.char_indices() {
        if accept(character as u32) {
            cursor = index + character.len_utf8();
        } else {
            break;
        }
    }
    &text[cursor..]
}

/// `parseXmlPlistIntegerLiteral(raw)`: parse CF-style decimal or hexadecimal
/// integer text without losing precision. Returns `None` when the literal does
/// not match the integer grammar.
pub(crate) fn parse_integer_literal(raw: &str) -> Option<i128> {
    // `^WS(?:([+-])WS)?(?:0[xX]([0-9a-fA-F]+)|(\d+))$`
    let mut rest = trim_leading(raw, is_integer_whitespace);
    let mut sign = 1i128;
    if let Some(first) = rest.chars().next()
        && (first == '+' || first == '-')
    {
        if first == '-' {
            sign = -1;
        }
        rest = &rest[1..];
        rest = trim_leading(rest, is_integer_whitespace);
    }
    let magnitude = if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        i128::from_str_radix(hex, 16).ok()?
    } else {
        if rest.is_empty() || !rest.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        rest.parse::<i128>().ok()?
    };
    Some(sign * magnitude)
}

/// `decodeXmlPlistDateLiteral(raw)`: parse UTC date fields without calendar
/// rollover. Returns the ISO-8601 spelling or a distinct unknown reason.
pub(crate) fn parse_date_literal(raw: &str) -> Result<String, UnknownScalarReason> {
    // `^(-?)(\d+)-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$`
    let bytes = raw.as_bytes();
    let mut index = 0;
    let negative = bytes.first() == Some(&b'-');
    if negative {
        index = 1;
    }
    let year_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    if index == year_start {
        return Err(UnknownScalarReason::InvalidLiteral);
    }
    let year_digits = &raw[year_start..index];
    let read_fixed = |cursor: &mut usize, separator: u8, width: usize| -> Option<u32> {
        if bytes.get(*cursor) != Some(&separator) {
            return None;
        }
        *cursor += 1;
        let start = *cursor;
        for _ in 0..width {
            match bytes.get(*cursor) {
                Some(byte) if byte.is_ascii_digit() => *cursor += 1,
                _ => return None,
            }
        }
        raw[start..*cursor].parse::<u32>().ok()
    };
    let Some(month) = read_fixed(&mut index, b'-', 2) else {
        return Err(UnknownScalarReason::InvalidLiteral);
    };
    let Some(day) = read_fixed(&mut index, b'-', 2) else {
        return Err(UnknownScalarReason::InvalidLiteral);
    };
    let Some(hour) = read_fixed(&mut index, b'T', 2) else {
        return Err(UnknownScalarReason::InvalidLiteral);
    };
    let Some(minute) = read_fixed(&mut index, b':', 2) else {
        return Err(UnknownScalarReason::InvalidLiteral);
    };
    let Some(second) = read_fixed(&mut index, b':', 2) else {
        return Err(UnknownScalarReason::InvalidLiteral);
    };
    if bytes.get(index) != Some(&b'Z') || index + 1 != bytes.len() {
        return Err(UnknownScalarReason::InvalidLiteral);
    }

    let year_magnitude: i64 = year_digits
        .parse()
        .map_err(|_| UnknownScalarReason::Unrepresentable)?;
    let year = if negative {
        -year_magnitude
    } else {
        year_magnitude
    };
    // `Number.isSafeInteger(year)` — year magnitude always fits here.
    if !(super::numbers::MIN_SAFE_INTEGER..=super::numbers::MAX_SAFE_INTEGER)
        .contains(&(year as i128))
        || month < 1
        || month > 12
        || hour > 23
        || minute > 59
        || second > 59
    {
        return Err(UnknownScalarReason::Unrepresentable);
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = [
        31,
        if leap_year { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ][(month - 1) as usize];
    if day < 1 || day > days_in_month {
        return Err(UnknownScalarReason::Unrepresentable);
    }
    Ok(format_iso8601(year, month, day, hour, minute, second))
}

/// Render a UTC instant the way `Date.prototype.toISOString` does. The year is
/// zero-padded to at least four digits and uses an expanded `±YYYYYY` form
/// outside the `[0, 9999]` range.
fn format_iso8601(year: i64, month: u32, day: u32, hour: u32, minute: u32, second: u32) -> String {
    let year_text = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    format!("{year_text}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.000Z")
}

/// `parseXmlPlistRealLiteral(raw)`: parse a decimal or CF-spelled non-finite
/// real literal. Returns the numeric value or a distinct unknown reason.
pub(crate) fn parse_real_literal(raw: &str) -> Result<f64, UnknownScalarReason> {
    let text = expand_real_references(raw);
    // CF compares complete non-finite spellings before scanning a decimal.
    if text.len() <= 9 {
        match text.to_ascii_lowercase().as_str() {
            "nan" => return Ok(f64::NAN),
            "+infinity" | "infinity" | "+inf" | "inf" => return Ok(f64::INFINITY),
            "-infinity" | "-inf" => return Ok(f64::NEG_INFINITY),
            _ => {}
        }
    }
    let numeric = trim_leading(&text, is_real_whitespace);
    if !is_decimal_real(numeric) {
        return Err(UnknownScalarReason::InvalidLiteral);
    }
    let value: f64 = numeric
        .parse()
        .map_err(|_| UnknownScalarReason::InvalidLiteral)?;
    if value.is_finite() {
        Ok(value)
    } else {
        Err(UnknownScalarReason::Unrepresentable)
    }
}

/// `^[+-]?(?:(?:\d+(?:\.\d*)?)|(?:\.\d+))(?:[eE][+-]?\d+)?$`
fn is_decimal_real(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        index += 1;
    }
    let integer_start = index;
    while index < bytes.len() && bytes[index].is_ascii_digit() {
        index += 1;
    }
    let has_integer = index > integer_start;
    if has_integer {
        // `\d+(?:\.\d*)?`
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
    } else {
        // `\.\d+`
        if bytes.get(index) != Some(&b'.') {
            return false;
        }
        index += 1;
        let fraction_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == fraction_start {
            return false;
        }
    }
    // `(?:[eE][+-]?\d+)?`
    if matches!(bytes.get(index), Some(b'e' | b'E')) {
        index += 1;
        if matches!(bytes.get(index), Some(b'+' | b'-')) {
            index += 1;
        }
        let exponent_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if index == exponent_start {
            return false;
        }
    }
    index == bytes.len()
}

/// Expand CDATA sections and XML character/named references outside CDATA,
/// mirroring the replacement in `parseXmlPlistRealLiteral`.
fn expand_real_references(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut output = String::with_capacity(raw.len());
    let mut index = 0;
    while index < bytes.len() {
        if raw[index..].starts_with("<![CDATA[") {
            let start = index + "<![CDATA[".len();
            if let Some(relative) = raw[start..].find("]]>") {
                output.push_str(&raw[start..start + relative]);
                index = start + relative + "]]>".len();
                continue;
            }
            // No terminator: the DOM would not have admitted this; copy verbatim.
            output.push_str(&raw[index..]);
            break;
        }
        if bytes[index] == b'&'
            && let Some(expansion) = expand_entity(&raw[index..], &mut index)
        {
            output.push_str(&expansion);
            continue;
        }
        let character = raw[index..].chars().next().unwrap();
        output.push(character);
        index += character.len_utf8();
    }
    output
}

/// Expand one `&...;` reference at the cursor, advancing it past the reference.
fn expand_entity(rest: &str, index: &mut usize) -> Option<String> {
    let end = rest.find(';')?;
    let body = &rest[1..end];
    let expansion = if let Some(hex) = body.strip_prefix("#x").or_else(|| body.strip_prefix("#X")) {
        let code = u32::from_str_radix(hex, 16).ok()?;
        char::from_u32(code)?.to_string()
    } else if let Some(decimal) = body.strip_prefix('#') {
        let code = decimal.parse::<u32>().ok()?;
        char::from_u32(code)?.to_string()
    } else {
        match body {
            "amp" => "&".to_owned(),
            "lt" => "<".to_owned(),
            "gt" => ">".to_owned(),
            "apos" => "'".to_owned(),
            "quot" => "\"".to_owned(),
            _ => return None,
        }
    };
    *index += end + 1;
    Some(expansion)
}

/// `decodeXmlPlistData(text)`: CFPropertyList reads raw ASCII, skips nonalphabet
/// bytes and emits complete base64 quartets. Returns the decoded bytes or the
/// distinct `non-ascii` reason.
pub(crate) fn decode_data(text: &str) -> Result<Vec<u8>, DataError> {
    let mut quartet: u32 = 0;
    let mut digits: usize = 0;
    let mut padding: usize = 0;
    let mut bytes = Vec::new();
    for (offset, character) in text.char_indices() {
        let code = character as u32;
        if code >= 128 {
            let _ = offset;
            return Err(DataError::NonAscii);
        }
        if character == '=' {
            padding += 1;
        } else if !is_c_whitespace(character) {
            padding = 0;
        }
        let digit = if character == '=' {
            0
        } else {
            match base64_digit(character) {
                Some(value) => value,
                None => continue,
            }
        };
        quartet = ((quartet << 6) | u32::from(digit)) & 0x00ff_ffff;
        digits += 1;
        if digits % 4 == 0 {
            let byte_count = if padding >= 2 {
                1
            } else if padding == 1 {
                2
            } else {
                3
            };
            bytes.push((quartet >> 16) as u8);
            if byte_count >= 2 {
                bytes.push((quartet >> 8) as u8);
            }
            if byte_count == 3 {
                bytes.push(quartet as u8);
            }
        }
    }
    Ok(bytes)
}

/// The data decoder failure reasons (`XmlPlistDataError.reason`). Only the
/// `non-ascii` reason is reachable from canonical plutil data elements.
#[derive(Debug)]
pub(crate) enum DataError {
    /// A non-ASCII byte was found in the data literal.
    NonAscii,
}

fn is_c_whitespace(character: char) -> bool {
    matches!(
        character,
        ' ' | '\t' | '\n' | '\u{000b}' | '\u{000c}' | '\r'
    )
}

fn base64_digit(character: char) -> Option<u8> {
    const DIGITS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    DIGITS
        .iter()
        .position(|&byte| byte as char == character)
        .map(|position| position as u8)
}
