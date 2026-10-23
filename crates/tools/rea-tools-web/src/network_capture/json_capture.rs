//! Lossless capture JSON parsing.
//!
//! Compatibility owner: `src/browser/history/CaptureJson.ts`. Materializes
//! upstream JSON events without duplicate folding or numeric rounding: numeric
//! literals are preserved as their exact source text, duplicate object members
//! are rejected, nesting beyond the 64-level budget fails, and only a single
//! permitted UTF-8 BOM is skipped before fatal UTF-8 decoding.
use super::errors::CaptureFormatError;
use super::limits::CAPTURE_DEPTH;
use serde_json::{Number, Value};

/// A parsed JSON value that remembers the exact source lexeme of every number.
///
/// Numbers are kept as their original text so the projection can publish the
/// producer literal independently of its nearest double.
#[derive(Clone, Debug)]
pub enum CaptureJson {
    Null,
    Bool(bool),
    /// `literal` is the exact source text of the JSON number.
    Number {
        literal: String,
    },
    String(String),
    Array(Vec<CaptureJson>),
    /// Ordered object members; duplicate keys are rejected during parsing.
    Object(Vec<(String, CaptureJson)>),
}

/// UTF-8 JSON decoding skips one permitted BOM and rejects malformed bytes.
pub fn decode_capture_text(bytes: &[u8], format: &str) -> Result<String, CaptureFormatError> {
    // `TextDecoder("utf-8", { fatal: true })` skips a single leading BOM.
    let body = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    match std::str::from_utf8(body) {
        Ok(text) => Ok(text.to_owned()),
        Err(_) => Err(CaptureFormatError::new(
            "format",
            format!("{format} is not valid UTF-8 JSON."),
            "",
        )),
    }
}

/// Materialize upstream JSON events without duplicate folding or numeric rounding.
pub fn parse_capture_json(text: &str, format: &str) -> Result<CaptureJson, CaptureFormatError> {
    let mut parser = Parser {
        chars: text.as_bytes(),
        position: 0,
        format,
    };
    parser.skip_ws();
    if parser.at_end() {
        // `allowEmptyContent: false`.
        return Err(parser.malformed());
    }
    let value = parser.parse_value(1)?;
    parser.skip_ws();
    if !parser.at_end() {
        return Err(parser.malformed());
    }
    Ok(value)
}

struct Parser<'a> {
    chars: &'a [u8],
    position: usize,
    format: &'a str,
}

impl Parser<'_> {
    fn at_end(&self) -> bool {
        self.position >= self.chars.len()
    }

    fn peek(&self) -> Option<u8> {
        self.chars.get(self.position).copied()
    }

    fn malformed(&self) -> CaptureFormatError {
        CaptureFormatError::new("format", format!("{} is malformed JSON.", self.format), "")
    }

    fn depth_error(&self) -> CaptureFormatError {
        CaptureFormatError::new(
            "input-limit",
            format!(
                "{} exceeds the 64-level complete-evidence nesting budget.",
                self.format
            ),
            "",
        )
    }

    fn duplicate_error(&self) -> CaptureFormatError {
        CaptureFormatError::new(
            "format",
            format!("{} JSON contains duplicate object members.", self.format),
            "",
        )
    }

    fn skip_ws(&mut self) {
        while let Some(byte) = self.peek() {
            // `jsonc-parser` treats only space, tab, CR and LF as whitespace.
            if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                self.position += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<CaptureJson, CaptureFormatError> {
        if depth > CAPTURE_DEPTH {
            return Err(self.depth_error());
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(CaptureJson::String(self.parse_string()?)),
            Some(b't') => self.parse_keyword("true", CaptureJson::Bool(true)),
            Some(b'f') => self.parse_keyword("false", CaptureJson::Bool(false)),
            Some(b'n') => self.parse_keyword("null", CaptureJson::Null),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => self.parse_number(),
            _ => Err(self.malformed()),
        }
    }

    fn parse_keyword(
        &mut self,
        keyword: &str,
        value: CaptureJson,
    ) -> Result<CaptureJson, CaptureFormatError> {
        let end = self.position + keyword.len();
        if end <= self.chars.len() && &self.chars[self.position..end] == keyword.as_bytes() {
            self.position = end;
            Ok(value)
        } else {
            Err(self.malformed())
        }
    }

    fn parse_number(&mut self) -> Result<CaptureJson, CaptureFormatError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.position += 1;
        }
        // Integer part.
        match self.peek() {
            Some(b'0') => self.position += 1,
            Some(byte) if byte.is_ascii_digit() => {
                while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                    self.position += 1;
                }
            }
            _ => return Err(self.malformed()),
        }
        // Fraction.
        if self.peek() == Some(b'.') {
            self.position += 1;
            if !matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                return Err(self.malformed());
            }
            while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                self.position += 1;
            }
        }
        // Exponent.
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            if !matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                return Err(self.malformed());
            }
            while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
                self.position += 1;
            }
        }
        let literal = std::str::from_utf8(&self.chars[start..self.position])
            .map_err(|_| self.malformed())?
            .to_owned();
        Ok(CaptureJson::Number { literal })
    }

    fn parse_string(&mut self) -> Result<String, CaptureFormatError> {
        // Opening quote.
        self.position += 1;
        let mut result = String::new();
        loop {
            let byte = self.peek().ok_or_else(|| self.malformed())?;
            match byte {
                b'"' => {
                    self.position += 1;
                    return Ok(result);
                }
                b'\\' => {
                    self.position += 1;
                    let escape = self.peek().ok_or_else(|| self.malformed())?;
                    self.position += 1;
                    match escape {
                        b'"' => result.push('"'),
                        b'\\' => result.push('\\'),
                        b'/' => result.push('/'),
                        b'b' => result.push('\u{0008}'),
                        b'f' => result.push('\u{000C}'),
                        b'n' => result.push('\n'),
                        b'r' => result.push('\r'),
                        b't' => result.push('\t'),
                        b'u' => {
                            let code = self.parse_hex4()?;
                            if (0xD800..=0xDBFF).contains(&code) {
                                // High surrogate; expect a trailing low surrogate.
                                if self.peek() == Some(b'\\')
                                    && self.chars.get(self.position + 1) == Some(&b'u')
                                {
                                    self.position += 2;
                                    let low = self.parse_hex4()?;
                                    if (0xDC00..=0xDFFF).contains(&low) {
                                        let combined =
                                            0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                                        result.push(
                                            char::from_u32(combined)
                                                .ok_or_else(|| self.malformed())?,
                                        );
                                    } else {
                                        result.push('\u{FFFD}');
                                        if (0xD800..=0xDBFF).contains(&low) {
                                            result.push('\u{FFFD}');
                                        } else {
                                            result.push(
                                                char::from_u32(low)
                                                    .ok_or_else(|| self.malformed())?,
                                            );
                                        }
                                    }
                                } else {
                                    result.push('\u{FFFD}');
                                }
                            } else if (0xDC00..=0xDFFF).contains(&code) {
                                // Unpaired low surrogate.
                                result.push('\u{FFFD}');
                            } else {
                                result.push(char::from_u32(code).ok_or_else(|| self.malformed())?);
                            }
                        }
                        _ => return Err(self.malformed()),
                    }
                }
                0x00..=0x1F => return Err(self.malformed()),
                _ => {
                    // Copy one UTF-8 scalar verbatim.
                    let rest = &self.chars[self.position..];
                    let text = std::str::from_utf8(rest).map_err(|_| self.malformed())?;
                    let ch = text.chars().next().ok_or_else(|| self.malformed())?;
                    result.push(ch);
                    self.position += ch.len_utf8();
                }
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, CaptureFormatError> {
        if self.position + 4 > self.chars.len() {
            return Err(self.malformed());
        }
        let slice = &self.chars[self.position..self.position + 4];
        let text = std::str::from_utf8(slice).map_err(|_| self.malformed())?;
        let value = u32::from_str_radix(text, 16).map_err(|_| self.malformed())?;
        self.position += 4;
        Ok(value)
    }

    fn parse_array(&mut self, depth: usize) -> Result<CaptureJson, CaptureFormatError> {
        self.position += 1; // '['
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.position += 1;
            return Ok(CaptureJson::Array(items));
        }
        loop {
            let value = self.parse_value(depth + 1)?;
            items.push(value);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.position += 1;
                    self.skip_ws();
                    // `allowTrailingComma: false`.
                    if self.peek() == Some(b']') {
                        return Err(self.malformed());
                    }
                }
                Some(b']') => {
                    self.position += 1;
                    return Ok(CaptureJson::Array(items));
                }
                _ => return Err(self.malformed()),
            }
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<CaptureJson, CaptureFormatError> {
        self.position += 1; // '{'
        let mut members: Vec<(String, CaptureJson)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.position += 1;
            return Ok(CaptureJson::Object(members));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.malformed());
            }
            let key = self.parse_string()?;
            if members.iter().any(|(existing, _)| existing == &key) {
                return Err(self.duplicate_error());
            }
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(self.malformed());
            }
            self.position += 1;
            let value = self.parse_value(depth + 1)?;
            members.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.position += 1;
                    self.skip_ws();
                    if self.peek() == Some(b'}') {
                        return Err(self.malformed());
                    }
                }
                Some(b'}') => {
                    self.position += 1;
                    return Ok(CaptureJson::Object(members));
                }
                _ => return Err(self.malformed()),
            }
        }
    }
}

/// Convert a producer number literal to the nearest JSON number for publication.
///
/// Mirrors `lossless-json` `isSafeNumber`: a literal whose round-trip through a
/// double changes its value is published as `null`; otherwise its nearest
/// double is published.
pub fn reported_number(literal: &str) -> Value {
    match safe_number(literal) {
        Some(number) => Value::Number(number),
        None => Value::Null,
    }
}

/// The nearest double of a literal when the round-trip preserves its value.
pub fn safe_number(literal: &str) -> Option<Number> {
    // Integers within i64 serialize losslessly.
    if let Ok(integer) = literal.parse::<i64>() {
        return Some(Number::from(integer));
    }
    let parsed: f64 = literal.parse().ok()?;
    if !parsed.is_finite() {
        return None;
    }
    if !digits_agree(literal, parsed) {
        return None;
    }
    Number::from_f64(parsed)
}

/// Whether a literal and its nearest double denote the same number.
fn digits_agree(literal: &str, parsed: f64) -> bool {
    let rendered = format!("{parsed}");
    match (literal.parse::<f64>(), rendered.parse::<f64>()) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}
