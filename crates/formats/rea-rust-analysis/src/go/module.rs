//! Lossless interpretation of the module records emitted by Go build info.
//!
//! The caller supplies the unframed module body. Invalid UTF-8 records and
//! unsupported text stay visible in the result instead of being discarded.

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GoModule {
    pub path: String,
    pub version: String,
    pub sum: Option<String>,
    pub replacement: Option<Replacement>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Replacement {
    pub path: String,
    pub version: String,
    pub sum: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Setting {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Metadata {
    pub path: Option<String>,
    pub main: Option<GoModule>,
    pub dependencies: Vec<GoModule>,
    pub settings: Vec<Setting>,
    pub unparsed_lines: Vec<String>,
    pub unparsed_line_bytes_base64: Vec<String>,
    pub complete: bool,
}

#[derive(Clone, Copy)]
enum LastModule {
    Main,
    Dependency(usize),
}

struct QuotedValue {
    value: String,
    end: usize,
}

/// Decode Go's module records while preserving unsupported and malformed lines.
pub fn parse(bytes: &[u8]) -> Metadata {
    let mut metadata = Metadata {
        path: None,
        main: None,
        dependencies: Vec::new(),
        settings: Vec::new(),
        unparsed_lines: Vec::new(),
        unparsed_line_bytes_base64: Vec::new(),
        complete: true,
    };
    let mut last_module = None;

    for (line, terminated) in source_lines(bytes) {
        let Ok(line) = std::str::from_utf8(line) else {
            metadata
                .unparsed_line_bytes_base64
                .push(crate::base64::encode(line));
            if is_module_record(line) {
                last_module = None;
            }
            continue;
        };

        if line.is_empty() {
            continue;
        }
        if !terminated {
            metadata.unparsed_lines.push(line.to_owned());
            continue;
        }

        if let Some(path) = line.strip_prefix("path\t") {
            if metadata.path.is_none() {
                metadata.path = Some(path.to_owned());
            } else {
                metadata.unparsed_lines.push(line.to_owned());
            }
            continue;
        }

        if let Some(record) = line.strip_prefix("mod\t") {
            last_module = None;
            if metadata.main.is_none()
                && let Some(module) = parse_module_line(record)
            {
                metadata.main = Some(module);
                last_module = Some(LastModule::Main);
                continue;
            }
            metadata.unparsed_lines.push(line.to_owned());
            continue;
        }

        if let Some(record) = line.strip_prefix("dep\t") {
            last_module = None;
            if let Some(module) = parse_module_line(record) {
                let index = metadata.dependencies.len();
                metadata.dependencies.push(module);
                last_module = Some(LastModule::Dependency(index));
                continue;
            }
            metadata.unparsed_lines.push(line.to_owned());
            continue;
        }

        if let Some(record) = line.strip_prefix("=>\t") {
            if let Some(replacement) = parse_replacement_line(record)
                && let Some(previous) = last_module
            {
                set_replacement(&mut metadata, previous, replacement);
                last_module = None;
                continue;
            }
            last_module = None;
            metadata.unparsed_lines.push(line.to_owned());
            continue;
        }

        if let Some(record) = line.strip_prefix("build\t")
            && let Some(setting) = parse_setting(record)
        {
            metadata.settings.push(setting);
            continue;
        }

        metadata.unparsed_lines.push(line.to_owned());
    }

    metadata.complete =
        metadata.unparsed_lines.is_empty() && metadata.unparsed_line_bytes_base64.is_empty();
    metadata
}

fn source_lines(bytes: &[u8]) -> impl Iterator<Item = (&[u8], bool)> {
    let mut start = 0;
    std::iter::from_fn(move || {
        if start >= bytes.len() {
            return None;
        }

        let newline = bytes[start..].iter().position(|byte| *byte == b'\n');
        let end = newline.map_or(bytes.len(), |offset| start + offset);
        let line = &bytes[start..end];
        start = newline.map_or(bytes.len(), |_| end + 1);
        Some((line, newline.is_some()))
    })
}

fn is_module_record(line: &[u8]) -> bool {
    [b"mod\t".as_slice(), b"dep\t", b"=>\t"]
        .iter()
        .any(|prefix| line.starts_with(prefix))
}

fn parse_module_line(record: &str) -> Option<GoModule> {
    let mut fields = record.split('\t');
    let path = fields.next()?;
    let version = fields.next()?;
    let sum = fields.next();
    if fields.next().is_some() {
        return None;
    }

    Some(GoModule {
        path: path.to_owned(),
        version: version.to_owned(),
        sum: sum.map(str::to_owned),
        replacement: None,
    })
}

fn parse_replacement_line(record: &str) -> Option<Replacement> {
    let mut fields = record.split('\t');
    let path = fields.next()?;
    let version = fields.next()?;
    let sum = fields.next()?;
    if fields.next().is_some() {
        return None;
    }

    Some(Replacement {
        path: path.to_owned(),
        version: version.to_owned(),
        sum: Some(sum.to_owned()),
    })
}

fn set_replacement(metadata: &mut Metadata, last: LastModule, replacement: Replacement) {
    match last {
        LastModule::Main => {
            if let Some(main) = metadata.main.as_mut() {
                main.replacement = Some(replacement);
            }
        }
        LastModule::Dependency(index) => {
            if let Some(dependency) = metadata.dependencies.get_mut(index) {
                dependency.replacement = Some(replacement);
            }
        }
    }
}

fn parse_setting(record: &str) -> Option<Setting> {
    let (key, raw_value) = if record.starts_with('"') || record.starts_with('`') {
        let decoded = parse_quoted(record)?;
        if record.as_bytes().get(decoded.end) != Some(&b'=') {
            return None;
        }
        (decoded.value, &record[decoded.end + 1..])
    } else {
        let separator = record.find('=')?;
        if separator == 0 {
            return None;
        }
        let key = &record[..separator];
        if key.bytes().any(is_forbidden_unquoted_key_byte) {
            return None;
        }
        (key.to_owned(), &record[separator + 1..])
    };

    let value = if raw_value.starts_with('"') || raw_value.starts_with('`') {
        let decoded = parse_quoted(raw_value)?;
        if decoded.end != raw_value.len() {
            return None;
        }
        decoded.value
    } else {
        if raw_value.bytes().any(is_forbidden_unquoted_value_byte) {
            return None;
        }
        raw_value.to_owned()
    };

    Some(Setting { key, value })
}

fn is_forbidden_unquoted_key_byte(byte: u8) -> bool {
    matches!(byte, b'=' | b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'`')
}

fn is_forbidden_unquoted_value_byte(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n' | b'"' | b'`')
}

fn parse_quoted(input: &str) -> Option<QuotedValue> {
    if input.starts_with('`') {
        let end = input.as_bytes()[1..]
            .iter()
            .position(|byte| *byte == b'`')?
            + 1;
        let value = input[1..end].replace('\r', "");
        return Some(QuotedValue {
            value,
            end: end + 1,
        });
    }
    if !input.starts_with('"') {
        return None;
    }

    let bytes = input.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 1;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                let value = String::from_utf8(output).ok()?;
                return Some(QuotedValue {
                    value,
                    end: index + 1,
                });
            }
            b'\n' => return None,
            b'\\' => {
                index = append_escape(bytes, index, &mut output)?;
            }
            _ => {
                let character = input[index..].chars().next()?;
                let width = character.len_utf8();
                output.extend_from_slice(&bytes[index..index + width]);
                index += width;
            }
        }
    }
    None
}

fn append_escape(bytes: &[u8], slash: usize, output: &mut Vec<u8>) -> Option<usize> {
    let escape = *bytes.get(slash + 1)?;
    let simple = match escape {
        b'a' => Some(7),
        b'b' => Some(8),
        b'f' => Some(12),
        b'n' => Some(b'\n'),
        b'r' => Some(b'\r'),
        b't' => Some(b'\t'),
        b'v' => Some(11),
        b'\\' => Some(b'\\'),
        b'"' => Some(b'"'),
        _ => None,
    };
    if let Some(byte) = simple {
        output.push(byte);
        return Some(slash + 2);
    }

    let digits = match escape {
        b'x' => 2,
        b'u' => 4,
        b'U' => 8,
        _ => 0,
    };
    if digits > 0 {
        let value = parse_hex_digits(bytes, slash + 2, digits)?;
        if escape == b'x' {
            output.push(u8::try_from(value).ok()?);
        } else {
            append_unicode_scalar(value, output)?;
        }
        return Some(slash + 2 + digits);
    }

    let octal = bytes.get(slash + 1..slash + 4)?;
    if !octal.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
        return None;
    }
    let value = u16::from(octal[0] - b'0') * 64
        + u16::from(octal[1] - b'0') * 8
        + u16::from(octal[2] - b'0');
    output.push(u8::try_from(value).ok()?);
    Some(slash + 4)
}

fn parse_hex_digits(bytes: &[u8], start: usize, digits: usize) -> Option<u32> {
    let selected = bytes.get(start..start + digits)?;
    if !selected.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    std::str::from_utf8(selected)
        .ok()
        .and_then(|value| u32::from_str_radix(value, 16).ok())
}

fn append_unicode_scalar(value: u32, output: &mut Vec<u8>) -> Option<()> {
    let character = char::from_u32(value)?;
    let mut encoded = [0; 4];
    output.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
    Some(())
}
