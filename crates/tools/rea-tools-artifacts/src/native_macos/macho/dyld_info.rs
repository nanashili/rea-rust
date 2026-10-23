//! Port of `src/native/parsers/dyldInfo.ts`.
//!
//! Decodes Apple dyld inventory rows, projecting export offsets to VM
//! addresses.

use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

/// One decoded dyld inventory row (`ParsedDyldSymbol`).
#[derive(Clone, Debug)]
pub(crate) struct ParsedDyldSymbol {
    pub name: String,
    pub address: Option<String>,
    pub weak: Option<bool>,
    pub reexport: Option<bool>,
    pub source: Option<String>,
    /// The source library's name for a symbol it re-exports under another name.
    pub source_symbol: Option<String>,
}

/// Symbol parsing mode (`imports` or `exports`).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DyldMode {
    Imports,
    Exports,
}

fn offset_header_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?m)^\s*offset\s+symbol\s*$").expect("valid"))
}

fn import_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)^(?:0x[\da-f]+\s+)?(.+?)(?:\s+\[([^\]]+)\])?\s+\(from (.+)\)$")
            .expect("valid")
    })
}

fn export_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(0x[\da-f]+)\s+(.+?)(?:\s+\[([^\]]+)\])?$").expect("valid"))
}

fn export_raw_name_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^0x[\da-f]+\s+(.+)$").expect("valid"))
}

fn word_boundary_contains(haystack: &str, needle: &str) -> bool {
    // `\b<needle>\b` tests. The needles used are alphanumeric/`-` tokens, so a
    // simple scan honoring ASCII word boundaries is faithful.
    let bytes = haystack.as_bytes();
    let needle_bytes = needle.as_bytes();
    if needle_bytes.is_empty() {
        return false;
    }
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let mut start = 0;
    while let Some(position) = haystack[start..].find(needle) {
        let absolute = start + position;
        let before_ok = absolute == 0 || !is_word(bytes[absolute - 1]);
        let after_index = absolute + needle_bytes.len();
        let after_ok = after_index >= bytes.len() || !is_word(bytes[after_index]);
        if before_ok && after_ok {
            return true;
        }
        start = absolute + 1;
    }
    false
}

/// `parseDyldSymbols(output, mode, imageBase, knownExportNames)`.
pub(crate) fn parse_dyld_symbols(
    output: &str,
    mode: DyldMode,
    image_base: Option<&str>,
    known_export_names: &HashSet<String>,
) -> Vec<ParsedDyldSymbol> {
    let offsets = offset_header_re().is_match(output);
    let mut rows = Vec::new();
    for raw_line in split_lines(output) {
        let line = raw_line.trim();
        match mode {
            DyldMode::Imports => {
                if let Some(captures) = import_re().captures(line) {
                    let name = captures.get(1).map(|matched| matched.as_str());
                    if let Some(name) = name {
                        let annotation = captures.get(2).map_or("", |matched| matched.as_str());
                        rows.push(ParsedDyldSymbol {
                            name: name.to_owned(),
                            address: None,
                            weak: if word_boundary_contains(annotation, "weak-import") {
                                Some(true)
                            } else {
                                None
                            },
                            reexport: None,
                            source: captures.get(3).map(|matched| matched.as_str().to_owned()),
                            source_symbol: None,
                        });
                    }
                }
            }
            DyldMode::Exports => {
                if let Some(parsed) =
                    parse_export_row(line, offsets, image_base, known_export_names)
                {
                    rows.push(parsed);
                }
            }
        }
    }
    rows
}

fn parse_export_row(
    line: &str,
    offsets: bool,
    image_base: Option<&str>,
    known_export_names: &HashSet<String>,
) -> Option<ParsedDyldSymbol> {
    if let Some(reexport) = parse_reexport_row(line, known_export_names) {
        return Some(ParsedDyldSymbol {
            name: reexport.name,
            address: None,
            weak: None,
            reexport: Some(true),
            source: reexport.source,
            source_symbol: reexport.source_symbol,
        });
    }
    let captures = export_re().captures(line)?;
    let group1 = captures.get(1)?;
    let group2 = captures.get(2)?;
    let group3 = captures.get(3);
    let raw_name = export_raw_name_re()
        .captures(line)
        .and_then(|caps| caps.get(1).map(|matched| matched.as_str().to_owned()));
    let literal_name = raw_name
        .as_deref()
        .is_some_and(|name| known_export_names.contains(name));
    // If nm establishes both interpretations, the textual row cannot bind an
    // address or flags. Let the caller retain the exact nm names.
    if literal_name && group3.is_some() && known_export_names.contains(group2.as_str()) {
        return None;
    }
    let annotation = if literal_name {
        None
    } else {
        group3.map(|matched| matched.as_str())
    };
    let absolute = annotation
        .map(|value| word_boundary_contains(value, "absolute"))
        .unwrap_or(false);
    let address = if offsets && !absolute {
        match image_base {
            None => None,
            Some(base) => Some(add_hex(base, group1.as_str())),
        }
    } else {
        canonical_hex(group1.as_str())
    };
    let name = if literal_name {
        raw_name.expect("literal name implies raw name")
    } else {
        group2.as_str().to_owned()
    };
    Some(ParsedDyldSymbol {
        name,
        address,
        weak: if annotation
            .map(|value| word_boundary_contains(value, "weak-def"))
            .unwrap_or(false)
        {
            Some(true)
        } else {
            None
        },
        reexport: Some(false),
        source: None,
        source_symbol: None,
    })
}

/// `0x${(BigInt(imageBase) + BigInt(offset)).toString(16)}`.
fn add_hex(image_base: &str, offset: &str) -> String {
    let base = parse_hex_u128(image_base).unwrap_or(0);
    let delta = parse_hex_u128(offset).unwrap_or(0);
    format!("0x{:x}", base.wrapping_add(delta))
}

/// `0x${BigInt(value).toString(16)}`.
fn canonical_hex(value: &str) -> Option<String> {
    parse_hex_u128(value).map(|parsed| format!("0x{parsed:x}"))
}

fn parse_hex_u128(value: &str) -> Option<u128> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u128::from_str_radix(digits, 16).ok()
}

struct ReexportRow {
    name: String,
    source: Option<String>,
    source_symbol: Option<String>,
}

/// `parseReexportRow(line, knownNames)`.
fn parse_reexport_row(line: &str, known_names: &HashSet<String>) -> Option<ReexportRow> {
    let rest = line.strip_prefix("[re-export]")?;
    // `^\[re-export\]\s+`: at least one whitespace must follow.
    let trimmed = rest.trim_start_matches([' ', '\t', '\r', '\n', '\u{000b}', '\u{000c}']);
    if trimmed.len() == rest.len() {
        // No whitespace was consumed; the prefix did not match `\s+`.
        return None;
    }
    let rest = trimmed;
    if rest.is_empty() {
        return None;
    }
    if !rest.ends_with(')') {
        return Some(ReexportRow {
            name: rest.to_owned(),
            source: None,
            source_symbol: None,
        });
    }
    let mut candidates: Vec<ReexportRow> = Vec::new();
    // `rest.matchAll(/\s+\(/gu)`: each run of whitespace immediately before `(`.
    for marker in whitespace_paren_markers(rest) {
        let name = &rest[..marker.start];
        if !known_names.contains(name) {
            continue;
        }
        // Inner text between the `(` and the final `)`.
        let inner = &rest[marker.end..rest.len() - 1];
        if let Some(parsed) = reexport_suffix(name, inner) {
            candidates.push(parsed);
        }
    }
    // Exact nm identities establish a boundary even when names contain
    // parentheses. Competing known interpretations remain unknown.
    if !candidates.is_empty() {
        if candidates.len() == 1 {
            return candidates.into_iter().next();
        }
        return None;
    }
    if known_names.contains(rest) {
        return Some(ReexportRow {
            name: rest.to_owned(),
            source: None,
            source_symbol: None,
        });
    }
    let chars: Vec<(usize, char)> = rest.char_indices().collect();
    let mut depth = 0i64;
    for position in (0..chars.len()).rev() {
        let (byte_index, character) = chars[position];
        if character == ')' {
            depth += 1;
        } else if character == '(' {
            depth -= 1;
            if depth == 0 {
                // Must be preceded by whitespace and not be at index 0.
                if position == 0 {
                    break;
                }
                let (_, previous) = chars[position - 1];
                if !previous.is_whitespace() {
                    break;
                }
                let name = rest[..byte_index].trim_end().to_owned();
                let inner = &rest[byte_index + character.len_utf8()..rest.len() - 1];
                return Some(reexport_suffix(&name, inner).unwrap_or(ReexportRow {
                    name: rest.to_owned(),
                    source: None,
                    source_symbol: None,
                }));
            }
        }
    }
    Some(ReexportRow {
        name: rest.to_owned(),
        source: None,
        source_symbol: None,
    })
}

struct WhitespaceParenMarker {
    /// Byte index of the first whitespace character of the run.
    start: usize,
    /// Byte index just past the `(`.
    end: usize,
}

/// Every `\s+\(` match in `rest`, reported as `(start, end)` byte ranges.
/// `matchAll` consumes each match, so overlapping runs cannot double-report.
fn whitespace_paren_markers(rest: &str) -> Vec<WhitespaceParenMarker> {
    let mut markers = Vec::new();
    let chars: Vec<(usize, char)> = rest.char_indices().collect();
    let mut index = 0;
    while index < chars.len() {
        let (byte_index, character) = chars[index];
        if character.is_whitespace() {
            let run_start = byte_index;
            let mut cursor = index;
            while cursor < chars.len() && chars[cursor].1.is_whitespace() {
                cursor += 1;
            }
            if cursor < chars.len() && chars[cursor].1 == '(' {
                let paren = chars[cursor].0;
                markers.push(WhitespaceParenMarker {
                    start: run_start,
                    end: paren + '('.len_utf8(),
                });
                index = cursor + 1;
                continue;
            }
            index = cursor;
            continue;
        }
        index += 1;
    }
    markers
}

/// `reexportSuffix(name, inner)`.
fn reexport_suffix(name: &str, inner: &str) -> Option<ReexportRow> {
    if name.is_empty() {
        return None;
    }
    if let Some(source) = inner.strip_prefix("from ")
        && inner.len() > 5
    {
        return Some(ReexportRow {
            name: name.to_owned(),
            source: Some(source.to_owned()),
            source_symbol: None,
        });
    }
    // `/\s+from /`: first whitespace run followed by `from `.
    let separator = find_from_separator(inner)?;
    let source_symbol = &inner[..separator.start];
    let source = &inner[separator.end..];
    if !source_symbol.is_empty() && !source.is_empty() {
        Some(ReexportRow {
            name: name.to_owned(),
            source: Some(source.to_owned()),
            source_symbol: Some(source_symbol.to_owned()),
        })
    } else {
        None
    }
}

struct Separator {
    start: usize,
    end: usize,
}

/// First `\s+from ` occurrence, reported as byte offsets of the whole match.
fn find_from_separator(inner: &str) -> Option<Separator> {
    let chars: Vec<(usize, char)> = inner.char_indices().collect();
    let mut index = 0;
    while index < chars.len() {
        let (byte_index, character) = chars[index];
        if character.is_whitespace() {
            let run_start = byte_index;
            let mut cursor = index;
            while cursor < chars.len() && chars[cursor].1.is_whitespace() {
                cursor += 1;
            }
            let rest_start = if cursor < chars.len() {
                chars[cursor].0
            } else {
                inner.len()
            };
            if inner[rest_start..].starts_with("from ") {
                return Some(Separator {
                    start: run_start,
                    end: rest_start + "from ".len(),
                });
            }
            index = cursor;
            continue;
        }
        index += 1;
    }
    None
}

/// Split on `\r?\n`, matching JavaScript `split(/\r?\n/u)`.
fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\n' {
            let end = if index > start && bytes[index - 1] == b'\r' {
                index - 1
            } else {
                index
            };
            lines.push(&text[start..end]);
            start = index + 1;
        }
        index += 1;
    }
    lines.push(&text[start..]);
    lines
}
