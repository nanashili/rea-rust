//! Babel-compatible source positions.
//!
//! oxc spans are UTF-8 byte offsets; every TS consumer reads Babel positions,
//! which are UTF-16 code-unit offsets with 1-based lines and 0-based UTF-16
//! columns. Line terminators follow ECMAScript (`\n`, `\r\n`, `\r`, U+2028,
//! U+2029), as Babel does. This is the only conversion point.

use serde::Serialize;

/// One Babel `Position` (`offset` is Babel `start`/`end`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SourcePosition {
    pub offset: u32,
    pub line: u32,
    pub column: u32,
}

/// A half-open source range in Babel coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SourceRange {
    pub start: SourcePosition,
    pub end: SourcePosition,
}

/// Byte offset to Babel position index for one source text.
///
/// Lookups are `O(log n)`: line starts and non-ASCII characters are indexed
/// once, so per-node conversion stays cheap on minified single-line bundles.
pub struct PositionIndex<'s> {
    source: &'s str,
    /// (byte offset of line start, UTF-16 offset of line start).
    lines: Vec<(usize, u32)>,
    /// (byte offset just after a non-ASCII character, UTF-16 offset there).
    wide: Vec<(usize, u32)>,
}

impl<'s> PositionIndex<'s> {
    pub fn new(source: &'s str) -> Self {
        let mut lines = vec![(0usize, 0u32)];
        let mut wide = Vec::new();
        let mut utf16 = 0u32;
        let mut chars = source.char_indices().peekable();
        while let Some((byte, ch)) = chars.next() {
            utf16 += ch.len_utf16() as u32;
            if !ch.is_ascii() {
                wide.push((byte + ch.len_utf8(), utf16));
            }
            let terminator = match ch {
                '\r' => {
                    if let Some(&(_, '\n')) = chars.peek() {
                        chars.next();
                        utf16 += 1;
                        Some(byte + 2)
                    } else {
                        Some(byte + 1)
                    }
                }
                '\n' => Some(byte + 1),
                '\u{2028}' | '\u{2029}' => Some(byte + ch.len_utf8()),
                _ => None,
            };
            if let Some(next) = terminator {
                lines.push((next, utf16));
            }
        }
        Self {
            source,
            lines,
            wide,
        }
    }

    /// The indexed source text.
    pub fn source(&self) -> &'s str {
        self.source
    }

    /// UTF-16 offset (Babel `start`/`end`) of a UTF-8 byte offset (clamped to
    /// the source, rounded down to a character boundary).
    pub fn utf16_offset(&self, byte: u32) -> u32 {
        let byte = self.boundary(byte);
        let before = self.wide.partition_point(|&(end, _)| end <= byte);
        match before.checked_sub(1).map(|index| self.wide[index]) {
            Some((end, utf16)) => utf16 + (byte - end) as u32,
            None => byte as u32,
        }
    }

    fn boundary(&self, byte: u32) -> usize {
        let mut byte = (byte as usize).min(self.source.len());
        while !self.source.is_char_boundary(byte) {
            byte -= 1;
        }
        byte
    }

    /// Babel position of a UTF-8 byte offset (clamped to the source).
    pub fn position(&self, byte: u32) -> SourcePosition {
        let byte = self.boundary(byte);
        let line = self.lines.partition_point(|&(start, _)| start <= byte) - 1;
        let (_, line_utf16) = self.lines[line];
        let offset = self.utf16_offset(byte as u32);
        SourcePosition {
            offset,
            line: line as u32 + 1,
            column: offset - line_utf16,
        }
    }

    pub fn range(&self, span: oxc_span::Span) -> SourceRange {
        SourceRange {
            start: self.position(span.start),
            end: self.position(span.end),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_utf16_and_ecmascript_terminators() {
        let source = "a\r\nb\u{2028}😀c\rd";
        let index = PositionIndex::new(source);
        let c = source.find('c').unwrap() as u32;
        assert_eq!(
            index.position(c),
            SourcePosition {
                offset: 7,
                line: 3,
                column: 2
            }
        );
        let d = source.find('d').unwrap() as u32;
        assert_eq!(
            index.position(d),
            SourcePosition {
                offset: 9,
                line: 4,
                column: 0
            }
        );
    }

    #[test]
    fn indexed_offsets_match_a_utf16_scan_at_every_boundary() {
        let source = "a😀é\nb\u{2028}c𝒜d\r\n€e";
        let index = PositionIndex::new(source);
        for (byte, _) in source.char_indices().chain([(source.len(), ' ')]) {
            let expected = source[..byte].encode_utf16().count() as u32;
            assert_eq!(index.utf16_offset(byte as u32), expected, "byte {byte}");
            assert_eq!(index.position(byte as u32).offset, expected, "byte {byte}");
        }
        // A byte inside a character rounds down to its start.
        assert_eq!(index.utf16_offset(2), 1);
    }
}
