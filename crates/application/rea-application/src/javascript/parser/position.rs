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
pub struct PositionIndex<'s> {
    source: &'s str,
    /// (byte offset of line start, UTF-16 offset of line start).
    lines: Vec<(usize, u32)>,
}

impl<'s> PositionIndex<'s> {
    pub fn new(source: &'s str) -> Self {
        let mut lines = vec![(0usize, 0u32)];
        let mut utf16 = 0u32;
        let mut chars = source.char_indices().peekable();
        while let Some((byte, ch)) = chars.next() {
            utf16 += ch.len_utf16() as u32;
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
        Self { source, lines }
    }

    /// Babel position of a UTF-8 byte offset (clamped to the source).
    pub fn position(&self, byte: u32) -> SourcePosition {
        let mut byte = (byte as usize).min(self.source.len());
        while !self.source.is_char_boundary(byte) {
            byte -= 1;
        }
        let line = self.lines.partition_point(|&(start, _)| start <= byte) - 1;
        let (line_start, line_utf16) = self.lines[line];
        let column = self.source[line_start..byte].encode_utf16().count() as u32;
        SourcePosition {
            offset: line_utf16 + column,
            line: line as u32 + 1,
            column,
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
        assert_eq!(index.position(c), SourcePosition { offset: 7, line: 3, column: 2 });
        let d = source.find('d').unwrap() as u32;
        assert_eq!(index.position(d), SourcePosition { offset: 9, line: 4, column: 0 });
    }
}
