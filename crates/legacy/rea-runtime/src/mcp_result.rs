//! Lossless MCP result encoding. The SDK-independent wire owner preserves raw
//! JSON text (including lone UTF-16 units) without a serde_json::Value conversion.
use rea_core::json_output;
use serde::Serialize;
use std::{
    fmt,
    io::{self, Write},
};

/// Existing REA/SDK default receive budget; the response reserves 1024 bytes for
/// JSON-RPC framing. Explicit server configuration may choose a different budget.
pub const DEFAULT_RECEIVE_BYTES: usize = 10 * 1024 * 1024;
const TARGET_META: &[u8] =
    br#","_meta":{"provenance":{"untrusted_content":true,"source":"analysis_target"}}"#;

#[derive(Debug)]
pub enum EncodeError {
    Io(io::Error),
    Json(serde_json::Error),
}
impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(f),
            Self::Json(error) => error.fmt(f),
        }
    }
}
impl std::error::Error for EncodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Io(error) => error,
            Self::Json(error) => error,
        })
    }
}
impl From<io::Error> for EncodeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
impl From<serde_json::Error> for EncodeError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

/// The two distinct wire representations owned by REA. Errors deliberately do
/// not advertise structuredContent; successful tool outputs carry both copies.
#[derive(Clone, Copy)]
pub enum Representation {
    Success,
    Failure,
}

/// A borrowed immutable payload. For failures, pass the canonical `{error: ...}`
/// projection, not the bare error; neither codec path reinterprets domain facts.
pub struct ToolResult<'a, T: Serialize + ?Sized> {
    pub value: &'a T,
    pub representation: Representation,
    pub target_content: bool,
}
impl<T: Serialize + ?Sized> ToolResult<'_, T> {
    /// Account for both copies and the complete untrusted-content marker.
    pub fn admitted_length(
        &self,
        maximum: usize,
    ) -> Result<usize, json_output::Error<EncodeError>> {
        json_output::admitted_encoding_length(maximum, |writer| self.write(writer))
    }
    /// Write an already admitted result. I/O failure remains observable to the
    /// transport; it must not append another response to a partially written one.
    pub fn write(&self, writer: &mut dyn Write) -> Result<(), EncodeError> {
        writer.write_all(br#"{"content":[{"type":"text","text":""#)?;
        serde_json::to_writer(CompactJson::new(EscapedText(writer)), self.value)?;
        writer.write_all(br#""}]"#)?;
        match self.representation {
            Representation::Success => {
                writer.write_all(br#","structuredContent":"#)?;
                serde_json::to_writer(CompactJson::new(&mut *writer), self.value)?;
            }
            Representation::Failure => writer.write_all(br#","isError":true"#)?,
        }
        if self.target_content {
            writer.write_all(TARGET_META)?;
        }
        writer.write_all(b"}")?;
        Ok(())
    }
}

// RawValue may contain valid pretty-printed JSON. Compact only insignificant
// whitespace so a raw nested document cannot introduce extra stdio frames.
// This lexer consumes already validated serializer output, not unknown input.
struct CompactJson<W> {
    writer: W,
    in_string: bool,
    escaped: bool,
}
impl<W: Write> CompactJson<W> {
    fn new(writer: W) -> Self {
        Self {
            writer,
            in_string: false,
            escaped: false,
        }
    }
}
impl<W: Write> Write for CompactJson<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if self.in_string {
                if self.escaped {
                    self.escaped = false;
                } else if byte == b'\\' {
                    self.escaped = true;
                } else if byte == b'"' {
                    self.in_string = false;
                }
            } else if byte == b'"' {
                self.in_string = true;
            } else if matches!(byte, b' ' | b'\t' | b'\r' | b'\n') {
                self.writer.write_all(&bytes[start..index])?;
                start = index + 1;
            }
        }
        self.writer.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// JSON-string escaping around an already serialized JSON document. UTF-8 byte
/// runs pass through unchanged, even when the inner writer splits a code point.
struct EscapedText<'a>(&'a mut dyn Write);
impl Write for EscapedText<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        for (index, byte) in bytes.iter().copied().enumerate() {
            if byte >= 0x20 && byte != b'"' && byte != b'\\' {
                continue;
            }
            self.0.write_all(&bytes[start..index])?;
            match byte {
                b'"' => self.0.write_all(br#"\""#)?,
                b'\\' => self.0.write_all(br#"\\"#)?,
                8 => self.0.write_all(br"\b")?,
                9 => self.0.write_all(br"\t")?,
                10 => self.0.write_all(br"\n")?,
                12 => self.0.write_all(br"\f")?,
                13 => self.0.write_all(br"\r")?,
                byte => {
                    const HEX: &[u8] = b"0123456789abcdef";
                    self.0.write_all(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(byte >> 4) as usize],
                        HEX[(byte & 15) as usize],
                    ])?;
                }
            }
            start = index + 1;
        }
        self.0.write_all(&bytes[start..])?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}
