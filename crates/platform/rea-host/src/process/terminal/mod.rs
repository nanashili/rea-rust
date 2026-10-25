//! Headless terminal-screen owner with xterm.js 6.0.0 semantics.
//!
//! A native port of `@xterm/headless` (parser, input handler, buffers,
//! scrollback, reflow, Unicode 6 widths) and `@xterm/addon-serialize`, so a
//! rendered frame answers what the TypeScript oracle's xterm observer saw.
//! Raw PTY bytes stay authoritative in the PTY owner; this module only
//! reconstructs the rendered state from them. Bytes are decoded like node-pty
//! hands them to xterm (Node `StringDecoder`).
//!
//! Documented residual differences (oracle behavior that is not a rendering
//! state): input-channel replies (DA/DSR/DECRQM/DECRQSS) are not produced;
//! inputs on which xterm throws (e.g. ED 1 on a viewport row past the line
//! list) are applied without the throw; `CSI b` repeats are bounded; OSC 8
//! link ids are reduced to linked/unlinked, the only distinction any
//! observed field exposes.

mod attr;
mod buffer;
mod charsets;
mod circular;
mod core;
mod line;
mod params;
mod parser;
mod reflow;
mod serialize;
mod unicode;
mod utf8;

use std::num::NonZeroU16;

use self::core::Core;
use self::parser::Parser;
use self::serialize::{SerializeInput, serialize};
pub use self::utf8::Utf8Decoder;

/// Terminal dimensions in character cells.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalSize {
    pub columns: NonZeroU16,
    pub rows: NonZeroU16,
}

impl TerminalSize {
    /// Parse caller dimensions; zero is not a terminal size.
    pub fn new(columns: u16, rows: u16) -> Option<Self> {
        Some(Self {
            columns: NonZeroU16::new(columns)?,
            rows: NonZeroU16::new(rows)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActiveBuffer {
    Normal,
    Alternate,
}

impl ActiveBuffer {
    /// The xterm buffer-type spelling used by the public contract.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Alternate => "alternate",
        }
    }
}

/// One rendered observation, field for field what `TerminalRenderer.ts`
/// reads from xterm before normalization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScreenSnapshot {
    pub columns: u16,
    pub rows: u16,
    /// xterm `cursorX`; equals `columns` while a wrap is pending.
    pub cursor_x: u16,
    pub cursor_y: u16,
    pub active_buffer: ActiveBuffer,
    /// Viewport rows as `translateToString(false, 0, cols).padEnd(cols)`
    /// (padding counts UTF-16 units, like JavaScript). Callers normalize
    /// first and trim trailing blanks afterwards, matching the oracle order.
    pub lines: Vec<String>,
    /// `SerializeAddon.serialize()` replay of the whole terminal state.
    pub serialized_state: String,
}

/// Owns one headless terminal.
pub struct TerminalScreen {
    decoder: Utf8Decoder,
    parser: Parser,
    core: Core,
}

impl TerminalScreen {
    pub fn new(size: TerminalSize, scrollback: usize) -> Self {
        Self {
            decoder: Utf8Decoder::default(),
            parser: Parser::default(),
            core: Core::new(
                usize::from(size.columns.get()),
                usize::from(size.rows.get()),
                scrollback,
            ),
        }
    }

    /// Parse one raw PTY chunk. Split UTF-8 and escape sequences carry over.
    pub fn write(&mut self, bytes: &[u8]) {
        let text = self.decoder.write(bytes);
        self.write_text(&text);
    }

    /// Parse text a caller already decoded with [`Utf8Decoder`] (node-pty
    /// hands xterm decoded strings); escape sequences still carry over.
    pub fn write_text(&mut self, text: &str) {
        let codes: Vec<u32> = text.chars().map(u32::from).collect();
        self.parser.parse(&codes, &mut self.core);
    }

    /// xterm `resize` (same size is a no-op; xterm's minimum is 2x1).
    pub fn resize(&mut self, size: TerminalSize) {
        self.core.resize(
            usize::from(size.columns.get()),
            usize::from(size.rows.get()),
        );
    }

    pub fn snapshot(&self) -> ScreenSnapshot {
        let core = &self.core;
        let buffer = core.buffer();
        let cols = core.cols;
        let lines = (0..core.rows)
            .map(|row| {
                let text = buffer
                    .line(buffer.ydisp + row as isize)
                    .map(|line| line.translate_to_string(false, 0, Some(cols)))
                    .unwrap_or_default();
                pad_utf16(text, cols)
            })
            .collect();
        let serialized_state = serialize(&SerializeInput {
            normal: &core.normal,
            alternate: core.alt_active.then_some(&core.alt),
            rows: core.rows,
            cols,
            cur_attr: &core.cur_attr,
            modes: core.modes(),
        });
        ScreenSnapshot {
            columns: clamp_u16(cols as isize),
            rows: clamp_u16(core.rows as isize),
            cursor_x: clamp_u16(buffer.x),
            cursor_y: clamp_u16(buffer.y),
            active_buffer: if core.alt_active {
                ActiveBuffer::Alternate
            } else {
                ActiveBuffer::Normal
            },
            lines,
            serialized_state,
        }
    }
}

fn clamp_u16(value: isize) -> u16 {
    u16::try_from(value.max(0)).unwrap_or(u16::MAX)
}

/// JavaScript `padEnd(cols, " ")`, which measures UTF-16 code units.
fn pad_utf16(mut text: String, cols: usize) -> String {
    let units: usize = text.chars().map(char::len_utf16).sum();
    for _ in units..cols {
        text.push(' ');
    }
    text
}

#[cfg(test)]
mod tests;
