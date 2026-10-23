//! Bounded newline framing for the TypeScript-compatible Ghidra Rust worker.
//!
//! Framing owns byte accumulation and JSON decoding only.  It deliberately
//! leaves protocol-specific interpretation to the protocol module and returns
//! each decoded JSON value to its caller.

use serde_json::Value;

use crate::ghidra_rust::protocol::MAX_FRAME_BYTES;

const INITIAL_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FrameError {
    ExceedsBudget,
    InvalidUtf8(String),
    InvalidJson(String),
    Unterminated,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExceedsBudget => {
                formatter.write_str("Rust worker output exceeds the 8 MiB frame budget.")
            }
            Self::InvalidUtf8(message) => {
                write!(formatter, "invalid UTF-8 in worker frame: {message}")
            }
            Self::InvalidJson(message) => {
                write!(formatter, "invalid JSON in worker frame: {message}")
            }
            Self::Unterminated => {
                formatter.write_str("Rust worker output ended without a newline.")
            }
        }
    }
}

impl std::error::Error for FrameError {}

/// Accumulates newline-delimited worker output without exceeding the frame cap.
#[derive(Debug)]
pub struct GhidraRustFrames {
    buffer: Vec<u8>,
    length: usize,
}

impl Default for GhidraRustFrames {
    fn default() -> Self {
        Self::new()
    }
}

impl GhidraRustFrames {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(INITIAL_BUFFER_BYTES),
            length: 0,
        }
    }

    /// Accepts arbitrary output fragments and returns every complete JSON line.
    pub fn accept(&mut self, chunk: &[u8]) -> Result<Vec<Value>, FrameError> {
        let mut offset = 0;
        let mut frames = Vec::new();

        while offset < chunk.len() {
            let end = chunk[offset..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(chunk.len(), |index| offset + index);
            self.append(&chunk[offset..end])?;

            if end == chunk.len() {
                break;
            }

            frames.push(self.decode_complete_frame()?);
            offset = end + 1;
        }

        Ok(frames)
    }

    pub fn finish(&self) -> Result<(), FrameError> {
        if self.length == 0 {
            return Ok(());
        }

        Err(FrameError::Unterminated)
    }

    pub fn dispose(&mut self) {
        self.buffer = Vec::new();
        self.length = 0;
    }

    fn append(&mut self, fragment: &[u8]) -> Result<(), FrameError> {
        let required = self
            .length
            .checked_add(fragment.len())
            .ok_or(FrameError::ExceedsBudget)?;
        let exceeds_budget = required
            .checked_add(1)
            .map_or(true, |size| size > MAX_FRAME_BYTES);
        if exceeds_budget {
            return Err(FrameError::ExceedsBudget);
        }

        self.grow(required);
        self.buffer.extend_from_slice(fragment);
        self.length = required;
        Ok(())
    }

    fn grow(&mut self, required: usize) {
        if required <= self.buffer.capacity() {
            return;
        }

        let doubled = self.buffer.capacity().saturating_mul(2);
        let capacity = MAX_FRAME_BYTES.min(required.max(doubled));
        self.buffer.reserve_exact(capacity - self.buffer.capacity());
    }

    fn decode_complete_frame(&mut self) -> Result<Value, FrameError> {
        let frame = &self.buffer[..self.length];
        let text = std::str::from_utf8(frame)
            .map_err(|error| FrameError::InvalidUtf8(error.to_string()))?
            .to_owned();

        self.length = 0;
        self.buffer.clear();

        serde_json::from_str(&text).map_err(|error| FrameError::InvalidJson(error.to_string()))
    }
}
