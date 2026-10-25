//! Rendered terminal frames under a cumulative byte budget.
//!
//! Compatibility owner: `TerminalRenderer.ts`. One frame is captured after
//! each parsed PTY chunk and after each resize; a frame whose normalized
//! lines and serialized state do not fit the remaining `output_bytes` budget
//! is omitted whole and counted.

use super::normalize::{Bounded, Normalizer};
use rea_host::process::terminal::{TerminalScreen, TerminalSize};
use serde_json::{Map, Value, json};

pub struct Renderer {
    screen: TerminalScreen,
    max_bytes: u64,
    frames: Vec<Value>,
    captured_bytes: u64,
    observed_bytes: u64,
    observed_frames: u64,
    unknown_size_frames: u64,
}

fn trailing_space_bytes(line: &str) -> u64 {
    (line.len() - line.trim_end_matches(' ').len()) as u64
}

impl Renderer {
    pub fn new(columns: u16, rows: u16, scrollback: usize, max_bytes: u64) -> Self {
        let size = TerminalSize::new(columns, rows).expect("validated terminal size");
        Self {
            screen: TerminalScreen::new(size, scrollback),
            max_bytes,
            frames: Vec::new(),
            captured_bytes: 0,
            observed_bytes: 0,
            observed_frames: 0,
            unknown_size_frames: 0,
        }
    }

    /// Parse decoded PTY text and capture; returns the frame sequence when retained.
    pub fn write(
        &mut self,
        text: &str,
        at_ms: u64,
        normalizer: &Normalizer,
        root_pid: i64,
    ) -> Option<usize> {
        self.screen.write_text(text);
        self.capture(at_ms, normalizer, root_pid)
    }

    pub fn resize(
        &mut self,
        columns: u16,
        rows: u16,
        at_ms: u64,
        normalizer: &Normalizer,
        root_pid: i64,
    ) -> Option<usize> {
        if let Some(size) = TerminalSize::new(columns, rows) {
            self.screen.resize(size);
        }
        self.capture(at_ms, normalizer, root_pid)
    }

    fn capture(&mut self, at_ms: u64, normalizer: &Normalizer, root_pid: i64) -> Option<usize> {
        let snapshot = self.screen.snapshot();
        self.observed_frames += 1;
        let mut remaining = self.max_bytes.saturating_sub(self.captured_bytes);
        let mut bytes = 0;
        let mut lines = Vec::with_capacity(snapshot.lines.len());
        for padded in &snapshot.lines {
            let budget = remaining.saturating_add(trailing_space_bytes(padded));
            let Bounded::Normalized(normalized) = normalizer.bounded(padded, budget, root_pid)
            else {
                self.unknown_size_frames += 1;
                return None;
            };
            let line = normalized.trim_end_matches(' ').to_owned();
            let line_bytes = line.len() as u64;
            if line_bytes > remaining {
                self.unknown_size_frames += 1;
                return None;
            }
            remaining -= line_bytes;
            bytes += line_bytes;
            lines.push(Value::String(line));
        }
        let Bounded::Normalized(state) =
            normalizer.bounded(&snapshot.serialized_state, remaining, root_pid)
        else {
            self.unknown_size_frames += 1;
            return None;
        };
        bytes += state.len() as u64;
        self.observed_bytes += bytes;
        self.captured_bytes += bytes;
        let sequence = self.frames.len();
        self.frames.push(json!({
            "sequence": sequence,
            "at_ms": at_ms,
            "columns": snapshot.columns,
            "rows": snapshot.rows,
            "cursor_x": snapshot.cursor_x,
            "cursor_y": snapshot.cursor_y,
            "active_buffer": snapshot.active_buffer.as_str(),
            "lines": lines,
            "serialized_state": state,
        }));
        Some(sequence)
    }

    pub fn frames(&self) -> Vec<Value> {
        self.frames.clone()
    }

    /// `retention()`.
    pub fn retention(&self) -> Value {
        let mut object = Map::new();
        object.insert("budget_bytes".into(), json!(self.max_bytes));
        object.insert("observed_bytes".into(), json!(self.observed_bytes));
        object.insert("retained_bytes".into(), json!(self.captured_bytes));
        object.insert("observed_frames".into(), json!(self.observed_frames));
        object.insert("retained_frames".into(), json!(self.frames.len()));
        if self.unknown_size_frames > 0 {
            object.insert(
                "unknown_size_frames".into(),
                json!(self.unknown_size_frames),
            );
        }
        Value::Object(object)
    }
}
