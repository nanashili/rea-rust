use std::io::{BufRead, Write};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use crate::encoding::encode_bounded;
use crate::protocol::{MAX_FRAME_BYTES, MAX_REQUEST_BYTES, Request, truncate_utf8};

pub trait Progress {
    fn report(&mut self, label: &str, completed: usize, total: Option<usize>) -> Result<()>;
}

pub struct Transport<W> {
    writer: W,
}

impl<W: Write> Transport<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    pub fn reply(&mut self, id: u64, result: Value) -> Result<()> {
        self.send(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
    }

    pub fn failure(&mut self, id: u64, error: &anyhow::Error) -> Result<()> {
        let mut message = format!("{error:#}");
        truncate_utf8(&mut message, 4096);
        self.send(json!({
            "jsonrpc": "2.0", "id": id,
            "error": {
                "code": -32000,
                "message": message,
                "data": { "error_code": crate::failure::code(error) }
            }
        }))
    }

    fn send(&mut self, frame: Value) -> Result<()> {
        let mut encoded = encode_bounded(&frame, MAX_FRAME_BYTES - 1)?;
        encoded.push(b'\n');
        self.writer
            .write_all(&encoded)
            .context("Write the worker protocol frame")?;
        self.writer
            .flush()
            .context("Flush the worker protocol frame")?;
        Ok(())
    }
}

impl<W: Write> Progress for Transport<W> {
    fn report(&mut self, label: &str, completed: usize, total: Option<usize>) -> Result<()> {
        self.send(json!({
            "jsonrpc": "2.0",
            "method": "analysis/progress",
            "params": { "label": label, "completed": completed, "total": total }
        }))
    }
}

pub fn read_request(reader: &mut impl BufRead) -> Result<Option<Request>> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().context("Read the worker request")?;
        if available.is_empty() {
            ensure!(frame.is_empty(), "Truncated worker request");
            return Ok(None);
        }

        let end = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map(|index| index + 1);
        let consumed = end.unwrap_or(available.len());
        ensure!(
            frame.len() + consumed <= MAX_REQUEST_BYTES,
            "Incoming request exceeds 64 KiB"
        );
        frame.extend_from_slice(&available[..consumed]);
        reader.consume(consumed);

        if end.is_some() {
            let request: Request =
                serde_json::from_slice(&frame).context("Invalid worker request")?;
            ensure!(request.jsonrpc == "2.0", "Invalid JSON-RPC version");
            ensure!(
                (1..=9_007_199_254_740_991).contains(&request.id),
                "Invalid request identity"
            );
            ensure!(request.method.len() <= 64, "Invalid RPC method length");
            return Ok(Some(request));
        }
    }
}
