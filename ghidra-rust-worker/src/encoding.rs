use std::io::{self, Write};

use anyhow::{Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn json_sha256(value: &impl Serialize) -> Result<String> {
    let mut hash = JsonHash(Sha256::new());
    serde_json::to_writer(&mut hash, value).context("Hash encoded JSON")?;
    Ok(format!("{:x}", hash.0.finalize()))
}

struct JsonHash(Sha256);

impl Write for JsonHash {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn encoded_size(value: &impl Serialize) -> Result<usize> {
    let mut counter = ByteCount(0);
    serde_json::to_writer(&mut counter, value).context("Measure encoded JSON")?;
    Ok(counter.0)
}

pub fn encode_bounded(value: &impl Serialize, maximum: usize) -> Result<Vec<u8>> {
    let mut output = BoundedBuffer {
        bytes: Vec::new(),
        maximum,
    };
    serde_json::to_writer(&mut output, value).context("Encode bounded JSON")?;
    Ok(output.bytes)
}

struct ByteCount(usize);

impl Write for ByteCount {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("encoded JSON size overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .filter(|length| *length <= self.maximum)
            .ok_or_else(|| io::Error::other("encoded JSON exceeds its byte limit"))?;
        self.bytes
            .try_reserve(length - self.bytes.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
