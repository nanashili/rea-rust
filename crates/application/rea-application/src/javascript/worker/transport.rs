//! Private worker wire format. Domain values remain unchanged after decoding.

use std::io::{BufReader, Cursor, Read, Write};

use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use base64::write::EncoderWriter;
use flate2::Compression;
use flate2::bufread::GzDecoder;
use flate2::write::GzEncoder;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::{CountingWriter, WorkerFailure, WorkerResponse, WorkerSemanticFailure};

const COMPRESSED_RESPONSE_VERSION: u8 = 1;
const COMPRESSED_RESPONSE_THRESHOLD: usize = 8 * 1024 * 1024;
const COMPRESSED_RESPONSE_MARKER: &str = "rea-worker-compressed-v1";
const DECODE_CHUNK_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerCheckpoint {
    static_analysis: Box<RawValue>,
}

#[derive(Serialize)]
struct WorkerCheckpointFrame<'a> {
    static_analysis: &'a RawValue,
}

#[derive(Serialize)]
struct WorkerResponseBody<'a> {
    semantic_ir: Option<&'a RawValue>,
    semantic_projection: Option<&'a RawValue>,
    semantic_metadata: Option<&'a RawValue>,
    semantic_failure: Option<&'a WorkerSemanticFailure>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerResponseBodyOwned {
    semantic_ir: Option<Box<RawValue>>,
    semantic_projection: Option<Box<RawValue>>,
    semantic_metadata: Option<Box<RawValue>>,
    semantic_failure: Option<WorkerSemanticFailure>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompressedResponseFrame<'a> {
    protocol: &'a str,
    version: u8,
    encoding: &'a str,
    decoded_bytes: usize,
    #[serde(borrow)]
    payload: &'a str,
}

/// Presence is separate from validity: even a null protocol must be validated.
#[derive(Default, Deserialize)]
struct ResponseProtocolProbe {
    #[serde(default, rename = "protocol", deserialize_with = "field_present")]
    has_protocol: bool,
    #[serde(default, rename = "semantic_ir", deserialize_with = "field_present")]
    has_semantic_ir: bool,
    #[serde(
        default,
        rename = "semantic_projection",
        deserialize_with = "field_present"
    )]
    has_semantic_projection: bool,
    #[serde(
        default,
        rename = "semantic_metadata",
        deserialize_with = "field_present"
    )]
    has_semantic_metadata: bool,
    #[serde(
        default,
        rename = "semantic_failure",
        deserialize_with = "field_present"
    )]
    has_semantic_failure: bool,
}

fn field_present<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<bool, D::Error> {
    serde::de::IgnoredAny::deserialize(deserializer)?;
    Ok(true)
}

struct ResponseFrames<'a> {
    checkpoint: Option<&'a [u8]>,
    terminal: &'a [u8],
}

impl<'a> ResponseFrames<'a> {
    fn parse(output: &'a [u8]) -> Result<Self, WorkerFailure> {
        let mut lines = output
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty());
        let terminal = lines
            .next_back()
            .ok_or_else(|| WorkerFailure::Protocol("worker response was empty".to_owned()))?;
        let checkpoint = lines.next();
        if lines.next().is_some() {
            return Err(WorkerFailure::Protocol(
                "worker response contains unexpected frames".to_owned(),
            ));
        }
        Ok(Self {
            checkpoint,
            terminal,
        })
    }
}

pub(super) fn parse_checkpoint(output: &[u8]) -> Option<Box<RawValue>> {
    let first = output
        .split(|byte| *byte == b'\n')
        .find(|line| !line.is_empty())?;
    serde_json::from_slice::<WorkerCheckpoint>(first)
        .ok()
        .map(|checkpoint| checkpoint.static_analysis)
}

pub(super) fn parse_worker_response(
    output: &[u8],
    decoded_response_limit: usize,
    mut check: impl FnMut() -> Option<WorkerFailure>,
) -> Result<WorkerResponse, WorkerFailure> {
    if let Some(failure) = check() {
        return Err(failure);
    }
    let frames = ResponseFrames::parse(output)?;
    let probe: ResponseProtocolProbe = serde_json::from_slice(frames.terminal)
        .map_err(|error| WorkerFailure::Protocol(format!("invalid worker JSON: {error}")))?;

    let response = if probe.has_protocol {
        parse_compressed_response(&frames, decoded_response_limit, &mut check)?
    } else {
        if !(probe.has_semantic_ir
            || probe.has_semantic_projection
            || probe.has_semantic_metadata
            || probe.has_semantic_failure)
        {
            return Err(WorkerFailure::Protocol(
                "worker emitted only a static checkpoint".to_owned(),
            ));
        }
        if frames.terminal.len() > decoded_response_limit {
            return Err(WorkerFailure::Protocol(format!(
                "worker response exceeds its {decoded_response_limit} decoded byte limit"
            )));
        }
        serde_json::from_slice(frames.terminal)
            .map_err(|error| WorkerFailure::Protocol(error.to_string()))?
    };
    check().map_or(Ok(response), Err)
}

fn parse_compressed_response(
    frames: &ResponseFrames<'_>,
    decoded_response_limit: usize,
    check: &mut impl FnMut() -> Option<WorkerFailure>,
) -> Result<WorkerResponse, WorkerFailure> {
    let frame: CompressedResponseFrame<'_> =
        serde_json::from_slice(frames.terminal).map_err(|error| {
            WorkerFailure::Protocol(format!("invalid compressed worker envelope: {error}"))
        })?;
    validate_envelope(&frame, decoded_response_limit)?;
    let checkpoint = frames.checkpoint.ok_or_else(|| {
        WorkerFailure::Protocol(
            "compressed worker response is missing its static checkpoint".to_owned(),
        )
    })?;
    let static_analysis = parse_checkpoint(checkpoint).ok_or_else(|| {
        WorkerFailure::Protocol(
            "compressed worker response has an invalid static checkpoint".to_owned(),
        )
    })?;

    let body = decode_body(&frame, decoded_response_limit, check)?;
    Ok(WorkerResponse {
        static_analysis,
        semantic_ir: body.semantic_ir,
        semantic_projection: body.semantic_projection,
        semantic_metadata: body.semantic_metadata,
        semantic_failure: body.semantic_failure,
    })
}

fn validate_envelope(
    frame: &CompressedResponseFrame<'_>,
    limit: usize,
) -> Result<(), WorkerFailure> {
    if frame.protocol != COMPRESSED_RESPONSE_MARKER
        || frame.version != COMPRESSED_RESPONSE_VERSION
        || frame.encoding != "gzip+base64"
    {
        return Err(WorkerFailure::Protocol(
            "unsupported compressed worker envelope".to_owned(),
        ));
    }
    if frame.decoded_bytes > limit {
        return Err(WorkerFailure::Protocol(format!(
            "compressed worker response declares {} decoded bytes, above the {limit} byte limit",
            frame.decoded_bytes
        )));
    }
    Ok(())
}

fn decode_body(
    frame: &CompressedResponseFrame<'_>,
    limit: usize,
    check: &mut impl FnMut() -> Option<WorkerFailure>,
) -> Result<WorkerResponseBodyOwned, WorkerFailure> {
    let encoded =
        base64::read::DecoderReader::new(Cursor::new(frame.payload.as_bytes()), &BASE64_STANDARD);
    let gzip = GzDecoder::new(BufReader::new(encoded));
    let mut reader = BoundedResponseReader::new(gzip, limit, check);

    // IoRead asks for individual bytes. Buffer above the admission/interrupt
    // boundary so decompression and cancellation checks run once per chunk.
    let parsed = {
        let buffered = BufReader::with_capacity(DECODE_CHUNK_BYTES, &mut reader);
        serde_json::from_reader(buffered)
    };
    if let Some(failure) = reader.interruption.take() {
        return Err(failure);
    }
    let body = parsed.map_err(|error| {
        WorkerFailure::Protocol(format!("invalid compressed worker response body: {error}"))
    })?;
    if reader.bytes_read != frame.decoded_bytes {
        return Err(WorkerFailure::Protocol(format!(
            "compressed worker response decoded {} bytes, expected {}",
            reader.bytes_read, frame.decoded_bytes
        )));
    }

    // from_reader validates JSON through EOF, including gzip CRC and trailer.
    // Recover the compressed-input BufReader, retaining its prefetched bytes
    // when checking for a second gzip member or trailing compressed data.
    let mut encoded = reader.inner.into_inner();
    let mut trailing = [0_u8; 1];
    match encoded.read(&mut trailing) {
        Ok(0) => Ok(body),
        Ok(_) => Err(WorkerFailure::Protocol(
            "compressed worker response contains trailing gzip data".to_owned(),
        )),
        Err(error) => Err(WorkerFailure::Protocol(format!(
            "invalid base64 worker response: {error}"
        ))),
    }
}

struct BoundedResponseReader<R, F> {
    inner: R,
    limit: usize,
    bytes_read: usize,
    check: F,
    interruption: Option<WorkerFailure>,
}

impl<R, F> BoundedResponseReader<R, F> {
    fn new(inner: R, limit: usize, check: F) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
            check,
            interruption: None,
        }
    }
}

impl<R: Read, F: FnMut() -> Option<WorkerFailure>> BoundedResponseReader<R, F> {
    fn check_interruption(&mut self) -> std::io::Result<()> {
        if self.interruption.is_none() {
            self.interruption = (self.check)();
        }
        if self.interruption.is_some() {
            return Err(std::io::Error::other("worker response decode interrupted"));
        }
        Ok(())
    }
}

impl<R: Read, F: FnMut() -> Option<WorkerFailure>> Read for BoundedResponseReader<R, F> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        self.check_interruption()?;
        let remaining = self.limit - self.bytes_read;
        if remaining == 0 {
            let mut probe = [0_u8; 1];
            if self.inner.read(&mut probe)? != 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "compressed worker response exceeded its decoded byte limit",
                ));
            }
            self.check_interruption()?;
            return Ok(0);
        }

        let read_length = buffer.len().min(remaining);
        let count = self.inner.read(&mut buffer[..read_length])?;
        self.bytes_read += count;
        self.check_interruption()?;
        Ok(count)
    }
}

pub(super) fn write_checkpoint(
    stdout: &mut impl Write,
    static_analysis: &RawValue,
) -> std::io::Result<()> {
    serde_json::to_writer(&mut *stdout, &WorkerCheckpointFrame { static_analysis })
        .map_err(std::io::Error::other)?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

pub(super) fn write_worker_response(
    stdout: &mut impl Write,
    response: &WorkerResponse,
    decoded_limit: usize,
) -> std::io::Result<()> {
    let body = WorkerResponseBody {
        semantic_ir: response.semantic_ir.as_deref(),
        semantic_projection: response.semantic_projection.as_deref(),
        semantic_metadata: response.semantic_metadata.as_deref(),
        semantic_failure: response.semantic_failure.as_ref(),
    };
    let mut counter = CountingWriter::default();
    serde_json::to_writer(&mut counter, &body).map_err(std::io::Error::other)?;
    if counter.bytes_written > decoded_limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("worker response exceeds its {decoded_limit} decoded byte limit"),
        ));
    }
    if counter.bytes_written <= COMPRESSED_RESPONSE_THRESHOLD {
        let mut plain_size = CountingWriter::default();
        serde_json::to_writer(&mut plain_size, response).map_err(std::io::Error::other)?;
        if plain_size.bytes_written > decoded_limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("worker response exceeds its {decoded_limit} decoded byte limit"),
            ));
        }
        serde_json::to_writer(&mut *stdout, response).map_err(std::io::Error::other)?;
        stdout.flush()
    } else {
        write_compressed_response(stdout, &body, counter.bytes_written)
    }
}

fn write_compressed_response(
    stdout: &mut impl Write,
    body: &WorkerResponseBody<'_>,
    decoded_bytes: usize,
) -> std::io::Result<()> {
    write!(
        stdout,
        "{{\"protocol\":\"{COMPRESSED_RESPONSE_MARKER}\",\"version\":{COMPRESSED_RESPONSE_VERSION},\"encoding\":\"gzip+base64\",\"decoded_bytes\":{decoded_bytes},\"payload\":\""
    )?;
    {
        let encoder = EncoderWriter::new(&mut *stdout, &BASE64_STANDARD);
        let mut gzip = GzEncoder::new(encoder, Compression::fast());
        serde_json::to_writer(&mut gzip, body).map_err(std::io::Error::other)?;
        let mut encoder = gzip.finish()?;
        encoder.finish()?;
    }
    stdout.write_all(b"\"}\n")?;
    stdout.flush()
}

#[cfg(test)]
mod tests;
