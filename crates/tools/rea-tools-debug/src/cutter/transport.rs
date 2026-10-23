//! Authenticated loopback transport for one Cutter bridge request.
//!
//! Port of `CutterBridgeClient.#request` and `serializeRequest` in
//! `src/cutter/CutterBridgeClient.ts`, speaking the exact
//! `rea-auth-v2` / `rea-cutter-*-v2` HMAC handshake implemented by
//! `bridge/cutter/rea_bridge.py`. The token is a transport credential: it is
//! used only to derive and verify HMAC proofs, is never returned, recorded or
//! logged, and is redacted from any error surface.

use hmac::{Hmac, Mac};
use rea_core::cancellation::Cancellation;
use sha2::Sha256;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

use super::client::Descriptor;

type HmacSha256 = Hmac<Sha256>;

/// 25s request timeout, matching the TS `setTimeout(..., 25_000)`.
const REQUEST_TIMEOUT: Duration = Duration::from_millis(25_000);
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// A transport failure that mirrors `CutterBridgeRequestFailure`.
///
/// `request_sent` records whether the authenticated request frame was written
/// before the failure, which the execute path uses to distinguish an
/// `unknown` (possibly-applied) command from a clean pre-send failure.
pub(super) struct RequestFailure {
    pub message: String,
    pub request_sent: bool,
}

impl RequestFailure {
    fn new(message: impl Into<String>, request_sent: bool) -> Self {
        Self {
            message: message.into(),
            request_sent,
        }
    }
}

/// Serialize a request body, binding its `session_id`, and enforce the
/// authenticated frame budget (`serializeRequest`). Returns the exact bytes
/// that are HMAC-signed and sent.
pub(super) fn serialize_request(
    descriptor: &Descriptor,
    request: serde_json::Value,
) -> Result<String, ResourceConstraint> {
    let mut object = match request {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    object.insert(
        "session_id".to_owned(),
        serde_json::Value::String(descriptor.session_id.clone()),
    );
    let request_bytes = serde_json::Value::Object(object).to_string();

    // Frame-size estimate identical to the TS producer: the fixed envelope
    // overhead plus the request bytes plus one byte per `"` or `\` that JSON
    // string-escaping will add when the request is embedded as a string.
    let envelope_overhead = serde_json::json!({ "request": "", "proof": "0".repeat(64) })
        .to_string()
        .len();
    let mut frame_bytes = envelope_overhead + request_bytes.len();
    for byte in request_bytes.bytes() {
        if byte == b'"' || byte == b'\\' {
            frame_bytes += 1;
        }
    }
    if frame_bytes > MAX_FRAME_BYTES {
        return Err(ResourceConstraint {
            frame_bytes,
            max_frame_bytes: MAX_FRAME_BYTES,
        });
    }
    Ok(request_bytes)
}

/// Reported by `serialize_request` when a request would exceed the frame
/// budget; mapped by the caller to `AnalysisResourceConstraintError`.
pub(super) struct ResourceConstraint {
    pub frame_bytes: usize,
    pub max_frame_bytes: usize,
}

/// Outcome of a completed request: the decoded response value plus the
/// authenticated connection ordinal (the first 16 hex chars of the server
/// nonce), which the service retains as a completion watermark.
pub(super) struct RequestOutcome {
    pub response: serde_json::Value,
    pub connection_ordinal: Option<String>,
}

/// Perform one authenticated request against a descriptor's loopback port.
///
/// Mirrors `CutterBridgeClient.#request`: connect, send the `rea-auth-v2`
/// hello, verify the server proof, send the signed request, verify and decode
/// the signed response. Cancellation is honored between blocking steps.
pub(super) fn request(
    descriptor: &Descriptor,
    request_bytes: &str,
    cancellation: &Cancellation,
) -> Result<RequestOutcome, RequestFailure> {
    if cancellation.reason().is_some() {
        return Err(RequestFailure::new(
            "Cutter bridge request was cancelled",
            false,
        ));
    }

    let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), descriptor.port);
    let stream = TcpStream::connect_timeout(&address, REQUEST_TIMEOUT).map_err(|cause| {
        RequestFailure::new(format!("Cutter bridge is unavailable: {cause}"), false)
    })?;
    stream
        .set_read_timeout(Some(REQUEST_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(REQUEST_TIMEOUT)))
        .map_err(|cause| {
            RequestFailure::new(format!("Cutter bridge is unavailable: {cause}"), false)
        })?;

    let mut session = Connection {
        stream,
        buffer: Vec::new(),
        frames_read: 0,
    };

    // Client hello.
    let client_nonce = client_nonce();
    session
        .write_frame(&serde_json::json!({ "kind": "rea-auth-v2", "nonce": client_nonce }))
        .map_err(|_| RequestFailure::new("Cutter bridge is unavailable", false))?;

    cancellation_check(cancellation, false)?;

    // Server challenge: { session_id, nonce, proof }.
    let challenge = session.read_frame().map_err(|_| {
        RequestFailure::new(
            "Cutter bridge closed before returning a complete response",
            false,
        )
    })?;
    let server_nonce =
        authenticate_server(descriptor, &client_nonce, &challenge).ok_or_else(|| {
            RequestFailure::new(
                "Cutter bridge peer authentication or response failed",
                false,
            )
        })?;
    let connection_ordinal = server_nonce.get(0..16).map(str::to_owned);

    // Signed request frame.
    let client_proof = sign(
        &descriptor.token,
        &format!(
            "rea-cutter-client-v2:{}:{client_nonce}:{server_nonce}:{request_bytes}",
            descriptor.session_id
        ),
    );
    session
        .write_frame(&serde_json::json!({ "request": request_bytes, "proof": client_proof }))
        .map_err(|_| RequestFailure::new("Cutter bridge is unavailable", true))?;

    cancellation_check(cancellation, true)?;

    // Signed response frame: { response, proof }.
    let envelope = session.read_frame().map_err(|_| {
        RequestFailure::new(
            "Cutter bridge closed before returning a complete response",
            true,
        )
    })?;
    let response = authenticate_response(descriptor, &client_nonce, &server_nonce, &envelope)
        .ok_or_else(|| {
            RequestFailure::new("Cutter bridge peer authentication or response failed", true)
        })?;

    Ok(RequestOutcome {
        response,
        connection_ordinal,
    })
}

fn cancellation_check(
    cancellation: &Cancellation,
    request_sent: bool,
) -> Result<(), RequestFailure> {
    if cancellation.reason().is_some() {
        return Err(RequestFailure::new(
            "Cutter bridge request was cancelled",
            request_sent,
        ));
    }
    Ok(())
}

/// A single owned connection with bounded, two-frame newline framing
/// (`CutterBridgeResponseFrames`: at most two protocol frames, bounded bytes).
struct Connection {
    stream: TcpStream,
    buffer: Vec<u8>,
    frames_read: u32,
}

impl Connection {
    fn write_frame(&mut self, value: &serde_json::Value) -> std::io::Result<()> {
        let mut line = value.to_string().into_bytes();
        line.push(b'\n');
        self.stream.write_all(&line)
    }

    /// Read one newline-delimited frame, enforcing the framed transport limit
    /// and the two-frame cap.
    fn read_frame(&mut self) -> Result<serde_json::Value, ()> {
        loop {
            if let Some(position) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let line = self.buffer[..position].to_vec();
                self.buffer.drain(..=position);
                self.frames_read += 1;
                if self.frames_read > 2 {
                    return Err(());
                }
                return serde_json::from_slice(&line).map_err(|_| ());
            }
            if self.buffer.len() > MAX_FRAME_BYTES {
                return Err(());
            }
            let mut chunk = [0_u8; 65536];
            let read = self.stream.read(&mut chunk).map_err(|_| ())?;
            if read == 0 {
                return Err(());
            }
            if self.buffer.len() + read > MAX_FRAME_BYTES {
                return Err(());
            }
            self.buffer.extend_from_slice(&chunk[..read]);
        }
    }
}

/// Verify the server challenge and return its nonce (`authenticated` branch of
/// the TS `on("data")` handler, first frame).
fn authenticate_server(
    descriptor: &Descriptor,
    client_nonce: &str,
    challenge: &serde_json::Value,
) -> Option<String> {
    let session_id = challenge.get("session_id")?.as_str()?;
    let nonce = challenge.get("nonce")?.as_str()?;
    let proof = challenge.get("proof")?.as_str()?;
    if session_id != descriptor.session_id || !is_hex64(nonce) || !is_hex64(proof) {
        return None;
    }
    let expected = sign(
        &descriptor.token,
        &format!(
            "rea-cutter-server-v2:{}:{client_nonce}:{nonce}",
            descriptor.session_id
        ),
    );
    if !constant_time_hex_eq(&expected, proof) {
        return None;
    }
    Some(nonce.to_owned())
}

/// Verify the signed response envelope and decode its `response` payload
/// (second frame of the TS `on("data")` handler).
fn authenticate_response(
    descriptor: &Descriptor,
    client_nonce: &str,
    server_nonce: &str,
    envelope: &serde_json::Value,
) -> Option<serde_json::Value> {
    let response = envelope.get("response")?.as_str()?;
    let proof = envelope.get("proof")?.as_str()?;
    if !is_hex64(proof) {
        return None;
    }
    let expected = sign(
        &descriptor.token,
        &format!(
            "rea-cutter-response-v2:{}:{client_nonce}:{server_nonce}:{response}",
            descriptor.session_id
        ),
    );
    if !constant_time_hex_eq(&expected, proof) {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(response).ok()
}

fn sign(token: &str, message: &str) -> String {
    let mut mac =
        HmacSha256::new_from_slice(token.as_bytes()).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    let digest = mac.finalize().into_bytes();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}

/// Constant-time comparison of an expected hex digest against a received hex
/// string (`timingSafeEqual` over decoded bytes in the oracle).
fn constant_time_hex_eq(expected_hex: &str, received_hex: &str) -> bool {
    let Some(received) = decode_hex(received_hex) else {
        return false;
    };
    let expected = decode_hex(expected_hex).unwrap_or_default();
    if expected.len() != received.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in expected.iter().zip(received.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

fn decode_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    let mut index = 0;
    while index < raw.len() {
        let high = (raw[index] as char).to_digit(16)?;
        let low = (raw[index + 1] as char).to_digit(16)?;
        bytes.push(((high << 4) | low) as u8);
        index += 2;
    }
    Some(bytes)
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// 32 random bytes rendered as 64 lowercase hex chars (TS
/// `randomBytes(32).toString("hex")`).
fn client_nonce() -> String {
    let id = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    let mut raw = [0_u8; 32];
    raw[..16].copy_from_slice(id.as_bytes());
    raw[16..].copy_from_slice(second.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in raw {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
