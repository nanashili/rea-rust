//! Minimal loopback HTTP/1.1 client for the JEB MCP streamable-HTTP transport.
//!
//! Compatibility owner: the `StreamableHTTPClientTransport` request path of
//! `@modelcontextprotocol/client` 2.3.1 as driven by `JebMcpConnection.ts`.
//! This sends exactly the bytes that transport sends for a loopback JEB
//! engine: a `POST`/`DELETE` to the `/mcp` route with the connection headers
//! the SDK sets, parsing an `application/json` or `text/event-stream` body.
//!
//! No credentials are ever transmitted: the endpoint admission already rejects
//! embedded credentials and the SDK only adds `Authorization` from an OAuth
//! provider, which this transport does not configure (`redirect: "error"`,
//! no auth provider). We never send an `Authorization` header.
use super::endpoint::Endpoint;
use rea_core::cancellation::Cancellation;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// How often the blocking socket wakes to re-check the deadline/cancellation.
const POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Response-body guard: the SDK buffers whole JSON/SSE responses in memory, so
/// a bounded ceiling keeps a hostile or runaway engine from exhausting it.
const MAX_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

/// A physical transport failure, before any typed classification.
#[derive(Debug)]
pub enum HttpError {
    /// Connection, read or write failure; carries the OS message.
    Io(String),
    /// The absolute deadline elapsed while waiting for the engine.
    Timeout,
    /// The caller cancelled while waiting for the engine.
    Cancelled(String),
    /// A redirect response (the transport uses `redirect: "error"`).
    Redirect(u16),
    /// A non-2xx status other than a redirect.
    Status { status: u16, body: String },
    /// A malformed HTTP response.
    Protocol(String),
}

impl HttpError {
    /// Human-readable text, as `cause instanceof Error ? cause.message : ...`.
    pub fn message(&self) -> String {
        match self {
            HttpError::Io(message) => message.clone(),
            HttpError::Timeout => "JEB MCP request timed out".to_owned(),
            HttpError::Cancelled(reason) => reason.clone(),
            HttpError::Redirect(status) => {
                format!("Error POSTing to endpoint: unexpected redirect (status {status})")
            }
            HttpError::Status { status, body } => {
                format!("Error POSTing to endpoint: HTTP {status} {body}")
            }
            HttpError::Protocol(message) => message.clone(),
        }
    }
}

/// A decoded HTTP response the transport cares about.
pub struct HttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub session_id: Option<String>,
    pub body: Vec<u8>,
}

/// One absolute deadline shared by connect, write and read, cancellable.
///
/// Compatibility owner: `JebMcpDeadline` over `ProviderStartupDeadline`. The
/// caller cancellation and the absolute timeout both abort the wait; the first
/// control path that fires is reported.
pub struct Deadline<'a> {
    deadline_at: Instant,
    timeout: Duration,
    cancellation: &'a Cancellation,
}

impl<'a> Deadline<'a> {
    pub fn new(timeout_ms: u64, cancellation: &'a Cancellation) -> Self {
        let timeout = Duration::from_millis(timeout_ms.max(1));
        Self {
            deadline_at: Instant::now() + timeout,
            timeout,
            cancellation,
        }
    }

    /// Milliseconds still available (floored at zero).
    pub fn remaining(&self) -> Duration {
        self.deadline_at.saturating_duration_since(Instant::now())
    }

    /// Classify whether the deadline or cancellation has fired, if either has.
    fn interruption(&self) -> Option<HttpError> {
        if let Some(reason) = self.cancellation.reason() {
            return Some(HttpError::Cancelled(reason.to_owned()));
        }
        if self.remaining().is_zero() {
            return Some(HttpError::Timeout);
        }
        None
    }
}

/// Perform one request/response exchange against the loopback engine.
///
/// `method` is `POST` or `DELETE`; `body` is the already-serialized JSON-RPC
/// message (empty for `DELETE`). `session_id` and `protocol_version` are the
/// connection-derived headers the SDK's `_commonHeaders` emits.
pub fn exchange(
    endpoint: &Endpoint,
    method: &str,
    headers: &RequestHeaders,
    body: &[u8],
    deadline: &Deadline<'_>,
) -> Result<HttpResponse, HttpError> {
    let mut stream = connect(endpoint, deadline)?;

    let request = build_request(endpoint, method, headers, body);
    write_all(&mut stream, request.as_bytes(), deadline)?;
    if !body.is_empty() {
        write_all(&mut stream, body, deadline)?;
    }

    read_response(&mut stream, deadline)
}

/// Connection-derived request headers, mirroring the SDK transport.
#[derive(Default)]
pub struct RequestHeaders {
    /// `mcp-session-id`, set once the engine returns one.
    pub session_id: Option<String>,
    /// `mcp-protocol-version`, set once the handshake negotiates it.
    pub protocol_version: Option<String>,
    /// `content-type` for a body-carrying request.
    pub content_type: Option<String>,
    /// `accept` header value.
    pub accept: Option<String>,
}

fn build_request(
    endpoint: &Endpoint,
    method: &str,
    headers: &RequestHeaders,
    body: &[u8],
) -> String {
    let mut request = String::new();
    request.push_str(&format!("{method} {} HTTP/1.1\r\n", endpoint.path));
    request.push_str(&format!("host: {}\r\n", endpoint.host_header()));
    // The SDK sets these headers from connection state; emit them in the same
    // lowercase spelling the transport uses.
    if let Some(session_id) = &headers.session_id {
        request.push_str(&format!("mcp-session-id: {session_id}\r\n"));
    }
    if let Some(protocol_version) = &headers.protocol_version {
        request.push_str(&format!("mcp-protocol-version: {protocol_version}\r\n"));
    }
    if let Some(accept) = &headers.accept {
        request.push_str(&format!("accept: {accept}\r\n"));
    }
    if let Some(content_type) = &headers.content_type {
        request.push_str(&format!("content-type: {content_type}\r\n"));
    }
    request.push_str(&format!("content-length: {}\r\n", body.len()));
    request.push_str("connection: close\r\n");
    request.push_str("\r\n");
    request
}

fn connect(endpoint: &Endpoint, deadline: &Deadline<'_>) -> Result<TcpStream, HttpError> {
    if let Some(interruption) = deadline.interruption() {
        return Err(interruption);
    }
    // Loopback-only: the endpoint admission already confined the host to a
    // literal loopback address, so resolution is direct and no DNS is used.
    let address = format!("{}:{}", socket_host(&endpoint.connect_host), endpoint.port);
    let addresses = std::net::ToSocketAddrs::to_socket_addrs(&address)
        .map_err(|error| HttpError::Io(error.to_string()))?;
    let mut last_error: Option<HttpError> = None;
    for socket in addresses {
        match TcpStream::connect_timeout(&socket, connect_timeout(deadline)) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(POLL_INTERVAL))
                    .map_err(|error| HttpError::Io(error.to_string()))?;
                stream
                    .set_write_timeout(Some(POLL_INTERVAL))
                    .map_err(|error| HttpError::Io(error.to_string()))?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(HttpError::Io(error.to_string())),
        }
        if let Some(interruption) = deadline.interruption() {
            return Err(interruption);
        }
    }
    Err(last_error.unwrap_or_else(|| HttpError::Io("no loopback address resolved".to_owned())))
}

/// Bracketed IPv6 literals connect to the address without brackets.
fn socket_host(connect_host: &str) -> &str {
    connect_host
}

fn connect_timeout(deadline: &Deadline<'_>) -> Duration {
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        // A positive duration is required; the next interruption check reports
        // the already-elapsed deadline.
        Duration::from_millis(1)
    } else {
        remaining.min(deadline.timeout)
    }
}

fn write_all(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: &Deadline<'_>,
) -> Result<(), HttpError> {
    while !bytes.is_empty() {
        if let Some(interruption) = deadline.interruption() {
            return Err(interruption);
        }
        match stream.write(bytes) {
            Ok(0) => return Err(HttpError::Io("connection closed during write".to_owned())),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if is_timeout(&error) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(HttpError::Io(error.to_string())),
        }
    }
    Ok(())
}

fn read_response(
    stream: &mut TcpStream,
    deadline: &Deadline<'_>,
) -> Result<HttpResponse, HttpError> {
    let mut raw: Vec<u8> = Vec::new();
    let header_end = loop {
        if let Some(position) = find_header_end(&raw) {
            break position;
        }
        read_chunk(stream, &mut raw, deadline)?;
    };

    let head = String::from_utf8_lossy(&raw[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = parse_status(status_line)?;

    let mut content_type: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_owned();
        match name.as_str() {
            "content-type" => content_type = Some(value),
            "mcp-session-id" => session_id = Some(value),
            "content-length" => content_length = value.parse::<usize>().ok(),
            "transfer-encoding" if value.to_ascii_lowercase().contains("chunked") => {
                chunked = true;
            }
            _ => {}
        }
    }

    // Redirects are an error for this transport (`redirect: "error"`).
    if (300..=399).contains(&status) {
        return Err(HttpError::Redirect(status));
    }

    let body_start = header_end + 4;
    let mut body_buffer = raw.split_off(body_start.min(raw.len()));
    // `raw[header_end..body_start]` is the CRLFCRLF separator; drop it.
    drop(raw);

    let body = if chunked {
        read_chunked_body(stream, &mut body_buffer, deadline)?
    } else if let Some(length) = content_length {
        read_fixed_body(stream, body_buffer, length, deadline)?
    } else {
        // No length and not chunked: read until the server closes (the SDK
        // relies on `connection: close` framing for such responses).
        read_until_close(stream, body_buffer, deadline)?
    };

    if !(200..=299).contains(&status) {
        let text = String::from_utf8_lossy(&body).into_owned();
        return Err(HttpError::Status { status, body: text });
    }

    Ok(HttpResponse {
        status,
        content_type,
        session_id,
        body,
    })
}

fn parse_status(status_line: &str) -> Result<u16, HttpError> {
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/") {
        return Err(HttpError::Protocol(format!(
            "JEB MCP returned a non-HTTP response line: {status_line}"
        )));
    }
    parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            HttpError::Protocol(format!(
                "JEB MCP returned an invalid status line: {status_line}"
            ))
        })
}

fn find_header_end(raw: &[u8]) -> Option<usize> {
    raw.windows(4).position(|window| window == b"\r\n\r\n")
}

fn read_fixed_body(
    stream: &mut TcpStream,
    mut buffer: Vec<u8>,
    length: usize,
    deadline: &Deadline<'_>,
) -> Result<Vec<u8>, HttpError> {
    if length > MAX_RESPONSE_BYTES {
        return Err(HttpError::Protocol(
            "JEB MCP response exceeds the supported size".to_owned(),
        ));
    }
    while buffer.len() < length {
        read_chunk(stream, &mut buffer, deadline)?;
    }
    buffer.truncate(length);
    Ok(buffer)
}

fn read_until_close(
    stream: &mut TcpStream,
    mut buffer: Vec<u8>,
    deadline: &Deadline<'_>,
) -> Result<Vec<u8>, HttpError> {
    loop {
        match read_chunk(stream, &mut buffer, deadline) {
            Ok(0) => break,
            Ok(_) => {}
            Err(HttpError::Io(_)) => break,
            Err(other) => return Err(other),
        }
        if buffer.len() > MAX_RESPONSE_BYTES {
            return Err(HttpError::Protocol(
                "JEB MCP response exceeds the supported size".to_owned(),
            ));
        }
    }
    Ok(buffer)
}

fn read_chunked_body(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    deadline: &Deadline<'_>,
) -> Result<Vec<u8>, HttpError> {
    let mut body: Vec<u8> = Vec::new();
    let mut cursor = 0usize;
    loop {
        // Find the chunk-size line terminator.
        let line_end = loop {
            if let Some(position) = find_crlf(&buffer[cursor..]) {
                break cursor + position;
            }
            read_chunk(stream, buffer, deadline)?;
        };
        let size_line = String::from_utf8_lossy(&buffer[cursor..line_end]).into_owned();
        let size_token = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_token, 16).map_err(|_| {
            HttpError::Protocol("JEB MCP returned an invalid chunk size".to_owned())
        })?;
        cursor = line_end + 2;
        if size == 0 {
            break;
        }
        if body.len() + size > MAX_RESPONSE_BYTES {
            return Err(HttpError::Protocol(
                "JEB MCP response exceeds the supported size".to_owned(),
            ));
        }
        while buffer.len() < cursor + size + 2 {
            read_chunk(stream, buffer, deadline)?;
        }
        body.extend_from_slice(&buffer[cursor..cursor + size]);
        cursor += size + 2;
    }
    Ok(body)
}

fn find_crlf(bytes: &[u8]) -> Option<usize> {
    bytes.windows(2).position(|window| window == b"\r\n")
}

/// Read one chunk of bytes into `buffer`, honoring the deadline and
/// cancellation. Returns the number of bytes read (0 on clean EOF).
fn read_chunk(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    deadline: &Deadline<'_>,
) -> Result<usize, HttpError> {
    let mut scratch = [0u8; 8192];
    loop {
        if let Some(interruption) = deadline.interruption() {
            return Err(interruption);
        }
        match stream.read(&mut scratch) {
            Ok(0) => return Ok(0),
            Ok(read) => {
                buffer.extend_from_slice(&scratch[..read]);
                if buffer.len() > MAX_RESPONSE_BYTES {
                    return Err(HttpError::Protocol(
                        "JEB MCP response exceeds the supported size".to_owned(),
                    ));
                }
                return Ok(read);
            }
            Err(error) if is_timeout(&error) => continue,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(HttpError::Io(error.to_string())),
        }
    }
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}
