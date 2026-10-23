//! Bounded, read-only Chrome DevTools Protocol transport.
//!
//! The application layer owns the operation contract while this module owns
//! the socket, request identifiers, and protocol framing.  It deliberately
//! accepts only a caller-selected loopback `ws://` endpoint.  Browser target
//! discovery is performed by the caller, so this transport cannot silently
//! choose a different page.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use tungstenite::client::client_with_config;
use tungstenite::protocol::{Message, WebSocket, WebSocketConfig};

/// Maximum JSON message accepted from a CDP peer.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;
/// Largest CDP message accepted by page inspections that retain DOM snapshots.
pub const MAX_INSPECTION_MESSAGE_BYTES: usize = 64 * 1024 * 1024;
/// Maximum unsolicited CDP events retained between application drain points.
pub const MAX_BUFFERED_EVENTS: usize = 1024;
/// Maximum serialized bytes retained by the unsolicited event buffer.
pub const MAX_BUFFERED_EVENT_BYTES: usize = 2 * 1024 * 1024;
/// Default connect/read/write timeout for one CDP request.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(100);

type Socket = WebSocket<TcpStream>;

/// One unsolicited CDP event, with a connection-local sequence number.
#[derive(Debug, Clone, PartialEq)]
pub struct CdpEvent {
    pub sequence: u64,
    pub value: Value,
}

/// Events and explicit omission information returned by `drain_events`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct CdpEventBatch {
    pub items: Vec<CdpEvent>,
    pub dropped: u64,
    pub overflowed: bool,
}

#[derive(Debug)]
struct CdpEventBuffer {
    items: VecDeque<CdpEvent>,
    retained_bytes: usize,
    dropped: u64,
    overflowed: bool,
    next_sequence: u64,
    max_items: usize,
    max_bytes: usize,
}

impl CdpEventBuffer {
    fn new() -> Self {
        Self {
            items: VecDeque::new(),
            retained_bytes: 0,
            dropped: 0,
            overflowed: false,
            next_sequence: 1,
            max_items: MAX_BUFFERED_EVENTS,
            max_bytes: MAX_BUFFERED_EVENT_BYTES,
        }
    }

    #[cfg(test)]
    fn with_limits(max_items: usize, max_bytes: usize) -> Self {
        Self {
            max_items,
            max_bytes,
            ..Self::new()
        }
    }

    fn record(&mut self, value: Value, serialized_bytes: usize) {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        if self.items.len() >= self.max_items
            || serialized_bytes > self.max_bytes.saturating_sub(self.retained_bytes)
        {
            self.dropped = self.dropped.saturating_add(1);
            self.overflowed = true;
            return;
        }
        self.retained_bytes += serialized_bytes;
        self.items.push_back(CdpEvent { sequence, value });
    }

    fn drain(&mut self) -> CdpEventBatch {
        let items = self.items.drain(..).collect();
        self.retained_bytes = 0;
        CdpEventBatch {
            items,
            dropped: std::mem::take(&mut self.dropped),
            overflowed: std::mem::take(&mut self.overflowed),
        }
    }
}

/// Errors reported by the transport without collapsing protocol failures into
/// stringly-typed application failures.
#[derive(Debug)]
pub enum CdpTransportError {
    InvalidEndpoint(String),
    Io(io::Error),
    WebSocket(tungstenite::Error),
    InvalidMessage(String),
    Protocol { code: Option<i64>, message: String },
    Timeout,
    Cancelled(String),
    RequestIdExhausted,
}

impl fmt::Display for CdpTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpoint(message) => write!(formatter, "invalid CDP endpoint: {message}"),
            Self::Io(error) => write!(formatter, "CDP socket I/O failed: {error}"),
            Self::WebSocket(error) => write!(formatter, "CDP WebSocket failed: {error}"),
            Self::InvalidMessage(message) => write!(formatter, "invalid CDP message: {message}"),
            Self::Protocol { code, message } => {
                if let Some(code) = code {
                    write!(formatter, "CDP protocol error {code}: {message}")
                } else {
                    write!(formatter, "CDP protocol error: {message}")
                }
            }
            Self::Timeout => formatter.write_str("CDP request timed out"),
            Self::Cancelled(reason) => write!(formatter, "CDP request was cancelled: {reason}"),
            Self::RequestIdExhausted => formatter.write_str("CDP request identifier exhausted"),
        }
    }
}

impl std::error::Error for CdpTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::WebSocket(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for CdpTransportError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<tungstenite::Error> for CdpTransportError {
    fn from(error: tungstenite::Error) -> Self {
        Self::WebSocket(error)
    }
}

/// A command sent without awaiting its reply (see
/// [`CdpWebSocketTransport::request_with_event_hook`]).
#[derive(Clone, Debug)]
pub struct DetachedCommand {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

/// A single synchronous CDP WebSocket connection.
pub struct CdpWebSocketTransport {
    socket: Socket,
    next_request_id: i64,
    endpoint: String,
    target_id: Option<String>,
    max_message_bytes: usize,
    request_timeout: Duration,
    events: CdpEventBuffer,
    abandoned_responses: BTreeMap<i64, Option<String>>,
}

impl fmt::Debug for CdpWebSocketTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CdpWebSocketTransport")
            .field("endpoint", &self.endpoint)
            .field("target_id", &self.target_id)
            .field("next_request_id", &self.next_request_id)
            .finish_non_exhaustive()
    }
}

impl CdpWebSocketTransport {
    /// Connect to a caller-selected CDP socket with the default timeout.
    pub fn connect(endpoint: &str) -> Result<Self, CdpTransportError> {
        Self::connect_with_timeout(endpoint, None, DEFAULT_TIMEOUT)
    }

    /// Connect to a page socket and verify its path identifies the selected
    /// target.  A browser socket may be used with `target_id == None` and is
    /// intended for explicit `Target.attachToTarget` commands by the caller.
    pub fn connect_for_target(endpoint: &str, target_id: &str) -> Result<Self, CdpTransportError> {
        if target_id.is_empty() {
            return Err(CdpTransportError::InvalidEndpoint(
                "target_id must be non-empty".into(),
            ));
        }
        Self::connect_with_timeout(endpoint, Some(target_id), DEFAULT_TIMEOUT)
    }

    /// Connect with an explicit bounded handshake and per-request timeout.
    pub fn connect_with_timeout(
        endpoint: &str,
        target_id: Option<&str>,
        timeout: Duration,
    ) -> Result<Self, CdpTransportError> {
        Self::connect_with_limits(endpoint, target_id, timeout, MAX_MESSAGE_BYTES)
    }

    /// Connect with an explicit bounded timeout and CDP message limit.
    pub fn connect_with_limits(
        endpoint: &str,
        target_id: Option<&str>,
        timeout: Duration,
        max_message_bytes: usize,
    ) -> Result<Self, CdpTransportError> {
        if max_message_bytes == 0 {
            return Err(CdpTransportError::InvalidMessage(
                "CDP message limit must be non-zero".into(),
            ));
        }
        let parsed = ParsedEndpoint::parse(endpoint, target_id)?;
        let address = resolve_loopback(parsed.port, parsed.host)?;
        let socket = TcpStream::connect_timeout(&address, timeout)?;
        socket.set_read_timeout(Some(timeout))?;
        socket.set_write_timeout(Some(timeout))?;
        socket.set_nodelay(true)?;

        let config = WebSocketConfig::default()
            .max_message_size(Some(max_message_bytes))
            .max_frame_size(Some(max_message_bytes));
        let (socket, _) =
            client_with_config(endpoint, socket, Some(config)).map_err(|error| match error {
                tungstenite::HandshakeError::Failure(error) => CdpTransportError::WebSocket(error),
                tungstenite::HandshakeError::Interrupted(_) => CdpTransportError::InvalidMessage(
                    "CDP WebSocket handshake was unexpectedly interrupted".into(),
                ),
            })?;

        Ok(Self {
            socket,
            next_request_id: 1,
            endpoint: endpoint.to_owned(),
            target_id: target_id.map(str::to_owned),
            max_message_bytes,
            request_timeout: timeout,
            events: CdpEventBuffer::new(),
            abandoned_responses: BTreeMap::new(),
        })
    }

    /// Return the exact validated endpoint supplied by the caller.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Return the page target bound at construction, if this is a page socket.
    pub fn target_id(&self) -> Option<&str> {
        self.target_id.as_deref()
    }

    /// Replace the unsolicited-event buffer bounds for owners that drain
    /// after every command and enforce their own retained-event budget.
    /// Overflow is still reported through `CdpEventBatch`.
    pub fn set_event_buffer_limits(&mut self, max_items: usize, max_bytes: usize) {
        self.events.max_items = max_items;
        self.events.max_bytes = max_bytes;
    }

    /// Drain unsolicited events observed since the previous drain.
    ///
    /// `dropped` and `overflowed` describe events that could not be retained
    /// due to the count or byte limit; ordinary empty batches have both set to
    /// zero and false respectively.
    pub fn drain_events(&mut self) -> CdpEventBatch {
        self.events.drain()
    }

    /// Send one CDP command and return its `result` object.
    ///
    /// Unsolicited CDP events are retained until the matching response arrives
    /// or the caller drains the bounded event buffer.
    /// A response for a different request identifier is a protocol failure and
    /// is never attributed to the caller's command.
    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, CdpTransportError> {
        self.request_scoped(method, params, None, None)
    }

    /// Send a page command through a flattened browser target session.
    pub fn request_in_session(
        &mut self,
        method: &str,
        params: Value,
        session_id: &str,
    ) -> Result<Value, CdpTransportError> {
        self.request_scoped(method, params, Some(session_id), None)
    }

    /// Send a command while polling for caller cancellation between reads.
    pub fn request_with_cancellation(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, CdpTransportError> {
        self.request_scoped(method, params, None, Some(cancellation))
    }

    /// Send a page command through a flattened browser session with cancellation.
    pub fn request_in_session_with_cancellation(
        &mut self,
        method: &str,
        params: Value,
        session_id: &str,
        cancellation: &Cancellation,
    ) -> Result<Value, CdpTransportError> {
        self.request_scoped(method, params, Some(session_id), Some(cancellation))
    }

    /// Send a page command with cancellation while letting `hook` answer
    /// unsolicited events that arrive before the reply.
    ///
    /// Some targets block an in-flight command until another target is
    /// serviced (for example, `window.open` holds the opener's input ack until
    /// the new page's domains are enabled). The hook sees each event before it
    /// is buffered and returns commands to send at once; their responses are
    /// discarded like abandoned responses. The event is still retained.
    pub fn request_with_event_hook(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        cancellation: &Cancellation,
        hook: &mut dyn FnMut(&Value) -> Vec<DetachedCommand>,
    ) -> Result<Value, CdpTransportError> {
        self.request_hooked(method, params, session_id, Some(cancellation), Some(hook))
    }

    fn send_detached(&mut self, command: DetachedCommand) -> Result<(), CdpTransportError> {
        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(CdpTransportError::RequestIdExhausted)?;
        let mut envelope = json!({"id": id, "method": command.method, "params": command.params});
        if let Some(session_id) = &command.session_id {
            envelope["sessionId"] = Value::String(session_id.clone());
        }
        let payload = serde_json::to_string(&envelope)
            .map_err(|error| CdpTransportError::InvalidMessage(error.to_string()))?;
        if payload.len() > self.max_message_bytes {
            return Err(CdpTransportError::InvalidMessage(
                "CDP request exceeds the protocol message limit".into(),
            ));
        }
        self.remember_abandoned_response(id, command.session_id.as_deref())?;
        self.socket
            .send(Message::text(payload))
            .map_err(map_socket_error)
    }

    fn request_scoped(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        cancellation: Option<&Cancellation>,
    ) -> Result<Value, CdpTransportError> {
        self.request_hooked(method, params, session_id, cancellation, None)
    }

    fn request_hooked(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        cancellation: Option<&Cancellation>,
        mut hook: Option<&mut dyn FnMut(&Value) -> Vec<DetachedCommand>>,
    ) -> Result<Value, CdpTransportError> {
        if method.is_empty() {
            return Err(CdpTransportError::InvalidMessage(
                "CDP method must be non-empty".into(),
            ));
        }
        check_cancellation(cancellation)?;

        let id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or(CdpTransportError::RequestIdExhausted)?;
        let mut envelope = json!({"id": id, "method": method, "params": params});
        if let Some(session_id) = session_id {
            envelope["sessionId"] = Value::String(session_id.to_owned());
        }
        let payload = serde_json::to_string(&envelope)
            .map_err(|error| CdpTransportError::InvalidMessage(error.to_string()))?;
        if payload.len() > self.max_message_bytes {
            return Err(CdpTransportError::InvalidMessage(
                "CDP request exceeds the protocol message limit".into(),
            ));
        }
        let deadline = Instant::now()
            .checked_add(self.request_timeout)
            .ok_or(CdpTransportError::Timeout)?;
        if let Err(error) = self.set_socket_timeout(deadline, cancellation.is_some()) {
            if matches!(error, CdpTransportError::Timeout) {
                self.remember_abandoned_response(id, session_id)?;
            }
            return Err(error);
        }
        self.socket
            .send(Message::text(payload))
            .map_err(map_socket_error)?;

        loop {
            if let Some(reason) = cancellation.and_then(Cancellation::reason) {
                self.remember_abandoned_response(id, session_id)?;
                return Err(CdpTransportError::Cancelled(reason.to_owned()));
            }
            if let Err(error) = self.set_socket_timeout(deadline, cancellation.is_some()) {
                if matches!(error, CdpTransportError::Timeout) {
                    self.remember_abandoned_response(id, session_id)?;
                }
                return Err(error);
            }
            let message = match self.socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    if let Some(reason) = cancellation.and_then(Cancellation::reason) {
                        self.remember_abandoned_response(id, session_id)?;
                        return Err(CdpTransportError::Cancelled(reason.to_owned()));
                    }
                    if cancellation.is_some() && Instant::now() < deadline {
                        continue;
                    }
                    self.remember_abandoned_response(id, session_id)?;
                    return Err(CdpTransportError::Timeout);
                }
                Err(error) => return Err(map_socket_error(error)),
            };
            if message.len() > self.max_message_bytes {
                return Err(CdpTransportError::InvalidMessage(
                    "CDP response exceeds the protocol message limit".into(),
                ));
            }
            if message.is_close() {
                return Err(CdpTransportError::InvalidMessage(
                    "CDP peer closed the connection before replying".into(),
                ));
            }
            if !(message.is_text() || message.is_binary()) {
                continue;
            }
            let body = message
                .into_text()
                .map_err(|error| CdpTransportError::InvalidMessage(error.to_string()))?;
            let value: Value = serde_json::from_str(body.as_str())
                .map_err(|error| CdpTransportError::InvalidMessage(error.to_string()))?;
            let Some(response_id) = value.get("id").and_then(Value::as_i64) else {
                if let Some(hook) = hook.as_mut() {
                    for command in hook(&value) {
                        self.send_detached(command)?;
                    }
                }
                self.events.record(value, body.len());
                continue;
            };
            if response_id != id {
                if self.consume_abandoned_response(response_id, &value)? {
                    continue;
                }
                return Err(CdpTransportError::InvalidMessage(format!(
                    "received response id {response_id} while waiting for {id}"
                )));
            }
            if session_id.is_some() && value.get("sessionId").and_then(Value::as_str) != session_id
            {
                return Err(CdpTransportError::InvalidMessage(
                    "CDP response did not match the selected target session".into(),
                ));
            }
            if let Some(error) = value.get("error") {
                return Err(CdpTransportError::Protocol {
                    code: error.get("code").and_then(Value::as_i64),
                    message: error
                        .get("message")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown CDP error")
                        .to_owned(),
                });
            }
            return value.get("result").cloned().ok_or_else(|| {
                CdpTransportError::InvalidMessage("CDP response omitted result".into())
            });
        }
    }

    /// Read and retain unsolicited events during an observation window.
    pub fn poll_events(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), CdpTransportError> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(CdpTransportError::Timeout)?;

        loop {
            check_cancellation(Some(cancellation))?;
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Ok(());
            };
            let read_window = remaining.min(CANCELLATION_POLL_INTERVAL);
            self.socket.get_mut().set_read_timeout(Some(read_window))?;

            let message = match self.socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) =>
                {
                    continue;
                }
                Err(error) => return Err(map_socket_error(error)),
            };
            self.record_event_message(message)?;
        }
    }

    fn record_event_message(&mut self, message: Message) -> Result<(), CdpTransportError> {
        if message.is_close() {
            return Err(CdpTransportError::InvalidMessage(
                "CDP peer closed the connection while observing events".into(),
            ));
        }
        if !(message.is_text() || message.is_binary()) {
            return Ok(());
        }
        if message.len() > self.max_message_bytes {
            return Err(CdpTransportError::InvalidMessage(
                "CDP event exceeds the protocol message limit".into(),
            ));
        }

        let body = message
            .into_text()
            .map_err(|error| CdpTransportError::InvalidMessage(error.to_string()))?;
        let value: Value = serde_json::from_str(body.as_str())
            .map_err(|error| CdpTransportError::InvalidMessage(error.to_string()))?;
        if let Some(response_id) = value.get("id").and_then(Value::as_i64) {
            if self.consume_abandoned_response(response_id, &value)? {
                return Ok(());
            }
            return Err(CdpTransportError::InvalidMessage(
                "CDP delivered an unsolicited command response".into(),
            ));
        }
        if value.get("method").and_then(Value::as_str).is_none() {
            return Err(CdpTransportError::InvalidMessage(
                "CDP event omitted its method".into(),
            ));
        }

        self.events.record(value, body.len());
        Ok(())
    }

    fn remember_abandoned_response(
        &mut self,
        request_id: i64,
        session_id: Option<&str>,
    ) -> Result<(), CdpTransportError> {
        const MAX_ABANDONED_RESPONSES: usize = 128;

        if self.abandoned_responses.len() >= MAX_ABANDONED_RESPONSES {
            return Err(CdpTransportError::InvalidMessage(
                "CDP abandoned-response capacity was exhausted".into(),
            ));
        }
        self.abandoned_responses
            .insert(request_id, session_id.map(str::to_owned));
        Ok(())
    }

    fn consume_abandoned_response(
        &mut self,
        response_id: i64,
        response: &Value,
    ) -> Result<bool, CdpTransportError> {
        let Some(expected_session) = self.abandoned_responses.remove(&response_id) else {
            return Ok(false);
        };
        if response.get("sessionId").and_then(Value::as_str) != expected_session.as_deref() {
            return Err(CdpTransportError::InvalidMessage(
                "late CDP response did not match its cancelled target session".into(),
            ));
        }
        Ok(true)
    }

    fn set_socket_timeout(
        &mut self,
        deadline: Instant,
        poll_for_cancellation: bool,
    ) -> Result<(), CdpTransportError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(CdpTransportError::Timeout)?;
        let read_timeout = if poll_for_cancellation {
            remaining.min(CANCELLATION_POLL_INTERVAL)
        } else {
            remaining
        };
        self.socket.get_mut().set_read_timeout(Some(read_timeout))?;
        self.socket.get_mut().set_write_timeout(Some(remaining))?;
        Ok(())
    }

    /// Send the WebSocket close handshake while retaining the owner for error handling.
    pub fn close_connection(&mut self) -> Result<(), CdpTransportError> {
        self.socket.close(None).map_err(CdpTransportError::from)
    }

    /// Close the WebSocket explicitly. Dropping the transport also releases it.
    pub fn close(mut self) -> Result<(), CdpTransportError> {
        self.close_connection()
    }
}

fn check_cancellation(cancellation: Option<&Cancellation>) -> Result<(), CdpTransportError> {
    let Some(reason) = cancellation.and_then(Cancellation::reason) else {
        return Ok(());
    };
    Err(CdpTransportError::Cancelled(reason.to_owned()))
}

fn map_socket_error(error: tungstenite::Error) -> CdpTransportError {
    match error {
        tungstenite::Error::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            CdpTransportError::Timeout
        }
        other => CdpTransportError::WebSocket(other),
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedEndpoint<'a> {
    host: &'a str,
    port: u16,
    path: &'a str,
}

impl<'a> ParsedEndpoint<'a> {
    fn parse(endpoint: &'a str, target_id: Option<&str>) -> Result<Self, CdpTransportError> {
        let remainder = endpoint.strip_prefix("ws://").ok_or_else(|| {
            CdpTransportError::InvalidEndpoint(
                "CDP WebSocket endpoint must use ws:// on loopback".into(),
            )
        })?;
        if remainder.contains('?') || remainder.contains('#') || remainder.contains('@') {
            return Err(CdpTransportError::InvalidEndpoint(
                "CDP endpoint must not contain credentials, query, or fragment".into(),
            ));
        }
        let (authority, _path) = remainder.split_once('/').ok_or_else(|| {
            CdpTransportError::InvalidEndpoint("CDP endpoint must include a WebSocket path".into())
        })?;
        let (host, port) = parse_authority(authority)?;
        let parsed = Self {
            host,
            port,
            path: &remainder[authority.len()..],
        };
        let page_id = cdp_path_target(parsed.path, "page")?;
        let browser_id = cdp_path_target(parsed.path, "browser")?;
        if page_id.is_none() && browser_id.is_none() {
            return Err(CdpTransportError::InvalidEndpoint(
                "CDP endpoint path must be /devtools/page/<id> or /devtools/browser/<id>".into(),
            ));
        }
        if let Some(target_id) = target_id {
            if page_id != Some(target_id) {
                return Err(CdpTransportError::InvalidEndpoint(
                    "CDP page endpoint does not identify the selected target".into(),
                ));
            }
        } else if page_id.is_none() && browser_id.is_none() {
            return Err(CdpTransportError::InvalidEndpoint(
                "CDP endpoint has no target scope".into(),
            ));
        }
        Ok(parsed)
    }
}

fn parse_authority(authority: &str) -> Result<(&str, u16), CdpTransportError> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.split_once("]:").ok_or_else(|| {
            CdpTransportError::InvalidEndpoint("IPv6 CDP endpoint must include a port".into())
        })?;
        (host, port)
    } else {
        authority.rsplit_once(':').ok_or_else(|| {
            CdpTransportError::InvalidEndpoint("CDP endpoint must include an explicit port".into())
        })?
    };
    if !is_loopback_host(host) {
        return Err(CdpTransportError::InvalidEndpoint(
            "CDP endpoint must resolve to a loopback host".into(),
        ));
    }
    let port = port.parse::<u16>().map_err(|_| {
        CdpTransportError::InvalidEndpoint("CDP endpoint port must be numeric".into())
    })?;
    if port == 0 {
        return Err(CdpTransportError::InvalidEndpoint(
            "CDP endpoint port must be non-zero".into(),
        ));
    }
    Ok((host, port))
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "::1")
        || host.parse::<IpAddr>().is_ok_and(|address| {
            address == IpAddr::V4(Ipv4Addr::LOCALHOST) || address == IpAddr::V6(Ipv6Addr::LOCALHOST)
        })
}

fn cdp_path_target<'a>(path: &'a str, scope: &str) -> Result<Option<&'a str>, CdpTransportError> {
    let prefix = format!("/devtools/{scope}/");
    if !path.starts_with(&prefix) {
        return Ok(None);
    }
    let target = &path[prefix.len()..];
    if target.is_empty() || target.contains('/') {
        return Err(CdpTransportError::InvalidEndpoint(
            "CDP endpoint path contains an invalid identifier".into(),
        ));
    }
    Ok(Some(target))
}

fn resolve_loopback(port: u16, host: &str) -> Result<SocketAddr, CdpTransportError> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(CdpTransportError::Io)?;
    addresses
        .into_iter()
        .find(|address| address.ip().is_loopback())
        .ok_or_else(|| {
            CdpTransportError::InvalidEndpoint(
                "CDP endpoint did not resolve to a loopback address".into(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    fn start_mock_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
        let port = listener.local_addr().expect("mock address").port();
        let handle = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mock CDP");
            let mut socket = tungstenite::accept(stream).expect("WebSocket handshake");
            let request = socket.read().expect("read request");
            let request: Value = serde_json::from_str(request.to_text().expect("request text"))
                .expect("request JSON");
            let id = request
                .get("id")
                .and_then(Value::as_i64)
                .expect("request id");
            socket
                .send(Message::text(
                    r#"{"method":"Page.loadEventFired","params":{}}"#,
                ))
                .expect("send event");
            socket
                .send(Message::text(
                    serde_json::json!({"id":id,"result":{"ok":true}}).to_string(),
                ))
                .expect("send result");
        });
        (
            format!("ws://127.0.0.1:{port}/devtools/page/target-1"),
            handle,
        )
    }

    #[test]
    fn mock_websocket_returns_matching_result_after_event() {
        let (endpoint, server) = start_mock_server();
        let mut transport =
            CdpWebSocketTransport::connect_for_target(&endpoint, "target-1").expect("connect CDP");
        assert_eq!(
            transport
                .request("Page.enable", json!({}))
                .expect("request"),
            json!({"ok":true})
        );
        let events = transport.drain_events();
        assert_eq!(events.dropped, 0);
        assert!(!events.overflowed);
        assert_eq!(events.items.len(), 1);
        assert_eq!(events.items[0].sequence, 1);
        assert_eq!(events.items[0].value["method"], "Page.loadEventFired");
        assert!(transport.drain_events().items.is_empty());
        server.join().expect("mock server");
    }

    #[test]
    fn event_buffer_marks_byte_overflow_without_parsing_or_retaining() {
        let mut buffer = CdpEventBuffer::with_limits(2, 4);
        buffer.record(json!({"method": "too_large"}), 5);

        let batch = buffer.drain();
        assert!(batch.items.is_empty());
        assert_eq!(batch.dropped, 1);
        assert!(batch.overflowed);
    }

    #[test]
    fn event_buffer_preserves_order_and_reports_count_overflow() {
        let mut buffer = CdpEventBuffer::with_limits(2, 1024);
        buffer.record(json!({"method": "first"}), 1);
        buffer.record(json!({"method": "second"}), 1);
        buffer.record(json!({"method": "third"}), 1);

        let batch = buffer.drain();
        assert_eq!(
            batch
                .items
                .iter()
                .map(|event| event.value["method"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec!["first", "second"]
        );
        assert_eq!(
            batch
                .items
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(batch.dropped, 1);
        assert!(batch.overflowed);
    }

    #[test]
    fn rejects_endpoint_for_a_different_target() {
        let result = CdpWebSocketTransport::connect_for_target(
            "ws://127.0.0.1:9222/devtools/page/actual",
            "requested",
        );
        assert!(matches!(result, Err(CdpTransportError::InvalidEndpoint(_))));
    }

    #[test]
    fn rejects_non_loopback_endpoint() {
        let result = CdpWebSocketTransport::connect_for_target(
            "ws://192.0.2.1:9222/devtools/page/target",
            "target",
        );
        assert!(matches!(result, Err(CdpTransportError::InvalidEndpoint(_))));
    }

    #[test]
    fn request_has_one_bounded_deadline_across_events() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
        let port = listener.local_addr().expect("mock address").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mock CDP");
            let mut socket = tungstenite::accept(stream).expect("WebSocket handshake");
            let _ = socket.read().expect("read request");
            thread::sleep(Duration::from_millis(100));
        });
        let endpoint = format!("ws://127.0.0.1:{port}/devtools/page/target-1");
        let mut transport = CdpWebSocketTransport::connect_with_timeout(
            &endpoint,
            Some("target-1"),
            Duration::from_millis(20),
        )
        .expect("connect CDP");
        let result = transport.request("Page.enable", json!({}));
        assert!(matches!(result, Err(CdpTransportError::Timeout)));
        server.join().expect("mock server");
    }

    #[test]
    fn cancelled_request_does_not_poison_later_cleanup_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
        let port = listener.local_addr().expect("mock address").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mock CDP");
            let mut socket = tungstenite::accept(stream).expect("WebSocket handshake");
            let first_request = socket.read().expect("read active request");
            let first_request: Value =
                serde_json::from_str(first_request.to_text().expect("request text"))
                    .expect("request JSON");
            let first_id = first_request["id"].as_i64().expect("active request id");

            thread::sleep(Duration::from_millis(150));
            socket
                .send(Message::text(
                    json!({"id": first_id, "result": {"late": true}}).to_string(),
                ))
                .expect("send late active response");

            let cleanup_request = socket.read().expect("read cleanup request");
            let cleanup_request: Value =
                serde_json::from_str(cleanup_request.to_text().expect("request text"))
                    .expect("request JSON");
            let cleanup_id = cleanup_request["id"].as_i64().expect("cleanup request id");
            socket
                .send(Message::text(
                    json!({"id": cleanup_id, "result": {"closed": true}}).to_string(),
                ))
                .expect("send cleanup response");
        });

        let endpoint = format!("ws://127.0.0.1:{port}/devtools/page/target-1");
        let mut transport = CdpWebSocketTransport::connect_with_timeout(
            &endpoint,
            Some("target-1"),
            Duration::from_secs(1),
        )
        .expect("connect CDP");
        let cancellation = Cancellation::default();
        let trigger = cancellation.clone();
        let canceller = thread::spawn(move || {
            thread::sleep(Duration::from_millis(30));
            trigger.cancel("test cancellation");
        });

        let cancelled =
            transport.request_with_cancellation("Page.getFrameTree", json!({}), &cancellation);
        assert!(matches!(cancelled, Err(CdpTransportError::Cancelled(_))));
        canceller.join().expect("cancellation trigger");

        assert_eq!(
            transport
                .request("Page.disable", json!({}))
                .expect("cleanup request after late response"),
            json!({"closed":true})
        );
        server.join().expect("mock server");
    }

    #[test]
    fn flattened_session_request_is_scoped_and_validates_its_response() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
        let port = listener.local_addr().expect("mock address").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mock CDP");
            let mut socket = tungstenite::accept(stream).expect("WebSocket handshake");
            let attach = socket.read().expect("read attach request");
            let attach: Value =
                serde_json::from_str(attach.to_text().expect("request text")).expect("attach JSON");
            assert_eq!(attach["method"], "Target.attachToTarget");
            let attach_id = attach["id"].as_i64().expect("attach id");
            socket
                .send(Message::text(
                    json!({"id": attach_id, "result": {"sessionId": "session-7"}}).to_string(),
                ))
                .expect("send attach response");

            let page_request = socket.read().expect("read page request");
            let page_request: Value =
                serde_json::from_str(page_request.to_text().expect("request text"))
                    .expect("page request JSON");
            assert_eq!(page_request["sessionId"], "session-7");
            assert_eq!(page_request["method"], "Page.enable");
            let page_id = page_request["id"].as_i64().expect("page request id");
            socket
                .send(Message::text(
                    json!({
                        "id": page_id,
                        "sessionId": "session-7",
                        "result": {"enabled": true}
                    })
                    .to_string(),
                ))
                .expect("send page response");
        });

        let endpoint = format!("ws://127.0.0.1:{port}/devtools/browser/browser-1");
        let mut transport = CdpWebSocketTransport::connect(&endpoint).expect("connect browser");
        let attached = transport
            .request(
                "Target.attachToTarget",
                json!({"targetId":"target-1","flatten":true}),
            )
            .expect("attach selected page");
        let session_id = attached["sessionId"].as_str().expect("session id");

        assert_eq!(
            transport
                .request_in_session("Page.enable", json!({}), session_id)
                .expect("page command"),
            json!({"enabled":true})
        );
        server.join().expect("mock server");
    }

    #[test]
    fn event_polling_retains_events_received_during_observation() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind mock CDP");
        let port = listener.local_addr().expect("mock address").port();
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept mock CDP");
            let mut socket = tungstenite::accept(stream).expect("WebSocket handshake");
            socket
                .send(Message::text(
                    json!({
                        "method": "Debugger.scriptParsed",
                        "params": {"scriptId": "3", "url": "file:///app.js"}
                    })
                    .to_string(),
                ))
                .expect("send script event");
            thread::sleep(Duration::from_millis(120));
        });

        let endpoint = format!("ws://127.0.0.1:{port}/devtools/page/target-1");
        let mut transport =
            CdpWebSocketTransport::connect_for_target(&endpoint, "target-1").expect("connect CDP");
        transport
            .poll_events(Duration::from_millis(60), &Cancellation::default())
            .expect("poll observation window");
        let events = transport.drain_events();
        assert_eq!(events.items.len(), 1);
        assert_eq!(events.items[0].value["method"], "Debugger.scriptParsed");
        server.join().expect("mock server");
    }
}
