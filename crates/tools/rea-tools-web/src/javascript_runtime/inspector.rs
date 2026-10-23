//! One correlated JSON-RPC connection to a validated V8 Inspector socket.
//!
//! Compatibility owner: `src/browser/CdpConnection.ts` as used by
//! `V8InspectorProvider` (`maxPayloadBytes` = 16 MiB, 20 s handshake and
//! command deadlines). Node serves its Inspector sockets at `/<id>` or
//! `/devtools/node/<id>`, which `rea_host::cdp_transport` does not accept, so
//! this owner speaks WebSocket directly over a literal loopback TCP stream.
use crate::cdp::observation_error;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::io::ErrorKind as IoKind;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

/// `INSPECTOR_MAX_PAYLOAD_BYTES`.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 16 * 1024 * 1024;
/// `WEB_RUNTIME_LIMITS.commandTimeoutMs`.
const COMMAND_TIMEOUT_MS: u64 = 20_000;
const POLL: Duration = Duration::from_millis(50);

/// One validated CDP event envelope.
pub(crate) struct Event {
    pub method: String,
    pub params: Value,
}

pub(crate) struct Inspector {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    operation: String,
}

impl Inspector {
    /// `CdpConnection.connect` + `waitForOpen`.
    pub(crate) fn connect(
        url: &str,
        operation: &str,
        cancellation: &Cancellation,
    ) -> Result<Self, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let unreachable = || observation_error(operation, "endpoint_unreachable", None);
        let timeout = || {
            observation_error(
                operation,
                "timeout",
                Some(format!(
                    "CDP WebSocket handshake exceeded its {COMMAND_TIMEOUT_MS} ms deadline."
                )),
            )
        };
        let parsed = url::Url::parse(url).map_err(|_| unreachable())?;
        let host = parsed.host_str().unwrap_or_default();
        let ip = host.trim_start_matches('[').trim_end_matches(']');
        let address = SocketAddr::new(
            ip.parse().map_err(|_| unreachable())?,
            parsed.port().unwrap_or(80),
        );
        let budget = Duration::from_millis(COMMAND_TIMEOUT_MS);
        let stream = TcpStream::connect_timeout(&address, budget).map_err(|error| {
            if error.kind() == IoKind::TimedOut {
                timeout()
            } else {
                unreachable()
            }
        })?;
        stream
            .set_read_timeout(Some(budget))
            .map_err(|_| unreachable())?;
        stream
            .set_write_timeout(Some(budget))
            .map_err(|_| unreachable())?;
        let _ = stream.set_nodelay(true);
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_PAYLOAD_BYTES))
            .max_frame_size(Some(MAX_PAYLOAD_BYTES));
        let (socket, _) = tungstenite::client::client_with_config(url, stream, Some(config))
            .map_err(|error| match error {
                tungstenite::HandshakeError::Failure(tungstenite::Error::Io(io))
                    if matches!(io.kind(), IoKind::TimedOut | IoKind::WouldBlock) =>
                {
                    timeout()
                }
                _ => unreachable(),
            })?;
        if cancellation.reason().is_some() {
            let mut connection = Self {
                socket,
                next_id: 1,
                operation: operation.to_owned(),
            };
            connection.close();
            return Err(AnalysisError::cancelled(operation));
        }
        Ok(Self {
            socket,
            next_id: 1,
            operation: operation.to_owned(),
        })
    }

    fn failure(&self, reason: &str) -> AnalysisError {
        let detail = (reason == "payload_limit").then(|| {
            format!("CDP message exceeded the selected {MAX_PAYLOAD_BYTES} byte protocol budget.")
        });
        observation_error(&self.operation, reason, detail)
    }

    /// Send one command, delivering events to `ingest` until its response.
    pub(crate) fn send(
        &mut self,
        method: &str,
        cancellation: &Cancellation,
        ingest: &mut dyn FnMut(Event),
    ) -> Result<Value, AnalysisError> {
        if cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(&self.operation));
        }
        let id = self.next_id;
        self.next_id += 1;
        let message = json!({ "id": id, "method": method, "params": {} }).to_string();
        self.socket
            .send(Message::text(message))
            .map_err(|error| self.socket_failure(&error))?;
        let deadline = Instant::now() + Duration::from_millis(COMMAND_TIMEOUT_MS);
        loop {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(&self.operation));
            }
            if Instant::now() >= deadline {
                return Err(observation_error(
                    &self.operation,
                    "timeout",
                    Some(format!(
                        "CDP command {method} exceeded its {COMMAND_TIMEOUT_MS} ms response deadline."
                    )),
                ));
            }
            match self.receive()? {
                Received::Idle => {}
                Received::Event(event) => ingest(event),
                Received::Response { id: response, body } if response == id => {
                    return self.response(method, &body);
                }
                Received::Response { .. } => {}
            }
        }
    }

    /// Correlated response validation (`#receiveResponse`).
    fn response(&self, method: &str, body: &Map<String, Value>) -> Result<Value, AnalysisError> {
        let has_result = body.contains_key("result");
        let has_error = body.contains_key("error");
        if body.contains_key("sessionId") || has_result == has_error {
            return Err(self.failure("protocol_error"));
        }
        if has_result {
            return match body.get("result") {
                Some(result @ Value::Object(_)) => Ok(result.clone()),
                _ => Err(self.failure("protocol_error")),
            };
        }
        let reported = body.get("error").and_then(Value::as_object);
        let code = reported
            .and_then(|error| error.get("code"))
            .and_then(Value::as_i64);
        let message = reported
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str);
        match (code, message) {
            (Some(code), Some(message)) => Err(observation_error(
                &self.operation,
                "protocol_error",
                Some(format!("CDP {method} failed ({code}): {message}")),
            )),
            _ => Err(self.failure("protocol_error")),
        }
    }

    /// `waitForCapture`: deliver events until the window elapses, the peer
    /// disconnects, or the wire fails.
    pub(crate) fn observe(
        &mut self,
        observation_ms: u64,
        cancellation: &Cancellation,
        ingest: &mut dyn FnMut(Event),
    ) -> Result<(), AnalysisError> {
        let deadline = Instant::now().checked_add(Duration::from_millis(observation_ms));
        loop {
            if cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(&self.operation));
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Ok(());
            }
            match self.receive()? {
                Received::Event(event) => ingest(event),
                Received::Idle | Received::Response { .. } => {}
            }
        }
    }

    fn socket_failure(&self, error: &tungstenite::Error) -> AnalysisError {
        match error {
            tungstenite::Error::Capacity(_) => self.failure("payload_limit"),
            _ => self.failure("disconnected"),
        }
    }

    /// `#receive`: one bounded read.
    fn receive(&mut self) -> Result<Received, AnalysisError> {
        let _ = self.socket.get_mut().set_read_timeout(Some(POLL));
        let message = match self.socket.read() {
            Ok(message) => message,
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    IoKind::WouldBlock | IoKind::TimedOut | IoKind::Interrupted
                ) =>
            {
                return Ok(Received::Idle);
            }
            Err(error) => return Err(self.socket_failure(&error)),
        };
        let text = match message {
            Message::Text(text) => text.as_str().to_owned(),
            Message::Binary(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Message::Close(_) => return Err(self.failure("disconnected")),
            _ => return Ok(Received::Idle),
        };
        let Ok(Value::Object(body)) = serde_json::from_str::<Value>(&text) else {
            return Err(self.failure("protocol_error"));
        };
        if let Some(id) = body.get("id") {
            return match id
                .as_u64()
                .filter(|id| *id >= 1 && *id <= 9_007_199_254_740_991)
            {
                Some(id) => Ok(Received::Response { id, body }),
                None => Err(self.failure("protocol_error")),
            };
        }
        let method = body
            .get("method")
            .and_then(Value::as_str)
            .filter(|method| !method.is_empty());
        let params_valid = body.get("params").is_none_or(Value::is_object);
        let session_valid = body.get("sessionId").is_none_or(Value::is_string);
        match method {
            Some(method) if params_valid && session_valid => Ok(Received::Event(Event {
                method: method.to_owned(),
                params: body
                    .get("params")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new())),
            })),
            _ => Err(self.failure("protocol_error")),
        }
    }

    /// Close only REA's socket; the TCP stream is released on drop.
    pub(crate) fn close(&mut self) {
        let _ = self
            .socket
            .get_mut()
            .set_read_timeout(Some(Duration::from_millis(100)));
        let _ = self.socket.close(None);
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            match self.socket.read() {
                Ok(_) => {}
                Err(tungstenite::Error::Io(error))
                    if matches!(error.kind(), IoKind::WouldBlock | IoKind::TimedOut) => {}
                Err(_) => break,
            }
        }
        let _ = self.socket.get_mut().shutdown(std::net::Shutdown::Both);
    }
}

enum Received {
    Idle,
    Event(Event),
    Response { id: u64, body: Map<String, Value> },
}
