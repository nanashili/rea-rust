//! JEB MCP streamable-HTTP connection: legacy `initialize` handshake,
//! `tools/list` catalog walk, `tools/call` dispatch, and result decoding.
//!
//! Compatibility owners: `src/jeb/JebMcpConnection.ts` (connection,
//! `decodeJebToolResult`, `readToolNames`) and `src/jeb/JebMcpConnectionOwner.ts`
//! (one SDK client + transport whose failed cleanup retains both identities).
//!
//! The `@modelcontextprotocol/client` 2.3.1 default version-negotiation mode is
//! `legacy`, so the handshake offers `protocolVersion: "2025-11-25"` (the
//! latest supported legacy revision), `capabilities: {}` and
//! `clientInfo: { name: "rea-jeb", version: "0.0.0" }`, then sends the
//! `notifications/initialized` notification. The session id returned on the
//! `initialize` response is carried on every later request, and session
//! termination sends an HTTP `DELETE`.
use super::endpoint::Endpoint;
use super::http::{self, Deadline, HttpError, HttpResponse, RequestHeaders};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::sync::Mutex;

/// Upstream protocol names for the operations REA exposes.
///
/// Compatibility owner: `JEB_ENGINE_TOOLS`.
pub const JEB_ENGINE_TOOLS: [(&str, &str); 4] = [
    ("inspect_jeb_client", "get_client_information"),
    ("open_jeb_project", "open_project"),
    ("list_jeb_units", "list_units"),
    ("decompile_jeb_item", "decompile_code_item"),
];

/// Latest legacy protocol revision the SDK offers in the `initialize` request.
const LEGACY_PROTOCOL_VERSION: &str = "2025-11-25";

/// Supported legacy protocol revisions (the SDK offers the newest and accepts
/// any of these in the `initialize` response).
const SUPPORTED_LEGACY_VERSIONS: [&str; 4] =
    ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"];

const ACCEPT: &str = "application/json, text/event-stream";
const CONTENT_TYPE: &str = "application/json";

/// A physical failure captured before any resource cleanup.
///
/// Compatibility owner: `JebMcpPhysicalFailure`. The SDK's phase label
/// (catalog vs tool) is decorative in the TS wrapper message; the provider's
/// classification uses the inner cause's message, so only that message and the
/// typed deadline outcomes are preserved here.
#[derive(Debug)]
pub enum PhysicalFailure {
    /// A transport/connection failure, carrying its OS/protocol message.
    Transport(HttpError),
    /// A protocol violation that cannot establish an observation.
    Protocol(String),
    /// A timeout classified from the deadline.
    Timeout,
    /// A cancellation classified from the deadline.
    Cancelled(String),
}

/// The decoded result of one JEB MCP tool call.
pub type ToolResult = Value;

/// One SDK client that owns its attached transport.
///
/// Compatibility owner: `JebMcpConnectionOwner`. The connection is lazily
/// established, retained in session state, and torn down by session cleanup:
/// a `DELETE` session-termination attempt whose failure retains the client and
/// transport resource identities for a later retry.
pub struct JebMcpConnection {
    endpoint: Endpoint,
    discovery_timeout_ms: u64,
    request_timeout_ms: u64,
    inner: Mutex<ConnectionState>,
}

#[derive(Default)]
struct ConnectionState {
    /// Session id negotiated by the `initialize` handshake.
    session_id: Option<String>,
    /// Negotiated legacy protocol version, set after the handshake.
    protocol_version: Option<String>,
    /// Advertised engine tool names relevant to REA, once discovered.
    tools: Option<Vec<String>>,
    /// Next JSON-RPC request id (a monotonic numeric counter, like the SDK).
    next_id: i64,
    /// True once the session was closed and must not be reused.
    closed: bool,
}

impl JebMcpConnection {
    pub fn new(endpoint: Endpoint, discovery_timeout_ms: u64, request_timeout_ms: u64) -> Self {
        Self {
            endpoint,
            discovery_timeout_ms,
            request_timeout_ms,
            inner: Mutex::new(ConnectionState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnectionState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Lazily run the legacy handshake and return the relevant engine tools.
    ///
    /// Compatibility owner: the `connect`/acquisition path. The initial
    /// acquisition owns its discovery deadline; a failure aborts the owner and
    /// disposes the failed connection.
    pub fn connect(&self, cancellation: &Cancellation) -> Result<Vec<String>, PhysicalFailure> {
        if let Some(reason) = cancellation.reason() {
            return Err(PhysicalFailure::Cancelled(reason.to_owned()));
        }
        {
            let state = self.lock();
            if state.closed {
                return Err(PhysicalFailure::Protocol(
                    "JEB MCP connection is closed".to_owned(),
                ));
            }
            if let Some(tools) = &state.tools {
                return Ok(tools.clone());
            }
        }

        let deadline = Deadline::new(self.discovery_timeout_ms, cancellation);
        self.handshake(&deadline)?;
        let tools = self.read_tool_names(&deadline)?;
        let mut state = self.lock();
        state.tools = Some(tools.clone());
        Ok(tools)
    }

    /// Refresh support for REA operations from the live engine catalog.
    ///
    /// Compatibility owner: `listTools`. The first acquisition owns its
    /// deadline; a later refresh runs a fresh discovery deadline.
    pub fn list_tools(&self, cancellation: &Cancellation) -> Result<Vec<String>, PhysicalFailure> {
        let had_tools = self.lock().tools.is_some();
        let tools = self.connect(cancellation)?;
        if !had_tools {
            return Ok(tools);
        }
        let deadline = Deadline::new(self.discovery_timeout_ms, cancellation);
        let refreshed = self.read_tool_names(&deadline)?;
        self.lock().tools = Some(refreshed.clone());
        Ok(refreshed)
    }

    /// Invoke one JEB MCP tool and decode its single structured result.
    ///
    /// Compatibility owner: `call` + `decodeJebToolResult`.
    pub fn call(
        &self,
        name: &str,
        arguments: Map<String, Value>,
        cancellation: &Cancellation,
    ) -> Result<ToolResult, PhysicalFailure> {
        self.connect(cancellation)?;
        if let Some(reason) = cancellation.reason() {
            return Err(PhysicalFailure::Cancelled(reason.to_owned()));
        }
        let deadline = Deadline::new(self.request_timeout_ms, cancellation);
        let result = self.request(
            "tools/call",
            json!({ "name": name, "arguments": Value::Object(arguments) }),
            &deadline,
        )?;
        decode_tool_result(result)
    }

    /// The legacy `initialize` handshake followed by `notifications/initialized`.
    fn handshake(&self, deadline: &Deadline<'_>) -> Result<(), PhysicalFailure> {
        let params = json!({
            "protocolVersion": LEGACY_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "rea-jeb", "version": "0.0.0" },
        });
        // The handshake POST carries no session id (the transport deletes it
        // for the initialize request) and no negotiated protocol version yet.
        let id = self.allocate_id();
        let message = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": params,
        });
        let body = serde_json::to_vec(&message).unwrap_or_default();
        let headers = RequestHeaders {
            session_id: None,
            protocol_version: None,
            content_type: Some(CONTENT_TYPE.to_owned()),
            accept: Some(ACCEPT.to_owned()),
        };
        let response = self.exchange("POST", &headers, &body, deadline)?;
        // The engine's session id (if any) is captured from the response.
        let session_id = response.session_id.clone();
        let result = self.decode_rpc_result(id, response)?;

        let negotiated = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                PhysicalFailure::Protocol("Server sent invalid initialize result".to_owned())
            })?;
        if !SUPPORTED_LEGACY_VERSIONS.contains(&negotiated) {
            return Err(PhysicalFailure::Protocol(format!(
                "Server's protocol version is not supported: {negotiated}"
            )));
        }
        let negotiated = negotiated.to_owned();

        {
            let mut state = self.lock();
            state.session_id = session_id;
            state.protocol_version = Some(negotiated.clone());
        }

        // `notifications/initialized` carries the session id and the now
        // negotiated protocol version.
        self.notify("notifications/initialized", deadline)?;
        Ok(())
    }

    /// Walk the engine's tool catalog, collecting the names REA exposes.
    ///
    /// Compatibility owner: `readToolNames`. Single pages are requested so the
    /// retained names and the whole walk stay bounded; a repeated cursor is a
    /// protocol error, and discovery stops once every relevant tool is seen.
    fn read_tool_names(&self, deadline: &Deadline<'_>) -> Result<Vec<String>, PhysicalFailure> {
        let relevant: Vec<&str> = JEB_ENGINE_TOOLS.iter().map(|(_, name)| *name).collect();
        let mut names: Vec<String> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            if let Some(reason) = deadline_reason(deadline) {
                return Err(reason);
            }
            let params = match &cursor {
                Some(cursor) => json!({ "cursor": cursor }),
                None => Value::Null,
            };
            let page = self.request("tools/list", params, deadline)?;
            if let Some(tools) = page.get("tools").and_then(Value::as_array) {
                for tool in tools {
                    if let Some(tool_name) = tool.get("name").and_then(Value::as_str)
                        && relevant.contains(&tool_name)
                        && !names.iter().any(|existing| existing == tool_name)
                    {
                        names.push(tool_name.to_owned());
                    }
                }
            }
            let next = page
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let (Some(next), Some(current)) = (&next, &cursor)
                && next == current
            {
                return Err(PhysicalFailure::Protocol(
                    "JEB MCP repeated a tool catalog cursor".to_owned(),
                ));
            }
            if let Some(reason) = deadline_reason(deadline) {
                return Err(reason);
            }
            if names.len() == relevant.len() {
                return Ok(names);
            }
            match next {
                Some(next) => cursor = Some(next),
                None => return Ok(names),
            }
        }
    }

    /// Send a JSON-RPC request and return its `result` value.
    fn request(
        &self,
        method: &str,
        params: Value,
        deadline: &Deadline<'_>,
    ) -> Result<Value, PhysicalFailure> {
        let id = self.allocate_id();
        let mut message = Map::new();
        message.insert("jsonrpc".to_owned(), Value::String("2.0".to_owned()));
        message.insert("id".to_owned(), Value::from(id));
        message.insert("method".to_owned(), Value::String(method.to_owned()));
        if !params.is_null() {
            message.insert("params".to_owned(), params);
        }
        let body = serde_json::to_vec(&Value::Object(message)).unwrap_or_default();
        let headers = self.request_headers();
        let response = self.exchange("POST", &headers, &body, deadline)?;
        if let Some(session_id) = response.session_id.clone() {
            self.lock().session_id = Some(session_id);
        }
        self.decode_rpc_result(id, response)
    }

    /// Send a JSON-RPC notification (no response id expected; 202 accepted).
    fn notify(&self, method: &str, deadline: &Deadline<'_>) -> Result<(), PhysicalFailure> {
        let message = json!({ "jsonrpc": "2.0", "method": method });
        let body = serde_json::to_vec(&message).unwrap_or_default();
        let headers = self.request_headers();
        let response = self.exchange("POST", &headers, &body, deadline)?;
        if let Some(session_id) = response.session_id {
            self.lock().session_id = Some(session_id);
        }
        Ok(())
    }

    fn request_headers(&self) -> RequestHeaders {
        let state = self.lock();
        RequestHeaders {
            session_id: state.session_id.clone(),
            protocol_version: state.protocol_version.clone(),
            content_type: Some(CONTENT_TYPE.to_owned()),
            accept: Some(ACCEPT.to_owned()),
        }
    }

    fn allocate_id(&self) -> i64 {
        let mut state = self.lock();
        let id = state.next_id;
        state.next_id += 1;
        id
    }

    fn exchange(
        &self,
        method: &str,
        headers: &RequestHeaders,
        body: &[u8],
        deadline: &Deadline<'_>,
    ) -> Result<HttpResponse, PhysicalFailure> {
        http::exchange(&self.endpoint, method, headers, body, deadline).map_err(classify_transport)
    }

    /// Parse the JSON-RPC response body and extract the matching `result`.
    fn decode_rpc_result(&self, id: i64, response: HttpResponse) -> Result<Value, PhysicalFailure> {
        let messages = parse_response_messages(&response)?;
        for message in messages {
            // Match the response/error by request id.
            let matches = message
                .get("id")
                .and_then(Value::as_i64)
                .map(|candidate| candidate == id)
                .unwrap_or(false);
            if !matches {
                continue;
            }
            if let Some(error) = message.get("error") {
                let message = error
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("JEB MCP returned a JSON-RPC error");
                return Err(PhysicalFailure::Protocol(format!(
                    "JEB MCP tool failed: {message}"
                )));
            }
            if let Some(result) = message.get("result") {
                return Ok(result.clone());
            }
        }
        Err(PhysicalFailure::Protocol(
            "JEB MCP returned no response for the request".to_owned(),
        ))
    }

    /// Terminate the session (`DELETE`) and release the connection.
    ///
    /// Compatibility owner: `close` + `JebMcpConnectionOwner.#closeResources`.
    /// A failed termination retains the client and transport resource
    /// identities so the owning session can retry.
    pub fn close(&self, cancellation: &Cancellation) -> Result<(), Vec<String>> {
        let session_id = {
            let mut state = self.lock();
            state.closed = true;
            state.tools = None;
            state.session_id.clone()
        };

        // No negotiated session means nothing to terminate upstream.
        let Some(session_id) = session_id else {
            return Ok(());
        };

        let deadline = Deadline::new(self.request_timeout_ms, cancellation);
        let headers = RequestHeaders {
            session_id: Some(session_id),
            protocol_version: self.lock().protocol_version.clone(),
            content_type: None,
            accept: Some(ACCEPT.to_owned()),
        };
        match http::exchange(&self.endpoint, "DELETE", &headers, &[], &deadline) {
            Ok(_) => {
                self.lock().session_id = None;
                Ok(())
            }
            // The server MAY respond 405 (termination not allowed): the SDK
            // treats that as success for session teardown.
            Err(HttpError::Status { status: 405, .. }) => {
                self.lock().session_id = None;
                Ok(())
            }
            Err(_) => Err(self.cleanup_resources()),
        }
    }

    /// Resource identities retained on failed cleanup.
    ///
    /// Compatibility owner: `JebMcpConnectionOwner.cleanupResources`.
    fn cleanup_resources(&self) -> Vec<String> {
        let href = self.endpoint.href();
        vec![
            format!("{href} (JEB MCP client)"),
            format!("{href} (JEB MCP transport)"),
        ]
    }
}

fn deadline_reason(deadline: &Deadline<'_>) -> Option<PhysicalFailure> {
    if deadline.remaining().is_zero() {
        Some(PhysicalFailure::Timeout)
    } else {
        None
    }
}

/// Classify a transport failure, preserving timeout and cancellation as their
/// own variants (the SDK/owner's deadline classifier).
fn classify_transport(error: HttpError) -> PhysicalFailure {
    match error {
        HttpError::Timeout => PhysicalFailure::Timeout,
        HttpError::Cancelled(reason) => PhysicalFailure::Cancelled(reason),
        other => PhysicalFailure::Transport(other),
    }
}

/// Parse a JSON or SSE response body into its JSON-RPC messages.
///
/// Compatibility owner: the transport's response parsing, which accepts an
/// `application/json` body or a `text/event-stream` body carrying `data:`
/// lines whose payloads are JSON-RPC messages.
fn parse_response_messages(response: &HttpResponse) -> Result<Vec<Value>, PhysicalFailure> {
    if response.status == 202 {
        // Accepted notification/ack: no body to parse.
        return Ok(Vec::new());
    }

    let media_type = response
        .content_type
        .as_deref()
        .map(media_type_essence)
        .unwrap_or_default();

    match media_type.as_str() {
        "application/json" => {
            let value: Value = serde_json::from_slice(&response.body).map_err(|error| {
                PhysicalFailure::Protocol(format!("JEB MCP returned invalid JSON: {error}"))
            })?;
            Ok(match value {
                Value::Array(items) => items,
                other => vec![other],
            })
        }
        "text/event-stream" => parse_sse(&response.body),
        other => Err(PhysicalFailure::Protocol(format!(
            "Unexpected content type: {other}"
        ))),
    }
}

/// Extract the essence media type (`type/subtype`) from a header value.
fn media_type_essence(content_type: &str) -> String {
    content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase()
}

/// Parse `text/event-stream` data events into JSON-RPC messages.
fn parse_sse(body: &[u8]) -> Result<Vec<Value>, PhysicalFailure> {
    let text = String::from_utf8_lossy(body);
    let mut messages = Vec::new();
    let mut data_lines: Vec<&str> = Vec::new();

    let flush = |data_lines: &mut Vec<&str>,
                 messages: &mut Vec<Value>|
     -> Result<(), PhysicalFailure> {
        if data_lines.is_empty() {
            return Ok(());
        }
        let payload = data_lines.join("\n");
        data_lines.clear();
        if payload.is_empty() {
            return Ok(());
        }
        let value: Value = serde_json::from_str(&payload).map_err(|error| {
            PhysicalFailure::Protocol(format!("JEB MCP SSE payload was not valid JSON: {error}"))
        })?;
        match value {
            Value::Array(items) => messages.extend(items),
            other => messages.push(other),
        }
        Ok(())
    };

    for raw_line in text.split('\n') {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            flush(&mut data_lines, &mut messages)?;
            continue;
        }
        if let Some(rest) = line.strip_prefix("data:") {
            data_lines.push(rest.strip_prefix(' ').unwrap_or(rest));
        }
        // Other SSE fields (event, id, retry, comments) are ignored.
    }
    flush(&mut data_lines, &mut messages)?;
    Ok(messages)
}

/// Decode a JEB MCP `tools/call` result without inventing an empty observation.
///
/// Compatibility owner: `decodeJebToolResult`.
pub fn decode_tool_result(result: Value) -> Result<ToolResult, PhysicalFailure> {
    let object = result.as_object().ok_or_else(|| {
        PhysicalFailure::Protocol("JEB MCP tool result was not an object".to_owned())
    })?;

    let is_error = object
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    // Collect `type == "text"` content blocks with a `text` field.
    let blocks: Vec<String> = object
        .get("content")
        .and_then(Value::as_array)
        .map(|content| {
            content
                .iter()
                .filter_map(|block| {
                    let is_text = block.get("type").and_then(Value::as_str) == Some("text");
                    let text = block.get("text").and_then(Value::as_str);
                    match (is_text, text) {
                        (true, Some(text)) => Some(text.to_owned()),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    let decoded: Value = if let Some(structured) = object.get("structuredContent") {
        structured.clone()
    } else {
        if blocks.len() != 1 {
            return Err(PhysicalFailure::Protocol(
                "JEB MCP omitted a single structured or text result; unsupported content cannot establish an empty observation."
                    .to_owned(),
            ));
        }
        let text = blocks.first().map(String::as_str).unwrap_or("null");
        match serde_json::from_str::<Value>(text) {
            Ok(value) => value,
            Err(_) => Value::String(text.to_owned()),
        }
    };

    if is_error && !is_jeb_failure_envelope(&decoded) {
        let detail = blocks
            .first()
            .cloned()
            .unwrap_or_else(|| "error-marked result without a JEB failure envelope".to_owned());
        return Err(PhysicalFailure::Protocol(format!(
            "JEB MCP tool failed: {detail}"
        )));
    }

    Ok(decoded)
}

/// A JEB failure envelope is an object with `success == false`.
fn is_jeb_failure_envelope(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|object| object.get("success"))
        .and_then(Value::as_bool)
        .map(|success| !success)
        .unwrap_or(false)
}
