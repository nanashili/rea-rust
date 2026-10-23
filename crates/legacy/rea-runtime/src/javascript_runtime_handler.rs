//! Runtime adapter for passive Node and Electron V8 Inspector observation.
//!
//! The application layer owns event interpretation. This module owns bounded
//! loopback discovery, the selected WebSocket session, and its cleanup.

use rea_application::javascript::runtime::{self as javascript_runtime, InspectorTransport};
use rea_core::cancellation::Cancellation;
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::{
    CdpEventBatch, CdpWebSocketTransport, DEFAULT_TIMEOUT, MAX_MESSAGE_BYTES,
};
use serde_json::{Value, json};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

const DISCOVERY_LIMIT: usize = 8 * 1024 * 1024;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// Inspect one caller-selected Inspector target.
pub fn observe(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    javascript_runtime::validate_observe_input(input)?;
    ensure_active(cancellation)?;

    let endpoint = input["inspector_endpoint"]
        .as_str()
        .expect("validated inspector_endpoint");
    let target_id = input["target_id"].as_str().expect("validated target_id");
    let discovery = discover(endpoint, target_id, cancellation)?;
    ensure_active(cancellation)?;

    let transport = CdpWebSocketTransport::connect_with_limits(
        &discovery.websocket_endpoint,
        Some(target_id),
        DEFAULT_TIMEOUT,
        MAX_MESSAGE_BYTES,
    )
    .map_err(|error| provider_failure(format!("Inspector WebSocket connection failed: {error}")))?;
    let mut transport = ConnectedTransport { transport };

    let observation = javascript_runtime::observe_connected(
        input,
        &discovery.runtime,
        &discovery.target,
        &mut transport,
        cancellation,
    );
    let cleanup = transport.close();

    match observation {
        Ok(mut result) => {
            if let Err(error) = cleanup {
                append_limitation(
                    &mut result,
                    &format!("Inspector transport cleanup failed: {error}"),
                );
            }
            Ok(result)
        }
        Err(mut failure) => {
            if let Err(error) = cleanup {
                failure.detail("cleanup_failure", Detail::Text(error));
            }
            Err(failure)
        }
    }
}

/// List discovered Inspector targets without attaching to any target.
pub fn list(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    javascript_runtime::validate_list_input(input)?;
    let endpoint = input["inspector_endpoint"]
        .as_str()
        .expect("validated inspector_endpoint");
    ensure_active(cancellation)?;
    let runtime_document = read_document(endpoint, "/json/version", cancellation)?;
    let targets = read_document(endpoint, "/json/list", cancellation)?;
    let target_values = targets
        .as_array()
        .ok_or_else(|| provider_failure("Inspector /json/list response was not an array"))?
        .iter()
        .filter_map(|target| project_target(target, endpoint))
        .collect::<Vec<_>>();

    Ok(json!({
        "runtime": project_runtime(&runtime_document),
        "targets": target_values,
        "limitations": ["Listing does not attach to or instrument Inspector targets."]
    }))
}

struct Discovery {
    runtime: Value,
    target: Value,
    websocket_endpoint: String,
}

fn discover(
    endpoint: &str,
    target_id: &str,
    cancellation: &Cancellation,
) -> Result<Discovery, Failure> {
    let runtime_document = read_document(endpoint, "/json/version", cancellation)?;
    let targets = read_document(endpoint, "/json/list", cancellation)?;
    let target = targets
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry.get("id").and_then(Value::as_str) == Some(target_id))
        })
        .ok_or_else(|| provider_failure("selected Inspector target was not found"))?;
    let websocket_endpoint = target
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .filter(|value| valid_websocket(endpoint, value))
        .map(str::to_owned)
        .ok_or_else(|| {
            provider_failure("selected Inspector target has no validated WebSocket endpoint")
        })?;

    Ok(Discovery {
        runtime: project_runtime(&runtime_document),
        target: project_discovered_target(target, target_id),
        websocket_endpoint,
    })
}

fn read_document(
    endpoint: &str,
    path: &str,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    ensure_active(cancellation)?;
    let authority = endpoint
        .strip_prefix("http://")
        .and_then(|value| value.strip_suffix('/').or(Some(value)))
        .ok_or_else(|| provider_failure("Inspector endpoint must use HTTP loopback transport"))?;
    let mut addresses = authority.to_socket_addrs().map_err(|error| {
        provider_failure(format!("Inspector endpoint could not be resolved: {error}"))
    })?;
    let address = addresses
        .next()
        .ok_or_else(|| provider_failure("Inspector endpoint has no resolved address"))?;
    let mut stream = TcpStream::connect_timeout(&address, DISCOVERY_TIMEOUT).map_err(|error| {
        provider_failure(format!("Inspector discovery connection failed: {error}"))
    })?;
    stream
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|error| provider_failure(format!("Inspector discovery setup failed: {error}")))?;
    stream
        .set_write_timeout(Some(DISCOVERY_TIMEOUT))
        .map_err(|error| provider_failure(format!("Inspector discovery setup failed: {error}")))?;
    write!(stream, "GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\nAccept: application/json\r\n\r\n")
        .and_then(|_| stream.flush())
        .map_err(|error| provider_failure(format!("Inspector discovery request failed: {error}")))?;

    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 16 * 1024];
    let deadline = Instant::now() + DISCOVERY_TIMEOUT;
    loop {
        ensure_active(cancellation)?;
        if Instant::now() >= deadline {
            return Err(provider_failure("Inspector discovery response timed out"));
        }
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                if bytes.len().saturating_add(count) > DISCOVERY_LIMIT {
                    return Err(provider_failure(
                        "Inspector discovery response exceeded its byte limit",
                    ));
                }
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(error) => {
                return Err(provider_failure(format!(
                    "Inspector discovery response failed: {error}"
                )));
            }
        }
    }
    let body = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| &bytes[position + 4..])
        .ok_or_else(|| provider_failure("Inspector discovery response had no HTTP body"))?;
    serde_json::from_slice(body)
        .map_err(|error| provider_failure(format!("Inspector discovery JSON was invalid: {error}")))
}

fn project_runtime(document: &Value) -> Value {
    json!({
        "product": document.get("Browser").or_else(|| document.get("browser")).and_then(Value::as_str).unwrap_or("unknown"),
        "protocol_version": document.get("Protocol-Version").or_else(|| document.get("protocolVersion")).and_then(Value::as_str).unwrap_or("unknown"),
        "v8_version": document.get("V8-Version").or_else(|| document.get("v8Version")).cloned().unwrap_or(Value::Null),
    })
}

fn project_discovered_target(target: &Value, target_id: &str) -> Value {
    json!({
        "target_id": target_id,
        "protocol_type": target.get("type").and_then(Value::as_str).unwrap_or("unknown"),
        "attached": target.get("attached").cloned().unwrap_or(Value::Null),
        "location": {"kind":"url", "reported_url": target.get("url").and_then(Value::as_str).unwrap_or("")}
    })
}

fn project_target(target: &Value, endpoint: &str) -> Option<Value> {
    let id = target.get("id").and_then(Value::as_str)?;
    let websocket = target.get("webSocketDebuggerUrl").and_then(Value::as_str)?;
    if !valid_websocket(endpoint, websocket) {
        return None;
    }
    Some(project_discovered_target(target, id))
}

fn valid_websocket(endpoint: &str, websocket: &str) -> bool {
    let authority = endpoint.trim_start_matches("http://").trim_end_matches('/');
    websocket.starts_with("ws://")
        && websocket
            .strip_prefix("ws://")
            .is_some_and(|value| value.starts_with(&format!("{authority}/")))
        && !websocket.contains(['?', '#'])
}

fn append_limitation(result: &mut Value, limitation: &str) {
    if let Some(limitations) = result.get_mut("limitations").and_then(Value::as_array_mut) {
        limitations.push(Value::String(limitation.to_owned()));
    }
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    if let Some(reason) = cancellation.reason() {
        return Err(Failure::new(
            "cancelled",
            "cancelled",
            reason.to_owned(),
            false,
            "Retry the passive Inspector observation.".into(),
            Default::default(),
        ));
    }
    Ok(())
}

fn provider_failure(reason: impl Into<String>) -> Failure {
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        reason.into(),
        true,
        "Check the loopback Inspector endpoint and selected target, then retry.".into(),
        Default::default(),
    )
}

struct ConnectedTransport {
    transport: CdpWebSocketTransport,
}

impl ConnectedTransport {
    fn close(&mut self) -> Result<(), String> {
        self.transport
            .close_connection()
            .map_err(|error| error.to_string())
    }
}

impl InspectorTransport for ConnectedTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.transport
            .request(method, params)
            .map_err(|error| error.to_string())
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        self.transport.drain_events()
    }
}
