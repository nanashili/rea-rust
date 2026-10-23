//! Bounded loopback CDP discovery (`src/browser/CdpEndpoint.ts`,
//! `openCdpEndpoint` in `src/browser/CdpTargetSession.ts`).
use super::urls;
use super::{Endpoint, Transport, observation_error};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_host::cdp_transport::{CdpTransportError, CdpWebSocketTransport};
use regex::Regex;
use serde_json::{Map, Value};
use std::io::{ErrorKind as IoKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

/// `CDP_DISCOVERY_RESPONSE_LIMITS`.
const RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const RESPONSE_TIMEOUT_MS: u64 = 10_000;
/// `WEB_RUNTIME_LIMITS.protocolBytes`.
pub(crate) const PROTOCOL_BYTES: usize = 64 * 1024 * 1024;
const POLL: Duration = Duration::from_millis(100);

/// Command-routing scope of the validated discovery socket. The socket URL
/// itself is not retained: target listing opens no target session.
#[derive(Clone, Debug)]
pub(crate) enum WebSocketEndpoint {
    Browser,
    Page { target_id: String },
}

#[derive(Clone, Debug)]
pub(crate) struct Target {
    pub id: String,
    pub kind: String,
    pub title: String,
    pub url: String,
    pub attached: Option<bool>,
    /// Validated direct page socket (`webSocket`).
    pub has_web_socket: bool,
    /// The validated direct page socket URL, host rewritten to the
    /// caller-selected loopback host.
    pub web_socket_url: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct Discovery {
    pub web_socket: WebSocketEndpoint,
    /// `{product, protocol_version, revision, user_agent, js_version}`.
    pub version: Value,
    pub targets: Vec<Target>,
    /// The validated discovery socket URL (`webSocket.url`).
    pub web_socket_url: String,
}

impl Discovery {
    /// `cdpTargetWebSocket`: the validated transport for one target and
    /// whether it is browser-scoped (requires `Target.attachToTarget`).
    pub(crate) fn target_web_socket(&self, target: &Target) -> Option<(String, bool)> {
        match &self.web_socket {
            WebSocketEndpoint::Browser => Some((self.web_socket_url.clone(), true)),
            WebSocketEndpoint::Page { target_id } => match &target.web_socket_url {
                Some(url) => Some((url.clone(), false)),
                None => (target_id == &target.id).then(|| (self.web_socket_url.clone(), false)),
            },
        }
    }

    /// `hasCdpTargetWebSocket`.
    pub(crate) fn has_target_web_socket(&self, target: &Target) -> bool {
        match &self.web_socket {
            WebSocketEndpoint::Browser => true,
            WebSocketEndpoint::Page { target_id, .. } => {
                target.has_web_socket || target_id == &target.id
            }
        }
    }
}

/// `openCdpEndpoint`: discovery through the caller-selected transport. The
/// browser socket opened for socket discovery is closed afterwards, as
/// `listTargets` finishes it immediately.
pub(crate) fn open(
    endpoint: &Endpoint,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Discovery, AnalysisError> {
    match endpoint.transport {
        Transport::HttpDiscovery => discover_http(&endpoint.url, operation, cancellation),
        Transport::BrowserWebSocket => {
            discover_browser_socket(&endpoint.url, operation, cancellation)
        }
    }
}

fn cancelled(operation: &str) -> AnalysisError {
    AnalysisError::cancelled(operation)
}

fn invalid_response(operation: &str) -> AnalysisError {
    observation_error(operation, "invalid_endpoint_response", None)
}

fn discover_http(
    endpoint: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Discovery, AnalysisError> {
    let version = read_json(endpoint, "/json/version", operation, cancellation)?;
    let targets = read_json(endpoint, "/json/list", operation, cancellation)?;
    let version = parse_http_version(&version).ok_or_else(|| invalid_response(operation))?;
    let targets = parse_http_targets(&targets).ok_or_else(|| invalid_response(operation))?;
    let web_socket =
        safe_web_socket(endpoint, &version.1).ok_or_else(|| invalid_response(operation))?;
    let web_socket_url =
        safe_web_socket_url(endpoint, &version.1).ok_or_else(|| invalid_response(operation))?;
    let targets = targets
        .into_iter()
        .map(|raw| {
            let has_web_socket = raw.web_socket_url.as_deref().is_some_and(|reported| {
                matches!(safe_web_socket(endpoint, reported),
                    Some(WebSocketEndpoint::Page { target_id }) if target_id == raw.id)
            });
            let web_socket_url = if has_web_socket {
                raw.web_socket_url
                    .as_deref()
                    .and_then(|reported| safe_web_socket_url(endpoint, reported))
            } else {
                None
            };
            Target {
                title: sanitize_target_title(&raw.title, &raw.url),
                web_socket_url,
                id: raw.id,
                kind: raw.kind,
                url: raw.url,
                attached: raw.attached,
                has_web_socket,
            }
        })
        .collect();
    Ok(Discovery {
        web_socket,
        version: version.0,
        targets,
        web_socket_url,
    })
}

fn required_string(object: &Map<String, Value>, key: &str, non_empty: bool) -> Option<String> {
    let value = object.get(key)?.as_str()?;
    (!non_empty || !value.is_empty()).then(|| value.to_owned())
}

/// `endpointVersionSchema`, projected to the shared version facts plus the
/// reported browser socket.
fn parse_http_version(value: &Value) -> Option<(Value, String)> {
    let object = value.as_object()?;
    let product = required_string(object, "Browser", true)?;
    let protocol = required_string(object, "Protocol-Version", true)?;
    let user_agent = required_string(object, "User-Agent", false)?;
    let js_version = required_string(object, "V8-Version", false)?;
    let revision = required_string(object, "WebKit-Version", false)?;
    let socket = required_string(object, "webSocketDebuggerUrl", true)?;
    Some((
        version_value(product, protocol, revision, user_agent, js_version),
        socket,
    ))
}

fn version_value(
    product: String,
    protocol: String,
    revision: String,
    user_agent: String,
    js_version: String,
) -> Value {
    let mut version = Map::new();
    version.insert("product".into(), Value::String(product));
    version.insert("protocol_version".into(), Value::String(protocol));
    version.insert("revision".into(), Value::String(revision));
    version.insert("user_agent".into(), Value::String(user_agent));
    version.insert("js_version".into(), Value::String(js_version));
    Value::Object(version)
}

struct RawTarget {
    id: String,
    kind: String,
    title: String,
    url: String,
    attached: Option<bool>,
    web_socket_url: Option<String>,
}

/// Optional zod field: absent or `undefined`-equivalent only when missing.
fn optional<'a>(object: &'a Map<String, Value>, key: &str) -> Result<Option<&'a Value>, ()> {
    Ok(object.get(key))
}

fn parse_target_common(
    object: &Map<String, Value>,
    id_key: &str,
    nullable_attached: bool,
) -> Option<(String, String, String, String, Option<bool>)> {
    let id = required_string(object, id_key, true)?;
    let kind = required_string(object, "type", true)?;
    let title = match object.get("title") {
        None => String::new(),
        Some(value) => value.as_str()?.to_owned(),
    };
    let url = required_string(object, "url", false)?;
    let attached = match object.get("attached") {
        None => None,
        Some(Value::Null) if nullable_attached => None,
        Some(Value::Bool(value)) => Some(*value),
        Some(_) => return None,
    };
    Some((id, kind, title, url, attached))
}

/// `endpointTargetsSchema`.
fn parse_http_targets(value: &Value) -> Option<Vec<RawTarget>> {
    value
        .as_array()?
        .iter()
        .map(|item| {
            let object = item.as_object()?;
            let (id, kind, title, url, attached) = parse_target_common(object, "id", true)?;
            let web_socket_url = match optional(object, "webSocketDebuggerUrl").ok()? {
                None => None,
                Some(value) => Some(value.as_str().filter(|text| !text.is_empty())?.to_owned()),
            };
            Some(RawTarget {
                id,
                kind,
                title,
                url,
                attached,
                web_socket_url,
            })
        })
        .collect()
}

/// The URL `safeCdpWebSocketEndpoint` validates, with the trusted host.
fn safe_web_socket_url(endpoint: &str, reported: &str) -> Option<String> {
    safe_web_socket(endpoint, reported)?;
    let mut parsed = urls::parse(reported)?;
    let trusted = urls::parse(endpoint)?;
    parsed.set_host(trusted.host_str()).ok()?;
    Some(parsed.as_str().to_owned())
}

/// `safeCdpWebSocketEndpoint`: the reported socket must stay on the trusted
/// endpoint's port; its host is replaced by the caller-selected loopback host.
fn safe_web_socket(endpoint: &str, reported: &str) -> Option<WebSocketEndpoint> {
    let mut parsed = urls::parse(reported)?;
    let trusted = urls::parse(endpoint)?;
    if parsed.scheme() != "ws"
        || urls::port(&parsed) != urls::port(&trusted)
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || urls::declares_query_or_fragment(&parsed)
    {
        return None;
    }
    let path = parsed.path().to_owned();
    let browser = path_identifier(&path, "/devtools/browser/").is_some();
    let page = path_identifier(&path, "/devtools/page/");
    if !browser && page.is_none() {
        return None;
    }
    parsed.set_host(trusted.host_str()).ok()?;
    Some(if browser {
        WebSocketEndpoint::Browser
    } else {
        WebSocketEndpoint::Page {
            target_id: page.unwrap_or_default().to_owned(),
        }
    })
}

fn path_identifier<'a>(path: &'a str, prefix: &str) -> Option<&'a str> {
    let identifier = path.strip_prefix(prefix)?;
    (!identifier.is_empty() && !identifier.contains('/')).then_some(identifier)
}

/// `sanitizeTargetTitle`.
fn sanitize_target_title(value: &str, target_url: &str) -> String {
    match urls::parse(value) {
        Some(url) if matches!(url.scheme(), "http" | "https") => {
            urls::sanitize_browser_url(value).url
        }
        _ => sanitize_target_url_alias(value, target_url),
    }
}

/// JavaScript `\s` under the `u` flag.
const JS_WHITESPACE: &str = r"\t\n\x0B\x0C\r \x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}";

fn sanitize_target_url_alias(value: &str, target_url: &str) -> String {
    let Some(parsed) = urls::parse(target_url) else {
        return value.to_owned();
    };
    let host = urls::host(&parsed);
    let mut markers = vec![urls::origin(&parsed), format!("//{host}"), host.clone()];
    if parsed.path() != "/" {
        markers.push(parsed.path().to_owned());
    }
    let alternatives = markers
        .iter()
        .map(|marker| regex::escape(marker))
        .collect::<Vec<_>>()
        .join("|");
    let Ok(pattern) = Regex::new(&format!("(?:{alternatives})[^{JS_WHITESPACE}<>\"']*")) else {
        return value.to_owned();
    };
    pattern
        .replace_all(value, |captures: &regex::Captures<'_>| {
            sanitize_same_origin_title_url(&captures[0], &parsed, &host)
        })
        .into_owned()
}

fn sanitize_same_origin_title_url(candidate: &str, target: &url::Url, host: &str) -> String {
    let protocol = format!("{}:", target.scheme());
    let target_origin = urls::origin(target);
    let parsed = if candidate.starts_with("//") {
        urls::parse(&format!("{protocol}{candidate}"))
    } else if candidate.starts_with(host) {
        urls::parse(&format!("{protocol}//{candidate}"))
    } else {
        url::Url::parse(&target_origin)
            .ok()
            .and_then(|base| base.join(candidate).ok())
    };
    let Some(parsed) = parsed else {
        return candidate.to_owned();
    };
    let credentials = !parsed.username().is_empty() || parsed.password().is_some();
    if urls::origin(&parsed) == target_origin && credentials {
        urls::sanitize_browser_url(candidate).url
    } else {
        candidate.to_owned()
    }
}

/// `readCdpJson`: one bounded GET without redirects.
fn read_json(
    endpoint: &str,
    path: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(cancelled(operation));
    }
    let url = urls::parse(endpoint).ok_or_else(|| invalid_response(operation))?;
    let host = urls::host(&url);
    let hostname = url.host_str().unwrap_or_default();
    let ip = hostname.trim_start_matches('[').trim_end_matches(']');
    let address: SocketAddr = SocketAddr::new(
        ip.parse()
            .map_err(|_| observation_error(operation, "endpoint_unreachable", None))?,
        url.port().unwrap_or(80),
    );
    let deadline = Instant::now() + Duration::from_millis(RESPONSE_TIMEOUT_MS);
    let timeout = || {
        observation_error(
            operation,
            "timeout",
            Some(format!(
                "CDP discovery response exceeded its {RESPONSE_TIMEOUT_MS} ms deadline."
            )),
        )
    };
    let unreachable = || observation_error(operation, "endpoint_unreachable", None);
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_millis(RESPONSE_TIMEOUT_MS)).map_err(
            |error| {
                if error.kind() == IoKind::TimedOut {
                    timeout()
                } else {
                    unreachable()
                }
            },
        )?;
    stream
        .set_read_timeout(Some(POLL))
        .map_err(|_| unreachable())?;
    stream
        .set_write_timeout(Some(Duration::from_millis(RESPONSE_TIMEOUT_MS)))
        .map_err(|_| unreachable())?;
    let request = format!(
        "GET {path} HTTP/1.1\r\nAccept: application/json\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|_| unreachable())?;
    let mut received = Vec::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut head: Option<Head> = None;
    loop {
        if cancellation.reason().is_some() {
            return Err(cancelled(operation));
        }
        if Instant::now() >= deadline {
            return Err(timeout());
        }
        let read = match stream.read(&mut buffer) {
            Ok(read) => read,
            Err(error)
                if matches!(
                    error.kind(),
                    IoKind::WouldBlock | IoKind::TimedOut | IoKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return Err(unreachable()),
        };
        if read > 0 {
            received.extend_from_slice(&buffer[..read]);
        }
        if head.is_none() {
            if let Some(parsed) = parse_head(&received) {
                let parsed = parsed.map_err(|()| invalid_response(operation))?;
                if parsed.status != 200 {
                    return Err(invalid_response(operation));
                }
                head = Some(parsed);
            } else if read == 0 {
                return Err(invalid_response(operation));
            } else {
                continue;
            }
        }
        let current = head
            .as_ref()
            .map(|head| head.body_start)
            .unwrap_or_default();
        let framing = head
            .as_ref()
            .map(|head| head.framing)
            .unwrap_or(Framing::Close);
        match body_state(&received[current..], framing) {
            BodyState::Complete(body) => {
                if body.len() > RESPONSE_BYTES {
                    return Err(payload_limit(operation));
                }
                return serde_json::from_slice(&body).map_err(|_| invalid_response(operation));
            }
            BodyState::Partial(decoded) => {
                if decoded > RESPONSE_BYTES {
                    return Err(payload_limit(operation));
                }
            }
            BodyState::Invalid => return Err(invalid_response(operation)),
        }
        if read == 0 {
            if framing == Framing::Close {
                let body = received[current..].to_vec();
                return serde_json::from_slice(&body).map_err(|_| invalid_response(operation));
            }
            return Err(invalid_response(operation));
        }
    }
}

fn payload_limit(operation: &str) -> AnalysisError {
    observation_error(
        operation,
        "payload_limit",
        Some(format!(
            "CDP discovery response exceeds its {RESPONSE_BYTES} byte limit."
        )),
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Framing {
    Length(usize),
    Chunked,
    Close,
}

struct Head {
    status: u16,
    body_start: usize,
    framing: Framing,
}

fn parse_head(received: &[u8]) -> Option<Result<Head, ()>> {
    let end = received
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?;
    let Ok(text) = std::str::from_utf8(&received[..end]) else {
        return Some(Err(()));
    };
    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next().unwrap_or_default();
    let Some(status) = parts.next().and_then(|code| code.parse::<u16>().ok()) else {
        return Some(Err(()));
    };
    if !version.starts_with("HTTP/1.") {
        return Some(Err(()));
    }
    let mut framing = Framing::Close;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
        {
            framing = Framing::Chunked;
        } else if name.eq_ignore_ascii_case("content-length") && framing != Framing::Chunked {
            match value.parse::<usize>() {
                Ok(length) => framing = Framing::Length(length),
                Err(_) => return Some(Err(())),
            }
        }
    }
    Some(Ok(Head {
        status,
        body_start: end + 4,
        framing,
    }))
}

enum BodyState {
    Complete(Vec<u8>),
    /// Decoded bytes so far.
    Partial(usize),
    Invalid,
}

fn body_state(body: &[u8], framing: Framing) -> BodyState {
    match framing {
        Framing::Length(length) => {
            if length > RESPONSE_BYTES {
                return BodyState::Partial(length);
            }
            if body.len() >= length {
                BodyState::Complete(body[..length].to_vec())
            } else {
                BodyState::Partial(body.len())
            }
        }
        Framing::Close => BodyState::Partial(body.len()),
        Framing::Chunked => {
            let mut decoded = Vec::new();
            let mut offset = 0;
            loop {
                let Some(line_end) = body[offset..]
                    .windows(2)
                    .position(|window| window == b"\r\n")
                else {
                    return BodyState::Partial(decoded.len());
                };
                let Ok(size_text) = std::str::from_utf8(&body[offset..offset + line_end]) else {
                    return BodyState::Invalid;
                };
                let size_text = size_text.split(';').next().unwrap_or_default().trim();
                let Ok(size) = usize::from_str_radix(size_text, 16) else {
                    return BodyState::Invalid;
                };
                let data_start = offset + line_end + 2;
                if size == 0 {
                    return BodyState::Complete(decoded);
                }
                if decoded.len().saturating_add(size) > RESPONSE_BYTES {
                    return BodyState::Partial(decoded.len().saturating_add(size));
                }
                if body.len() < data_start + size + 2 {
                    return BodyState::Partial(
                        decoded.len() + body.len().saturating_sub(data_start),
                    );
                }
                decoded.extend_from_slice(&body[data_start..data_start + size]);
                offset = data_start + size + 2;
            }
        }
    }
}

/// Map one transport failure to the `CdpConnection` reason.
pub(crate) fn transport_error(
    error: CdpTransportError,
    operation: &str,
    method: &str,
) -> AnalysisError {
    match error {
        CdpTransportError::Cancelled(_) => cancelled(operation),
        CdpTransportError::Timeout => observation_error(
            operation,
            "timeout",
            Some(format!(
                "CDP command {method} exceeded its 20000 ms response deadline."
            )),
        ),
        CdpTransportError::Protocol { code, message } => observation_error(
            operation,
            "protocol_error",
            Some(format!(
                "CDP {method} failed ({}): {message}",
                code.map_or_else(|| "unknown code".to_owned(), |code| code.to_string())
            )),
        ),
        CdpTransportError::InvalidMessage(message)
            if message.contains("exceeds the protocol message limit") =>
        {
            observation_error(
                operation,
                "payload_limit",
                Some(format!(
                    "CDP message exceeded the selected {PROTOCOL_BYTES} byte protocol budget."
                )),
            )
        }
        CdpTransportError::WebSocket(tungstenite_error) if is_capacity(&tungstenite_error) => {
            observation_error(
                operation,
                "payload_limit",
                Some(format!(
                    "CDP message exceeded the selected {PROTOCOL_BYTES} byte protocol budget."
                )),
            )
        }
        CdpTransportError::InvalidMessage(message) if message.contains("closed the connection") => {
            observation_error(operation, "disconnected", None)
        }
        CdpTransportError::Io(_) | CdpTransportError::WebSocket(_) => {
            observation_error(operation, "disconnected", None)
        }
        CdpTransportError::InvalidMessage(_)
        | CdpTransportError::RequestIdExhausted
        | CdpTransportError::InvalidEndpoint(_) => {
            observation_error(operation, "protocol_error", None)
        }
    }
}

fn is_capacity(error: &tungstenite::Error) -> bool {
    matches!(error, tungstenite::Error::Capacity(_))
}

/// Remaining time under one deadline, or `None` once it has passed.
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

/// `withCdpDiscoveryDeadline` + `discoverCdpBrowserSocket`.
fn discover_browser_socket(
    url: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Discovery, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(cancelled(operation));
    }
    let deadline = Instant::now() + Duration::from_millis(RESPONSE_TIMEOUT_MS);
    let deadline_error = || {
        observation_error(
            operation,
            "timeout",
            Some(format!(
                "CDP browser-socket discovery exceeded its {RESPONSE_TIMEOUT_MS} ms deadline."
            )),
        )
    };
    let budget = remaining(deadline).ok_or_else(deadline_error)?;
    let mut transport =
        CdpWebSocketTransport::connect_with_limits(url, None, budget, PROTOCOL_BYTES).map_err(
            |error| match error {
                CdpTransportError::Io(io)
                    if io.kind() == IoKind::TimedOut || io.kind() == IoKind::WouldBlock =>
                {
                    deadline_error()
                }
                CdpTransportError::Timeout => deadline_error(),
                _ => observation_error(operation, "endpoint_unreachable", None),
            },
        )?;
    let result = (|| {
        let mut send = |method: &str| {
            if remaining(deadline).is_none() {
                return Err(deadline_error());
            }
            transport
                .request_with_cancellation(method, Value::Object(Map::new()), cancellation)
                .map_err(|error| match error {
                    CdpTransportError::Timeout => deadline_error(),
                    other => transport_error(other, operation, method),
                })
        };
        let version = send("Browser.getVersion")?;
        let targets = send("Target.getTargets")?;
        Ok::<_, AnalysisError>((version, targets))
    })();
    let _ = transport.close();
    let (version, targets) = result?;
    let version = parse_socket_version(&version).ok_or_else(|| invalid_response(operation))?;
    let targets = targets
        .as_object()
        .and_then(|object| object.get("targetInfos"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_response(operation))?
        .iter()
        .map(|item| {
            let (id, kind, title, target_url, attached) =
                parse_target_common(item.as_object()?, "targetId", false)?;
            Some(Target {
                title: sanitize_target_title(&title, &target_url),
                id,
                kind,
                url: target_url,
                attached,
                has_web_socket: false,
                web_socket_url: None,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| invalid_response(operation))?;
    Ok(Discovery {
        web_socket: WebSocketEndpoint::Browser,
        version,
        targets,
        web_socket_url: url.to_owned(),
    })
}

/// `browserSocketVersionSchema`.
fn parse_socket_version(value: &Value) -> Option<Value> {
    let object = value.as_object()?;
    Some(version_value(
        required_string(object, "product", true)?,
        required_string(object, "protocolVersion", true)?,
        required_string(object, "revision", false)?,
        required_string(object, "userAgent", false)?,
        required_string(object, "jsVersion", false)?,
    ))
}

/// `readCdpJson` for discovery owners with their own document schemas
/// (V8 Inspector discovery).
#[cfg(feature = "javascript-runtime")]
pub(crate) fn read_cdp_json(
    endpoint: &str,
    path: &str,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    read_json(endpoint, path, operation, cancellation)
}
