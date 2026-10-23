//! Shared owner of loopback CDP endpoint selection and discovery.
//!
//! Compatibility owners: `src/domain/browserObservation.ts`
//! (`browserObservationEndpointSchema`, `browserAllowedOriginsSchema`),
//! `src/browser/CdpEndpoint.ts` (HTTP `/json/version` + `/json/list`
//! discovery, browser-socket discovery, title redaction and WebSocket
//! validation), `src/browser/CdpTargetSession.ts` (`openCdpEndpoint`) and
//! `src/browser/CdpConnection.ts` (transport failure reasons). The socket is
//! `rea_host::cdp_transport::CdpWebSocketTransport`, which only connects to
//! literal loopback `ws://` endpoints.
pub(crate) mod discovery;
#[cfg(any(feature = "electron", feature = "javascript-runtime"))]
pub(crate) mod file_scope;
#[cfg(feature = "browser")]
pub(crate) mod json_text;
pub(crate) mod target_session;
pub(crate) mod urls;

use rea_core::analysis_error::{AnalysisError, ErrorKind, InputIssue};
use rea_mcp::ToolOutput;
use rea_mcp::schema::{Issue, validation_error_text};
use serde_json::{Value, json};

const HTTP_ENDPOINT_MESSAGE: &str =
    "CDP endpoint must be an explicit-port HTTP URL on 127.0.0.1 or ::1";
const BROWSER_SOCKET_PATH: &str = "/devtools/browser/";
const ORIGIN_MESSAGE: &str = "Expected one exact HTTP(S) origin without a path or wildcard";

/// Caller-selected passive endpoint (`BrowserObservationEndpoint`).
#[derive(Clone, Debug)]
pub(crate) struct Endpoint {
    pub transport: Transport,
    pub url: String,
    /// Evidence form; a browser socket identifier is redacted.
    pub recorded: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transport {
    HttpDiscovery,
    BrowserWebSocket,
}

/// One refinement issue in the SDK's rendering.
pub(crate) struct Refinement {
    pub path: Vec<Value>,
    pub message: String,
}

impl Refinement {
    pub(crate) fn new(path: Vec<Value>, message: impl Into<String>) -> Self {
        Self {
            path,
            message: message.into(),
        }
    }
}

/// The SDK's text-only input failure for Zod refinements, carrying the typed
/// input failure for in-process callers.
pub(crate) fn refinement_failure(tool: &str, refinements: Vec<Refinement>) -> ToolOutput {
    let segment = |part: &Value| match part {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let rendered: Vec<Issue> = refinements
        .iter()
        .map(|refinement| Issue {
            path: refinement.path.iter().map(segment).collect(),
            message: refinement.message.clone(),
        })
        .collect();
    let text = validation_error_text(tool, &rendered);
    let error = AnalysisError::input(
        tool,
        refinements
            .into_iter()
            .map(|refinement| InputIssue {
                path: refinement.path,
                reason: "invalid_value",
                message: Some(refinement.message),
                expected: None,
                minimum: None,
                maximum: None,
            })
            .collect(),
    );
    ToolOutput::Raw(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "error": error.project() },
        "isError": true,
    }))
}

/// `httpDiscoveryOrigin`.
fn http_discovery_origin(url: &url::Url) -> Option<String> {
    (url.scheme() == "http"
        && urls::is_literal_loopback_hostname(url.host_str().unwrap_or_default())
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/"
        && !urls::declares_query_or_fragment(url))
    .then(|| urls::origin(url))
}

/// `browserSocketAuthority`.
fn browser_socket_authority(url: &url::Url) -> Option<String> {
    let path = url.path();
    let identifier = path.strip_prefix(BROWSER_SOCKET_PATH)?;
    (url.scheme() == "ws"
        && urls::is_literal_loopback_hostname(url.host_str().unwrap_or_default())
        && url.port().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && !urls::declares_query_or_fragment(url)
        && !identifier.is_empty()
        && !identifier.contains('/'))
    .then(|| format!("ws://{}", urls::host(url)))
}

/// `browserObservationEndpointSchema` transform.
pub(crate) fn parse_endpoint(value: &str) -> Result<Endpoint, &'static str> {
    let Some(url) = urls::parse(value) else {
        return Err("Invalid CDP endpoint URL");
    };
    if let Some(origin) = http_discovery_origin(&url) {
        return Ok(Endpoint {
            transport: Transport::HttpDiscovery,
            url: origin.clone(),
            recorded: origin,
        });
    }
    if let Some(authority) = browser_socket_authority(&url) {
        return Ok(Endpoint {
            transport: Transport::BrowserWebSocket,
            url: url.as_str().to_owned(),
            recorded: format!("{authority}{BROWSER_SOCKET_PATH}[REDACTED]"),
        });
    }
    Err(if url.scheme() == "ws" {
        "CDP browser WebSocket must be ws://127.0.0.1:PORT/devtools/browser/ID or ws://[::1]:PORT/devtools/browser/ID"
    } else {
        HTTP_ENDPOINT_MESSAGE
    })
}

/// `browserEndpointSchema` transform: an HTTP discovery origin only.
pub(crate) fn parse_http_endpoint(value: &str) -> Result<Endpoint, &'static str> {
    let Some(url) = urls::parse(value) else {
        return Err("Invalid CDP endpoint URL");
    };
    let origin = http_discovery_origin(&url).ok_or(HTTP_ENDPOINT_MESSAGE)?;
    Ok(Endpoint {
        transport: Transport::HttpDiscovery,
        url: origin.clone(),
        recorded: origin,
    })
}
/// Parsed shared browser scope (`cdp_endpoint`, `allowed_origins`).
pub(crate) struct BrowserScope {
    pub endpoint: Endpoint,
    /// Deduplicated, sorted exact origins.
    pub allowed_origins: Vec<String>,
}

/// Parse the shared browser scope, appending refinement issues in schema order.
pub(crate) fn parse_scope(input: &Value, issues: &mut Vec<Refinement>) -> Option<BrowserScope> {
    parse_scope_with(input, issues, parse_endpoint)
}
/// Parse the shared browser scope with the caller's endpoint schema.
pub(crate) fn parse_scope_with(
    input: &Value,
    issues: &mut Vec<Refinement>,
    parse_endpoint: fn(&str) -> Result<Endpoint, &'static str>,
) -> Option<BrowserScope> {
    let endpoint = match parse_endpoint(
        input
            .get("cdp_endpoint")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        Ok(endpoint) => Some(endpoint),
        Err(message) => {
            issues.push(Refinement::new(vec![json!("cdp_endpoint")], message));
            None
        }
    };
    let mut origins = Vec::new();
    let mut valid = true;
    for (index, value) in input
        .get("allowed_origins")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        match value.as_str().and_then(urls::exact_origin) {
            Some(origin) => origins.push(origin),
            None => {
                valid = false;
                issues.push(Refinement::new(
                    vec![json!("allowed_origins"), json!(index)],
                    ORIGIN_MESSAGE,
                ));
            }
        }
    }
    origins.sort();
    origins.dedup();
    let endpoint = endpoint?;
    valid.then_some(BrowserScope {
        endpoint,
        allowed_origins: origins,
    })
}

/// A typed `BrowserObservationError`.
pub(crate) fn observation_error(
    operation: &str,
    reason: &str,
    detail: Option<String>,
) -> AnalysisError {
    AnalysisError::from(ErrorKind::BrowserObservation {
        operation: operation.to_owned(),
        reason: reason.to_owned(),
        detail,
        cause_cancelled: false,
        primary_reason: None,
    })
}
