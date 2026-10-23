//! Connected CDP adapter for passive WebMCP discovery.

use crate::web::webmcp_discovery::{self, CdpWebMcpTransport};
use rea_core::cancellation::Cancellation;
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::{CdpEvent, CdpEventBatch, CdpTransportError, CdpWebSocketTransport};
use serde_json::Value;
use std::collections::BTreeMap;

/// A caller-selected page connection with no target discovery or mutation authority.
pub struct ConnectedCdpWebMcpPort<T> {
    transport: T,
    target_id: String,
}

impl ConnectedCdpWebMcpPort<WebMcpTransport> {
    pub fn connect(endpoint: &str, target_id: &str) -> Result<Self, CdpTransportError> {
        let transport = if endpoint.contains("/devtools/browser/") {
            WebMcpTransport::Browser(BrowserScopedTransport::connect(endpoint, target_id)?)
        } else {
            WebMcpTransport::Direct(CdpWebSocketTransport::connect_for_target(
                endpoint, target_id,
            )?)
        };
        Ok(Self::from_transport(transport, target_id))
    }
}

/// Project a failed connection as a provider availability failure while
/// preserving the operation and transport reason for both adapters.
pub fn connection_failure(reason: String) -> Failure {
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        "The selected browser target could not be connected for WebMCP discovery.".into(),
        true,
        "Check the caller-selected browser endpoint and target, then retry.".into(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text(webmcp_discovery::OPERATION.into()),
            ),
            ("reason", Detail::Text(reason)),
        ]),
    )
}

impl<T> ConnectedCdpWebMcpPort<T> {
    pub fn from_transport(transport: T, target_id: &str) -> Self {
        Self {
            transport,
            target_id: target_id.to_owned(),
        }
    }

    pub fn discover(
        &mut self,
        input: &Value,
        started_at: &str,
        ended_at: &str,
    ) -> Result<Value, Failure>
    where
        T: CdpWebMcpTransport,
    {
        self.discover_with_cancellation(input, started_at, ended_at, &Cancellation::default())
    }

    pub fn discover_with_cancellation(
        &mut self,
        input: &Value,
        started_at: &str,
        ended_at: &str,
        cancellation: &Cancellation,
    ) -> Result<Value, Failure>
    where
        T: CdpWebMcpTransport,
    {
        webmcp_discovery::validate_input(input)?;
        if input.get("target_id").and_then(Value::as_str) != Some(self.target_id.as_str()) {
            return Err(Failure::new(
                "target_changed",
                "target_changed",
                "The discovery target differs from the connected target.".into(),
                false,
                "Retry after reconnecting to the caller-selected page target.".into(),
                std::collections::BTreeMap::new(),
            ));
        }
        webmcp_discovery::discover_with_cancellation(
            input,
            &mut self.transport,
            started_at,
            ended_at,
            cancellation,
        )
    }
}

impl CdpWebMcpTransport for CdpWebSocketTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        CdpWebSocketTransport::request(self, method, params).map_err(|error| error.to_string())
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        CdpWebSocketTransport::drain_events(self)
    }
}

/// Browser-level CDP sockets require an explicit target session for page
/// commands. This adapter keeps that routing inside the WebMCP provider.
pub struct BrowserScopedTransport {
    transport: CdpWebSocketTransport,
    session_id: String,
    next_message_id: i64,
    pending: Vec<CdpEvent>,
    next_sequence: u64,
}

impl BrowserScopedTransport {
    fn connect(endpoint: &str, target_id: &str) -> Result<Self, CdpTransportError> {
        let mut transport = CdpWebSocketTransport::connect(endpoint)?;
        let attached = transport.request(
            "Target.attachToTarget",
            serde_json::json!({"targetId": target_id, "flatten": false}),
        )?;
        let session_id = attached
            .get("sessionId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                CdpTransportError::InvalidMessage("Target.attachToTarget omitted sessionId".into())
            })?
            .to_owned();
        Ok(Self {
            transport,
            session_id,
            next_message_id: 1,
            pending: Vec::new(),
            next_sequence: 1,
        })
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let message_id = self.next_message_id;
        self.next_message_id = self
            .next_message_id
            .checked_add(1)
            .ok_or_else(|| "WebMCP CDP message identifier exhausted".to_owned())?;
        let message = serde_json::json!({"id": message_id, "method": method, "params": params});
        self.transport
            .request(
                "Target.sendMessageToTarget",
                serde_json::json!({
                    "sessionId": self.session_id,
                    "message": serde_json::to_string(&message).map_err(|error| error.to_string())?
                }),
            )
            .map_err(|error| error.to_string())?;
        let events = self.transport.drain_events();
        let mut response = None;
        for event in events.items {
            if event.value.get("method").and_then(Value::as_str)
                == Some("Target.receivedMessageFromTarget")
            {
                let event_session = event
                    .value
                    .pointer("/params/sessionId")
                    .and_then(Value::as_str);
                let message_value = event
                    .value
                    .pointer("/params/message")
                    .and_then(Value::as_str)
                    .and_then(|value| serde_json::from_str::<Value>(value).ok());
                if event_session == Some(self.session_id.as_str())
                    && message_value
                        .as_ref()
                        .and_then(|value| value.get("id"))
                        .and_then(Value::as_i64)
                        == Some(message_id)
                {
                    response = message_value;
                    continue;
                }
            }
            if let Some(message) = event
                .value
                .pointer("/params/message")
                .and_then(Value::as_str)
                .and_then(|value| serde_json::from_str::<Value>(value).ok())
            {
                self.pending.push(CdpEvent {
                    sequence: self.next_sequence,
                    value: message,
                });
                self.next_sequence = self.next_sequence.saturating_add(1);
            }
        }
        let response =
            response.ok_or_else(|| "browser CDP session omitted command response".to_owned())?;
        if let Some(error) = response.get("error") {
            return Err(format!("browser CDP session command failed: {error}"));
        }
        Ok(response
            .get("result")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})))
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        let mut items = std::mem::take(&mut self.pending);
        for event in self.transport.drain_events().items {
            if event.value.get("method").and_then(Value::as_str)
                == Some("Target.receivedMessageFromTarget")
            {
                if let Some(message) = event
                    .value
                    .pointer("/params/message")
                    .and_then(Value::as_str)
                    .and_then(|value| serde_json::from_str::<Value>(value).ok())
                {
                    items.push(CdpEvent {
                        sequence: self.next_sequence,
                        value: message,
                    });
                    self.next_sequence = self.next_sequence.saturating_add(1);
                }
            }
        }
        CdpEventBatch {
            items,
            dropped: 0,
            overflowed: false,
        }
    }
}

pub enum WebMcpTransport {
    Direct(CdpWebSocketTransport),
    Browser(BrowserScopedTransport),
}

impl CdpWebMcpTransport for WebMcpTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        match self {
            Self::Direct(transport) => transport
                .request(method, params)
                .map_err(|error| error.to_string()),
            Self::Browser(transport) => transport.request(method, params),
        }
    }

    fn drain_events(&mut self) -> CdpEventBatch {
        match self {
            Self::Direct(transport) => transport.drain_events(),
            Self::Browser(transport) => transport.drain_events(),
        }
    }
}
