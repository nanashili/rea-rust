//! Read-only CDP adapter for the web-page inspection application contract.
//!
//! Target discovery chooses the page and returns its WebSocket debugger URL.
//! This adapter binds that selection to one bounded transport, then delegates
//! page projection to [`crate::web::page_inspection`].

use crate::web::page_inspection::{self, CdpTransport};
use rea_core::failure::{Detail, Failure};
use rea_host::cdp_transport::{CdpTransportError, CdpWebSocketTransport};
use serde_json::Value;
use std::collections::BTreeMap;

/// A connected, caller-selected page target for passive inspection.
pub struct ConnectedCdpWebPagePort<T> {
    transport: T,
    target_id: String,
}

impl ConnectedCdpWebPagePort<CdpWebSocketTransport> {
    /// Connect to the WebSocket URL returned by target discovery.
    ///
    /// The transport validates that the URL is loopback and that its path
    /// names `target_id`; no browser-level endpoint can silently select a
    /// different page.
    pub fn connect(websocket_endpoint: &str, target_id: &str) -> Result<Self, CdpTransportError> {
        let transport = CdpWebSocketTransport::connect_for_target(websocket_endpoint, target_id)?;
        Ok(Self::from_transport(transport, target_id))
    }
}

impl<T> ConnectedCdpWebPagePort<T> {
    /// Bind an existing transport to the exact target selected by discovery.
    pub fn from_transport(transport: T, target_id: &str) -> Self {
        Self {
            transport,
            target_id: target_id.to_owned(),
        }
    }

    pub fn target_id(&self) -> &str {
        &self.target_id
    }

    /// Inspect the selected page through the shared application contract.
    pub fn inspect(
        &mut self,
        input: &Value,
        started_at: &str,
        ended_at: &str,
    ) -> Result<Value, Failure>
    where
        T: CdpTransport,
    {
        page_inspection::validate_input(input)?;

        let requested_target = input
            .get("target_id")
            .and_then(Value::as_str)
            .ok_or_else(|| target_mismatch("input does not contain the selected target_id"))?;
        if requested_target != self.target_id {
            return Err(target_mismatch(
                "the inspection target differs from the connected target",
            ));
        }

        page_inspection::inspect(input, &mut self.transport, started_at, ended_at)
    }
}

impl CdpTransport for CdpWebSocketTransport {
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        CdpWebSocketTransport::request(self, method, params).map_err(|error| error.to_string())
    }
}

fn target_mismatch(reason: &str) -> Failure {
    Failure::new(
        "target_changed",
        "target_changed",
        reason.into(),
        false,
        "Retry after reconnecting to the caller-selected page target.".into(),
        BTreeMap::from([("operation", Detail::Text(page_inspection::OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    struct MockTransport;

    impl CdpTransport for MockTransport {
        fn request(&mut self, method: &str, _params: Value) -> Result<Value, String> {
            if method == "Page.getFrameTree" {
                return Ok(json!({
                    "frameTree": {"frame": {
                        "url": "https://app.example.test/",
                        "name": "Example",
                    }}
                }));
            }

            Ok(match method {
                "DOM.getDocument" => json!({
                    "root": {"nodeId": 1, "nodeType": 9, "nodeName": "#document"}
                }),
                "DOM.resolveNode" => json!({"object": {"objectId": "root-object"}}),
                "DOMDebugger.getEventListeners" => json!({"listeners": []}),
                "Page.getResourceTree" => json!({"frameTree": {"frame": {}, "resources": []}}),
                "Browser.getVersion" => json!({"product": "Mock/1"}),
                _ => json!({}),
            })
        }
    }

    fn input(target_id: &str) -> Value {
        json!({
            "cdp_endpoint": "http://127.0.0.1:9222",
            "target_id": target_id,
        })
    }

    #[test]
    fn mock_inspection_preserves_selected_target_identity() {
        let transport = MockTransport;
        let mut port = ConnectedCdpWebPagePort::from_transport(transport, "page-1");

        let result = port
            .inspect(
                &input("page-1"),
                "2026-10-20T00:00:00Z",
                "2026-10-20T00:00:01Z",
            )
            .expect("selected page should be inspected");

        assert_eq!(result["target"]["target_id"], "page-1");
    }

    #[test]
    fn rejects_input_for_a_different_target_before_transport_use() {
        let transport = MockTransport;
        let mut port = ConnectedCdpWebPagePort::from_transport(transport, "page-1");

        let error = port
            .inspect(
                &input("page-2"),
                "2026-10-20T00:00:00Z",
                "2026-10-20T00:00:01Z",
            )
            .expect_err("target mismatch must fail closed");

        assert_eq!(error.code(), "target_changed");
    }
}
