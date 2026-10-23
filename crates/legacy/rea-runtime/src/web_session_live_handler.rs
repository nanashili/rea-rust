//! Live adapter for caller-selected web session observations.
//!
//! The application owner performs the CDP observation. This adapter owns only
//! browser-page discovery: it verifies the selected page against the caller's
//! loopback endpoint, resolves its page WebSocket, and then delegates without
//! changing the requested target identity or observation options.

use rea_application::web;
use rea_core::cancellation::Cancellation;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable operation name shared with the application-owned observation contract.
pub const OPERATION: &str = web::session_observation::OPERATION;

/// Observe the caller-selected browser page through the live CDP adapter.
///
/// Page discovery is deliberately kept here rather than in the application
/// owner so the owner never acquires browser-level authority or silently picks
/// a different target. The selected page's advertised WebSocket is accepted
/// only after the shared discovery boundary verifies its scope.
#[cfg(unix)]
pub fn observe(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    web::session_observation::validate_input(input)?;

    if cancellation.reason().is_some() {
        return Err(cancelled_failure());
    }

    let endpoint = input
        .get("cdp_endpoint")
        .and_then(Value::as_str)
        .expect("validated cdp_endpoint");
    let target_id = input
        .get("target_id")
        .and_then(Value::as_str)
        .expect("validated target_id");
    let websocket = crate::mcp::resolve_page_websocket_endpoint(endpoint, target_id, cancellation)?;

    if cancellation.reason().is_some() {
        return Err(cancelled_failure());
    }

    crate::web_capture_offline_handlers::observe_live(input, &websocket, cancellation)
}

#[cfg(not(unix))]
pub fn observe(_input: &Value, _cancellation: &Cancellation) -> Result<Value, Failure> {
    Err(Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        "live web session observation is unavailable on this platform".into(),
        true,
        "Run the native adapter on a Unix host with a loopback CDP endpoint.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(web::session_observation::OPERATION.into()),
        )]),
    ))
}

#[cfg(unix)]
fn cancelled_failure() -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        "web session observation was cancelled before page capture completed".into(),
        true,
        "Retry the observation with the selected page target still available.".into(),
        BTreeMap::from([(
            "operation",
            Detail::Text(web::session_observation::OPERATION.into()),
        )]),
    )
}
