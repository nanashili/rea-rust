//! One REA-owned CDP target session over a validated loopback socket.
//!
//! Compatibility owners: `src/browser/CdpAuthorizedTarget.ts`
//! (`authorizeCdpTarget`), `src/browser/CdpTargetSession.ts`
//! (`openCdpTargetSession`, `attachCdpTargetSession`),
//! `src/browser/CdpTargetEvents.ts` (`cdpTargetEventMatches`) and the
//! transport close of `src/browser/CdpConnection.ts`. The selected browser
//! and page stay externally owned; only REA's socket and attached session
//! are released here.
use super::discovery::{Discovery, Target, transport_error};
use super::{observation_error, urls};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_host::cdp_transport::{CdpEventBatch, CdpTransportError, CdpWebSocketTransport};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const DEADLINE_REASON: &str = "rea-cdp-deadline";
const DEADLINE_POLL: Duration = Duration::from_millis(10);

/// A disposable deadline joined with an optional caller cancellation, the
/// synchronous form of `AbortSignal.any([signal, timeout])`. Reaching the
/// deadline is distinguishable from caller cancellation.
pub(crate) struct Deadline {
    cancellation: Cancellation,
    done: Arc<AtomicBool>,
}

impl Deadline {
    pub(crate) fn new(parent: Option<&Cancellation>, timeout: Duration) -> Self {
        let cancellation = Cancellation::default();
        let done = Arc::new(AtomicBool::new(false));
        let (child, finished, parent) = (cancellation.clone(), done.clone(), parent.cloned());
        let until = Instant::now() + timeout;
        std::thread::spawn(move || {
            loop {
                if finished.load(Ordering::Acquire) {
                    return;
                }
                if let Some(reason) = parent.as_ref().and_then(Cancellation::reason) {
                    child.cancel(reason.to_owned());
                    return;
                }
                if Instant::now() >= until {
                    child.cancel(DEADLINE_REASON);
                    return;
                }
                std::thread::sleep(DEADLINE_POLL);
            }
        });
        Self { cancellation, done }
    }

    pub(crate) fn cancellation(&self) -> &Cancellation {
        &self.cancellation
    }

    /// The deadline, not the caller, ended the work.
    pub(crate) fn expired(&self) -> bool {
        self.cancellation.reason() == Some(DEADLINE_REASON)
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Release);
    }
}

/// `authorizeCdpTarget`: one page target and its origin scope.
pub(crate) fn authorize_target<'a>(
    discovery: &'a Discovery,
    target_id: &str,
    allowed_origins: &[String],
    operation: &str,
) -> Result<(&'a Target, BTreeSet<String>), AnalysisError> {
    let Some(target) = discovery
        .targets
        .iter()
        .find(|candidate| candidate.id == target_id)
    else {
        return Err(observation_error(
            operation,
            "target_not_found",
            Some(format!(
                "Target {target_id} was not found at the selected endpoint."
            )),
        ));
    };
    let origin = urls::sanitize_browser_url(&target.url).origin;
    match origin {
        Some(origin)
            if target.kind == "page"
                && (allowed_origins.is_empty() || allowed_origins.contains(&origin)) =>
        {
            let allowed = if allowed_origins.is_empty() {
                BTreeSet::from([origin])
            } else {
                allowed_origins.iter().cloned().collect()
            };
            Ok((target, allowed))
        }
        _ => Err(observation_error(
            operation,
            "target_not_allowed",
            Some(format!(
                "Target {target_id} must be an HTTP(S) page in the selected origin scope."
            )),
        )),
    }
}

/// One owned CDP connection scoped by a flat browser session or page socket.
pub(crate) struct TargetSession {
    transport: Option<CdpWebSocketTransport>,
    session_id: Option<String>,
}

/// `openCdpTargetSession`: connect the target's validated socket and, for a
/// browser socket, attach one flat session. A failed attach closes the socket.
pub(crate) fn open(
    discovery: &Discovery,
    target: &Target,
    operation: &str,
    cancellation: &Cancellation,
    request_timeout: Duration,
    max_message_bytes: usize,
) -> Result<TargetSession, AnalysisError> {
    let Some((url, browser_scope)) = discovery.target_web_socket(target) else {
        return Err(observation_error(
            operation,
            "invalid_endpoint_response",
            None,
        ));
    };
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let page_target = (!browser_scope).then_some(target.id.as_str());
    let mut transport = CdpWebSocketTransport::connect_with_limits(
        &url,
        page_target,
        request_timeout,
        max_message_bytes,
    )
    .map_err(|_| observation_error(operation, "endpoint_unreachable", None))?;
    // Runtime metadata replays can exceed the default buffer between drains;
    // the protocol budget bounds the retained bytes instead.
    transport.set_event_buffer_limits(usize::MAX, max_message_bytes);
    let mut session = TargetSession {
        transport: Some(transport),
        session_id: None,
    };
    if !browser_scope {
        return Ok(session);
    }
    let attached = session.send_browser(
        "Target.attachToTarget",
        json!({ "targetId": target.id, "flatten": true }),
        cancellation,
    );
    let attached = match attached {
        Ok(value) => value,
        Err(error) => {
            let error = transport_error(error, operation, "Target.attachToTarget");
            let _ = session.close();
            return Err(error);
        }
    };
    match attached
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    {
        Some(id) => {
            session.session_id = Some(id.to_owned());
            Ok(session)
        }
        None => {
            let _ = session.close();
            Err(observation_error(operation, "protocol_error", None))
        }
    }
}

impl TargetSession {
    fn transport(&mut self) -> Result<&mut CdpWebSocketTransport, CdpTransportError> {
        self.transport.as_mut().ok_or_else(|| {
            CdpTransportError::InvalidMessage("CDP peer closed the connection".into())
        })
    }

    pub(crate) fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Send one command to the selected target.
    pub(crate) fn send(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, CdpTransportError> {
        let session_id = self.session_id.clone();
        let transport = self.transport()?;
        match session_id {
            Some(id) => {
                transport.request_in_session_with_cancellation(method, params, &id, cancellation)
            }
            None => transport.request_with_cancellation(method, params, cancellation),
        }
    }

    /// Send one browser-level command (no target session envelope).
    pub(crate) fn send_browser(
        &mut self,
        method: &str,
        params: Value,
        cancellation: &Cancellation,
    ) -> Result<Value, CdpTransportError> {
        self.transport()?
            .request_with_cancellation(method, params, cancellation)
    }

    /// Read unsolicited events for at most `timeout`.
    pub(crate) fn poll(
        &mut self,
        timeout: Duration,
        cancellation: &Cancellation,
    ) -> Result<(), CdpTransportError> {
        self.transport()?.poll_events(timeout, cancellation)
    }

    /// Events received since the previous drain, in arrival order.
    pub(crate) fn drain(&mut self) -> CdpEventBatch {
        self.transport
            .as_mut()
            .map(CdpWebSocketTransport::drain_events)
            .unwrap_or_default()
    }

    /// `cdpTargetEventMatches`: ordinary envelopes carry the session ID; root
    /// detachment names it in its parameters.
    pub(crate) fn event_matches(&self, event: &Value) -> bool {
        let envelope = event.get("sessionId").and_then(Value::as_str);
        if event.get("method").and_then(Value::as_str) != Some("Target.detachedFromTarget") {
            return envelope == self.session_id.as_deref();
        }
        self.session_id.is_some()
            && event
                .get("params")
                .and_then(|params| params.get("sessionId"))
                .and_then(Value::as_str)
                == self.session_id.as_deref()
    }

    /// Close only REA's socket. Dropping the transport releases the OS socket
    /// even when the close handshake cannot be sent.
    /// A failed close handshake (peer already gone) still releases the
    /// socket, so the transport's release is always confirmed here.
    pub(crate) fn close(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            let _ = transport.close_connection();
        }
    }
}

impl Drop for TargetSession {
    fn drop(&mut self) {
        self.close();
    }
}
