//! `CdpConnection` semantics over the shared target session, and the
//! provider's `withTargetSession` lifecycle (`src/browser/CdpBrowserProvider.ts`,
//! `src/browser/CdpTargetSession.ts` `closeCdpTargetSession`).
//!
//! The synchronous transport buffers events until they are drained, so a
//! drain after each command observes exactly the events the TS listener saw
//! before that command's reply resolved, in arrival order.
use super::values::Event;
use crate::cdp::discovery::{self, Discovery, PROTOCOL_BYTES, Target};
use crate::cdp::target_session::{self, Deadline, TargetSession};
use crate::cdp::{BrowserScope, observation_error};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use rea_host::cdp_transport::CdpTransportError;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

/// `WEB_RUNTIME_LIMITS.commandTimeoutMs`.
const COMMAND_TIMEOUT: Duration = Duration::from_millis(20_000);
/// `closeCdpTargetSession` cleanup bound.
const CLEANUP_TIMEOUT: Duration = Duration::from_millis(1_000);
const CLEANUP_DOMAINS: [&str; 5] = ["Network", "Debugger", "Runtime", "Page", "WebMCP"];
const POLL_SLICE: Duration = Duration::from_millis(25);

/// One operation's view of the target connection.
pub(crate) struct Connection<'a> {
    session: TargetSession,
    operation: &'a str,
    pub cancellation: Cancellation,
    protocol_failed: bool,
    /// `disconnected` or `payload_limit` once the transport is lost.
    closed: Option<&'static str>,
}

impl<'a> Connection<'a> {
    pub(crate) fn session_id(&self) -> Option<&str> {
        self.session.session_id()
    }

    fn transport_failure(&self, reason: &'static str) -> AnalysisError {
        observation_error(
            self.operation,
            reason,
            (reason == "payload_limit").then(|| {
                format!("CDP message exceeded the selected {PROTOCOL_BYTES} byte protocol budget.")
            }),
        )
    }

    fn record_failure(&mut self, error: &AnalysisError) {
        if let ErrorKind::BrowserObservation { reason, .. } = &error.kind {
            match reason.as_str() {
                "disconnected" => self.closed = Some("disconnected"),
                "payload_limit" => self.closed = Some("payload_limit"),
                _ => {}
            }
        }
    }

    fn send_raw(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, Result<CdpTransportError, AnalysisError>> {
        if self.protocol_failed {
            return Err(Err(observation_error(
                self.operation,
                "protocol_error",
                None,
            )));
        }
        if let Some(reason) = self.closed {
            return Err(Err(self.transport_failure(reason)));
        }
        if self.cancellation.reason().is_some() {
            return Err(Err(AnalysisError::cancelled(self.operation)));
        }
        let cancellation = self.cancellation.clone();
        match self.session.send(method, params, &cancellation) {
            Ok(value) if value.is_object() => Ok(value),
            Ok(_) => {
                self.protocol_failed = true;
                Err(Err(observation_error(
                    self.operation,
                    "protocol_error",
                    None,
                )))
            }
            Err(error) => Err(Ok(error)),
        }
    }

    fn map_error(&mut self, error: CdpTransportError, method: &str) -> AnalysisError {
        if matches!(&error, CdpTransportError::InvalidMessage(message)
            if !message.contains("exceeds the protocol message limit") && !message.contains("closed the connection"))
        {
            self.protocol_failed = true;
        }
        let mapped = discovery::transport_error(error, self.operation, method);
        self.record_failure(&mapped);
        mapped
    }

    /// `connection.send(method, params, sessionId, signal)`.
    pub(crate) fn send(&mut self, method: &str, params: Value) -> Result<Value, AnalysisError> {
        match self.send_raw(method, params) {
            Ok(value) => Ok(value),
            Err(Err(error)) => Err(error),
            Err(Ok(error)) => Err(self.map_error(error, method)),
        }
    }

    /// `optionalCdpCommand`: a `-32601` rejection is reported as a limitation.
    pub(crate) fn send_optional(
        &mut self,
        method: &str,
        params: Value,
        limitations: &mut Vec<String>,
    ) -> Result<Option<Value>, AnalysisError> {
        match self.send_raw(method, params) {
            Ok(value) => Ok(Some(value)),
            Err(Err(error)) => Err(error),
            Err(Ok(CdpTransportError::Protocol {
                code: Some(-32_601),
                ..
            })) => {
                limitations.push(format!(
                    "{method} was unavailable from this browser target."
                ));
                Ok(None)
            }
            Err(Ok(error)) => Err(self.map_error(error, method)),
        }
    }

    /// `connection.send` that keeps a producer's command rejection
    /// (`CdpCommandRejection`: code and reported message) distinct from
    /// transport and cancellation failures. `cancellation` replaces the
    /// operation signal for this one command (a joined deadline signal).
    pub(crate) fn send_rejectable(
        &mut self,
        method: &str,
        params: Value,
        cancellation: Option<&Cancellation>,
    ) -> Result<Value, Rejection> {
        let joined = match cancellation {
            Some(signal) => {
                if self.protocol_failed {
                    return Err(Rejection::Failed(observation_error(
                        self.operation,
                        "protocol_error",
                        None,
                    )));
                }
                if let Some(reason) = self.closed {
                    return Err(Rejection::Failed(self.transport_failure(reason)));
                }
                if signal.reason().is_some() {
                    return Err(Rejection::Failed(AnalysisError::cancelled(self.operation)));
                }
                match self.session.send(method, params, signal) {
                    Ok(value) if value.is_object() => Ok(value),
                    Ok(_) => {
                        self.protocol_failed = true;
                        Err(Err(observation_error(
                            self.operation,
                            "protocol_error",
                            None,
                        )))
                    }
                    Err(error) => Err(Ok(error)),
                }
            }
            None => self.send_raw(method, params),
        };
        match joined {
            Ok(value) => Ok(value),
            Err(Err(error)) => Err(Rejection::Failed(error)),
            Err(Ok(CdpTransportError::Protocol { code, message })) => {
                let error = self.map_error(
                    CdpTransportError::Protocol {
                        code,
                        message: message.clone(),
                    },
                    method,
                );
                Err(Rejection::Rejected {
                    code,
                    message,
                    error,
                })
            }
            Err(Ok(error)) => Err(Rejection::Failed(self.map_error(error, method))),
        }
    }
    /// `optionalCdpCommand` with `sessionId: undefined` (browser level).
    pub(crate) fn send_browser_optional(
        &mut self,
        method: &str,
        params: Value,
        limitations: &mut Vec<String>,
    ) -> Result<Option<Value>, AnalysisError> {
        if self.protocol_failed {
            return Err(observation_error(self.operation, "protocol_error", None));
        }
        if let Some(reason) = self.closed {
            return Err(self.transport_failure(reason));
        }
        if self.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(self.operation));
        }
        let cancellation = self.cancellation.clone();
        match self.session.send_browser(method, params, &cancellation) {
            Ok(value) if value.is_object() => Ok(Some(value)),
            Ok(_) => {
                self.protocol_failed = true;
                Err(observation_error(self.operation, "protocol_error", None))
            }
            Err(CdpTransportError::Protocol {
                code: Some(-32_601),
                ..
            }) => {
                limitations.push(format!(
                    "{method} was unavailable from this browser target."
                ));
                Ok(None)
            }
            Err(error) => Err(self.map_error(error, method)),
        }
    }
    /// Validated events delivered since the previous drain. A malformed
    /// envelope is a fatal protocol failure: it and every later message are
    /// not delivered, and the next command fails.
    pub(crate) fn drain(&mut self) -> Result<Vec<Event>, AnalysisError> {
        let batch = self.session.drain();
        if batch.overflowed || batch.dropped > 0 {
            self.closed = Some("payload_limit");
            return Err(self.transport_failure("payload_limit"));
        }
        let mut events = Vec::new();
        for item in batch.items {
            if self.protocol_failed || self.closed.is_some() {
                break;
            }
            match parse_event(item.value) {
                Some(event) => events.push(event),
                None => self.protocol_failed = true,
            }
        }
        Ok(events)
    }

    /// Read events for at most `duration`. Returns `true` when the transport
    /// was lost (the `onDisconnect` notification).
    pub(crate) fn poll(&mut self, duration: Duration) -> Result<bool, AnalysisError> {
        if self.closed.is_some() || self.protocol_failed {
            std::thread::sleep(duration);
            return Ok(false);
        }
        let cancellation = self.cancellation.clone();
        match self.session.poll(duration, &cancellation) {
            Ok(()) => Ok(false),
            Err(CdpTransportError::Cancelled(_)) => Err(AnalysisError::cancelled(self.operation)),
            Err(error) => {
                let mapped = self.map_error(error, "event");
                Ok(self.closed.is_some()
                    && !matches!(&mapped.kind, ErrorKind::BrowserObservation { reason, .. } if reason == "protocol_error"))
            }
        }
    }

    /// `delayWithCancellation`, delivering events to `ingest` as they arrive.
    /// Returns `true` once `ingest` asks to stop early.
    pub(crate) fn wait(
        &mut self,
        duration: Duration,
        mut ingest: impl FnMut(&mut Self, Vec<Event>, bool) -> bool,
    ) -> Result<bool, AnalysisError> {
        let until = Instant::now() + duration;
        loop {
            if self.cancellation.reason().is_some() {
                return Err(AnalysisError::cancelled(self.operation));
            }
            let Some(remaining) = until
                .checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
            else {
                return Ok(false);
            };
            let disconnected = self.poll(remaining.min(POLL_SLICE))?;
            let events = self.drain()?;
            if ingest(self, events, disconnected) {
                return Ok(true);
            }
        }
    }

    /// Validate and discard events nobody was listening for.
    pub(crate) fn discard(&mut self) -> Result<(), AnalysisError> {
        self.drain().map(|_| ())
    }

    /// `cleanupCdpTargetCommands`: best-effort domain shutdown (skipped on
    /// cancellation), then a bounded detach, then REA's socket close.
    fn cleanup(self) {
        self.cleanup_domains(&CLEANUP_DOMAINS);
    }

    /// `closeCdpTargetSession(session, enabledDomains)`.
    fn cleanup_domains(mut self, domains: &[&str]) {
        let deadline = Deadline::new(None, CLEANUP_TIMEOUT);
        if self.cancellation.reason().is_none() && self.closed.is_none() && !self.protocol_failed {
            for domain in domains {
                if deadline.expired() || self.cancellation.reason().is_some() {
                    break;
                }
                let _ = self.session.send(
                    &format!("{domain}.disable"),
                    json!({}),
                    deadline.cancellation(),
                );
            }
        }
        if !deadline.expired() && self.closed.is_none() {
            if let Some(session_id) = self.session.session_id().map(str::to_owned) {
                let _ = self.session.send_browser(
                    "Target.detachFromTarget",
                    json!({ "sessionId": session_id }),
                    deadline.cancellation(),
                );
            }
        }
        self.session.close();
    }
}

/// A failed `send_rejectable` command.
pub(crate) enum Rejection {
    /// The producer answered with a command error.
    Rejected {
        code: Option<i64>,
        message: String,
        error: AnalysisError,
    },
    /// Transport, protocol, or cancellation failure.
    Failed(AnalysisError),
}
impl Rejection {
    pub(crate) fn into_error(self) -> AnalysisError {
        match self {
            Rejection::Rejected { error, .. } | Rejection::Failed(error) => error,
        }
    }
}
/// `CdpConnection#receive` event-envelope validation.
fn parse_event(value: Value) -> Option<Event> {
    let Value::Object(mut message) = value else {
        return None;
    };
    let method = message
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty())?
        .to_owned();
    let params = match message.remove("params") {
        None => Value::Object(Map::new()),
        Some(params @ Value::Object(_)) => params,
        Some(_) => return None,
    };
    let session_id = match message.get("sessionId") {
        None => None,
        Some(Value::String(id)) => Some(id.clone()),
        Some(_) => return None,
    };
    Some(Event {
        method,
        params,
        session_id,
    })
}

/// Facts handed to one target operation.
pub(crate) struct TargetFacts<'a> {
    pub discovery: &'a Discovery,
    pub target: &'a Target,
    /// The scoped origins (`scopeToTargetOrigin`).
    pub origins: BTreeSet<String>,
}

/// `withTargetSession` + `providerError`: discover, authorize, open the
/// session, run `work`, then clean up. Errors raised under another
/// operation name are re-tagged without their detail.
pub(crate) fn with_target_session<T>(
    operation: &str,
    scope: &BrowserScope,
    target_id: &str,
    cancellation: &Cancellation,
    work: impl FnOnce(&mut Connection<'_>, &TargetFacts<'_>) -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    let discovery = discovery::open(&scope.endpoint, operation, cancellation)?;
    // `authorizeTarget` reports under `inspect_web_page`; `providerError`
    // re-tags it under the requested operation without its detail.
    let (target, origins) =
        target_session::authorize_target(&discovery, target_id, &scope.allowed_origins, operation)
            .map_err(|error| without_detail(error, operation))?;
    let session = target_session::open(
        &discovery,
        target,
        operation,
        cancellation,
        COMMAND_TIMEOUT,
        PROTOCOL_BYTES,
    )?;
    let mut connection = Connection {
        session,
        operation,
        cancellation: cancellation.clone(),
        protocol_failed: false,
        closed: None,
    };
    let facts = TargetFacts {
        discovery: &discovery,
        target,
        origins,
    };
    let outcome = work(&mut connection, &facts);
    connection.cleanup();
    let value = outcome?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    Ok(value)
}

/// `openCdpTargetSession` + `closeCdpTargetSession` for a target the caller
/// already discovered and authorized: open the session, run `work`, then
/// disable `cleanup_domains` and release REA's socket. Final cancellation is
/// left to the caller, which may retain completed facts.
pub(crate) fn with_authorized_session<T>(
    operation: &str,
    discovery: &Discovery,
    target: &Target,
    cleanup_domains: &[&str],
    cancellation: &Cancellation,
    work: impl FnOnce(&mut Connection<'_>) -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    let session = target_session::open(
        discovery,
        target,
        operation,
        cancellation,
        COMMAND_TIMEOUT,
        PROTOCOL_BYTES,
    )?;
    let mut connection = Connection {
        session,
        operation,
        cancellation: cancellation.clone(),
        protocol_failed: false,
        closed: None,
    };
    let outcome = work(&mut connection);
    connection.cleanup_domains(cleanup_domains);
    outcome
}

/// A `BrowserObservationError` the producer raised as `inspect_web_page`
/// and `providerError` re-created under `operation` (no detail).
pub(crate) fn foreign(operation: &str, reason: &str) -> AnalysisError {
    observation_error(operation, reason, None)
}

fn without_detail(error: AnalysisError, operation: &str) -> AnalysisError {
    match &error.kind {
        ErrorKind::BrowserObservation { reason, .. } if operation != "inspect_web_page" => {
            observation_error(operation, reason, None)
        }
        _ => error,
    }
}
