//! Owned transport and instrumentation for one externally owned page.
//!
//! Compatibility owners: `src/browser/execution/CdpRuntimeSession.ts`,
//! `src/browser/CdpAuthorizedMainFrame.ts` and the runtime limits of
//! `src/domain/webRuntime.ts` (`WEB_RUNTIME_LIMITS`).
use super::protocol;
use crate::cdp::discovery::{self, Discovery, transport_error};
use crate::cdp::target_session::{self, Deadline, TargetSession};
use crate::cdp::{Endpoint, observation_error, urls};
use rea_core::analysis_error::AnalysisError;
use rea_core::analysis_error::cleanup::provider_cleanup_error;
use rea_core::cancellation::Cancellation;
use rea_host::cdp_transport::CdpTransportError;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::time::Duration;

/// `WEB_RUNTIME_LIMITS`.
pub(super) const PROTOCOL_BYTES: usize = 64 * 1024 * 1024;
pub(super) const RETAINED_EVENT_BYTES: usize = 8 * 1024 * 1024;
pub(super) const SOURCE_BYTES: usize = 32 * 1024 * 1024;
pub(super) const COMMAND_TIMEOUT_MS: u64 = 20_000;
const CLEANUP_TIMEOUT_MS: u64 = 5_000;
/// The transport's own response bound stays above the command deadline so
/// the runtime deadline owns timeout classification.
const TRANSPORT_TIMEOUT: Duration = Duration::from_millis(COMMAND_TIMEOUT_MS + 5_000);
pub(super) const PROVIDER_ID: &str = "rea-cdp-browser";

/// `webRuntimeTargetSchema`.
#[derive(Clone, Debug)]
pub(super) struct TargetFacts {
    pub target_id: String,
    pub initial_url: String,
    pub origin: String,
    pub frame_id: String,
    pub loader_id: Option<String>,
}

impl TargetFacts {
    pub(super) fn to_json(&self) -> Value {
        json!({
            "target_id": self.target_id,
            "origin": self.origin,
            "initial_url": self.initial_url,
            "frame_id": self.frame_id,
            "loader_id": self.loader_id,
        })
    }
}

/// Runtime scope (`webRuntimeScopeSchema`).
pub(super) struct Scope {
    pub endpoint: Endpoint,
    pub allowed_origins: Vec<String>,
    pub target_id: String,
}

pub(super) struct RuntimeSession<'a> {
    pub transport: TargetSession,
    pub discovery: Discovery,
    pub target: TargetFacts,
    pub allowed_origins: BTreeSet<String>,
    pub operation: &'static str,
    pub cancellation: &'a Cancellation,
    pub enabled_domains: Vec<String>,
    pub precise_coverage_may_be_active: bool,
    completion: Option<Deadline>,
    /// Target events received since the last pump, in arrival order.
    pending: Vec<Value>,
    /// The bounded event buffer dropped events.
    overflowed: bool,
}

fn timeout(operation: &str) -> AnalysisError {
    AnalysisError::timeout(operation, COMMAND_TIMEOUT_MS)
}

/// Classify a failure under a runtime deadline: caller cancellation stays
/// cancellation; reaching a deadline is `AnalysisTimeoutError`.
fn classify(
    error: CdpTransportError,
    operation: &str,
    method: &str,
    caller: &Cancellation,
) -> AnalysisError {
    match error {
        CdpTransportError::Cancelled(_) if caller.reason().is_some() => {
            AnalysisError::cancelled(operation)
        }
        CdpTransportError::Cancelled(_) | CdpTransportError::Timeout => timeout(operation),
        other => transport_error(other, operation, method),
    }
}

/// `runtimeDeadline` over setup work that already returns typed failures.
fn deadline_failure(
    error: AnalysisError,
    deadline: &Deadline,
    caller: &Cancellation,
    operation: &str,
) -> AnalysisError {
    if deadline.expired() && caller.reason().is_none() {
        timeout(operation)
    } else {
        error
    }
}

impl<'a> RuntimeSession<'a> {
    /// `CdpRuntimeSession.open`: discover, authorize, connect and wait for the
    /// main frame inside one setup deadline; failed setup releases the socket.
    pub(super) fn open(
        scope: &Scope,
        operation: &'static str,
        cancellation: &'a Cancellation,
    ) -> Result<Self, AnalysisError> {
        let deadline = Deadline::new(
            Some(cancellation),
            Duration::from_millis(COMMAND_TIMEOUT_MS),
        );
        let signal = deadline.cancellation().clone();
        let discovery = discovery::open(&scope.endpoint, operation, &signal)
            .map_err(|error| deadline_failure(error, &deadline, cancellation, operation))?;
        let (target, allowed_origins) = target_session::authorize_target(
            &discovery,
            &scope.target_id,
            &scope.allowed_origins,
            operation,
        )?;
        let target = target.clone();
        let mut transport = target_session::open(
            &discovery,
            &target,
            operation,
            &signal,
            TRANSPORT_TIMEOUT,
            PROTOCOL_BYTES,
        )
        .map_err(|error| deadline_failure(error, &deadline, cancellation, operation))?;
        let tree = authorized_main_frame(
            &mut transport,
            &allowed_origins,
            operation,
            &signal,
            cancellation,
        )
        .map_err(|error| deadline_failure(error, &deadline, cancellation, operation));
        // Setup events precede the collection's subscription.
        let _ = transport.drain();
        let tree = match tree {
            Ok(tree) => tree,
            Err(error) => {
                transport.close();
                return Err(error);
            }
        };
        let frame = match protocol::frame_tree(&tree) {
            Some(frame) => frame,
            None => {
                transport.close();
                return Err(AnalysisError::output(
                    operation,
                    protocol::FRAME_TREE_MESSAGE,
                ));
            }
        };
        let url = urls::sanitize_browser_url(&frame.url);
        let Some(origin) = url.origin else {
            transport.close();
            return Err(observation_error(operation, "target_not_allowed", None));
        };
        Ok(Self {
            transport,
            discovery,
            target: TargetFacts {
                target_id: target.id.clone(),
                initial_url: url.url,
                origin,
                frame_id: frame.id,
                loader_id: frame.loader_id,
            },
            allowed_origins,
            operation,
            cancellation,
            enabled_domains: Vec::new(),
            precise_coverage_may_be_active: false,
            completion: None,
            pending: Vec::new(),
            overflowed: false,
        })
    }

    fn collect_events(&mut self) {
        let batch = self.transport.drain();
        self.overflowed |= batch.overflowed || batch.dropped > 0;
        self.pending
            .extend(batch.items.into_iter().map(|event| event.value));
    }

    /// Target events delivered since the previous call, and whether the
    /// bounded buffer dropped any.
    pub(super) fn take_events(&mut self) -> (Vec<Value>, bool) {
        self.collect_events();
        (
            std::mem::take(&mut self.pending),
            std::mem::take(&mut self.overflowed),
        )
    }

    /// One command bounded separately from the observation window, returning
    /// the raw transport failure for callers that classify rejections.
    pub(super) fn command_raw(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Value, CdpTransportError> {
        let parent = self
            .completion
            .as_ref()
            .map_or(self.cancellation, Deadline::cancellation);
        let deadline = Deadline::new(Some(parent), Duration::from_millis(COMMAND_TIMEOUT_MS));
        let result = self.transport.send(method, params, deadline.cancellation());
        self.collect_events();
        result
    }

    /// `CdpRuntimeSession.command`.
    pub(super) fn command(&mut self, method: &str, params: Value) -> Result<Value, AnalysisError> {
        self.command_raw(method, params)
            .map_err(|error| self.classify(error, method))
    }

    pub(super) fn classify(&self, error: CdpTransportError, method: &str) -> AnalysisError {
        classify(error, self.operation, method, self.cancellation)
    }

    /// `beginCompletion`: bound the complete inspection/source-join phase.
    pub(super) fn begin_completion(&mut self) {
        if self.completion.is_none() {
            self.completion = Some(Deadline::new(
                Some(self.cancellation),
                Duration::from_millis(COMMAND_TIMEOUT_MS),
            ));
        }
    }

    /// `enable`: cleanup is registered before the command is sent.
    pub(super) fn enable(&mut self, domain: &str) -> Result<(), AnalysisError> {
        self.enabled_domains.push(domain.to_owned());
        self.command(&format!("{domain}.enable"), json!({}))
            .map(|_| ())
    }

    /// `assertDocument`.
    pub(super) fn assert_document(&mut self) -> Result<(), AnalysisError> {
        let tree = self.command("Page.getFrameTree", json!({}))?;
        let frame = protocol::frame_tree(&tree)
            .ok_or_else(|| AnalysisError::output(self.operation, protocol::FRAME_TREE_MESSAGE))?;
        let url = urls::sanitize_browser_url(&frame.url);
        if frame.id != self.target.frame_id
            || frame.loader_id != self.target.loader_id
            || (self.target.loader_id.is_none() && url.url != self.target.initial_url)
        {
            return Err(observation_error(
                self.operation,
                "target_changed",
                Some(format!(
                    "Selected target {} changed document during {}.",
                    self.target.target_id, self.operation
                )),
            ));
        }
        if !url
            .origin
            .is_some_and(|origin| self.allowed_origins.contains(&origin))
        {
            return Err(observation_error(
                self.operation,
                "target_not_allowed",
                Some(format!(
                    "Selected target {} moved to an unselected origin during {}.",
                    self.target.target_id, self.operation
                )),
            ));
        }
        Ok(())
    }

    /// `close`: cleanup uses its own deadline after caller cancellation, then
    /// closes REA's transport. Returns the cleanup failure, if any.
    pub(super) fn close(
        mut self,
        previous: Option<&AnalysisError>,
        object_group: Option<&str>,
    ) -> Option<AnalysisError> {
        self.completion = None;
        let cleanup = Deadline::new(None, Duration::from_millis(CLEANUP_TIMEOUT_MS));
        let signal = cleanup.cancellation().clone();
        let operation = self.operation;
        let mut failures: Vec<String> = Vec::new();
        let mut send = |session: &mut TargetSession, method: &str, params: Value, browser: bool| {
            let outcome = if browser {
                session.send_browser(method, params, &signal)
            } else {
                session.send(method, params, &signal)
            };
            if let Err(error) = outcome {
                let error = match error {
                    CdpTransportError::Cancelled(_) | CdpTransportError::Timeout => {
                        AnalysisError::cancelled(operation)
                    }
                    other => transport_error(other, operation, method),
                };
                failures.push(format!("{method}: {}", error.user_message()));
            }
        };
        if self.precise_coverage_may_be_active {
            send(
                &mut self.transport,
                "Profiler.stopPreciseCoverage",
                json!({}),
                false,
            );
        }
        if let Some(group) = object_group {
            send(
                &mut self.transport,
                "Runtime.releaseObjectGroup",
                json!({ "objectGroup": group }),
                false,
            );
        }
        for domain in self.enabled_domains.clone().iter().rev() {
            send(
                &mut self.transport,
                &format!("{domain}.disable"),
                json!({}),
                false,
            );
        }
        if let Some(session_id) = self.transport.session_id().map(str::to_owned) {
            send(
                &mut self.transport,
                "Target.detachFromTarget",
                json!({ "sessionId": session_id }),
                true,
            );
        }
        drop(cleanup);
        self.transport.close();
        if failures.is_empty() {
            return None;
        }
        let mut diagnostics = Map::new();
        diagnostics.insert(
            "target_id".into(),
            Value::String(self.target.target_id.clone()),
        );
        diagnostics.insert(
            "cleanup_failures".into(),
            Value::Array(failures.into_iter().map(Value::String).collect()),
        );
        diagnostics.insert(
            "previous_error".into(),
            previous.map_or(Value::Null, |error| Value::String(error.user_message())),
        );
        Some(provider_cleanup_error(
            PROVIDER_ID,
            vec![
                self.target.target_id.clone(),
                "runtime-instrumentation".to_owned(),
            ],
            diagnostics,
            Some(operation),
            None,
        ))
    }
}

/// `authorizedMainFrame`: wait for the attached main frame to enter its
/// approved origin.
fn authorized_main_frame(
    transport: &mut TargetSession,
    allowed_origins: &BTreeSet<String>,
    operation: &str,
    signal: &Cancellation,
    caller: &Cancellation,
) -> Result<Value, AnalysisError> {
    for _ in 0..80 {
        let result = transport
            .send("Page.getFrameTree", json!({}), signal)
            .map_err(|error| classify(error, operation, "Page.getFrameTree", caller))?;
        // `requiredRecord` reports its failure under `inspect_web_page`.
        let Some(record) = result.as_object() else {
            return Err(observation_error(
                "inspect_web_page",
                "protocol_error",
                None,
            ));
        };
        let url = record
            .get("frameTree")
            .and_then(Value::as_object)
            .and_then(|tree| tree.get("frame"))
            .and_then(Value::as_object)
            .and_then(|frame| frame.get("url"))
            .and_then(Value::as_str);
        if let Some(url) = url {
            let sanitized = urls::sanitize_browser_url(url);
            if sanitized
                .origin
                .is_some_and(|origin| allowed_origins.contains(&origin))
            {
                return Ok(result);
            }
            if urls::parse(url).is_some_and(|parsed| matches!(parsed.scheme(), "http" | "https")) {
                return Err(observation_error(operation, "target_not_allowed", None));
            }
        }
        for _ in 0..5 {
            if signal.reason().is_some() {
                return Err(if caller.reason().is_some() {
                    AnalysisError::cancelled(operation)
                } else {
                    timeout(operation)
                });
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    Err(observation_error(operation, "target_not_allowed", None))
}
