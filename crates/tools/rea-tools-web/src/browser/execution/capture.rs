//! One resetting precise-coverage sample and its request-source relationships.
//!
//! Compatibility owners: `src/browser/execution/CdpExecutionCapture.ts`,
//! `CdpExecutionCollection.ts` and `CdpPreciseCoverage.ts`.
use super::iso_now;
use super::protocol::{self, Coverage};
use super::requests::Requests;
use super::session::RuntimeSession;
use super::sources::{ReadEvents, SourceState, Sources};
use super::window::{EndReason, Window};
use crate::cdp::discovery::transport_error;
use crate::cdp::observation_error;
use rea_core::analysis_error::AnalysisError;
use rea_host::cdp_transport::CdpTransportError;
use rea_mcp::Progress;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(50);

const LIMITATIONS: [&str; 11] = [
    "Website source ownership requires the selected main frame and a proven default execution world. Isolated, worker and unknown worlds are excluded from coverage/source joins; referenced producer context metadata is retained.",
    "Precise coverage resets counters, retains execution records and prevents optimized execution until stopped. Timing and JIT behavior are affected.",
    "Only the selected main document's proven frame/context scripts are attributed. Child frames, workers, service workers, WebAssembly and scripts without ownership metadata remain outside this operation.",
    "V8 reports nested function/block ranges and counts, not a chronological trace. Counts must not be summed across overlapping ranges; zero counts concern this instrumented window only.",
    "Previously parsed scripts may be absent from a precise sample. Their source inventory is retained, but missing coverage never means zero execution or an unexecuted function.",
    "A detailed-coverage request does not guarantee block granularity for already compiled functions. When is_block_coverage is false, branch execution is unknown; REA preserves the function-only producer ranges.",
    "The local armed/end clock and backend coverage timestamps are distinct clocks. Counters start when the backend accepts instrumentation, before the armed receipt, and end at the resetting sample after the requested window. Counts may include execution during those command intervals; requests are restricted to the locally armed window.",
    "Source metadata is collected through the final resetting sample, then frozen for source joins. Known identities remain checked during asynchronous source completion; newly parsed scripts after that cutoff are outside this evidence.",
    "Request callsites are producer-reported initiators associated by session script ID; they do not establish UI causality. Unresolved asynchronous parent IDs are retained without fetching their stacks.",
    "Producer hashes and UTF-8 digests of retained text are distinct identities. Inline script locations use reported resource offsets; anonymous/eval/sourceURL names are declarations.",
    "Metadata has an 8 MiB script budget and 8 MiB request budget; complete retained sources have a 32 MiB budget. Resource failures return no partial success. The externally owned browser's CPU and memory are not controlled by REA.",
];

/// `CdpExecutionCollection`: source/request collection and failure
/// subscriptions through a precise-sample cutoff.
struct Collection {
    sources: Sources,
    requests: Requests,
    window: Window,
    metadata_open: bool,
}

impl Collection {
    /// Deliver every event received since the last delivery, in order.
    fn pump(&mut self, session: &mut RuntimeSession<'_>) {
        let (events, overflowed) = session.take_events();
        if overflowed {
            let error = AnalysisError::output(
                session.operation,
                "Context/script metadata exceeds the complete 8 MiB event budget.",
            );
            self.sources.fail(error.clone());
            self.window.fail(error);
        }
        for event in &events {
            self.deliver(session, event);
        }
    }

    fn deliver(&mut self, session: &RuntimeSession<'_>, event: &Value) {
        if !session.transport.event_matches(event) {
            return;
        }
        let reason = self.window.reason;
        if self.metadata_open && matches!(reason, None | Some(EndReason::WindowElapsed)) {
            self.sources.ingest(event, true);
        } else if reason == Some(EndReason::WindowElapsed) {
            self.sources.verify_known_identity(event);
        }
        if self.window.active() {
            self.requests.ingest(event, &self.sources);
        }
        if let Err(error) = self.sources.check().and_then(|()| self.requests.check()) {
            self.window.fail(error);
        }
        self.window.ingest(event);
    }

    /// `freezeMetadata`.
    fn freeze_metadata(&mut self) -> Result<(), AnalysisError> {
        self.metadata_open = false;
        self.sources.check()
    }

    fn command(
        &mut self,
        session: &mut RuntimeSession<'_>,
        method: &str,
        params: Value,
    ) -> Result<Value, AnalysisError> {
        let result = session.command(method, params);
        self.pump(session);
        result
    }

    fn enable(
        &mut self,
        session: &mut RuntimeSession<'_>,
        domain: &str,
    ) -> Result<(), AnalysisError> {
        let result = session.enable(domain);
        self.pump(session);
        result
    }

    fn assert_document(&mut self, session: &mut RuntimeSession<'_>) -> Result<(), AnalysisError> {
        let result = session.assert_document();
        self.pump(session);
        result
    }

    /// Wait for the armed window to end by time, document change, target
    /// loss, failure or cancellation.
    fn wait(
        &mut self,
        session: &mut RuntimeSession<'_>,
        duration_ms: u64,
    ) -> Result<EndReason, AnalysisError> {
        let until = Instant::now().checked_add(Duration::from_millis(duration_ms));
        loop {
            self.window.check()?;
            if let Some(reason) = self.window.reason {
                return Ok(reason);
            }
            if session.cancellation.reason().is_some() {
                self.window
                    .fail(AnalysisError::cancelled(session.operation));
                continue;
            }
            let left = until.map_or(POLL, |until| {
                until.saturating_duration_since(Instant::now())
            });
            if left.is_zero() {
                self.window.end(EndReason::WindowElapsed);
                continue;
            }
            let polled = session.transport.poll(left.min(POLL), session.cancellation);
            self.pump(session);
            match polled {
                Ok(()) => {}
                Err(CdpTransportError::Cancelled(_)) => self
                    .window
                    .fail(AnalysisError::cancelled(session.operation)),
                Err(error) if is_disconnect(&error) => self.window.end(EndReason::TargetTerminated),
                Err(error) => self
                    .window
                    .fail(transport_error(error, session.operation, "event")),
            }
        }
    }
}

/// `onDisconnect`: transport loss, as opposed to a malformed delivery.
fn is_disconnect(error: &CdpTransportError) -> bool {
    match error {
        CdpTransportError::Io(_) | CdpTransportError::WebSocket(_) => !matches!(
            error,
            CdpTransportError::WebSocket(tungstenite::Error::Capacity(_))
        ),
        CdpTransportError::InvalidMessage(message) => message.contains("closed the connection"),
        _ => false,
    }
}

/// `captureWebExecution`.
pub(super) fn capture(
    session: &mut RuntimeSession<'_>,
    observation_ms: u64,
    progress: &Progress,
) -> Result<Value, AnalysisError> {
    let mut collection = Collection {
        sources: Sources::new(session),
        requests: Requests::new(
            session.operation,
            session.target.frame_id.clone(),
            session.allowed_origins.clone(),
        ),
        window: Window::new(session.target.frame_id.clone()),
        metadata_open: true,
    };
    let operation = session.operation;
    for domain in ["Page", "Runtime", "Debugger", "Network", "Profiler"] {
        collection.enable(session, domain)?;
    }
    collection.assert_document(session)?;
    collection.sources.check()?;
    session.precise_coverage_may_be_active = true;
    let started = collection.command(
        session,
        "Profiler.startPreciseCoverage",
        json!({ "callCount": true, "detailed": true, "allowTriggeredUpdates": false }),
    )?;
    let started = started
        .get("timestamp")
        .and_then(protocol::non_negative)
        .ok_or_else(|| {
            AnalysisError::output(operation, "Malformed Profiler.startPreciseCoverage result.")
        })?;
    collection.sources.check()?;
    collection.window.check()?;
    if let Some(reason) = collection.window.reason {
        return Err(observation_error(
            operation,
            "target_changed",
            Some(format!(
                "Selected target {} ended with {} before execution observation could be armed.",
                session.target.target_id,
                reason.as_str()
            )),
        ));
    }
    collection.window.arm();
    progress.report(
        "browser_execution",
        "Browser execution observation armed; perform the requested action now",
    );
    let reason = collection.wait(session, observation_ms)?;
    session.begin_completion();
    if session.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    collection.sources.check()?;
    collection.requests.check()?;
    let mut raw = None;
    if reason == EndReason::WindowElapsed {
        collection.assert_document(session)?;
        raw = Some(collection.command(session, "Profiler.takePreciseCoverage", json!({}))?);
    }
    collection.freeze_metadata()?;
    collection.command(session, "Profiler.stopPreciseCoverage", json!({}))?;
    session.precise_coverage_may_be_active = false;
    collection.requests.result(&collection.sources)?;
    let parsed = match &raw {
        None => None,
        Some(raw) => Some(protocol::precise_coverage(raw).ok_or_else(|| {
            AnalysisError::output(
                operation,
                "Malformed precise coverage: invalid Profiler.takePreciseCoverage result.",
            )
        })?),
    };
    let main_scripts: Vec<String> = collection
        .sources
        .script_order
        .iter()
        .filter(|id| collection.sources.belongs_to_document(id))
        .cloned()
        .collect();
    let reported: HashSet<&str> = parsed
        .as_ref()
        .map(|coverage| {
            coverage
                .result
                .iter()
                .map(|script| script.script_id.as_str())
                .collect()
        })
        .unwrap_or_default();
    let mut ids = main_scripts.clone();
    ids.extend(collection.requests.callsite_script_ids());
    let read_events = if reason == EndReason::WindowElapsed {
        ReadEvents::VerifyKnown
    } else {
        ReadEvents::Ignore
    };
    let retained = collection.sources.read(session, &ids, read_events)?;
    if reason == EndReason::WindowElapsed {
        collection.assert_document(session)?;
    }
    collection.sources.check()?;
    let verified_requests = collection.requests.result(&collection.sources)?;
    let verified_main: Vec<&String> = main_scripts
        .iter()
        .filter(|id| collection.sources.belongs_to_document(id))
        .collect();
    let sample = match &parsed {
        Some(coverage) => Some(normalize(coverage, &collection.sources, operation)?),
        None => None,
    };
    progress.report("browser_execution", "Browser execution observation ended");
    let window = &collection.window;
    let coverage = match &sample {
        Some(coverage) => coverage.clone(),
        None => json!({
            "state": "unavailable",
            "reason": format!(
                "The observation ended with {}; no complete final precise-coverage sample was retained.",
                reason.as_str()
            ),
            "offset_units": "utf16-code-units",
            "end_offset": "exclusive",
            "scripts": [],
            "excluded_scripts": 0,
        }),
    };
    Ok(json!({
        "browser": session.discovery.version,
        "target": session.target.to_json(),
        "window": {
            "armed_at": window.armed_at.clone().unwrap_or_else(iso_now),
            "ended_at": window.ended_at.clone().unwrap_or_else(iso_now),
            "requested_ms": observation_ms,
            "end_reason": reason.as_str(),
            "producer_started_seconds": started,
            "producer_sampled_seconds": parsed.as_ref().map(|coverage| coverage.timestamp.clone()),
        },
        "coverage": coverage,
        "requests": verified_requests,
        "excluded_requests": collection.requests.excluded,
        "script_inventory": {
            "main_document_scripts": verified_main.len(),
            "not_reported_script_ids": verified_main
                .iter()
                .filter(|id| !reported.contains(id.as_str()))
                .collect::<Vec<_>>(),
            "coverage_absence": "unknown",
        },
        "sources": retained,
        "instrumentation": {
            "resets_execution_counters": true,
            "disables_optimized_execution": true,
            "takes_one_resetting_sample": sample.is_some(),
            "executes_selected_code": false,
            "cleanup": "confirmed",
            "page_ownership": "external",
        },
        "limitations": LIMITATIONS,
    }))
}

/// `normalizePreciseCoverage`: validate ranges against retained UTF-16 text
/// without flattening nested counts.
fn normalize(
    parsed: &Coverage,
    sources: &Sources,
    operation: &str,
) -> Result<Value, AnalysisError> {
    let mut scripts = Vec::new();
    let mut excluded = 0_u64;
    for script in &parsed.result {
        if !sources.belongs_to_document(&script.script_id) {
            excluded += 1;
            continue;
        }
        let captured = match sources.retained(&script.script_id) {
            Some(SourceState::Captured { utf16_units, .. }) => Some(*utf16_units as u64),
            _ => None,
        };
        let mut functions = Vec::new();
        for function in &script.functions {
            let mut ranges = Vec::new();
            for range in &function.ranges {
                if range.end < range.start || captured.is_some_and(|units| range.end > units) {
                    return Err(AnalysisError::output(
                        operation,
                        format!(
                            "Script {} coverage range {}:{} is outside retained source bounds.",
                            script.script_id, range.start, range.end
                        ),
                    ));
                }
                ranges.push(json!({
                    "start_offset": range.start,
                    "end_offset": range.end,
                    "count": range.count,
                    "source_bounds": if captured.is_some() { "verified" } else { "unknown" },
                }));
            }
            functions.push(json!({
                "name": function.name,
                "is_block_coverage": function.is_block_coverage,
                "ranges": ranges,
            }));
        }
        scripts.push(json!({
            "script_id": script.script_id,
            "reported_url": sources.source_url(&script.script_id, &script.url),
            "functions": functions,
        }));
    }
    Ok(json!({
        "state": "captured",
        "reason": null,
        "offset_units": "utf16-code-units",
        "end_offset": "exclusive",
        "scripts": scripts,
        "excluded_scripts": excluded,
    }))
}
