//! `inspect_web_page`: one passive, origin-scoped page capture.
//!
//! Compatibility owners: `src/application/BrowserObservationService.ts`
//! (`inspectWebPage`, `retainBrowserObservation`),
//! `src/browser/CdpBrowserProvider.ts` (`inspectPage`, `withTargetSession`),
//! `src/browser/CdpPageCapture.ts` (`capturePage`),
//! `src/browser/CdpAuthorizedMainFrame.ts`, `src/browser/CdpOptionalCommand.ts`
//! and the owners named by each submodule. Input facts are
//! `inspectWebPageInputSchema` (`src/domain/browserObservation.ts`).
//!
//! The TS listener ingests target-session events as they arrive; here every
//! command is followed by a drain, so events are applied in arrival order
//! before the next step, exactly where the TS `await` resumed.
mod bundle;
mod documents;
mod events;
mod metadata;
mod ordered;
mod scripts;
mod snapshot;
mod source_maps;
mod storage;

use super::connection::{self, Connection, Rejection, TargetFacts, foreign};
use super::values::{self, Event};
use crate::cdp::{self, BrowserScope, Refinement};
use events::Events;
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};
use std::collections::{BTreeSet, HashSet};
use std::time::Duration;

pub(super) const OPERATION: &str = "inspect_web_page";
const PREDICATE: &str = "rea.web-page-inspection";
const PHASE: &str = "browser_observation";

pub(super) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| inspect(context, &input));
    bundle::register(registry);
}

/// Completed page capture facts retained for a subsequent bundle-analysis
/// phase. The source-map requests are kept beside the inspection because they
/// are derived from the same authorized script identities.
pub(super) struct CapturedPage {
    pub(super) inspection: Value,
    pub(super) source_map_requests: Vec<scripts::SourceMapRequest>,
}

/// The approved capture switches of `InspectWebPageInput`.
#[derive(Clone)]
pub(super) struct Options {
    pub observation_ms: u64,
    pub include_accessibility_text: bool,
    pub include_console_text: bool,
    pub include_json_body_shapes: bool,
    pub include_websocket_shapes: bool,
    pub include_storage_keys: bool,
    pub include_storage_fingerprints: bool,
    pub include_script_sources: bool,
}

struct Input {
    scope: BrowserScope,
    target_id: String,
    options: Options,
}

fn parse_input(input: &Value) -> Result<Input, ToolOutput> {
    let mut issues: Vec<Refinement> = Vec::new();
    let scope = cdp::parse_scope(input, &mut issues);
    let target_id = super::js_trim(
        input
            .get("target_id")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .to_owned();
    if target_id.is_empty() {
        issues.push(Refinement::new(
            vec![json!("target_id")],
            "Too small: expected string to have >=1 characters",
        ));
    }
    let flag = |name: &str| input.get(name).and_then(Value::as_bool).unwrap_or(false);
    let options = Options {
        observation_ms: input
            .get("observation_ms")
            .and_then(Value::as_u64)
            .unwrap_or(500),
        include_accessibility_text: flag("include_accessibility_text"),
        include_console_text: flag("include_console_text"),
        include_json_body_shapes: flag("include_json_body_shapes"),
        include_websocket_shapes: flag("include_websocket_shapes"),
        include_storage_keys: flag("include_storage_keys"),
        include_storage_fingerprints: flag("include_storage_fingerprints"),
        include_script_sources: flag("include_script_sources"),
    };
    // `refineInspectWebPageInput` runs unless an aborting transform (the
    // endpoint or origin schemas) failed; `target_id`'s length check does
    // not abort it.
    if scope.is_some() && options.include_storage_fingerprints && !options.include_storage_keys {
        issues.push(Refinement::new(
            vec![json!("include_storage_fingerprints")],
            "Storage fingerprints require storage key capture",
        ));
    }
    match scope {
        Some(scope) if issues.is_empty() => Ok(Input {
            scope,
            target_id,
            options,
        }),
        _ => Err(cdp::refinement_failure(OPERATION, issues)),
    }
}

fn inspect(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let parsed = match parse_input(input) {
        Ok(parsed) => parsed,
        Err(failure) => return failure,
    };
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(OPERATION));
    }
    let mut completed: Option<Value> = None;
    let outcome = connection::with_target_session(
        OPERATION,
        &parsed.scope,
        &parsed.target_id,
        &context.cancellation,
        |connection, facts| {
            let inspection = capture_page(connection, facts, &parsed.options, context)?;
            completed = Some(inspection.clone());
            Ok(inspection)
        },
    );
    match outcome {
        Ok(result) => {
            let parameters = parameters(&parsed, &result);
            match super::super::browser_observation_evidence(
                OPERATION, PREDICATE, parameters, result,
            ) {
                // `completeProviderEvidence`: a late cancellation retains the
                // completed Evidence as its partial observation.
                Ok(evidence) if context.cancellation.reason().is_some() => ToolOutput::Failure(
                    AnalysisError::cancelled(OPERATION)
                        .retain_partial_observation(evidence.into_value()),
                ),
                Ok(evidence) => ToolOutput::Evidence(evidence),
                Err(error) => ToolOutput::Failure(error),
            }
        }
        // `retainBrowserObservation`: a cancellation that arrived after the
        // capture completed keeps the inspection as Evidence.
        Err(error) if is_cancelled(&error) && completed.is_some() => {
            let result = completed.unwrap_or(Value::Null);
            let parameters = parameters(&parsed, &result);
            match super::super::browser_observation_evidence(
                OPERATION, PREDICATE, parameters, result,
            ) {
                Ok(evidence) => {
                    ToolOutput::Failure(error.retain_partial_observation(evidence.into_value()))
                }
                Err(_) => ToolOutput::Failure(AnalysisError::output(
                    OPERATION,
                    "Browser provider retained a malformed completed page inspection.",
                )),
            }
        }
        Err(error) => ToolOutput::Failure(error),
    }
}

fn is_cancelled(error: &AnalysisError) -> bool {
    matches!(
        error.kind,
        rea_core::analysis_error::ErrorKind::Cancelled { .. }
    )
}

/// `browserParameters` for an inspection input.
fn parameters(input: &Input, result: &Value) -> Value {
    let allowed: Vec<String> = if input.scope.allowed_origins.is_empty() {
        result["target"]["origin"]
            .as_str()
            .map(str::to_owned)
            .into_iter()
            .collect()
    } else {
        input.scope.allowed_origins.clone()
    };
    let options = &input.options;
    json!({
        "cdp_endpoint": input.scope.endpoint.recorded,
        "allowed_origins": allowed,
        "target_id": input.target_id,
        "observation_ms": options.observation_ms,
        "include_accessibility_text": options.include_accessibility_text,
        "include_console_text": options.include_console_text,
        "include_json_body_shapes": options.include_json_body_shapes,
        "include_websocket_shapes": options.include_websocket_shapes,
        "include_storage_keys": options.include_storage_keys,
        "include_storage_fingerprints": options.include_storage_fingerprints,
        "include_script_sources": options.include_script_sources,
    })
}

/// One capture's connection, event state and limitations (`CaptureState`).
struct Capture<'c, 'a> {
    conn: &'c mut Connection<'a>,
    events: Events,
    limitations: Vec<String>,
    options: Options,
    origins: BTreeSet<String>,
    target_id: String,
    session_id: Option<String>,
}

impl Capture<'_, '_> {
    /// Apply events delivered so far (the TS `onEvent` listener).
    fn ingest(&mut self, batch: Vec<Event>) {
        for event in batch {
            if event.session_id == self.session_id {
                self.events.ingest(&event);
            }
        }
    }
    fn pump(&mut self) -> Result<(), AnalysisError> {
        let batch = self.conn.drain()?;
        self.ingest(batch);
        Ok(())
    }
    fn after<T>(&mut self, result: Result<T, AnalysisError>) -> Result<T, AnalysisError> {
        let value = result?;
        self.pump()?;
        Ok(value)
    }
    pub(super) fn send(&mut self, method: &str, params: Value) -> Result<Value, AnalysisError> {
        let result = self.conn.send(method, params);
        self.after(result)
    }
    /// `optionalCdpCommand` in the target session.
    pub(super) fn optional(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Option<Value>, AnalysisError> {
        let result = self
            .conn
            .send_optional(method, params, &mut self.limitations);
        self.after(result)
    }
    /// `optionalCdpCommand` with `sessionId: undefined`.
    pub(super) fn browser_optional(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Option<Value>, AnalysisError> {
        let result = self
            .conn
            .send_browser_optional(method, params, &mut self.limitations);
        self.after(result)
    }
    pub(super) fn send_rejectable(
        &mut self,
        method: &str,
        params: Value,
        cancellation: Option<rea_core::cancellation::Cancellation>,
    ) -> Result<Value, Rejection> {
        let result = self
            .conn
            .send_rejectable(method, params, cancellation.as_ref());
        let value = result?;
        self.pump().map_err(Rejection::Failed)?;
        Ok(value)
    }
    /// `delayWithCancellation` with the listener attached.
    fn delay(&mut self, milliseconds: u64) -> Result<(), AnalysisError> {
        let session_id = self.session_id.clone();
        let events = &mut self.events;
        self.conn
            .wait(Duration::from_millis(milliseconds), |_, batch, _| {
                for event in batch {
                    if event.session_id == session_id {
                        events.ingest(&event);
                    }
                }
                false
            })?;
        Ok(())
    }
    /// `authorizedMainFrame`.
    fn authorized_main_frame(&mut self) -> Result<Value, AnalysisError> {
        for _ in 0..80 {
            let result = self.send("Page.getFrameTree", json!({}))?;
            let url = values::main_frame_url(&result)
                .map_err(|()| foreign(OPERATION, "protocol_error"))?;
            if values::allowed_sanitized_url(url.as_deref(), &self.origins).is_some() {
                return Ok(result);
            }
            if values::is_http_url(url.as_deref()) {
                return Err(foreign(OPERATION, "target_not_allowed"));
            }
            self.delay(25)?;
        }
        Err(foreign(OPERATION, "target_not_allowed"))
    }
}

/// `capturePage` + `captureAuthorizedPage`.
fn capture_page(
    conn: &mut Connection<'_>,
    facts: &TargetFacts<'_>,
    options: &Options,
    context: &ToolContext<'_>,
) -> Result<Value, AnalysisError> {
    Ok(capture_page_with_sources(conn, facts, options, context)?.inspection)
}

/// Capture an authorized page while retaining source-map identities for the
/// caller that owns bundle analysis.
pub(super) fn capture_page_with_sources(
    conn: &mut Connection<'_>,
    facts: &TargetFacts<'_>,
    options: &Options,
    context: &ToolContext<'_>,
) -> Result<CapturedPage, AnalysisError> {
    let mut limitations: Vec<String> = [
        "Observation starts when REA attaches; prior network and console activity is unavailable.",
        "Raw network headers, bodies, cookies, storage values, console objects, and WebSocket payloads are never retained; explicitly requested primitive console text is retained verbatim, while payload captures retain value-free shapes.",
        "Source maps are reported only as declarative URLs and are not fetched.",
        "URL-less scripts and console events without an allowed source URL are excluded because their origin cannot be proven.",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    if facts.target.attached.is_none() {
        limitations.push(
            "CDP discovery omitted the target attachment state; attached is reported as unknown."
                .to_owned(),
        );
    }
    let started_at = super::iso_now();
    let session_id = conn.session_id().map(str::to_owned);
    let mut capture = Capture {
        conn,
        events: Events::new(options.clone(), facts.origins.clone()),
        limitations,
        options: options.clone(),
        origins: facts.origins.clone(),
        target_id: facts.target.id.clone(),
        session_id,
    };
    let progress = &context.progress;

    // `authorizeObservationWindow`.
    progress.report(PHASE, "Enabling passive CDP domains");
    capture.send("Page.enable", json!({}))?;
    let initial = capture.authorized_main_frame()?;
    let Some(main) = values::capture_frames(&initial, &capture.origins, None, None)
        .into_iter()
        .next()
    else {
        return Err(foreign(OPERATION, "target_not_allowed"));
    };
    capture.events.begin_authorized_frame(&main.frame_id);
    for domain in ["Runtime.enable", "Debugger.enable", "Network.enable"] {
        capture.send(domain, json!({}))?;
    }
    progress.report(PHASE, "Observing page events");
    capture.delay(options.observation_ms)?;
    if capture.events.origin_violation {
        return Err(foreign(OPERATION, "target_not_allowed"));
    }

    capture_json_bodies(&mut capture)?;
    let frame_result = capture.authorized_main_frame()?;
    let attached_url = values::main_frame_url(&frame_result)
        .map_err(|()| foreign(OPERATION, "protocol_error"))?
        .unwrap_or_default();
    let frames = values::capture_frames(
        &frame_result,
        &capture.origins,
        None,
        Some(&mut capture.events.completeness),
    );
    let Some(capture_frame) = frames.first() else {
        return Err(foreign(OPERATION, "target_not_allowed"));
    };
    capture.events.begin_final_capture(&capture_frame.frame_id);
    let frame_ids: BTreeSet<String> = frames.iter().map(|frame| frame.frame_id.clone()).collect();

    let tree = capture.send("Page.getResourceTree", json!({}))?;
    let raw_resources =
        documents::capture_resources(&tree, &capture.origins, &mut capture.events.completeness);
    let resources = documents::stable_resources(&raw_resources);
    let dom = capture_page_dom(&mut capture)?;
    let accessibility = accessibility_for_frames(&mut capture, &frames)?;
    let (scripts, source_map_requests) =
        scripts::capture_scripts(&mut capture, &raw_resources, &resources, &frame_ids)?;
    let workers = scripts::capture_workers(&mut capture, &frame_ids)?;
    let storage = storage::capture_storage(&mut capture, &attached_url)?;
    if !options.include_storage_keys {
        capture
            .events
            .completeness
            .exclude_count("storage_keys", "not_approved", None);
    } else if let Some(reason) = storage.keys_exclusion {
        capture
            .events
            .completeness
            .exclude_count("storage_keys", reason, None);
    }
    progress.report(PHASE, "Normalizing browser evidence");
    let completed = capture.authorized_main_frame()?;
    let completed_url = values::main_frame_url(&completed)
        .map_err(|()| foreign(OPERATION, "protocol_error"))?
        .unwrap_or_default();
    if capture.events.origin_violation {
        return Err(foreign(OPERATION, "target_not_allowed"));
    }
    if capture.events.navigation_during_capture || completed_url != attached_url {
        return Err(foreign(OPERATION, "target_changed"));
    }
    capture.events.settle_unexamined_bodies();
    capture.events.record_script_budget_exclusions();

    let target_url = values::allowed_sanitized_url(Some(&attached_url), &capture.origins);
    let events = &capture.events;
    let mut hints: Vec<Value> = events.agent_hints.clone();
    hints.extend(dom.agent_hints.iter().cloned());
    let mut seen = HashSet::new();
    hints.retain(|hint| {
        seen.insert(format!(
            "{}\0{}\0{}",
            hint["mechanism"].as_str().unwrap_or(""),
            hint["declaration"].as_str().unwrap_or(""),
            hint["url"].as_str().unwrap_or("")
        ))
    });
    let inspection = json!({
        "browser": facts.discovery.version,
        "target": {
            "target_id": facts.target.id,
            "type": facts.target.kind,
            "title": facts.target.title,
            "url": target_url.as_ref().map_or("[unsupported-url]", |url| url.url.as_str()),
            "origin": target_url.as_ref().and_then(|url| url.origin.as_deref()).unwrap_or(""),
            "attached": facts.target.attached,
        },
        "capture_window": {
            "started_at": started_at,
            "ended_at": super::iso_now(),
            "observation_ms": options.observation_ms,
        },
        "completeness": events.completeness.snapshot(),
        "frames": frames.iter().map(|frame| json!({
            "frame_id": frame.frame_id,
            "parent_frame_id": frame.parent_frame_id,
            "url": frame.url,
            "origin": frame.origin,
        })).collect::<Vec<_>>(),
        "dom": { "total_nodes": dom.total, "nodes": dom.nodes },
        "accessibility": {
            "total_nodes": accessibility.total,
            "text_capture": accessibility.text_capture,
            "nodes": accessibility.nodes,
        },
        "scripts": scripts,
        "resources": resources,
        "network": {
            "requests": events.network.values().map(events::Request::to_json).collect::<Vec<_>>(),
            "websocket_connections": events.websockets.values().map(|socket| json!({
                "request_id": socket.request_id,
                "url": socket.url,
                "events": socket.events,
            })).collect::<Vec<_>>(),
            "coverage_started_at": started_at,
            "prior_activity_available": false,
        },
        "console": {
            "events": events.console,
            "coverage_started_at": started_at,
            "prior_activity_available": false,
        },
        "workers": workers,
        "metadata": {
            "responses": events.response_metadata,
            "dom_urls": dom.urls,
            "agent_hints": hints,
            "excluded_dom_urls": dom.excluded_urls,
            "headers_allowlisted": true,
        },
        "storage": storage.value,
        "limitations": capture.limitations,
    });
    Ok(CapturedPage {
        inspection: values::js_json(&inspection),
        source_map_requests,
    })
}

/// `captureJsonResponseBodies`.
fn capture_json_bodies(capture: &mut Capture<'_, '_>) -> Result<(), AnalysisError> {
    let requests = capture.events.response_body_requests();
    for (index, candidate) in requests.iter().enumerate() {
        let Some(current) = capture.events.current_body_request(candidate) else {
            continue;
        };
        if current.encoded_data_length.is_null() {
            capture.events.response_body_unavailable(candidate);
            continue;
        }
        let method = "Network.getResponseBody";
        match capture.send_rejectable(method, json!({ "requestId": candidate.request_id }), None) {
            Ok(result) => capture.events.ingest_response_body(candidate, &result),
            Err(Rejection::Rejected {
                code: Some(-32_601),
                ..
            }) => {
                capture.limitations.push(format!(
                    "{method} was unavailable from this browser target."
                ));
                capture.pump()?;
                for remaining in &requests[index..] {
                    capture.events.response_body_unavailable(remaining);
                }
                return Ok(());
            }
            Err(Rejection::Rejected {
                code: Some(-32_000),
                message,
                ..
            }) => {
                capture.pump()?;
                capture.events.response_body_unavailable(candidate);
                capture.limitations.push(format!(
                    "Response body unavailable for request {}: CDP {method} failed (-32000): {message}",
                    candidate.request_id
                ));
            }
            Err(rejection) => return Err(rejection.into_error()),
        }
    }
    Ok(())
}

/// `capturePageDom`.
fn capture_page_dom(capture: &mut Capture<'_, '_>) -> Result<documents::DomCapture, AnalysisError> {
    let result = capture.send(
        "DOMSnapshot.captureSnapshot",
        json!({ "computedStyles": [], "includePaintOrder": false, "includeDOMRects": false }),
    )?;
    let mut buffered: Vec<Event> = Vec::new();
    let mut description_unavailable = false;
    let conn = &mut *capture.conn;
    let mut describe =
        |queries: &[snapshot::SvgQuery]| -> Result<Vec<Option<bool>>, AnalysisError> {
            // Every query of one batch is issued before any reply is read, so all
            // of them observe the availability known when the batch started.
            let skip = description_unavailable;
            let mut kinds = Vec::with_capacity(queries.len());
            for query in queries {
                if skip {
                    kinds.push(None);
                    continue;
                }
                let reply = conn.send_rejectable(
                    "DOM.describeNode",
                    json!({ "backendNodeId": query.backend_node_id, "depth": 0 }),
                    None,
                );
                buffered.extend(conn.drain()?);
                match reply {
                    Ok(result) => kinds.push(snapshot::svg_node_kind(query, &result)),
                    Err(Rejection::Rejected {
                        code: Some(-32_601),
                        ..
                    }) => {
                        description_unavailable = true;
                        kinds.push(None);
                    }
                    Err(Rejection::Rejected {
                        code: Some(-32_000),
                        ..
                    }) => kinds.push(None),
                    Err(rejection) => return Err(rejection.into_error()),
                }
            }
            Ok(kinds)
        };
    let dom = documents::capture_dom(
        &result,
        &capture.origins,
        &mut capture.events.completeness,
        &mut describe,
    );
    capture.ingest(buffered);
    let dom = dom?;
    if dom.unresolved_svg_nodes > 0 {
        capture.limitations.push(format!(
            "SVG identity was unavailable for {} snapshotted XLink candidate nodes; their URL destinations remain unknown.",
            dom.unresolved_svg_nodes
        ));
    }
    Ok(dom)
}

/// `accessibilityForFrames`.
fn accessibility_for_frames(
    capture: &mut Capture<'_, '_>,
    frames: &[values::Frame],
) -> Result<documents::Accessibility, AnalysisError> {
    let mut results = Vec::new();
    let mut unavailable = false;
    for frame in frames {
        match capture.optional(
            "Accessibility.getFullAXTree",
            json!({ "frameId": frame.frame_id }),
        )? {
            Some(result) => results.push(result),
            None => unavailable = true,
        }
    }
    let completeness = &mut capture.events.completeness;
    if unavailable {
        completeness.unavailable("accessibility");
    }
    let include = capture.options.include_accessibility_text;
    let accessibility = documents::capture_accessibility(
        &results,
        include,
        results.is_empty() && unavailable,
        completeness,
    );
    if !include {
        completeness.exclude_count(
            "accessibility",
            "not_approved",
            Some(accessibility.excluded_fields),
        );
    }
    if accessibility.has_unobserved_children {
        completeness.truncate("accessibility");
    }
    Ok(accessibility)
}
