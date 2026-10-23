//! `src/browser/CdpObservationSession.ts` (`observeCdpSession`,
//! `TimelineCapture`) and `src/browser/CdpAuthorizedMainFrame.ts`.
use super::completeness::Completeness;
use super::connection::{Connection, TargetFacts, foreign};
use super::values::{self, Event, Record};
use rea_core::analysis_error::AnalysisError;
use rea_mcp::Progress;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::time::Duration;

pub(super) const OPERATION: &str = "observe_web_session";
const PHASE: &str = "browser_observation";

/// `authorizedMainFrame`.
fn authorized_main_frame(
    connection: &mut Connection<'_>,
    origins: &BTreeSet<String>,
) -> Result<Value, AnalysisError> {
    for _ in 0..80 {
        let result = connection.send("Page.getFrameTree", json!({}))?;
        connection.discard()?;
        let url =
            values::main_frame_url(&result).map_err(|()| foreign(OPERATION, "protocol_error"))?;
        if values::allowed_sanitized_url(url.as_deref(), origins).is_some() {
            return Ok(result);
        }
        if values::is_http_url(url.as_deref()) {
            return Err(foreign(OPERATION, "target_not_allowed"));
        }
        // `delayWithCancellation(25)`: nobody listens yet.
        connection.wait(Duration::from_millis(25), |_, _, _| false)?;
        connection.discard()?;
    }
    Err(foreign(OPERATION, "target_not_allowed"))
}

struct Scoped {
    url: Option<String>,
    scope: &'static str,
}

/// `scopedUrl`.
fn scoped_url(value: Option<&str>, origins: &BTreeSet<String>) -> Scoped {
    if let Some(allowed) = values::allowed_sanitized_url(value, origins) {
        return Scoped {
            url: Some(allowed.url),
            scope: "approved",
        };
    }
    Scoped {
        url: None,
        scope: if values::is_http_url(value) {
            "outside_policy"
        } else {
            "unsupported"
        },
    }
}

/// `safeDetail`.
fn safe_detail(value: Option<&Value>) -> Option<String> {
    let detail = values::string(value)?.to_lowercase();
    let length = detail.chars().count();
    ((1..=100).contains(&length)
        && detail
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || "_.:-".contains(ch)))
    .then_some(detail)
}

/// `safeNetworkError`.
fn safe_network_error(value: Option<&Value>) -> Option<String> {
    let error = values::string(value)?;
    let code = error.strip_prefix("net::ERR_")?;
    ((1..=100).contains(&code.len())
        && code
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_'))
    .then(|| error.to_owned())
}

struct Entry<'a> {
    kind: &'static str,
    params: &'a Record,
    raw_url: Option<&'a str>,
    request_id: Option<&'a str>,
    detail: Option<String>,
}

/// `TimelineCapture`.
struct Timeline<'a> {
    origins: &'a BTreeSet<String>,
    main_frame_id: String,
    timeline: Vec<Value>,
    completeness: Completeness,
    final_url: Option<String>,
    sequence: u64,
    pending_reload: bool,
    scope_excluded: bool,
    end_reason: Option<&'static str>,
}

impl<'a> Timeline<'a> {
    fn ingest(&mut self, event: &Event) {
        if self.end_reason.is_some() || self.scope_excluded {
            return;
        }
        let Some(params) = event.params.as_object() else {
            return;
        };
        match event.method.as_str() {
            "Page.frameRequestedNavigation" => self.navigation_requested(event, params),
            "Page.frameNavigated" => self.navigation_committed(event, params),
            "Page.navigatedWithinDocument" => self.same_document(event, params),
            "Network.requestWillBeSent" => self.redirect(params),
            "Network.loadingFailed" => self.loading_failed(params),
            "Page.lifecycleEvent" => self.lifecycle(params),
            "Inspector.targetCrashed" | "Target.detachedFromTarget" => self.target_terminated(),
            _ => {}
        }
    }

    fn end(&mut self, reason: &'static str) {
        if self.end_reason.is_none() {
            self.end_reason = Some(reason);
        }
    }

    fn target_terminated(&mut self) {
        if self.end_reason.is_some() {
            return;
        }
        let empty = Map::new();
        self.add(Entry {
            kind: "target_terminated",
            params: &empty,
            raw_url: None,
            request_id: None,
            detail: Some("target_terminated".to_owned()),
        });
        self.end("target_terminated");
    }

    fn set_final_url(&mut self, raw: &str) {
        if self.scope_excluded {
            return;
        }
        let destination = scoped_url(Some(raw), self.origins);
        self.final_url = if destination.scope == "approved" {
            destination.url
        } else {
            None
        };
    }

    fn exclude_target_scope(&mut self, reason: &'static str) {
        if self.scope_excluded {
            return;
        }
        self.scope_excluded = true;
        self.final_url = None;
        self.completeness.exclude("timeline", reason);
    }

    fn left_scope(&mut self) {
        self.exclude_target_scope("out_of_target_scope");
        self.end("target_left_scope");
    }

    fn navigation_requested(&mut self, event: &Event, params: &Record) {
        if !values::is_main_frame_navigation(event, &self.main_frame_id) {
            return;
        }
        let reason = safe_detail(params.get("reason"));
        self.pending_reload = reason.as_deref() == Some("reload");
        self.add(Entry {
            kind: "navigation_requested",
            params,
            raw_url: values::string(params.get("url")),
            request_id: None,
            detail: reason,
        });
    }

    fn navigation_committed(&mut self, event: &Event, params: &Record) {
        let frame = values::record(params.get("frame"));
        if !values::is_main_frame_navigation(event, &self.main_frame_id) {
            return;
        }
        let raw_url = values::string(frame.and_then(|frame| frame.get("url")));
        let destination = scoped_url(raw_url, self.origins);
        let mut merged = params.clone();
        for key in ["frameId", "loaderId"] {
            let source = if key == "frameId" { "id" } else { "loaderId" };
            match frame.and_then(|frame| frame.get(source)) {
                Some(value) => merged.insert(key.to_owned(), value.clone()),
                None => merged.remove(key),
            };
        }
        let kind = if self.pending_reload {
            "same_origin_reload"
        } else {
            "navigation_committed"
        };
        self.add(Entry {
            kind,
            params: &merged,
            raw_url,
            request_id: None,
            detail: safe_detail(frame.and_then(|frame| frame.get("transitionType"))),
        });
        self.pending_reload = false;
        if destination.scope == "approved" {
            self.final_url = destination.url;
        } else {
            self.left_scope();
        }
    }

    fn same_document(&mut self, event: &Event, params: &Record) {
        if !values::is_main_frame_navigation(event, &self.main_frame_id) {
            return;
        }
        let raw_url = values::string(params.get("url"));
        let destination = scoped_url(raw_url, self.origins);
        self.add(Entry {
            kind: "same_document_navigation",
            params,
            raw_url,
            request_id: None,
            detail: None,
        });
        if destination.scope == "approved" {
            self.final_url = destination.url;
        } else {
            self.left_scope();
        }
    }

    fn redirect(&mut self, params: &Record) {
        if values::string(params.get("type")).is_some_and(|kind| kind != "Document") {
            return;
        }
        if values::string(params.get("frameId")) != Some(self.main_frame_id.as_str())
            || values::record(params.get("redirectResponse")).is_none()
        {
            return;
        }
        let raw_url = values::string(
            values::record(params.get("request")).and_then(|request| request.get("url")),
        );
        let destination = scoped_url(raw_url, self.origins);
        self.add(Entry {
            kind: "redirect",
            params,
            raw_url,
            request_id: values::string(params.get("requestId")),
            detail: None,
        });
        if destination.scope != "approved" {
            self.left_scope();
        }
    }

    fn loading_failed(&mut self, params: &Record) {
        if values::string(params.get("frameId")).is_some_and(|frame| frame != self.main_frame_id) {
            return;
        }
        self.add(Entry {
            kind: "load_failed",
            params,
            raw_url: None,
            request_id: values::string(params.get("requestId")),
            detail: safe_network_error(params.get("errorText")),
        });
    }

    fn lifecycle(&mut self, params: &Record) {
        if values::string(params.get("frameId")) != Some(self.main_frame_id.as_str()) {
            return;
        }
        self.add(Entry {
            kind: "lifecycle",
            params,
            raw_url: None,
            request_id: None,
            detail: safe_detail(params.get("name")),
        });
    }

    fn add(&mut self, entry: Entry<'_>) {
        let destination = entry.raw_url.map(|raw| scoped_url(Some(raw), self.origins));
        self.sequence += 1;
        let timestamp = values::number(entry.params.get("timestamp"))
            .unwrap_or(0.0)
            .max(0.0);
        let bounded =
            |key: &str| values::string(entry.params.get(key)).map_or(Value::Null, |id| json!(id));
        let (url, scope) = match destination {
            Some(Scoped { url, scope }) => {
                (if scope == "approved" { url } else { None }, Some(scope))
            }
            None => (None, None),
        };
        self.timeline.push(json!({
            "sequence": self.sequence,
            "type": entry.kind,
            "timestamp": values::js_number(timestamp),
            "frame_id": bounded("frameId"),
            "loader_id": bounded("loaderId"),
            "request_id": entry.request_id,
            "url": url,
            "destination_scope": scope,
            "detail": entry.detail,
        }));
    }
}

pub(super) fn observe(
    connection: &mut Connection<'_>,
    facts: &TargetFacts<'_>,
    observation_ms: u64,
    progress: &Progress,
) -> Result<Value, AnalysisError> {
    let origins = &facts.origins;
    let initial = authorized_main_frame(connection, origins)?;
    let initial_url = values::main_frame_url(&initial)
        .map_err(|()| foreign(OPERATION, "protocol_error"))?
        .unwrap_or_default();
    let main_frame_id = values::string(
        values::record(values::frame_tree_root(&initial).and_then(|tree| tree.get("frame")))
            .and_then(|frame| frame.get("id")),
    )
    .ok_or_else(|| foreign(OPERATION, "protocol_error"))?
    .to_owned();
    let mut capture = Timeline {
        origins,
        main_frame_id,
        timeline: Vec::new(),
        completeness: Completeness::new(&["timeline"]),
        final_url: values::allowed_sanitized_url(Some(&initial_url), origins).map(|url| url.url),
        sequence: 0,
        pending_reload: false,
        scope_excluded: false,
        end_reason: None,
    };
    let session_id = connection.session_id().map(str::to_owned);
    let matches = |event: &Event| {
        if event.method != "Target.detachedFromTarget" {
            return event.session_id == session_id;
        }
        session_id.is_some()
            && values::string(event.params.get("sessionId")) == session_id.as_deref()
    };
    let mut deliver = |connection: &mut Connection<'_>,
                       capture: &mut Timeline<'_>|
     -> Result<(), AnalysisError> {
        for event in connection.drain()? {
            if matches(&event) {
                capture.ingest(&event);
            }
        }
        Ok(())
    };
    for (method, params) in [
        ("Page.enable", json!({})),
        ("Network.enable", json!({})),
        ("Page.setLifecycleEventsEnabled", json!({ "enabled": true })),
    ] {
        connection.send(method, params)?;
        deliver(connection, &mut capture)?;
    }
    let armed_at = super::iso_now();
    progress.report(
        PHASE,
        "Browser observation armed; perform the requested user action now",
    );
    let mut end_reason = capture.end_reason;
    if end_reason.is_none() {
        let ended = connection.wait(
            Duration::from_millis(observation_ms),
            |_, events, disconnected| {
                for event in events {
                    if matches(&event) {
                        capture.ingest(&event);
                    }
                }
                if disconnected {
                    capture.target_terminated();
                }
                capture.end_reason.is_some()
            },
        )?;
        end_reason = if ended { capture.end_reason } else { None };
    }
    let mut end_reason = match end_reason {
        Some(reason) => reason,
        None => capture_final_url(connection, &mut capture, &mut deliver)?,
    };
    progress.report(PHASE, "Browser observation window ended");
    if capture.scope_excluded {
        end_reason = "target_left_scope";
    }
    Ok(json!({
        "browser": facts.discovery.version,
        "target": {
            "target_id": facts.target.id,
            "initial_url": values::allowed_sanitized_url(Some(&initial_url), origins).map(|url| url.url).unwrap_or_default(),
            "final_url": capture.final_url,
        },
        "window": {
            "armed_at": armed_at,
            "ended_at": super::iso_now(),
            "requested_ms": observation_ms,
            "end_reason": end_reason,
        },
        "timeline": capture.timeline,
        "completeness": capture.completeness.snapshot(),
        "limitations": [
            "The timeline begins after REA attaches; earlier navigation and network activity is unavailable.",
            "Only navigation metadata is retained; headers, bodies, cookies, console values, and payloads are not captured by this tool.",
            "An out-of-policy destination ends collection immediately and is recorded without its URL.",
        ],
    }))
}

/// `captureFinalUrl`.
fn capture_final_url(
    connection: &mut Connection<'_>,
    capture: &mut Timeline<'_>,
    deliver: &mut impl FnMut(&mut Connection<'_>, &mut Timeline<'_>) -> Result<(), AnalysisError>,
) -> Result<&'static str, AnalysisError> {
    if capture.scope_excluded {
        return Ok("target_left_scope");
    }
    let result = connection.send("Page.getFrameTree", json!({}))?;
    deliver(connection, capture)?;
    if capture.scope_excluded {
        return Ok("target_left_scope");
    }
    let url = values::main_frame_url(&result).map_err(|()| foreign(OPERATION, "protocol_error"))?;
    if let Some(url) = url
        .as_deref()
        .filter(|url| values::allowed_sanitized_url(Some(url), capture.origins).is_some())
    {
        capture.set_final_url(url);
        return Ok("window_elapsed");
    }
    capture.exclude_target_scope(if url.is_none() {
        "invalid_protocol_value"
    } else {
        "out_of_target_scope"
    });
    Ok("target_left_scope")
}
