//! One owned CDP browser connection and the page world it observes.
//!
//! The synchronous transport buffers unsolicited events while a command is
//! in flight; every command and wait drains them in arrival order into
//! [`World::dispatch`], so observers see exactly CDP receipt order. Work that
//! needs a command in response to an event (target initialization, content
//! reads) is queued by the world and serviced by the driver afterwards.
//!
//! Compatibility owners for the observed CDP semantics: Playwright 1.58.2's
//! `crPage.js` (frame/lifecycle/console/exception handling, context option
//! emulation), `crNetworkManager.js` (request/response/redirect/finish/fail
//! ordering, favicon and `data:` exclusion) and `frames.js`.
use super::input::Environment;
use super::network::{Network, RequestRecord, ResponseRecord, headers_from_object};
use super::recorder::Recorder;
use super::secrets::Secrets;
use crate::cdp::target_session::Deadline;
use rea_core::cancellation::Cancellation;
use rea_host::cdp_transport::{CdpTransportError, CdpWebSocketTransport, DetachedCommand};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::{Duration, Instant};

pub(crate) const UTILITY_WORLD: &str = "__rea_scenario_utility__";
pub(crate) const PAGE_HELPER: &str = include_str!("page.js");
const FONT_FAMILIES: &str = include_str!("font_families.json");
const POLL_SLICE: Duration = Duration::from_millis(20);

/// Why one command or wait did not complete.
#[derive(Clone, Debug)]
pub(crate) enum CallError {
    /// The caller's request was cancelled.
    Cancelled,
    /// The step deadline elapsed.
    Deadline,
    /// The browser answered with a protocol error.
    Protocol(String),
    /// The connection or target is gone.
    Closed(String),
}

impl CallError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::Cancelled => "scenario request cancelled".to_owned(),
            Self::Deadline => "deadline".to_owned(),
            Self::Protocol(message) | Self::Closed(message) => message.clone(),
        }
    }
}

/// A caller cancellation joined with an optional step deadline.
pub(crate) struct Scope {
    deadline: Option<Deadline>,
    request: Cancellation,
}

impl Scope {
    pub(crate) fn new(request: &Cancellation, timeout_ms: Option<u64>) -> Self {
        Self {
            deadline: timeout_ms.map(|ms| Deadline::new(Some(request), Duration::from_millis(ms))),
            request: request.clone(),
        }
    }

    /// A narrower deadline under the same caller cancellation.
    pub(crate) fn child(&self, timeout_ms: Option<u64>) -> Self {
        Self::new(&self.request, timeout_ms)
    }

    pub(crate) fn token(&self) -> &Cancellation {
        self.deadline.as_ref().map_or(&self.request, Deadline::cancellation)
    }

    pub(crate) fn interrupted(&self) -> Option<CallError> {
        if self.request.reason().is_some() {
            return Some(CallError::Cancelled);
        }
        if self.deadline.as_ref().is_some_and(Deadline::expired) {
            return Some(CallError::Deadline);
        }
        None
    }

    fn classify(&self, error: CdpTransportError) -> CallError {
        match error {
            CdpTransportError::Cancelled(_) => self.interrupted().unwrap_or(CallError::Cancelled),
            CdpTransportError::Protocol { message, .. } => CallError::Protocol(message),
            CdpTransportError::Timeout => CallError::Closed("CDP request timed out".to_owned()),
            other => CallError::Closed(other.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SessionKind {
    Page,
    Frame,
    Worker,
    Other,
}

#[derive(Clone, Debug)]
pub(crate) struct SessionInfo {
    pub kind: SessionKind,
    pub target_id: String,
    pub url: String,
    pub parent: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct FrameInfo {
    pub session: String,
    pub parent: Option<String>,
    pub name: String,
    pub url: String,
}

#[derive(Clone, Debug)]
struct ContextInfo {
    frame: String,
    utility: bool,
    /// The page main world (`auxData.isDefault`), not an extension or REA world.
    main: bool,
}

/// Target initialization queued by an attach event.
#[derive(Clone, Debug)]
struct PendingAttach {
    session: String,
    kind: SessionKind,
    waiting: bool,
}

/// Page state as REA's observers know it.
pub(crate) struct World {
    pub secrets: Secrets,
    pub recorder: Recorder,
    pub network: Option<Network>,
    pub requests: Vec<RequestRecord>,
    request_index: HashMap<(String, String), usize>,
    hops: HashMap<(String, String), Vec<usize>>,
    request_extra: HashMap<(String, String), Vec<Vec<(String, String)>>>,
    response_extra: HashMap<(String, String), Vec<Vec<(String, String)>>>,
    favicons: BTreeSet<usize>,
    pub sessions: HashMap<String, SessionInfo>,
    pub main_session: Option<String>,
    pub main_target: Option<String>,
    pub frames: HashMap<String, FrameInfo>,
    pub main_frame: Option<String>,
    contexts: HashMap<(String, i64), ContextInfo>,
    installed: BTreeSet<(String, i64)>,
    pub loader: Option<String>,
    pub lifecycle: BTreeMap<String, BTreeSet<String>>,
    pub navigation_requests: u64,
    pub commits: u64,
    pub navigation_failure: Option<(String, String)>,
    pending: Vec<PendingAttach>,
    /// Launch mode applies context options to every page target.
    pub launch: Option<Environment>,
    pub init_scripts: Vec<String>,
    pub init_script_ids: Vec<String>,
    pub page_closed: bool,
    pub transport_lost: Option<String>,
    sockets: HashMap<String, String>,
    pub popups: BTreeSet<String>,
    pub font_families: Option<Value>,
    pub service_worker_targets: BTreeSet<String>,
    pub seeds: Seeds,
}

/// Non-cookie storage seeds, applied once per origin before page scripts.
///
/// Compatibility owner: `src/browser/PlaywrightScenarioStorage.ts`. The TS
/// owner pauses each new document in a private debugger script; this owner
/// uses a utility-world document-start script, which also runs before any
/// page script, and removes an origin from it once its first document seeded.
#[derive(Default)]
pub(crate) struct Seeds {
    pub local: BTreeMap<String, Vec<(String, String)>>,
    pub session: BTreeMap<String, Vec<(String, String)>>,
    pub dirty: bool,
    pub script_ids: Vec<(String, String)>,
}

impl Seeds {
    fn mark_seeded(&mut self, origin: &str) {
        let local = self.local.remove(origin).is_some();
        let session = self.session.remove(origin).is_some();
        self.dirty |= local || session;
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.local.is_empty() && self.session.is_empty()
    }

    /// The current document-start script, or `None` when nothing remains.
    pub(crate) fn script(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        let table = |seeds: &BTreeMap<String, Vec<(String, String)>>| {
            Value::Object(seeds.iter().map(|(origin, entries)| (origin.clone(), json!(entries))).collect())
        };
        Some(format!(
            "(() => {{ const local = {}; const session = {}; const origin = location.origin; \
             try {{ for (const [name, value] of local[origin] || []) localStorage.setItem(name, value); }} catch (error) {{}} \
             try {{ for (const [name, value] of session[origin] || []) sessionStorage.setItem(name, value); }} catch (error) {{}} }})();",
            table(&self.local),
            table(&self.session),
        ))
    }
}

impl World {
    pub(crate) fn new(secrets: Secrets, recorder: Recorder, network: Option<Network>) -> Self {
        Self {
            secrets,
            recorder,
            network,
            requests: Vec::new(),
            request_index: HashMap::new(),
            hops: HashMap::new(),
            request_extra: HashMap::new(),
            response_extra: HashMap::new(),
            favicons: BTreeSet::new(),
            sessions: HashMap::new(),
            main_session: None,
            main_target: None,
            frames: HashMap::new(),
            main_frame: None,
            contexts: HashMap::new(),
            installed: BTreeSet::new(),
            loader: None,
            lifecycle: BTreeMap::new(),
            navigation_requests: 0,
            commits: 0,
            navigation_failure: None,
            pending: Vec::new(),
            launch: None,
            init_scripts: Vec::new(),
            init_script_ids: Vec::new(),
            page_closed: false,
            transport_lost: None,
            sockets: HashMap::new(),
            popups: BTreeSet::new(),
            font_families: None,
            service_worker_targets: BTreeSet::new(),
            seeds: Seeds::default(),
        }
    }

    /// `page.url()`: the main frame URL.
    pub(crate) fn current_url(&self) -> String {
        self.main_frame
            .as_ref()
            .and_then(|frame| self.frames.get(frame))
            .map(|frame| frame.url.clone())
            .unwrap_or_else(|| "about:blank".to_owned())
    }

    fn page_session_of(&self, session: &str) -> Option<String> {
        let mut current = session.to_owned();
        loop {
            let info = self.sessions.get(&current)?;
            if info.kind == SessionKind::Page {
                return Some(current);
            }
            current = info.parent.clone()?;
        }
    }

    fn observed(&self, session: &str) -> bool {
        self.page_session_of(session).is_some()
    }

    fn is_main_frame(&self, frame: &str) -> bool {
        self.main_frame.as_deref() == Some(frame)
    }

    fn safe_url(&self, url: &str) -> Value {
        if url.is_empty() { Value::Null } else { self.secrets.sanitize_url(url) }
    }

    fn frame_event(&mut self, kind: &str, frame: &str) {
        if !self.recorder.listening {
            return;
        }
        if !self.recorder.families.has("frames") {
            return;
        }
        let info = self.frames.get(frame).cloned().unwrap_or_default();
        if !self.recorder.admit_text(&self.secrets, kind, &[&info.url, &info.name], false).retained() {
            return;
        }
        let name = if info.name.is_empty() { Value::Null } else { json!(self.secrets.redact(&info.name)) };
        let url = self.safe_url(&info.url);
        self.recorder.push(kind, vec![("kind", json!(kind)), ("url", url), ("name", name)]);
    }

    /// Route one CDP event to its owner, in receipt order.
    pub(crate) fn dispatch(&mut self, event: &Value) {
        let method = event.get("method").and_then(Value::as_str).unwrap_or_default();
        let params = event.get("params").cloned().unwrap_or(Value::Null);
        let session = event.get("sessionId").and_then(Value::as_str).unwrap_or_default().to_owned();
        if method.starts_with("Target.") && std::env::var_os("REA_SCENARIO_TRACE").is_some() {
            eprintln!("[scenario] <- {method} {session} {params}");
        }
        match method {
            "Target.attachedToTarget" => self.attached(&session, &params),
            "Target.detachedFromTarget" => self.detached(&params),
            "Target.targetDestroyed" => {
                if params.get("targetId").and_then(Value::as_str) == self.main_target.as_deref() {
                    self.page_closed = true;
                }
            }
            "Inspector.targetCrashed" if Some(&session) == self.main_session.as_ref() => self.page_closed = true,
            "Inspector.detached" if Some(&session) == self.main_session.as_ref() => self.page_closed = true,
            _ if !self.observed(&session) => {
                if method == "Browser.downloadWillBegin" {
                    self.download(&params);
                }
            }
            "Page.frameAttached" => {
                let frame = params.get("frameId").and_then(Value::as_str).unwrap_or_default().to_owned();
                let parent = params.get("parentFrameId").and_then(Value::as_str).map(str::to_owned);
                if self.frames.contains_key(&frame) {
                    return;
                }
                self.frames.insert(frame.clone(), FrameInfo { session: session.clone(), parent, ..FrameInfo::default() });
                self.frame_event("frame-attached", &frame);
            }
            "Page.frameNavigated" => self.frame_navigated(&session, params.get("frame").unwrap_or(&Value::Null), true),
            "Page.navigatedWithinDocument" => {
                let frame = params.get("frameId").and_then(Value::as_str).unwrap_or_default().to_owned();
                let url = params.get("url").and_then(Value::as_str).unwrap_or_default().to_owned();
                if let Some(info) = self.frames.get_mut(&frame) {
                    info.url = url;
                    if self.is_main_frame(&frame) {
                        self.commits += 1;
                    }
                    self.frame_event("frame-navigated", &frame);
                }
            }
            "Page.frameDetached" => {
                let frame = params.get("frameId").and_then(Value::as_str).unwrap_or_default().to_owned();
                if params.get("reason").and_then(Value::as_str) == Some("swap") {
                    return;
                }
                self.remove_frame(&frame);
            }
            "Page.frameRequestedNavigation" | "Page.frameScheduledNavigation" => {
                if params.get("frameId").and_then(Value::as_str).is_some_and(|frame| self.is_main_frame(frame)) {
                    self.navigation_requests += 1;
                }
            }
            "Page.lifecycleEvent" => {
                let frame = params.get("frameId").and_then(Value::as_str).unwrap_or_default();
                if self.is_main_frame(frame) {
                    let loader = params.get("loaderId").and_then(Value::as_str).unwrap_or_default().to_owned();
                    let name = params.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
                    if name == "init" {
                        self.lifecycle.insert(loader.clone(), BTreeSet::new());
                    }
                    self.lifecycle.entry(loader).or_default().insert(name);
                }
            }
            "Page.downloadWillBegin" => self.download(&params),
            "Runtime.executionContextCreated" => {
                let context = params.get("context").cloned().unwrap_or(Value::Null);
                let id = context.get("id").and_then(Value::as_i64).unwrap_or_default();
                let aux = context.get("auxData").cloned().unwrap_or(Value::Null);
                let frame = aux.get("frameId").and_then(Value::as_str).unwrap_or_default().to_owned();
                let utility = context.get("name").and_then(Value::as_str) == Some(UTILITY_WORLD);
                if utility {
                    // The seed script ran when this world was created.
                    let origin = context.get("origin").and_then(Value::as_str).unwrap_or_default().to_owned();
                    self.seeds.mark_seeded(&origin);
                }
                let main = aux.get("isDefault").and_then(Value::as_bool).unwrap_or(false);
                self.contexts.insert((session, id), ContextInfo { frame, utility, main });
            }
            "Runtime.executionContextDestroyed" => {
                let id = params.get("executionContextId").and_then(Value::as_i64).unwrap_or_default();
                self.contexts.remove(&(session.clone(), id));
                self.installed.remove(&(session, id));
            }
            "Runtime.executionContextsCleared" => {
                self.contexts.retain(|(owner, _), _| *owner != session);
                self.installed.retain(|(owner, _)| *owner != session);
            }
            "Runtime.consoleAPICalled" => self.console_api(&session, &params),
            "Log.entryAdded" => self.log_entry(&params),
            "Runtime.exceptionThrown" => self.exception(&params),
            "Network.requestWillBeSent" => self.request_will_be_sent(&session, &params),
            // `ResponseExtraInfoTracker`: extra info may precede or follow
            // its request/response and is matched by redirect-hop order.
            "Network.requestWillBeSentExtraInfo" | "Network.responseReceivedExtraInfo" => {
                let id = params.get("requestId").and_then(Value::as_str).unwrap_or_default().to_owned();
                let headers = headers_from_object(params.get("headers"), true);
                let queue = if method == "Network.requestWillBeSentExtraInfo" { &mut self.request_extra } else { &mut self.response_extra };
                queue.entry((session.clone(), id)).or_default().push(headers);
                self.patch_headers(&session, &params);
            }
            "Network.responseReceived" => self.response_received(&session, &params),
            "Network.loadingFinished" => self.loading_finished(&session, &params),
            "Network.loadingFailed" => self.loading_failed(&session, &params),
            "Network.webSocketCreated" => self.socket_created(&params),
            "Network.webSocketClosed" => self.socket_closed(&params),
            "Network.webSocketFrameSent" => self.socket_frame("websocket-frame-sent", &params),
            "Network.webSocketFrameReceived" => self.socket_frame("websocket-frame-received", &params),
            _ => {}
        }
    }

    fn attached(&mut self, parent: &str, params: &Value) {
        let session = params.get("sessionId").and_then(Value::as_str).unwrap_or_default().to_owned();
        let info = params.get("targetInfo").cloned().unwrap_or(Value::Null);
        let target_type = info.get("type").and_then(Value::as_str).unwrap_or_default();
        let target_id = info.get("targetId").and_then(Value::as_str).unwrap_or_default().to_owned();
        let url = info.get("url").and_then(Value::as_str).unwrap_or_default().to_owned();
        let waiting = params.get("waitingForDebugger").and_then(Value::as_bool).unwrap_or(false);
        let parent = (!parent.is_empty()).then(|| parent.to_owned());
        let kind = match target_type {
            "page" if parent.is_none() => SessionKind::Page,
            "iframe" => SessionKind::Frame,
            "worker" => SessionKind::Worker,
            _ => SessionKind::Other,
        };
        if target_type == "service_worker" {
            self.service_worker_targets.insert(target_id.clone());
        }
        if kind == SessionKind::Page {
            if self.main_session.is_none() {
                self.main_session = Some(session.clone());
                self.main_target = Some(target_id.clone());
            } else {
                self.popup(&session, &url);
            }
        }
        if kind == SessionKind::Worker && parent.as_deref().is_some_and(|parent| self.observed(parent)) {
            self.worker_created(&url);
        }
        self.sessions.insert(session.clone(), SessionInfo { kind: kind.clone(), target_id, url, parent });
        self.pending.push(PendingAttach { session, kind, waiting });
    }

    fn detached(&mut self, params: &Value) {
        let session = params.get("sessionId").and_then(Value::as_str).unwrap_or_default().to_owned();
        let Some(info) = self.sessions.remove(&session) else { return };
        if Some(&session) == self.main_session.as_ref() {
            self.page_closed = true;
        }
        match info.kind {
            SessionKind::Worker if info.parent.as_deref().is_some_and(|parent| self.observed(parent)) => {
                if self.recorder.families.has("workers") {
                    let url = self.secrets.sanitize_url(&info.url);
                    self.recorder.push("worker-closed", vec![("kind", json!("worker-closed")), ("url", url), ("name", Value::Null)]);
                }
            }
            SessionKind::Page if self.popups.contains(&session) => {
                if self.recorder.families.has("popups") && self.recorder.admit_text(&self.secrets, "popup-closed", &[&info.url], false).retained() {
                    let url = self.safe_url(&info.url);
                    self.recorder.push("popup-closed", vec![("kind", json!("popup-closed")), ("url", url), ("name", Value::Null)]);
                }
            }
            _ => {}
        }
    }

    fn popup(&mut self, session: &str, url: &str) {
        if !self.recorder.listening {
            return;
        }
        if self.recorder.families.enabled.is_empty() {
            self.popups.insert(session.to_owned());
            return;
        }
        if !self.recorder.admit_owner("popup-opened") || !self.recorder.admit_text(&self.secrets, "popup-opened", &[url], false).retained() {
            return;
        }
        self.popups.insert(session.to_owned());
        for family in ["frames", "workers", "websockets", "downloads"] {
            if self.recorder.families.has(family) {
                self.recorder.incomplete_families.insert(family.to_owned());
            }
        }
        if self.recorder.families.has("popups") {
            let url = self.safe_url(url);
            self.recorder.push("popup-opened", vec![("kind", json!("popup-opened")), ("url", url), ("name", Value::Null)]);
        }
    }

    fn worker_created(&mut self, url: &str) {
        if !self.recorder.listening {
            return;
        }
        if !self.recorder.families.has("workers") {
            return;
        }
        if !self.recorder.admit_owner("worker-created") || !self.recorder.admit_text(&self.secrets, "worker-created", &[url], false).retained() {
            return;
        }
        let url = self.secrets.sanitize_url(url);
        self.recorder.push("worker-created", vec![("kind", json!("worker-created")), ("url", url), ("name", Value::Null)]);
    }

    /// `_removeFramesRecursively`: children detach before their parent.
    fn remove_frame(&mut self, frame: &str) {
        if !self.frames.contains_key(frame) {
            return;
        }
        let children: Vec<String> = self
            .frames
            .iter()
            .filter(|(_, info)| info.parent.as_deref() == Some(frame))
            .map(|(id, _)| id.clone())
            .collect();
        for child in children {
            self.remove_frame(&child);
        }
        self.frame_event("frame-detached", frame);
        self.frames.remove(frame);
    }

    fn frame_navigated(&mut self, session: &str, frame: &Value, record: bool) {
        let id = frame.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
        let parent = frame.get("parentId").and_then(Value::as_str).map(str::to_owned);
        let url = format!(
            "{}{}",
            frame.get("url").and_then(Value::as_str).unwrap_or_default(),
            frame.get("urlFragment").and_then(Value::as_str).unwrap_or_default()
        );
        let name = frame.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
        if parent.is_none() && Some(session) == self.main_session.as_deref() {
            self.main_frame = Some(id.clone());
            if record {
                self.commits += 1;
                self.loader = frame.get("loaderId").and_then(Value::as_str).map(str::to_owned);
            }
        }
        let entry = self.frames.entry(id.clone()).or_insert_with(|| FrameInfo { session: session.to_owned(), parent: parent.clone(), ..FrameInfo::default() });
        entry.url = url;
        entry.name = name;
        entry.session = session.to_owned();
        if record {
            self.frame_event("frame-navigated", &id);
        }
    }

    fn console_api(&mut self, session: &str, params: &Value) {
        if !self.recorder.families.has("console") {
            return;
        }
        let context = params.get("executionContextId").and_then(Value::as_i64).unwrap_or_default();
        // Playwright knows only main-world and its utility-world contexts.
        let known = self.contexts.get(&(session.to_owned(), context)).is_some_and(|info| info.main || info.utility);
        if context == 0 || !known {
            return;
        }
        let level = params.get("type").and_then(Value::as_str).unwrap_or("log").to_owned();
        let text = params
            .get("args")
            .and_then(Value::as_array)
            .map(|args| args.iter().map(render_preview).collect::<Vec<_>>().join(" "))
            .unwrap_or_default();
        let url = params
            .pointer("/stackTrace/callFrames/0/url")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        self.console(&level, &text, &url);
    }

    fn console(&mut self, level: &str, text: &str, url: &str) {
        if !self.recorder.listening {
            return;
        }
        if !self.recorder.admit_text(&self.secrets, "console", &[text, url, level], false).retained() {
            return;
        }
        let fields = vec![
            ("kind", json!("console")),
            ("level", json!(self.secrets.redact(level))),
            ("text", json!(self.secrets.redact(text))),
            ("url", self.safe_url(url)),
        ];
        self.recorder.push("console", fields);
    }

    fn log_entry(&mut self, params: &Value) {
        if !self.recorder.families.has("console") {
            return;
        }
        let entry = params.get("entry").cloned().unwrap_or(Value::Null);
        if entry.get("source").and_then(Value::as_str) == Some("worker") {
            return;
        }
        let level = entry.get("level").and_then(Value::as_str).unwrap_or("info").to_owned();
        let text = entry.get("text").and_then(Value::as_str).unwrap_or_default().to_owned();
        let url = entry.get("url").and_then(Value::as_str).unwrap_or_default().to_owned();
        self.console(&level, &text, &url);
    }

    fn exception(&mut self, params: &Value) {
        if !self.recorder.listening {
            return;
        }
        if !self.recorder.families.has("page-errors") {
            return;
        }
        let details = params.get("exceptionDetails").cloned().unwrap_or(Value::Null);
        let (message, stack) = exception_to_error(&details);
        if !self.recorder.admit_text(&self.secrets, "page-error", &[&message, &stack], false).retained() {
            return;
        }
        let fields = vec![
            ("kind", json!("page-error")),
            ("message", json!(self.secrets.redact(&message))),
            ("stack", json!(self.secrets.redact(&stack))),
        ];
        self.recorder.push("page-error", fields);
    }

    fn download(&mut self, params: &Value) {
        if !self.recorder.listening {
            return;
        }
        if !self.recorder.families.has("downloads") {
            return;
        }
        let name = params.get("suggestedFilename").and_then(Value::as_str).unwrap_or_default().to_owned();
        let url = params.get("url").and_then(Value::as_str).unwrap_or_default().to_owned();
        if self.recorder.admit_text(&self.secrets, "download-cancelled", &[&name, &url], false).retained() {
            let fields = vec![
                ("kind", json!("download-cancelled")),
                ("suggested_filename", json!(self.secrets.redact(&name))),
                ("url", self.secrets.sanitize_url(&url)),
            ];
            self.recorder.push("download-cancelled", fields);
        }
    }

    fn request_for(&self, session: &str, params: &Value) -> Option<usize> {
        let id = params.get("requestId").and_then(Value::as_str)?;
        self.request_index.get(&(session.to_owned(), id.to_owned())).copied()
    }

    /// `_patchHeaders`: raw headers apply once the hop has a response.
    fn patch_headers(&mut self, session: &str, params: &Value) {
        let id = params.get("requestId").and_then(Value::as_str).unwrap_or_default().to_owned();
        let key = (session.to_owned(), id);
        let hops = self.hops.get(&key).cloned().unwrap_or_default();
        for (hop, index) in hops.into_iter().enumerate() {
            if self.requests[index].response.is_none() {
                continue;
            }
            if self.requests[index].raw_headers.is_none()
                && let Some(headers) = self.request_extra.get(&key).and_then(|queue| queue.get(hop)).cloned()
            {
                self.requests[index].raw_headers = Some(headers);
            }
            if let Some(headers) = self.response_extra.get(&key).and_then(|queue| queue.get(hop)).cloned()
                && let Some(response) = self.requests[index].response.as_mut()
                && response.raw_headers.is_none()
            {
                response.raw_headers = Some(headers);
            }
        }
    }

    fn with_network(&mut self, phase: &str, index: usize) {
        if self.favicons.contains(&index) {
            return;
        }
        let Some(network) = self.network.as_mut() else { return };
        let (recorder, secrets, requests) = (&mut self.recorder, &self.secrets, &self.requests);
        match phase {
            "request" => network.request(recorder, secrets, requests, index),
            "response" => network.response(recorder, secrets, requests, index),
            "finished" => network.finished(recorder, secrets, requests, index),
            _ => network.failed(recorder, secrets, requests, index),
        }
    }

    fn request_will_be_sent(&mut self, session: &str, params: &Value) {
        if !self.recorder.listening {
            return;
        }
        let request = params.get("request").cloned().unwrap_or(Value::Null);
        let url = request.get("url").and_then(Value::as_str).unwrap_or_default().to_owned();
        if url.starts_with("data:") {
            return;
        }
        let request_id = params.get("requestId").and_then(Value::as_str).unwrap_or_default().to_owned();
        let key = (session.to_owned(), request_id.clone());
        let mut redirected_from = None;
        if let Some(redirect) = params.get("redirectResponse")
            && let Some(previous) = self.request_index.get(&key).copied()
        {
            self.requests[previous].response = Some(response_record(redirect, false));
            self.patch_headers(session, params);
            self.with_network("response", previous);
            self.with_network("finished", previous);
            redirected_from = Some(previous);
        }
        // Requests without a known frame belong to no observed page.
        let frame = params.get("frameId").and_then(Value::as_str);
        let session_kind = self.sessions.get(session).map(|info| info.kind.clone());
        if frame.is_none_or(|frame| !self.frames.contains_key(frame)) && session_kind != Some(SessionKind::Worker) {
            let known_target = frame.is_some_and(|frame| self.sessions.get(session).is_some_and(|info| info.target_id == frame));
            if !known_target {
                return;
            }
        }
        let post_data = request
            .get("postDataEntries")
            .and_then(Value::as_array)
            .map(|entries| {
                use base64::Engine;
                entries
                    .iter()
                    .filter_map(|entry| entry.get("bytes").and_then(Value::as_str))
                    .flat_map(|bytes| base64::engine::general_purpose::STANDARD.decode(bytes).unwrap_or_default())
                    .collect::<Vec<u8>>()
            })
            .or_else(|| request.get("postData").and_then(Value::as_str).map(|text| text.as_bytes().to_vec()));
        let resource_type = params
            .get("type")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .unwrap_or_else(|| "other".to_owned());
        let index = self.requests.len();
        let favicon = url.ends_with("/favicon.ico") || redirected_from.is_some_and(|previous| self.favicons.contains(&previous));
        self.requests.push(RequestRecord {
            session: session.to_owned(),
            request_id,
            method: request.get("method").and_then(Value::as_str).unwrap_or("GET").to_owned(),
            url,
            resource_type,
            headers: headers_from_object(request.get("headers"), false),
            raw_headers: None,
            post_data,
            redirected_from,
            failure: None,
            response: None,
        });
        if favicon {
            self.favicons.insert(index);
        }
        self.hops.entry(key.clone()).or_default().push(index);
        self.request_index.insert(key, index);
        self.with_network("request", index);
    }

    fn response_received(&mut self, session: &str, params: &Value) {
        let Some(index) = self.request_for(session, params) else { return };
        let response = params.get("response").cloned().unwrap_or(Value::Null);
        self.requests[index].response = Some(response_record(&response, true));
        self.patch_headers(session, params);
        self.with_network("response", index);
    }

    fn loading_finished(&mut self, session: &str, params: &Value) {
        let Some(index) = self.request_for(session, params) else { return };
        self.request_index.remove(&(session.to_owned(), self.requests[index].request_id.clone()));
        self.with_network("finished", index);
    }

    fn loading_failed(&mut self, session: &str, params: &Value) {
        let Some(index) = self.request_for(session, params) else { return };
        let text = params
            .get("errorText")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .or_else(|| params.get("blockedReason").and_then(Value::as_str))
            .unwrap_or_default()
            .to_owned();
        let request_id = self.requests[index].request_id.clone();
        if self.loader.as_deref() == Some(request_id.as_str()) || self.requests[index].resource_type == "document" {
            self.navigation_failure = Some((request_id.clone(), text.clone()));
        }
        self.requests[index].failure = Some(text);
        self.request_index.remove(&(session.to_owned(), request_id));
        self.with_network("failed", index);
    }

    fn socket_created(&mut self, params: &Value) {
        if !self.recorder.listening {
            return;
        }
        let id = params.get("requestId").and_then(Value::as_str).unwrap_or_default().to_owned();
        let url = params.get("url").and_then(Value::as_str).unwrap_or_default().to_owned();
        if !self.recorder.families.has("websockets") {
            return;
        }
        if !self.recorder.admit_owner("websocket-opened") || !self.recorder.admit_text(&self.secrets, "websocket-opened", &[&url], false).retained() {
            return;
        }
        let safe = self.secrets.sanitize_url(&url);
        self.recorder.push("websocket-opened", vec![("kind", json!("websocket-opened")), ("url", safe)]);
        self.sockets.insert(id, url);
    }

    fn socket_closed(&mut self, params: &Value) {
        let id = params.get("requestId").and_then(Value::as_str).unwrap_or_default();
        if let Some(url) = self.sockets.remove(id) {
            let safe = self.secrets.sanitize_url(&url);
            self.recorder.push("websocket-closed", vec![("kind", json!("websocket-closed")), ("url", safe)]);
        }
    }

    fn socket_frame(&mut self, kind: &str, params: &Value) {
        let id = params.get("requestId").and_then(Value::as_str).unwrap_or_default();
        let Some(url) = self.sockets.get(id).cloned() else { return };
        let safe = self.secrets.sanitize_url(&url);
        let opcode = params.pointer("/response/opcode").and_then(Value::as_u64).unwrap_or(1);
        let payload = params.pointer("/response/payloadData").and_then(Value::as_str).unwrap_or_default().to_owned();
        if opcode == 2 {
            use base64::Engine;
            let bytes = base64::engine::general_purpose::STANDARD.decode(&payload).map(|bytes| bytes.len()).unwrap_or_default();
            let fields = vec![
                ("kind", json!(kind)),
                ("url", safe),
                ("payload_bytes", json!(bytes)),
                ("truncated", json!(false)),
                ("payload_type", json!("binary")),
                ("payload_text", Value::Null),
            ];
            self.recorder.push(kind, fields);
            return;
        }
        if !self.recorder.admit_text(&self.secrets, kind, &[&payload], false).retained() {
            return;
        }
        let fields = vec![
            ("kind", json!(kind)),
            ("url", safe),
            ("payload_bytes", json!(payload.len())),
            ("truncated", json!(false)),
            ("payload_type", json!("text")),
            ("payload_text", json!(self.secrets.redact(&payload))),
        ];
        self.recorder.push(kind, fields);
    }
}

/// A new page target attached while a command is in flight is enabled at
/// once: Chromium holds an opener's `window.open` (and so its input ack)
/// until the popup's Page and Runtime domains are enabled. Full
/// initialization follows when the in-flight command returns. Before the
/// resume, network capture is enabled (Playwright's context-wide request
/// events include the popup's initial navigation) and a launched browser's
/// `Accept-Language` is applied, so that first request carries the context
/// headers as in Playwright.
fn popup_unblock(event: &Value, main: Option<&str>, network: bool, accept_language: Option<&str>) -> Vec<DetachedCommand> {
    if event.get("method").and_then(Value::as_str) != Some("Target.attachedToTarget") {
        return Vec::new();
    }
    let Some(params) = event.get("params") else { return Vec::new() };
    let session = params.get("sessionId").and_then(Value::as_str).unwrap_or_default();
    let page = params.pointer("/targetInfo/type").and_then(Value::as_str) == Some("page");
    if !page || main.is_none() || Some(session) == main || event.get("sessionId").is_some() {
        return Vec::new();
    }
    let command = |method: &str, params: Value| DetachedCommand { method: method.to_owned(), params, session_id: Some(session.to_owned()) };
    let mut commands = vec![command("Page.enable", json!({})), command("Runtime.enable", json!({}))];
    if network {
        commands.push(command("Network.enable", json!({})));
    }
    if let Some(locale) = accept_language {
        commands.push(command("Emulation.setUserAgentOverride", json!({ "userAgent": "", "acceptLanguage": locale })));
    }
    commands.push(command("Runtime.runIfWaitingForDebugger", json!({})));
    commands
}

fn response_record(response: &Value, readable: bool) -> ResponseRecord {
    ResponseRecord {
        url: response.get("url").and_then(Value::as_str).unwrap_or_default().to_owned(),
        status: response.get("status").and_then(Value::as_u64).unwrap_or_default(),
        headers: headers_from_object(response.get("headers"), false),
        raw_headers: None,
        readable,
    }
}

/// JavaScript `String(number)` for CDP numeric values.
fn js_number(value: &serde_json::Number) -> String {
    if let Some(integer) = value.as_i64() {
        return integer.to_string();
    }
    if let Some(integer) = value.as_u64() {
        return integer.to_string();
    }
    let float = value.as_f64().unwrap_or_default();
    if float.fract() == 0.0 && float.abs() < 1e21 {
        return format!("{float:.0}");
    }
    let text = format!("{float}");
    text
}

fn js_string(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Number(number) => js_number(number),
        Value::Bool(flag) => flag.to_string(),
        Value::Null => "null".to_owned(),
        other => other.to_string(),
    }
}

/// `renderPreview` of one console argument.
fn render_preview(object: &Value) -> String {
    if object.get("type").and_then(Value::as_str) == Some("undefined") {
        return "undefined".to_owned();
    }
    if let Some(value) = object.get("value") {
        return js_string(value);
    }
    if let Some(value) = object.get("unserializableValue").and_then(Value::as_str) {
        return value.to_owned();
    }
    let description = object.get("description").and_then(Value::as_str).unwrap_or_default();
    if description == "Object"
        && let Some(properties) = object.pointer("/preview/properties").and_then(Value::as_array)
    {
        let tokens: Vec<String> = properties
            .iter()
            .map(|property| {
                format!(
                    "{}: {}",
                    property.get("name").and_then(Value::as_str).unwrap_or_default(),
                    property.get("value").and_then(Value::as_str).unwrap_or_default()
                )
            })
            .collect();
        return format!("{{{}}}", tokens.join(", "));
    }
    if object.get("subtype").and_then(Value::as_str) == Some("array")
        && let Some(properties) = object.pointer("/preview/properties").and_then(Value::as_array)
    {
        let mut entries: Vec<(i64, String)> = properties
            .iter()
            .filter_map(|property| {
                let index: i64 = property.get("name").and_then(Value::as_str)?.parse().ok()?;
                (index >= 0).then(|| (index, property.get("value").and_then(Value::as_str).unwrap_or_default().to_owned()))
            })
            .collect();
        entries.sort_by_key(|(index, _)| *index);
        let mut last = -1;
        let mut tokens = Vec::new();
        for (index, value) in entries {
            let empty = index - last - 1;
            if empty == 1 {
                tokens.push("empty".to_owned());
            } else if empty > 1 {
                tokens.push(format!("empty x {empty}"));
            }
            tokens.push(value);
            last = index;
        }
        return format!("[{}]", tokens.join(", "));
    }
    description.to_owned()
}

/// `exceptionToError`: (message, stack) as the client-side `Error` exposes.
fn exception_to_error(details: &Value) -> (String, String) {
    let message_with_stack = if let Some(exception) = details.get("exception") {
        exception
            .get("description")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| js_string(exception.get("value").unwrap_or(&Value::Null)))
    } else {
        let mut message = details.get("text").and_then(Value::as_str).unwrap_or_default().to_owned();
        for frame in details.pointer("/stackTrace/callFrames").and_then(Value::as_array).into_iter().flatten() {
            let location = format!(
                "{}:{}:{}",
                frame.get("url").and_then(Value::as_str).unwrap_or_default(),
                frame.get("lineNumber").and_then(Value::as_i64).unwrap_or_default(),
                frame.get("columnNumber").and_then(Value::as_i64).unwrap_or_default()
            );
            let function = frame.get("functionName").and_then(Value::as_str).filter(|name| !name.is_empty()).unwrap_or("<anonymous>");
            message.push_str(&format!("\n    at {function} ({location})"));
        }
        message
    };
    let lines: Vec<&str> = message_with_stack.split('\n').collect();
    let first = lines.iter().position(|line| line.starts_with("    at"));
    let (with_name, stack) = match first {
        None => (message_with_stack.clone(), String::new()),
        Some(index) => (lines[..index].join("\n"), message_with_stack.clone()),
    };
    let message = match with_name.find(':') {
        Some(index) if index + 2 <= with_name.len() => with_name[index + 2..].to_owned(),
        _ => with_name,
    };
    (message, stack)
}

/// The owned connection plus its observed world.
pub(crate) struct Driver {
    transport: Option<CdpWebSocketTransport>,
    servicing: bool,
    /// Events received but not yet dispatched because a wait was satisfied
    /// by an earlier event in the same batch.
    backlog: std::collections::VecDeque<Value>,
    /// Popup sessions already resumed by `popup_unblock`.
    unblocked: BTreeSet<String>,
    /// While an action runs, unblocked popups are initialized only after it
    /// returns: Playwright initializes a popup concurrently, so the action
    /// does not wait for (and its step does not absorb) the popup's load.
    pub hold_popups: bool,
    held: Vec<PendingAttach>,
    holds_objects: bool,
    pub world: World,
    pub product: String,
    pub version: String,
    pub user_agent: String,
}

impl Driver {
    pub(crate) fn new(transport: CdpWebSocketTransport, world: World) -> Self {
        Self {
            transport: Some(transport),
            servicing: false,
            backlog: std::collections::VecDeque::new(),
            unblocked: BTreeSet::new(),
            hold_popups: false,
            held: Vec::new(),
            holds_objects: false,
            world,
            product: String::new(),
            version: String::new(),
            user_agent: String::new(),
        }
    }

    pub(crate) fn connected(&self) -> bool {
        self.transport.is_some() && self.world.transport_lost.is_none()
    }

    /// Send one command, then route the events it buffered.
    pub(crate) fn call(&mut self, session: Option<&str>, method: &str, params: Value, scope: &Scope) -> Result<Value, CallError> {
        if let Some(interruption) = scope.interrupted() {
            return Err(interruption);
        }
        if let Some(reason) = &self.world.transport_lost {
            return Err(CallError::Closed(reason.clone()));
        }
        // Earlier round-trip reads complete before this command's own events.
        self.service_content(scope);
        let Some(transport) = self.transport.as_mut() else {
            return Err(CallError::Closed("Browser connection is closed".to_owned()));
        };
        if std::env::var_os("REA_SCENARIO_TRACE").is_some() {
            eprintln!("[scenario] -> {method} {}", session.unwrap_or("-"));
        }
        let main = self.world.main_session.clone();
        let network = self.world.network.is_some();
        let accept_language = self.world.launch.as_ref().map(|environment| environment.locale.clone());
        let mut unblocked = Vec::new();
        let mut hook = |event: &Value| {
            let commands = popup_unblock(event, main.as_deref(), network, accept_language.as_deref());
            if let Some(command) = commands.first() {
                unblocked.extend(command.session_id.clone());
            }
            commands
        };
        let result = transport.request_with_event_hook(method, params, session, scope.token(), &mut hook);
        self.unblocked.extend(unblocked);
        let result = result.map_err(|error| {
            let classified = scope.classify(error);
            if let CallError::Closed(reason) = &classified {
                self.world.transport_lost = Some(reason.clone());
            }
            classified
        });
        self.pump(scope);
        result
    }

    pub(crate) fn main_call(&mut self, method: &str, params: Value, scope: &Scope) -> Result<Value, CallError> {
        let session = self.world.main_session.clone();
        self.call(session.as_deref(), method, params, scope)
    }

    /// Drain buffered events, then service queued initialization and reads.
    ///
    /// Read timing follows Playwright's event loop: request content and
    /// precomputed states are emitted right after their triggering event
    /// (before the next protocol message). A response body read is a browser
    /// round trip whose reply, in Playwright, lands after events already in
    /// flight and after the waiting caller has resumed. Those reads therefore
    /// run only when the caller issues its next command (`call`) or a poll
    /// slice is quiet (`poll`), never inside the pump that a wait checks, so a
    /// wait this pump satisfies (and the step change after it) precedes the
    /// body. Returns the number of dispatched events.
    pub(crate) fn pump(&mut self, scope: &Scope) -> usize {
        self.pump_until(scope, &mut |_| false).0
    }

    /// `pump`, stopping right after the event that satisfies `ready`, as a
    /// Playwright waiter resumes before later protocol messages are handled.
    /// Undispatched events stay in `backlog`, ahead of newer transport events.
    fn pump_until(&mut self, scope: &Scope, ready: &mut dyn FnMut(&World) -> bool) -> (usize, bool) {
        let mut dispatched = 0;
        let mut satisfied = false;
        loop {
            let mut items = std::mem::take(&mut self.backlog);
            match self.transport.as_mut() {
                Some(transport) => items.extend(transport.drain_events().items.into_iter().map(|event| event.value)),
                None if items.is_empty() => return (dispatched, false),
                None => {}
            }
            let empty = items.is_empty();
            while let Some(event) = items.pop_front() {
                dispatched += 1;
                self.world.dispatch(&event);
                self.service_reads(scope, true);
                if ready(&self.world) {
                    satisfied = true;
                    self.backlog = items;
                    break;
                }
            }
            let mut pending = std::mem::take(&mut self.world.pending);
            if !self.hold_popups && !self.held.is_empty() {
                pending.splice(0..0, std::mem::take(&mut self.held));
            }
            if self.hold_popups {
                let (held, now): (Vec<_>, Vec<_>) = pending
                    .into_iter()
                    .partition(|attach| attach.kind == SessionKind::Page && self.unblocked.contains(&attach.session));
                self.held.extend(held);
                pending = now;
            }
            if pending.is_empty() && empty {
                break;
            }
            for attach in pending {
                self.initialize_session(&attach, scope);
            }
            if empty || satisfied {
                break;
            }
        }
        self.refresh_seeds(scope);
        self.service_reads(scope, true);
        (dispatched, satisfied)
    }

    /// Run every queued network content read (`collect`), bounded at 5 s each.
    pub(crate) fn service_content(&mut self, scope: &Scope) {
        self.service_reads(scope, false);
    }

    fn service_reads(&mut self, scope: &Scope, local_only: bool) {
        if self.servicing {
            return;
        }
        self.servicing = true;
        loop {
            let World { network, requests, .. } = &mut self.world;
            let Some(job) = network.as_mut().and_then(|network| network.next_job(requests, local_only)) else { break };
            let read_scope = scope.child(Some(5_000));
            let request = self.world.requests[job.request].clone();
            let selection = self.world.network.as_ref().map(|network| network.selection.clone()).unwrap_or_default();
            let (headers_source, content_type) = if job.phase == "request" {
                let headers = request.raw_headers.clone().unwrap_or_else(|| request.headers.clone());
                let content_type = super::network::header_lookup(&request.headers, "content-type").map(str::to_owned);
                (headers, content_type)
            } else {
                let response = request.response.clone().unwrap_or_default();
                let headers = response.raw_headers.clone().unwrap_or_else(|| response.headers.clone());
                let content_type = super::network::header_lookup(&response.headers, "content-type").map(str::to_owned);
                (headers, content_type)
            };
            let headers = if selection.header_values {
                self.world.network.as_ref().map(|network| network.headers_value(&self.world.secrets, &headers_source)).unwrap_or(Value::Null)
            } else {
                json!({ "state": "not_requested" })
            };
            let observed = if let Some(body) = job.body.clone() {
                Ok(body)
            } else if job.phase == "request" {
                Err(Ok(request.post_data.clone()))
            } else if !request.response.as_ref().is_some_and(|response| response.readable) {
                Err(Err("Response body is unavailable for redirect responses".to_owned()))
            } else {
                match self.call(Some(&request.session), "Network.getResponseBody", json!({ "requestId": request.request_id }), &read_scope) {
                    Ok(result) => {
                        use base64::Engine;
                        let body = result.get("body").and_then(Value::as_str).unwrap_or_default();
                        let bytes = if result.get("base64Encoded").and_then(Value::as_bool).unwrap_or(false) {
                            base64::engine::general_purpose::STANDARD.decode(body).unwrap_or_default()
                        } else {
                            body.as_bytes().to_vec()
                        };
                        Err(Ok(Some(bytes)))
                    }
                    Err(CallError::Deadline) => Ok(json!({
                        "state": "unavailable",
                        "reason": "body-read-timeout",
                        "message": "Analysis operation timed out after 5000ms: capture_browser_scenario",
                    })),
                    Err(CallError::Cancelled) => Ok(json!({
                        "state": "unavailable",
                        "reason": "cancelled",
                        "message": "Analysis operation was cancelled: capture_browser_scenario",
                    })),
                    Err(error) => Err(Err(error.message())),
                }
            };
            let World { network, recorder, secrets, .. } = &mut self.world;
            let Some(network) = network.as_mut() else { break };
            let body = match observed {
                Ok(body) => Ok(body),
                Err(read) => network.body_value(recorder, secrets, &job, &headers, read, content_type.as_deref()),
            };
            network.emit_content(recorder, &job, headers, body);
        }
        self.servicing = false;
    }

    /// Wait for unsolicited events for at most `slice`.
    fn poll(&mut self, slice: Duration, scope: &Scope) -> Result<(), CallError> {
        if let Some(interruption) = scope.interrupted() {
            return Err(interruption);
        }
        let Some(transport) = self.transport.as_mut() else {
            return Err(CallError::Closed("Browser connection is closed".to_owned()));
        };
        if let Err(error) = transport.poll_events(slice, scope.token()) {
            let classified = scope.classify(error);
            if let CallError::Closed(reason) = &classified {
                self.world.transport_lost = Some(reason.clone());
            }
            return Err(classified);
        }
        Ok(())
    }

    /// Process events until `ready` holds for the world. Readiness is checked
    /// after every event, so later events in the same batch are attributed to
    /// what the caller does next, as with a resolved Playwright waiter.
    pub(crate) fn wait_until(&mut self, scope: &Scope, mut ready: impl FnMut(&World) -> bool) -> Result<(), CallError> {
        let mut polled = false;
        loop {
            let (dispatched, satisfied) = self.pump_until(scope, &mut ready);
            if satisfied || ready(&self.world) {
                return Ok(());
            }
            if let Some(reason) = &self.world.transport_lost {
                return Err(CallError::Closed(reason.clone()));
            }
            if polled && dispatched == 0 {
                self.service_content(scope);
            }
            self.poll(POLL_SLICE, scope)?;
            polled = true;
        }
    }

    /// `page.waitForTimeout`: keep observing while the time passes.
    pub(crate) fn sleep(&mut self, duration: Duration, scope: &Scope) -> Result<(), CallError> {
        let until = Instant::now() + duration;
        loop {
            let Some(remaining) = until.checked_duration_since(Instant::now()) else { return Ok(()) };
            if remaining.is_zero() {
                return Ok(());
            }
            self.poll(remaining.min(POLL_SLICE), scope)?;
            if self.pump(scope) == 0 {
                self.service_content(scope);
            }
        }
    }

    /// Enable observation domains on one attached target and resume it.
    fn initialize_session(&mut self, attach: &PendingAttach, scope: &Scope) {
        let session = attach.session.clone();
        let observing = self.world.page_session_of(&session).is_some();
        let s = Some(session.as_str());
        if observing && matches!(attach.kind, SessionKind::Page | SessionKind::Frame) {
            let _ = self.call(s, "Page.enable", json!({}), scope);
            if let Ok(tree) = self.call(s, "Page.getFrameTree", json!({}), scope) {
                self.seed_frames(&session, tree.get("frameTree").unwrap_or(&Value::Null), attach.kind == SessionKind::Page);
            }
            if self.world.recorder.families.has("console") || attach.kind == SessionKind::Page {
                let _ = self.call(s, "Log.enable", json!({}), scope);
            }
            let _ = self.call(s, "Page.setLifecycleEventsEnabled", json!({ "enabled": true }), scope);
            let _ = self.call(s, "Runtime.enable", json!({}), scope);
            let _ = self.call(s, "Page.addScriptToEvaluateOnNewDocument", json!({ "source": "", "worldName": UTILITY_WORLD }), scope);
            let _ = self.call(s, "Network.enable", json!({}), scope);
            // Child frames and workers are held until initialized; popups
            // are excluded because `window.open` blocks the opener until the
            // new page runs (they attach unheld at browser level instead).
            let _ = self.call(
                s,
                "Target.setAutoAttach",
                json!({
                    "autoAttach": true,
                    "waitForDebuggerOnStart": true,
                    "flatten": true,
                    "filter": [{ "type": "page", "exclude": true }, { "type": "tab", "exclude": true }, {}],
                }),
                scope,
            );
            if attach.kind == SessionKind::Page {
                if let Some(environment) = self.world.launch.clone() {
                    self.emulate(&session, &environment, scope);
                }
                self.install_init_scripts(&session, scope);
                self.install_seed_script(&session, scope);
            }
            let frames: Vec<String> = self
                .world
                .frames
                .iter()
                .filter(|(_, info)| info.session == session)
                .map(|(id, _)| id.clone())
                .collect();
            for frame in frames {
                let _ = self.call(s, "Page.createIsolatedWorld", json!({ "frameId": frame, "grantUniveralAccess": true, "worldName": UTILITY_WORLD }), scope);
            }
        } else if observing && attach.kind == SessionKind::Worker {
            let _ = self.call(s, "Network.enable", json!({}), scope);
        }
        if attach.waiting {
            let _ = self.call(s, "Runtime.runIfWaitingForDebugger", json!({}), scope);
        }
        if !observing && attach.kind != SessionKind::Page {
            let _ = self.call(None, "Target.detachFromTarget", json!({ "sessionId": session }), scope);
        }
    }

    fn install_seed_script(&mut self, session: &str, scope: &Scope) {
        let Some(source) = self.world.seeds.script() else { return };
        let added = self.call(
            Some(session),
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": source, "worldName": UTILITY_WORLD }),
            scope,
        );
        if let Ok(added) = added
            && let Some(identifier) = added.get("identifier").and_then(Value::as_str)
        {
            self.world.seeds.script_ids.push((session.to_owned(), identifier.to_owned()));
        }
    }

    /// Replace the seed script after an origin seeded its first document.
    fn refresh_seeds(&mut self, scope: &Scope) {
        if !std::mem::take(&mut self.world.seeds.dirty) {
            return;
        }
        let previous = std::mem::take(&mut self.world.seeds.script_ids);
        let mut sessions: Vec<String> = Vec::new();
        for (session, identifier) in previous {
            let _ = self.call(Some(&session), "Page.removeScriptToEvaluateOnNewDocument", json!({ "identifier": identifier }), scope);
            if !sessions.contains(&session) {
                sessions.push(session);
            }
        }
        for session in sessions {
            self.install_seed_script(&session, scope);
        }
    }

    /// Remove REA's seed scripts from a target REA does not own.
    pub(crate) fn remove_seed_scripts(&mut self, scope: &Scope) {
        self.world.seeds.local.clear();
        self.world.seeds.session.clear();
        self.world.seeds.dirty = true;
        self.refresh_seeds(scope);
    }

    /// Add the scenario's init scripts to one page session.
    pub(crate) fn install_init_scripts(&mut self, session: &str, scope: &Scope) {
        for source in self.world.init_scripts.clone() {
            let added = self.call(
                Some(session),
                "Page.addScriptToEvaluateOnNewDocument",
                json!({ "source": source, "runImmediately": true }),
                scope,
            );
            if let Ok(added) = added
                && let Some(identifier) = added.get("identifier").and_then(Value::as_str)
            {
                self.world.init_script_ids.push(identifier.to_owned());
            }
        }
    }

    fn seed_frames(&mut self, session: &str, tree: &Value, page: bool) {
        if let Some(frame) = tree.get("frame") {
            let id = frame.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
            let parent = frame.get("parentId").and_then(Value::as_str).map(str::to_owned);
            if !self.world.frames.contains_key(&id) {
                self.world.frames.insert(id.clone(), FrameInfo { session: session.to_owned(), parent, ..FrameInfo::default() });
            }
            let is_main = page && frame.get("parentId").is_none() && Some(session) == self.world.main_session.as_deref();
            self.world.frame_navigated(session, frame, false);
            if is_main {
                self.world.loader = frame.get("loaderId").and_then(Value::as_str).map(str::to_owned);
            }
        }
        for child in tree.get("childFrames").and_then(Value::as_array).into_iter().flatten() {
            self.seed_frames(session, child, false);
        }
    }

    /// Playwright's launch-time context options for one page.
    fn emulate(&mut self, session: &str, environment: &Environment, scope: &Scope) {
        let s = Some(session);
        let _ = self.call(s, "Emulation.setFocusEmulationEnabled", json!({ "enabled": true }), scope);
        if let Ok(window) = self.call(s, "Browser.getWindowForTarget", json!({}), scope)
            && let Some(id) = window.get("windowId").cloned()
        {
            let _ = self.call(None, "Browser.setWindowBounds", json!({ "windowId": id, "bounds": { "width": environment.width, "height": environment.height } }), scope);
        }
        let _ = self.call(
            s,
            "Emulation.setDeviceMetricsOverride",
            json!({
                "mobile": false,
                "width": environment.width,
                "height": environment.height,
                "screenWidth": environment.width,
                "screenHeight": environment.height,
                "deviceScaleFactor": environment.device_scale_factor,
                "screenOrientation": { "angle": 0, "type": "landscapePrimary" },
                "dontSetVisibleSize": false,
            }),
            scope,
        );
        let _ = self.call(s, "Emulation.setUserAgentOverride", json!({ "userAgent": "", "acceptLanguage": environment.locale }), scope);
        let _ = self.call(s, "Emulation.setLocaleOverride", json!({ "locale": environment.locale }), scope);
        let _ = self.call(s, "Emulation.setTimezoneOverride", json!({ "timezoneId": environment.timezone }), scope);
        if let Some(families) = self.world.font_families.clone() {
            let _ = self.call(s, "Page.setFontFamilies", families, scope);
        }
        let _ = self.call(
            s,
            "Emulation.setEmulatedMedia",
            json!({
                "media": "",
                "features": [
                    { "name": "prefers-color-scheme", "value": environment.color_scheme },
                    { "name": "prefers-reduced-motion", "value": environment.reduced_motion },
                    { "name": "forced-colors", "value": "" },
                    { "name": "prefers-contrast", "value": "" },
                ],
            }),
            scope,
        );
        let _ = self.call(s, "Page.setInterceptFileChooserDialog", json!({ "enabled": false }), scope);
    }

    /// Platform default font families for headless launch (`_setDefaultFontFamilies`).
    pub(crate) fn select_font_families(&mut self) {
        let table: Value = serde_json::from_str(FONT_FAMILIES).unwrap_or(Value::Null);
        let platform = if self.user_agent.contains("Windows") {
            "win"
        } else if self.user_agent.contains("Macintosh") {
            "mac"
        } else {
            "linux"
        };
        self.world.font_families = table.get(platform).cloned();
    }

    /// The utility-world execution context of the main frame.
    pub(crate) fn utility_context(&mut self, scope: &Scope) -> Result<i64, CallError> {
        let session = self.world.main_session.clone().ok_or_else(|| CallError::Closed("Target page, context or browser has been closed".to_owned()))?;
        let frame = self.world.main_frame.clone().unwrap_or_default();
        let find = |world: &World| {
            world
                .contexts
                .iter()
                .find(|((owner, _), info)| *owner == session && info.frame == frame && info.utility)
                .map(|((_, id), _)| *id)
        };
        if find(&self.world).is_none() {
            let _ = self.call(Some(&session), "Page.createIsolatedWorld", json!({ "frameId": frame, "grantUniveralAccess": true, "worldName": UTILITY_WORLD }), scope);
        }
        let mut found = None;
        self.wait_until(scope, |world| {
            found = find(world);
            found.is_some() || world.page_closed
        })?;
        let id = found.ok_or_else(|| CallError::Closed("Target page, context or browser has been closed".to_owned()))?;
        if !self.world.installed.contains(&(session.clone(), id)) {
            self.call(Some(&session), "Runtime.evaluate", json!({ "expression": PAGE_HELPER, "contextId": id }), scope)?;
            self.world.installed.insert((session, id));
        }
        Ok(id)
    }

    /// Evaluate in REA's utility world of the main frame.
    pub(crate) fn evaluate_utility(&mut self, expression: &str, by_value: bool, await_promise: bool, scope: &Scope) -> Result<Value, CallError> {
        let context = self.utility_context(scope)?;
        self.holds_objects |= !by_value;
        let result = self.main_call(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "contextId": context,
                "returnByValue": by_value,
                "awaitPromise": await_promise,
                "objectGroup": "rea-scenario",
            }),
            scope,
        )?;
        evaluation_result(result)
    }

    /// Evaluate in the page's main world (`page.evaluate`).
    pub(crate) fn evaluate_main(&mut self, expression: &str, scope: &Scope) -> Result<Value, CallError> {
        let session = self.world.main_session.clone().unwrap_or_default();
        let frame = self.world.main_frame.clone().unwrap_or_default();
        let context = self
            .world
            .contexts
            .iter()
            .find(|((owner, _), info)| *owner == session && info.frame == frame && info.main)
            .map(|((_, id), _)| *id);
        let mut params = json!({ "expression": expression, "returnByValue": true, "awaitPromise": true });
        if let Some(context) = context {
            params["contextId"] = json!(context);
        }
        let result = self.main_call("Runtime.evaluate", params, scope)?;
        evaluation_result(result).map(|object| object.get("value").cloned().unwrap_or(Value::Null))
    }

    /// Call a helper function with `this` bound to a remote element.
    pub(crate) fn call_on(&mut self, object_id: &str, function: &str, arguments: Vec<Value>, await_promise: bool, scope: &Scope) -> Result<Value, CallError> {
        let arguments: Vec<Value> = arguments.into_iter().map(|value| json!({ "value": value })).collect();
        let result = self.main_call(
            "Runtime.callFunctionOn",
            json!({
                "objectId": object_id,
                "functionDeclaration": function,
                "arguments": arguments,
                "returnByValue": true,
                "awaitPromise": await_promise,
            }),
            scope,
        )?;
        evaluation_result(result).map(|object| object.get("value").cloned().unwrap_or(Value::Null))
    }

    /// Release remote handles, only when this owner created some: an idle
    /// command would also drain events earlier than the TS owner observes them.
    pub(crate) fn release_objects(&mut self, scope: &Scope) {
        if !std::mem::take(&mut self.holds_objects) {
            return;
        }
        let _ = self.main_call("Runtime.releaseObjectGroup", json!({ "objectGroup": "rea-scenario" }), scope);
    }

    /// Close the transport. The owner decides what else must be released.
    pub(crate) fn disconnect(&mut self) {
        if let Some(mut transport) = self.transport.take() {
            let _ = transport.close_connection();
        }
    }
}

/// A thrown evaluation becomes a protocol-style failure with its message.
fn evaluation_result(result: Value) -> Result<Value, CallError> {
    if let Some(details) = result.get("exceptionDetails") {
        let (message, _) = exception_to_error(details);
        return Err(CallError::Protocol(message));
    }
    Ok(result.get("result").cloned().unwrap_or(Value::Null))
}

impl Drop for Driver {
    fn drop(&mut self) {
        self.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::popup_unblock;
    use serde_json::json;

    fn attached(session: &str, kind: &str) -> serde_json::Value {
        json!({ "method": "Target.attachedToTarget", "params": { "sessionId": session, "targetInfo": { "type": kind } } })
    }

    fn methods(event: &serde_json::Value, network: bool, locale: Option<&str>) -> Vec<String> {
        popup_unblock(event, Some("main"), network, locale).into_iter().map(|command| command.method).collect()
    }

    #[test]
    fn popup_resume_follows_network_and_language_setup() {
        let event = attached("popup", "page");
        assert_eq!(
            methods(&event, true, Some("de-DE")),
            ["Page.enable", "Runtime.enable", "Network.enable", "Emulation.setUserAgentOverride", "Runtime.runIfWaitingForDebugger"]
        );
        assert_eq!(methods(&event, false, None), ["Page.enable", "Runtime.enable", "Runtime.runIfWaitingForDebugger"]);
        let commands = popup_unblock(&event, Some("main"), false, Some("de-DE"));
        assert_eq!(commands[2].params, json!({ "userAgent": "", "acceptLanguage": "de-DE" }));
        assert!(commands.iter().all(|command| command.session_id.as_deref() == Some("popup")));
    }

    #[test]
    fn only_new_browser_level_pages_are_unblocked() {
        assert!(methods(&attached("main", "page"), true, None).is_empty());
        assert!(methods(&attached("worker", "worker"), true, None).is_empty());
        let mut nested = attached("child", "page");
        nested["sessionId"] = json!("parent");
        assert!(methods(&nested, true, None).is_empty());
        assert!(popup_unblock(&attached("popup", "page"), None, true, None).is_empty());
    }
}
