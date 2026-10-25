//! Native `capture_electron_scenario`: one provider-owned Electron run with
//! REA-owned launch, main-process evaluation, renderer actions and cleanup.
//!
//! Compatibility owners: `src/application/javascript/ElectronActiveObservationService.ts`
//! (path canonicalization), `src/domain/javascript/electronActiveObservation.ts`
//! (refinements), `src/browser/PlaywrightElectronActiveProvider.ts`,
//! `PlaywrightElectronActiveActions.ts`, `PlaywrightElectronActiveProjection.ts`,
//! `PlaywrightElectronActiveFuses.ts`, `ElectronCaptureCleanup.ts`,
//! `ElectronActiveEvidence.ts` and `scripts/electron-active-hook*.cjs` (the
//! injected main-process agent, embedded unchanged). Playwright 1.58.2's
//! `_electron.launch` with an explicit `executablePath` is reproduced: no
//! Playwright loader, `--inspect=0 --remote-debugging-port=0` ahead of the
//! caller's arguments, the Node Inspector and DevTools endpoints read from
//! stderr, `require('electron')` resolved in the default main context.
//!
//! Deliberate differences, recorded in `.cache/rust-migration/progress.md`:
//! the launch also passes `--user-data-dir=<REA temp>` so a Chromium-family
//! executable can never hand the request to the user's running browser or
//! profile; the hook is written to that REA-owned temp root; launch failure
//! diagnostics reproduce Playwright's call-log shape from REA's own
//! observations (not Playwright's internal kill log); clicks accept plain
//! CSS (Playwright selector-engine syntax is refused, as in
//! `capture_browser_scenario`). A dedicated Electron 45 runtime has been
//! verified against the owned readiness fixture, including IPC, protocol,
//! renderer failure/restart, utility and child-process observations, plus
//! cancellation cleanup. Packaged runtimes that load a different application
//! root are rejected to prevent false application provenance.
use super::driver::{CallError, PAGE_HELPER, Scope};
use crate::cdp::{self, Refinement};
use crate::comparisons::digest::digest_canonical_value;
use rea_core::analysis_error::cleanup;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_host::cdp_transport::{CdpTransportError, CdpWebSocketTransport};
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::ownership::{self, OwnershipBaseline, OwnershipRelation};
use rea_host::process::windows::job::WindowsJobLimits;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, VecDeque};
use std::ffi::OsString;
use std::io::ErrorKind as IoKind;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

pub(crate) const OPERATION: &str = "capture_electron_scenario";
const PROVIDER_ID: &str = "rea-playwright-electron-active";
const PROVIDER_NAME: &str = "REA Playwright active Electron observation provider";
const PROVIDER_VERSION: &str = "1";
/// `STARTUP_TIMEOUT_MS`.
const STARTUP_TIMEOUT: Duration = Duration::from_millis(60_000);
/// `CANCELLED_STATE_READ_TIMEOUT_MS`.
const CANCELLED_STATE_READ_GRACE: Duration = Duration::from_millis(5_000);
/// `ElectronCaptureCleanup` transport close deadline.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(5_000);
const STDERR_CAPTURE: usize = 1024 * 1024;
const MESSAGE_BYTES: usize = 256 * 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const POLL: Duration = Duration::from_millis(25);
const HOOK: &str = include_str!("../../../../../../scripts/electron-active-hook.cjs");
const HOOK_BOUNDARIES: &str =
    include_str!("../../../../../../scripts/electron-active-hook-boundaries.cjs");
const PATH_MESSAGE: &str = "Electron executable, application, and root paths must be absolute local filesystem paths (for example /Applications/Electron.app/Contents/MacOS/Electron)";

fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| handle(context, &input));
}

fn handle(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let request = match parse(input) {
        Ok(request) => request,
        Err(refinements) => return cdp::refinement_failure(OPERATION, refinements),
    };
    let request = match canonicalize(request) {
        Ok(request) => request,
        Err(issues) => return ToolOutput::Failure(AnalysisError::input(OPERATION, issues)),
    };
    let environment = safe_environment(&|name| context.session.env(name).map(str::to_owned));
    capture(&request, environment, &context.cancellation).into()
}

// ---- Input (`electronActiveObservationInputSchema`) -------------------------

#[derive(Clone, Debug)]
enum ActionKind {
    Click {
        selector: String,
        window_index: u64,
    },
    Wait {
        duration_ms: u64,
        window_index: Option<u64>,
    },
    RendererReload {
        window_index: u64,
    },
    RendererCrash {
        window_index: u64,
    },
    DeepLink {
        delivery: String,
        url: String,
    },
}

#[derive(Clone, Debug)]
struct Action {
    step_id: String,
    kind: ActionKind,
}

impl Action {
    fn kind_name(&self) -> &'static str {
        match self.kind {
            ActionKind::Click { .. } => "click",
            ActionKind::Wait { .. } => "wait",
            ActionKind::RendererReload { .. } => "renderer-reload",
            ActionKind::RendererCrash { .. } => "renderer-crash",
            ActionKind::DeepLink { .. } => "deep-link",
        }
    }

    /// `actionWindowIndex`.
    fn window_index(&self) -> Option<u64> {
        match &self.kind {
            ActionKind::Click { window_index, .. }
            | ActionKind::RendererReload { window_index }
            | ActionKind::RendererCrash { window_index } => Some(*window_index),
            ActionKind::Wait { window_index, .. } => *window_index,
            ActionKind::DeepLink { .. } => None,
        }
    }

    /// The Zod output shape, in schema key order with defaults applied.
    fn canonical(&self) -> Value {
        let mut value = Map::new();
        value.insert("step_id".into(), json!(self.step_id));
        value.insert("kind".into(), json!(self.kind_name()));
        match &self.kind {
            ActionKind::Click {
                selector,
                window_index,
            } => {
                value.insert("selector".into(), json!(selector));
                value.insert("window_index".into(), json!(window_index));
            }
            ActionKind::Wait {
                duration_ms,
                window_index,
            } => {
                value.insert("duration_ms".into(), json!(duration_ms));
                if let Some(index) = window_index {
                    value.insert("window_index".into(), json!(index));
                }
            }
            ActionKind::RendererReload { window_index }
            | ActionKind::RendererCrash { window_index } => {
                value.insert("window_index".into(), json!(window_index));
            }
            ActionKind::DeepLink { delivery, url } => {
                value.insert("delivery".into(), json!(delivery));
                value.insert("url".into(), json!(url));
            }
        }
        Value::Object(value)
    }
}

#[derive(Clone, Debug)]
struct Request {
    executable_path: String,
    application_path: String,
    application_root: Option<String>,
    args: Vec<String>,
    actions: Vec<Action>,
}

/// A request whose paths were resolved (`CanonicalElectronActiveObservationInput`).
#[derive(Clone, Debug)]
struct Canonical {
    executable_path: String,
    application_path: String,
    application_root: String,
    root_selected: bool,
    args: Vec<String>,
    actions: Vec<Action>,
}

impl Canonical {
    /// `{ ...input, executable_path, application_path, application_root }`:
    /// an omitted root is appended after the parsed keys.
    fn parameters(&self) -> Value {
        let mut value = Map::new();
        value.insert("executable_path".into(), json!(self.executable_path));
        value.insert("application_path".into(), json!(self.application_path));
        if self.root_selected {
            value.insert("application_root".into(), json!(self.application_root));
        }
        value.insert("args".into(), json!(self.args));
        value.insert(
            "actions".into(),
            Value::Array(self.actions.iter().map(Action::canonical).collect()),
        );
        if !self.root_selected {
            value.insert("application_root".into(), json!(self.application_root));
        }
        let scenario = Value::Object(value);
        let digest = digest_canonical_value(&scenario);
        let mut parameters = scenario;
        if let Some(map) = parameters.as_object_mut() {
            map.insert("scenario_sha256".into(), json!(digest));
        }
        parameters
    }
}

/// Node's POSIX `path.isAbsolute`.
fn is_absolute(value: &str) -> bool {
    if cfg!(windows) {
        let bytes = value.as_bytes();
        value.starts_with('\\')
            || value.starts_with('/')
            || (bytes.len() > 2 && bytes[1] == b':' && matches!(bytes[2], b'\\' | b'/'))
    } else {
        value.starts_with('/')
    }
}

/// Refinements in schema traversal order; the catalog schema has already
/// enforced types, patterns, bounds and the action union.
fn parse(input: &Value) -> Result<Request, Vec<Refinement>> {
    let mut refinements = Vec::new();
    let text = |key: &str| input.get(key).and_then(Value::as_str).map(str::to_owned);
    let path = |key: &'static str, refinements: &mut Vec<Refinement>| {
        let value = text(key);
        if let Some(value) = &value
            && !is_absolute(value)
        {
            refinements.push(Refinement::new(vec![json!(key)], PATH_MESSAGE));
        }
        value
    };
    let executable_path = path("executable_path", &mut refinements).unwrap_or_default();
    let application_path = path("application_path", &mut refinements).unwrap_or_default();
    let application_root = path("application_root", &mut refinements);
    let args = input
        .get("args")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let mut actions = Vec::new();
    for (index, action) in input
        .get("actions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let field = |key: &str| {
            action
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let window = |key: &str| action.get(key).and_then(Value::as_u64);
        let kind = match action
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or_default()
        {
            "click" => ActionKind::Click {
                selector: field("selector"),
                window_index: window("window_index").unwrap_or(0),
            },
            "wait" => ActionKind::Wait {
                duration_ms: action
                    .get("duration_ms")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                window_index: window("window_index"),
            },
            "renderer-reload" => ActionKind::RendererReload {
                window_index: window("window_index").unwrap_or(0),
            },
            "renderer-crash" => ActionKind::RendererCrash {
                window_index: window("window_index").unwrap_or(0),
            },
            _ => {
                let url = field("url");
                // `new URL(value).protocol.length > 0`.
                if url::Url::parse(&url).is_err() {
                    refinements.push(Refinement::new(
                        vec![json!("actions"), json!(index), json!("url")],
                        "deep-link url must be an absolute URL",
                    ));
                }
                ActionKind::DeepLink {
                    delivery: field("delivery"),
                    url,
                }
            }
        };
        actions.push(Action {
            step_id: field("step_id"),
            kind,
        });
    }
    if !refinements.is_empty() {
        return Err(refinements);
    }
    Ok(Request {
        executable_path,
        application_path,
        application_root,
        args,
        actions,
    })
}

/// libuv's `uv_strerror` text for the errnos `realpath`/`stat`/`access` report.
fn uv_error(error: &std::io::Error, syscall: &str, path: &str) -> String {
    let (code, description) = match error.raw_os_error() {
        Some(libc::ENOENT) => ("ENOENT", "no such file or directory"),
        Some(libc::ENOTDIR) => ("ENOTDIR", "not a directory"),
        Some(libc::EACCES) => ("EACCES", "permission denied"),
        Some(libc::EPERM) => ("EPERM", "operation not permitted"),
        Some(libc::ELOOP) => ("ELOOP", "too many symbolic links encountered"),
        Some(libc::ENAMETOOLONG) => ("ENAMETOOLONG", "name too long"),
        Some(libc::EIO) => ("EIO", "i/o error"),
        _ => return error.to_string(),
    };
    format!("{code}: {description}, {syscall} '{path}'")
}

fn path_issue(field: &str, message: String) -> InputIssue {
    InputIssue {
        path: vec![json!(field)],
        reason: "invalid_value",
        message: Some(message),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

/// `resolveInputPath`: `fs.realpath` of the caller's path.
fn resolve_path(field: &str, selected: &str) -> Result<String, InputIssue> {
    std::fs::canonicalize(selected)
        .map(|path| path.to_string_lossy().into_owned())
        .map_err(|error| {
            path_issue(
                field,
                format!(
                    "Cannot resolve {field} {selected}: {}",
                    uv_error(&error, "realpath", selected)
                ),
            )
        })
}

/// `resolveExecutablePath`: a launchable regular file before any spawn.
fn resolve_executable(selected: &str) -> Result<String, InputIssue> {
    let resolved = resolve_path("executable_path", selected)?;
    let failure = |message: String| {
        path_issue(
            "executable_path",
            format!("executable_path {selected} is not an executable file: {message}"),
        )
    };
    match std::fs::metadata(&resolved) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => return Err(failure("not a regular file".to_owned())),
        Err(error) => return Err(failure(uv_error(&error, "stat", &resolved))),
    }
    #[cfg(unix)]
    {
        if let Err(errno) = rustix::fs::access(resolved.as_str(), rustix::fs::Access::EXEC_OK) {
            return Err(failure(uv_error(
                &std::io::Error::from(errno),
                "access",
                &resolved,
            )));
        }
    }
    Ok(resolved)
}

/// `canonicalizeInput`: every path resolves independently; issues keep field order.
fn canonicalize(request: Request) -> Result<Canonical, Vec<InputIssue>> {
    let executable = resolve_executable(&request.executable_path);
    let application = resolve_path("application_path", &request.application_path);
    let root = request
        .application_root
        .as_deref()
        .map(|root| resolve_path("application_root", root))
        .transpose();
    match (executable, application, root) {
        (Ok(executable_path), Ok(application_path), Ok(root)) => {
            let root_selected = root.is_some();
            let application_root = root.unwrap_or_else(|| {
                Path::new(&application_path).parent().map_or_else(
                    || "/".to_owned(),
                    |parent| parent.to_string_lossy().into_owned(),
                )
            });
            Ok(Canonical {
                executable_path,
                application_path,
                application_root,
                root_selected,
                args: request.args,
                actions: request.actions,
            })
        }
        (executable, application, root) => Err([executable.err(), application.err(), root.err()]
            .into_iter()
            .flatten()
            .collect()),
    }
}

/// `safeElectronEnvironment` without the run token.
fn safe_environment(read: &dyn Fn(&str) -> Option<String>) -> Vec<(OsString, OsString)> {
    let mut names = vec![
        "HOME",
        "LANG",
        "PATH",
        "TMP",
        "TMPDIR",
        "USER",
        "DISPLAY",
        "WAYLAND_DISPLAY",
    ];
    if cfg!(windows) {
        names.extend([
            "SYSTEMROOT",
            "TEMP",
            "APPDATA",
            "LOCALAPPDATA",
            "USERPROFILE",
            "COMSPEC",
            "PATHEXT",
            "PROGRAMDATA",
            "ALLUSERSPROFILE",
            "USERNAME",
            "SYSTEMDRIVE",
            "HOMEDRIVE",
            "HOMEPATH",
        ]);
    }
    names
        .into_iter()
        .filter_map(|name| read(name).map(|value| (OsString::from(name), OsString::from(value))))
        .collect()
}

fn random_uuid() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut file) = std::fs::File::open("/dev/urandom") {
        let _ = std::io::Read::read_exact(&mut file, &mut bytes);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

// ---- Errors ------------------------------------------------------------------

fn observation(reason: &str) -> AnalysisError {
    cdp::observation_error(OPERATION, reason, None)
}

/// `ProviderAdapterError` with the producer message as its diagnostics.
fn adapter(message: impl Into<String>) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("message".into(), json!(message.into()));
    AnalysisError::provider_adapter(PROVIDER_ID, OPERATION).with_diagnostics(diagnostics)
}

/// `runWithExecutionLimits` failures.
fn call_failure(error: CallError) -> AnalysisError {
    match error {
        CallError::Cancelled => observation("cancelled"),
        CallError::Deadline => observation("timeout"),
        CallError::Protocol(message) | CallError::Closed(message) => adapter(message),
    }
}

fn classify(scope: &Scope, error: CdpTransportError) -> CallError {
    match error {
        CdpTransportError::Cancelled(_) => scope.interrupted().unwrap_or(CallError::Cancelled),
        CdpTransportError::Protocol { message, .. } => CallError::Protocol(message),
        CdpTransportError::Timeout => CallError::Closed("CDP request timed out".to_owned()),
        other => CallError::Closed(other.to_string()),
    }
}

// ---- Node Inspector (main process) -------------------------------------------

/// One JSON-RPC connection to Electron's main-process Node Inspector socket
/// (`ws://127.0.0.1:<port>/<uuid>`, which `rea_host::cdp_transport` does not
/// admit).
struct NodeInspector {
    socket: WebSocket<TcpStream>,
    next_id: u64,
    events: VecDeque<Value>,
}

impl NodeInspector {
    fn connect(url: &str) -> Result<Self, String> {
        let parsed = url::Url::parse(url).map_err(|error| error.to_string())?;
        let host = parsed
            .host_str()
            .unwrap_or_default()
            .trim_start_matches('[')
            .trim_end_matches(']');
        let ip: std::net::IpAddr = host
            .parse()
            .map_err(|_| format!("Inspector endpoint {url} is not a literal loopback address"))?;
        if !ip.is_loopback() {
            return Err(format!("Inspector endpoint {url} is not loopback"));
        }
        let address = SocketAddr::new(ip, parsed.port().unwrap_or(80));
        let stream = TcpStream::connect_timeout(&address, REQUEST_TIMEOUT)
            .map_err(|error| error.to_string())?;
        let _ = stream.set_nodelay(true);
        stream
            .set_write_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|error| error.to_string())?;
        let config = WebSocketConfig::default()
            .max_message_size(Some(MESSAGE_BYTES))
            .max_frame_size(Some(MESSAGE_BYTES));
        let (socket, _) = tungstenite::client::client_with_config(url, stream, Some(config))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            socket,
            next_id: 1,
            events: VecDeque::new(),
        })
    }

    fn receive(&mut self) -> Result<Option<Value>, CallError> {
        let _ = self.socket.get_mut().set_read_timeout(Some(POLL));
        match self.socket.read() {
            Ok(Message::Text(text)) => serde_json::from_str(text.as_str())
                .map(Some)
                .map_err(|error| CallError::Closed(format!("invalid Inspector message: {error}"))),
            Ok(Message::Close(_)) => Err(CallError::Closed(
                "Electron main-process Inspector closed".to_owned(),
            )),
            Ok(_) => Ok(None),
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    IoKind::WouldBlock | IoKind::TimedOut | IoKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(error) => Err(CallError::Closed(error.to_string())),
        }
    }

    fn call(&mut self, method: &str, params: Value, scope: &Scope) -> Result<Value, CallError> {
        if let Some(interruption) = scope.interrupted() {
            return Err(interruption);
        }
        let id = self.next_id;
        self.next_id += 1;
        self.socket
            .send(Message::text(
                json!({ "id": id, "method": method, "params": params }).to_string(),
            ))
            .map_err(|error| CallError::Closed(error.to_string()))?;
        loop {
            if let Some(interruption) = scope.interrupted() {
                return Err(interruption);
            }
            let Some(message) = self.receive()? else {
                continue;
            };
            if message.get("id").and_then(Value::as_u64) == Some(id) {
                if let Some(error) = message.get("error") {
                    return Err(CallError::Protocol(
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or("protocol error")
                            .to_owned(),
                    ));
                }
                return Ok(message.get("result").cloned().unwrap_or(Value::Null));
            }
            if message.get("method").is_some() {
                self.events.push_back(message);
            }
        }
    }

    fn next_event(&mut self, scope: &Scope) -> Result<Value, CallError> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }
            if let Some(interruption) = scope.interrupted() {
                return Err(interruption);
            }
            if let Some(message) = self.receive()?
                && message.get("method").is_some()
            {
                self.events.push_back(message);
            }
        }
    }

    fn close(&mut self) {
        let _ = self.socket.close(None);
        let _ = self.socket.get_mut().shutdown(std::net::Shutdown::Both);
    }
}

/// The main-process `require('electron')` handle (`_nodeElectronHandlePromise`).
struct MainProcess {
    inspector: NodeInspector,
    electron: String,
}

impl MainProcess {
    /// `ElectronApplication` construction plus `initialize()`.
    fn open(url: &str, scope: &Scope) -> Result<Self, CallError> {
        let mut inspector = NodeInspector::connect(url).map_err(CallError::Closed)?;
        inspector.call("Runtime.enable", json!({}), scope)?;
        let context = loop {
            let event = inspector.next_event(scope)?;
            if event.get("method").and_then(Value::as_str)
                == Some("Runtime.executionContextCreated")
                && event
                    .pointer("/params/context/auxData/isDefault")
                    .and_then(Value::as_bool)
                    == Some(true)
                && let Some(id) = event.pointer("/params/context/id").and_then(Value::as_i64)
            {
                break id;
            }
        };
        let handle = inspector.call(
            "Runtime.evaluate",
            json!({ "expression": "require('electron')", "contextId": context, "includeCommandLineAPI": true }),
            scope,
        )?;
        let electron = handle
            .pointer("/result/objectId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        if electron.is_empty() {
            return Err(CallError::Protocol(
                "require('electron') did not return the Electron module".to_owned(),
            ));
        }
        // Without Playwright's loader this reports a ReferenceError, as in TS.
        let _ = inspector.call(
            "Runtime.evaluate",
            json!({ "expression": "__playwright_run()" }),
            scope,
        );
        Ok(Self {
            inspector,
            electron,
        })
    }

    /// `electronApplication.evaluate(fn, arg)`: `fn(require('electron'), arg)`.
    fn evaluate(
        &mut self,
        function: &str,
        argument: Value,
        scope: &Scope,
    ) -> Result<Value, CallError> {
        let result = self.inspector.call(
            "Runtime.callFunctionOn",
            json!({
                "objectId": self.electron,
                "functionDeclaration": format!("function(arg) {{ return ({function})(this, arg); }}"),
                "arguments": [{ "value": argument }],
                "returnByValue": true,
                "awaitPromise": true,
            }),
            scope,
        )?;
        if let Some(details) = result.get("exceptionDetails") {
            let message = details
                .pointer("/exception/description")
                .or_else(|| details.get("text"))
                .and_then(Value::as_str)
                .unwrap_or("Evaluation failed");
            return Err(CallError::Protocol(format!(
                "electronApplication.evaluate: {message}"
            )));
        }
        Ok(result
            .pointer("/result/value")
            .cloned()
            .unwrap_or(Value::Null))
    }
}

// ---- Renderer (DevTools browser endpoint) ------------------------------------

struct Window {
    session: String,
}

/// The browser-level CDP connection and its page targets in attach order
/// (`application.windows()`).
struct Renderer {
    transport: CdpWebSocketTransport,
    windows: Vec<Window>,
    loads: BTreeSet<String>,
    lost: Option<String>,
}

impl Renderer {
    fn open(url: &str, scope: &Scope) -> Result<Self, CallError> {
        let mut transport =
            CdpWebSocketTransport::connect_with_limits(url, None, REQUEST_TIMEOUT, MESSAGE_BYTES)
                .map_err(|error| CallError::Closed(error.to_string()))?;
        transport.set_event_buffer_limits(usize::MAX, MESSAGE_BYTES);
        let mut renderer = Self {
            transport,
            windows: Vec::new(),
            loads: BTreeSet::new(),
            lost: None,
        };
        renderer.call(
            None,
            "Target.setAutoAttach",
            json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
            scope,
        )?;
        Ok(renderer)
    }

    fn route(&mut self, scope: &Scope) {
        for event in self.transport.drain_events().items {
            let value = event.value;
            let method = value
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let params = value.get("params").cloned().unwrap_or(Value::Null);
            match method {
                "Target.attachedToTarget"
                    if params.pointer("/targetInfo/type").and_then(Value::as_str)
                        == Some("page") =>
                {
                    let session = params
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    if !session.is_empty()
                        && !self.windows.iter().any(|window| window.session == session)
                    {
                        self.windows.push(Window {
                            session: session.clone(),
                        });
                        let _ = self.transport.request_in_session_with_cancellation(
                            "Page.enable",
                            json!({}),
                            &session,
                            scope.token(),
                        );
                    }
                }
                "Target.detachedFromTarget" => {
                    let session = params
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    self.windows.retain(|window| window.session != session);
                }
                "Page.loadEventFired" => {
                    if let Some(session) = value.get("sessionId").and_then(Value::as_str) {
                        self.loads.insert(session.to_owned());
                    }
                }
                _ => {}
            }
        }
    }

    fn call(
        &mut self,
        session: Option<&str>,
        method: &str,
        params: Value,
        scope: &Scope,
    ) -> Result<Value, CallError> {
        if let Some(interruption) = scope.interrupted() {
            return Err(interruption);
        }
        if let Some(reason) = &self.lost {
            return Err(CallError::Closed(reason.clone()));
        }
        let result = match session {
            Some(session) => self.transport.request_in_session_with_cancellation(
                method,
                params,
                session,
                scope.token(),
            ),
            None => self
                .transport
                .request_with_cancellation(method, params, scope.token()),
        }
        .map_err(|error| {
            let classified = classify(scope, error);
            if let CallError::Closed(reason) = &classified {
                self.lost = Some(reason.clone());
            }
            classified
        });
        self.route(scope);
        result
    }

    /// One bounded event-loop turn.
    fn poll(&mut self, scope: &Scope) -> Result<(), CallError> {
        if let Some(interruption) = scope.interrupted() {
            return Err(interruption);
        }
        if self.lost.is_none()
            && let Err(error) = self.transport.poll_events(POLL, scope.token())
        {
            match classify(scope, error) {
                CallError::Closed(reason) => self.lost = Some(reason),
                other => return Err(other),
            }
        }
        if self.lost.is_some() {
            std::thread::sleep(POLL);
        }
        self.route(scope);
        Ok(())
    }

    fn sleep(&mut self, duration: Duration, scope: &Scope) -> Result<(), CallError> {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline {
            self.poll(scope)?;
        }
        Ok(())
    }

    fn close(self) {
        let _ = self.transport.close();
    }
}

// ---- Actions (`runElectronActions`) -----------------------------------------

fn evaluation_value(result: &Value) -> Result<Value, CallError> {
    if let Some(details) = result.get("exceptionDetails") {
        let message = details
            .pointer("/exception/description")
            .or_else(|| details.get("text"))
            .and_then(Value::as_str)
            .unwrap_or("Evaluation failed");
        return Err(CallError::Protocol(message.to_owned()));
    }
    Ok(result.get("result").cloned().unwrap_or(Value::Null))
}

/// Same rule as `capture_browser_scenario`'s `css` locator.
fn playwright_selector_syntax(selector: &str) -> bool {
    let trimmed = selector.trim_start();
    const ENGINES: [&str; 12] = [
        "text=",
        "css=",
        "xpath=",
        "id=",
        "data-testid=",
        "data-test-id=",
        "data-test=",
        "nth=",
        "visible=",
        "internal:",
        "role=",
        "_react=",
    ];
    const PSEUDOS: [&str; 12] = [
        ":has-text(",
        ":text(",
        ":text-is(",
        ":text-matches(",
        ":visible",
        ":nth-match(",
        ":right-of(",
        ":left-of(",
        ":above(",
        ":below(",
        ":near(",
        ":light(",
    ];
    ENGINES.iter().any(|engine| trimmed.starts_with(engine))
        || trimmed.starts_with("//")
        || trimmed.starts_with("..")
        || trimmed.starts_with('"')
        || selector.contains(">>")
        || PSEUDOS.iter().any(|pseudo| selector.contains(pseudo))
}

/// `locator(selector).click({ timeout: 0 })` in one window: wait for exactly
/// one visible, enabled, stable element, scroll it into view and click the
/// center of its first sizeable content quad when it receives the hit.
fn click(
    renderer: &mut Renderer,
    session: &str,
    selector: &str,
    scope: &Scope,
) -> Result<(), CallError> {
    if playwright_selector_syntax(selector) {
        return Err(CallError::Protocol(format!(
            "Playwright selector-engine syntax is not supported by REA's native Electron scenario runner: \"{selector}\". Use a plain CSS selector."
        )));
    }
    let s = Some(session);
    let locator = json!({ "kind": "css", "selector": selector });
    loop {
        let tree = renderer.call(s, "Page.getFrameTree", json!({}), scope)?;
        let frame = tree
            .pointer("/frameTree/frame/id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let world = renderer.call(s, "Page.createIsolatedWorld", json!({ "frameId": frame, "worldName": "rea-electron-scenario", "grantUniveralAccess": true }), scope)?;
        let context = world
            .get("executionContextId")
            .and_then(Value::as_i64)
            .unwrap_or_default();
        evaluation_value(&renderer.call(
            s,
            "Runtime.evaluate",
            json!({ "expression": PAGE_HELPER, "contextId": context }),
            scope,
        )?)?;
        let resolved = evaluation_value(&renderer.call(
            s,
            "Runtime.evaluate",
            json!({ "expression": format!("__reaScenario.resolve({locator})"), "contextId": context, "objectGroup": "rea-electron" }),
            scope,
        )?)?;
        let release = |renderer: &mut Renderer| {
            let _ = renderer.call(
                s,
                "Runtime.releaseObjectGroup",
                json!({ "objectGroup": "rea-electron" }),
                scope,
            );
        };
        if resolved.get("subtype").and_then(Value::as_str) != Some("node") {
            release(renderer);
            renderer.sleep(Duration::from_millis(20), scope)?;
            continue;
        }
        let object = resolved
            .get("objectId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let call_on = |renderer: &mut Renderer,
                       function: &str,
                       arguments: Vec<Value>,
                       await_promise: bool| {
            let arguments: Vec<Value> = arguments
                .into_iter()
                .map(|value| json!({ "value": value }))
                .collect();
            renderer
                .call(
                    s,
                    "Runtime.callFunctionOn",
                    json!({ "objectId": object, "functionDeclaration": function, "arguments": arguments, "returnByValue": true, "awaitPromise": await_promise }),
                    scope,
                )
                .and_then(|result| evaluation_value(&result))
                .map(|value| value.get("value").cloned().unwrap_or(Value::Null))
        };
        let states = call_on(
            renderer,
            "function(states) { return __reaScenario.states(this, states); }",
            vec![json!(["stable", "visible", "enabled"])],
            true,
        )?;
        if states.as_str() != Some("ok")
            || renderer
                .call(
                    s,
                    "DOM.scrollIntoViewIfNeeded",
                    json!({ "objectId": object }),
                    scope,
                )
                .is_err()
        {
            release(renderer);
            renderer.sleep(Duration::from_millis(100), scope)?;
            continue;
        }
        let Some((x, y)) = clickable_point(renderer, session, &object, scope)? else {
            release(renderer);
            renderer.sleep(Duration::from_millis(100), scope)?;
            continue;
        };
        let hit = call_on(
            renderer,
            "function(x, y) { return __reaScenario.hit(this, x, y); }",
            vec![json!(x), json!(y)],
            false,
        )?;
        release(renderer);
        if hit.as_str() != Some("done") {
            renderer.sleep(Duration::from_millis(100), scope)?;
            continue;
        }
        for (kind, buttons, force) in [
            ("mouseMoved", 0, 0.0),
            ("mousePressed", 1, 0.5),
            ("mouseReleased", 0, 0.0),
        ] {
            let mut event = json!({ "type": kind, "button": if kind == "mouseMoved" { "none" } else { "left" }, "buttons": buttons, "x": x, "y": y, "modifiers": 0, "force": force });
            if kind != "mouseMoved" {
                event["clickCount"] = json!(1);
            }
            renderer.call(s, "Input.dispatchMouseEvent", event, scope)?;
        }
        return Ok(());
    }
}

fn clickable_point(
    renderer: &mut Renderer,
    session: &str,
    object: &str,
    scope: &Scope,
) -> Result<Option<(f64, f64)>, CallError> {
    let quads = match renderer.call(
        Some(session),
        "DOM.getContentQuads",
        json!({ "objectId": object }),
        scope,
    ) {
        Ok(quads) => quads,
        Err(CallError::Protocol(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let metrics = renderer.call(Some(session), "Page.getLayoutMetrics", json!({}), scope)?;
    let width = metrics
        .pointer("/cssLayoutViewport/clientWidth")
        .and_then(Value::as_f64)
        .unwrap_or(f64::MAX);
    let height = metrics
        .pointer("/cssLayoutViewport/clientHeight")
        .and_then(Value::as_f64)
        .unwrap_or(f64::MAX);
    for quad in quads
        .get("quads")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let points: Vec<f64> = quad
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_f64)
            .collect();
        if points.len() != 8 {
            continue;
        }
        let clipped: Vec<(f64, f64)> = (0..4)
            .map(|index| {
                (
                    points[index * 2].clamp(0.0, width),
                    points[index * 2 + 1].clamp(0.0, height),
                )
            })
            .collect();
        let area: f64 = (0..4)
            .map(|index| {
                let (x1, y1) = clipped[index];
                let (x2, y2) = clipped[(index + 1) % 4];
                (x1 * y2 - x2 * y1) / 2.0
            })
            .sum();
        if area.abs() > 0.99 {
            let x = clipped.iter().map(|point| point.0).sum::<f64>() / 4.0;
            let y = clipped.iter().map(|point| point.1).sum::<f64>() / 4.0;
            return Ok(Some((x, y)));
        }
    }
    Ok(None)
}

struct Application {
    main: MainProcess,
    renderer: Renderer,
}

/// `waitForWindow`.
fn wait_for_window(
    application: &mut Application,
    index: u64,
    scope: &Scope,
) -> Result<String, CallError> {
    loop {
        if let Some(window) = usize::try_from(index)
            .ok()
            .and_then(|index| application.renderer.windows.get(index))
        {
            return Ok(window.session.clone());
        }
        application.renderer.poll(scope)?;
    }
}

const CRASH: &str = "({ BrowserWindow }, index) => { const candidate = BrowserWindow.getAllWindows()[index]; if (candidate === undefined || candidate.isDestroyed()) return false; candidate.webContents.forcefullyCrashRenderer(); return true; }";
const DEEP_LINK: &str = "({ app }, payload) => { if (payload.delivery === \"open-url\") return app.emit(\"open-url\", { preventDefault: () => undefined }, payload.url); return app.emit(\"second-instance\", {}, [payload.url], \"\", {}); }";

fn run_action(
    application: &mut Application,
    action: &Action,
    window: Option<&str>,
    scope: &Scope,
) -> Result<(), AnalysisError> {
    let missing = || observation("window_not_found");
    match &action.kind {
        ActionKind::Click { selector, .. } => click(
            &mut application.renderer,
            window.ok_or_else(missing)?,
            selector,
            scope,
        )
        .map_err(call_failure),
        ActionKind::Wait { duration_ms, .. } => {
            if window.is_none() {
                wait_for_window(application, 0, scope).map_err(call_failure)?;
            }
            application
                .renderer
                .sleep(Duration::from_millis(*duration_ms), scope)
                .map_err(call_failure)
        }
        ActionKind::RendererReload { .. } => {
            let session = window.ok_or_else(missing)?;
            application.renderer.loads.remove(session);
            application
                .renderer
                .call(Some(session), "Page.reload", json!({}), scope)
                .map_err(call_failure)?;
            while !application.renderer.loads.contains(session) {
                if !application
                    .renderer
                    .windows
                    .iter()
                    .any(|window| window.session == session)
                {
                    return Err(adapter("Target page, context or browser has been closed"));
                }
                application.renderer.poll(scope).map_err(call_failure)?;
            }
            Ok(())
        }
        ActionKind::RendererCrash { window_index } => {
            let crashed = application
                .main
                .evaluate(CRASH, json!(window_index), scope)
                .map_err(call_failure)?;
            if crashed != Value::Bool(true) {
                return Err(missing());
            }
            Ok(())
        }
        ActionKind::DeepLink { delivery, url } => application
            .main
            .evaluate(
                DEEP_LINK,
                json!({ "delivery": delivery, "url": url }),
                scope,
            )
            .map_err(call_failure)
            .map(|_| ()),
    }
}

/// `safeActionErrorMessage`: the failure's `Error.message`.
fn action_error_message(error: &AnalysisError) -> String {
    match error
        .project()
        .pointer("/details/diagnostics/message")
        .and_then(Value::as_str)
    {
        Some(message) => message.to_owned(),
        None => error.message(),
    }
}

fn run_actions(
    application: &mut Application,
    actions: &[Action],
    cancellation: &Cancellation,
) -> Vec<Value> {
    let scope = Scope::new(cancellation, None);
    let mut results = Vec::new();
    for action in actions {
        let started = Instant::now();
        let index = action.window_index();
        let mut selected: Option<String> = None;
        let outcome = (|| {
            if cancellation.reason().is_some() {
                return Err(observation("cancelled"));
            }
            if let Some(index) = index {
                selected = Some(wait_for_window(application, index, &scope).map_err(call_failure)?);
            }
            run_action(application, action, selected.as_deref(), &scope)
        })();
        let target = match (&selected, index) {
            (Some(_), Some(index)) => json!(format!("window:{index}")),
            _ => Value::Null,
        };
        let elapsed = started.elapsed().as_millis() as u64;
        let mut result = json!({
            "step_id": action.step_id,
            "kind": action.kind_name(),
            "window_index": index,
            "target": target,
            "status": "completed",
            "elapsed_ms": elapsed,
            "error": null,
        });
        match outcome {
            Ok(()) => results.push(result),
            Err(error) => {
                result["status"] = json!(if cancellation.reason().is_some() {
                    "cancelled"
                } else {
                    "failed"
                });
                result["error"] = json!(action_error_message(&error));
                results.push(result);
                break;
            }
        }
    }
    results
}

// ---- Application state (`readApplicationState`) -----------------------------

const WINDOWS: &str = "({ BrowserWindow }) => BrowserWindow.getAllWindows().map((window) => ({ window_id: `window:${String(window.id)}`, web_contents_id: `webContents:${String(window.webContents.id)}`, url: window.webContents.getURL(), title: window.webContents.getTitle(), visible: window.isDestroyed() ? null : window.isVisible(), destroyed: window.isDestroyed() }))";
const METRICS: &str = "({ app }) => app.getAppMetrics().map((metric) => ({ pid: metric.pid, type: metric.type, name: metric.name ?? null, service_name: metric.serviceName ?? null }))";
const APPLICATION_ROOT: &str = "({ app }) => app.getAppPath()";
const VERSION: &str = "() => process.versions.electron";
const SNAPSHOT: &str = "() => { const candidate = Reflect.get(globalThis, \"__reaElectronActiveSnapshot\"); return typeof candidate === \"function\" ? candidate() : { events: [], retention_budget_bytes: 0, estimated_retained_bytes: 0, event_serialized_byte_upper_bound: 0, retained: 0, dropped: 0, dropped_ipc: 0, dropped_runtime: 0, dropped_event_families: [], dropped_event_roles: [], observed: 0, observed_ipc: 0, observed_runtime: 0, hook_error: true }; }";

const SNAPSHOT_COUNTS: [&str; 11] = [
    "retention_budget_bytes",
    "estimated_retained_bytes",
    "event_serialized_byte_upper_bound",
    "retained",
    "dropped",
    "dropped_ipc",
    "dropped_runtime",
    "observed",
    "observed_ipc",
    "observed_runtime",
    "hook_error",
];

#[derive(Clone)]
struct State {
    application_root: String,
    windows: Value,
    metrics: Value,
    version: String,
    snapshot: Value,
}

/// The strict-object checks of `windowMetadataSchema`, `metricSchema` and
/// `hookSnapshotSchema` at the hook boundary.
fn shape_failure(what: &str) -> AnalysisError {
    adapter(format!("Electron {what} did not match the expected shape"))
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn validate_state(state: &State) -> Result<(), AnalysisError> {
    let windows_ok = state.windows.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            exact_keys(
                item,
                &[
                    "window_id",
                    "web_contents_id",
                    "url",
                    "title",
                    "visible",
                    "destroyed",
                ],
            ) && ["window_id", "web_contents_id", "url", "title"]
                .iter()
                .all(|key| item[*key].is_string())
                && (item["visible"].is_boolean() || item["visible"].is_null())
                && item["destroyed"].is_boolean()
        })
    });
    if !windows_ok {
        return Err(shape_failure("window metadata"));
    }
    let metrics_ok = state.metrics.as_array().is_some_and(|items| {
        items.iter().all(|item| {
            exact_keys(item, &["pid", "type", "name", "service_name"])
                && item["pid"].as_u64().is_some_and(|pid| pid >= 1)
                && item["type"].as_str().is_some_and(|kind| !kind.is_empty())
                && (item["name"].is_string() || item["name"].is_null())
                && (item["service_name"].is_string() || item["service_name"].is_null())
        })
    });
    if !metrics_ok {
        return Err(shape_failure("process metrics"));
    }
    let mut keys: Vec<&str> = SNAPSHOT_COUNTS.to_vec();
    keys.extend(["events", "dropped_event_families", "dropped_event_roles"]);
    let snapshot = &state.snapshot;
    let snapshot_ok = exact_keys(snapshot, &keys)
        && SNAPSHOT_COUNTS[..10]
            .iter()
            .all(|key| snapshot[*key].is_u64())
        && snapshot["hook_error"].is_boolean()
        && snapshot["events"].as_array().is_some_and(|events| {
            events
                .iter()
                .all(|event| event.get("kind").is_some_and(Value::is_string))
        })
        && ["dropped_event_families", "dropped_event_roles"]
            .iter()
            .all(|key| snapshot[*key].is_array());
    if !snapshot_ok {
        return Err(shape_failure("hook snapshot"));
    }
    Ok(())
}

fn validate_application_root(state: &State, expected: &str) -> Result<(), AnalysisError> {
    if state.application_root == expected {
        return Ok(());
    }

    Err(adapter(format!(
        "Electron loaded application root {} instead of requested root {}",
        state.application_root, expected
    )))
}

fn read_state(main: &mut MainProcess, scope: &Scope) -> Result<State, AnalysisError> {
    let application_root = main
        .evaluate(APPLICATION_ROOT, Value::Null, scope)
        .map_err(call_failure)?;
    let windows = main
        .evaluate(WINDOWS, Value::Null, scope)
        .map_err(call_failure)?;
    let metrics = main
        .evaluate(METRICS, Value::Null, scope)
        .map_err(call_failure)?;
    let version = main
        .evaluate(VERSION, Value::Null, scope)
        .map_err(call_failure)?;
    let snapshot = main
        .evaluate(SNAPSHOT, Value::Null, scope)
        .map_err(call_failure)?;
    let Some(version) = version.as_str().map(str::to_owned) else {
        return Err(shape_failure("version"));
    };
    let Some(application_root) = application_root.as_str().map(str::to_owned) else {
        return Err(shape_failure("application root"));
    };
    let state = State {
        application_root,
        windows,
        metrics,
        version,
        snapshot,
    };
    validate_state(&state)?;
    Ok(state)
}

/// `readFinalApplicationState`: cancellation leaves a bounded grace period.
fn read_final_state(
    main: &mut MainProcess,
    cancellation: &Cancellation,
) -> Result<State, AnalysisError> {
    if cancellation.reason().is_none() {
        match read_state(main, &Scope::new(cancellation, None)) {
            Err(error) if cancellation.reason().is_some() && error.code() == "cancelled" => {}
            other => return other,
        }
    }
    let grace = Cancellation::default();
    match read_state(
        main,
        &Scope::new(&grace, Some(CANCELLED_STATE_READ_GRACE.as_millis() as u64)),
    ) {
        Err(error) if error.code() == "provider_timeout" => {
            let mut diagnostics = Map::new();
            diagnostics.insert(
                "final_state_read".into(),
                json!("cancellation_grace_expired"),
            );
            diagnostics.insert(
                "cancellation_grace_ms".into(),
                json!(CANCELLED_STATE_READ_GRACE.as_millis() as u64),
            );
            Err(observation("cancelled").with_diagnostics(diagnostics))
        }
        other => other,
    }
}

// ---- Projection (`projectElectronActiveCapture`) -----------------------------

const OBSERVABLE_FAMILIES: [&str; 17] = [
    "app-lifecycle",
    "window-lifecycle",
    "web-contents-lifecycle",
    "navigation",
    "shell-attempt",
    "process-lifecycle",
    "permission",
    "popup-attempt",
    "download",
    "protocol",
    "preload",
    "preload-configuration",
    "renderer-ipc",
    "native-addon",
    "updater",
    "error",
    "ipc",
];
const IPC_KINDS: [&str; 9] = [
    "main-handler-invocation",
    "main-event-invocation",
    "utility-process-fork",
    "utility-process-message",
    "ipc-main-to-renderer",
    "ipc-utility-to-main",
    "ipc-renderer-send",
    "ipc-renderer-invoke",
    "ipc-renderer-post-message",
];

fn event_family(kind: &str, process_type: Option<&str>) -> String {
    if kind == "preload" && matches!(process_type, Some("main" | "browser")) {
        return "preload-configuration".to_owned();
    }
    if kind.starts_with("ipc-renderer") {
        return if process_type == Some("renderer") {
            "renderer-ipc"
        } else {
            "ipc"
        }
        .to_owned();
    }
    if IPC_KINDS.contains(&kind) {
        "ipc".to_owned()
    } else {
        kind.to_owned()
    }
}

fn names(items: &Value, key: &str) -> Vec<String> {
    items
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.get(key).and_then(Value::as_str))
        .map(str::to_owned)
        .collect()
}

fn project(paths: (&str, &str), actions: &[Value], state: &State) -> Value {
    let snapshot = &state.snapshot;
    let events: Vec<Value> = snapshot["events"].as_array().cloned().unwrap_or_default();
    let field =
        |event: &Value, key: &str| event.get(key).and_then(Value::as_str).map(str::to_owned);
    let mut families: BTreeSet<String> = events
        .iter()
        .map(|event| {
            event_family(
                &field(event, "kind").unwrap_or_default(),
                field(event, "process_type").as_deref(),
            )
        })
        .collect();
    families.extend(names(&snapshot["dropped_event_families"], "family"));
    let mut roles = BTreeSet::new();
    for event in &events {
        let kind = field(event, "kind").unwrap_or_default();
        let process = field(event, "process_type");
        if let Some(process) = &process {
            roles.insert(process.clone());
        }
        if kind == "window-lifecycle" {
            roles.insert("window".to_owned());
        }
        if kind == "web-contents-lifecycle" || kind == "navigation" {
            roles.insert("web_contents".to_owned());
        }
        if kind == "preload" && process.as_deref() == Some("preload") {
            roles.insert("preload".to_owned());
        }
        if kind.starts_with("ipc-renderer") && process.as_deref() == Some("renderer") {
            roles.insert("renderer".to_owned());
        }
    }
    roles.extend(names(&snapshot["dropped_event_roles"], "role"));
    let mut unavailable: BTreeSet<String> = OBSERVABLE_FAMILIES
        .iter()
        .filter(|family| !families.contains(**family))
        .map(|family| (*family).to_owned())
        .collect();
    if !roles.contains("preload") {
        unavailable.insert("preload".to_owned());
    }
    if !roles.contains("renderer") {
        unavailable.insert("renderer-ipc".to_owned());
    }
    let count = |key: &str| snapshot[key].as_u64().unwrap_or_default();
    let hook_error = snapshot["hook_error"].as_bool().unwrap_or(true);
    let ipc_events: Vec<Value> = events
        .iter()
        .filter(|event| IPC_KINDS.contains(&field(event, "kind").unwrap_or_default().as_str()))
        .cloned()
        .collect();
    let mut limitations = vec![
        "IPC payloads are represented by value shapes; payload values are never retained."
            .to_owned(),
    ];
    if families.contains("ipc-observation-gap") {
        limitations.push("IPC observation gaps have unobserved callback arguments and execution. Available ipc-observation-gap timeline records identify the callable, registration or removal boundary and channel where known; dropped gap records are counted by retention. Registration gaps do not prove IPC delivery, and removal gaps do not confirm which registration was removed.".to_owned());
    }
    limitations.push("IPC direction and sender/receiver identifiers are observed only where Electron exposes them at the hooked boundary.".to_owned());
    limitations.push("The runtime timeline records lifecycle, navigation, shell, permission, popup, download, protocol, preload, native-addon, process, and IPC events; activity before hook installation is unavailable.".to_owned());
    limitations.push("The preload and renderer process contexts are not instrumented by the main-process -r hook; preload configuration and contextBridge API-shape events are main-boundary observations, not proof of renderer-side execution.".to_owned());
    if !families.contains("preload-configuration") {
        limitations.push("Preload configuration was not exposed by the observed Electron window metadata. Preload paths and execution remain unavailable.".to_owned());
    }
    if snapshot["dropped_event_families"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|entry| {
            entry.get("family").and_then(Value::as_str) == Some("preload")
                && entry
                    .get("count")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
                    > 0
        })
    {
        limitations.push("Dropped preload-family events were not attributed to preload configuration; independently aggregated event families and roles cannot establish that relationship.".to_owned());
    }
    limitations.push("Process metrics are an Electron API snapshot and do not prove hostile-local-user isolation.".to_owned());
    if count("dropped") > 0 {
        limitations.push(format!(
            "The active hook retained {} of {} observed events within a {}-byte retained-data budget; {} events were dropped ({} IPC, {} runtime).",
            count("retained"),
            count("observed"),
            count("retention_budget_bytes"),
            count("dropped"),
            count("dropped_ipc"),
            count("dropped_runtime")
        ));
    }
    limitations.push("External shell opens, external navigation, permission grants, downloads, popup windows, updater relaunches, and OS integration are blocked and recorded by the active hook; other application filesystem and network behavior is not sandboxed by this provider.".to_owned());
    if hook_error {
        limitations.push("The active IPC hook could not be installed.".to_owned());
    }
    json!({
        "application": {
            "executable_path": paths.0,
            "application_path": paths.1,
            "electron_version": state.version,
            "process_ownership": "provider-owned",
            "cleanup": "terminated-owned-process",
        },
        "actions": actions,
        "windows": state.windows,
        "processes": { "items": state.metrics },
        "ipc": { "events": ipc_events, "observed": count("observed_ipc"), "dropped": count("dropped_ipc") },
        "timeline": { "events": events, "observed": count("observed"), "dropped": count("dropped") },
        "retention": {
            "budget_bytes": count("retention_budget_bytes"),
            "estimated_retained_bytes": count("estimated_retained_bytes"),
            "event_serialized_byte_upper_bound": count("event_serialized_byte_upper_bound"),
            "retained": count("retained"),
            "dropped": count("dropped"),
            "dropped_event_families": snapshot["dropped_event_families"],
            "dropped_event_roles": snapshot["dropped_event_roles"],
            "observed_ipc": count("observed_ipc"),
            "dropped_ipc": count("dropped_ipc"),
            "observed_runtime": count("observed_runtime"),
            "dropped_runtime": count("dropped_runtime"),
        },
        "coverage": {
            "status": if hook_error { "hook_conflict" } else { "partial_attach" },
            "observed_event_families": families.into_iter().collect::<Vec<_>>(),
            "unavailable_event_families": unavailable.into_iter().collect::<Vec<_>>(),
            "observed_roles": roles.into_iter().collect::<Vec<_>>(),
            "pre_capture_activity": "unavailable",
        },
        "limitations": limitations,
    })
}

fn partial(capture: &Value) -> Value {
    json!({ "kind": "electron-active-observation", "capture": capture })
}

/// `createElectronActiveEvidence`.
fn evidence(request: &Canonical, capture: Value) -> Result<Evidence, AnalysisError> {
    let version = capture
        .pointer("/application/electron_version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let limitations: Vec<String> = capture["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .chain(std::iter::once(
            "Application host platform and architecture were not observed.".to_owned(),
        ))
        .collect();
    let observation = Observation::new(OPERATION, request.parameters(), capture)
        .predicate("rea.electron-active-scenario")
        .confidence("observed")
        .authority("controlled-replay")
        .environment(json!({ "id": format!("{version}@unknown"), "platform": "unknown", "architecture": "unknown", "isolation": "none" }))
        .limitations(limitations);
    Evidence::create(None, &provider(), observation).map_err(|_| {
        AnalysisError::output(
            OPERATION,
            "Electron active provider returned a malformed completed capture.",
        )
    })
}

// ---- Launch ------------------------------------------------------------------

/// Everything one capture acquired, released by `release`.
struct Owned {
    child: Option<OwnedChildProcess>,
    root: Option<PathBuf>,
    run_id: String,
    baseline: OwnershipBaseline,
    leader: u32,
}

/// Playwright's progress call log, rebuilt from REA's own launch observations.
struct CallLog(Vec<String>);

impl CallLog {
    fn push(&mut self, line: impl Into<String>) {
        self.0.push(line.into());
    }

    fn failure(&self, head: &str) -> AnalysisError {
        let mut message = format!("electron.launch: {head}\nCall log:\n");
        for line in &self.0 {
            message.push_str(&format!("\u{1b}[2m  - {line}\u{1b}[22m\n"));
        }
        adapter(message)
    }
}

struct Endpoints {
    node: String,
    chrome: String,
}

fn prepare_root() -> Result<(PathBuf, PathBuf, PathBuf), String> {
    let root = tempfile::Builder::new()
        .prefix("rea-electron-scenario-")
        .tempdir()
        .map_err(|error| error.to_string())?
        .keep();
    let profile = root.join("profile");
    let hook_directory = root.join("hook");
    let hook = hook_directory.join("electron-active-hook.cjs");
    let written = std::fs::create_dir(&profile)
        .and_then(|()| std::fs::create_dir(&hook_directory))
        .and_then(|()| std::fs::write(&hook, HOOK))
        .and_then(|()| {
            std::fs::write(
                hook_directory.join("electron-active-hook-boundaries.cjs"),
                HOOK_BOUNDARIES,
            )
        });
    if let Err(error) = written {
        let _ = remove_root(&root);
        return Err(error.to_string());
    }
    Ok((root, profile, hook))
}

fn remove_root(root: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..4 {
        match std::fs::remove_dir_all(root) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == IoKind::NotFound => return Ok(()),
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

/// `_electron.launch`: spawn through the owned launcher and wait for both
/// debugging endpoints on stderr.
fn launch(
    request: &Canonical,
    mut environment: Vec<(OsString, OsString)>,
    deadline: Instant,
    cancellation: &Cancellation,
) -> Result<(Owned, Endpoints), AnalysisError> {
    let run_id = random_uuid();
    environment.push((
        OsString::from("REA_PROCESS_RUN_ID"),
        OsString::from(&run_id),
    ));
    let baseline = ownership::capture_baseline().unwrap_or_default();
    if cancellation.reason().is_some() {
        return Err(observation("cancelled"));
    }
    let (root, profile, hook) = prepare_root().map_err(|error| {
        adapter(format!(
            "Could not prepare the Electron scenario directory: {error}"
        ))
    })?;
    let mut arguments = vec![
        "--inspect=0".to_owned(),
        "--remote-debugging-port=0".to_owned(),
    ];
    if cfg!(target_os = "linux")
        && rustix::process::geteuid().is_root()
        && !request.args.iter().any(|arg| arg == "--no-sandbox")
    {
        arguments.insert(0, "--no-sandbox".to_owned());
    }
    arguments.push(format!("--user-data-dir={}", profile.display()));
    arguments.extend([
        "-r".to_owned(),
        hook.to_string_lossy().into_owned(),
        request.application_path.clone(),
    ]);
    arguments.extend(request.args.iter().cloned());
    let timeout_ms = deadline
        .saturating_duration_since(Instant::now())
        .as_secs_f64()
        * 1000.0;
    let mut log = CallLog(vec![format!(
        "<launching> {} {}",
        request.executable_path,
        arguments.join(" ")
    )]);
    let spec = ChildLaunchSpec {
        executable: PathBuf::from(&request.executable_path),
        arguments: ChildLaunchSpec::arguments(arguments),
        working_directory: Some(PathBuf::from(&request.application_root)),
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let child = match OwnedChildProcess::launch_with_environment(spec, &environment, STDERR_CAPTURE)
    {
        Ok(child) => child,
        Err(error) => {
            let _ = remove_root(&root);
            log.push(format!("<launch error> {}", error.message));
            return Err(log.failure("Process failed to launch!"));
        }
    };
    let leader = child.id();
    log.push(format!("<launched> pid={leader}"));
    let mut owned = Owned {
        child: Some(child),
        root: Some(root),
        run_id,
        baseline,
        leader,
    };
    let found = wait_for_endpoints(&owned, &mut log, timeout_ms, deadline, cancellation);
    match found {
        Ok(endpoints) => Ok((owned, endpoints)),
        Err(error) => {
            // Playwright kills the launched process before rejecting.
            match release_processes(&mut owned) {
                Ok(_) => Err(error),
                Err(failure) => Err(failure.compose(Some(error), None)),
            }
        }
    }
}

fn wait_for_endpoints(
    owned: &Owned,
    log: &mut CallLog,
    timeout_ms: f64,
    deadline: Instant,
    cancellation: &Cancellation,
) -> Result<Endpoints, AnalysisError> {
    let child = owned.child.as_ref().expect("launched child");
    let pid = owned.leader;
    let mut consumed = 0usize;
    let (mut node, mut chrome) = (None, None);
    loop {
        if cancellation.reason().is_some() {
            return Err(observation("cancelled"));
        }
        let output = child
            .read_output()
            .map_err(|error| adapter(error.message))?;
        let complete = output.stderr[consumed..]
            .iter()
            .rposition(|byte| *byte == b'\n')
            .map(|end| consumed + end + 1);
        let end = if output.stderr_closed {
            output.stderr.len()
        } else {
            complete.unwrap_or(consumed)
        };
        for line in String::from_utf8_lossy(&output.stderr[consumed..end]).lines() {
            let line = line.trim_end_matches('\r');
            log.push(format!("[pid={pid}][err] {line}").trim_end().to_owned());
            if let Some(url) = line
                .strip_prefix("Debugger listening on ")
                .filter(|url| url.starts_with("ws://"))
            {
                node.get_or_insert_with(|| url.to_owned());
            }
            if let Some(url) = line
                .strip_prefix("DevTools listening on ")
                .filter(|url| url.starts_with("ws://"))
            {
                chrome.get_or_insert_with(|| url.to_owned());
            }
        }
        consumed = end;
        if let (Some(node), Some(chrome)) = (&node, &chrome) {
            return Ok(Endpoints {
                node: node.clone(),
                chrome: chrome.clone(),
            });
        }
        if let Ok(Some(exit)) = child.try_wait() {
            let signal = exit
                .signal
                .map_or_else(|| "null".to_owned(), |signal| signal.to_string());
            let code = if exit.signal.is_some() {
                "null".to_owned()
            } else {
                exit.code.to_string()
            };
            log.push(format!(
                "[pid={pid}] <process did exit: exitCode={code}, signal={signal}>"
            ));
            return Err(log.failure("Process failed to launch!"));
        }
        if output.stderr_closed {
            return Err(log.failure("Process failed to launch!"));
        }
        if Instant::now() >= deadline {
            return Err(log.failure(&format!("Timeout {timeout_ms}ms exceeded.")));
        }
        std::thread::sleep(POLL);
    }
}

// ---- Cleanup (`ElectronCaptureCleanup`) --------------------------------------

struct CleanupFailure {
    process: bool,
    reason: String,
    resources: Vec<String>,
}

impl CleanupFailure {
    /// The `cleanup_failed` observation, composed with a primary failure.
    fn compose(self, primary: Option<AnalysisError>, capture: Option<&Value>) -> AnalysisError {
        let prefix = if self.process {
            "Electron process cleanup could not be verified"
        } else {
            "Electron transport teardown failed after process cleanup"
        };
        let mut failure = cdp::observation_error(
            OPERATION,
            "cleanup_failed",
            Some(format!(
                "{prefix}: {}. Collected observations are retained when available.",
                self.reason
            )),
        )
        .with_cleanup(self.reason.clone(), self.resources.clone());
        if let Some(capture) = capture {
            let mut capture = capture.clone();
            if self.process {
                capture["application"]["cleanup"] = json!("unverified");
            }
            failure = failure.retain_partial_observation(partial(&capture));
        }
        match primary {
            None => failure,
            Some(primary) => {
                let retained = failure.clone();
                let composed = cleanup::with_cleanup_failure(primary, failure, OPERATION);
                match retained.project().pointer("/details/partial_observation") {
                    Some(observation) => composed.retain_partial_observation(observation.clone()),
                    None => composed,
                }
            }
        }
    }
}

/// Stop the owned process group, sweep token-owned descendants that left it,
/// then remove the REA temp root. Returns unverified unrelated processes.
fn release_processes(owned: &mut Owned) -> Result<Vec<(u32, String)>, CleanupFailure> {
    let mut failures = Vec::new();
    if let Some(mut child) = owned.child.take() {
        let exited = matches!(child.try_wait(), Ok(Some(_)));
        let settled = if exited {
            child.wait().map(|_| ())
        } else {
            child.cancel(1)
        };
        if let Err(error) = settled {
            failures.push(error.to_string());
            owned.child = Some(child);
        }
    }
    let relation = OwnershipRelation {
        leader_pid: owned.leader,
        process_group_id: owned.leader,
        sampled_process_group_ids: Vec::new(),
    };
    let swept = ownership::cleanup_token_owned_processes(&owned.run_id, &owned.baseline, &relation);
    if !swept.cleaned {
        failures.push(
            swept
                .reason
                .clone()
                .unwrap_or_else(|| "owned Electron processes could not be verified".to_owned()),
        );
    }
    if failures.is_empty()
        && let Some(root) = owned.root.take()
        && let Err(error) = remove_root(&root)
    {
        failures.push(format!(
            "Electron scenario directory {} could not be removed: {error}",
            root.display()
        ));
        owned.root = Some(root);
    }
    if failures.is_empty() {
        return Ok(swept
            .unverified
            .into_iter()
            .map(|item| (item.pid, item.diagnostic))
            .collect());
    }
    let mut resources = vec![
        "owned_process_group".to_owned(),
        format!("run:{}", owned.run_id),
        format!("process-group:{}", owned.leader),
    ];
    if owned.root.is_some() {
        resources.push("electron_scenario_directory".to_owned());
    }
    Err(CleanupFailure {
        process: true,
        reason: failures.join("; "),
        resources,
    })
}

/// `application.close()`: `app.quit()` over the main handle, close both
/// connections and wait (bounded) for the leader to exit.
fn release_transport(
    application: Option<Application>,
    owned: &Owned,
) -> Result<(), CleanupFailure> {
    let Some(mut application) = application else {
        return Ok(());
    };
    let request = Cancellation::default();
    let scope = Scope::new(&request, Some(CLOSE_TIMEOUT.as_millis() as u64));
    let _ = application
        .main
        .evaluate("({ app }) => app.quit()", Value::Null, &scope);
    application.main.inspector.close();
    application.renderer.close();
    let deadline = Instant::now() + CLOSE_TIMEOUT;
    while Instant::now() < deadline {
        match owned.child.as_ref().map(OwnedChildProcess::try_wait) {
            Some(Ok(Some(_))) | None => return Ok(()),
            _ => std::thread::sleep(POLL),
        }
    }
    let reason = cdp::observation_error(OPERATION, "timeout", None).message();
    Err(CleanupFailure {
        process: false,
        reason,
        resources: vec!["browser_transport".to_owned()],
    })
}

// ---- Capture (`PlaywrightElectronActiveProvider.capture`) --------------------

fn capture(
    request: &Canonical,
    environment: Vec<(OsString, OsString)>,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(observation("cancelled"));
    }
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    let disabled = crate::electron_fuses::node_cli_inspect_arguments_disabled(
        &request.executable_path,
        cancellation,
    );
    if cancellation.reason().is_some() {
        return Err(observation("cancelled"));
    }
    if disabled {
        return Err(AnalysisError::unsupported_target(
            OPERATION,
            request.executable_path.clone(),
            "Target binary disables the EnableNodeCliInspectArguments fuse; Node CLI inspector arguments are ignored and active scenario capture cannot attach.",
        )
        .with_remediation("Use passive CDP observation tools (inspect_electron_page), or launch active capture against an Electron development build or a stock Electron runtime with the extracted app."));
    }
    if Instant::now() >= deadline {
        return Err(observation("timeout"));
    }
    let (mut owned, endpoints) = launch(request, environment, deadline, cancellation)?;
    let paths = (
        request.executable_path.as_str(),
        request.application_path.as_str(),
    );
    let mut application: Option<Application> = None;
    let mut initial: Option<State> = None;
    let mut actions: Vec<Value> = Vec::new();
    let outcome = (|| -> Result<Value, AnalysisError> {
        let startup = Scope::new(
            cancellation,
            Some(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis()
                    .max(1) as u64,
            ),
        );
        let main = MainProcess::open(&endpoints.node, &startup).map_err(call_failure)?;
        let renderer = Renderer::open(&endpoints.chrome, &startup).map_err(call_failure)?;
        let app = application.insert(Application { main, renderer });
        let initial_state = read_state(&mut app.main, &startup)?;
        validate_application_root(&initial_state, &request.application_root)?;
        initial = Some(initial_state);
        actions = run_actions(app, &request.actions, cancellation);
        let state = read_final_state(&mut app.main, cancellation)?;
        Ok(project(paths, &actions, &state))
    })();
    let outcome = match outcome {
        Ok(capture) if cancellation.reason().is_some() => {
            Err((observation("cancelled"), Some(capture)))
        }
        Ok(capture) => Ok(capture),
        Err(error) => {
            let retained = initial.as_ref().map(|state| {
                let mut capture = project(paths, &actions, state);
                let cause = action_error_message(&error);
                if let Some(limitations) = capture["limitations"].as_array_mut() {
                    limitations.push(json!(format!(
                        "Capture stopped after the initial pre-action snapshot: {cause}. Final Windows, metrics, IPC, and timeline state is unknown; the retained snapshot may omit action effects."
                    )));
                }
                capture
            });
            // A failure observed under cancellation reports the cancellation;
            // incomplete cleanup keeps its own cause.
            let error = if cancellation.reason().is_some()
                && !error.is_cleanup_incomplete()
                && error.code() != "cancelled"
            {
                observation("cancelled")
            } else {
                error
            };
            Err((error, retained))
        }
    };
    let transport = release_transport(application, &owned);
    let processes = release_processes(&mut owned);
    let capture_ref = match &outcome {
        Ok(capture) => Some(capture.clone()),
        Err((_, capture)) => capture.clone(),
    };
    let failure = match (processes, transport) {
        (Err(failure), _) | (Ok(_), Err(failure)) => Some(failure),
        (Ok(unverified), Ok(())) => {
            if cancellation.reason().is_some() {
                // Late cancellation keeps the completed capture as partial Evidence.
                return match outcome {
                    Ok(capture) => {
                        Err(observation("cancelled").retain_partial_observation(partial(&capture)))
                    }
                    Err((error, capture)) => Err(with_partial(error, capture.as_ref())),
                };
            }
            return match outcome {
                Ok(mut capture) => {
                    if let Some(limitations) = capture["limitations"].as_array_mut() {
                        for (pid, diagnostic) in unverified {
                            limitations.push(json!(format!(
                                "Ownership of unrelated process {pid} could not be verified; it was left untouched: {diagnostic}"
                            )));
                        }
                    }
                    evidence(request, capture)
                }
                Err((error, capture)) => Err(with_partial(error, capture.as_ref())),
            };
        }
    };
    let failure = failure.expect("cleanup failure");
    Err(match outcome {
        Ok(_) => failure.compose(None, capture_ref.as_ref()),
        Err((error, _)) => failure.compose(Some(error), capture_ref.as_ref()),
    })
}

fn with_partial(error: AnalysisError, capture: Option<&Value>) -> AnalysisError {
    match capture {
        Some(capture) => error.retain_partial_observation(partial(capture)),
        None => error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refinements_follow_schema_order() {
        let input = json!({
            "executable_path": "electron",
            "application_path": "/a",
            "application_root": "rel",
            "actions": [{ "step_id": "d", "kind": "deep-link", "delivery": "open-url", "url": "not a url" }],
        });
        let refinements = parse(&input).err().unwrap();
        let paths: Vec<_> = refinements
            .iter()
            .map(|refinement| refinement.path.clone())
            .collect();
        assert_eq!(
            paths,
            vec![
                vec![json!("executable_path")],
                vec![json!("application_root")],
                vec![json!("actions"), json!(0), json!("url")]
            ]
        );
    }

    #[test]
    fn missing_paths_report_node_realpath_text() {
        let request = parse(
            &json!({ "executable_path": "/nonexistent/E", "application_path": "/nonexistent/a" }),
        )
        .ok()
        .unwrap();
        let issues = canonicalize(request).err().unwrap();
        assert_eq!(
            issues[0].message.as_deref(),
            Some(
                "Cannot resolve executable_path /nonexistent/E: ENOENT: no such file or directory, realpath '/nonexistent/E'"
            )
        );
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn omitted_root_is_the_application_directory_and_appended() {
        let root = tempfile::tempdir().unwrap();
        let app = root.path().join("app.asar");
        std::fs::write(&app, b"x").unwrap();
        let request = parse(
            &json!({ "executable_path": "/bin/sh", "application_path": app.to_string_lossy() }),
        )
        .ok()
        .unwrap();
        let canonical = canonicalize(request).unwrap();
        let resolved = std::fs::canonicalize(root.path()).unwrap();
        assert_eq!(canonical.application_root, resolved.to_string_lossy());
        let parameters = canonical.parameters();
        let keys: Vec<_> = parameters.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            keys,
            [
                "executable_path",
                "application_path",
                "args",
                "actions",
                "application_root",
                "scenario_sha256"
            ]
        );
    }

    #[test]
    fn projection_marks_hook_conflict_and_unavailable_families() {
        let state = State {
            application_root: "/a".into(),
            windows: json!([]),
            metrics: json!([]),
            version: "1.0.0".into(),
            snapshot: json!({
                "events": [{ "kind": "ipc-renderer-send", "process_type": "renderer" }],
                "retention_budget_bytes": 0, "estimated_retained_bytes": 0, "event_serialized_byte_upper_bound": 0,
                "retained": 1, "dropped": 0, "dropped_ipc": 0, "dropped_runtime": 0,
                "dropped_event_families": [], "dropped_event_roles": [],
                "observed": 1, "observed_ipc": 1, "observed_runtime": 0, "hook_error": true,
            }),
        };
        let capture = project(("/e", "/a"), &[], &state);
        assert_eq!(capture["coverage"]["status"], "hook_conflict");
        assert_eq!(
            capture["coverage"]["observed_event_families"],
            json!(["renderer-ipc"])
        );
        assert_eq!(capture["coverage"]["observed_roles"], json!(["renderer"]));
        assert_eq!(capture["ipc"]["events"].as_array().unwrap().len(), 1);
        assert!(
            capture["coverage"]["unavailable_event_families"]
                .as_array()
                .unwrap()
                .contains(&json!("preload"))
        );
        assert_eq!(
            capture["limitations"].as_array().unwrap().last().unwrap(),
            "The active IPC hook could not be installed."
        );
    }

    /// A launched process that never exposes the Node Inspector is stopped
    /// and its REA temp root removed (`Process failed to launch!`).
    #[test]
    fn early_exit_is_launch_failure_and_releases_everything() {
        let request = Canonical {
            executable_path: "/usr/bin/false".into(),
            application_path: "/tmp".into(),
            application_root: "/tmp".into(),
            root_selected: false,
            args: Vec::new(),
            actions: Vec::new(),
        };
        let error = capture(
            &request,
            safe_environment(&|name| std::env::var(name).ok()),
            &Cancellation::default(),
        )
        .err()
        .unwrap();
        let projection = error.project();
        let message = projection
            .pointer("/details/diagnostics/message")
            .and_then(Value::as_str)
            .unwrap();
        assert!(
            message.starts_with("electron.launch: Process failed to launch!\nCall log:\n"),
            "{message}"
        );
        let directory = message
            .split("--user-data-dir=")
            .nth(1)
            .unwrap()
            .split("/profile")
            .next()
            .unwrap();
        assert!(
            !Path::new(directory).exists(),
            "temp root {directory} was not removed"
        );
    }
}
