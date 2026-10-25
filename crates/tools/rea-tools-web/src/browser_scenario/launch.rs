//! Owned Chromium launch and external CDP attachment for one scenario.
//!
//! Compatibility owners: `src/browser/PlaywrightScenarioBrowser.ts`
//! (`openPlaywrightScenarioBrowser`, `allowedBrowserEnvironment`, the
//! private-profile cleanup owner, the attached-target admission and
//! `AttachedScenarioEnvironmentOwner`) and Playwright 1.58.2's
//! `chromiumSwitches.js` / `chromium.js` default arguments.
//!
//! Launch uses `rea_host::process::launcher` so the browser runs in an owned
//! process group with an explicit environment. Chromium's DevTools endpoint
//! is `--remote-debugging-port=0` on loopback (Playwright uses a pipe, which
//! the launcher does not expose); the endpoint is read from the private
//! profile's `DevToolsActivePort` and is reachable by other local processes
//! for the scenario's lifetime.
use super::driver::{CallError, Driver, Scope, World};
use super::input::{Environment, OPERATION};
use crate::cdp::{self, discovery};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_host::cdp_transport::CdpWebSocketTransport;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// `PLAYWRIGHT_CLEANUP_CONFIRMATION_TIMEOUT_MS`.
const CLEANUP_TIMEOUT: Duration = Duration::from_millis(30_000);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const MESSAGE_BYTES: usize = 256 * 1024 * 1024;
const STDERR_CAPTURE: usize = 64 * 1024;

/// `allowedBrowserEnvironment`.
const ALLOWED_ENVIRONMENT: [&str; 13] = [
    "DBUS_SESSION_BUS_ADDRESS",
    "DISPLAY",
    "HOME",
    "LANG",
    "LD_LIBRARY_PATH",
    "PATH",
    "SystemRoot",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WAYLAND_DISPLAY",
    "XAUTHORITY",
    "XDG_RUNTIME_DIR",
];

const DISABLED_FEATURES: [&str; 15] = [
    "AvoidUnnecessaryBeforeUnloadCheckSync",
    "BoundaryEventDispatchTracksNodeRemoval",
    "DestroyProfileOnBrowserClose",
    "DialMediaRouteProvider",
    "GlobalMediaControls",
    "HttpsUpgrades",
    "LensOverlay",
    "MediaRouter",
    "PaintHolding",
    "ThirdPartyStoragePartitioning",
    "Translate",
    "AutoDeElevate",
    "RenderDocument",
    "OptimizationHints",
    "",
];

/// Playwright 1.58.2 `chromiumSwitches()` for a non-assistant launch.
fn chromium_switches() -> Vec<String> {
    let features: Vec<&str> = DISABLED_FEATURES
        .iter()
        .copied()
        .filter(|item| !item.is_empty())
        .collect();
    let mut switches: Vec<String> = [
        "--disable-field-trial-config",
        "--disable-background-networking",
        "--disable-background-timer-throttling",
        "--disable-backgrounding-occluded-windows",
        "--disable-back-forward-cache",
        "--disable-breakpad",
        "--disable-client-side-phishing-detection",
        "--disable-component-extensions-with-background-pages",
        "--disable-component-update",
        "--no-default-browser-check",
        "--disable-default-apps",
        "--disable-dev-shm-usage",
        "--disable-extensions",
    ]
    .iter()
    .map(|item| (*item).to_owned())
    .collect();
    switches.push(format!("--disable-features={}", features.join(",")));
    switches.extend(
        [
            "--enable-features=CDPScreenshotNewSurface",
            "--allow-pre-commit-input",
            "--disable-hang-monitor",
            "--disable-ipc-flooding-protection",
            "--disable-popup-blocking",
            "--disable-prompt-on-repost",
            "--disable-renderer-backgrounding",
            "--force-color-profile=srgb",
            "--metrics-recording-only",
            "--no-first-run",
            "--password-store=basic",
            "--use-mock-keychain",
            "--no-service-autorun",
            "--export-tagged-pdf",
            "--disable-search-engine-choice-screen",
            "--unsafely-disable-devtools-self-xss-warnings",
            "--edge-skip-compat-layer-relaunch",
            "--enable-automation",
            "--disable-infobars",
            "--disable-search-engine-choice-screen",
            "--disable-sync",
        ]
        .iter()
        .map(|item| (*item).to_owned()),
    );
    switches
}

fn launch_arguments(profile: &Path, headless: bool) -> Vec<String> {
    let mut arguments = chromium_switches();
    if !cfg!(target_os = "macos") {
        arguments.push("--enable-unsafe-swiftshader".to_owned());
    }
    if headless {
        arguments.extend(
            [
                "--headless", "--hide-scrollbars", "--mute-audio",
                "--blink-settings=primaryHoverType=2,availableHoverTypes=2,primaryPointerType=4,availablePointerTypes=4",
            ]
            .iter()
            .map(|item| (*item).to_owned()),
        );
    }
    arguments.push("--no-sandbox".to_owned());
    arguments.push(format!("--user-data-dir={}", profile.display()));
    arguments.push("--remote-debugging-port=0".to_owned());
    arguments.push("--remote-debugging-address=127.0.0.1".to_owned());
    arguments.push("about:blank".to_owned());
    arguments
}

fn browser_environment(environment: &BTreeMap<String, String>) -> Vec<(OsString, OsString)> {
    ALLOWED_ENVIRONMENT
        .iter()
        .filter_map(|name| {
            environment
                .get(*name)
                .map(|value| (OsString::from(name), OsString::from(value)))
        })
        .collect()
}

/// What `close()` reports when it succeeds.
#[derive(Clone, Copy, Debug)]
pub(crate) enum CleanupKind {
    TerminatedOwnedProcess,
    DisconnectedExternal,
}

impl CleanupKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::TerminatedOwnedProcess => "terminated-owned-process",
            Self::DisconnectedExternal => "disconnected-external",
        }
    }
}

/// Resources that remain owned after a failed release.
#[derive(Clone, Debug)]
pub(crate) struct CleanupFailure {
    pub reason: String,
    pub resources: Vec<String>,
}

/// The owner of everything one scenario acquired.
pub(crate) enum Ownership {
    Launched {
        child: Option<OwnedChildProcess>,
        profile: Option<PathBuf>,
    },
    Attached {
        admission: Option<AdmissionGuard>,
        target_session: String,
        overrides: Overrides,
    },
}

/// Emulation overrides applied to an external target, for restoration.
#[derive(Clone, Debug, Default)]
pub(crate) struct Overrides {
    pub media: bool,
    pub metrics: bool,
    pub locale: bool,
    pub timezone: bool,
}

pub(crate) struct Opened {
    pub driver: Driver,
    pub ownership: Ownership,
}

/// `ProviderAdapterError`: the TS owner projects no diagnostics for launch,
/// attach or transport failures, so the producer detail stays internal.
fn adapter_failure(detail: impl Into<String>) -> AnalysisError {
    let _ = detail.into();
    AnalysisError::provider_adapter(super::PROVIDER_ID, OPERATION)
}

fn cancelled() -> AnalysisError {
    cdp::observation_error(OPERATION, "cancelled", None)
}

/// Launch Chromium from the caller-selected executable with a private profile.
pub(crate) fn launch(
    executable: &str,
    headless: bool,
    environment: &BTreeMap<String, String>,
    world: World,
    cancellation: &Cancellation,
) -> Result<Opened, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(cancelled());
    }
    let profile = tempfile::Builder::new()
        .prefix("rea-browser-scenario-")
        .tempdir()
        .map_err(|error| {
            adapter_failure(format!(
                "Could not create the private browser profile: {error}"
            ))
        })?
        .keep();
    let remove_profile = |profile: &Path| remove_profile(profile);
    let spec = ChildLaunchSpec {
        executable: PathBuf::from(executable),
        arguments: ChildLaunchSpec::arguments(launch_arguments(&profile, headless)),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let mut child = match OwnedChildProcess::launch_with_environment(
        spec,
        &browser_environment(environment),
        STDERR_CAPTURE,
    ) {
        Ok(child) => child,
        Err(error) => {
            let _ = remove_profile(&profile);
            return Err(adapter_failure(format!(
                "Failed to launch the browser: {error}"
            )));
        }
    };
    let endpoint = match wait_for_endpoint(&mut child, &profile, cancellation) {
        Ok(endpoint) => endpoint,
        Err(error) => {
            let _ = child.cancel(1);
            let _ = remove_profile(&profile);
            return Err(error);
        }
    };
    let transport = match CdpWebSocketTransport::connect_with_limits(
        &endpoint,
        None,
        REQUEST_TIMEOUT,
        MESSAGE_BYTES,
    ) {
        Ok(mut transport) => {
            transport.set_event_buffer_limits(usize::MAX, MESSAGE_BYTES);
            transport
        }
        Err(error) => {
            let _ = child.cancel(1);
            let _ = remove_profile(&profile);
            return Err(adapter_failure(format!(
                "Could not connect to the launched browser: {error}"
            )));
        }
    };
    let mut opened = Opened {
        driver: Driver::new(transport, world),
        ownership: Ownership::Launched {
            child: Some(child),
            profile: Some(profile),
        },
    };
    if let Err(error) = initialize_launched(&mut opened.driver, cancellation) {
        let _ = close(&mut opened, false);
        return Err(error);
    }
    Ok(opened)
}

fn wait_for_endpoint(
    child: &mut OwnedChildProcess,
    profile: &Path,
    cancellation: &Cancellation,
) -> Result<String, AnalysisError> {
    let file = profile.join("DevToolsActivePort");
    loop {
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        if let Ok(text) = std::fs::read_to_string(&file) {
            let mut lines = text.lines();
            if let (Some(port), Some(path)) = (lines.next(), lines.next())
                && port.trim().parse::<u16>().is_ok()
                && path.starts_with("/devtools/browser/")
            {
                return Ok(format!("ws://127.0.0.1:{}{}", port.trim(), path.trim()));
            }
        }
        if let Ok(Some(exit)) = child.try_wait() {
            let stderr = child
                .read_output()
                .map(|output| String::from_utf8_lossy(&output.stderr).into_owned())
                .unwrap_or_default();
            return Err(adapter_failure(format!(
                "Browser process exited before exposing its DevTools endpoint (code {}): {}",
                exit.code,
                stderr.trim()
            )));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn initialize_launched(
    driver: &mut Driver,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    let scope = Scope::new(cancellation, None);
    let version = driver
        .call(None, "Browser.getVersion", json!({}), &scope)
        .map_err(|error| call_failure(&error))?;
    driver.product = version
        .get("product")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    driver.version = driver
        .product
        .split_once('/')
        .map(|(_, version)| version.to_owned())
        .unwrap_or_else(|| driver.product.clone());
    driver.user_agent = version
        .get("userAgent")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    driver.select_font_families();
    let _ = driver.call(
        None,
        "Browser.setDownloadBehavior",
        json!({ "behavior": "deny", "eventsEnabled": true }),
        &scope,
    );
    // Pages are not held at start: `window.open` is synchronous for the
    // opener, and this single-threaded owner only initializes a new target
    // after the opener's in-flight command returns. Popup activity before
    // initialization is reported as a coverage gap, as the TS owner does.
    driver
        .call(
            None,
            "Target.setAutoAttach",
            json!({ "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true }),
            &scope,
        )
        .map_err(|error| call_failure(&error))?;
    driver
        .wait_until(&scope, |world| {
            world.main_session.is_some() && world.main_frame.is_some()
        })
        .map_err(|error| call_failure(&error))
}

pub(crate) fn call_failure(error: &CallError) -> AnalysisError {
    match error {
        CallError::Cancelled => cancelled(),
        CallError::Deadline => AnalysisError::timeout(OPERATION, 0),
        CallError::Protocol(message) | CallError::Closed(message) => {
            adapter_failure(message.clone())
        }
    }
}

// ---- Attached-target admission (`attachedScenarioLeaseKey`) ---------------

fn admissions() -> &'static (Mutex<BTreeSet<String>>, Condvar) {
    static ADMISSIONS: OnceLock<(Mutex<BTreeSet<String>>, Condvar)> = OnceLock::new();
    ADMISSIONS.get_or_init(|| (Mutex::new(BTreeSet::new()), Condvar::new()))
}

/// One active scenario per loopback CDP browser and target.
pub(crate) struct AdmissionGuard {
    key: String,
}

impl Drop for AdmissionGuard {
    fn drop(&mut self) {
        let (lock, signal) = admissions();
        if let Ok(mut active) = lock.lock() {
            active.remove(&self.key);
        }
        signal.notify_all();
    }
}

/// `attachedScenarioLeaseKey`: loopback spellings share one admission.
fn admission_key(endpoint: &str, target_id: &str) -> String {
    let mut discovery = url::Url::parse(endpoint)
        .and_then(|base| base.join("/json/version"))
        .map(|url| url.to_string())
        .unwrap_or_else(|_| endpoint.to_owned());
    if let Ok(mut url) = url::Url::parse(&discovery)
        && url
            .host_str()
            .is_some_and(crate::cdp::urls::is_literal_loopback_hostname)
    {
        let _ = url.set_host(Some("127.0.0.1"));
        discovery = url.to_string();
    }
    serde_json::to_string(&json!([discovery, target_id])).unwrap_or_default()
}

fn acquire(
    endpoint: &str,
    target_id: &str,
    cancellation: &Cancellation,
) -> Result<AdmissionGuard, AnalysisError> {
    let key = admission_key(endpoint, target_id);
    let (lock, signal) = admissions();
    let mut active = lock
        .lock()
        .map_err(|_| adapter_failure("admission state was poisoned"))?;
    loop {
        if cancellation.reason().is_some() {
            return Err(cancelled());
        }
        if active.insert(key.clone()) {
            return Ok(AdmissionGuard { key });
        }
        active = signal
            .wait_timeout(active, Duration::from_millis(50))
            .map_err(|_| adapter_failure("admission state was poisoned"))?
            .0;
    }
}

/// Attach to one caller-owned page target over loopback CDP.
pub(crate) fn connect(
    endpoint: &str,
    target_id: &str,
    environment: &Environment,
    service_worker_policy: bool,
    world: World,
    cancellation: &Cancellation,
) -> Result<Opened, AnalysisError> {
    let admission = acquire(endpoint, target_id, cancellation)?;
    // `chromium.connectOverCDP` failures surface as a provider adapter error.
    let discovered = discovery::open(
        &cdp::parse_http_endpoint(endpoint).map_err(adapter_failure)?,
        OPERATION,
        cancellation,
    )
    .map_err(|error| {
        if cancellation.reason().is_some() {
            cancelled()
        } else {
            adapter_failure(error.message())
        }
    })?;
    if !matches!(discovered.web_socket, discovery::WebSocketEndpoint::Browser) {
        return Err(adapter_failure(
            "CDP endpoint did not report a browser socket",
        ));
    }
    let browser_socket = discovered.web_socket_url.clone();
    let mut transport = CdpWebSocketTransport::connect_with_limits(
        &browser_socket,
        None,
        REQUEST_TIMEOUT,
        MESSAGE_BYTES,
    )
    .map_err(|error| adapter_failure(error.to_string()))?;
    let Some(target) = discovered
        .targets
        .iter()
        .find(|target| target.id == target_id && target.kind == "page")
    else {
        return Err(cdp::observation_error(OPERATION, "target_not_found", None));
    };
    // The service-worker policy owner authorizes an HTTP(S) page target
    // (`authorizeCdpTarget`) before it installs its registration wrapper.
    if service_worker_policy
        && crate::cdp::urls::sanitize_browser_url(&target.url)
            .origin
            .is_none()
    {
        return Err(cdp::observation_error(
            OPERATION,
            "target_not_allowed",
            Some(format!(
                "Target {target_id} must be an HTTP(S) page in the selected origin scope."
            )),
        ));
    }
    transport.set_event_buffer_limits(usize::MAX, MESSAGE_BYTES);
    let mut driver = Driver::new(transport, world);
    let scope = Scope::new(cancellation, None);
    let version = driver
        .call(None, "Browser.getVersion", json!({}), &scope)
        .map_err(|error| call_failure(&error))?;
    driver.product = version
        .get("product")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    driver.version = driver
        .product
        .split_once('/')
        .map(|(_, version)| version.to_owned())
        .unwrap_or_else(|| driver.product.clone());
    let attached = driver
        .call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
            &scope,
        )
        .map_err(|error| match error {
            CallError::Protocol(_) => cdp::observation_error(OPERATION, "target_not_found", None),
            other => call_failure(&other),
        })?;
    let session = attached
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let mut opened = Opened {
        driver,
        ownership: Ownership::Attached {
            admission: Some(admission),
            target_session: session.clone(),
            overrides: Overrides::default(),
        },
    };
    if let Err(error) = apply_attached_environment(&mut opened, &session, environment, cancellation)
    {
        let _ = close(&mut opened, false);
        return Err(error);
    }
    Ok(opened)
}

/// `AttachedScenarioEnvironmentOwner.apply`.
fn apply_attached_environment(
    opened: &mut Opened,
    session: &str,
    environment: &Environment,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    let scope = Scope::new(cancellation, None);
    let driver = &mut opened.driver;
    driver
        .wait_until(&scope, |world| world.main_session.is_some())
        .map_err(|error| call_failure(&error))?;
    driver
        .wait_until(&scope, |world| {
            world.main_frame.is_some() || world.page_closed
        })
        .map_err(|error| call_failure(&error))?;
    let Ownership::Attached { overrides, .. } = &mut opened.ownership else {
        return Ok(());
    };
    let s = Some(session);
    driver
        .call(
            s,
            "Emulation.setEmulatedMedia",
            json!({ "media": "", "features": [
                { "name": "prefers-color-scheme", "value": environment.color_scheme },
                { "name": "prefers-reduced-motion", "value": environment.reduced_motion },
                { "name": "forced-colors", "value": "" },
                { "name": "prefers-contrast", "value": "" },
            ] }),
            &scope,
        )
        .map_err(|error| call_failure(&error))?;
    overrides.media = true;
    driver
        .call(
            s,
            "Emulation.setDeviceMetricsOverride",
            json!({
                "width": environment.width,
                "height": environment.height,
                "deviceScaleFactor": environment.device_scale_factor,
                "mobile": false,
                "dontSetVisibleSize": true,
            }),
            &scope,
        )
        .map_err(|error| call_failure(&error))?;
    overrides.metrics = true;
    driver
        .call(
            s,
            "Emulation.setLocaleOverride",
            json!({ "locale": environment.locale }),
            &scope,
        )
        .map_err(|error| call_failure(&error))?;
    overrides.locale = true;
    driver
        .call(
            s,
            "Emulation.setTimezoneOverride",
            json!({ "timezoneId": environment.timezone }),
            &scope,
        )
        .map_err(|error| call_failure(&error))?;
    overrides.timezone = true;
    Ok(())
}

fn remove_profile(profile: &Path) -> Result<(), String> {
    let mut last = String::new();
    for _ in 0..4 {
        match std::fs::remove_dir_all(profile) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => last = error.to_string(),
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

/// Release every owned resource; failures keep their owners for retry.
pub(crate) fn close(
    opened: &mut Opened,
    stop_loading: bool,
) -> Result<CleanupKind, CleanupFailure> {
    let request = Cancellation::default();
    let scope = Scope::new(&request, Some(CLEANUP_TIMEOUT.as_millis() as u64));
    match &mut opened.ownership {
        Ownership::Launched { child, profile } => {
            let mut failures = Vec::new();
            if let Some(mut owned) = child.take() {
                if stop_loading {
                    let _ = opened
                        .driver
                        .main_call("Page.stopLoading", json!({}), &scope);
                }
                let _ = opened.driver.call(None, "Browser.close", json!({}), &scope);
                opened.driver.disconnect();
                let deadline = Instant::now() + CLEANUP_TIMEOUT;
                let mut exited = false;
                while Instant::now() < deadline {
                    if matches!(owned.try_wait(), Ok(Some(_))) {
                        exited = true;
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                let settled = if exited {
                    owned.wait().map(|_| ())
                } else {
                    Err(rea_host::process::launcher::ProcessLaunchError {
                        operation: "close_browser",
                        message: "browser did not exit".into(),
                        cleanup: None,
                    })
                };
                if settled.is_err()
                    && let Err(error) = owned.cancel(1)
                {
                    failures.push(error.to_string());
                    *child = Some(owned);
                }
            }
            if child.is_none()
                && let Some(path) = profile.take()
                && let Err(error) = remove_profile(&path)
            {
                failures.push(error);
                *profile = Some(path);
            }
            if failures.is_empty() {
                return Ok(CleanupKind::TerminatedOwnedProcess);
            }
            let mut resources = Vec::new();
            if child.is_some() {
                resources.push("browser_transport".to_owned());
            }
            if profile.is_some() {
                resources.push("browser_profile".to_owned());
            }
            Err(CleanupFailure {
                reason: failures.join("; "),
                resources,
            })
        }
        Ownership::Attached {
            admission,
            target_session,
            overrides,
        } => {
            let session = target_session.clone();
            let s = Some(session.as_str());
            let mut failures = Vec::new();
            if stop_loading {
                let _ = opened.driver.call(s, "Page.stopLoading", json!({}), &scope);
            }
            if opened.driver.connected() && !opened.driver.world.page_closed {
                let mut restore =
                    |driver: &mut Driver, flag: &mut bool, method: &str, params: Value| {
                        if *flag {
                            match driver.call(s, method, params, &scope) {
                                Ok(_) => *flag = false,
                                Err(error) => failures.push(error.message()),
                            }
                        }
                    };
                restore(
                    &mut opened.driver,
                    &mut overrides.timezone,
                    "Emulation.setTimezoneOverride",
                    json!({ "timezoneId": "" }),
                );
                restore(
                    &mut opened.driver,
                    &mut overrides.locale,
                    "Emulation.setLocaleOverride",
                    json!({ "locale": "" }),
                );
                restore(
                    &mut opened.driver,
                    &mut overrides.metrics,
                    "Emulation.clearDeviceMetricsOverride",
                    json!({}),
                );
                restore(
                    &mut opened.driver,
                    &mut overrides.media,
                    "Emulation.setEmulatedMedia",
                    json!({ "media": "", "features": [
                        { "name": "prefers-color-scheme", "value": "" },
                        { "name": "prefers-reduced-motion", "value": "" },
                        { "name": "forced-colors", "value": "" },
                        { "name": "prefers-contrast", "value": "" },
                    ] }),
                );
                for script in std::mem::take(&mut opened.driver.world.init_script_ids) {
                    let _ = opened.driver.call(
                        s,
                        "Page.removeScriptToEvaluateOnNewDocument",
                        json!({ "identifier": script }),
                        &scope,
                    );
                }
                opened.driver.remove_seed_scripts(&scope);
                if failures.is_empty() {
                    let _ = opened.driver.call(
                        None,
                        "Target.detachFromTarget",
                        json!({ "sessionId": session }),
                        &scope,
                    );
                }
            }
            if !failures.is_empty() && opened.driver.connected() && !opened.driver.world.page_closed
            {
                return Err(CleanupFailure {
                    reason: failures.join("; "),
                    resources: vec!["browser_transport".to_owned()],
                });
            }
            opened.driver.disconnect();
            admission.take();
            Ok(CleanupKind::DisconnectedExternal)
        }
    }
}
