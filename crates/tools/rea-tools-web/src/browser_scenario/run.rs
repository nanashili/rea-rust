//! One controlled scenario: open, initial state, actions, finish, cleanup.
//!
//! Compatibility owners: `src/browser/PlaywrightBrowserScenarioProvider.ts`
//! (`runScenario`, step projection, completeness), `PlaywrightScenarioSession`
//! (`open`, `perform`, `capture`, `close`), `BrowserScenarioPartialObservation`
//! (capture data, limitations, failure projection),
//! `src/application/BrowserScenarioCaptureService.ts` and
//! `BrowserScenarioEvidence.ts`.
use super::actions::{self, ActionError};
use super::artifacts::{self, SNAPSHOT_KINDS};
use super::driver::{CallError, Driver, Scope, World};
use super::input::{BrowserSelection, OPERATION, Scenario};
use super::launch::{self, CleanupKind, Opened};
use super::network::Network;
use super::recorder::{Families, Recorder};
use super::secrets::Secrets;
use super::{PROVIDER_ID, provider};
use crate::cdp;
use crate::comparisons::digest::digest_canonical_value;
use rea_core::analysis_error::{AnalysisError, cleanup};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, Observation};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

/// Playwright's context option blocking service-worker registration (launch).
const SERVICE_WORKER_BLOCK: &str = "\nif (navigator.serviceWorker) navigator.serviceWorker.register = async () => { console.warn('Service Worker registration blocked by Playwright'); };\n";

/// `PlaywrightScenarioServiceWorkers` (connect): a restorable registration
/// wrapper on the caller's page, and the controller/registration check.
struct ServiceWorkerPolicy {
    marker: String,
    restore_key: String,
    secret: String,
}

fn random_token() -> String {
    let mut bytes = [0u8; 16];
    let filled = std::fs::File::open("/dev/urandom")
        .and_then(|mut file| std::io::Read::read_exact(&mut file, &mut bytes));
    if filled.is_err() {
        let seed = format!(
            "{:?}{}{:p}",
            std::time::SystemTime::now(),
            std::process::id(),
            &bytes
        );
        bytes.copy_from_slice(&super::secrets::sha256_hex(seed.as_bytes()).as_bytes()[..16]);
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl ServiceWorkerPolicy {
    fn new() -> Self {
        let quote = |value: String| serde_json::to_string(&value).unwrap_or_default();
        Self {
            marker: quote(format!("rea-service-workers-{}", random_token())),
            restore_key: quote(format!("rea-restore-{}", random_token())),
            secret: quote(random_token()),
        }
    }

    fn install_script(&self) -> String {
        let (marker, key, secret) = (&self.marker, &self.restore_key, &self.secret);
        format!(
            "(() => {{\n  if (!(\"serviceWorker\" in navigator)) return;\n  const prototype = ServiceWorkerContainer.prototype;\n  const descriptor = Object.getOwnPropertyDescriptor(prototype, \"register\");\n  if (typeof descriptor?.value === \"function\" && Object.hasOwn(descriptor.value, Symbol.for({marker}))) return;\n  const register = () => Promise.reject(new Error(\"service workers are blocked by scenario policy\"));\n  Object.defineProperty(register, Symbol.for({marker}), {{ value: true }});\n  const secret = {secret};\n  Object.defineProperty(globalThis, {key}, {{ configurable: true, value: (provided) => {{\n    if (provided !== secret) return false;\n    if (Object.getOwnPropertyDescriptor(prototype, \"register\")?.value === register) {{\n      if (descriptor === undefined) delete prototype.register;\n      else Object.defineProperty(prototype, \"register\", descriptor);\n    }}\n    delete globalThis[{key}];\n    return true;\n  }}}});\n  Object.defineProperty(prototype, \"register\", {{ ...descriptor, configurable: true, value: register }});\n}})()"
        )
    }

    fn restore_script(&self) -> String {
        format!(
            "(() => {{ const restore = globalThis[{0}]; if (typeof restore === \"function\") restore({1}); return null; }})()",
            self.restore_key, self.secret
        )
    }

    fn assert_script(&self) -> String {
        format!(
            "(async () => {{ if (!(\"serviceWorker\" in navigator)) return null; const serviceWorker = navigator.serviceWorker; \
             if (!Object.hasOwn(serviceWorker.register, Symbol.for({0})) || typeof globalThis[{1}] !== \"function\") return \"policy_unprotected\"; \
             if (serviceWorker.controller !== null) return \"service_worker_blocked\"; \
             return (await serviceWorker.getRegistrations()).length > 0 ? \"service_worker_blocked\" : null; }})()",
            self.marker, self.restore_key
        )
    }
}

/// `assertBlocked` for the main frame of an attached page.
fn assert_blocked(session: &mut Session, scope: &Scope) -> Result<(), AnalysisError> {
    let Some(policy) = &session.service_workers else {
        return Ok(());
    };
    let script = policy.assert_script();
    match session.driver().evaluate_main(&script, scope) {
        Ok(Value::String(reason)) => Err(cdp::observation_error(
            OPERATION,
            match reason.as_str() {
                "policy_unprotected" => "target_not_allowed",
                "service_worker_blocked" => "service_worker_blocked",
                _ => "protocol_error",
            },
            None,
        )),
        Ok(_) => Ok(()),
        Err(CallError::Cancelled) => Err(AnalysisError::cancelled(OPERATION)),
        Err(error) => Err(launch::call_failure(&error)),
    }
}

struct Session {
    opened: Opened,
    mode: &'static str,
    initial_url: String,
    viewport: Option<(u64, u64)>,
    service_workers: Option<ServiceWorkerPolicy>,
}

impl Session {
    fn driver(&mut self) -> &mut Driver {
        &mut self.opened.driver
    }
}

fn requested_for_step(scenario: &Scenario, index: usize) -> BTreeSet<String> {
    let mut requested: BTreeSet<String> =
        scenario.capture.after_each_step.iter().cloned().collect();
    if index == scenario.actions.len() {
        requested.extend(scenario.capture.at_end.iter().cloned());
    }
    requested
}

/// `classifyBrowserScenarioCompleteness`.
fn completeness(missing: Vec<String>, truncated: Vec<String>) -> Value {
    let missing: BTreeSet<String> = missing.into_iter().collect();
    let truncated: BTreeSet<String> = truncated.into_iter().collect();
    if !truncated.is_empty() {
        return json!({ "status": "truncated", "equality_eligible": false, "missing_sections": missing, "truncated_sections": truncated });
    }
    if !missing.is_empty() {
        return json!({ "status": "incomplete", "equality_eligible": false, "missing_sections": missing, "truncated_sections": [] });
    }
    json!({ "status": "complete", "equality_eligible": true, "missing_sections": [], "truncated_sections": [] })
}

fn step_completeness(artifacts: &Value, status: &str) -> Value {
    let state = |kind: &str| {
        artifacts
            .get(kind)
            .and_then(|item| item.get("state"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut missing: Vec<String> = SNAPSHOT_KINDS
        .iter()
        .filter(|kind| state(kind) == "missing")
        .map(|kind| (*kind).to_owned())
        .collect();
    let truncated: Vec<String> = SNAPSHOT_KINDS
        .iter()
        .filter(|kind| state(kind) == "truncated")
        .map(|kind| (*kind).to_owned())
        .collect();
    if status != "completed" {
        missing.push("action".to_owned());
    }
    completeness(missing, truncated)
}

#[allow(clippy::too_many_arguments)]
fn step(
    index: usize,
    step_id: &str,
    action: &str,
    status: &str,
    error: Option<String>,
    elapsed_ms: u128,
    before_url: Value,
    after_url: Value,
    event_start: u64,
    event_end: u64,
    artifacts: Value,
) -> Value {
    let completeness = step_completeness(&artifacts, status);
    json!({
        "step_index": index,
        "step_id": step_id,
        "action": action,
        "elapsed_ms": elapsed_ms,
        "before_url": before_url,
        "after_url": after_url,
        "event_sequence_start": event_start,
        "event_sequence_end": event_end,
        "artifacts": artifacts,
        "completeness": completeness,
        "status": status,
        "error": error,
    })
}

fn limitations(session: &Session, scenario: &Scenario, events: &[Value]) -> Vec<String> {
    let world = &session.opened.driver.world;
    let captured_response_body = scenario.capture.network.response_body
        && events.iter().any(|event| {
            event.get("kind").and_then(Value::as_str) == Some("network-content")
                && event.get("phase").and_then(Value::as_str) == Some("response")
                && event.pointer("/body/state").and_then(Value::as_str) == Some("captured")
        });
    let mut limitations: Vec<String> = vec![
        "Event sequence records provider receipt order; simultaneous browser causality is not inferred.".into(),
        "Network content is retained only when selected; Playwright response-body bytes are API results and are not guaranteed to match wire bytes.".into(),
        "Request bytes are limited to what Playwright exposes; not_exposed does not establish body absence or multipart file coverage.".into(),
        "Network content reads settle within 5 seconds each and the observer does not request bodies from unfinished responses.".into(),
    ];
    if captured_response_body {
        limitations.push("Captured response-body bytes are the result of Playwright's Response.body() API. Playwright may satisfy that API with a credentialed follow-up load of the request URL when CDP has no body, so transaction and event links do not verify that retained bytes came from the original network transaction.".into());
    }
    limitations.push("Playwright scenario events do not expose request initiator stacks; receipt order does not prove causality.".into());
    limitations.push("Storage values are hashed only after declared-secret redaction.".into());
    if !scenario.local_storage.is_empty() || !scenario.session_storage.is_empty() {
        limitations.push("Non-cookie storage seeds use CDP pre-script instrumentation; only pauses in the scenario's private seed script are resumed by this observer.".into());
    }
    limitations.extend(event_limitations(world));
    if session.mode == "connect" {
        limitations.push("CDP attachment cannot recover pre-attach events or guarantee launch-time context options.".into());
        limitations.push(format!(
            "Attached locale {} applies to Intl formatting only; navigator.language(s) and Accept-Language remain caller-controlled. Use launch mode for matching page and request languages.",
            scenario.environment.locale
        ));
        limitations.push("Detaching a CDP page session may clear caller-owned navigator.platform emulation. REA cannot snapshot the caller's complete user-agent/client-hint state before attachment; use launch mode to avoid mutating that external browser.".into());
    }
    limitations
}

fn event_limitations(world: &World) -> Vec<String> {
    let gaps = world
        .network
        .as_ref()
        .map(Network::limitations)
        .unwrap_or_default();
    world.recorder.limitations(gaps)
}

/// `browserScenarioCaptureData`.
fn capture_data(
    session: &Session,
    scenario: &Scenario,
    started: Instant,
    steps: &[Value],
    cleanup: &str,
    extra: &[&str],
) -> Map<String, Value> {
    let world = &session.opened.driver.world;
    let range = world
        .network
        .as_ref()
        .map(Network::omitted_range)
        .unwrap_or(Value::Null);
    let events = world.recorder.result(range);
    let items = world.recorder.items().to_vec();
    let mut limitations = limitations(session, scenario, &items);
    limitations.extend(extra.iter().map(|item| (*item).to_owned()));
    let start_origin = url::Url::parse(&scenario.start_url.url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_default();
    let mut secret_references: Vec<String> = scenario
        .secrets
        .iter()
        .map(|secret| secret.secret_id.clone())
        .collect();
    secret_references.sort();
    let families: BTreeSet<&String> = scenario.capture.events.iter().collect();
    let mut data = Map::new();
    data.insert(
        "browser".into(),
        json!({
            "mode": session.mode,
            "process_ownership": if session.mode == "launch" { "provider-owned" } else { "external" },
            "cleanup": cleanup,
            "product": "Chromium",
            "version": session.opened.driver.version,
        }),
    );
    data.insert(
        "scenario".into(),
        json!({
            "start_origin": start_origin,
            "action_count": scenario.actions.len(),
            "secret_references": secret_references,
            "network_content": scenario.capture.network_value,
            "event_families": families,
            "limits": scenario.capture.limits_value,
        }),
    );
    data.insert("duration_ms".into(), json!(started.elapsed().as_millis()));
    data.insert("steps".into(), json!(steps));
    data.insert("events".into(), events);
    data.insert("limitations".into(), json!(limitations));
    data
}

fn partial(data: Map<String, Value>) -> Value {
    json!({ "kind": "browser-scenario-observation", "capture": Value::Object(data) })
}

/// The ambient environment, read once per request for secrets and launch.
fn environment() -> BTreeMap<String, String> {
    std::env::vars_os()
        .filter_map(|(name, value)| Some((name.into_string().ok()?, value.into_string().ok()?)))
        .collect()
}

fn families(scenario: &Scenario) -> Families {
    let mut enabled: BTreeSet<String> = scenario.capture.events.iter().cloned().collect();
    let network = &scenario.capture.network;
    if network.request_body || network.response_body || network.header_values {
        enabled.insert("network".to_owned());
    }
    Families { enabled }
}

/// `addSeeds`: resolved entries per exact origin, in declaration order.
fn seeds(
    items: &[super::input::StorageSeed],
    secrets: &Secrets,
) -> BTreeMap<String, Vec<(String, String)>> {
    let mut table: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
    for seed in items {
        let entries = table.entry(seed.origin.clone()).or_default();
        entries.extend(
            seed.entries
                .iter()
                .map(|(name, value)| (name.clone(), secrets.value(value))),
        );
    }
    table
}

fn open(
    scenario: &Scenario,
    secrets: Secrets,
    cancellation: &Cancellation,
    environment: &BTreeMap<String, String>,
) -> Result<Session, AnalysisError> {
    let launch_mode = matches!(scenario.browser, BrowserSelection::Launch { .. });
    let families = families(scenario);
    let network = families.has("network").then(|| {
        Network::new(
            scenario.capture.network.clone(),
            scenario.capture.limits.clone(),
        )
    });
    let recorder = Recorder::new(scenario.capture.limits.clone(), families, launch_mode);
    let local = seeds(&scenario.local_storage, &secrets);
    let session = seeds(&scenario.session_storage, &secrets);
    let mut world = World::new(secrets, recorder, network);
    world.seeds.local = local;
    world.seeds.session = session;
    let block = scenario.environment.block_service_workers;
    let policy = (block && !launch_mode).then(ServiceWorkerPolicy::new);
    if launch_mode {
        world.launch = Some(scenario.environment.clone());
        if block {
            world.init_scripts.push(SERVICE_WORKER_BLOCK.to_owned());
        }
    }
    if let Some(policy) = &policy {
        world.init_scripts.push(policy.install_script());
    }
    let opened = match &scenario.browser {
        BrowserSelection::Launch {
            executable_path,
            headless,
        } => launch::launch(executable_path, *headless, environment, world, cancellation)?,
        BrowserSelection::Connect {
            endpoint,
            target_id,
        } => launch::connect(
            endpoint,
            target_id,
            &scenario.environment,
            block,
            world,
            cancellation,
        )?,
    };
    let initial_url = opened.driver.world.current_url();
    Ok(Session {
        opened,
        mode: if launch_mode { "launch" } else { "connect" },
        initial_url,
        viewport: launch_mode.then_some((scenario.environment.width, scenario.environment.height)),
        service_workers: policy,
    })
}

fn install_cookies(
    session: &mut Session,
    scenario: &Scenario,
    scope: &Scope,
) -> Result<(), CallError> {
    if scenario.cookies.is_empty() {
        return Ok(());
    }
    let secrets = &session.opened.driver.world.secrets;
    let cookies: Vec<Value> = scenario
        .cookies
        .iter()
        .map(|cookie| {
            let url = secrets.url(&cookie.destination);
            let parsed = url::Url::parse(&url).ok();
            let path = parsed
                .as_ref()
                .map(|url| {
                    let path = url.path();
                    path[..path.rfind('/').map_or(0, |index| index + 1)].to_owned()
                })
                .unwrap_or_default();
            json!({
                "name": cookie.name,
                "value": secrets.value(&cookie.value),
                "url": url,
                "domain": parsed.as_ref().and_then(|url| url.host_str().map(str::to_owned)),
                "path": path,
                "httpOnly": cookie.http_only,
                "secure": parsed.as_ref().is_some_and(|url| url.scheme() == "https"),
                "sameSite": cookie.same_site,
            })
        })
        .collect();
    session
        .driver()
        .call(
            None,
            "Storage.setCookies",
            json!({ "cookies": cookies }),
            scope,
        )
        .map(|_| ())
}

fn action_error_text(
    secrets: &Secrets,
    error: &ActionError,
    timeout_ms: Option<u64>,
) -> (String, String) {
    match error {
        ActionError::Interrupted(CallError::Deadline) => (
            "failed".into(),
            secrets.redact(
                &AnalysisError::timeout(OPERATION, timeout_ms.unwrap_or_default()).message(),
            ),
        ),
        ActionError::Interrupted(_) => (
            "cancelled".into(),
            secrets.redact(&AnalysisError::cancelled(OPERATION).message()),
        ),
        ActionError::Message(message) => ("failed".into(), secrets.redact(message)),
    }
}

fn close_session(
    session: &mut Session,
    stop_loading: bool,
) -> Result<CleanupKind, launch::CleanupFailure> {
    {
        let driver = &mut session.opened.driver;
        let request = Cancellation::default();
        let scope = Scope::new(&request, Some(30_000));
        driver.pump(&scope);
        let World {
            network,
            recorder,
            secrets,
            requests,
            ..
        } = &mut driver.world;
        if let Some(network) = network.as_mut() {
            network.finish(recorder, secrets, requests, stop_loading);
        }
        driver.service_content(&scope);
        driver.world.recorder.sealed = true;
        // Restore the caller page's registration before detaching.
        if let Some(policy) = &session.service_workers
            && !driver.world.page_closed
        {
            let _ = driver.evaluate_main(&policy.restore_script(), &scope);
        }
    }
    launch::close(&mut session.opened, stop_loading)
}

fn cleanup_failed(failure: &launch::CleanupFailure, detail: Option<String>) -> AnalysisError {
    let error = cdp::observation_error(OPERATION, "cleanup_failed", detail);
    error.with_cleanup(failure.reason.clone(), failure.resources.clone())
}

/// `runScenario` + `captureBrowserScenario`.
pub(crate) fn run(
    scenario: &Scenario,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(cdp::observation_error(OPERATION, "cancelled", None));
    }
    let environment = environment();
    let secrets = Secrets::resolve(scenario, &environment)
        .ok_or_else(|| cdp::observation_error(OPERATION, "secret_unavailable", None))?;
    let started = Instant::now();
    let mut session = open(scenario, secrets, cancellation, &environment)?;

    // Initial navigation (`waitUntil: "load"`, no deadline).
    let navigation = {
        let scope = Scope::new(cancellation, None);
        install_cookies(&mut session, scenario, &scope)
            .map_err(ActionError::from)
            .and_then(|()| {
                // `new PlaywrightScenarioEvents` follows page initialization.
                session.driver().pump(&scope);
                session.opened.driver.world.recorder.listening = true;
                let start = session.opened.driver.world.secrets.url(&scenario.start_url);
                actions::navigate_start(session.driver(), &start, &scope)
            })
    };
    let navigation = navigation.map_err(Err).and_then(|()| {
        let scope = Scope::new(cancellation, None);
        assert_blocked(&mut session, &scope).map_err(Ok)
    });
    if let Err(error) = navigation {
        let cancelled = cancellation.reason().is_some();
        let typed = match error {
            Ok(typed) => Some(typed),
            Err(_) => None,
        };
        let cleanup = close_session(&mut session, true);
        let label = match &cleanup {
            Ok(kind) => kind.label(),
            Err(_) => "incomplete",
        };
        let data = capture_data(
            &session,
            scenario,
            started,
            &[],
            label,
            &["Scenario navigation failed before the initial state was captured."],
        );
        // The TS owner wraps the Playwright navigation error without
        // diagnostics; its text is not part of the projected failure.
        let primary = match typed {
            Some(typed) => typed,
            None if cancelled => AnalysisError::cancelled(OPERATION),
            None => AnalysisError::provider_adapter(PROVIDER_ID, OPERATION),
        };
        let primary = primary.retain_partial_observation(partial(data));
        return Err(match cleanup {
            Ok(_) => primary,
            Err(failure) => with_cleanup(primary, &failure),
        });
    }

    let mut steps: Vec<Value> = Vec::new();
    {
        let scope = Scope::new(cancellation, None);
        let requested = requested_for_step(scenario, 0);
        let artifacts = match capture_step(&mut session, &requested, &scope) {
            Ok(artifacts) => artifacts,
            Err(error) => {
                return Err(operation_failure(
                    &mut session,
                    scenario,
                    started,
                    &steps,
                    error,
                    cancellation,
                ));
            }
        };
        let world = &session.opened.driver.world;
        steps.push(step(
            0,
            "scenario_start",
            "goto_start",
            "completed",
            None,
            started.elapsed().as_millis(),
            world.secrets.sanitize_url(&session.initial_url),
            world.secrets.sanitize_url(&world.current_url()),
            1,
            world.recorder.last_sequence(),
            artifacts,
        ));
    }
    let mut failed = false;
    for (offset, action) in scenario.actions.iter().enumerate() {
        let index = offset + 1;
        let requested = requested_for_step(scenario, index);
        let world = &session.opened.driver.world;
        let before = world.secrets.sanitize_url(&world.current_url());
        let event_start = world.recorder.next_sequence();
        if failed {
            let end = world.recorder.last_sequence();
            steps.push(step(
                index,
                &action.step_id,
                &action.name,
                "cancelled",
                Some("not executed after an earlier action failure".into()),
                0,
                before.clone(),
                before,
                event_start,
                end,
                artifacts::unavailable(
                    &requested,
                    "action was not executed after an earlier failure",
                ),
            ));
            continue;
        }
        let action_started = Instant::now();
        session.opened.driver.world.recorder.set_step(index as u64);
        let (status, error) = if cancellation.reason().is_some() {
            (
                "cancelled".to_owned(),
                Some("scenario request cancelled".to_owned()),
            )
        } else {
            let timeout = match &action.kind {
                super::input::ActionKind::WaitForTimeout { .. } => None,
                _ => action.timeout_ms,
            };
            let scope = Scope::new(cancellation, timeout);
            let secrets = session.opened.driver.world.secrets.clone();
            session.driver().hold_popups = true;
            let performed = actions::perform(session.driver(), action, &secrets, &scope);
            session.driver().hold_popups = false;
            match performed {
                Ok(()) => ("completed".to_owned(), None),
                Err(error) => {
                    let (status, text) = action_error_text(&secrets, &error, timeout);
                    let status = if cancellation.reason().is_some() {
                        "cancelled".to_owned()
                    } else {
                        status
                    };
                    (status, Some(text))
                }
            }
        };
        let artifacts = if status == "cancelled" {
            artifacts::unavailable(&requested, "scenario request cancelled")
        } else {
            let scope = Scope::new(cancellation, None);
            match capture_step(&mut session, &requested, &scope) {
                Ok(artifacts) => artifacts,
                Err(error) => {
                    return Err(operation_failure(
                        &mut session,
                        scenario,
                        started,
                        &steps,
                        error,
                        cancellation,
                    ));
                }
            }
        };
        let world = &session.opened.driver.world;
        steps.push(step(
            index,
            &action.step_id,
            &action.name,
            &status,
            error,
            action_started.elapsed().as_millis(),
            before,
            world.secrets.sanitize_url(&world.current_url()),
            event_start,
            world.recorder.last_sequence(),
            artifacts,
        ));
        failed |= status != "completed";
    }

    let cancelled = cancellation.reason().is_some();
    let cleanup = close_session(&mut session, cancelled);
    let failure = match cleanup {
        Err(failure) => failure,
        Ok(kind) => {
            let mut data = capture_data(&session, scenario, started, &steps, kind.label(), &[]);
            let mut missing: Vec<String> = steps
                .iter()
                .flat_map(|step| {
                    step.pointer("/completeness/missing_sections")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            let truncated: Vec<String> = steps
                .iter()
                .flat_map(|step| {
                    step.pointer("/completeness/truncated_sections")
                        .and_then(Value::as_array)
                        .cloned()
                        .unwrap_or_default()
                })
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect();
            if session.mode == "connect"
                || !event_limitations(&session.opened.driver.world).is_empty()
            {
                missing.push("events".to_owned());
            }
            let limitations = data.remove("limitations").unwrap_or(Value::Null);
            data.insert("completeness".into(), completeness(missing, truncated));
            data.insert("limitations".into(), limitations);
            let capture = Value::Object(data);
            let evidence = evidence(scenario, &capture, session.mode)?;
            if cancellation.reason().is_some() {
                let mut capture = capture;
                if let Some(items) = capture.get_mut("limitations").and_then(Value::as_array_mut) {
                    items.push(json!("Scenario capture was cancelled; collected steps, observations, and cleanup state are retained."));
                }
                let partial_evidence = evidence_value(scenario, &capture, session.mode)?;
                return Err(AnalysisError::cancelled(OPERATION)
                    .retain_partial_observation(partial_evidence));
            }
            return Ok(evidence);
        }
    };
    let data = capture_data(
        &session,
        scenario,
        started,
        &steps,
        "incomplete",
        &["Scenario observations are partial because browser cleanup could not be confirmed."],
    );
    let detail = format!(
        "Browser scenario cleanup could not be confirmed: {}. Collected steps and events are retained in partial_observation. Review the reported resources before retrying.",
        failure.reason
    );
    Err(cleanup_failed(&failure, Some(detail)).retain_partial_observation(partial(data)))
}

/// `session.capture`: the service-worker policy check, then artifacts.
fn capture_step(
    session: &mut Session,
    requested: &BTreeSet<String>,
    scope: &Scope,
) -> Result<Value, AnalysisError> {
    assert_blocked(session, scope)?;
    let secrets = session.opened.driver.world.secrets.clone();
    let viewport = session.viewport;
    Ok(artifacts::capture(
        session.driver(),
        &secrets,
        requested,
        viewport,
        None,
        scope,
    ))
}

/// `runScenario`'s operation-failure path after cleanup.
fn operation_failure(
    session: &mut Session,
    scenario: &Scenario,
    started: Instant,
    steps: &[Value],
    error: AnalysisError,
    cancellation: &Cancellation,
) -> AnalysisError {
    let cleanup = close_session(session, cancellation.reason().is_some());
    match cleanup {
        Ok(kind) => {
            let data = capture_data(
                session,
                scenario,
                started,
                steps,
                kind.label(),
                &[
                    "Scenario capture ended after an operation failed; uncollected steps are not represented.",
                ],
            );
            error.retain_partial_observation(partial(data))
        }
        Err(failure) => {
            let data = capture_data(
                session,
                scenario,
                started,
                steps,
                "incomplete",
                &[
                    "Scenario observations are partial because browser cleanup could not be confirmed.",
                ],
            );
            with_cleanup(error.retain_partial_observation(partial(data)), &failure)
        }
    }
}

fn with_cleanup(primary: AnalysisError, failure: &launch::CleanupFailure) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert("reason".into(), json!(failure.reason));
    let cleanup = cleanup::provider_cleanup_error(
        PROVIDER_ID,
        failure.resources.clone(),
        diagnostics,
        Some("close_browser_scenario"),
        None,
    );
    cleanup::with_cleanup_failure(primary, cleanup, OPERATION)
}

fn parameters(scenario: &Scenario) -> Value {
    let mut parameters = scenario.canonical.clone();
    let digest = digest_canonical_value(&scenario.canonical);
    if let Some(map) = parameters.as_object_mut() {
        map.insert("scenario_sha256".into(), json!(digest));
    }
    parameters
}

fn observation(scenario: &Scenario, capture: &Value, mode: &str) -> Observation {
    let limitations: Vec<String> = capture
        .get("limitations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .chain(std::iter::once(
            "Browser host platform and architecture were not observed.".to_owned(),
        ))
        .collect();
    let version = capture
        .pointer("/browser/version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    Observation::new(OPERATION, parameters(scenario), capture.clone())
        .predicate("rea.browser-scenario-capture")
        .confidence("observed")
        .authority("controlled-replay")
        .environment(json!({
            "id": format!("Chromium@{version}"),
            "platform": "unknown",
            "architecture": "unknown",
            "isolation": if mode == "launch" { "process" } else { "none" },
        }))
        .limitations(limitations)
}

fn evidence(scenario: &Scenario, capture: &Value, mode: &str) -> Result<Evidence, AnalysisError> {
    Evidence::create(None, &provider(), observation(scenario, capture, mode)).map_err(|_| {
        AnalysisError::output(
            OPERATION,
            "Browser scenario provider returned a malformed completed capture.",
        )
    })
}

fn evidence_value(
    scenario: &Scenario,
    capture: &Value,
    mode: &str,
) -> Result<Value, AnalysisError> {
    evidence(scenario, capture, mode).map(Evidence::into_value)
}
