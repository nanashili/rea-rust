//! Native `capture_browser_scenario`: a controlled Chromium scenario driven
//! over CDP with REA-owned launch, lifecycle, cleanup and artifacts.
//!
//! Compatibility owners: `src/server/registerBrowserScenarioTool.ts`,
//! `src/application/BrowserScenarioCaptureService.ts`,
//! `src/browser/PlaywrightBrowserScenarioProvider.ts` and the
//! `PlaywrightScenario*` session modules. Playwright is not used; the
//! behaviors of Playwright 1.58.2 that shape the output are reproduced here
//! (see `.cache/rust-migration/progress.md`, "capture_browser_scenario").
//!
//! Layout: `input` (contract refinements), `secrets` (declared-secret
//! redaction), `launch` (owned launch / external attach and cleanup),
//! `driver` (CDP connection and observed world), `recorder` + `network`
//! (event budgets and network phases), `actions` + `page.js` (declarative
//! actions), `artifacts` (step snapshots) and `run` (scenario lifecycle and
//! Evidence).
mod actions;
mod artifacts;
mod driver;
#[cfg(all(feature = "electron-scenario", unix))]
pub(crate) mod electron;
mod input;
mod launch;
mod network;
mod recorder;
mod run;
mod secrets;

use base64::Engine;
use driver::Scope;
use input::Limits;
use recorder::Families;
use secrets::Secrets;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use crate::cdp;
use input::{OPERATION, Rejection};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::EvidenceProvider;
use rea_mcp::{Registry, ToolContext, ToolOutput};

/// Contract identity of the scenario provider. The identifier, name and
/// version are the TS contract values consumed by scenario comparisons and
/// script publication; the implementation is REA's native CDP runner.
pub(crate) const PROVIDER_ID: &str = "rea-playwright-browser-scenario";
const PROVIDER_NAME: &str = "REA Playwright browser scenario capture provider";
const PROVIDER_VERSION: &str = "1";

pub(crate) fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| handle(context, &input));
}

/// Resolve module specifiers through the caller's Chromium using a synthetic,
/// request-intercepted document. The selected application source is never
/// loaded or executed; only the generated resolver stub is fulfilled.
pub(crate) fn resolve_module(
    executable: &str,
    environment: &BTreeMap<String, String>,
    importer_url: &str,
    specifiers: &[String],
    import_map: Option<&Value>,
    cancellation: &rea_core::cancellation::Cancellation,
) -> Result<Value, AnalysisError> {
    let world = driver::World::new(Secrets::empty(), resolver_recorder(), None);
    let mut opened = launch::launch(executable, true, environment, world, cancellation)?;
    let scope = Scope::new(cancellation, Some(20_000));
    let result = resolve_module_opened(
        &mut opened,
        &scope,
        executable,
        importer_url,
        specifiers,
        import_map,
    );
    let cleanup = launch::close(&mut opened, true);
    match (result, cleanup) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), Ok(_)) => Err(error),
        (Ok(value), Err(cleanup)) => Err(rea_core::analysis_error::cleanup::with_cleanup_failure(
            AnalysisError::output(
                "trace_web_module_imports",
                "Native module resolution completed but browser cleanup failed",
            )
            .retain_partial_observation(value),
            AnalysisError::output("trace_web_module_imports", cleanup.reason.clone())
                .with_cleanup(cleanup.reason, cleanup.resources),
            "trace_web_module_imports",
        )),
        (Err(error), Err(cleanup)) => Err(rea_core::analysis_error::cleanup::with_cleanup_failure(
            error,
            AnalysisError::output("trace_web_module_imports", cleanup.reason.clone())
                .with_cleanup(cleanup.reason, cleanup.resources),
            "trace_web_module_imports",
        )),
    }
}

fn resolve_module_opened(
    opened: &mut launch::Opened,
    scope: &Scope,
    executable: &str,
    importer_url: &str,
    specifiers: &[String],
    import_map: Option<&Value>,
) -> Result<Value, AnalysisError> {
    let importer = url::Url::parse(importer_url)
        .map_err(|_| AnalysisError::input("trace_web_module_imports", vec![]))?;
    let mut transport_url = importer.clone();
    transport_url.set_fragment(None);
    let mut requests = Vec::new();
    let report_slot = script_json_strings(specifiers);
    let map_script = import_map.map_or(String::new(), |map| {
        let Some(base_url) = map.get("baseUrl").and_then(Value::as_str) else {
            return String::new();
        };
        let base_url = url::Url::parse(base_url)
            .map(|url| url.to_string())
            .unwrap_or_else(|_| base_url.to_owned());
        let map_value = map.get("value").cloned().unwrap_or(Value::Null);
        format!(
            "<base href=\"{}\"><script type=\"importmap\">{}</script>",
            html_attribute(&base_url),
            script_json_value(&map_value),
        )
    });
    let body = format!(
        "<!doctype html>{map_script}<script type=\"module\" src=\"{}\"></script>",
        html_attribute(importer_url),
    );
    inject_resolver_document(opened, scope, &body, &mut requests)?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        service_resolver_requests(
            opened,
            scope,
            transport_url.as_str(),
            &report_slot,
            &mut requests,
        )?;
        let value = opened
            .driver
            .evaluate_main(
                "globalThis.__reaModuleResult || globalThis.__reaModuleUnsupported || globalThis.__reaModuleFailure || null",
                scope,
            )
            .map_err(|error| resolver_call_failure("resolver polling", &error))?;
        if let Some(report) = value.as_object() {
            let Some(reported_importer) = report.get("importer_url").and_then(Value::as_str) else {
                return Err(invalid_resolver_report());
            };
            let Some(entries) = report.get("entries").and_then(Value::as_array) else {
                return Err(invalid_resolver_report());
            };
            return project_resolver_report(
                opened,
                executable,
                importer_url,
                specifiers,
                reported_importer,
                entries,
                report,
                &requests,
            );
        }
        if value.as_bool() == Some(true) {
            return Err(AnalysisError::capability_unavailable(
                PROVIDER_ID,
                "trace_web_module_imports",
                "native_resolution_unsupported",
            ));
        }
        if let Some(failure) = value.as_str() {
            return Err(AnalysisError::output(
                "trace_web_module_imports",
                format!("Native module resolver failed: {failure}"),
            ));
        }
        if Instant::now() >= deadline || scope.interrupted().is_some() {
            return Err(AnalysisError::cancelled("trace_web_module_imports"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn inject_resolver_document(
    opened: &mut launch::Opened,
    scope: &Scope,
    body: &str,
    requests: &mut Vec<Value>,
) -> Result<(), AnalysisError> {
    opened
        .driver
        .main_call(
            "Fetch.enable",
            json!({"patterns":[{"urlPattern":"*","requestStage":"Request"}]}),
            scope,
        )
        .map_err(|_| AnalysisError::provider_adapter(PROVIDER_ID, "trace_web_module_imports"))?;

    requests.push(json!({
        "url": "about:blank",
        "resource_type": "document",
        "effect": "injected",
    }));

    opened
        .driver
        .evaluate_main(
            &format!(
                "document.open(); document.write({}); document.close();",
                script_json_string(body),
            ),
            scope,
        )
        .map_err(|error| resolver_call_failure("document evaluation", &error))?;

    Ok(())
}

fn service_resolver_requests(
    opened: &mut launch::Opened,
    scope: &Scope,
    transport_url: &str,
    report_slot: &str,
    requests: &mut Vec<Value>,
) -> Result<(), AnalysisError> {
    for paused in opened.driver.take_fetch_paused() {
        let request_id = paused["requestId"].as_str().unwrap_or_default();
        let session = paused.get("sessionId").and_then(Value::as_str);
        let request_url = paused
            .pointer("/request/url")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let (fulfill, body) = if request_url == transport_url {
            let mut script = String::from(
                "try { globalThis.__reaModuleUnsupported = typeof import.meta.resolve !== 'function'; if (!globalThis.__reaModuleUnsupported) { globalThis.__reaModuleResult = { importer_url: import.meta.url, entries: ",
            );
            script.push_str(report_slot);
            script.push_str(
                ".map(specifier => { try { return {specifier, resolution: {state: 'resolved', url: import.meta.resolve(specifier)}}; } catch (error) { return {specifier, resolution: {state: 'rejected', message: String(error)}}; } }) }; } } catch (error) { globalThis.__reaModuleFailure = String(error); }",
            );
            (true, script)
        } else {
            (false, String::new())
        };
        let method = if fulfill {
            "Fetch.fulfillRequest"
        } else {
            "Fetch.failRequest"
        };
        requests.push(json!({
            "url": request_url,
            "resource_type": paused
                .get("resourceType")
                .and_then(Value::as_str)
                .unwrap_or("other"),
            "effect": if fulfill { "fulfilled" } else { "blocked" },
        }));
        let params = if fulfill {
            let mut headers = vec![json!({
                "name": "Content-Type",
                "value": "text/javascript",
            })];
            if request_url == transport_url {
                headers.push(json!({
                    "name": "Access-Control-Allow-Origin",
                    "value": "*",
                }));
            }
            json!({"requestId":request_id,"responseCode":200,"responseHeaders":headers,"body":base64::engine::general_purpose::STANDARD.encode(body)})
        } else {
            json!({"requestId":request_id,"errorReason":"BlockedByClient"})
        };
        opened
            .driver
            .call(session, method, params, scope)
            .map_err(|error| resolver_call_failure("resolver request", &error))?;
    }
    Ok(())
}

fn invalid_resolver_report() -> AnalysisError {
    AnalysisError::provider_adapter(PROVIDER_ID, "trace_web_module_imports")
}

fn project_resolver_report(
    opened: &launch::Opened,
    executable: &str,
    importer_url: &str,
    specifiers: &[String],
    reported_importer: &str,
    entries: &[Value],
    report: &serde_json::Map<String, Value>,
    requests: &[Value],
) -> Result<Value, AnalysisError> {
    if reported_importer != importer_url || entries.len() != specifiers.len() {
        return Err(invalid_resolver_report());
    }

    let mut resolutions = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        if entry.get("specifier") != Some(&Value::String(specifiers[index].clone())) {
            return Err(invalid_resolver_report());
        }
        let Some(resolution) = entry.get("resolution") else {
            return Err(invalid_resolver_report());
        };
        resolutions.push(resolution.clone());
    }

    let diagnostics = resolver_diagnostics(opened);
    let engine = json!({
        "id": "chromium-native-module-resolver",
        "version": opened.driver.version,
    });
    Ok(json!({
        "engine": engine.clone(),
        "resolutions": resolutions,
        "diagnostics": diagnostics,
        "importer_url": reported_importer,
        "raw_result": {
            "native_report": report,
            "requests": requests,
            "diagnostics": resolver_diagnostics(opened),
            "engine": engine,
            "executable_path": executable,
        },
    }))
}

fn resolver_call_failure(label: &str, error: &driver::CallError) -> AnalysisError {
    match error {
        driver::CallError::Cancelled => AnalysisError::cancelled("trace_web_module_imports"),
        driver::CallError::Deadline => AnalysisError::output(
            "trace_web_module_imports",
            format!("Native module resolver {label} exceeded its deadline"),
        ),
        driver::CallError::Protocol(message) | driver::CallError::Closed(message) => {
            AnalysisError::output(
                "trace_web_module_imports",
                format!("Native module resolver {label} failed: {message}"),
            )
        }
    }
}

fn resolver_recorder() -> recorder::Recorder {
    let mut families = Families::default();
    families.enabled.insert("console".to_owned());
    let mut recorder = recorder::Recorder::new(Limits::resolver_defaults(), families, true);
    recorder.listening = true;
    recorder
}

fn resolver_diagnostics(opened: &launch::Opened) -> Vec<String> {
    opened
        .driver
        .world
        .recorder
        .items()
        .iter()
        .filter(|item| item.get("kind").and_then(Value::as_str) == Some("console"))
        .map(|item| {
            let level = item.get("level").and_then(Value::as_str).unwrap_or("log");
            let text = item.get("text").and_then(Value::as_str).unwrap_or_default();
            format!("{level}: {text}")
        })
        .collect()
}

fn script_json_value(value: &Value) -> String {
    value.to_string().replace('<', "\\u003c")
}

fn script_json_strings(values: &[String]) -> String {
    script_json_value(&Value::Array(
        values.iter().cloned().map(Value::String).collect(),
    ))
}

fn script_json_string(value: &str) -> String {
    script_json_value(&Value::String(value.to_owned()))
}

fn html_attribute(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn handle(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let scenario = match input::parse(input) {
        Ok(scenario) => scenario,
        Err(Rejection::Schema(issues)) => return cdp::refinement_failure(OPERATION, issues),
        Err(Rejection::Scenario(issues)) => {
            let issues = issues
                .into_iter()
                .map(|issue| InputIssue {
                    path: issue.path,
                    reason: "invalid_value",
                    message: Some(issue.message),
                    expected: None,
                    minimum: None,
                    maximum: None,
                })
                .collect();
            return ToolOutput::Failure(AnalysisError::input(OPERATION, issues));
        }
    };
    run::run(&scenario, &context.cancellation).into()
}
