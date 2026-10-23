//! Passive Node/Electron V8 Inspector observation.
//!
//! Compatibility owners: `src/server/registerJavaScriptRuntimeObservationTools.ts`,
//! `src/application/javascript/JavaScriptRuntimeObservationService.ts`,
//! `src/application/javascript/JavaScriptRuntimeObservationEvidence.ts`,
//! `src/domain/javascript/javascriptRuntimeObservation.ts` (input
//! refinements) and `src/inspector/V8InspectorProvider.ts`. The provider sends
//! only `Runtime.enable` and `Debugger.enable` to an already-running target.
mod capture;
mod inspector;
mod scope;

use crate::cdp::{self, Refinement, observation_error};
use capture::{AuthorizedTarget, CaptureState, Request};
use inspector::Inspector;
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use scope::Decision;
use serde_json::{Map, Value, json};

const PROVIDER_ID: &str = "rea-v8-inspector";
const PROVIDER_NAME: &str = "REA passive Node/Electron V8 Inspector provider";
const PROVIDER_VERSION: &str = "1";
const LIST: &str = "list_javascript_runtime_targets";
const OBSERVE: &str = "observe_javascript_runtime";

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(LIST, |context, input| list(context, &input));
    registry.handle(OBSERVE, |context, input| observe(context, &input));
}

fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

fn endpoint(input: &Value, issues: &mut Vec<Refinement>) -> Option<String> {
    match cdp::parse_http_endpoint(
        input
            .get("inspector_endpoint")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        Ok(endpoint) => Some(endpoint.url),
        Err(message) => {
            issues.push(Refinement::new(vec![json!("inspector_endpoint")], message));
            None
        }
    }
}

/// `createJavaScriptRuntimeObservationEvidence`.
fn evidence(operation: &str, parameters: Value, result: Value) -> Result<Evidence, AnalysisError> {
    let runtime = &result["runtime"];
    let environment = json!({
        "id": format!(
            "{}@{}",
            runtime["product"].as_str().unwrap_or_default(),
            runtime["protocol_version"].as_str().unwrap_or_default()
        ),
        "platform": "unknown",
        "architecture": "unknown",
        "isolation": "none",
    });
    let mut limitations: Vec<String> = result["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    limitations.push("Runtime host platform and architecture were not observed.".to_owned());
    let mut observation = Observation::new(operation, parameters, result);
    observation.predicate_type = Some(
        if operation == LIST {
            "rea.javascript-runtime-target-list"
        } else {
            "rea.javascript-runtime-observation"
        }
        .to_owned(),
    );
    observation.confidence = Some("observed".to_owned());
    observation.authority = Some("external-service".to_owned());
    observation.environment = Some(environment);
    observation.limitations = limitations;
    Evidence::create(None, &provider(), observation).map_err(|_| {
        AnalysisError::output(
            operation,
            "Inspector returned a malformed runtime observation.",
        )
    })
}

/// `completeProviderEvidence`.
fn complete(
    context: &ToolContext<'_>,
    operation: &str,
    parameters: Value,
    result: Value,
) -> ToolOutput {
    match evidence(operation, parameters, result) {
        Ok(evidence) if context.cancellation.reason().is_some() => ToolOutput::Failure(
            AnalysisError::cancelled(operation).retain_partial_observation(evidence.into_value()),
        ),
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn project_target(target: &AuthorizedTarget) -> Value {
    json!({
        "target_id": target.id,
        "protocol_type": target.kind,
        "attached": target.attached,
        "location": target.location,
    })
}

fn list(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let mut issues = Vec::new();
    let Some(origin) = endpoint(input, &mut issues).filter(|_| issues.is_empty()) else {
        return cdp::refinement_failure(LIST, issues);
    };
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(LIST));
    }
    let discovery = match scope::discover(&origin, LIST, cancellation) {
        Ok(discovery) => discovery,
        Err(error) => return ToolOutput::Failure(error),
    };
    let mut allowed: Vec<AuthorizedTarget> = Vec::new();
    let mut unsupported_location = 0_u64;
    let mut unconnectable = 0_u64;
    let mut examined = 0_usize;
    let mut outcome = Ok(());
    for target in &discovery.targets {
        if cancellation.reason().is_some() {
            outcome = Err(AnalysisError::cancelled(LIST));
            break;
        }
        let decision = match scope::authorize_target_location(
            &target.url,
            &target.kind,
            &discovery.product,
            cancellation,
            LIST,
        ) {
            Ok(decision) => decision,
            Err(error) => {
                outcome = Err(error);
                break;
            }
        };
        examined += 1;
        match decision {
            Decision::Denied => unsupported_location += 1,
            Decision::Allowed(location) if Decision::is_builtin(&location) => {
                unsupported_location += 1
            }
            Decision::Allowed(_) if target.web_socket_url.is_none() => unconnectable += 1,
            Decision::Allowed(location) => allowed.push(AuthorizedTarget {
                id: target.id.clone(),
                kind: target.kind.clone(),
                attached: target.attached,
                location,
            }),
        }
    }
    allowed.sort_by(|left, right| left.id.cmp(&right.id));
    if outcome.is_ok() && cancellation.reason().is_some() {
        outcome = Err(AnalysisError::cancelled(LIST));
    }
    let attachment_unknown = allowed.iter().any(|target| target.attached.is_none());
    let targets: Vec<Value> = allowed.iter().map(project_target).collect();
    let excluded =
        json!({ "unsupported_location": unsupported_location, "unconnectable": unconnectable });
    if let Err(error) = outcome {
        if !matches!(error.kind, ErrorKind::Cancelled { .. }) {
            return ToolOutput::Failure(error);
        }
        let complete = examined == discovery.targets.len();
        let mut limitations = capture::target_limitations(attachment_unknown);
        if !complete {
            limitations.push(Value::String(
                "Cancellation stopped target authorization; unexamined targets are unknown, not excluded.".to_owned(),
            ));
        }
        let mut diagnostics = Map::new();
        diagnostics.insert(
            "completed_target_inventory".into(),
            json!({
                "runtime": discovery.runtime,
                "targets": targets,
                "excluded": excluded,
                "targets_examined": examined,
                "targets_discovered": discovery.targets.len(),
                "complete": complete,
                "limitations": limitations,
            }),
        );
        return ToolOutput::Failure(AnalysisError::cancelled(LIST).with_diagnostics(diagnostics));
    }
    let result = json!({
        "runtime": discovery.runtime,
        "targets": targets,
        "excluded": excluded,
        "limitations": capture::target_limitations(attachment_unknown),
    });
    complete(
        context,
        LIST,
        json!({ "inspector_endpoint": origin }),
        result,
    )
}

/// `isCancelled` across the error algebra.
fn is_cancelled(error: &AnalysisError) -> bool {
    matches!(error.kind, ErrorKind::Cancelled { .. })
}

fn observe(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let mut issues = Vec::new();
    let origin = endpoint(input, &mut issues);
    let target_id = input
        .get("target_id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_owned();
    if target_id.is_empty() {
        issues.push(Refinement::new(
            vec![json!("target_id")],
            "Too small: expected string to have >=1 characters",
        ));
    }
    let Some(origin) = origin.filter(|_| issues.is_empty()) else {
        return cdp::refinement_failure(OBSERVE, issues);
    };
    let runtime_kind = input.get("runtime_kind").and_then(Value::as_str);
    let observation_ms = input
        .get("observation_ms")
        .and_then(Value::as_u64)
        .unwrap_or(100);
    let mut parameters = Map::new();
    parameters.insert("inspector_endpoint".into(), Value::String(origin.clone()));
    parameters.insert("target_id".into(), Value::String(target_id.clone()));
    if let Some(kind) = runtime_kind {
        parameters.insert("runtime_kind".into(), Value::String(kind.to_owned()));
    }
    parameters.insert("observation_ms".into(), json!(observation_ms));
    let parameters = Value::Object(parameters);
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(OBSERVE));
    }
    let request = Request {
        runtime_kind,
        observation_ms,
    };
    let mut connection: Option<Inspector> = None;
    let mut captured: Option<(Value, AuthorizedTarget, CaptureState)> = None;
    let outcome = run_observation(
        &origin,
        &target_id,
        &request,
        cancellation,
        &mut connection,
        &mut captured,
    );
    if let Some(mut connection) = connection {
        connection.close();
    }
    let outcome = match outcome {
        Ok(result) if cancellation.reason().is_some() => {
            Err(AnalysisError::cancelled(OBSERVE).retain_partial_observation(result))
        }
        other => other,
    };
    match outcome {
        Ok(result) => complete(context, OBSERVE, parameters, result),
        Err(error) => ToolOutput::Failure(with_partial_evidence(
            error,
            captured,
            &request,
            &parameters,
            cancellation,
        )),
    }
}

/// The provider's partial-observation retention plus the service's
/// conversion of a raw partial observation into Evidence.
fn with_partial_evidence(
    mut error: AnalysisError,
    captured: Option<(Value, AuthorizedTarget, CaptureState)>,
    request: &Request<'_>,
    parameters: &Value,
    cancellation: &rea_core::cancellation::Cancellation,
) -> AnalysisError {
    let browser = matches!(error.kind, ErrorKind::BrowserObservation { .. });
    if error.partial_observation.is_none() && (browser || is_cancelled(&error)) {
        if let Some((runtime, target, state)) = &captured {
            if let Ok(partial) = capture::finalize(
                request,
                runtime,
                target,
                state,
                false,
                cancellation,
                OBSERVE,
            ) {
                error = error.retain_partial_observation(partial);
            }
        }
    }
    if let Some(partial) = error.partial_observation.take() {
        if partial.get("evidence_id").is_some() || partial.get("kind").is_some() {
            error.partial_observation = Some(partial);
        } else {
            match evidence(OBSERVE, parameters.clone(), partial) {
                Ok(built) => error.partial_observation = Some(built.into_value()),
                Err(_) if is_cancelled(&error) => {
                    return AnalysisError::output(
                        OBSERVE,
                        "Inspector retained a malformed completed runtime observation.",
                    );
                }
                Err(_) => {}
            }
        }
    }
    error
}

fn run_observation(
    origin: &str,
    target_id: &str,
    request: &Request<'_>,
    cancellation: &rea_core::cancellation::Cancellation,
    connection: &mut Option<Inspector>,
    captured: &mut Option<(Value, AuthorizedTarget, CaptureState)>,
) -> Result<Value, AnalysisError> {
    let discovery = scope::discover(origin, OBSERVE, cancellation)?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OBSERVE));
    }
    let Some(target) = discovery
        .targets
        .iter()
        .find(|target| target.id == target_id)
    else {
        return Err(observation_error(OBSERVE, "target_not_found", None));
    };
    let decision = scope::authorize_target_location(
        &target.url,
        &target.kind,
        &discovery.product,
        cancellation,
        OBSERVE,
    )?;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OBSERVE));
    }
    let location = match decision {
        Decision::Allowed(location)
            if target.attached != Some(true) && !Decision::is_builtin(&location) =>
        {
            location
        }
        _ => return Err(observation_error(OBSERVE, "target_not_allowed", None)),
    };
    let Some(web_socket) = target.web_socket_url.clone() else {
        return Err(observation_error(
            OBSERVE,
            "invalid_endpoint_response",
            Some(
                "The selected Inspector target has no validated direct WebSocket endpoint."
                    .to_owned(),
            ),
        ));
    };
    if let Some(kind) = request.runtime_kind {
        let page = matches!(kind, "electron-preload" | "electron-renderer");
        if (page && target.kind != "page") || (!page && target.kind != "node") {
            return Err(observation_error(OBSERVE, "target_not_allowed", None));
        }
    }
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OBSERVE));
    }
    let authorized = AuthorizedTarget {
        id: target.id.clone(),
        kind: target.kind.clone(),
        attached: target.attached,
        location,
    };
    let opened = connection.insert(Inspector::connect(&web_socket, OBSERVE, cancellation)?);
    let (_, _, state) = captured.insert((
        discovery.runtime.clone(),
        authorized,
        CaptureState::default(),
    ));
    let mut ingest = |event| state.ingest(event);
    opened.send("Runtime.enable", cancellation, &mut ingest)?;
    opened.send("Debugger.enable", cancellation, &mut ingest)?;
    opened.observe(request.observation_ms, cancellation, &mut ingest)?;
    let (runtime, authorized, state) = captured.as_ref().expect("capture state");
    capture::finalize(
        request,
        runtime,
        authorized,
        state,
        true,
        cancellation,
        OBSERVE,
    )
}
