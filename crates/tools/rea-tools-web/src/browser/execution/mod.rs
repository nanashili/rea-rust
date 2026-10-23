//! Instrumented execution observation and listener inspection of one
//! externally owned page.
//!
//! Compatibility owners: `src/server/registerWebRuntimeTools.ts`,
//! `src/application/WebRuntimeService.ts`,
//! `src/browser/execution/CdpWebRuntimeProvider.ts` and the domain contracts
//! `src/domain/webRuntime.ts`, `webExecution.ts`, `webEventListeners.ts`.
mod capture;
mod listeners;
mod protocol;
mod requests;
mod session;
mod sources;
mod window;

use crate::cdp::{self, Refinement};
use rea_core::analysis_error::AnalysisError;
use rea_core::analysis_error::cleanup::with_cleanup_failure;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use session::{RuntimeSession, Scope};
use std::time::{SystemTime, UNIX_EPOCH};

const OBSERVE: &str = "observe_web_execution";
const LISTENERS: &str = "inspect_web_event_listeners";

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OBSERVE, |context, input| observe(context, &input));
    registry.handle(LISTENERS, |context, input| inspect(context, &input));
}

/// `Date.prototype.toISOString` of the current time.
pub(super) fn iso_now() -> String {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let millis = elapsed.subsec_millis();
    let seconds = elapsed.as_secs();
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    // Civil-from-days (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// `webRuntimeScopeSchema` refinements (`browserEndpointSchema`,
/// `browserAllowedOriginsSchema`), rendered as the SDK's input failure.
fn parse_scope(tool: &str, input: &Value) -> Result<Scope, ToolOutput> {
    let mut issues: Vec<Refinement> = Vec::new();
    let scope = cdp::parse_scope_with(input, &mut issues, cdp::parse_http_endpoint);
    match scope.filter(|_| issues.is_empty()) {
        Some(scope) => Ok(Scope {
            endpoint: scope.endpoint,
            allowed_origins: scope.allowed_origins,
            target_id: input["target_id"].as_str().unwrap_or_default().to_owned(),
        }),
        None => Err(cdp::refinement_failure(tool, issues)),
    }
}

/// The parsed input, as recorded in Evidence parameters.
fn parameters(scope: &Scope, extra: (&str, Value)) -> Value {
    let mut parameters = Map::new();
    parameters.insert(
        "cdp_endpoint".into(),
        Value::String(scope.endpoint.recorded.clone()),
    );
    parameters.insert("allowed_origins".into(), json!(scope.allowed_origins));
    parameters.insert("target_id".into(), Value::String(scope.target_id.clone()));
    parameters.insert(extra.0.into(), extra.1);
    Value::Object(parameters)
}

/// `CdpWebRuntimeProvider.run`: one owned session with confirmed cleanup.
fn run(
    context: &ToolContext<'_>,
    scope: &Scope,
    operation: &'static str,
    group: Option<&str>,
    capture: impl FnOnce(&mut RuntimeSession<'_>) -> Result<Value, AnalysisError>,
) -> Result<Value, AnalysisError> {
    let cancellation = &context.cancellation;
    let mut session = RuntimeSession::open(scope, operation, cancellation)?;
    let result = capture(&mut session);
    let failure = session.close(result.as_ref().err(), group);
    let cancelled = cancellation.reason().is_some();
    if let Some(failure) = failure {
        return Err(match result {
            Ok(value) if cancelled => with_cleanup_failure(
                AnalysisError::cancelled(operation).retain_partial_observation(value),
                failure,
                operation,
            ),
            Ok(value) => failure.retain_partial_observation(value),
            Err(error) => with_cleanup_failure(error, failure, operation),
        });
    }
    match result {
        Ok(value) if cancelled => {
            Err(AnalysisError::cancelled(operation).retain_partial_observation(value))
        }
        other => other,
    }
}

/// `WebRuntimeService.evidence`.
fn evidence(
    operation: &str,
    scope: &Scope,
    parameters: Value,
    result: Value,
) -> Result<Evidence, AnalysisError> {
    let origin = result["target"]["origin"].as_str().unwrap_or_default();
    if !scope.allowed_origins.is_empty()
        && !scope
            .allowed_origins
            .iter()
            .any(|allowed| allowed == origin)
    {
        return Err(AnalysisError::output(
            operation,
            "Provider returned a document outside the selected origin scope.",
        ));
    }
    let limitations: Vec<String> = result["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let observation = Observation::new(operation, parameters, result)
        .predicate(format!("rea.{}", operation.replace('_', "-")))
        .confidence("observed")
        .authority("external-service")
        .limitations(limitations);
    Evidence::create(None, &super::provider(), observation).map_err(|_| {
        AnalysisError::output(
            operation,
            "Browser provider returned non-JSON observation data.",
        )
    })
}

/// `WebRuntimeService.observe` / `inspect` result delivery, including the
/// conversion of a retained completed result into partial Evidence.
fn deliver(
    context: &ToolContext<'_>,
    operation: &'static str,
    scope: &Scope,
    parameters: Value,
    result: Result<Value, AnalysisError>,
    partial_keys: [&str; 2],
) -> ToolOutput {
    let value = match result {
        Ok(value) => value,
        Err(mut error) => {
            let convertible = error.partial_observation.as_ref().is_some_and(|partial| {
                partial.get("evidence_id").is_none()
                    && partial_keys.iter().all(|key| partial.get(*key).is_some())
            });
            if convertible {
                let partial = error.partial_observation.take().unwrap_or(Value::Null);
                match evidence(operation, scope, parameters, partial) {
                    Ok(evidence) => error.partial_observation = Some(evidence.into_value()),
                    Err(failure)
                        if matches!(
                            error.kind,
                            rea_core::analysis_error::ErrorKind::Cancelled { .. }
                        ) =>
                    {
                        return ToolOutput::Failure(failure);
                    }
                    Err(_) => {}
                }
            }
            return ToolOutput::Failure(error);
        }
    };
    match evidence(operation, scope, parameters, value) {
        // `completeProviderEvidence`.
        Ok(evidence) if context.cancellation.reason().is_some() => ToolOutput::Failure(
            AnalysisError::cancelled(operation).retain_partial_observation(evidence.into_value()),
        ),
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn observe(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let scope = match parse_scope(OBSERVE, input) {
        Ok(scope) => scope,
        Err(output) => return output,
    };
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(OBSERVE));
    }
    let observation_ms = input["observation_ms"].as_u64().unwrap_or(10_000);
    let parameters = parameters(&scope, ("observation_ms", json!(observation_ms)));
    let result = run(context, &scope, OBSERVE, None, |session| {
        capture::capture(session, observation_ms, &context.progress)
    });
    deliver(
        context,
        OBSERVE,
        &scope,
        parameters,
        result,
        ["instrumentation", "window"],
    )
}

fn inspect(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let scope = match parse_scope(LISTENERS, input) {
        Ok(scope) => scope,
        Err(output) => return output,
    };
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(LISTENERS));
    }
    let selector = input["selector"].as_str().unwrap_or_default().to_owned();
    let parameters = parameters(&scope, ("selector", Value::String(selector.clone())));
    let group = listeners::object_group();
    let result = run(context, &scope, LISTENERS, Some(&group), |session| {
        listeners::capture(session, &selector, &group)
    });
    deliver(
        context,
        LISTENERS,
        &scope,
        parameters,
        result,
        ["selected_node", "listeners"],
    )
}
