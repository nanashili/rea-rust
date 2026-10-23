//! Target-session browser observations: `capture_web_screenshot`,
//! `observe_web_session` and `discover_webmcp_tools`.
//!
//! Compatibility owners: `src/application/BrowserObservationService.ts`
//! (`captureWebScreenshot`, `observeWebSession`, `discoverWebMcpTools`),
//! `src/browser/CdpBrowserProvider.ts` (`withTargetSession`,
//! `providerError`), `src/browser/CdpScreenshot.ts`,
//! `src/browser/CdpObservationSession.ts` and
//! `src/browser/CdpWebMcpDiscovery.ts`. Input schemas are
//! `captureWebScreenshotInputSchema`, `observeWebSessionInputSchema` and
//! `discoverWebMcpToolsInputSchema` (`target_id` is `trim().min(1)`).
pub(crate) mod completeness;
pub(crate) mod connection;
mod page;
mod screenshot;
mod session;
pub(crate) mod values;
mod webmcp;

use crate::cdp::{self, BrowserScope, Refinement};
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};
use std::time::SystemTime;

pub(super) fn register(registry: &mut Registry) {
    page::register(registry);
    registry.handle(screenshot::OPERATION, |context, input| {
        run(
            context,
            &input,
            screenshot::OPERATION,
            "rea.web-screenshot",
            |connection, facts, _, context| {
                screenshot::capture(connection, facts, &context.progress)
            },
        )
    });
    registry.handle(session::OPERATION, |context, input| {
        run(
            context,
            &input,
            session::OPERATION,
            "rea.web-observation-session",
            |connection, facts, ms, context| {
                session::observe(connection, facts, ms.unwrap_or(10_000), &context.progress)
            },
        )
    });
    registry.handle(webmcp::OPERATION, |context, input| {
        run(
            context,
            &input,
            webmcp::OPERATION,
            "rea.webmcp-discovery",
            |connection, facts, ms, context| {
                webmcp::discover(connection, facts, ms.unwrap_or(100), &context.progress)
            },
        )
    });
}

/// `String.prototype.trim`.
fn js_trim(text: &str) -> &str {
    text.trim_matches(|character: char| {
        (character.is_whitespace() && character != '\u{85}') || character == '\u{FEFF}'
    })
}

struct TargetInput {
    scope: BrowserScope,
    target_id: String,
    observation_ms: Option<u64>,
}

fn parse_input(tool: &str, input: &Value) -> Result<TargetInput, ToolOutput> {
    let mut issues: Vec<Refinement> = Vec::new();
    let scope = cdp::parse_scope(input, &mut issues);
    let target_id = js_trim(
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
    match scope {
        Some(scope) if issues.is_empty() => Ok(TargetInput {
            scope,
            target_id,
            observation_ms: input.get("observation_ms").and_then(Value::as_u64),
        }),
        _ => Err(cdp::refinement_failure(tool, issues)),
    }
}

type Work = fn(
    &mut connection::Connection<'_>,
    &connection::TargetFacts<'_>,
    Option<u64>,
    &ToolContext<'_>,
) -> Result<Value, AnalysisError>;

fn run(
    context: &ToolContext<'_>,
    input: &Value,
    operation: &str,
    predicate: &str,
    work: Work,
) -> ToolOutput {
    let parsed = match parse_input(operation, input) {
        Ok(parsed) => parsed,
        Err(failure) => return failure,
    };
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }
    let outcome = connection::with_target_session(
        operation,
        &parsed.scope,
        &parsed.target_id,
        &context.cancellation,
        |connection, facts| work(connection, facts, parsed.observation_ms, context),
    );
    let result = match outcome {
        Ok(result) => result,
        Err(error) => return ToolOutput::Failure(error),
    };
    super::browser_evidence(
        context,
        operation,
        predicate,
        parameters(&parsed, &result),
        result,
    )
}

/// `browserParameters` for a target-scoped input.
fn parameters(input: &TargetInput, result: &Value) -> Value {
    let allowed_origins: Vec<String> = if !input.scope.allowed_origins.is_empty() {
        input.scope.allowed_origins.clone()
    } else {
        observed_origin(result).into_iter().collect()
    };
    let mut parameters = json!({
        "cdp_endpoint": input.scope.endpoint.recorded,
        "allowed_origins": allowed_origins,
        "target_id": input.target_id,
    });
    if let Some(ms) = input.observation_ms {
        parameters["observation_ms"] = json!(ms);
    }
    parameters
}

/// `browserResultTargetOrigin`.
fn observed_origin(result: &Value) -> Option<String> {
    let target = result.get("target")?;
    if let Some(origin) = target.get("origin") {
        return origin.as_str().map(str::to_owned);
    }
    let initial = target.get("initial_url")?.as_str()?;
    cdp::urls::sanitize_browser_url(initial).origin
}

/// `new Date().toISOString()`.
pub(crate) fn iso_now() -> String {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let total_seconds = (millis / 1000) as i64;
    let (days, seconds) = (
        total_seconds.div_euclid(86_400),
        total_seconds.rem_euclid(86_400),
    );
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60,
        millis % 1000
    )
}

/// Howard Hinnant's `civil_from_days` (proleptic Gregorian).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = yoe + era * 400 + i64::from(month <= 2);
    (year, month, day)
}
