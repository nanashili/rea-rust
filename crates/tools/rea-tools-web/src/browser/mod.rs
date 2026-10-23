//! Passive browser observation over a caller-selected loopback CDP endpoint.
//!
//! Compatibility owners: `src/server/registerBrowserTools.ts`,
//! `src/application/BrowserObservationService.ts`,
//! `src/application/BrowserEvidence.ts`, `src/browser/CdpBrowserProvider.ts`
//! and `src/browser/providerIdentities.ts`.
//!
//! `list_browser_targets` is bound here; `capture` binds the target-session
//! observations (`capture_web_screenshot`, `observe_web_session`,
//! `discover_webmcp_tools`, and `inspect_web_page` in `capture::page`).
//! `analyze_web_bundle` remains unbound until its bundle-analysis owner is
//! ported.
use crate::cdp::discovery::{self, Discovery};
use crate::cdp::{self, Refinement};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

const PROVIDER_ID: &str = "rea-cdp-browser";
const PROVIDER_NAME: &str = "REA Chrome DevTools Protocol observation provider";
const PROVIDER_VERSION: &str = "2";
const LIST: &str = "list_browser_targets";
pub(crate) mod capture;
mod execution;

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(LIST, |context, input| list_targets(context, &input));
    capture::register(registry);
    execution::register(registry);
}

pub(crate) fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

fn list_targets(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let mut issues: Vec<Refinement> = Vec::new();
    let scope = cdp::parse_scope(input, &mut issues);
    let Some(scope) = scope.filter(|_| issues.is_empty()) else {
        return cdp::refinement_failure(LIST, issues);
    };
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(LIST));
    }
    let discovery = match discovery::open(&scope.endpoint, LIST, &context.cancellation) {
        Ok(discovery) => discovery,
        Err(error) => return ToolOutput::Failure(error),
    };
    let allowed: Option<BTreeSet<&str>> = (!scope.allowed_origins.is_empty())
        .then(|| scope.allowed_origins.iter().map(String::as_str).collect());
    let selected = select_targets(&discovery, allowed.as_ref());
    let mut limitations = vec![Value::String(
        if scope.allowed_origins.is_empty() {
            "All page targets with supported HTTP(S) URLs are listed."
        } else {
            "Only page targets whose current URL matches an explicitly requested exact origin are listed."
        }
        .to_owned(),
    )];
    if selected.unconnectable > 0 {
        limitations.push(Value::String(format!(
            "{} otherwise allowed page target(s) lacked a validated direct CDP WebSocket and were excluded.",
            selected.unconnectable
        )));
    }
    if selected
        .allowed
        .iter()
        .any(|target| target["attached"].is_null())
    {
        limitations.push(Value::String(
            "CDP discovery omitted attachment state for one or more targets; attached is reported as unknown."
                .to_owned(),
        ));
    }
    let mut result = Map::new();
    result.insert("browser".into(), discovery.version.clone());
    result.insert("targets".into(), Value::Array(selected.allowed));
    result.insert(
        "excluded".into(),
        json!({
            "disallowed_origin": selected.disallowed_origin,
            "unsupported_url": selected.unsupported_url,
            "non_page": selected.non_page,
        }),
    );
    result.insert("limitations".into(), Value::Array(limitations));
    let parameters = json!({
        "cdp_endpoint": scope.endpoint.recorded,
        "allowed_origins": scope.allowed_origins,
    });
    browser_evidence(
        context,
        LIST,
        "rea.browser-target-list",
        parameters,
        Value::Object(result),
    )
}

/// `createBrowserEvidence` for a result that carries `browser` facts.
fn browser_evidence(
    context: &ToolContext<'_>,
    operation: &str,
    predicate: &str,
    parameters: Value,
    result: Value,
) -> ToolOutput {
    // `completeProviderEvidence`: a cancellation that arrived during the
    // observation wins over the completed result.
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }
    match browser_observation_evidence(operation, predicate, parameters, result) {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// `createBrowserEvidence`, without the completion cancellation check.
fn browser_observation_evidence(
    operation: &str,
    predicate: &str,
    parameters: Value,
    result: Value,
) -> Result<Evidence, AnalysisError> {
    let browser = &result["browser"];
    let environment = json!({
        "id": format!(
            "{}@{}",
            browser["product"].as_str().unwrap_or_default(),
            browser["revision"].as_str().unwrap_or_default()
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
    limitations.push("Browser host platform and architecture were not observed.".to_owned());
    let mut observation = Observation::new(operation, parameters, result);
    observation.predicate_type = Some(predicate.to_owned());
    observation.confidence = Some("observed".to_owned());
    observation.authority = Some("external-service".to_owned());
    observation.environment = Some(environment);
    observation.limitations = limitations;
    Evidence::create(None, &provider(), observation).map_err(|_| {
        AnalysisError::output(
            operation,
            "Browser provider returned non-JSON observation data.",
        )
    })
}

struct Selection {
    allowed: Vec<Value>,
    disallowed_origin: u64,
    unsupported_url: u64,
    non_page: u64,
    unconnectable: u64,
}

/// `selectTargets`.
fn select_targets(discovery: &Discovery, allowed_origins: Option<&BTreeSet<&str>>) -> Selection {
    let mut selection = Selection {
        allowed: Vec::new(),
        disallowed_origin: 0,
        unsupported_url: 0,
        non_page: 0,
        unconnectable: 0,
    };
    let mut allowed: Vec<(String, Value)> = Vec::new();
    for target in &discovery.targets {
        if target.kind != "page" {
            selection.non_page += 1;
            continue;
        }
        let url = cdp::urls::sanitize_browser_url(&target.url);
        let Some(origin) = url.origin else {
            selection.unsupported_url += 1;
            continue;
        };
        if allowed_origins.is_some_and(|origins| !origins.contains(origin.as_str())) {
            selection.disallowed_origin += 1;
            continue;
        }
        if !discovery.has_target_web_socket(target) {
            selection.unconnectable += 1;
            continue;
        }
        let mut entry = Map::new();
        entry.insert("target_id".into(), Value::String(target.id.clone()));
        entry.insert("type".into(), Value::String(target.kind.clone()));
        entry.insert("title".into(), Value::String(target.title.clone()));
        entry.insert("url".into(), Value::String(url.url));
        entry.insert("origin".into(), Value::String(origin));
        entry.insert(
            "attached".into(),
            target.attached.map_or(Value::Null, Value::Bool),
        );
        allowed.push((target.id.clone(), Value::Object(entry)));
    }
    allowed.sort_by(|left, right| left.0.cmp(&right.0));
    selection.allowed = allowed.into_iter().map(|(_, value)| value).collect();
    selection
}
