//! Passive Electron file-page observation over a caller-selected loopback CDP
//! endpoint.
//!
//! Compatibility owners: `src/server/registerElectronTools.ts`,
//! `src/application/javascript/ElectronObservationService.ts`,
//! `src/application/javascript/ElectronEvidence.ts`,
//! `src/domain/javascript/electronObservation.ts` and
//! `src/browser/CdpElectronProvider.ts`. Local file paths are authorized by
//! `crate::cdp::file_scope`.
//!
//! `list_electron_targets` is bound here; `inspect` binds
//! `inspect_electron_page` on the shared `browser::capture::connection`
//! target session. `capture_electron_scenario` (Playwright) is out of scope.
mod inspect;

use crate::cdp::{self, Refinement, discovery, file_scope};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};

const PROVIDER_ID: &str = "rea-cdp-electron";
const PROVIDER_NAME: &str = "REA Electron file-page CDP observation provider";
const PROVIDER_VERSION: &str = "1";
const LIST: &str = "list_electron_targets";

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(LIST, |context, input| list_targets(context, &input));
    registry.handle(inspect::OPERATION, |context, input| {
        inspect::run(context, &input)
    });
}

fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

/// `createElectronEvidence` for a target list (no environment facts).
fn list_evidence(context: &ToolContext<'_>, parameters: Value, result: Value) -> ToolOutput {
    let limitations: Vec<String> = result["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let mut observation = Observation::new(LIST, parameters, result);
    observation.predicate_type = Some("rea.electron-target-list".to_owned());
    observation.confidence = Some("observed".to_owned());
    observation.authority = Some("external-service".to_owned());
    observation.limitations = limitations;
    match Evidence::create(None, &provider(), observation) {
        // `completeProviderEvidence`: a late cancellation keeps the facts.
        Ok(evidence) if context.cancellation.reason().is_some() => ToolOutput::Failure(
            AnalysisError::cancelled(LIST).retain_partial_observation(evidence.into_value()),
        ),
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(_) => ToolOutput::Failure(AnalysisError::output(
            LIST,
            "Electron provider returned a malformed target list.",
        )),
    }
}

fn list_targets(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let endpoint = match cdp::parse_http_endpoint(
        input
            .get("cdp_endpoint")
            .and_then(Value::as_str)
            .unwrap_or(""),
    ) {
        Ok(endpoint) => endpoint,
        Err(message) => {
            return cdp::refinement_failure(
                LIST,
                vec![Refinement::new(vec![json!("cdp_endpoint")], message)],
            );
        }
    };
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(LIST));
    }
    let discovered = match discovery::open(&endpoint, LIST, cancellation) {
        Ok(discovered) => discovered,
        Err(error) => return ToolOutput::Failure(error),
    };
    let mut allowed: Vec<Value> = Vec::new();
    let (mut unsupported_url, mut non_page, mut unconnectable, mut examined) =
        (0_u64, 0_u64, 0_u64, 0_u64);
    let mut failure: Option<AnalysisError> = None;
    for target in &discovered.targets {
        if cancellation.reason().is_some() {
            failure = Some(AnalysisError::cancelled(LIST));
            break;
        }
        examined += 1;
        if target.kind != "page" {
            non_page += 1;
            continue;
        }
        let path = match file_scope::authorized_file(&target.url, cancellation, LIST) {
            Ok(path) => path,
            Err(error) => {
                examined -= 1;
                failure = Some(error);
                break;
            }
        };
        let Some(path) = path else {
            unsupported_url += 1;
            continue;
        };
        if !discovered.has_target_web_socket(target) {
            unconnectable += 1;
            continue;
        }
        let mut entry = Map::new();
        entry.insert("target_id".into(), Value::String(target.id.clone()));
        entry.insert("type".into(), Value::String(target.kind.clone()));
        entry.insert("title".into(), Value::String(target.title.clone()));
        entry.insert("file_path".into(), Value::String(path));
        entry.insert(
            "attached".into(),
            target.attached.map_or(Value::Null, Value::Bool),
        );
        allowed.push(Value::Object(entry));
    }
    // `compareUnicodeCodePoints`: UTF-8 byte order is code point order.
    allowed.sort_by(|left, right| left["target_id"].as_str().cmp(&right["target_id"].as_str()));
    if failure.is_none() && cancellation.reason().is_some() {
        failure = Some(AnalysisError::cancelled(LIST));
    }
    let excluded = json!({ "unsupported_url": unsupported_url, "non_page": non_page });
    if let Some(error) = failure {
        if !matches!(error.kind, ErrorKind::Cancelled { .. }) {
            return ToolOutput::Failure(error);
        }
        let mut diagnostics = Map::new();
        diagnostics.insert(
            "completed_prefix".into(),
            json!({
                "browser_version": discovered.version,
                "examined_targets": examined,
                "discovered_targets": discovered.targets.len(),
                "allowed_targets": allowed,
                "excluded": excluded,
                "unconnectable_targets": unconnectable,
                "coverage": "partial: target authorization stopped; remaining targets are unknown",
            }),
        );
        return ToolOutput::Failure(AnalysisError::cancelled(LIST).with_diagnostics(diagnostics));
    }
    let mut limitations = vec![Value::String(
        "Every local file page exposed by the selected loopback CDP endpoint is eligible for listing.".to_owned(),
    )];
    if unconnectable > 0 {
        limitations.push(Value::String(format!(
            "{unconnectable} otherwise allowed page target(s) lacked a validated direct CDP WebSocket and were excluded."
        )));
    }
    if allowed.iter().any(|target| target["attached"].is_null()) {
        limitations.push(Value::String(
            "CDP discovery omitted attachment state for one or more targets; attached is reported as unknown.".to_owned(),
        ));
    }
    let result = json!({
        "browser": discovered.version,
        "targets": allowed,
        "excluded": excluded,
        "limitations": limitations,
    });
    list_evidence(context, json!({ "cdp_endpoint": endpoint.url }), result)
}
