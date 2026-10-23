//! `reconcile_javascript_runtime`: derive a combined JavaScript Application
//! Graph from verified static analysis and passive runtime Evidence.
//!
//! Compatibility owners: the registration in `src/server/registerElectronTools.ts`,
//! `src/application/javascript/JavaScriptRuntimeReconciliationService.ts`,
//! `JavaScriptRuntimeReconciliationEvidence.ts`, and
//! `src/domain/javascript/javascriptRuntimeReconciliation*.ts`,
//! `javascriptRuntimeStaticCandidates.ts` and `javascriptRuntimeLoadState.ts`.
//!
//! The original accepts only inline Evidence (no retained references) and
//! records nothing besides the derived Evidence.
mod candidates;
mod captures;
mod graph;
mod input;
mod jag;
mod layers;
mod load_state;
mod matching;
mod paths;
mod result;
mod runtime;

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{EvidenceProvider, Observation};
use rea_mcp::schema::{Issue, validation_error_text};
use rea_mcp::{Registry, ToolOutput};
use serde_json::{Value, json};

const OPERATION: &str = "reconcile_javascript_runtime";

/// A construction defect: the original's `TypeError`/schema failure while
/// producing the result, projected as `AnalysisProtocolError`.
#[derive(Debug)]
pub struct Defect;

/// `digestCanonicalValue(value, ...)`.
pub fn digest(value: &Value) -> Result<String, Defect> {
    rea_core::canonical_json::digest(value).map_err(|_| Defect)
}

/// `invalidInput(path, message)`: one custom Zod issue.
pub fn custom(path: &[Value], message: impl Into<String>) -> InputIssue {
    InputIssue {
        path: path.to_vec(),
        reason: "invalid_value",
        message: Some(message.into()),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

/// `[...path, ...more]`.
pub fn join(path: &[Value], more: &[Value]) -> Vec<Value> {
    let mut full = path.to_vec();
    full.extend_from_slice(more);
    full
}

pub fn str_of(value: &Value) -> &str {
    value.as_str().unwrap_or_default()
}

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |_context, input| reconcile(input));
}

fn reconcile(raw: Value) -> ToolOutput {
    let input = match input::refine(&raw) {
        Ok(input) => input,
        Err(issues) => return refinement_failure(issues),
    };
    let input = input::normalize_runtime_mapping_roots(input);
    let layers = match layers::parse_static_layers(&input["static_layers"]) {
        Ok(layers) => layers,
        Err(issues) => return ToolOutput::Failure(AnalysisError::input(OPERATION, issues)),
    };
    let captures = match captures::parse_runtime_captures(&input["runtime_observations"]) {
        Ok(captures) => captures,
        Err(issues) => return ToolOutput::Failure(AnalysisError::input(OPERATION, issues)),
    };
    let result = match reconcile_parsed(&layers, &captures) {
        Ok(result) => result,
        Err(Defect) => {
            return ToolOutput::Failure(AnalysisError::protocol(
                "JavaScript runtime reconciliation produced an invalid result",
            ));
        }
    };
    ToolOutput::from(create_evidence(&input, result))
}

/// The contract schema's Zod refinements fail at the SDK boundary in the
/// original, as text-only `Input validation error: ...` results; the typed
/// input failure is carried for in-process callers (as the web tools do).
fn refinement_failure(issues: Vec<InputIssue>) -> ToolOutput {
    let segment = |part: &Value| match part {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let rendered: Vec<Issue> = issues
        .iter()
        .map(|issue| Issue {
            path: issue.path.iter().map(segment).collect(),
            message: issue.message.clone().unwrap_or_default(),
        })
        .collect();
    let text = validation_error_text(OPERATION, &rendered);
    let error = AnalysisError::input(OPERATION, issues);
    ToolOutput::Raw(json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "error": error.project() },
        "isError": true,
    }))
}

/// `reconcileJavaScriptRuntime(parsed)`.
fn reconcile_parsed(
    layers: &[layers::Layer],
    captures: &[captures::Capture],
) -> Result<Value, Defect> {
    let runtime = runtime::project_runtime_captures(captures)?;
    let candidates = candidates::collect_static_runtime_candidates(layers);
    let matching =
        matching::reconcile_runtime_entities(&runtime.entities, &candidates, layers, captures)?;
    let load_states = load_state::classify_static_load_states(
        layers,
        captures,
        &runtime.entities,
        &matching.items,
    );
    let graph =
        graph::build_reconciled_application_graph(layers, captures, &runtime, &matching.edges)?;
    result::create_result(layers, captures, &runtime, &matching, &load_states, graph)
}

/// `createJavaScriptRuntimeReconciliationEvidence(input, result)`.
fn create_evidence(
    input: &Value,
    result: Value,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let static_layers: Vec<Value> = input["static_layers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|layer| {
            json!({
                "role": layer["role"],
                "evidence_id": layer["analysis"]["evidence_id"],
                "runtime_mappings": layer["runtime_mappings"],
            })
        })
        .collect();
    let runtime_ids: Vec<Value> = input["runtime_observations"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|observation| observation["evidence_id"].clone())
        .collect();
    let parameters = json!({
        "static_layers": static_layers,
        "runtime_evidence_ids": runtime_ids,
    });
    let strings = |value: &Value| -> Vec<String> {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    };
    let limitations = strings(&result["limitations"]);
    let links = strings(&result["evidence_links"]);
    let observation = Observation::new(OPERATION, parameters, result)
        .predicate("rea.javascript-runtime-reconciliation")
        .confidence("inferred")
        .authority("analyst-inference")
        .limitations(limitations)
        .links(links);
    let provider = EvidenceProvider::new(
        "rea-javascript-runtime-reconciliation",
        "REA JavaScript runtime reconciliation",
        Some("1".into()),
    );
    rea_mcp::support::evidence(None, &provider, observation)
}
