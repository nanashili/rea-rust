//! Session tool `correlate_static_and_runtime`.
//!
//! Compatibility owner: `registerStaticRuntime` (`src/server/registerInvestigationTools.ts`).

use crate::derived::{
    InvestigationUnknown, comparison_closure, deliver, evidence_closure, probe,
    record_workflow_evidence, run_derived_operation, with_session_admission,
};
use crate::session::investigation::static_runtime as domain;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::Value;

/// `STATIC_RUNTIME_PROVIDER`.
fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-static-runtime-correlation",
        "REA static/runtime correlation",
        Some("1".to_owned()),
    )
}

/// Handler for `correlate_static_and_runtime`.
pub fn correlate_static_and_runtime(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    with_session_admission(context, || run(context, &input))
}

fn run(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let seed_records = domain::comparison_closure_seed(input);
    let seed_ids = comparison_closure(seed_records.iter());
    let links = match evidence_closure(context.session, &seed_ids) {
        Ok(links) => links,
        Err(error) => return ToolOutput::Failure(error),
    };

    let result = match run_derived_operation(context, context.name(), || {
        domain::correlate_static_and_runtime(input)
    }) {
        Ok(result) => result,
        Err(error) => return ToolOutput::Failure(error),
    };

    let limitations = string_array(result.get("limitations"));
    let observation = Observation::new(
        context.name().to_owned(),
        domain::handler_parameters(input),
        result.clone(),
    )
    .predicate("rea.static-runtime-correlation")
    .confidence("inferred")
    .authority("analyst-inference")
    .limitations(limitations)
    .links(links);
    let evidence = match Evidence::create(None, &provider(), observation) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::output(context.name(), error.to_string()));
        }
    };

    let status = result
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let unresolved = status == "unknown" || status == "truncated";
    let recorded = record_workflow_evidence(
        context.session,
        &evidence,
        unresolved,
        InvestigationUnknown {
            question: "Does runtime behavior match the available static analysis?",
            domain: "static-runtime-correlation",
            required_authority: None,
            required_confidence: "derived",
            probes: vec![probe(
                "capture_process_scenario",
                "Repeat runtime observations and complete the mapped static comparison Evidence.",
            )],
        },
    );
    deliver(evidence, recorded)
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}
