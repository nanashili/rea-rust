//! Session tool `build_call_path`.
//!
//! Compatibility owner: `registerCallPath` (`src/server/registerInvestigationTools.ts`).

use crate::derived::{
    InvestigationUnknown, deliver, evidence_closure, function_evidence_ids, probe,
    record_workflow_evidence, run_derived_operation, with_session_admission,
};
use crate::session::investigation::call_path as domain;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::Value;

/// `CALL_PATH_PROVIDER` (`src/application/InvestigationProviders.ts`).
fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-call-path",
        "REA call path reconstruction",
        Some("1".to_owned()),
    )
}

/// Handler for `build_call_path`.
pub fn build_call_path(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    with_session_admission(context, || run(context, &input))
}

fn run(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    // evidenceClosure(session, functionEvidenceIds(input.functions)) first.
    let seed_ids = function_evidence_ids(
        input
            .get("functions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten(),
    );
    let links = match evidence_closure(context.session, &seed_ids) {
        Ok(links) => links,
        Err(error) => return ToolOutput::Failure(error),
    };

    let result =
        match run_derived_operation(context, context.name(), || domain::build_call_path(input)) {
            Ok(result) => result,
            Err(error) => return ToolOutput::Failure(error),
        };

    let limitations = string_array(result.get("limitations"));
    let parameters = domain::handler_parameters(input);
    let observation = Observation::new(context.name().to_owned(), parameters, result.clone())
        .predicate("rea.call-path")
        .confidence("derived")
        .authority("analyst-inference")
        .limitations(limitations)
        .links(links);
    let evidence = match Evidence::create(None, &provider(), observation) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::output(context.name(), error.to_string()));
        }
    };

    let unresolved = result.get("status").and_then(Value::as_str) == Some("unknown");
    let recorded = record_workflow_evidence(
        context.session,
        &evidence,
        unresolved,
        InvestigationUnknown {
            question: "Can the requested call path be established from complete analysis?",
            domain: "call-path",
            required_authority: Some("shipped-artifact"),
            required_confidence: "derived",
            probes: vec![probe(
                "analyze_function",
                "Collect complete callee dossiers for the reported frontier addresses.",
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
