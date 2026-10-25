//! Session tool `find_changed_behavior`.
//!
//! Compatibility owner: `registerChangedBehavior`
//! (`src/server/registerInvestigationTools.ts`).
use crate::derived::{
    InvestigationUnknown, deliver, evidence_closure, is_incomplete, probe,
    record_workflow_evidence, run_derived_operation, with_session_admission,
};
use crate::session::investigation::changed_behavior as domain;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Value, json};

/// `CHANGED_BEHAVIOR_PROVIDER` (`src/application/InvestigationProviders.ts`).
fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-changed-behavior",
        "REA changed behavior investigation",
        Some("1".to_owned()),
    )
}

/// Handler for `find_changed_behavior`.
pub fn find_changed_behavior(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let input = match rea_mcp::schema::parse_application_input(context.name(), &input) {
        Ok(input) => input,
        Err(error) => return ToolOutput::Failure(error),
    };

    with_session_admission(context, || run(context, &input))
}

fn run(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let computed = match run_derived_operation(context, context.name(), || {
        domain::find_changed_behavior(input)
    }) {
        Ok(computed) => computed,
        Err(error) => return ToolOutput::Failure(error),
    };
    let result = computed.result;
    let comparison_evidence_ids = computed.comparison_evidence_ids;

    // evidenceClosure(session, result.evidence_links).
    let seed_ids: Vec<String> = result
        .get("evidence_links")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let links = match evidence_closure(context.session, &seed_ids) {
        Ok(links) => links,
        Err(error) => return ToolOutput::Failure(error),
    };

    let limitations = string_array(result.get("limitations"));
    let parameters = json!({ "comparison_evidence_ids": comparison_evidence_ids });
    let observation = Observation::new(context.name().to_owned(), parameters, result.clone())
        .predicate("rea.changed-behavior")
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

    let behavior_status = result
        .get("behavior_status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let unresolved = is_incomplete(behavior_status);
    let recorded = record_workflow_evidence(
        context.session,
        &evidence,
        unresolved,
        InvestigationUnknown {
            question: "Did both versions behave the same under a complete controlled replay?",
            domain: "changed-behavior",
            required_authority: Some("controlled-replay"),
            required_confidence: "observed",
            probes: vec![probe(
                "capture_process_scenario",
                "Capture both versions under the same bounded scenario and environment.",
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
