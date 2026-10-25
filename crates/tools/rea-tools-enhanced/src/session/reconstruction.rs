//! Session tool `verify_reconstruction`.
//!
//! The application layer owns reconstruction semantics. This adapter owns the
//! session lifecycle: it evaluates the caller's finite specification against
//! the session's authenticated bundle, links the resulting Evidence closure,
//! and retains unresolved verification as a residual unknown.

use crate::derived::{
    InvestigationUnknown, deliver, evidence_closure, record_workflow_evidence,
    run_derived_operation, with_session_admission,
};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Value, json};

fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-reconstruction-verifier",
        "REA reconstruction verifier",
        Some("1".to_owned()),
    )
}

/// Handler for `verify_reconstruction`.
pub fn verify_reconstruction(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    with_session_admission(context, || run(context, &input))
}

fn run(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let bundle = match context.session.export_bundle() {
        Ok(bundle) => bundle,
        Err(error) => return ToolOutput::Failure(error),
    };

    let result = match run_derived_operation(context, context.name(), || {
        rea_application::reconstruction::verification::project(input, &bundle)
            .map_err(|error| AnalysisError::output(context.name(), error.to_string()))
    }) {
        Ok(result) => result,
        Err(error) => return ToolOutput::Failure(error),
    };

    let links = match evidence_closure(context.session, &string_array(result.get("evidence_links")))
    {
        Ok(links) => links,
        Err(error) => return ToolOutput::Failure(error),
    };

    let specification = input
        .get("specification")
        .and_then(Value::as_object)
        .expect("application validation established specification");
    let claim_ids = specification
        .get("claims")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|claim| claim.get("claim_id").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let parameters = json!({
        "specification_sha256": result.get("specification_sha256"),
        "claim_ids": claim_ids,
    });
    let observation = Observation::new(context.name().to_owned(), parameters, result.clone())
        .predicate("rea.reconstruction-verification")
        .confidence("derived")
        .authority("analyst-inference")
        .limitations(string_array(result.get("limitations")))
        .links(links);
    let evidence = match Evidence::create(None, &provider(), observation) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::output(context.name(), error.to_string()));
        }
    };

    let unresolved = result.get("status").and_then(Value::as_str) == Some("unknown");
    let probes = workflow_probes(result.get("recommended_probes"));
    let recorded = record_workflow_evidence(
        context.session,
        &evidence,
        unresolved,
        InvestigationUnknown {
            question: "Does the reconstruction satisfy every declared claim?",
            domain: "reconstruction-verification",
            required_authority: None,
            required_confidence: "derived",
            probes,
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

/// `registerReconstruction` keeps only the workflow probe fields accepted by
/// the residual-unknown registry. The richer claim and unknown identifiers
/// remain available in the verification Evidence result itself.
fn workflow_probes(value: Option<&Value>) -> Vec<Value> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|probe| {
            Some(json!({
                "operation": probe.get("operation")?.as_str()?,
                "rationale": probe.get("rationale")?.as_str()?,
            }))
        })
        .collect()
}
