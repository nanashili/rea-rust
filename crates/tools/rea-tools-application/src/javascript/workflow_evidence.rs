//! Derived workflow Evidence.
//!
//! Compatibility owner:
//! `src/application/javascript/JavaScriptApplicationWorkflowEvidence.ts`.
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use serde_json::Value;

/// `JAVASCRIPT_APPLICATION_WORKFLOW_PROVIDER`.
pub fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-javascript-application-workflows",
        "REA JavaScript application workflows",
        Some("1".into()),
    )
}

/// Subject-free inferred Evidence whose limitations and links come from the
/// result, as every `create*Evidence` helper of the original.
pub fn create(
    predicate: &str,
    operation: &str,
    parameters: Value,
    result: Value,
) -> Result<Evidence, AnalysisError> {
    let limitations = strings(&result["limitations"]);
    let links = strings(&result["evidence_links"]);
    let observation = Observation::new(operation, parameters, result)
        .predicate(predicate)
        .confidence("inferred")
        .authority("analyst-inference")
        .limitations(limitations)
        .links(links);
    rea_mcp::support::evidence(None, &provider(), observation)
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
