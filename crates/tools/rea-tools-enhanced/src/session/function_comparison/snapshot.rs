//! Parse one analyze_function Evidence record into a comparison snapshot.
//!
//! Compatibility owners: `functionDossierEvidence.parseFunctionEvidence`,
//! `functionCallCoverage.assessFunctionCallCoverage`,
//! `relationshipCoverage.relationshipCoverageLimitations`.
use crate::derived::invalid_value;
use crate::domain::dossier::function_dossier;
use crate::js::{compare_code_points, unique_sorted};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use serde_json::Value;
const OPERATION: &str = "compare_functions";
/// Complete function observation parsed from one analyze_function Evidence.
pub struct FunctionSnapshot {
    pub evidence_id: String,
    /// The caller Evidence record value.
    pub evidence: Value,
    /// Authenticated subject (never null here).
    pub subject: Value,
    /// Strictly parsed dossier.
    pub dossier: Value,
    pub limitations: Vec<String>,
    pub call_coverage_blockers: Vec<String>,
    pub call_coverage_diagnostics: Vec<String>,
}
impl FunctionSnapshot {
    pub fn subject_sha256(&self) -> &str {
        self.subject["digest"]["sha256"]
            .as_str()
            .unwrap_or_default()
    }
}
/// `relationshipCoverageLimitations`.
pub fn relationship_coverage_limitations(coverage: Option<&Value>) -> Vec<String> {
    match coverage {
        None | Some(Value::Null) => {
            vec!["Provider did not report relationship coverage.".to_owned()]
        }
        Some(coverage) => match coverage["status"].as_str() {
            Some("complete") => Vec::new(),
            Some("partial") => coverage["limitations"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            Some("unknown") => coverage["reason"]
                .as_str()
                .map(str::to_owned)
                .into_iter()
                .collect(),
            _ => vec!["Provider did not report relationship coverage.".to_owned()],
        },
    }
}
/// `assessFunctionCallCoverage`.
fn assess_call_coverage(coverage: Option<&Value>, dossier: &Value) -> (Vec<String>, Vec<String>) {
    let mut blockers: Vec<String> = relationship_coverage_limitations(coverage);
    for call in dossier["unresolved_calls"].as_array().into_iter().flatten() {
        let address = call["address"].as_str().unwrap_or_default();
        let reason = call["reason"].as_str().unwrap_or_default();
        blockers.push(format!("Unresolved call at {address}: {reason}"));
    }
    let blockers = unique_sorted(blockers);
    let diagnostics = coverage
        .and_then(|coverage| coverage["diagnostics"].as_array())
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned);
    (blockers, unique_sorted(diagnostics))
}
/// `parseFunctionEvidence`. Reusable entry point for the investigation tools.
#[allow(dead_code)]
pub fn parse_function_evidence(input: &Value) -> Result<FunctionSnapshot, AnalysisError> {
    let evidence = crate::derived::parse_evidence(input).map_err(|error| {
        AnalysisError::evidence_integrity(crate::derived::evidence_failure_message(&error))
    })?;
    parse_snapshot(evidence)
}
/// Build the snapshot from an already-authenticated Evidence record.
pub fn snapshot_from_evidence(evidence: Evidence) -> Result<FunctionSnapshot, AnalysisError> {
    parse_snapshot(evidence)
}
fn parse_snapshot(evidence: Evidence) -> Result<FunctionSnapshot, AnalysisError> {
    let value = evidence.value().clone();
    if value["operation"].as_str() != Some("analyze_function") {
        return Err(invalid_value(
            OPERATION,
            "Function comparison requires analyze_function Evidence",
        ));
    }
    if value["subject"].is_null() {
        return Err(invalid_value(
            OPERATION,
            "Function comparison requires artifact-bound Evidence",
        ));
    }
    let dossier = function_dossier()
        .parse(&value["normalized_result"])
        .map_err(|_| {
            invalid_value(
                OPERATION,
                "provider output did not match the dossier contract",
            )
        })?;
    let evidence_limitations = value["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned);
    let dossier_limitations = dossier["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned);
    let mut limitations: Vec<String> = evidence_limitations.chain(dossier_limitations).collect();
    // `[...new Set(...)].sort(compareUnicodeCodePoints)`
    let mut seen = std::collections::HashSet::new();
    limitations.retain(|item| seen.insert(item.clone()));
    limitations.sort_by(|a, b| compare_code_points(a, b));
    let coverage = value
        .get("relationship_coverage")
        .filter(|value| !value.is_null());
    let (blockers, diagnostics) = assess_call_coverage(coverage, &dossier);
    Ok(FunctionSnapshot {
        evidence_id: evidence.id().to_owned(),
        subject: value["subject"].clone(),
        evidence: value,
        dossier,
        limitations,
        call_coverage_blockers: blockers,
        call_coverage_diagnostics: diagnostics,
    })
}
