//! `workflowUnknownInput`: scope an automatic question to its immutable
//! result before registry mutation.
//!
//! Compatibility owner: `src/application/investigation/WorkflowUnknown.ts`.
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

/// One recommended probe (`{ operation, rationale }`).
pub struct Probe {
    pub operation: &'static str,
    pub rationale: &'static str,
}

/// Fields of one automatic residual question before Evidence scoping.
pub struct WorkflowUnknown {
    pub question: &'static str,
    pub severity: &'static str,
    pub domain: &'static str,
    pub required_authority: &'static str,
    pub required_confidence: &'static str,
    pub recommended_probes: Vec<Probe>,
}

/// ECMAScript `String.prototype.trim` whitespace, matching Zod `.trim()`.
fn is_javascript_whitespace(character: char) -> bool {
    matches!(
        character,
        '\u{0009}'..='\u{000D}'
            | '\u{0020}'
            | '\u{00A0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200A}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202F}'
            | '\u{205F}'
            | '\u{3000}'
            | '\u{FEFF}'
    )
}

/// `workflowUnknownInput(evidenceId, input)`.
///
/// Validates the question like the registry's trimmed, non-empty text, then
/// scopes it to the Evidence. Object key order mirrors the TypeScript spread
/// `{ ...input, question, supporting_evidence_ids, contradicting_evidence_ids }`:
/// `question` keeps its original position, the two id lists are appended.
pub fn workflow_unknown_input(
    evidence_id: &str,
    input: WorkflowUnknown,
) -> Result<Value, AnalysisError> {
    let trimmed = input.question.trim_matches(is_javascript_whitespace);
    if trimmed.is_empty() {
        return Err(AnalysisError::unknown_registry("invalid-transition"));
    }
    let probes: Vec<Value> = input
        .recommended_probes
        .iter()
        .map(|probe| json!({ "operation": probe.operation, "rationale": probe.rationale }))
        .collect();
    let mut object = Map::new();
    object.insert(
        "question".into(),
        json!(format!("{trimmed} (Evidence {evidence_id})")),
    );
    object.insert("severity".into(), json!(input.severity));
    object.insert("domain".into(), json!(input.domain));
    object.insert("required_authority".into(), json!(input.required_authority));
    object.insert(
        "required_confidence".into(),
        json!(input.required_confidence),
    );
    object.insert("required_environment".into(), Value::Null);
    object.insert("recommended_probes".into(), Value::Array(probes));
    object.insert("relationships".into(), json!([]));
    object.insert("supporting_evidence_ids".into(), json!([evidence_id]));
    object.insert("contradicting_evidence_ids".into(), json!([]));
    Ok(Value::Object(object))
}
