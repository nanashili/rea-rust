//! Shared Evidence for composed binary workflows.
//!
//! Compatibility owners: `REA_WORKFLOW_PROVIDER` / `workflowAnalysisProfile`
//! (`InvestigationProviders.ts`), `createWorkflowEvidence`,
//! `workflowSnapshotRecord` and `recordWorkflowUnknowns`
//! (`WorkflowEvidence.ts`) and `workflowUnknownInput` (`WorkflowUnknown.ts`).
use rea_analysis::{BinaryTarget, ProviderIdentity, create_analysis_profile};
use rea_application::ledger::artifact_records::{RecordError, UnknownMutationFailure};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::Session;
use rea_mcp::session::record_error;
use serde_json::{Map, Value, json};
use std::sync::Arc;

/// Provider identity for deterministic composed analysis workflows.
pub fn workflow_provider() -> ProviderIdentity {
    ProviderIdentity::new(
        "rea-workflow",
        "REA composed investigation workflow",
        Some("1".to_owned()),
    )
}

/// Commit a workflow result to its upstream profile and semantic revision.
pub fn workflow_analysis_profile(
    upstream: &Value,
    operation: &str,
) -> Result<Value, AnalysisError> {
    let revision = match operation {
        "binary_overview" => 4,
        "batch_decompile" | "get_call_graph" | "trace_feature" => 3,
        _ => 1,
    };
    create_analysis_profile(
        &workflow_provider(),
        json!({
            "upstream_analysis_profile": upstream,
            "source_limitations": "provider-operation-caveats-v1",
            "workflow_revision": revision,
        }),
    )
}

/// `batchProcedureLocations`: unique resolved canonical entries in item order.
fn batch_procedure_locations(result: &Value) -> Vec<Value> {
    let Some(items) = result.get("items").and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut addresses: Vec<&str> = Vec::new();
    for item in items {
        let Some(procedure) = item.as_object().and_then(|item| item.get("procedure")) else {
            continue;
        };
        if procedure.get("status").and_then(Value::as_str) == Some("resolved")
            && let Some(address) = procedure.get("address").and_then(Value::as_str)
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    addresses
        .into_iter()
        .map(|address| json!({ "kind": "address", "address": address }))
        .collect()
}

/// `createWorkflowEvidence`.
pub fn create_workflow_evidence(
    target: Option<&BinaryTarget>,
    operation: &str,
    parameters: Value,
    result: Value,
    upstream_profile: Option<&Value>,
    upstream_limitations: Vec<String>,
) -> Result<Evidence, AnalysisError> {
    let mut limitations = Vec::with_capacity(upstream_limitations.len() + 1);
    limitations.push("Derived by an REA composed workflow.".to_owned());
    limitations.extend(upstream_limitations);
    let locations = if operation == "batch_decompile" {
        batch_procedure_locations(&result)
    } else {
        Vec::new()
    };
    let mut observation = Observation::new(operation, parameters, result)
        .confidence("derived")
        .limitations(limitations)
        .locations(locations);
    if let Some(upstream) = upstream_profile {
        observation = observation.profile(workflow_analysis_profile(upstream, operation)?);
    }
    let subject = target.map(BinaryTarget::subject);
    Evidence::create(
        subject.as_ref(),
        &workflow_provider().evidence_provider(),
        observation,
    )
    .map_err(|error| AnalysisError::output(operation, error.to_string()))
}

/// JavaScript `String.prototype.trim` whitespace.
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

/// Fields of one automatic residual question before Evidence scoping.
pub struct WorkflowUnknown {
    pub question: String,
    pub severity: &'static str,
    pub domain: String,
    pub required_authority: Option<&'static str>,
    pub required_confidence: &'static str,
    pub recommended_probes: Vec<Value>,
    /// `comparison_conclusion_scope`, placed after `domain` when present.
    pub comparison_conclusion_scope: Option<Value>,
}

/// `workflowUnknownInput`: scope a question to its immutable result.
///
/// The question is validated like the registry's trimmed, non-empty text.
pub fn workflow_unknown_input(
    evidence_id: &str,
    input: WorkflowUnknown,
) -> Result<Value, AnalysisError> {
    let trimmed = input.question.trim_matches(is_javascript_whitespace);
    if trimmed.is_empty() {
        return Err(AnalysisError::unknown_registry("invalid-transition"));
    }
    let mut object = Map::new();
    object.insert(
        "question".into(),
        json!(format!("{trimmed} (Evidence {evidence_id})")),
    );
    object.insert("severity".into(), json!(input.severity));
    object.insert("domain".into(), json!(input.domain));
    if let Some(scope) = input.comparison_conclusion_scope {
        object.insert("comparison_conclusion_scope".into(), scope);
    }
    object.insert("required_authority".into(), json!(input.required_authority));
    object.insert(
        "required_confidence".into(),
        json!(input.required_confidence),
    );
    object.insert("required_environment".into(), Value::Null);
    object.insert(
        "recommended_probes".into(),
        Value::Array(input.recommended_probes),
    );
    object.insert("relationships".into(), json!([]));
    object.insert("supporting_evidence_ids".into(), json!([evidence_id]));
    object.insert("contradicting_evidence_ids".into(), json!([]));
    Ok(Value::Object(object))
}

fn raw(value: &Value) -> Result<Box<serde_json::value::RawValue>, AnalysisError> {
    serde_json::value::to_raw_value(value)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
}

/// The active target subject used for analyst-registry mutations.
fn active_subject_raw(
    session: &Arc<Session>,
) -> Result<Option<Box<serde_json::value::RawValue>>, AnalysisError> {
    match rea_tools_binary::port::active_target(session) {
        Some(target) => raw(&target.subject_json()).map(Some),
        None => Ok(None),
    }
}

/// `recordWorkflowUnknowns`: retain residual questions of traces and native
/// API inspections; an already-recorded question is not an error.
pub fn record_workflow_unknowns(
    session: &Arc<Session>,
    name: &str,
    result: &Value,
    evidence_id: &str,
) -> Result<(), AnalysisError> {
    if !matches!(
        name,
        "trace_feature" | "trace_call_path" | "inspect_native_api"
    ) {
        return Ok(());
    }
    let Some(questions) = result
        .as_object()
        .and_then(|object| object.get("residual_unknowns"))
        .and_then(Value::as_array)
    else {
        return Ok(());
    };
    let native = name == "inspect_native_api";
    for question in questions {
        let Some(question) = question.as_str() else {
            continue;
        };
        let input = workflow_unknown_input(
            evidence_id,
            WorkflowUnknown {
                question: question.to_owned(),
                severity: "medium",
                domain: if native { "native-api" } else { "control-flow" }.to_owned(),
                required_authority: Some("shipped-artifact"),
                required_confidence: "observed",
                recommended_probes: vec![json!({
                    "operation": name,
                    "rationale": if native {
                        "Confirm the unsupported boundary with a capable provider or ABI probe."
                    } else {
                        "Continue with a focused query or another available provider."
                    },
                })],
                comparison_conclusion_scope: None,
            },
        )?;
        let subject = active_subject_raw(session)?;
        match session
            .records()
            .record_unknown(&raw(&input)?, subject.as_deref())
        {
            Ok(_) | Err(RecordError::UnknownMutation(UnknownMutationFailure::AlreadyExists)) => {}
            Err(error) => return Err(record_error(error)),
        }
    }
    Ok(())
}

/// `recordDerivedEvidence`: retain derived Evidence, atomically with its
/// supported unknown when one applies.
pub fn record_derived_evidence(
    session: &Arc<Session>,
    evidence: &Evidence,
    unknown: Option<Value>,
) -> Result<(), AnalysisError> {
    match unknown {
        None => session.record(evidence),
        Some(input) => {
            let evidence_raw = evidence
                .to_raw()
                .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
            session
                .records()
                .record_evidence_with_unknown(&evidence_raw, &raw(&input)?)
                .map_err(record_error)
        }
    }
}
