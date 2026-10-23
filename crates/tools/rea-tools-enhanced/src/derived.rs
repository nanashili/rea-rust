//! Shared runtime for Evidence-composed session investigation tools.
//!
//! Compatibility owners: `runAdmittedToolOperation`
//! (`admittedToolOperation.ts`), `runDerivedOperation`
//! (`runDerivedOperation.ts`), `recordSessionEvidenceSources`
//! (`sessionEvidence.ts`), `parseEvidence` (`domain/evidence.ts`) and the
//! closure/recording helpers of `registerInvestigationTools/helpers.ts`.
use crate::analysis::ProgressSink;
use crate::workflow::{WorkflowUnknown, record_derived_evidence, workflow_unknown_input};
use rea_core::analysis_error::{AnalysisError, ErrorKind, InputIssue};
use rea_core::evidence::envelope::Evidence;
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use rea_mcp::{Session, ToolContext, ToolOutput};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;

/// Run one complete session tool inside the binary session's admission.
///
/// The original session admission only serializes the operation against
/// target transitions; it admits work when no target is open. The session
/// port reports `NoBinaryOpenError` in that state, so the Evidence-only
/// operation then runs directly after the same cancellation check.
pub fn with_session_admission(
    context: &ToolContext<'_>,
    work: impl FnOnce() -> ToolOutput,
) -> ToolOutput {
    let mut pending = Some(work);
    let admitted = rea_tools_binary::port::with_admitted_analysis(
        context.session,
        context.name(),
        &context.cancellation,
        |_port| pending.take().map(|work| work()),
    );
    match admitted {
        Ok(Some(output)) => output,
        Ok(None) => ToolOutput::Failure(AnalysisError::cancelled(context.name())),
        Err(error) => match (&error.kind, pending.take()) {
            (ErrorKind::NoBinaryOpen, Some(work)) => {
                if context.cancellation.reason().is_some() {
                    ToolOutput::Failure(AnalysisError::cancelled(context.name()))
                } else {
                    work()
                }
            }
            _ => ToolOutput::Failure(error),
        },
    }
}

/// An input failure for a computation that rejected malformed values
/// (the original `TypeError`/`ZodError` mapping).
pub fn invalid_value(operation: &str, message: impl Into<String>) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue {
            path: Vec::new(),
            reason: "invalid_value",
            message: Some(message.into()),
            expected: None,
            minimum: None,
            maximum: None,
        }],
    )
}

/// `runDerivedOperation`: progress phases and cancellation guards around a
/// synchronous derivation.
pub fn run_derived_operation<T>(
    context: &ToolContext<'_>,
    operation: &str,
    compute: impl FnOnce() -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    let progress = ProgressSink::new(context.progress.clone());
    let cancelled = || context.cancellation.reason().is_some();
    progress.report("prepare", &format!("Preparing {operation}"), false);
    if cancelled() {
        return Err(AnalysisError::cancelled(operation));
    }
    let value = compute()?;
    progress.report("compute", &format!("Computed {operation}"), false);
    if cancelled() {
        return Err(AnalysisError::cancelled(operation));
    }
    progress.report("complete", &format!("Completed {operation}"), true);
    if cancelled() {
        return Err(AnalysisError::cancelled(operation));
    }
    Ok(value)
}

/// Zod's `ZodError.message` for one custom issue (pretty JSON issue list).
fn zod_custom_issue(path: &[&str], message: &str) -> String {
    serde_json::to_string_pretty(&json!([{
        "code": "custom",
        "path": path,
        "message": message,
    }]))
    .unwrap_or_default()
}

/// Authentication failure text in the original parser's wording.
pub fn evidence_failure_message(error: &EvidenceRecordError) -> String {
    match error {
        EvidenceRecordError::SemanticIdMismatch => zod_custom_issue(
            &["evidence_id"],
            "Evidence semantic identifier does not match its record",
        ),
        other => other.to_string(),
    }
}

/// `parseEvidence`: authenticate one caller-supplied Evidence record and
/// return its canonical value.
pub fn parse_evidence(value: &Value) -> Result<Evidence, EvidenceRecordError> {
    let raw = serde_json::value::to_raw_value(value).map_err(EvidenceRecordError::Json)?;
    let record = EvidenceRecord::parse(&raw)?;
    let id = record.evidence_id().to_owned();
    // Keep the caller's projection (field order) as the delivered value; the
    // record authenticated exactly these semantic contents.
    Ok(Evidence::from_authenticated(id, value.clone()))
}

/// `recordSessionEvidenceSources`: record sources in order, stopping at the
/// first session rejection.
pub fn record_sources(session: &Arc<Session>, sources: &[&Evidence]) -> Result<(), AnalysisError> {
    for source in sources {
        session.record(source)?;
    }
    Ok(())
}

/// Sorted unique identifiers.
pub fn unique_ids(ids: impl IntoIterator<Item = String>) -> Vec<String> {
    ids.into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// `comparisonClosure`: comparison IDs and their direct links.
pub fn comparison_closure<'a>(comparisons: impl IntoIterator<Item = &'a Value>) -> Vec<String> {
    let mut ids = Vec::new();
    for evidence in comparisons {
        if let Some(id) = evidence.get("evidence_id").and_then(Value::as_str) {
            ids.push(id.to_owned());
        }
        for link in evidence
            .get("evidence_links")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            ids.push(link.to_owned());
        }
    }
    unique_ids(ids)
}

/// `functionEvidenceIds`.
pub fn function_evidence_ids<'a>(records: impl IntoIterator<Item = &'a Value>) -> Vec<String> {
    unique_ids(
        records
            .into_iter()
            .filter_map(|evidence| evidence.get("evidence_id").and_then(Value::as_str))
            .map(str::to_owned),
    )
}

/// `evidenceClosure`: every retained record reachable from `seed_ids`.
pub fn evidence_closure(
    session: &Arc<Session>,
    seed_ids: &[String],
) -> Result<Vec<String>, AnalysisError> {
    let mut visited = BTreeSet::new();
    let mut pending = seed_ids.to_vec();
    while let Some(evidence_id) = pending.pop() {
        if visited.contains(&evidence_id) {
            continue;
        }
        let Some(evidence) = session.evidence(&evidence_id) else {
            return Err(AnalysisError::evidence_integrity(
                "Investigation input has a dangling Evidence link",
            ));
        };
        visited.insert(evidence_id);
        pending.extend(
            evidence
                .get("evidence_links")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        );
    }
    Ok(visited.into_iter().collect())
}

/// `isIncomplete`.
pub fn is_incomplete(status: &str) -> bool {
    status == "unknown" || status == "truncated"
}

/// Residual question attached to an unresolved investigation result.
pub struct InvestigationUnknown {
    pub question: &'static str,
    pub domain: &'static str,
    pub required_authority: Option<&'static str>,
    pub required_confidence: &'static str,
    pub probes: Vec<Value>,
}

/// `recordWorkflowEvidence`: retain the result, with a high-severity unknown
/// when it is unresolved.
pub fn record_workflow_evidence(
    session: &Arc<Session>,
    evidence: &Evidence,
    unresolved: bool,
    input: InvestigationUnknown,
) -> Result<(), AnalysisError> {
    if !unresolved {
        return record_derived_evidence(session, evidence, None);
    }
    let unknown = workflow_unknown_input(
        evidence.id(),
        WorkflowUnknown {
            question: input.question.to_owned(),
            severity: "high",
            domain: input.domain.to_owned(),
            required_authority: input.required_authority,
            required_confidence: input.required_confidence,
            recommended_probes: input.probes,
            comparison_conclusion_scope: None,
        },
    )?;
    record_derived_evidence(session, evidence, Some(unknown))
}

/// Deliver derived Evidence after its recording outcome.
pub fn deliver(evidence: Evidence, recorded: Result<(), AnalysisError>) -> ToolOutput {
    match recorded {
        Ok(()) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// One recommended probe.
pub fn probe(operation: &str, rationale: &str) -> Value {
    json!({ "operation": operation, "rationale": rationale })
}
