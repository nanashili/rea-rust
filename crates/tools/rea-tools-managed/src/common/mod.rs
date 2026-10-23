//! Shared helpers for the managed tool family and analysis views.
pub mod json;
pub mod schema;
pub mod view;

use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_core::evidence::record::EvidenceRecord;
use rea_mcp::Session;
use serde_json::Value;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

/// `MANAGED_STATIC_PROVIDER`.
pub fn managed_static_provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-dotnet-static",
        "REA managed static analysis provider",
        Some("1".into()),
    )
}

/// `MANAGED_WORKFLOW_PROVIDER`.
pub fn managed_workflow_provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-dotnet-workflows",
        "REA managed-code workflows",
        Some("1".into()),
    )
}

/// `ANALYSIS_VIEW_PROVIDER`.
pub fn analysis_view_provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-analysis-view",
        "REA analysis view projection",
        Some("1".into()),
    )
}

/// Evidence subject (`{ local_path, digest, format, architecture }`) as a target.
pub fn subject_target(subject: &Value) -> Option<SubjectTarget> {
    let subject = subject.as_object()?;
    Some(SubjectTarget {
        path: subject.get("local_path")?.as_str()?.to_owned(),
        sha256: subject.get("digest")?.get("sha256")?.as_str()?.to_owned(),
        format: subject.get("format")?.as_str()?.to_owned(),
        architecture: subject
            .get("architecture")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// `createEvidence`, mapping canonicalization failures into the error algebra.
pub fn create_evidence(
    operation: &str,
    target: Option<&SubjectTarget>,
    provider: &EvidenceProvider,
    observation: Observation,
) -> Result<Evidence, AnalysisError> {
    Evidence::create(target, provider, observation)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))
}

/// `parseEvidence`: authenticate a caller-supplied record and return its
/// canonical value. Failures become `EvidenceIntegrityError` with the
/// authenticator's message.
pub fn authenticate(value: &Value) -> Result<Value, AnalysisError> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    serde_json::from_str(record.raw().get())
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
}

/// Recently resolved retained records, parsed once from the ledger's text.
#[derive(Default)]
pub struct RecordCache {
    entries: Mutex<VecDeque<(String, Arc<Value>)>>,
}

const RECORD_CACHE_CAPACITY: usize = 4;

/// `resolveEvidenceInput` for a retained reference: the exact same-session
/// record, or `EvidenceReferenceError(missing)`.
pub fn retained_evidence(
    session: &Session,
    evidence_id: &str,
) -> Result<Arc<Value>, AnalysisError> {
    let cache = session.state::<RecordCache>();
    {
        let mut entries = cache
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(index) = entries.iter().position(|(id, _)| id == evidence_id)
            && let Some(entry) = entries.remove(index)
        {
            let value = Arc::clone(&entry.1);
            entries.push_back(entry);
            return Ok(value);
        }
    }
    let Some(record) = session.evidence(evidence_id) else {
        return Err(AnalysisError::evidence_reference(
            evidence_id,
            "missing",
            "Evidence retained in this session",
            None,
        ));
    };
    let actual = record.get("evidence_id").and_then(Value::as_str);
    if actual != Some(evidence_id) {
        return Err(AnalysisError::evidence_reference(
            evidence_id,
            "identity_mismatch",
            evidence_id,
            actual.map(str::to_owned),
        ));
    }
    let record = Arc::new(record);
    let mut entries = cache
        .entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.push_back((evidence_id.to_owned(), Arc::clone(&record)));
    while entries.len() > RECORD_CACHE_CAPACITY {
        entries.pop_front();
    }
    Ok(record)
}

/// Keep an already-retained record's parsed value available for later views
/// (for example the complete parent of a summary delivery).
pub fn remember_retained(session: &Session, evidence_id: &str, record: Arc<Value>) {
    let cache = session.state::<RecordCache>();
    let mut entries = cache
        .entries
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if entries.iter().any(|(id, _)| id == evidence_id) {
        return;
    }
    entries.push_back((evidence_id.to_owned(), record));
    while entries.len() > RECORD_CACHE_CAPACITY {
        entries.pop_front();
    }
}

/// One failed input-schema refinement the advertised JSON Schema cannot
/// express (`.refine`/`.superRefine`): its argument path and Zod message.
pub struct Refinement {
    pub path: Vec<Value>,
    pub message: String,
}

impl Refinement {
    pub fn new(path: Vec<Value>, message: impl Into<String>) -> Self {
        Self {
            path,
            message: message.into(),
        }
    }
}

/// The SDK's text-only input-validation failure for refinements, reported
/// together and in schema order before the handler runs. In-process (CLI)
/// callers receive the typed input failure as structured content.
pub fn refinement_failure(tool: &str, refinements: Vec<Refinement>) -> rea_mcp::ToolOutput {
    use rea_core::analysis_error::InputIssue;
    let segment = |part: &Value| match part {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    };
    let rendered: Vec<rea_mcp::schema::Issue> = refinements
        .iter()
        .map(|refinement| rea_mcp::schema::Issue {
            path: refinement.path.iter().map(segment).collect(),
            message: refinement.message.clone(),
        })
        .collect();
    let text = rea_mcp::schema::validation_error_text(tool, &rendered);
    let error = AnalysisError::input(
        tool,
        refinements
            .into_iter()
            .map(|refinement| InputIssue {
                path: refinement.path,
                reason: "invalid_value",
                message: Some(refinement.message),
                expected: None,
                minimum: None,
                maximum: None,
            })
            .collect(),
    );
    rea_mcp::ToolOutput::Raw(serde_json::json!({
        "content": [{ "type": "text", "text": text }],
        "structuredContent": { "error": error.project() },
        "isError": true,
    }))
}

/// Evidence `limitations` as owned strings.
pub fn limitations_of(record: &Value) -> Vec<String> {
    json::strings(record.get("limitations").unwrap_or(&Value::Null))
}
