//! Evidence assembly shared by the Android-family providers.
//!
//! Compatibility owners: `createAnalysisExecutionEvidence` and
//! `completeProviderEvidence` in `src/application/`.
use super::target::BinaryTarget;
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use serde_json::Value;

/// Subject identity of an admitted target.
pub fn subject(target: &BinaryTarget) -> SubjectTarget {
    SubjectTarget {
        path: target.path.clone(),
        sha256: target.sha256.clone(),
        format: target.format.clone(),
        architecture: target.architecture.clone(),
    }
}

/// Subject identity from explicit facts.
pub fn subject_of(
    path: &str,
    sha256: &str,
    format: &str,
    architecture: Option<&str>,
) -> SubjectTarget {
    SubjectTarget {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        format: format.to_owned(),
        architecture: architecture.map(str::to_owned),
    }
}

/// Atomic successful provider observation (`AnalysisExecution`).
#[derive(Clone, Debug)]
pub struct Execution {
    pub result: Value,
    pub raw_result: Option<Value>,
    pub provider: EvidenceProvider,
    pub analysis_profile: Option<Value>,
    pub relationship_coverage: Option<Value>,
    pub limitations: Vec<String>,
    pub locations: Vec<Value>,
    pub subject: Option<SubjectTarget>,
}

impl Execution {
    pub fn new(result: Value, provider: EvidenceProvider) -> Self {
        Self {
            result,
            raw_result: None,
            provider,
            analysis_profile: None,
            relationship_coverage: None,
            limitations: Vec::new(),
            locations: Vec::new(),
            subject: None,
        }
    }
}

/// `createAnalysisExecutionEvidence(operation, input, execution, confidence)`.
pub fn execution_evidence(
    operation: &str,
    parameters: Value,
    execution: Execution,
    confidence: &str,
) -> Result<Evidence, AnalysisError> {
    let mut observation = Observation::new(operation, parameters, execution.result);
    observation.raw_result = execution.raw_result;
    observation.analysis_profile = execution.analysis_profile;
    observation.relationship_coverage = execution.relationship_coverage;
    observation.limitations = execution.limitations;
    observation.locations = execution.locations;
    observation.confidence = Some(confidence.to_owned());
    rea_mcp::support::evidence(execution.subject.as_ref(), &execution.provider, observation)
        .map_err(|error| AnalysisError::output(operation, error.message()))
}

/// `completeProviderEvidence(evidence, signal, capturedOutput)`: a late
/// cancellation keeps the complete Evidence as its partial observation.
pub fn complete(
    evidence: Evidence,
    cancellation: &Cancellation,
    captured_output: Option<CapturedOutput>,
) -> Result<Evidence, AnalysisError> {
    if cancellation.reason().is_none() {
        return Ok(evidence);
    }
    let mut error =
        AnalysisError::cancelled(evidence.value()["operation"].as_str().unwrap_or_default())
            .retain_partial_observation(evidence.into_value());
    error.captured_output = captured_output;
    Err(error)
}
