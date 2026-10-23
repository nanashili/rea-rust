//! Compose one completed pcap execution into caller-visible Evidence.
//!
//! Compatibility owners: `src/domain/pcap/pcapEvidence.ts` and
//! `createAnalysisExecutionEvidence` in `src/application/AnalysisProvider.ts`.
//! Success and a late cancellation that retains the observation carry
//! identical facts.
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use serde_json::Value;

pub const PROVIDER_ID: &str = "pcap";
pub const PROVIDER_NAME: &str = "Packet capture analysis";

/// Operation names handled by this family.
pub const CLIENT: &str = "inspect_pcap_client";
pub const CAPTURE: &str = "inspect_pcap_capture";

/// Provider identity with the resolved tshark version (or `null`).
pub fn provider(version: Option<String>) -> EvidenceProvider {
    EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, version)
}

/// Domain facts for a successful or retained partial observation.
pub struct PcapObservation {
    pub subject: Option<SubjectTarget>,
    pub provider: EvidenceProvider,
    pub result: Value,
    pub raw_result: Option<Value>,
    pub limitations: Vec<String>,
    pub locations: Vec<Value>,
}

/// `createPcapEvidence`.
pub fn create(
    operation: &str,
    parameters: &Value,
    observation: PcapObservation,
) -> Result<Evidence, AnalysisError> {
    let confidence = if operation == CAPTURE {
        "derived"
    } else {
        "observed"
    };
    let mut built = Observation::new(operation, parameters.clone(), observation.result)
        .confidence(confidence)
        .limitations(observation.limitations)
        .locations(observation.locations);
    if let Some(raw) = observation.raw_result {
        built = built.raw(raw);
    }
    if operation == CAPTURE {
        built = built.authority("historical-reference");
    }
    rea_mcp::support::evidence(observation.subject.as_ref(), &observation.provider, built)
}

/// Build a partial-observation Evidence value for retention during cleanup.
pub fn partial_value(
    operation: &str,
    parameters: &Value,
    observation: PcapObservation,
) -> Option<Value> {
    create(operation, parameters, observation)
        .ok()
        .map(Evidence::into_value)
}
