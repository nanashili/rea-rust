//! Shared active-target, provider and Evidence helpers for this family.
//!
//! Compatibility owners: `src/server/registerEvidenceTools.ts`,
//! `src/application/binary/BinarySessionExecution.ts` (target binding) and
//! `src/domain/evidence.ts` (`createEvidence`).
#![allow(dead_code)]
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::ToolContext;
use serde_json::Value;

/// `NATIVE_MACOS_PROVIDER_IDENTITY` in `src/native/NativeMacOSProviderMetadata.ts`.
pub(crate) fn native_macos_provider() -> EvidenceProvider {
    EvidenceProvider::new("native-macos", "macOS native inspection utilities", None)
}

/// The admitted target of the binary session.
///
/// Fails with the original `NoBinaryOpenError` when no target is open. When
/// the session exposes only an Evidence subject, the source path, kind and
/// bundle bindings the provider depends on are unknown; fail closed.
pub(crate) fn active_target(context: &ToolContext<'_>) -> Result<BinaryTarget, AnalysisError> {
    rea_tools_binary::port::active_target(context.session).ok_or_else(AnalysisError::no_binary_open)
}

/// Evidence subject bound by `bindExecutionTarget`.
pub(crate) fn target_subject(target: &BinaryTarget) -> SubjectTarget {
    target.subject()
}

/// `createEvidence` for one provider execution bound to `subject`.
pub(crate) fn create_evidence(
    operation: &str,
    subject: Option<&SubjectTarget>,
    provider: &EvidenceProvider,
    parameters: Value,
    result: Value,
    limitations: Vec<String>,
    locations: Vec<Value>,
) -> Result<Evidence, AnalysisError> {
    let observation = Observation::new(operation, parameters, result)
        .limitations(limitations)
        .locations(locations);
    Evidence::create(subject, provider, observation)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))
}
