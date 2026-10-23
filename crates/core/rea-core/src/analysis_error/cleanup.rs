//! Cleanup composition for typed analysis failures.
//!
//! Compatibility owners: `src/domain/analysisErrorCleanup.ts`
//! (`analysisErrorWithCleanupFailure`) and
//! `src/domain/providerCleanupError.ts` (`ProviderCleanupError`). Provider
//! adapters and the binary session share these owners so cleanup uncertainty
//! is composed one way everywhere.
use crate::analysis_error::{AnalysisError, CleanupObservation, ErrorKind};
use serde_json::{Map, Value};

/// `ProviderCleanupError.userMessage`.
pub const PROVIDER_CLEANUP_MESSAGE: &str = "Provider cleanup could not be fully confirmed. Review the reported local resources before opening another target.";

/// `new ProviderCleanupError(providerId, resources, diagnostics, options)`:
/// a provider adapter failure whose cleanup is live-incomplete and whose
/// unresolved resources are exactly `resources`.
pub fn provider_cleanup_error(
    provider_id: &str,
    resources: Vec<String>,
    diagnostics: Map<String, Value>,
    operation: Option<&str>,
    remediation_action: Option<String>,
) -> AnalysisError {
    let mut error = AnalysisError::from(ErrorKind::ProviderAdapter {
        provider_id: provider_id.to_owned(),
        operation: operation.unwrap_or("close_binary").to_owned(),
        user_message: Some(PROVIDER_CLEANUP_MESSAGE.to_owned()),
        remediation_action,
    })
    .with_diagnostics(diagnostics);
    error.cleanup_incomplete = Some(true);
    error.cleanup_resources = Some(resources);
    error
}

fn unique(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = Vec::new();
    for value in values {
        if !seen.contains(&value) {
            seen.push(value);
        }
    }
    seen
}

/// `analysisErrorWithCleanupFailure`: preserve the original lifecycle failure
/// alongside incomplete cleanup.
pub fn with_cleanup_failure(
    primary: AnalysisError,
    cleanup: AnalysisError,
    operation: &str,
) -> AnalysisError {
    let projected = cleanup.project();
    let primary_projection = primary.project();
    let provider_id = match &cleanup.kind {
        ErrorKind::ProviderAdapter { provider_id, .. } => provider_id.clone(),
        _ => "rea".to_owned(),
    };
    let mut resources = Vec::new();
    if primary.is_cleanup_incomplete() {
        resources.extend(primary.unresolved_resources());
    }
    resources.extend(cleanup.unresolved_resources());
    let mut diagnostics = Map::new();
    diagnostics.insert("primary_error".into(), primary_projection.clone());
    diagnostics.insert("cleanup_error".into(), projected.clone());
    let mut error = AnalysisError::from(ErrorKind::ProviderAdapter {
        provider_id,
        operation: operation.to_owned(),
        user_message: primary_projection["message"].as_str().map(str::to_owned),
        remediation_action: projected["remediation"]["action"]
            .as_str()
            .map(str::to_owned),
    })
    .with_diagnostics(diagnostics);
    error.captured_output = primary.captured_output.clone();
    error.partial_observation = primary.partial_observation.clone();
    error.cleanup = Some(CleanupObservation {
        reason: projected["message"].as_str().unwrap_or_default().to_owned(),
        resources: unique(resources),
    });
    error.cleanup_primary = Some(Box::new(primary));
    error
}

/// The innermost primary failure of a cleanup composition.
pub fn cleanup_root(error: &AnalysisError) -> &AnalysisError {
    let mut current = error;
    while let Some(primary) = &current.cleanup_primary {
        current = primary;
    }
    current
}
