//! Typed lifecycle failures owned by the binary session.
//!
//! Compatibility owners: `src/domain/providerSelectionError.ts` and
//! `src/providers/AnalysisClientCleanup.ts`. Cleanup composition
//! (`analysisErrorWithCleanupFailure`, `ProviderCleanupError`) is owned by
//! `rea_core::analysis_error::cleanup` and shared with provider adapters.
pub(crate) use rea_core::analysis_error::cleanup::{provider_cleanup_error, with_cleanup_failure};
use rea_core::analysis_error::{AnalysisError, ErrorKind, SelectionRejection};
use serde_json::{Map, Value, json};

/// `ProviderAdapterError(providerId, operation, { diagnostics })`.
pub(crate) fn provider_adapter(
    provider_id: &str,
    operation: &str,
    diagnostics: Option<Map<String, Value>>,
) -> AnalysisError {
    let error = AnalysisError::provider_adapter(provider_id, operation);
    match diagnostics {
        Some(diagnostics) => error.with_diagnostics(diagnostics),
        None => error,
    }
}

/// `new ProviderSelectionError({ operation, reason, requestedProviderId,
/// candidateIds, rejections })`.
pub(crate) fn provider_selection(
    operation: &str,
    reason: &str,
    requested_provider_id: &str,
    candidate_ids: Vec<String>,
    rejections: Vec<SelectionRejection>,
) -> AnalysisError {
    ErrorKind::ProviderSelection {
        operation: operation.to_owned(),
        reason: reason.to_owned(),
        requested_provider_id: requested_provider_id.to_owned(),
        candidate_ids,
        rejections,
        user_message: None,
    }
    .into()
}

/// Whether a failure is the original `AnalysisCancelledError` class.
pub(crate) fn is_cancelled(error: &AnalysisError) -> bool {
    matches!(error.kind, ErrorKind::Cancelled { .. })
}

/// `new ProviderCleanupError(providerId, ["provider-client"], ...)` for a
/// client whose close panicked instead of returning a typed outcome.
pub(crate) fn unexpected_close_failure(provider_id: &str) -> AnalysisError {
    let mut diagnostics = Map::new();
    diagnostics.insert(
        "reason".into(),
        json!("provider client close rejected unexpectedly"),
    );
    provider_cleanup_error(
        provider_id,
        vec!["provider-client".into()],
        diagnostics,
        None,
        None,
    )
}

/// `closeAnalysisClient`: close one provider client and normalize an
/// unexpected adapter rejection.
pub(crate) fn close_analysis_client(
    provider_id: &str,
    close: impl FnOnce() -> Result<(), AnalysisError>,
) -> Result<(), AnalysisError> {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(close)) {
        Ok(result) => result,
        Err(_) => Err(unexpected_close_failure(provider_id)),
    }
}

/// Combine several independent cleanup failures in their reported order,
/// retaining the first as primary (`analysisErrorWithCleanupFailure` fold).
pub(crate) fn fold_cleanup_failures(
    failures: Vec<AnalysisError>,
    operation: &str,
) -> Option<AnalysisError> {
    let mut failures = failures.into_iter();
    let mut combined = failures.next()?;
    for next in failures {
        combined = with_cleanup_failure(combined, next, operation);
    }
    Some(combined)
}
