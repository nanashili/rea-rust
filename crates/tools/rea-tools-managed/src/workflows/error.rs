//! The error channel the managed workflow domain raises, mirroring the
//! JavaScript exceptions the TypeScript services catch and classify.
use rea_core::analysis_error::{AnalysisError, InputIssue};

/// A domain exception, matching the JS `throw` sites the services handle.
pub enum DomainError {
    /// `TypeError` / `z.ZodError` with a message: becomes `workflowInputError`.
    Type(String),
    /// An already-typed `AnalysisError`, preserved as-is.
    Analysis(AnalysisError),
}

impl DomainError {
    /// A `TypeError` carrying the exact message.
    pub fn type_error(message: impl Into<String>) -> Self {
        DomainError::Type(message.into())
    }
}

impl From<AnalysisError> for DomainError {
    fn from(error: AnalysisError) -> Self {
        DomainError::Analysis(error)
    }
}

/// `workflowInputError(operation, cause)` for a caught `TypeError`/`ZodError`:
/// a single root-path issue carrying the message verbatim.
pub fn workflow_input_error(operation: &str, message: &str) -> AnalysisError {
    AnalysisError::input(
        operation,
        vec![InputIssue::new(&[], "invalid_value", message.to_owned())],
    )
}

/// Map a caught domain exception the way each workflow service does:
/// an `AnalysisError` passes through; a `TypeError` becomes an input error.
///
/// `compareManagedMembersEvidenceValidated` additionally wraps non-input,
/// non-AnalysisError causes as `AnalysisProtocolError`, but every domain
/// `throw` here is a `TypeError`, so the two agree for the reachable cases.
pub fn classify(operation: &str, error: DomainError) -> AnalysisError {
    match error {
        DomainError::Analysis(error) => error,
        DomainError::Type(message) => workflow_input_error(operation, &message),
    }
}
