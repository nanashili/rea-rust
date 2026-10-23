//! Domain exceptions the application services classify as input errors.
//!
//! Compatibility owner: `workflowInputError` in
//! `src/application/workflowInputError.ts`. A thrown `TypeError` becomes one
//! root issue carrying its message; a nested `ZodError` becomes one root
//! issue per Zod issue, naming the nested path in the message.
use rea_core::analysis_error::{AnalysisError, InputIssue};

/// One or more root-path issue messages, already in the original wording.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub messages: Vec<String>,
    /// A plain `TypeError` outside the caller-input error classes that some
    /// services (the obligation ledger) classify as a protocol failure.
    pub unclassified: bool,
}

impl Rejection {
    /// A `TypeError` with its exact message.
    pub fn type_error(message: impl Into<String>) -> Self {
        Self {
            messages: vec![message.into()],
            unclassified: false,
        }
    }

    /// A plain `TypeError` that is not one of the named input error classes.
    pub fn unclassified(message: impl Into<String>) -> Self {
        Self {
            messages: vec![message.into()],
            unclassified: true,
        }
    }

    /// A nested `ZodError` issue at `path` (dot-joined, as the original).
    pub fn nested(path: &str, message: &str) -> Self {
        let location = if path.is_empty() { "its root" } else { path };
        Self {
            messages: vec![format!(
                "A nested value failed validation at {location}: {message}"
            )],
            unclassified: false,
        }
    }

    /// A nested validation failure whose Zod path is not reproduced.
    pub fn nested_root(message: impl Into<String>) -> Self {
        Self::nested("", &message.into())
    }

    /// `workflowInputError(operation, cause)`.
    pub fn into_input_error(self, operation: &str) -> AnalysisError {
        AnalysisError::input(
            operation,
            self.messages
                .into_iter()
                .map(|message| InputIssue::new(&[], "invalid_value", message))
                .collect(),
        )
    }
}
