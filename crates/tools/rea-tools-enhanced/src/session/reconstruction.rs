//! PORT IN PROGRESS: session tool `verify_reconstruction`.
use rea_core::analysis_error::AnalysisError;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::Value;

/// Handler for `verify_reconstruction`.
pub fn verify_reconstruction(_context: &ToolContext<'_>, _input: Value) -> ToolOutput {
    ToolOutput::Failure(AnalysisError::capability_unavailable(
        "rea",
        "verify_reconstruction",
        "port in progress",
    ))
}
