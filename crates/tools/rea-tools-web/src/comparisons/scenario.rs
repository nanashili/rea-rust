//! Scenario comparison boundary.
//!
//! Browser scenario capture requires a Playwright-compatible action runner;
//! the native runtime does not yet own that authority. Keep the comparison
//! tool bound, but fail closed for scenario-shaped inputs rather than treating
//! a passive capture as a scenario.
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};

pub(super) fn compare(_input: &Value) -> Result<(Value, Value, Vec<String>), AnalysisError> {
    Err(AnalysisError::capability_unavailable(
        "rea-cdp-browser",
        "compare_web_captures",
        "Browser scenario comparison requires the native CDP scenario runner, which is not available in this build.",
    ))
}
