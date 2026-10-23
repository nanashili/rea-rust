//! Native `capture_browser_scenario`: a controlled Chromium scenario driven
//! over CDP with REA-owned launch, lifecycle, cleanup and artifacts.
//!
//! Compatibility owners: `src/server/registerBrowserScenarioTool.ts`,
//! `src/application/BrowserScenarioCaptureService.ts`,
//! `src/browser/PlaywrightBrowserScenarioProvider.ts` and the
//! `PlaywrightScenario*` session modules. Playwright is not used; the
//! behaviors of Playwright 1.58.2 that shape the output are reproduced here
//! (see `.cache/rust-migration/progress.md`, "capture_browser_scenario").
//!
//! Layout: `input` (contract refinements), `secrets` (declared-secret
//! redaction), `launch` (owned launch / external attach and cleanup),
//! `driver` (CDP connection and observed world), `recorder` + `network`
//! (event budgets and network phases), `actions` + `page.js` (declarative
//! actions), `artifacts` (step snapshots) and `run` (scenario lifecycle and
//! Evidence).
mod actions;
mod artifacts;
mod driver;
mod input;
mod launch;
mod network;
mod recorder;
mod run;
mod secrets;

use crate::cdp;
use input::{OPERATION, Rejection};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::EvidenceProvider;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::Value;

/// Contract identity of the scenario provider. The identifier, name and
/// version are the TS contract values consumed by scenario comparisons and
/// script publication; the implementation is REA's native CDP runner.
pub(crate) const PROVIDER_ID: &str = "rea-playwright-browser-scenario";
const PROVIDER_NAME: &str = "REA Playwright browser scenario capture provider";
const PROVIDER_VERSION: &str = "1";

pub(crate) fn provider() -> EvidenceProvider {
    EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, Some(PROVIDER_VERSION.to_owned()))
}

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context, input| handle(context, &input));
}

fn handle(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    let scenario = match input::parse(input) {
        Ok(scenario) => scenario,
        Err(Rejection::Schema(issues)) => return cdp::refinement_failure(OPERATION, issues),
        Err(Rejection::Scenario(issues)) => {
            let issues = issues
                .into_iter()
                .map(|issue| InputIssue {
                    path: issue.path,
                    reason: "invalid_value",
                    message: Some(issue.message),
                    expected: None,
                    minimum: None,
                    maximum: None,
                })
                .collect();
            return ToolOutput::Failure(AnalysisError::input(OPERATION, issues));
        }
    };
    run::run(&scenario, &context.cancellation).into()
}
