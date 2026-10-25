//! Packet-capture inspection: `inspect_pcap_client` and `inspect_pcap_capture`.
//!
//! Compatibility owners: `src/server/registerPcapTools.ts`,
//! `src/application/pcap/PcapAnalysisService.ts`, `src/pcap/PcapProvider.ts`
//! and `src/domain/pcap/*`. The provider inspects saved captures through
//! caller-supplied tshark and capinfos under an enforced native memory bound.
mod command;
mod configuration;
mod evidence;
mod native_bound;
mod order;
mod output;
mod provider;
mod snapshot;
mod url;
mod windows_batch;
use crate::validation;
use provider::PcapProvider;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext};
use serde_json::Value;
const CLIENT: &str = "inspect_pcap_client";
const CAPTURE: &str = "inspect_pcap_capture";
/// Bind both pcap tools to their exact catalog contracts.
pub fn register(registry: &mut Registry) {
    registry.handle(CLIENT, |context, input| {
        inspect_client(context, &input).into()
    });
    registry
        .handle_application_validated(CAPTURE, |context, input| inspect_capture(context, input));
}
/// Session-owned provider created on first use and closed at shutdown.
fn provider(context: &ToolContext<'_>) -> std::sync::Arc<PcapProvider> {
    let state = context.session.state::<PcapProvider>();
    context.session.own_once::<PcapProvider>(state.clone());
    state
}
fn inspect_client(context: &ToolContext<'_>, _input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(CLIENT));
    }
    let provider = provider(context);
    provider.execute_client(context.session.environment(), cancellation)
}
/// `inspect_pcap_capture`: complete Evidence inline, or its summary view.
fn inspect_capture(context: &ToolContext<'_>, input: Value) -> rea_mcp::ToolOutput {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return rea_mcp::ToolOutput::Failure(AnalysisError::cancelled(CAPTURE));
    }

    let input = match rea_mcp::schema::parse_application_input(CAPTURE, &input) {
        Ok(input) => input,
        Err(error) => return rea_mcp::ToolOutput::Failure(error),
    };

    // Re-parse refinements the frozen JSON Schema cannot express, then split
    // `detail` from the operation input exactly like the original handler.
    let path = rea_mcp::support::string(&input, "path").to_owned();
    if let Err(error) = validate_capture_path(&path) {
        return rea_mcp::ToolOutput::Failure(error);
    }
    let detail = input
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("complete")
        .to_owned();
    let provider = provider(context);
    let result = provider.execute_capture(&path, context.session.environment(), cancellation);
    let evidence = match result {
        Ok(evidence) => evidence,
        Err(error) => return rea_mcp::ToolOutput::Failure(error),
    };
    if detail != "summary" {
        return rea_mcp::ToolOutput::Evidence(evidence);
    }
    // summary: record the complete Evidence and project its summary view.
    match summarize_retained(context, evidence) {
        Ok(view) => rea_mcp::ToolOutput::Evidence(view),
        Err(error) => rea_mcp::ToolOutput::Failure(error),
    }
}
/// `path` refinement: a non-empty, NUL-free local path.
///
/// `localPathStringSchema` (`src/domain/localPath.ts`) is only non-empty and
/// NUL-free; it explicitly admits relative paths and leaves any absolute
/// narrowing to callers, and pcap's request schema adds no such narrowing.
/// Presence, min-length and the NUL pattern are already enforced by the frozen
/// advertised JSON Schema, so this re-check mirrors that pattern defensively
/// and must not introduce an absolute-path restriction the original lacks.
fn validate_capture_path(path: &str) -> Result<(), AnalysisError> {
    if path.contains('\0') {
        let mut issues = Vec::new();
        validation::argument(&mut issues, &["path"], None, path);
        return Err(AnalysisError::input(CAPTURE, issues));
    }
    Ok(())
}
/// `summarizeRetainedAnalysis`: record Evidence, project its summary view.
///
/// The native session always retains Evidence, so the retention requirement
/// (`requireAnalysisViewRetention`) always succeeds.
fn summarize_retained(
    context: &ToolContext<'_>,
    evidence: Evidence,
) -> Result<Evidence, AnalysisError> {
    context.session.record(&evidence)?;
    let parent = evidence.into_value();
    let raw =
        rea_application::analysis_view::project(&parent, &serde_json::json!({ "kind": "summary" }))
            .map_err(AnalysisError::from)?;
    let value: Value = serde_json::from_str(raw.get())
        .map_err(|error| AnalysisError::output("inspect_analysis_view", error.to_string()))?;
    rea_mcp::support::adopt_evidence(value)
}
