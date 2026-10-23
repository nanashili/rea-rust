//! Flutter build-identification family.
//!
//! Compatibility owners: `src/server/registerFlutterTools.ts`,
//! `src/composition/flutter.ts`, `src/application/flutter/*` and
//! `src/flutter/*`. Both tools run no engine, install nothing and perform no
//! external lookups: they parse the admitted APK directly.
//!
//! `identify_flutter_build` reports per-ABI Flutter build facts.
//! `inspect_dart_aot` inspects one ABI's Dart AOT snapshot, and its
//! `detail: "summary"` delivery retains the complete Evidence and returns the
//! projected summary view.

mod artifact_decompression_budget;
mod dart_elf;
mod elf_build_id;
mod payload_scan;
mod provider;
mod zip;

use rea_application::analysis_view;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::Evidence;
use rea_mcp::{Registry, ToolContext};
use serde_json::{Map, Value, json};

const IDENTIFY: &str = "identify_flutter_build";
const INSPECT: &str = "inspect_dart_aot";

/// Bind both Flutter tools to their exact named contracts.
pub fn register(registry: &mut Registry) {
    registry.handle(IDENTIFY, |context, input| identify(context, &input).into());
    registry.handle(INSPECT, |context, input| inspect(context, &input).into());
}

/// `identify_flutter_build`: pure per-ABI Flutter build identification.
fn identify(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(IDENTIFY));
    }
    let path = rea_mcp::support::string(input, "path").to_owned();
    let provider_input = provider_parameters(IDENTIFY, input);
    run(IDENTIFY, &path, None, &provider_input, cancellation)
}

/// `inspect_dart_aot`: one ABI's Dart AOT snapshot, optionally summarized.
fn inspect(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(INSPECT));
    }

    let path = rea_mcp::support::string(input, "path").to_owned();
    let abi = rea_mcp::support::optional_string(input, "abi").map(str::to_owned);
    // `detail` has no schema default; absent means the full observation.
    let detail = rea_mcp::support::optional_string(input, "detail").map(str::to_owned);
    let summary = detail.as_deref() == Some("summary");

    // Provider input excludes `detail` (TS `const { detail, ...providerInput }`).
    let provider_input = provider_parameters(INSPECT, input);

    // `detail: "summary"` fails before analysis if the session cannot retain
    // Evidence. This crate's session always retains delivered Evidence, so the
    // retention precondition always holds; the summary path proceeds.

    let evidence = run(
        INSPECT,
        &path,
        abi.as_deref(),
        &provider_input,
        cancellation,
    )?;
    if !summary {
        return Ok(evidence);
    }
    summarize_retained_analysis(context, evidence)
}

/// Caller/selection parameters recorded in Evidence, in schema-shape order.
fn provider_parameters(operation: &str, input: &Value) -> Value {
    let mut map = Map::new();
    map.insert(
        "path".into(),
        json!(rea_mcp::support::string(input, "path")),
    );
    if operation == INSPECT {
        if let Some(abi) = rea_mcp::support::optional_string(input, "abi") {
            map.insert("abi".into(), json!(abi));
        }
    }
    Value::Object(map)
}

/// Shared execution and Evidence composition, with late-cancellation retention
/// mirroring `completeProviderEvidence`/the provider's final abort check.
fn run(
    operation: &str,
    path: &str,
    abi: Option<&str>,
    provider_input: &Value,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    let execution = provider::execute(operation, path, abi, cancellation)?;
    let identity = provider::provider_identity();
    let observation = provider::observation(operation, provider_input, &execution);
    let evidence = rea_mcp::support::evidence(Some(&execution.subject), &identity, observation)?;
    if cancellation.reason().is_some() {
        return Err(
            AnalysisError::cancelled(operation).retain_partial_observation(evidence.into_value())
        );
    }
    Ok(evidence)
}

/// Retain the complete analysis Evidence, then project and return its summary
/// view (`summarizeRetainedAnalysis` + `inspectAnalysisViewValidated`).
fn summarize_retained_analysis(
    context: &ToolContext<'_>,
    evidence: Evidence,
) -> Result<Evidence, AnalysisError> {
    context.session.record(&evidence)?;
    let view = json!({ "kind": "summary" });
    let raw = analysis_view::project(evidence.value(), &view).map_err(AnalysisError::from)?;
    let value: Value = serde_json::from_str(raw.get())
        .map_err(|error| AnalysisError::output(analysis_view::OPERATION, error.to_string()))?;
    rea_mcp::support::adopt_evidence(value)
}
