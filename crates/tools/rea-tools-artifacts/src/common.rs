//! Shared delivery, Evidence adoption and active-target helpers for this family.
//!
//! Compatibility owners: `src/server/registerEvidenceTools.ts`,
//! `src/server/contractToolHandler.ts`, `src/server/retainedSummaryDelivery.ts`,
//! `src/application/analysisView/AnalysisViewService.ts` (summary delivery) and
//! `src/application/binary/BinarySessionExecution.ts` (target binding).
#![allow(dead_code)]
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_core::failure::Failure;
use rea_mcp::{ToolContext, ToolOutput};
use serde::Serialize;
use serde_json::{Map, Value, json, value::RawValue};
use std::sync::Arc;

/// Host file access used by stable artifact reads.
#[cfg(unix)]
pub(crate) type HostFiles = rea_host::fs::unix_file::UnixFiles;
/// Host file access used by stable artifact reads.
#[cfg(windows)]
pub(crate) type HostFiles = rea_host::fs::windows_file::WindowsFiles;

/// Shared host file owner.
#[cfg(any(unix, windows))]
pub(crate) fn host_files() -> Arc<HostFiles> {
    Arc::new(HostFiles {})
}

/// `ARTIFACT_GRAPH_PROVIDER` in `src/application/InvestigationProviders.ts`.
pub(crate) fn artifact_graph_provider() -> EvidenceProvider {
    EvidenceProvider::new(
        "rea-artifact-graph",
        "REA safe artifact graph provider",
        Some("1".into()),
    )
}

/// `NATIVE_MACOS_PROVIDER_IDENTITY` in `src/native/NativeMacOSProviderMetadata.ts`.
pub(crate) fn native_macos_provider() -> EvidenceProvider {
    EvidenceProvider::new("native-macos", "macOS native inspection utilities", None)
}

/// Identity reported by the original session route when no deep provider is
/// bound: the sorted composite of the three auxiliary provider families.
pub(crate) const AUXILIARY_ROUTE_PROVIDER_ID: &str =
    "composite:native-macos+rea-artifact-graph+rea-dotnet-static";

/// Serialize a producer value into JSON.
pub(crate) fn to_value<T: Serialize + ?Sized>(
    operation: &str,
    value: &T,
) -> Result<Value, AnalysisError> {
    serde_json::to_value(value).map_err(|error| AnalysisError::output(operation, error.to_string()))
}

/// Adopt an owner-projected legacy failure, lifting a complete partial
/// Evidence observation so delivery retains and references it exactly as the
/// original `deliverEvidenceResult`.
pub(crate) fn adopt_failure(failure: Failure) -> AnalysisError {
    let mut error = AnalysisError::from(failure);
    lift_partial_observation(&mut error);
    error
}

/// Move a complete partial Evidence observation out of projected details.
pub(crate) fn lift_partial_observation(error: &mut AnalysisError) {
    let ErrorKind::Projected { projection } = &mut error.kind else {
        return;
    };
    let Some(details) = projection.get_mut("details").and_then(Value::as_object_mut) else {
        return;
    };
    let complete = details
        .get("partial_observation")
        .and_then(|partial| partial.get("evidence_id"))
        .and_then(Value::as_str)
        .is_some();
    if !complete {
        return;
    }
    if let Some(partial) = details.remove("partial_observation") {
        error.partial_observation = Some(normalize_envelope(partial));
    }
}

const ENVELOPE_ORDER: [&str; 16] = [
    "evidence_id",
    "subject",
    "provider",
    "analysis_profile",
    "predicate_type",
    "operation",
    "parameters",
    "raw_result",
    "normalized_result",
    "confidence",
    "authority",
    "environment",
    "limitations",
    "relationship_coverage",
    "locations",
    "evidence_links",
];

fn reorder(value: Value, order: &[&str]) -> Value {
    let Value::Object(mut map) = value else {
        return value;
    };
    let mut ordered = Map::new();
    for key in order {
        if let Some(value) = map.remove(*key) {
            ordered.insert((*key).to_owned(), value);
        }
    }
    for (key, value) in map {
        ordered.insert(key, value);
    }
    Value::Object(ordered)
}

/// Reorder an Evidence envelope into the original strict-schema field order
/// (`createEvidence` output), without changing any value.
pub(crate) fn normalize_envelope(value: Value) -> Value {
    let Value::Object(mut map) = value else {
        return value;
    };
    let mut ordered = Map::new();
    for key in ENVELOPE_ORDER {
        if let Some(mut value) = map.remove(key) {
            if key == "subject" {
                value = reorder(
                    value,
                    &["name", "digest", "local_path", "format", "architecture"],
                );
            } else if key == "provider" {
                value = reorder(value, &["id", "name", "version"]);
            }
            ordered.insert(key.to_owned(), value);
        }
    }
    for (key, value) in map {
        ordered.insert(key, value);
    }
    Value::Object(ordered)
}

/// Adopt an already identified Evidence value (for example from a legacy owner).
pub(crate) fn adopt_evidence_value(value: Value) -> Result<Evidence, AnalysisError> {
    rea_mcp::support::adopt_evidence(normalize_envelope(value))
}

/// Adopt serialized Evidence text.
pub(crate) fn adopt_raw_evidence(raw: &RawValue) -> Result<Evidence, AnalysisError> {
    let value: Value = serde_json::from_str(raw.get())
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    adopt_evidence_value(value)
}

/// Adopt any serializable legacy Evidence record (for example `ArtifactEvidence`).
pub(crate) fn adopt_serialized_evidence<T: Serialize + ?Sized>(
    evidence: &T,
) -> Result<Evidence, AnalysisError> {
    let value = serde_json::to_value(evidence)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    adopt_evidence_value(value)
}

/// Retain complete Evidence, then deliver its `inspect_analysis_view` summary
/// (`summarizeRetainedAnalysis`). This session always retains Evidence, so the
/// original `requireAnalysisViewRetention` preflight always succeeds.
pub(crate) fn summary_view(
    context: &ToolContext<'_>,
    complete: Evidence,
) -> Result<Evidence, AnalysisError> {
    context.session.record(&complete)?;
    let raw =
        rea_application::analysis_view::project(complete.value(), &json!({ "kind": "summary" }))
            .map_err(adopt_failure)?;
    adopt_raw_evidence(&raw)
}

/// Fail fast when the request was cancelled before admission
/// (`#waitForTransition` / `runAdmittedToolOperation`).
pub(crate) fn admit(context: &ToolContext<'_>) -> Result<(), AnalysisError> {
    context.check_cancelled()
}

/// The admitted target of the binary session (owned by `rea-tools-binary`).
///
/// Fails with the original `NoBinaryOpenError` when no target is open.
pub(crate) fn active_target(context: &ToolContext<'_>) -> Result<BinaryTarget, AnalysisError> {
    rea_tools_binary::port::active_target(context.session).ok_or_else(AnalysisError::no_binary_open)
}

/// Capability unavailable on the active route (`prepareSessionExecution`).
pub(crate) fn route_capability_unavailable(operation: &str, reason: &str) -> AnalysisError {
    AnalysisError::capability_unavailable(AUXILIARY_ROUTE_PROVIDER_ID, operation, reason)
}

/// Evidence subject bound by `bindExecutionTarget`.
pub(crate) fn target_subject(target: &BinaryTarget) -> SubjectTarget {
    target.subject()
}

/// `target.sourcePath ?? target.path`.
pub(crate) fn source_or_path(target: &BinaryTarget) -> &str {
    target.source_path.as_deref().unwrap_or(&target.path)
}

/// `bundleInfoPlist` when the target was resolved from an app bundle directory.
pub(crate) fn bundle_info_plist(target: &BinaryTarget) -> Option<&str> {
    target
        .metadata
        .get("bundleInfoPlist")
        .and_then(Value::as_str)
}

/// One successful provider observation (`AnalysisExecution`).
#[derive(Clone, Debug)]
pub(crate) struct Execution {
    pub result: Value,
    /// Distinct provider representation; `None` records `null`.
    pub raw_result: Option<Value>,
    pub provider: EvidenceProvider,
    pub limitations: Vec<String>,
    pub locations: Vec<Value>,
    pub subject: Option<SubjectTarget>,
}

impl Execution {
    pub(crate) fn new(result: Value, provider: EvidenceProvider) -> Self {
        Self {
            result,
            raw_result: None,
            provider,
            limitations: Vec::new(),
            locations: Vec::new(),
            subject: None,
        }
    }
}

/// Bind the execution to the active target exactly as `bindExecutionTarget`.
pub(crate) fn bind_execution_target(
    operation: &str,
    mut execution: Execution,
    target: &BinaryTarget,
) -> Result<Execution, AnalysisError> {
    if let Some(subject) = &execution.subject
        && subject.sha256 != target.sha256
    {
        let artifact_bundle = matches!(
            operation,
            "inventory_artifact" | "inspect_artifact" | "extract_artifact"
        ) && subject.path == source_or_path(target);
        if !artifact_bundle {
            return Err(AnalysisError::provider_adapter(
                execution.provider.id.clone(),
                format!("{operation}:subject"),
            ));
        }
    }
    if execution.subject.is_none() {
        execution.subject = Some(target_subject(target));
    }
    Ok(execution)
}

/// Evidence for a provider-backed tool (`registerEvidenceTools`).
pub(crate) fn provider_evidence(
    operation: &str,
    execution: &Execution,
    parameters: Value,
    evidence_links: Vec<String>,
) -> Result<Evidence, AnalysisError> {
    let mut observation = Observation::new(operation, parameters, execution.result.clone())
        .limitations(execution.limitations.clone())
        .locations(execution.locations.clone())
        .links(evidence_links);
    if let Some(raw) = &execution.raw_result {
        observation = observation.raw(raw.clone());
    }
    Evidence::create(execution.subject.as_ref(), &execution.provider, observation)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))
}

/// Remove the delivery-only `detail` selection.
pub(crate) fn without_detail(input: &Value) -> Map<String, Value> {
    let mut parameters = input.as_object().cloned().unwrap_or_default();
    parameters.remove("detail");
    parameters
}

/// Successful provider outcome: the execution and any source Evidence it
/// embeds (recorded before the derived record, as `sourceEvidence`).
pub(crate) struct ProviderOutcome {
    pub execution: Execution,
    pub sources: Vec<Evidence>,
}

impl From<Execution> for ProviderOutcome {
    fn from(execution: Execution) -> Self {
        Self {
            execution,
            sources: Vec::new(),
        }
    }
}

/// Selections for one provider-backed tool call.
pub(crate) struct ProviderCall {
    /// Parameters passed to the provider (`parametersForExecution`).
    pub execution_parameters: Map<String, Value>,
    /// Parameters committed to Evidence identity (`parametersForEvidence`).
    pub evidence_parameters: Value,
    /// Deliver the retained summary view (`detail: "summary"`).
    pub summary: bool,
    /// Reason the operation is unavailable on this host, if any.
    pub unavailable: Option<&'static str>,
}

/// Run one provider-backed tool through the original admission, progress,
/// target binding, Evidence and delivery order.
pub(crate) fn run_provider_tool(
    context: &ToolContext<'_>,
    call: ProviderCall,
    execute: impl FnOnce(&BinaryTarget, &Map<String, Value>) -> Result<ProviderOutcome, AnalysisError>,
) -> ToolOutput {
    let name = context.name().to_owned();
    if let Err(error) = admit(context) {
        return error.into();
    }
    context.progress.report(&name, "started");
    let executed = (|| {
        admit(context)?;
        let target = active_target(context)?;
        if let Some(reason) = call.unavailable {
            return Err(route_capability_unavailable(&name, reason));
        }
        let outcome = execute(&target, &call.execution_parameters)?;
        let execution = bind_execution_target(&name, outcome.execution, &target)?;
        Ok((execution, outcome.sources))
    })();
    context.progress.report(
        &name,
        if executed.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    let (execution, sources) = match executed {
        Ok(executed) => executed,
        Err(error) => return error.into(),
    };
    let links = sources
        .iter()
        .map(|source| source.id().to_owned())
        .collect();
    let evidence = match provider_evidence(&name, &execution, call.evidence_parameters, links) {
        Ok(evidence) => evidence,
        Err(error) => return error.into(),
    };
    for source in &sources {
        if let Err(error) = context.session.record(source) {
            return error.into();
        }
    }
    if call.summary {
        return summary_view(context, evidence).into();
    }
    ToolOutput::Evidence(evidence)
}

/// One `ArtifactReaderFailure` (`src/artifacts/ArtifactReader.ts`).
#[derive(Clone, Debug)]
pub(crate) struct ReaderFailure {
    /// cancelled, format, integrity, io, limit, path or unavailable.
    pub reason: &'static str,
    /// The reader's message (becomes the operation error `detail`).
    pub message: String,
    /// Declared-integrity facts for an artifact entry.
    pub details: Option<rea_core::analysis_error::ArtifactDetails>,
    /// Cleanup that remains owned after the failure.
    pub cleanup: Option<rea_core::analysis_error::CleanupObservation>,
    /// Completed observation retained by the failure.
    pub partial_observation: Option<Value>,
}

impl ReaderFailure {
    pub(crate) fn new(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
            details: None,
            cleanup: None,
            partial_observation: None,
        }
    }
}

/// A failure thrown inside an artifact boundary before translation.
#[derive(Debug)]
pub(crate) enum ArtifactCause {
    /// An `ArtifactReaderFailure`.
    Reader(ReaderFailure),
    /// An already typed analysis failure.
    Typed(AnalysisError),
    /// Any other unexpected failure.
    Unexpected,
}

impl From<ReaderFailure> for ArtifactCause {
    fn from(failure: ReaderFailure) -> Self {
        Self::Reader(failure)
    }
}

impl From<AnalysisError> for ArtifactCause {
    fn from(error: AnalysisError) -> Self {
        Self::Typed(error)
    }
}

/// `translateArtifactFailure` (`src/artifacts/ArtifactOperationFailure.ts`).
pub(crate) fn translate_artifact_failure(operation: &str, cause: ArtifactCause) -> AnalysisError {
    match cause {
        ArtifactCause::Reader(failure) => {
            let mut error: AnalysisError = ErrorKind::ArtifactOperation {
                operation: operation.to_owned(),
                reason: failure.reason.to_owned(),
                artifact_details: failure.details,
                detail: Some(failure.message),
            }
            .into();
            error.cleanup = failure.cleanup;
            error.partial_observation = failure.partial_observation;
            error
        }
        // Caller-selection and unsupported-target failures are already typed;
        // keep their correction details instead of reducing them to I/O.
        ArtifactCause::Typed(error)
            if matches!(
                error.kind,
                ErrorKind::Input { .. }
                    | ErrorKind::Cancelled { .. }
                    | ErrorKind::UnsupportedTarget { .. }
            ) =>
        {
            error
        }
        ArtifactCause::Typed(_) | ArtifactCause::Unexpected => {
            AnalysisError::artifact_operation(operation, "io")
        }
    }
}

/// Run one service-backed Evidence tool (`createEvidenceToolHandler`).
pub(crate) fn run_service_tool(
    context: &ToolContext<'_>,
    operation: impl FnOnce() -> Result<Evidence, AnalysisError>,
) -> ToolOutput {
    if let Err(error) = admit(context) {
        return error.into();
    }
    operation().into()
}
