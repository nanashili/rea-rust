//! Apple artifact family: `decode_interface_builder`, `inspect_keyed_archive`,
//! `inspect_asset_catalog` and `trace_dylib_resolution`.
//!
//! Compatibility owners (TypeScript oracle):
//! - `src/server/registerArtifactTools.ts` (delivery, `detail` handling,
//!   summary delivery, `decodeWithoutDelivery`)
//! - `src/contracts/artifactToolContracts.ts` (frozen input contracts)
//! - `src/artifacts/ArtifactProvider.ts` (per-operation target admission and
//!   execution: `.app` bundle checks on `sourcePath`, standalone plist rules,
//!   archive digest re-check, `rootPath`/`enumerateRoots` from
//!   `bundleInfoPlist`, `locations` per result)
//! - `src/artifacts/apple/KeyedArchiveReader.ts`,
//!   `src/artifacts/apple/DylibResolutionReader.ts`,
//!   `src/artifacts/apple/InterfaceBuilderAnalysis.ts`,
//!   `src/artifacts/apple/AppleAssetCatalogAnalysis.ts`
//! - `src/domain/apple/keyedArchive.ts`, `dylibResolution.ts`,
//!   `appleAssetCatalog.ts`, `interfaceBuilderGraph.ts`
//!
//! These four operations are the artifact-graph provider's Apple capabilities.
//! Every one runs against the admitted active target and is delivered exactly
//! like `registerEvidenceTools`: admission, progress, active-target binding,
//! provider Evidence (`rea-artifact-graph`), then Evidence or summary-view
//! delivery. That shared order is owned by `crate::common::run_provider_tool`;
//! each submodule contributes only the per-operation admission (the checks the
//! `ArtifactProvider` performs before calling a reader) and the real read.
//!
//! The real reads reuse this workspace's verified producers; the legacy
//! `rea-runtime` Apple handlers are the *captured/offline* variants (base64
//! bytes, caller-supplied `assetutil` JSON, retained Evidence), which the
//! public contract (a real read of the active target) supersedes, so they are
//! not used.
use crate::common::{Execution, ProviderOutcome};
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::EvidenceProvider;
use rea_mcp::Registry;
use serde::Serialize;
use serde_json::Value;

mod asset_catalog;
mod dylib;
mod interface_builder;
mod keyed_archive;

/// Bind every Apple artifact-graph tool to its frozen catalog contract.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle(
        interface_builder::OPERATION,
        interface_builder::decode_interface_builder,
    );
    registry.handle(
        keyed_archive::OPERATION,
        keyed_archive::inspect_keyed_archive,
    );
    registry.handle(
        asset_catalog::OPERATION,
        asset_catalog::inspect_asset_catalog,
    );
    registry.handle(dylib::OPERATION, dylib::trace_dylib_resolution);
}

/// `ARTIFACT_GRAPH_PROVIDER`, the identity every artifact-graph tool reports.
pub(crate) fn provider() -> EvidenceProvider {
    crate::common::artifact_graph_provider()
}

/// `this.target.kind === "executable" && sourcePath?.toLowerCase().endsWith(
/// ".app")`, the common `.app` bundle admission the `ArtifactProvider` applies
/// before the interface-builder and asset-catalog readers
/// (`ArtifactProvider.ts`). Returns the admitted bundle source path.
pub(crate) fn admit_app_bundle<'a>(
    target: &'a BinaryTarget,
    operation: &str,
    reason: &str,
) -> Result<&'a str, AnalysisError> {
    let source = target.source_path.as_deref();
    let is_app = source.is_some_and(|path| path.to_lowercase().ends_with(".app"));
    match source {
        Some(path) if target.kind == "executable" && is_app => Ok(path),
        _ => Err(unsupported_target(target, operation, reason)),
    }
}

/// `this.unsupportedTarget(operation, reason)` in `ArtifactProvider.ts`:
/// `new AnalysisUnsupportedTargetError(operation, sourcePath ?? path, reason)`.
pub(crate) fn unsupported_target(
    target: &BinaryTarget,
    operation: &str,
    reason: &str,
) -> AnalysisError {
    AnalysisError::unsupported_target(operation, crate::common::source_or_path(target), reason)
}

/// Build a successful provider outcome from a legacy `ArtifactEvidence` produced
/// by a verified application reader.
///
/// The TypeScript provider returns the reader's *result* to
/// `createAnalysisExecution(result, PROVIDER, { limitations, locations })` with
/// no subject, so `bindExecutionTarget` binds the active target subject and the
/// final Evidence is identified under `rea-artifact-graph` with the tool's
/// parameters. The native readers already compute the same `normalized_result`,
/// `limitations` and per-artifact `locations`; this lifts exactly those three
/// facts out of the reader's envelope so `run_provider_tool` can rebuild the
/// Evidence with the provider identity, parameters and target subject
/// `registerEvidenceTools` commits. `raw_result` stays `null`, matching the
/// readers (`rawResult` is never set for these operations).
pub(crate) fn outcome_from_artifact_evidence<E: Serialize>(
    operation: &str,
    evidence: &E,
) -> Result<ProviderOutcome, AnalysisError> {
    let envelope = crate::common::to_value(operation, evidence)?;
    let result = envelope
        .get("normalized_result")
        .cloned()
        .ok_or_else(|| AnalysisError::output(operation, "reader omitted normalized_result"))?;
    let limitations = string_array(envelope.get("limitations"));
    let locations = envelope
        .get("locations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut execution = Execution::new(result, provider());
    execution.limitations = limitations;
    execution.locations = locations;
    Ok(ProviderOutcome::from(execution))
}

/// Collect a JSON string array, dropping non-string entries.
pub(crate) fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}
