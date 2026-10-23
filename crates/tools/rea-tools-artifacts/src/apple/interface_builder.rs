//! `decode_interface_builder`: bounded decode of compiled Interface Builder
//! archives in the active `.app` bundle.
//!
//! Compatibility owners: `src/server/registerArtifactTools.ts`
//! (`SUMMARY_DELIVERY`, `decodeWithoutDelivery`), `src/artifacts/
//! ArtifactProvider.ts` (`decode_interface_builder` branch) and
//! `src/artifacts/apple/InterfaceBuilderAnalysis.ts`.
//!
//! `registerArtifactTools` strips `detail` from BOTH the execution parameters
//! and the committed Evidence parameters (`decodeWithoutDelivery`), and this
//! operation supports summary delivery (`detail: "summary"`). The provider
//! branch requires an active `.app` bundle (`kind === "executable"`,
//! `sourcePath` ends with `.app`), parses the graph limits, decodes the bundle
//! and reports a location per decoded document.
//!
//! The real decode reuses `rea_application::interface_builder::bundle`
//! (`#[cfg(unix)]`), the verified port of `analyzeInterfaceBuilderBundle`
//! (bounded discovery, NIBArchive/plist decoding, the decode budget, coverage
//! and provenance). That module is Unix-only; on a non-Unix host this crate has
//! no Interface Builder decoder, so the operation fails closed with a
//! capability-unavailable error instead of inventing a reduced decoder. The
//! TypeScript tool is portable, so this is a documented host gap.
use crate::common::{ProviderCall, ProviderOutcome, run_provider_tool};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::{Map, Value};

pub(crate) const OPERATION: &str = "decode_interface_builder";

/// `registerArtifactTools` binding for `decode_interface_builder`.
pub(crate) fn decode_interface_builder(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let object = input.as_object().cloned().unwrap_or_default();

    // Delivery selection is adapter-owned (`SUMMARY_DELIVERY`) and is stripped
    // from both execution and Evidence parameters (`decodeWithoutDelivery`).
    let summary = matches!(
        object.get("detail").and_then(Value::as_str),
        Some("summary")
    );
    let mut parameters = object;
    parameters.remove("detail");

    // The surviving `{ max_documents, max_objects, max_connections }` (defaults
    // already applied by the frozen schema) are the execution parameters and
    // the exact Evidence parameters.
    let evidence_parameters = Value::Object(parameters.clone());
    let cancellation = context.cancellation.clone();

    run_provider_tool(
        context,
        ProviderCall {
            execution_parameters: parameters,
            evidence_parameters,
            summary,
            unavailable: None,
        },
        move |target, parameters| execute(target, parameters, &cancellation),
    )
}

/// `ArtifactClient.execute` `decode_interface_builder` branch.
fn execute(
    target: &rea_analysis::BinaryTarget,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    // `kind !== "executable" || sourcePath === undefined ||
    //  !sourcePath.endsWith(".app")` → unsupported target.
    let bundle_path = super::admit_app_bundle(
        target,
        OPERATION,
        "decode_interface_builder requires an active .app bundle target",
    )?;
    decode(target, bundle_path, parameters, cancellation)
}

#[cfg(unix)]
fn decode(
    target: &rea_analysis::BinaryTarget,
    bundle_path: &str,
    parameters: &Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    use rea_application::interface_builder::bundle::{
        self as interface_builder_bundle, InterfaceBuilderLimits,
    };

    // `interfaceBuilderLimitsSchema.parse(parameters)`: the frozen input schema
    // already validated and defaulted `max_documents`/`max_objects`/
    // `max_connections` to the same bounds, so the surviving object carries
    // exactly those three numbers.
    let limits = InterfaceBuilderLimits {
        max_documents: limit(
            parameters,
            "max_documents",
            interface_builder_bundle::MAX_DOCUMENTS,
        ),
        max_objects: limit(
            parameters,
            "max_objects",
            interface_builder_bundle::MAX_OBJECTS,
        ),
        max_connections: limit(
            parameters,
            "max_connections",
            interface_builder_bundle::MAX_CONNECTIONS,
        ),
    };

    // The reader owns no-follow bundle traversal, the decode budget, coverage
    // and the `InterfaceBuilderAnalysis` result; its `ArtifactEvidence` carries
    // the `normalized_result`, `limitations` and per-document `locations` of
    // `analyzeInterfaceBuilderBundle` + `createAnalysisExecution`.
    let evidence = interface_builder_bundle::inspect_bundle_with_limits(
        std::path::Path::new(bundle_path),
        target.sha256.clone(),
        limits,
        cancellation,
    )
    .map_err(crate::common::adopt_failure)?;

    super::outcome_from_artifact_evidence(OPERATION, &evidence)
}

#[cfg(not(unix))]
fn decode(
    _target: &rea_analysis::BinaryTarget,
    _bundle_path: &str,
    _parameters: &Map<String, Value>,
    _cancellation: &Cancellation,
) -> Result<ProviderOutcome, AnalysisError> {
    Err(AnalysisError::capability_unavailable(
        super::provider().id,
        OPERATION,
        "Compiled Interface Builder decoding requires a Unix host in this build.",
    ))
}

/// Read one bounded graph limit, falling back to the schema maximum default.
#[cfg(unix)]
fn limit(parameters: &Map<String, Value>, key: &str, default: usize) -> usize {
    parameters
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .unwrap_or(default)
}
