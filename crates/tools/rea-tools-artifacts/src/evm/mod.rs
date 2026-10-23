//! `inspect_evm_interface`: explicit local flat EVM bytecode interface
//! recovery with the locked EVMole 0.9.3 engine, run in-process.
//!
//! Compatibility owners (TypeScript oracle):
//! - `src/server/registerEvmTools.ts` (delivery, `detail` handling, the
//!   `detail: "summary"` retention preflight and summary projection).
//! - `src/composition/evm.ts` (service composition).
//! - `src/application/evm/EvmInterfaceService.ts` (input validation, absolute
//!   path refinement, output re-validation, Evidence finalization).
//! - `src/application/evm/EvmInterfaceEvidence.ts` (Evidence shape: provider
//!   identity, `{ path, encoding }` parameters, `inferred` confidence,
//!   locations, limitations, raw_result).
//! - `src/application/evm/EvmInterfacePort.ts` (successful execution must
//!   identify the selected local file with `format: "file"`).
//! - `src/evm/EvmoleInterfaceProvider.ts` (host gate, carrier read, engine
//!   call, reply validation, decoded-identity re-check, limitations).
//! - `src/evm/EvmoleInterfaceWorker.ts` / `EvmoleInterfaceAdapter.ts` /
//!   `EvmBytecodeCarrier.ts` / `SolidityMetadata.ts` / `EvmoleRelease.ts`
//!   (ported under `src/evm/`).
//! - `src/domain/evm/evmInterface.ts`, `src/domain/evm/solidityMetadata.ts`
//!   (the `evmInterfaceSchema` result shape and `superRefine` invariants).
//! - frozen `inspect_evm_interface` contract in
//!   `native/crates/interfaces/rea-mcp/contracts/catalog/mcp-tools.json`.
//!
//! ## In-process engine deviation
//!
//! The TypeScript provider runs EVMole inside an owned Node child under
//! util-linux `prlimit` (`REA_EVM_PRLIMIT_COMMAND`, `/proc/self/limits`
//! selection, address-space / CPU-time / file-size `rlimit`s), with a 256 MiB
//! V8 heap cap and worker-crash containment. This crate exposes no worker
//! entrypoint reachable from the native binary, so the same locked engine
//! release runs in-process. Every byte, size, selector and representation
//! budget that bounds input and output is preserved exactly
//! (`INPUT_BYTES = 4 MiB` carrier read, `OUTPUT_BYTES = 16 MiB` reply budget,
//! the strict adapter/metadata profiles). The isolation guarantees that are
//! **not** reproduced, and the shared change that would restore them, are
//! stated in the result `limitations` and the worker report:
//! address-space / CPU-time / file-size `rlimit`s, the V8 heap cap, the worker
//! deadline, and worker-crash containment. Restoring them requires a hidden
//! native worker subcommand launched through
//! `rea_host::process::launcher::OwnedChildProcess` (a shared change to the
//! `native/crates/apps/rea` binary and `rea-host`, outside this crate).

mod carrier;
mod engine;
mod failures;
mod metadata;
mod release;

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use carrier::Encoding;
use release::{
    ADDRESS_SPACE_BYTES, CPU_SECONDS, HOST_REQUIREMENT, OPERATION, OUTPUT_BYTES, PROVIDER_ID,
    PROVIDER_NAME, PROVIDER_VERSION,
};

/// Bind the single EVM contract to shared validation and session delivery.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context: &ToolContext<'_>, input: Value| {
        inspect(context, input)
    });
}

/// Validated `{ path, encoding }` provider input (`InspectEvmInterfaceInput`).
struct InspectInput {
    path: String,
    encoding: Encoding,
}

/// Port of `registerEvmTools` delivery + `EvmInterfaceService.inspect` +
/// `EvmoleInterfaceProvider.#inspect`.
fn inspect(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // `createEvidenceToolHandler` admission: fail fast when cancelled before
    // the operation is admitted.
    if let Err(error) = crate::common::admit(context) {
        return error.into();
    }

    // The delivery-only `detail` selection is stripped before the service
    // (`registerEvmTools`: `const { detail, ...input } = parsed.data`). The
    // surviving `{ path, encoding }` is the provider input and the exact
    // Evidence `parameters`.
    let summary = matches!(input.get("detail").and_then(Value::as_str), Some("summary"));

    // `detail: "summary"` retention preflight runs before the service
    // (`requireAnalysisViewRetention`). The native session always retains
    // Evidence, so it always succeeds; it is ordered here as the TS does. The
    // actual summary projection runs on success via `summary_view`.

    let parameters = parameters_value(&input);

    crate::common::run_service_tool(context, || {
        // `AnalysisCancelledError` when the request was already aborted
        // (`EvmInterfaceService.inspect`, first branch).
        context.check_cancelled()?;

        let request = parse_input(&input)?;

        // Zod refinement JSON Schema cannot express: the service requires an
        // absolute path on this host (`EvmInterfaceService.inspect`).
        if !std::path::Path::new(&request.path).is_absolute() {
            return Err(AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_format",
                    "Expected an absolute filesystem path on this host.",
                )],
            ));
        }

        let evidence = provider_inspect(context, &request, parameters.clone())?;

        // `detail === "summary"` → deliver the retained, linked summary view.
        if summary {
            crate::common::summary_view(context, evidence)
        } else {
            context.session.record(&evidence)?;
            Ok(evidence)
        }
    })
}

/// Evidence `parameters`: the exact surviving `{ path, encoding }` object, in
/// input order, with the delivery-only `detail` removed.
fn parameters_value(input: &Value) -> Value {
    let mut parameters = Map::new();
    if let Some(object) = input.as_object() {
        if let Some(path) = object.get("path") {
            parameters.insert("path".into(), path.clone());
        }
        if let Some(encoding) = object.get("encoding") {
            parameters.insert("encoding".into(), encoding.clone());
        }
    }
    Value::Object(parameters)
}

/// Parse the surviving provider input. The frozen `inputSchema` already
/// enforced a non-empty, NUL-free `path` and `encoding ∈ {raw, hex}`; this
/// only reads the validated values.
fn parse_input(input: &Value) -> Result<InspectInput, AnalysisError> {
    let object = input.as_object().ok_or_else(|| {
        AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_type",
                "Expected an EVM interface inspection request object.",
            )],
        )
    })?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_type",
                    "A caller-selected local bytecode carrier path is required.",
                )],
            )
        })?
        .to_owned();
    let encoding = match object.get("encoding").and_then(Value::as_str) {
        Some("raw") => Encoding::Raw,
        Some("hex") => Encoding::Hex,
        _ => {
            return Err(AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["encoding"],
                    "invalid_value",
                    "Select raw or hex carrier encoding explicitly.",
                )],
            ));
        }
    };
    Ok(InspectInput { path, encoding })
}

/// Port of `EvmoleInterfaceProvider.#inspect` + the service's output
/// re-validation and `evmInterfaceEvidence` finalization, with provider
/// progress reporting.
fn provider_inspect(
    context: &ToolContext<'_>,
    request: &InspectInput,
    parameters: Value,
) -> Result<Evidence, AnalysisError> {
    context.progress.report(OPERATION, "started");
    let result = provider_execute(context, request, parameters);
    context.progress.report(
        OPERATION,
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    result
}

fn provider_execute(
    context: &ToolContext<'_>,
    request: &InspectInput,
    parameters: Value,
) -> Result<Evidence, AnalysisError> {
    // `#inspect`: cancellation, then the host gate before any file read.
    context.check_cancelled()?;
    host_gate()?;

    // `phase = "artifact-read"`: stable carrier acquisition with identity
    // revalidation, bounded by `EVM_INTERFACE_LIMITS.inputBytes`.
    let access = crate::common::host_files();
    let carrier = rea_host::fs::stable_file::read(
        Arc::clone(&access),
        std::path::Path::new(&request.path),
        release::INPUT_BYTES,
        &context.cancellation,
    )
    .map_err(|failure| failures::carrier_read_failure(&failure, &request.path))?;

    // `phase = "worker"`: run the locked engine (carrier decode, EF00 guard,
    // EVMole call, SHA-256, metadata candidate) in-process.
    let reply = match engine::run(&carrier.bytes, request.encoding) {
        Ok(reply) => reply,
        // `reply.reason === "unsupported"` → AnalysisUnsupportedTargetError.
        Err(engine::EngineFailure::Unsupported(message)) => {
            return Err(AnalysisError::unsupported_target(
                OPERATION,
                request.path.clone(),
                message,
            ));
        }
        // `reply.reason === "format"` → AnalysisInputError (invalid_format).
        Err(engine::EngineFailure::Format(message)) => {
            return Err(AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(&["path"], "invalid_format", message)],
            ));
        }
    };

    // Decoded-identity re-check (`decodeEvmBytecodeCarrier` + SHA-256 vs the
    // reply). In-process this is computed once, but the invariant is retained.
    let selected = carrier::decode_evm_bytecode_carrier(&carrier.bytes, request.encoding)
        .map_err(|_| decoded_identity_error())?;
    let selected_hex = hex_lower(&selected);
    let decoded_hash = format!("{:x}", Sha256::new().chain_update(&selected).finalize());
    if decoded_hash != reply.sha256 || selected_hex != reply.hex || selected.len() != reply.bytes {
        return Err(decoded_identity_error());
    }

    let limitations = limitations();

    // `evmInterfaceSchema` result (`EvmoleInterfaceProvider` assembles it, then
    // `safeParse`s). Reproduce the same ordered object and the `superRefine`
    // invariants.
    let report = build_report(
        request,
        &carrier.sha256,
        carrier.bytes.len(),
        &reply,
        &limitations,
    )?;

    // The service re-validates carrier identity/encoding and subject binding
    // (`EvmInterfaceService.inspect`, `AnalysisOutputError` branch).
    verify_output(request, &report, &carrier.sha256)?;

    let subject = SubjectTarget {
        path: request.path.clone(),
        sha256: carrier.sha256.clone(),
        format: "file".to_owned(),
        architecture: None,
    };

    let observation = Observation::new(OPERATION, parameters, report)
        .raw(reply.raw)
        .confidence("inferred")
        .limitations(limitations)
        .locations(vec![json!({
            "kind": "artifact-path",
            "path": request.path,
        })]);

    Evidence::create(Some(&subject), &provider_identity(), observation)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}

/// `process.platform !== "linux" || process.arch !== "x64"` → fail closed with
/// `AnalysisCapabilityUnavailableError` carrying `HOST_REQUIREMENT`.
fn host_gate() -> Result<(), AnalysisError> {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Ok(())
    } else {
        Err(
            AnalysisError::capability_unavailable(PROVIDER_ID, OPERATION, HOST_REQUIREMENT)
                .with_user_message(HOST_REQUIREMENT),
        )
    }
}

/// `EVMOLE_PROVIDER_IDENTITY`.
fn provider_identity() -> EvidenceProvider {
    EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, Some(PROVIDER_VERSION.into()))
}

fn decoded_identity_error() -> AnalysisError {
    AnalysisError::output(
        OPERATION,
        "Decoded bytecode representation does not match the selected carrier, encoding or reported SHA-256.",
    )
}

/// The `evmInterfaceSchema` result value, with its fields and `bytecode`
/// sub-fields in the original order, enforcing the `superRefine` invariants.
fn build_report(
    request: &InspectInput,
    carrier_sha256: &str,
    carrier_bytes: usize,
    reply: &engine::EngineReply,
    limitations: &[String],
) -> Result<Value, AnalysisError> {
    // `superRefine`: `bytecode.hex.length === bytecode.bytes * 2`.
    if reply.hex.len() != reply.bytes * 2 {
        return Err(AnalysisError::output(
            OPERATION,
            "Selected byte count does not match the bytecode hex representation.",
        ));
    }
    validate_metadata_range(reply)?;
    // `superRefine`: every inferred body offset lies inside the selected bytecode.
    for function in &reply.functions {
        let offset = function
            .get("bytecode_offset")
            .and_then(Value::as_u64)
            .unwrap_or(u64::MAX);
        if offset >= reply.bytes as u64 {
            return Err(AnalysisError::output(
                OPERATION,
                "Inferred body offset lies outside the selected bytecode.",
            ));
        }
    }

    let mut bytecode = Map::new();
    bytecode.insert("sha256".into(), reply.sha256.clone().into());
    bytecode.insert("bytes".into(), json!(reply.bytes));
    bytecode.insert("hex".into(), reply.hex.clone().into());
    bytecode.insert("digest_algorithm".into(), "sha256".into());
    bytecode.insert("kind".into(), "unknown".into());
    bytecode.insert("deployment_authenticity".into(), "unknown".into());
    bytecode.insert("hardfork".into(), "unknown".into());
    bytecode.insert("metadata".into(), reply.metadata.clone());

    let mut report = Map::new();
    report.insert(
        "artifact".into(),
        json!({
            "path": request.path,
            "sha256": carrier_sha256,
            "bytes": carrier_bytes,
            "encoding": request.encoding.as_str(),
        }),
    );
    report.insert("bytecode".into(), Value::Object(bytecode));
    report.insert("evidence_kind".into(), "inferred".into());
    report.insert("functions".into(), Value::Array(reply.functions.clone()));
    report.insert("discovery_completeness".into(), "unknown".into());
    report.insert("runtime_execution".into(), "not-performed".into());
    report.insert(
        "diagnostics".into(),
        json!({ "stdout": "", "stderr": "", "truncated": false }),
    );
    report.insert(
        "limitations".into(),
        Value::Array(limitations.iter().cloned().map(Value::String).collect()),
    );
    Ok(Value::Object(report))
}

/// `superRefine` metadata-range invariant: when metadata is examined, its
/// candidate range must match the terminal length suffix in selected bytecode.
fn validate_metadata_range(reply: &engine::EngineReply) -> Result<(), AnalysisError> {
    let Some(metadata) = reply.metadata.as_object() else {
        return Ok(());
    };
    let status = metadata.get("status").and_then(Value::as_str).unwrap_or("");
    if status == "unavailable" {
        return Ok(());
    }
    let bytecode_offset = metadata.get("bytecode_offset").and_then(Value::as_u64);
    let cbor_bytes = metadata.get("cbor_bytes").and_then(Value::as_u64);
    let (Some(offset), Some(cbor_bytes)) = (bytecode_offset, cbor_bytes) else {
        return Err(metadata_range_error());
    };
    // `metadata.bytecode_offset + metadata.cbor_bytes + 2 === bytecode.bytes`.
    if offset + cbor_bytes + 2 != reply.bytes as u64 {
        return Err(metadata_range_error());
    }
    // `metadata.cbor_bytes === parseInt(bytecode.hex.slice(-4), 16)`.
    let suffix = reply
        .hex
        .get(reply.hex.len().saturating_sub(4)..)
        .unwrap_or("");
    let suffix_value = u64::from_str_radix(suffix, 16).unwrap_or(u64::MAX);
    if cbor_bytes != suffix_value {
        return Err(metadata_range_error());
    }
    Ok(())
}

fn metadata_range_error() -> AnalysisError {
    AnalysisError::output(
        OPERATION,
        "Metadata range must match the terminal length suffix in selected bytecode.",
    )
}

/// `EvmInterfaceService.inspect` output re-validation: the adapter must not
/// change the selected carrier identity or encoding.
fn verify_output(
    request: &InspectInput,
    report: &Value,
    carrier_sha256: &str,
) -> Result<(), AnalysisError> {
    let artifact = report.get("artifact").and_then(Value::as_object);
    let path_ok = artifact
        .and_then(|artifact| artifact.get("path"))
        .and_then(Value::as_str)
        == Some(request.path.as_str());
    let encoding_ok = artifact
        .and_then(|artifact| artifact.get("encoding"))
        .and_then(Value::as_str)
        == Some(request.encoding.as_str());
    let sha_ok = artifact
        .and_then(|artifact| artifact.get("sha256"))
        .and_then(Value::as_str)
        == Some(carrier_sha256);
    if path_ok && encoding_ok && sha_ok {
        Ok(())
    } else {
        Err(AnalysisError::output(
            OPERATION,
            "Interface adapter returned malformed data or changed the selected carrier identity/encoding.",
        ))
    }
}

/// The result `limitations` (`EvmoleInterfaceProvider.#inspect`), adapted to
/// the in-process engine. The inference, authenticity, metadata and SHA-256
/// lines are retained verbatim; the two worker-isolation lines state the
/// native reality (the engine runs in-process, so the util-linux `rlimit`s,
/// the V8 heap cap, the worker deadline and worker-crash containment from the
/// owned Node worker are not reproduced here).
fn limitations() -> Vec<String> {
    vec![
        format!(
            "Native in-process EVMole 0.9.3 engine: the util-linux prlimit isolation is not reproduced here. The original owned Node worker configured soft limits from inherited tighter /proc/self/limits (address space ceiling {ADDRESS_SPACE_BYTES} bytes, cpu time ceiling {CPU_SECONDS} seconds, file size ceiling {OUTPUT_BYTES} bytes); in-process no such rlimits, V8 heap cap or worker-crash containment apply. Effective limits are not independently probed.",
        ),
        "Upstream may also report terminal metadata while recovering selectors. Its reported values are retained in raw_result, but integer precision and non-text-key coverage are unknown in the JS binding; complete original bytecode remains available.".to_owned(),
        "Recovered selectors, argument strings and mutability are upstream inferences, not verified ABI signatures or names. Empty results do not prove the absence of callable dispatch.".to_owned(),
        "Bytecode kind, hardfork and deployed-contract authenticity are unknown. This inspection performs no target runtime execution, chain/RPC lookup or network request.".to_owned(),
        "Original carrier and decoded bytecode SHA-256 are distinct identities; SHA-256 is not the Ethereum Keccak code hash.".to_owned(),
        "Terminal CBOR metadata is an independently decoded candidate, not proof of Solidity origin, source identity or deployment. Nested or unsupported values retain explicit unavailable interpretation and original byte ranges.".to_owned(),
        format!(
            "The original owned worker had a 256 MiB JavaScript heap, {ADDRESS_SPACE_BYTES}-byte virtual address-space limit and {TIMEOUT_SECONDS}-second deadline. Running in-process, these bounds and their fail-without-partial-success semantics are not enforced by this adapter.",
        ),
    ]
}

/// The worker deadline in seconds (`EVM_INTERFACE_LIMITS.timeoutMs / 1000`).
const TIMEOUT_SECONDS: u64 = release::TIMEOUT_MS / 1_000;

fn hex_lower(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        text.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    text
}
