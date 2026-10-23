//! Firmware signature inspection (Binwalk) and extraction (Unblob).
//!
//! Compatibility owners: `src/server/registerFirmwareTools.ts`,
//! `src/application/firmware/FirmwareAnalysisService.ts`,
//! `src/firmware/FirmwareProvider.ts` and the modules it composes
//! (`FirmwareCommand`, `FirmwareFiles`, `FirmwareReports`,
//! `FirmwarePublication`, `FirmwareVersion`, `FirmwareRelease`) plus
//! `src/domain/firmware/firmwareAnalysis.ts`.
mod command;
mod deadline;
mod files;
mod publication;
mod release;
mod reports;
mod version;
use crate::errors;
use crate::resources::AnalysisResources;
use crate::runtime::RuntimeRoot;
use command::{CommandExecution, OutputBudget, RunContext};
use deadline::OperationDeadline;
use files::Range;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_mcp::{Registry, ToolContext};
use reports::UnblobContext;
use serde_json::{Map, Value, json};
use std::sync::Arc;
use version::{Admission, Engine};
const INSPECT: &str = "inspect_firmware_regions";
const EXTRACT: &str = "extract_firmware";
/// `limitations` shared by both firmware operations.
const LIMITATIONS: [&str; 5] = [
    "Signature matches and reported sizes do not establish partition validity, encryption or runtime mappings. Binwalk may infer unknown lengths before emitting its report.",
    "Only Linux is supported by this integration. One worker, inherited per-process address-space/file-size/CPU limits and a deadline constrain execution; staging byte and entry budgets are polled and may transiently overshoot. Limits are not aggregate process-memory or filesystem quotas.",
    "Unblob's default sandbox and skip rules remain enabled. Missing external extractors, unknown chunks, encrypted chunks and depth limits yield partial coverage. Extracted code is never executed; only regular files are published, without executable permission bits.",
    "extraction_gaps lists regions that were carved or left unextracted and names extractor dependencies the producer reported as missing. A listed gap does not mean the target is corrupt or that a retained region is empty.",
    "The actual launcher executable is hashed. Interpreter, shared libraries and installed Python package dependencies are not independently attested; source revision remains unknown for caller-supplied builds.",
];
/// Session-owned firmware provider: one inspection or extraction at a time.
struct Firmware(AnalysisResources);
impl Default for Firmware {
    fn default() -> Self {
        Self(AnalysisResources::new(
            "firmware",
            INSPECT,
            "A firmware operation is already active; retry after it completes.",
            || json!({ "max_concurrent_operations": 1 }),
        ))
    }
}
impl rea_mcp::SessionResource for Firmware {
    fn close(&self) -> Result<(), AnalysisError> {
        self.0.close()
    }
}
pub fn register(registry: &mut Registry) {
    registry.handle(INSPECT, |context, input| inspect(context, &input).into());
    registry.handle(EXTRACT, |context, input| extract(context, &input).into());
}
fn provider(context: &ToolContext<'_>) -> Arc<Firmware> {
    let state = context.session.state::<Firmware>();
    context.session.own_once::<Firmware>(state.clone());
    state
}
/// `firmwareRequestSchema` refinements the frozen JSON Schema cannot express:
/// absolute `path` and (extraction) absolute `output_directory`. The service
/// rejects a failed request parse as `new AnalysisInputError(operation, {
/// cause })`, without caller issue metadata.
fn validate_request(operation: &str, input: &Value) -> Result<(), AnalysisError> {
    let absolute = |key: &str| crate::node::is_absolute(rea_mcp::support::string(input, key));
    if !absolute("path") || (operation == EXTRACT && !absolute("output_directory")) {
        return Err(AnalysisError::input(operation, Vec::new()));
    }
    Ok(())
}
fn inspect(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    execute(context, INSPECT, Engine::Binwalk, input)
}
fn extract(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    // `output_directory` is validated absolute by the schema, but the port also
    // revalidates it the way the provider did before publication.
    execute(context, EXTRACT, Engine::Unblob, input)
}
/// Shared orchestration: `FirmwareAnalysisService.execute` + `FirmwareProvider.#execute`.
fn execute(
    context: &ToolContext<'_>,
    operation: &'static str,
    engine: Engine,
    input: &Value,
) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    validate_request(operation, input)?;
    let provider = provider(context);
    let environment = context.session.environment().clone();
    let input_owned = input.clone();
    let execution = provider.0.run(operation, cancellation, || {
        run_operation(
            &provider.0,
            operation,
            engine,
            &input_owned,
            &environment,
            cancellation,
        )
    })?;
    // Compose Evidence; a late cancellation retains the completed observation.
    service_evidence(operation, input, execution, cancellation)
}
/// One completed firmware observation before Evidence identity.
struct FirmwareExecution {
    result: Value,
    raw: Value,
    provider: EvidenceProvider,
    subject: rea_core::evidence::envelope::SubjectTarget,
    limitations: Vec<String>,
    locations: Vec<Value>,
}
fn run_operation(
    resources: &AnalysisResources,
    operation: &'static str,
    engine: Engine,
    input: &Value,
    environment: &std::collections::HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<FirmwareExecution, AnalysisError> {
    // One operation-wide deadline, created after admission exactly as the TS
    // provider builds `AbortSignal.timeout` at the top of `#execute`, combined
    // with the caller cancellation and shared by every phase and the finish.
    let deadline = OperationDeadline::start(cancellation);
    let outcome = run_inner(resources, operation, engine, input, environment, &deadline);
    // `finish`: release retained roots and compose cleanup with the outcome.
    let finished = resources.finish(
        outcome,
        |execution| partial_observation(operation, input, execution),
        operation,
        cancellation,
    );
    // `if (finished.ok && signal.aborted)`: a deadline that elapsed during a
    // successful run surfaces as a timeout retaining the completed observation.
    // `finish` already reclassified a late caller cancellation.
    match finished {
        Ok(execution) if cancellation.reason().is_none() && deadline.expired() => {
            let partial = partial_observation(operation, input, &execution);
            let mut error = AnalysisError::timeout(operation, release::FIRMWARE_LIMITS.timeout_ms);
            if let Some(partial) = partial {
                error = error.retain_partial_observation(partial);
            }
            Err(error)
        }
        other => other,
    }
}
fn run_inner(
    resources: &AnalysisResources,
    operation: &'static str,
    engine: Engine,
    input: &Value,
    environment: &std::collections::HashMap<String, String>,
    deadline: &OperationDeadline<'_>,
) -> Result<FirmwareExecution, AnalysisError> {
    let cancellation = deadline.cancellation();
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let command = command::resolve_command(environment, engine, operation, cancellation)?;
    // Private runtime root (cwd), retained for cleanup.
    let parent = crate::node::tmpdir(environment);
    let root = RuntimeRoot::create_in(&parent, "rea-firmware-").map_err(|error| {
        errors::provider_adapter(
            "firmware",
            operation,
            Some(errors::map([("reason", json!(error.to_string()))])),
            None,
        )
    })?;
    let root_path = root.path().to_owned();
    let root_id = resources.retain_root(root);
    let range = extract_range(input);
    let source_path = rea_mcp::support::string(input, "path");
    let target = files::snapshot(operation, source_path, range, &root_path, cancellation)?;
    // The private snapshot can read up to the 128 MiB input limit; observe
    // the shared deadline at the boundary the way the TS combined signal does.
    if let Some(error) = deadline.interruption(operation) {
        return Err(error);
    }
    let run = |args: Vec<String>,
               output_budget: Option<OutputBudget>|
     -> Result<CommandExecution, AnalysisError> {
        command::run(&RunContext {
            engine,
            operation,
            command: &command.command,
            limiter: &command.limiter,
            args,
            cwd: root_path.clone(),
            environment,
            cancellation,
            deadline,
            resources,
            root: root_id,
            accept_reported_extraction_failure: output_budget.is_some(),
            output_budget,
        })
    };
    // `--version` runs through the same bounded launcher.
    let version_run = run(vec!["--version".to_owned()], None)?;
    let banner = version_run.stdout.text.trim().to_owned();
    if version_run.stdout.bytes > 1024 {
        return Err(command::tool_unavailable(
            engine,
            operation,
            format!(
                "Tool version banner is {} bytes; expected a short {} version line.",
                version_run.stdout.bytes,
                engine.id()
            ),
        ));
    }
    let admitted = version::admit(engine, &banner);
    let admitted_version = match &admitted {
        Admission::Verified { version } | Admission::Compatible { version, .. } => version.clone(),
        Admission::Unsupported { message } | Admission::Unresolved { message } => {
            return Err(command::tool_unavailable(
                engine,
                operation,
                message.clone(),
            ));
        }
    };
    let engine_value = engine_value(engine, &admitted_version, &command.command, &command.sha256);
    let report_path = crate::node::join(&root_path, "report.json");
    let (result, raw, provider_identity) = match engine {
        Engine::Binwalk => {
            let process_run = run(
                vec![
                    "--quiet".to_owned(),
                    "--search-all".to_owned(),
                    "--threads".to_owned(),
                    "1".to_owned(),
                    "--log".to_owned(),
                    report_path.clone(),
                    target.input_path.clone(),
                ],
                None,
            )?;
            let report =
                command::read_report(&report_path, engine, operation, &process_run, cancellation)?;
            let regions = reports::normalize_binwalk(&report, &target.input_path, target.size)?;
            let mut result = Map::new();
            result.insert("engine".into(), engine_value.clone());
            result.insert("input_size".into(), json!(target.size));
            result.insert(
                "regions".into(),
                Value::Array(
                    regions
                        .iter()
                        .map(reports::BinwalkRegion::to_value)
                        .collect(),
                ),
            );
            result.insert("coverage".into(), json!("signature_scan"));
            let raw = errors::object([
                ("report", report),
                ("execution", process_run.to_value()),
                ("version_execution", version_run.to_value()),
            ]);
            (
                Value::Object(result),
                raw,
                EvidenceProvider::new(
                    release::BINWALK_PROVIDER_ID,
                    release::BINWALK_PROVIDER_NAME,
                    Some(admitted_version.clone()),
                ),
            )
        }
        Engine::Unblob => {
            // Absoluteness was established by `validate_request` before admission.
            let output_directory = rea_mcp::support::string(input, "output_directory").to_owned();
            let output_root = crate::node::join(&root_path, "extracted");
            let max_depth = crate::validation::uint(input, "max_depth").unwrap_or(3);
            let max_output_bytes =
                crate::validation::uint(input, "max_output_bytes").unwrap_or(256 * 1024 * 1024);
            let max_output_files =
                crate::validation::uint(input, "max_output_files").unwrap_or(10_000);
            let process_run = run(
                vec![
                    "--process-num".to_owned(),
                    "1".to_owned(),
                    "--depth".to_owned(),
                    max_depth.to_string(),
                    "--randomness-depth".to_owned(),
                    "0".to_owned(),
                    "--report".to_owned(),
                    report_path.clone(),
                    "--log".to_owned(),
                    crate::node::join(&root_path, "unblob.log"),
                    "--extract-dir".to_owned(),
                    output_root.clone(),
                    target.input_path.clone(),
                ],
                Some(OutputBudget {
                    root: output_root.clone(),
                    bytes: max_output_bytes,
                    entries: max_output_files,
                }),
            )?;
            let report =
                command::read_report(&report_path, engine, operation, &process_run, cancellation)?;
            let normalized = reports::normalize_unblob(
                &report,
                &UnblobContext {
                    input_path: &target.input_path,
                    output_root: &output_root,
                    sha256: &target.selection.sha256,
                    length: target.selection.length,
                    offset: target.selection.offset,
                    max_depth,
                },
            )?;
            if process_run.exit_code == Some(1) && normalized.diagnostics.is_empty() {
                return Err(AnalysisError::output(
                    operation,
                    "Unblob failed without a reported extraction diagnostic",
                ));
            }
            // The operation deadline is shared by inventory and publication the
            // way the TS provider threads its combined signal; observe it at the
            // boundary between the extraction command and these phases.
            if let Some(error) = deadline.interruption(operation) {
                return Err(error);
            }
            let entries = files::inventory(
                &output_root,
                max_output_bytes,
                max_output_files,
                operation,
                cancellation,
            )?;
            if let Some(error) = deadline.interruption(operation) {
                return Err(error);
            }
            let published = publication::publish(&publication::PublishContext {
                output_directory: &output_directory,
                entries: &entries,
                normalized: &normalized,
                selection: &target.selection,
                max_depth,
                engine: &engine_value,
                cancellation,
            })?;
            let raw = errors::object([
                ("report", report),
                ("execution", process_run.to_value()),
                ("version_execution", version_run.to_value()),
            ]);
            let _ = published.output_root;
            (
                published.result,
                raw,
                EvidenceProvider::new(
                    release::UNBLOB_PROVIDER_ID,
                    release::UNBLOB_PROVIDER_NAME,
                    Some(admitted_version.clone()),
                ),
            )
        }
    };
    let mut limitations: Vec<String> = LIMITATIONS.iter().map(|text| (*text).to_owned()).collect();
    if let Admission::Compatible { limitation, .. } = &admitted {
        limitations.push(limitation.clone());
    }
    let locations = vec![json!({
        "kind": "file-offset-range",
        "start": target.selection.offset,
        "end": target.selection.offset + target.selection.length,
    })];
    Ok(FirmwareExecution {
        result,
        raw,
        provider: provider_identity,
        subject: target.subject,
        limitations,
        locations,
    })
}
/// `engine` member of both results.
fn engine_value(
    engine: Engine,
    version: &str,
    executable_path: &str,
    executable_sha256: &str,
) -> Value {
    errors::object([
        ("name", json!(engine.id())),
        ("version", json!(version)),
        ("executable_path", json!(executable_path)),
        ("executable_sha256", json!(executable_sha256)),
        ("source_revision", Value::Null),
        ("worker_count", json!(1)),
    ])
}
/// Parse the optional `range` strict object.
fn extract_range(input: &Value) -> Option<Range> {
    let range = input.get("range")?.as_object()?;
    let offset = range.get("offset").and_then(Value::as_u64)?;
    let length = range.get("length").and_then(Value::as_u64)?;
    Some(Range { offset, length })
}
/// `FirmwareAnalysisService.execute` Evidence composition.
fn service_evidence(
    operation: &str,
    input: &Value,
    execution: FirmwareExecution,
    cancellation: &Cancellation,
) -> Result<Evidence, AnalysisError> {
    let observation = Observation::new(operation, input.clone(), execution.result)
        .raw(execution.raw)
        .confidence("observed")
        .locations(execution.locations)
        .limitations(execution.limitations);
    let evidence =
        rea_mcp::support::evidence(Some(&execution.subject), &execution.provider, observation)?;
    if cancellation.reason().is_some() {
        return Err(
            AnalysisError::cancelled(operation).retain_partial_observation(evidence.into_value())
        );
    }
    Ok(evidence)
}
/// Completed Evidence value retained when a late cancellation interrupts cleanup.
fn partial_observation(
    operation: &str,
    input: &Value,
    execution: &FirmwareExecution,
) -> Option<Value> {
    let observation = Observation::new(operation, input.clone(), execution.result.clone())
        .raw(execution.raw.clone())
        .confidence("observed")
        .locations(execution.locations.clone())
        .limitations(execution.limitations.clone());
    rea_mcp::support::evidence(Some(&execution.subject), &execution.provider, observation)
        .ok()
        .map(Evidence::into_value)
}
