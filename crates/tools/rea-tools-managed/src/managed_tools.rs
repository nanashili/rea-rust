//! Execution-free managed PE/CLI inspection tools.
//!
//! Compatibility owners: `src/server/registerManagedTools.ts`,
//! `src/server/registerEvidenceTools.ts`, `src/server/retainedSummaryDelivery.ts`,
//! `runManagedProviderExecution` (`src/application/DirectAnalysis.ts`),
//! `src/dotnet/ManagedStaticProvider.ts`, `ManagedSnapshot.ts` and
//! `ManagedStaticProviderMetadata.ts`.
//!
//! Each call resolves its path (explicit, previously selected, or the active
//! managed PE target), opens it in an isolated managed-only session, retains
//! one eagerly read snapshot bound to the opened digest and decodes it with
//! `crate::dotnet`. The target is never loaded or executed.
use crate::common::Refinement;
use crate::dotnet::{self, ReadError};
use crate::target::{self, TargetOptions};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Evidence, Observation};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::sync::Mutex;

const ARTIFACT: &str = "inspect_managed_artifact";
const MEMBERS: &str = "inspect_managed_members";
const BOUNDARIES: &str = "inspect_managed_native_boundaries";

/// `MAX_MANAGED_SNAPSHOT_BYTES`: the complete PE snapshot is retained in memory.
const MAX_MANAGED_SNAPSHOT_BYTES: u64 = 128 * 1024 * 1024;
const READ_CHUNK_BYTES: usize = 64 * 1024;

const ABSOLUTE_PATH_MESSAGE: &str = "path must be an absolute local filesystem path (for example /tmp/Example.dll or C:\\Example.dll)";
const MISSING_PATH_MESSAGE: &str =
    "Provide a managed PE/CLI path or first select one with inspect_managed_artifact.";

/// Bind the three managed inspection tools to their exact contracts.
pub fn register(registry: &mut Registry) {
    for operation in [ARTIFACT, MEMBERS, BOUNDARIES] {
        registry.handle(operation, move |context: &ToolContext<'_>, input: Value| {
            handle(context, operation, &input)
        });
    }
}

/// `selectedManagedPath`: the last explicit path whose execution succeeded,
/// shared by the three tools of one server session.
#[derive(Default)]
struct SelectedManagedPath(Mutex<Option<String>>);

fn handle(context: &ToolContext<'_>, operation: &'static str, input: &Value) -> ToolOutput {
    // `localPathStringSchema.refine(isAbsolute)`: the advertised JSON Schema
    // cannot express it, so the SDK input-validation failure is reproduced.
    let requested = input.get("path").and_then(Value::as_str);
    if let Some(path) = requested
        && !is_absolute(path)
    {
        return crate::common::refinement_failure(
            operation,
            vec![Refinement::new(vec![json!("path")], ABSOLUTE_PATH_MESSAGE)],
        );
    }
    // Summary delivery requires session retention, which this server always
    // provides, so the preflight always succeeds.
    let summary = matches!(operation, ARTIFACT | MEMBERS)
        && input.get("detail").and_then(Value::as_str) == Some("summary");
    context.progress.report(operation, "started");
    let outcome = execute(context, operation, input, requested);
    context.progress.report(
        operation,
        if outcome.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    let evidence = match outcome {
        Ok(evidence) => evidence,
        Err(error) => return ToolOutput::Failure(error),
    };
    if !summary {
        return ToolOutput::Evidence(evidence);
    }
    crate::analysis_view::summarize_retained(context.session, evidence).into()
}

/// The admitted execution plus Evidence creation (`registerEvidenceTools`).
fn execute(
    context: &ToolContext<'_>,
    operation: &'static str,
    input: &Value,
    requested: Option<&str>,
) -> Result<Evidence, AnalysisError> {
    let selected = context.session.state::<SelectedManagedPath>();
    let path = match requested {
        Some(path) => path.to_owned(),
        None => {
            let remembered = selected
                .0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            match remembered.or_else(|| active_managed_path(context)) {
                Some(path) => path,
                None => {
                    return Err(AnalysisError::input(
                        operation,
                        vec![InputIssue::new(
                            &["path"],
                            "missing_argument",
                            MISSING_PATH_MESSAGE,
                        )],
                    ));
                }
            }
        }
    };
    let (target, result) = run_managed_execution(context, operation, input, &path)?;
    if let Some(requested) = requested {
        *selected
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(requested.to_owned());
    }
    let limitations =
        crate::common::json::strings(result.get("limitations").unwrap_or(&Value::Null));
    let locations = managed_locations(&result);
    let mut observation =
        Observation::new(operation, evidence_parameters(operation, input), result)
            .limitations(limitations)
            .locations(locations);
    observation.raw_result = Some(Value::Null);
    let subject = target.subject();
    crate::common::create_evidence(
        operation,
        Some(&subject),
        &crate::common::managed_static_provider(),
        observation,
    )
}

/// `activeTarget()` when it is a managed PE: the binary session owns the
/// active subject; its `managed` admission fact is re-derived from the path.
fn active_managed_path(context: &ToolContext<'_>) -> Option<String> {
    let subject = context.session.active_subject()?;
    if subject.get("format").and_then(Value::as_str) != Some("pe") {
        return None;
    }
    let path = subject
        .get("local_path")
        .and_then(Value::as_str)?
        .to_owned();
    match target::parse_binary_target(&path, &TargetOptions::default(), &context.cancellation) {
        Ok(resolved) => {
            let managed = resolved.format == "pe"
                && resolved.metadata.get("managed").and_then(Value::as_bool) == Some(true);
            managed.then_some(path)
        }
        // The isolated open reports the same failure for this path.
        Err(_) => Some(path),
    }
}

/// `runManagedProviderExecution`: open the path in a managed-only session and
/// execute the operation through `ManagedStaticClient`.
fn run_managed_execution(
    context: &ToolContext<'_>,
    operation: &'static str,
    input: &Value,
    path: &str,
) -> Result<(rea_analysis::BinaryTarget, Value), AnalysisError> {
    context.check_cancelled()?;
    let target =
        target::parse_binary_target(path, &TargetOptions::default(), &context.cancellation)?;
    if target.format != "pe" {
        return Err(AnalysisError::capability_unavailable(
            crate::common::managed_static_provider().id,
            operation,
            format!(
                "Managed static triage requires a PE target; observed {}.",
                target.format
            ),
        ));
    }
    if context.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let (bytes, sha256) = read_managed_snapshot(&target.path, operation, context)?;
    if sha256 != target.sha256 {
        return Err(AnalysisError::evidence_integrity(format!(
            "Managed artifact digest changed after open: expected {}, observed {sha256} at {}",
            target.sha256, target.path
        )));
    }
    let identity = dotnet::Target {
        path: &target.path,
        sha256: &target.sha256,
    };
    let inspected = match operation {
        MEMBERS => {
            let type_names = input
                .get("type_names")
                .and_then(Value::as_array)
                .map(|names| {
                    names
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                });
            dotnet::inspect_managed_members_bytes(&bytes, &identity, type_names.as_deref())
        }
        ARTIFACT => dotnet::inspect_managed_artifact_bytes(&bytes, &identity),
        _ => dotnet::inspect_managed_native_boundaries_bytes(&bytes, &identity),
    };
    match inspected {
        Ok(result) => Ok((target, result)),
        Err(failure) => Err(inspection_failure(
            context,
            operation,
            &target.path,
            failure,
        )),
    }
}

/// The `ManagedStaticClient.execute` catch: typed errors pass through, a
/// malformed (non-capacity) reader failure is an input error, and every other
/// failure is a provider-adapter failure.
///
/// No inspector raises a typed `AnalysisError`; its failures are reader
/// issues or other thrown failures, whose cause the projection omits.
fn inspection_failure(
    context: &ToolContext<'_>,
    operation: &str,
    path: &str,
    failure: ReadError,
) -> AnalysisError {
    if context.cancellation.reason().is_some() {
        return AnalysisError::cancelled(operation);
    }
    match failure {
        ReadError::Reader(failure) if failure.issue.code != "resource-limit" => {
            AnalysisError::input(
                operation,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_format",
                    format!("Selected artifact {path}: {}", failure.issue.detail),
                )],
            )
        }
        _ => {
            AnalysisError::provider_adapter(crate::common::managed_static_provider().id, operation)
        }
    }
}

/// `readManagedSnapshot`: read the complete regular file within the snapshot
/// budget and digest it, failing closed when the file changes mid-read.
fn read_managed_snapshot(
    path: &str,
    operation: &str,
    context: &ToolContext<'_>,
) -> Result<(Vec<u8>, String), AnalysisError> {
    use sha2::{Digest, Sha256};
    let capacity = || {
        AnalysisError::resource_constraint(
            operation,
            "memory",
            "Managed static inspection requires an eagerly retained PE snapshot within its input byte budget.",
            Some(json!({ "max_snapshot_bytes": MAX_MANAGED_SNAPSHOT_BYTES })),
        )
    };
    let filesystem = |error: target::FsError| {
        if context.cancellation.reason().is_some() {
            AnalysisError::cancelled(operation)
        } else {
            target::filesystem_failure(path, &error)
        }
    };
    let file = target::open_regular_file_reject(path).map_err(filesystem)?;
    if file.initial.size > MAX_MANAGED_SNAPSHOT_BYTES {
        return Err(capacity());
    }
    let mut bytes = Vec::with_capacity(file.initial.size as usize);
    let mut chunk = vec![0u8; READ_CHUNK_BYTES];
    loop {
        if context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(operation));
        }
        let read = file
            .read_at(&mut chunk, bytes.len() as u64)
            .map_err(filesystem)?;
        if read == 0 {
            break;
        }
        if (bytes.len() + read) as u64 > MAX_MANAGED_SNAPSHOT_BYTES {
            return Err(capacity());
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
    let observed = file.stat().map_err(filesystem)?;
    if !target::same_regular_file_state(&file.initial, &observed) {
        return Err(AnalysisError::evidence_integrity(format!(
            "Managed source changed while {operation} was reading {path}."
        )));
    }
    let sha256 = format!("{:x}", Sha256::digest(&bytes));
    Ok((bytes, sha256))
}

/// Evidence parameters: the parsed input without the delivery `detail`
/// selection (`withoutDeliveryDetail`), in schema key order.
fn evidence_parameters(operation: &str, input: &Value) -> Value {
    let mut parameters = Map::new();
    for key in ["path", "detail", "type_names"] {
        if key == "detail" && matches!(operation, ARTIFACT | MEMBERS) {
            continue;
        }
        if let Some(value) = input.get(key) {
            parameters.insert(key.to_owned(), value.clone());
        }
    }
    Value::Object(parameters)
}

/// `managedLocations(result)`.
fn managed_locations(result: &Value) -> Vec<Value> {
    let offset = |offset: &Value| json!({ "kind": "file-offset", "offset": offset });
    let module_location = || match result.get("module") {
        Some(module) if !module.is_null() => {
            offset(module.get("row_offset").unwrap_or(&Value::Null))
        }
        _ => json!({ "kind": "file-offset", "offset": 0 }),
    };
    if let Some(pe) = result.get("pe") {
        let cli = pe.get("cli").unwrap_or(&Value::Null);
        if cli.is_null() {
            return vec![json!({ "kind": "file-offset", "offset": 0 })];
        }
        let start = cli
            .get("header_offset")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        let size = cli.get("header_size").and_then(Value::as_i64).unwrap_or(0);
        let mut locations =
            vec![json!({ "kind": "file-offset-range", "start": start, "end": start + size })];
        for key in ["module", "assembly"] {
            if let Some(row) = result.get(key).filter(|row| !row.is_null()) {
                locations.push(offset(row.get("row_offset").unwrap_or(&Value::Null)));
            }
        }
        return locations;
    }
    let mut locations = vec![module_location()];
    if let Some(methods) = result.get("methods").and_then(Value::as_array) {
        for method in methods {
            if let Some(file_offset) = method
                .get("body")
                .and_then(|body| body.get("file_offset"))
                .filter(|value| !value.is_null())
            {
                locations.push(offset(file_offset));
            }
        }
        return locations;
    }
    if let Some(imports) = result.get("pinvoke_imports").and_then(Value::as_array) {
        for mapping in imports {
            locations.push(offset(mapping.get("row_offset").unwrap_or(&Value::Null)));
        }
    }
    locations
}

/// `node:path` `isAbsolute` on this host.
fn is_absolute(path: &str) -> bool {
    if cfg!(windows) {
        let bytes = path.as_bytes();
        let separator = |byte: u8| byte == b'/' || byte == b'\\';
        match bytes {
            [] => false,
            [first, ..] if separator(*first) => true,
            [drive, b':', third, ..] => drive.is_ascii_alphabetic() && separator(*third),
            _ => false,
        }
    } else {
        path.starts_with('/')
    }
}
