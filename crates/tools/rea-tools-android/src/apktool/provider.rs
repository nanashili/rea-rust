//! Apktool provider: tool registration, launcher probe, serialized dispatch,
//! resource decoding and per-operation Evidence assembly.
//!
//! Compatibility owner: `src/apktool/ApktoolProvider.ts` with the shared
//! execution workflow in `src/application/ProviderOperationExecution.ts` and
//! `src/application/AnalysisProvider.ts`.

use crate::common::evidence::{Execution, complete, execution_evidence, subject_of};
use crate::common::process::{
    CommandLimits, CommandOutput, CommandSpec, FailureKind, OutputBudget, RetainedChild,
    run_command,
};
use crate::common::workspace::PrivateRoot;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use super::config::{self, ClientProbeError, Selection};
use super::decode_output;
use super::locale;
use super::state::{self, ApktoolState, PendingWorkspace};
use super::string_tables::{self, Selection as StringSelection};
use super::workspace::{self, Workspace};

pub const APKTOOL_PROVIDER_ID: &str = "apktool";
pub const APKTOOL_PROVIDER_NAME: &str = "Apktool";
pub(crate) const OPERATION_INSPECT: &str = "inspect_apktool_client";
pub(crate) const OPERATION_DECODE: &str = "decode_android_resources";

const DECODE_TIMEOUT_MS: u64 = 600_000;
const DECODE_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MANIFEST_MAX_BYTES: usize = 512 * 1024;
const MAX_DECODED_ENTRIES_VISITED: u64 = 100_000;
const STDERR_EXCERPT_BYTES: usize = 512;

/// Register every Apktool tool by its exact catalog name.
pub fn register(registry: &mut Registry) {
    for operation in [OPERATION_INSPECT, OPERATION_DECODE] {
        registry.handle(operation, move |context: &ToolContext<'_>, input: Value| {
            run_tool(operation, context, input)
        });
    }
}

fn run_tool(operation: &'static str, context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let state = state::state(context.session);
    // Serialize every Apktool call on this session, as the single TS provider.
    let _turn = match state.turn.acquire(&context.cancellation) {
        Ok(turn) => turn,
        Err(_) => return ToolOutput::Failure(AnalysisError::cancelled(operation)),
    };
    if state.is_closing() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }
    // Retained process and workspace cleanup are retried before each operation.
    let unresolved = state.retry_retained_children();
    if !unresolved.is_empty() {
        return ToolOutput::Failure(crate::common::errors::provider_cleanup(
            APKTOOL_PROVIDER_ID,
            operation,
            unresolved,
            crate::common::errors::object(
                json!({ "reason": "Apktool provider-owned command cleanup failed" }),
            ),
        ));
    }
    let unresolved = state.retry_pending_workspaces();
    if !unresolved.is_empty() {
        return ToolOutput::Failure(crate::common::errors::provider_cleanup(
            APKTOOL_PROVIDER_ID,
            operation,
            unresolved,
            crate::common::errors::object(
                json!({ "reason": "Failed Apktool workspaces remain after cleanup retry" }),
            ),
        ));
    }
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }

    // Validate the Zod refinement the JSON schema cannot express: locale
    // qualifiers must not be Android non-locale configuration qualifiers.
    if operation == OPERATION_DECODE {
        if let Some(error) = validate_locale_refinements(&input) {
            return ToolOutput::Failure(error);
        }
    }

    let environment = context.session.environment();
    let (selection, identity) =
        match probe_client(operation, environment, &context.cancellation, &state) {
            Ok(resolved) => resolved,
            Err(error) => return ToolOutput::Failure(error),
        };

    let client = json!({
        "command": selection.command,
        "command_source": selection.command_source.as_str(),
        "apktool_version": identity.version,
    });
    let provider = EvidenceProvider::new(
        APKTOOL_PROVIDER_ID,
        APKTOOL_PROVIDER_NAME,
        Some(identity.version.clone()),
    );

    if operation == OPERATION_INSPECT {
        let result = json!({ "client": client });
        let mut execution = Execution::new(result, provider);
        execution.limitations = identity.limitations.clone();
        let evidence = execution_evidence(operation, input.clone(), execution, "observed")
            .and_then(|evidence| complete(evidence, &context.cancellation, None));
        return evidence.into();
    }

    decode_resources(
        &selection,
        &client,
        &provider,
        &input,
        &identity.limitations,
        &context.cancellation,
        &state,
        environment,
    )
    .into()
}

/// Re-validate `locale` and `locales[i]` against the non-locale-qualifier rule.
fn validate_locale_refinements(input: &Value) -> Option<AnalysisError> {
    let mut issues: Vec<InputIssue> = Vec::new();
    if let Some(value) = input.get("locale").and_then(Value::as_str) {
        if !locale::is_locale_qualifier(value) {
            issues.push(locale_issue(vec![Value::String("locale".into())]));
        }
    }
    if let Some(values) = input.get("locales").and_then(Value::as_array) {
        for (index, value) in values.iter().enumerate() {
            if let Some(text) = value.as_str() {
                if !locale::is_locale_qualifier(text) {
                    issues.push(locale_issue(vec![
                        Value::String("locales".into()),
                        Value::Number(index.into()),
                    ]));
                }
            }
        }
    }
    if issues.is_empty() {
        None
    } else {
        Some(AnalysisError::input(OPERATION_DECODE, issues))
    }
}

fn locale_issue(path: Vec<Value>) -> InputIssue {
    InputIssue {
        path,
        reason: "invalid_value",
        message: Some("Android resource configuration qualifiers are not locales".into()),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

/// Resolve selection and probe the launcher, mapping configuration refusals and
/// retaining any owned child whose cleanup failed.
fn probe_client(
    operation: &str,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
    state: &Arc<ApktoolState>,
) -> Result<(Selection, super::version::ClientIdentity), AnalysisError> {
    let selection = match config::resolve_apktool_command(environment, cancellation) {
        Ok(selection) => selection,
        Err(ClientProbeError::Configuration(failure)) => {
            return Err(config::configuration_refusal(
                APKTOOL_PROVIDER_ID,
                operation,
                &failure,
            ));
        }
        Err(ClientProbeError::Analysis(error)) => return Err(error),
    };
    match config::inspect_apktool_client(&selection, cancellation) {
        Ok(success) => Ok((selection, success.identity)),
        Err(failure) => {
            if let Some(child) = failure.retained {
                state.retain_child(child);
            }
            match failure.error {
                ClientProbeError::Configuration(configuration) => Err(
                    config::configuration_refusal(APKTOOL_PROVIDER_ID, operation, &configuration),
                ),
                ClientProbeError::Analysis(error) => Err(error),
            }
        }
    }
}

/// `inspectAvailability(...)` as a `ProviderAvailability` JSON value for the
/// binary-session owner's provider discovery. Decodes nothing.
pub fn availability(environment: &HashMap<String, String>) -> Value {
    let cancellation = Cancellation::with_static_reasons(&[]);
    match config::resolve_apktool_command(environment, &cancellation) {
        Err(ClientProbeError::Configuration(failure)) => {
            config::configuration_availability(&failure)
        }
        Err(ClientProbeError::Analysis(error)) => analysis_availability(error),
        Ok(selection) => match config::inspect_apktool_client(&selection, &cancellation) {
            Ok(_) => json!({
                "status": "available",
                "code": Value::Null,
                "reason": Value::Null,
                "diagnostics": {
                    "selected_command": selection.command,
                    "command_source": selection.command_source.as_str(),
                },
            }),
            Err(failure) => match failure.error {
                ClientProbeError::Configuration(configuration) => {
                    config::configuration_availability(&configuration)
                }
                ClientProbeError::Analysis(error) => analysis_availability(error),
            },
        },
    }
}

fn analysis_availability(error: AnalysisError) -> Value {
    let mut diagnostics = Map::new();
    diagnostics.insert("probe_error".into(), json!(error.message()));
    json!({
        "status": "unavailable",
        "code": "version_unresolved",
        "reason": error.message(),
        "diagnostics": Value::Object(diagnostics),
    })
}

/// Run the owned `apktool d` command, classifying its failure like
/// `apktoolCommandFailure`. A child whose cleanup could not be confirmed is
/// retained in session state.
fn run_apktool(
    target_path: &str,
    selection: &Selection,
    arguments: &[&std::ffi::OsStr],
    cancellation: &Cancellation,
    state: &Arc<ApktoolState>,
) -> Result<CommandOutput, AnalysisError> {
    if cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION_DECODE));
    }
    let spec = CommandSpec::new(&selection.command, arguments.iter().copied());
    let limits = CommandLimits {
        timeout: Duration::from_millis(DECODE_TIMEOUT_MS),
        budget: OutputBudget::Combined(DECODE_MAX_OUTPUT_BYTES),
    };
    match run_command(&spec, limits, cancellation, true) {
        Ok(output) => Ok(output),
        Err(failure) => {
            let retained = failure.retained;
            let error = apktool_command_failure(
                &failure.kind,
                &failure.output,
                target_path,
                selection,
                retained.as_ref(),
            );
            if let Some(child) = retained {
                state.retain_child(child);
            }
            Err(error)
        }
    }
}

/// `apktoolCommandFailure(cause, operation, targetPath, selection, limits)`.
fn apktool_command_failure(
    kind: &FailureKind,
    output: &CommandOutput,
    target_path: &str,
    selection: &Selection,
    retained: Option<&RetainedChild>,
) -> AnalysisError {
    let captured = output.captured();
    let diagnostics = || {
        crate::common::errors::object(json!({
            "selected_command": selection.command,
            "target_path": target_path,
        }))
    };
    match kind {
        FailureKind::Cancelled { .. } => {
            let mut error = AnalysisError::cancelled(OPERATION_DECODE);
            error.captured_output = Some(captured);
            error
        }
        FailureKind::Timeout => {
            let mut error = AnalysisError::timeout(OPERATION_DECODE, DECODE_TIMEOUT_MS);
            error.captured_output = Some(captured);
            error
        }
        FailureKind::OutputLimit => {
            let mut error = AnalysisError::resource_constraint(
                OPERATION_DECODE,
                "memory",
                format!(
                    "apktool output exceeded the {DECODE_MAX_OUTPUT_BYTES}-byte capture budget"
                ),
                Some(json!({ "max_output_bytes": DECODE_MAX_OUTPUT_BYTES })),
            );
            error.captured_output = Some(captured);
            error
        }
        // A fully collected ordinary nonzero decode exit is a target refusal.
        FailureKind::Exit if is_clean_nonzero_exit(output, retained) => {
            let reason = target_refusal_reason(output);
            let mut error =
                AnalysisError::unsupported_target(OPERATION_DECODE, target_path, reason);
            error.captured_output = Some(captured);
            error
        }
        // A physical launcher/capture/settlement failure does not establish refusal.
        _ => {
            let mut error = crate::common::errors::provider_adapter(
                APKTOOL_PROVIDER_ID,
                OPERATION_DECODE,
                Some(format!(
                    "The selected Apktool command failed while decoding {target_path}"
                )),
                Some(diagnostics()),
            );
            error.captured_output = Some(captured);
            error
        }
    }
}

/// Whether the failure is a fully collected ordinary nonzero exit.
fn is_clean_nonzero_exit(output: &CommandOutput, retained: Option<&RetainedChild>) -> bool {
    retained.is_none()
        && output.output_closed
        && !output.truncated
        && matches!(output.exit_code, Some(code) if code != 0)
}

fn target_refusal_reason(output: &CommandOutput) -> String {
    let stderr = output.stderr_text();
    let excerpt: String = stderr.trim().chars().take(STDERR_EXCERPT_BYTES).collect();
    if excerpt.is_empty() {
        format!(
            "apktool exited with code {} for {OPERATION_DECODE}",
            output
                .exit_code
                .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
        )
    } else {
        excerpt
    }
}

/// `decodeResources(...)`: decode into a provider-owned workspace, project the
/// requested facts, then remove the workspace. A failed removal is retained.
#[allow(clippy::too_many_arguments)]
fn decode_resources(
    selection: &Selection,
    client: &Value,
    provider: &EvidenceProvider,
    input: &Value,
    client_limitations: &[String],
    cancellation: &Cancellation,
    state: &Arc<ApktoolState>,
    environment: &HashMap<String, String>,
) -> Result<Evidence, AnalysisError> {
    let path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let selection_facts = StringSelection {
        include_strings: input
            .get("include_strings")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        string_tables_only: input
            .get("string_tables_only")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        locale: input
            .get("locale")
            .and_then(Value::as_str)
            .map(str::to_owned),
        locales: input.get("locales").and_then(Value::as_array).map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        }),
    };

    let root = match PrivateRoot::create(
        &crate::common::env::temporary_directory(environment),
        "rea-apktool-",
    ) {
        Ok(root) => root,
        Err(error) => {
            return Err(AnalysisError::protocol(format!(
                "Apktool workspace could not be created: {error}"
            )));
        }
    };
    let mut resources = Workspace::new(root);
    let root_path = resources.path().display().to_string();
    let decoded = resources.path().join("decoded");
    let framework = resources.path().join("framework");
    let snapshot = resources.path().join("input.apk");

    let limitations_base: Vec<String> = client_limitations
        .iter()
        .cloned()
        .chain(std::iter::once(
            "Decoding skips smali (--no-src); Java-source recovery belongs to the JADX family"
                .to_owned(),
        ))
        .collect();

    let outcome = decode_into_workspace(
        &mut resources,
        selection,
        client,
        provider,
        input,
        path,
        &selection_facts,
        &limitations_base,
        &decoded,
        &framework,
        &snapshot,
        cancellation,
        state,
    );

    // Classify a late cancellation before releasing, so a successful result
    // retains its observation exactly like `completeProviderEvidence`.
    let outcome = match outcome {
        Ok(evidence) => complete(evidence, cancellation, None),
        Err(error) => Err(error),
    };

    // Release (remove) the workspace. A failed removal is retained for retry.
    let cleanup_failed = match resources.release() {
        Ok(()) => false,
        Err(root) => {
            state.retain_workspace(PendingWorkspace {
                root,
                resource: root_path.clone(),
            });
            true
        }
    };

    match (outcome, cleanup_failed) {
        (Ok(evidence), false) => Ok(evidence),
        (Ok(evidence), true) => {
            let partial = evidence.into_value();
            Err(provider_cleanup_error(&root_path, Some(partial)))
        }
        (Err(error), false) => Err(error),
        (Err(error), true) => {
            let partial = error.partial_observation.clone();
            let cleanup = provider_cleanup_error(&root_path, partial);
            Err(crate::common::errors::with_cleanup_failure(
                error,
                cleanup,
                OPERATION_DECODE,
            ))
        }
    }
}

fn provider_cleanup_error(root: &str, partial: Option<Value>) -> AnalysisError {
    let mut error = crate::common::errors::provider_cleanup(
        APKTOOL_PROVIDER_ID,
        OPERATION_DECODE,
        vec![root.to_owned()],
        Map::new(),
    );
    error.partial_observation = partial;
    error
}

/// Decode into the workspace and build the success Evidence (without cleanup).
#[allow(clippy::too_many_arguments)]
fn decode_into_workspace(
    resources: &mut Workspace,
    selection: &Selection,
    client: &Value,
    provider: &EvidenceProvider,
    input: &Value,
    path: &str,
    selection_facts: &StringSelection,
    limitations_base: &[String],
    decoded: &Path,
    framework: &Path,
    snapshot: &Path,
    cancellation: &Cancellation,
    state: &Arc<ApktoolState>,
) -> Result<Evidence, AnalysisError> {
    let mut limitations = limitations_base.to_vec();
    let mut completed = Map::new();
    completed.insert("client".into(), client.clone());
    let mut stopped_at = "metadata";

    let run = (|| -> Result<Evidence, AnalysisError> {
        let identity = resources.snapshot_input(path, OPERATION_DECODE, cancellation)?;
        let sha256 = identity.sha256.clone();
        std::fs::create_dir(decoded).map_err(mkdir_failure)?;
        std::fs::create_dir(framework).map_err(mkdir_failure)?;

        let arguments: Vec<&std::ffi::OsStr> = vec![
            "d".as_ref(),
            "--no-src".as_ref(),
            "-f".as_ref(),
            "-o".as_ref(),
            decoded.as_os_str(),
            "--frame-path".as_ref(),
            framework.as_os_str(),
            snapshot.as_os_str(),
        ];
        run_apktool(path, selection, &arguments, cancellation, state)?;

        completed.insert(
            "target".into(),
            json!({ "path": path, "bytes": identity.bytes, "sha256": sha256 }),
        );
        completed.insert("locale".into(), json!(selection_facts.locale));
        completed.insert("coverage".into(), json!("partial"));
        throw_if_cancelled(cancellation)?;

        // apktool.yml metadata.
        let yml = resources
            .read_text(
                &decoded.join("apktool.yml"),
                MANIFEST_MAX_BYTES,
                cancellation,
            )
            .map_err(read_failure)?;
        let Some(yml_text) = yml.text.filter(|_| !yml.truncated) else {
            return Err(AnalysisError::protocol(format!(
                "apktool produced missing or oversized apktool.yml: {path}"
            )));
        };
        let metadata = decode_output::parse_apktool_yml(&yml_text)
            .map_err(|error| AnalysisError::protocol(error.message))?;
        let mut metadata_object = Map::new();
        metadata_object.insert("version_name".into(), json!(metadata.version_name));
        metadata_object.insert("version_code".into(), json!(metadata.version_code));
        metadata_object.insert("min_sdk_version".into(), json!(metadata.min_sdk_version));
        metadata_object.insert(
            "target_sdk_version".into(),
            json!(metadata.target_sdk_version),
        );

        stopped_at = "manifest";
        let manifest_read = resources
            .read_text(
                &decoded.join("AndroidManifest.xml"),
                MANIFEST_MAX_BYTES,
                cancellation,
            )
            .map_err(read_failure)?;
        let manifest = manifest_read.text.clone();
        completed.insert("manifest".into(), json!(manifest));
        if manifest_read.truncated {
            limitations.push(format!(
                "manifest is truncated at {MANIFEST_MAX_BYTES} bytes"
            ));
        }
        let package_name = if manifest.is_none() || manifest_read.truncated {
            None
        } else {
            decode_output::parse_manifest_package(manifest.as_deref().unwrap_or_default())
                .map_err(|error| AnalysisError::protocol(error.message))?
        };
        metadata_object.insert("package_name".into(), json!(package_name));
        completed.insert("metadata".into(), Value::Object(metadata_object));

        stopped_at = "inventory";
        let inventory_result =
            workspace::count_decoded_files(decoded, cancellation, MAX_DECODED_ENTRIES_VISITED);
        let (inventory, inventory_error) = match inventory_result {
            Ok(inventory) => (inventory, None),
            Err((error, partial)) => (partial, Some(error)),
        };
        completed.insert("locales".into(), json!(inventory.locales));
        completed.insert("decoded_file_count".into(), json!(inventory.count));
        if !inventory.unreadable_strings_tables.is_empty() {
            let detail = inventory
                .unreadable_strings_tables
                .iter()
                .map(|table| {
                    format!(
                        "{} ({})",
                        super::version::json_string(&table.path),
                        table.kind
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            limitations.push(format!(
                "String tables omitted because they are not regular files: {detail}"
            ));
        }
        if !inventory.other_strings_tables.is_empty() {
            let detail = inventory
                .other_strings_tables
                .iter()
                .map(|table| super::version::json_string(table))
                .collect::<Vec<_>>()
                .join(", ");
            limitations.push(format!(
                "Other strings tables are not selected by locale; their resource configuration suffixes are preserved without inferring Android runtime matching: {detail}"
            ));
        }
        if inventory.capped {
            limitations.push(format!(
                "Decoded workspace enumeration stopped after {MAX_DECODED_ENTRIES_VISITED} entries; decoded_file_count and locales may be partial"
            ));
        }
        if let Some(error) = inventory_error {
            return Err(error);
        }
        throw_if_cancelled(cancellation)?;

        stopped_at = "string projection";
        let projection_result =
            string_tables::project_string_tables(resources, decoded, selection_facts, cancellation);
        let (projection, projection_error) = match projection_result {
            Ok(projection) => (projection, None),
            Err((error, partial)) => (partial, Some(error)),
        };
        limitations.extend(projection.limitations.iter().cloned());
        let coverage = if projection.coverage == "partial"
            || manifest_read.truncated
            || inventory.capped
            || !inventory.unreadable_strings_tables.is_empty()
        {
            "partial"
        } else {
            "complete"
        };
        completed.insert(
            "strings".into(),
            json!(
                projection
                    .strings
                    .iter()
                    .map(|entry| json!({ "name": entry.name, "value": entry.value }))
                    .collect::<Vec<_>>()
            ),
        );
        if selection_facts.locales.is_some() || selection_facts.string_tables_only {
            completed.insert(
                "string_tables".into(),
                json!(
                    projection
                        .tables
                        .iter()
                        .map(string_tables::StringTable::to_json)
                        .collect::<Vec<_>>()
                ),
            );
        }
        completed.insert("coverage".into(), json!(coverage));
        if let Some(error) = projection_error {
            return Err(error);
        }

        let subject = subject_of(path, &sha256, "apk", None);
        let mut execution = Execution::new(Value::Object(completed.clone()), provider.clone());
        execution.limitations = limitations.clone();
        execution.subject = Some(subject);
        execution_evidence(OPERATION_DECODE, input.clone(), execution, "observed")
    })();

    match run {
        Ok(evidence) => Ok(evidence),
        Err(mut error) => {
            if error.partial_observation.is_none() {
                if let Some(partial) =
                    build_partial(provider, input, path, &completed, &limitations, stopped_at)
                {
                    error = error.retain_partial_observation(partial);
                } else if let Some(snapshot_identity) = resources.snapshot() {
                    error = error.retain_partial_observation(json!({
                        "kind": "file-snapshot-hash",
                        "path": snapshot_identity.path,
                        "bytes": snapshot_identity.bytes,
                        "sha256": snapshot_identity.sha256,
                    }));
                }
            }
            Err(error)
        }
    }
}

/// Build a partial-observation Evidence value from the facts gathered so far,
/// once the decode produced a target. Returns `None` before that point.
fn build_partial(
    provider: &EvidenceProvider,
    input: &Value,
    path: &str,
    completed: &Map<String, Value>,
    limitations: &[String],
    stopped_at: &str,
) -> Option<Value> {
    if !completed.contains_key("target") {
        return None;
    }
    let mut facts = completed.clone();
    facts.insert("coverage".into(), json!("partial"));
    let mut limitations = limitations.to_vec();
    limitations.push(format!(
        "Decode observation stopped during {stopped_at}; fields not yet observed are omitted"
    ));
    let sha256 = facts
        .get("target")
        .and_then(|target| target.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let subject = subject_of(path, &sha256, "apk", None);
    let mut execution = Execution::new(Value::Object(facts), provider.clone());
    execution.limitations = limitations;
    execution.subject = Some(subject);
    execution_evidence(OPERATION_DECODE, input.clone(), execution, "observed")
        .ok()
        .map(Evidence::into_value)
}

fn throw_if_cancelled(cancellation: &Cancellation) -> Result<(), AnalysisError> {
    if cancellation.reason().is_some() {
        Err(AnalysisError::cancelled(OPERATION_DECODE))
    } else {
        Ok(())
    }
}

fn mkdir_failure(error: std::io::Error) -> AnalysisError {
    AnalysisError::protocol(format!(
        "Apktool workspace subdirectory could not be created: {error}"
    ))
}

fn read_failure(error: workspace::ReadError) -> AnalysisError {
    match error {
        workspace::ReadError::Cancelled => AnalysisError::cancelled(OPERATION_DECODE),
        workspace::ReadError::Protocol(message) => AnalysisError::protocol(message),
        workspace::ReadError::Io { path, error } => AnalysisError::protocol(format!(
            "Apktool output could not be read: {}",
            crate::common::files::node_io_message(&error, "read", &path)
        )),
    }
}
