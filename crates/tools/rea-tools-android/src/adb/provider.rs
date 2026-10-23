//! ADB provider: tool registration, client probe, serialized dispatch and
//! per-operation Evidence assembly.
//!
//! Compatibility owner: `src/adb/AdbProvider.ts` with the shared execution
//! workflow in `src/application/ProviderOperationExecution.ts` and
//! `src/application/AnalysisProvider.ts`.
use crate::adb::command::{
    AdbCommandError, AdbCommandTarget, AdbRunLimits, adb_arguments, run_adb,
};
use crate::adb::config::{
    ClientIdentity, ClientProbeError, Selection, configuration_availability, configuration_refusal,
    inspect_adb_client, resolve_adb_binary,
};
use crate::adb::state::{self, AdbState};
use crate::common::evidence::{Execution, complete, execution_evidence};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::Arc;

pub const ADB_PROVIDER_ID: &str = "adb";
pub const ADB_PROVIDER_NAME: &str = "Android Debug Bridge";

pub(crate) const DEVICES_TIMEOUT_MS: u64 = 20_000;
pub(crate) const DEVICES_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const SHELL_TIMEOUT_MS: u64 = 30_000;
pub(crate) const GETPROP_MAX_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
pub(crate) const PACKAGE_LIST_TIMEOUT_MS: u64 = 60_000;
pub(crate) const PACKAGE_LIST_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const PM_PATH_TIMEOUT_MS: u64 = 30_000;
pub(crate) const PM_PATH_MAX_OUTPUT_BYTES: usize = 64 * 1024;
pub(crate) const PULL_TIMEOUT_MS: u64 = 600_000;
pub(crate) const PULL_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const LOGCAT_TIMEOUT_MS: u64 = 60_000;
pub(crate) const LOGCAT_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const DUMPSYS_PACKAGE_TIMEOUT_MS: u64 = 60_000;
pub(crate) const DUMPSYS_PACKAGE_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const DUMPSYS_WINDOW_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const LISTING_TIMEOUT_MS: u64 = 30_000;
pub(crate) const LISTING_MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const SETTINGS_TIMEOUT_MS: u64 = 20_000;
pub(crate) const SETTINGS_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const SCREEN_TIMEOUT_MS: u64 = 60_000;
pub(crate) const SCREEN_MAX_OUTPUT_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const BUGREPORT_TIMEOUT_MS: u64 = 600_000;
pub(crate) const BUGREPORT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub(crate) const UNPARSED_LINES_REPORTED: usize = 10;

/// The parameters and resolved facts carried through one operation.
pub(crate) struct Context<'a> {
    pub operation: &'static str,
    pub selection: Selection,
    pub client: Value,
    pub provider: EvidenceProvider,
    pub cancellation: &'a Cancellation,
    pub state: &'a Arc<AdbState>,
    pub environment: &'a HashMap<String, String>,
}

impl Context<'_> {
    pub fn limits(timeout_ms: u64, max_output_bytes: usize) -> AdbRunLimits {
        AdbRunLimits {
            timeout_ms,
            max_output_bytes,
        }
    }

    /// `shell(arguments, limits)` over the active device serial.
    pub fn shell(
        &self,
        serial: &str,
        arguments: &[&str],
        limits: AdbRunLimits,
    ) -> Result<crate::adb::command::AdbResult, AdbCommandError> {
        let mut shell_args = vec!["shell"];
        shell_args.extend_from_slice(arguments);
        let args = adb_arguments(Some(serial), &shell_args);
        run_adb(
            self.operation,
            &AdbCommandTarget {
                device: serial.to_owned(),
                path: None,
                local_path: None,
            },
            &self.selection.binary,
            &args,
            limits,
            self.cancellation,
        )
    }

    /// Retain any unresolved child, returning the typed error for the failure.
    pub fn retain_child(&self, error: AdbCommandError) -> AnalysisError {
        if let Some(child) = error.retained {
            self.state.retain_child(child);
        }
        error.error
    }
}

/// `clientIdentityResult(selection, identity)`.
pub(crate) fn client_result(selection: &Selection, identity: &ClientIdentity) -> Value {
    json!({
        "binary_path": selection.binary,
        "path_source": selection.path_source.as_str(),
        "version": identity.version,
        "installed_path": identity.installed_path,
    })
}

/// Provider identity for Evidence, carrying the probed version.
pub(crate) fn provider_identity(identity: &ClientIdentity) -> EvidenceProvider {
    EvidenceProvider::new(ADB_PROVIDER_ID, ADB_PROVIDER_NAME, identity.version.clone())
}

/// `reported(unparsedLines, coverage)`: the capped lines and derived coverage.
pub(crate) fn reported(unparsed_lines: &[String], coverage: &str) -> (Vec<String>, &'static str) {
    let capped: Vec<String> = unparsed_lines
        .iter()
        .take(UNPARSED_LINES_REPORTED)
        .cloned()
        .collect();
    let coverage = if coverage == "partial" || !unparsed_lines.is_empty() {
        "partial"
    } else {
        "complete"
    };
    (capped, coverage)
}

/// `unparsedOverflowLimitation(unparsedLines)`.
pub(crate) fn unparsed_overflow_limitation(unparsed_lines: &[String]) -> Vec<String> {
    if unparsed_lines.len() > UNPARSED_LINES_REPORTED {
        vec![format!(
            "unparsed_lines reports the first {UNPARSED_LINES_REPORTED} of {} unrecognized lines",
            unparsed_lines.len()
        )]
    } else {
        Vec::new()
    }
}

/// Build the success Evidence for one operation, then classify a late cancel.
pub(crate) fn finish(
    context: &Context<'_>,
    parameters: Value,
    result: Value,
    limitations: Vec<String>,
    raw_result: Option<Value>,
) -> Result<Evidence, AnalysisError> {
    let mut execution = Execution::new(result, context.provider.clone());
    execution.limitations = limitations;
    execution.raw_result = raw_result;
    let evidence = execution_evidence(context.operation, parameters, execution, "observed")?;
    complete(evidence, context.cancellation, None)
}

/// The validated input object as Evidence parameters.
pub(crate) fn parameters(input: &Value) -> Value {
    input.clone()
}

/// Required `serial` argument.
pub(crate) fn serial_of(input: &Value) -> &str {
    input
        .get("serial")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Register every ADB tool by its exact catalog name.
pub fn register(registry: &mut Registry) {
    for operation in [
        "inspect_adb_client",
        "list_adb_devices",
        "inspect_adb_device",
        "list_adb_packages",
        "pull_adb_package",
        "read_adb_logcat",
        "inspect_adb_package",
        "pull_adb_file",
        "push_adb_file",
        "capture_adb_screen",
        "list_adb_processes",
        "list_adb_directory",
        "list_adb_features",
        "list_adb_services",
        "inspect_adb_display",
        "inspect_adb_window",
        "read_adb_setting",
        "collect_adb_bugreport",
        "resolve_adb_packages",
        "install_adb_package",
        "uninstall_adb_package",
        "start_adb_app",
        "start_adb_activity",
        "stop_adb_app",
    ] {
        registry.handle(operation, move |context: &ToolContext<'_>, input: Value| {
            run_tool(operation, context, input)
        });
    }
}

/// Resolve selection and probe the client, mapping configuration failures.
fn probe_client(
    operation: &str,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<(Selection, ClientIdentity), AnalysisError> {
    let selection = match resolve_adb_binary(environment) {
        Ok(selection) => selection,
        Err(failure) => {
            return Err(configuration_refusal(ADB_PROVIDER_ID, operation, &failure));
        }
    };
    match inspect_adb_client(&selection, cancellation) {
        Ok(identity) => Ok((selection, identity)),
        Err(ClientProbeError::Configuration(failure)) => {
            Err(configuration_refusal(ADB_PROVIDER_ID, operation, &failure))
        }
        Err(ClientProbeError::Analysis(error)) => Err(error),
    }
}

fn run_tool(operation: &'static str, context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // `executeProviderOperation`: a cancelled request fails before admission.
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }
    let state = state::state(context.session);
    // Operations run concurrently, as the original provider admits them; the
    // active guard lets `close()` join them after stopping admission.
    let Some(_active) = state.enter() else {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    };
    // Retained process and output-directory cleanup are retried before each
    // operation; a surviving failure fails the call.
    let unresolved = state.retry_retained_children();
    if !unresolved.is_empty() {
        return ToolOutput::Failure(crate::common::errors::provider_cleanup(
            ADB_PROVIDER_ID,
            operation,
            unresolved.resources.clone(),
            crate::common::errors::object(json!({ "reason": unresolved.reason() })),
        ));
    }
    if state.has_pending_directories() {
        let unresolved = state.retry_pending_directories();
        if !unresolved.is_empty() {
            return ToolOutput::Failure(crate::common::errors::provider_cleanup(
                ADB_PROVIDER_ID,
                operation,
                unresolved.resources.clone(),
                crate::common::errors::object(json!({ "reason": unresolved.reason() })),
            ));
        }
    }

    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(operation));
    }

    let environment = context.session.environment();
    let (selection, identity) = match probe_client(operation, environment, &context.cancellation) {
        Ok(resolved) => resolved,
        Err(error) => return ToolOutput::Failure(error),
    };
    let client = client_result(&selection, &identity);
    let provider = provider_identity(&identity);
    let ctx = Context {
        operation,
        selection,
        client,
        provider,
        cancellation: &context.cancellation,
        state: &state,
        environment,
    };
    dispatch(&ctx, &input).into()
}

fn dispatch(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    use crate::adb::{provider_acquire, provider_mutate, provider_reads};
    match ctx.operation {
        "inspect_adb_client" => inspect_client(ctx, input),
        "list_adb_devices" => provider_reads::list_devices(ctx, input),
        "inspect_adb_device" => provider_reads::inspect_device(ctx, input),
        "list_adb_packages" => provider_reads::list_packages(ctx, input),
        "read_adb_logcat" => provider_reads::read_logcat(ctx, input),
        "inspect_adb_package" => provider_reads::inspect_package(ctx, input),
        "list_adb_processes" => provider_reads::list_processes(ctx, input),
        "list_adb_directory" => provider_reads::list_directory(ctx, input),
        "list_adb_features" => provider_reads::list_features(ctx, input),
        "list_adb_services" => provider_reads::list_services(ctx, input),
        "inspect_adb_display" => provider_reads::inspect_display(ctx, input),
        "inspect_adb_window" => provider_reads::inspect_window(ctx, input),
        "read_adb_setting" => provider_reads::read_setting(ctx, input),
        "resolve_adb_packages" => provider_reads::resolve_packages(ctx, input),
        "pull_adb_package" => provider_acquire::pull_package(ctx, input),
        "pull_adb_file" => provider_acquire::pull_file(ctx, input),
        "capture_adb_screen" => provider_acquire::capture_screen(ctx, input),
        "collect_adb_bugreport" => provider_acquire::collect_bugreport(ctx, input),
        "push_adb_file" => provider_mutate::push_file_env(ctx, input, ctx.environment),
        "install_adb_package" => provider_mutate::install_package_env(ctx, input, ctx.environment),
        "uninstall_adb_package" => provider_mutate::uninstall_package(ctx, input),
        "start_adb_app" => provider_mutate::start_app(ctx, input),
        "start_adb_activity" => provider_mutate::start_activity(ctx, input),
        "stop_adb_app" => provider_mutate::stop_app(ctx, input),
        other => Err(AnalysisError::protocol(format!(
            "ADB {other} returned no result"
        ))),
    }
}

fn inspect_client(ctx: &Context<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let result = json!({
        "client": ctx.client,
        "contacted_adb_server": false,
    });
    finish(ctx, parameters(input), result, Vec::new(), None)
}

/// `inspectAvailability(...)` as a `ProviderAvailability` JSON value for the
/// binary-session owner's provider discovery. Never contacts devices.
pub fn availability(environment: &HashMap<String, String>) -> Value {
    let cancellation = Cancellation::with_static_reasons(&[]);
    match resolve_adb_binary(environment) {
        Err(failure) => configuration_availability(&failure),
        Ok(selection) => match inspect_adb_client(&selection, &cancellation) {
            Ok(_) => json!({
                "status": "available",
                "code": Value::Null,
                "reason": Value::Null,
                "diagnostics": {
                    "selected_binary": selection.binary,
                    "path_source": selection.path_source.as_str(),
                },
            }),
            Err(ClientProbeError::Configuration(failure)) => configuration_availability(&failure),
            Err(ClientProbeError::Analysis(error)) => {
                let mut diagnostics = Map::new();
                diagnostics.insert("probe_error".into(), json!(error.message()));
                json!({
                    "status": "unavailable",
                    "code": "version_unresolved",
                    "reason": error.message(),
                    "diagnostics": Value::Object(diagnostics),
                })
            }
        },
    }
}
