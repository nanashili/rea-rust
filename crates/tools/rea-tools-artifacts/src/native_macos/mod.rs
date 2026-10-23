//! macOS native inspection tools (`native-macos` provider).
//!
//! Compatibility owners: `src/server/registerNativeTools.ts`,
//! `src/contracts/native/nativeToolContracts.ts`,
//! `src/native/NativeMacOSProvider.ts`, `src/native/CommandRunner.ts`,
//! `src/native/parsers/{lipo,demangle,echoedPath}.ts`,
//! `src/domain/native/nativeInspection.ts` and
//! `src/domain/swiftSymbolClassification.ts`.
//!
//! Every tool runs real host commands on the active target through the shared
//! allowlisted runner (`crate::native_command`), which resolves each tool with
//! `xcrun --find`, digests its executable for provenance and launches it
//! without a shell through the owned-process launcher.
use crate::common::{self, Execution, ProviderCall, native_macos_provider, run_provider_tool};
use crate::native_command::{
    self, CommandCleanup, FailureReason, NATIVE_COMMAND_OUTPUT_BUDGET_BYTES,
    NATIVE_COMMAND_TIMEOUT_MS, NativeCommandCapture, NativeCommandFailure,
};
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::{AnalysisError, CapturedOutput, ErrorKind};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::sync::Arc;

use crate::lipo;

#[cfg(feature = "native-macho")]
mod macho;
#[cfg(feature = "native-plist")]
mod plist;
#[cfg(feature = "native-signature")]
mod signature;

/// `NATIVE_MACOS_PROVIDER_IDENTITY.id`.
pub(crate) const IDENTITY_ID: &str = "native-macos";

/// Off-darwin capability message mirrored from `nativeMacOSCapabilities`.
const UNAVAILABLE_OFF_DARWIN: &str = "Native macOS utilities require macOS.";

/// Bind the native tools owned by this family.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle("demangle_swift", demangle_swift);
    registry.handle("list_architectures", list_architectures);
    #[cfg(feature = "native-macho")]
    macho::register(registry);
    #[cfg(feature = "native-plist")]
    plist::register(registry);
    #[cfg(feature = "native-signature")]
    signature::register(registry);
}

/// `nativeMacOSCapabilities(platform)`: every capability is unavailable off
/// darwin, so the route reports the exact TypeScript reason.
pub(crate) fn unavailable_reason() -> Option<&'static str> {
    if cfg!(target_os = "macos") {
        None
    } else {
        Some(UNAVAILABLE_OFF_DARWIN)
    }
}

/// Session-owned native command cleanup, registered once for shutdown retry.
pub(crate) fn command_cleanup(context: &ToolContext<'_>) -> Arc<CommandCleanup> {
    let cleanup = context.session.state::<CommandCleanup>();
    context.session.own_once(cleanup.clone());
    cleanup
}

/// Run one allowlisted tool for `operation`, translating failures exactly as
/// the provider (`#run` + `translateCommandFailure`).
pub(crate) fn run_tool(
    context: &ToolContext<'_>,
    operation: &str,
    tool: &str,
    arguments: &[String],
    accept_non_zero: bool,
) -> Result<NativeCommandCapture, AnalysisError> {
    let cleanup = command_cleanup(context);
    native_command::run(
        &cleanup,
        &context.cancellation,
        tool,
        arguments,
        accept_non_zero,
    )
    .map_err(|failure| translate_command_failure(operation, &failure))
}

/// `translateCommandFailure(operation, failure)`.
pub(crate) fn translate_command_failure(
    operation: &str,
    failure: &NativeCommandFailure,
) -> AnalysisError {
    let captured_output = failure.capture.as_ref().map(|capture| CapturedOutput {
        stdout: capture.stdout.clone(),
        stderr: capture.stderr.clone(),
        truncated: capture.truncated,
        stdout_bytes: Some(capture.stdout_bytes as u64),
        stderr_bytes: Some(capture.stderr_bytes as u64),
        exit_code: Some(capture.exit_code),
        signal: Some(capture.signal.clone()),
    });
    let attach = |mut error: AnalysisError| {
        if let Some(output) = &captured_output {
            error.captured_output = Some(output.clone());
        }
        if let Some(reason) = &failure.cleanup_failure {
            error = error.with_cleanup(reason.clone(), failure.cleanup_resources.clone());
        }
        error
    };
    match failure.reason {
        FailureReason::Unavailable => {
            let reason = format!("{} is unavailable through xcrun.", failure.tool);
            attach(
                AnalysisError::capability_unavailable(IDENTITY_ID, operation, reason.clone())
                    .with_user_message(reason),
            )
        }
        FailureReason::Cancelled => attach(AnalysisError::cancelled(operation)),
        FailureReason::Timeout => {
            attach(AnalysisError::timeout(operation, NATIVE_COMMAND_TIMEOUT_MS))
        }
        FailureReason::OutputLimit => attach(AnalysisError::resource_constraint(
            operation,
            "memory",
            format!(
                "Native command output exceeded {NATIVE_COMMAND_OUTPUT_BUDGET_BYTES} bytes; complete output is required for analysis."
            ),
            Some(json!({ "max_output_bytes": NATIVE_COMMAND_OUTPUT_BUDGET_BYTES })),
        )),
        FailureReason::NonzeroExit | FailureReason::Io => {
            let mut diagnostics = Map::new();
            diagnostics.insert("tool".into(), json!(failure.tool));
            diagnostics.insert("reason".into(), json!(failure.reason.as_str()));
            diagnostics.insert(
                "exit_code".into(),
                json!(
                    failure
                        .capture
                        .as_ref()
                        .map(|capture| capture.exit_code)
                        .unwrap_or(failure.exit_code)
                ),
            );
            diagnostics.insert(
                "signal".into(),
                json!(
                    failure
                        .capture
                        .as_ref()
                        .and_then(|capture| capture.signal.clone())
                ),
            );
            diagnostics.insert(
                "stdout_bytes".into(),
                json!(
                    failure
                        .capture
                        .as_ref()
                        .map_or(0, |capture| capture.stdout_bytes)
                ),
            );
            diagnostics.insert(
                "stderr_bytes".into(),
                json!(
                    failure
                        .capture
                        .as_ref()
                        .map_or(0, |capture| capture.stderr_bytes)
                ),
            );
            if let Some(detail) = &failure.detail {
                diagnostics.insert("detail".into(), json!(detail));
            }
            attach(
                AnalysisError::from(ErrorKind::ProviderAdapter {
                    provider_id: IDENTITY_ID.into(),
                    operation: operation.into(),
                    user_message: None,
                    remediation_action: None,
                })
                .with_diagnostics(diagnostics),
            )
        }
    }
}

/// `isMachOFormat` in `src/domain/binaryTargetTypes.ts`.
pub(crate) fn is_macho_format(format: &str) -> bool {
    format == "mach-o" || format == "mach-o-universal"
}

/// `demangle_swift`: `swift-demangle --compact -- <symbols...>`.
fn demangle_swift(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let evidence_parameters = input.clone();
    let execution_parameters = common::without_detail(&input);
    run_provider_tool(
        context,
        ProviderCall {
            execution_parameters,
            evidence_parameters,
            summary: false,
            unavailable: unavailable_reason(),
        },
        |target, parameters| execute_demangle(context, target, parameters),
    )
}

fn execute_demangle(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    parameters: &Map<String, Value>,
) -> Result<common::ProviderOutcome, AnalysisError> {
    // The provider maps a non-string-array `symbols` to AnalysisOutputError.
    let symbols = parameters
        .get("symbols")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .map(|item| item.as_str().map(ToOwned::to_owned))
                .collect::<Option<Vec<_>>>()
        })
        .ok_or_else(|| {
            AnalysisError::output("demangle_swift", "symbols were not parsed strings")
        })?;
    // `--` keeps symbols beginning with `-` from selecting demangler options.
    let mut arguments: Vec<String> = vec!["--compact".into(), "--".into()];
    arguments.extend(symbols.iter().cloned());
    let capture = run_tool(
        context,
        "demangle_swift",
        "swift-demangle",
        &arguments,
        false,
    )?;
    let provenance = json!([native_command::invocation(
        &capture,
        &target.path,
        "$ARTIFACT"
    )]);
    let result = rea_application::native::swift_demangle::result(
        &symbols,
        &capture.stdout,
        provenance,
        Vec::new(),
    )
    .map_err(|reason| AnalysisError::output("demangle_swift", reason))?;
    Ok(Execution::new(result, native_macos_provider()).into())
}

/// `list_architectures`: `lipo -detailed_info <path>`.
fn list_architectures(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let evidence_parameters = input.clone();
    let execution_parameters = common::without_detail(&input);
    run_provider_tool(
        context,
        ProviderCall {
            execution_parameters,
            evidence_parameters,
            summary: false,
            unavailable: unavailable_reason(),
        },
        |target, _parameters| execute_list_architectures(context, target),
    )
}

fn execute_list_architectures(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
) -> Result<common::ProviderOutcome, AnalysisError> {
    // lipo reads only Mach-O; a PE/ELF/plist refusal is not a repairable tool
    // failure, so it is a capability-unavailable verdict.
    if !is_macho_format(&target.format) {
        return Err(AnalysisError::capability_unavailable(
            IDENTITY_ID,
            "list_architectures",
            "Active artifact is not Mach-O.",
        ));
    }
    let arguments = ["-detailed_info".to_owned(), target.path.clone()];
    let capture = run_tool(context, "list_architectures", "lipo", &arguments, false)?;
    let provenance = json!([native_command::invocation(
        &capture,
        &target.path,
        "$ARTIFACT"
    )]);
    let parsed = lipo::parse_lipo_output(&capture.stdout, Some(&target.path))
        .map_err(|reason| AnalysisError::output("list_architectures", reason))?;
    let items: Vec<Value> = parsed
        .architectures
        .iter()
        .map(lipo::LipoArchitecture::to_value)
        .collect();
    let total = items.len();
    let result = json!({
        "architectures": {
            "items": items,
            "total": total,
            "exhaustive": true,
            "limitations": [],
        },
        "provenance": provenance,
        "limitations": [],
    });
    let mut execution = Execution::new(result, native_macos_provider());
    execution.locations = architecture_locations(&parsed.architectures);
    Ok(execution.into())
}

/// `architectureLocations` in `src/native/NativeMachoInspection.ts`.
pub(crate) fn architecture_locations(architectures: &[lipo::LipoArchitecture]) -> Vec<Value> {
    let mut locations = Vec::new();
    for architecture in architectures {
        let Some(offset) = architecture.file_offset else {
            continue;
        };
        match architecture.size {
            None => locations.push(json!({ "kind": "file-offset", "offset": offset })),
            Some(size) => locations.push(json!({
                "kind": "file-offset-range",
                "start": offset,
                "end": offset + size,
            })),
        }
    }
    locations
}
