//! Owned process execution shared by version probes and capture reads.
//!
//! Compatibility owner: `src/pcap/PcapCommand.ts`. Each command runs in an
//! owned process group (Windows: a Job Object), optionally wrapped by a Linux
//! prlimit limiter, with the host environment plus `LC_ALL=C`/`LANG=C`.
//! Failures are classified into the same typed analysis errors.
use crate::pcap::configuration::tool_unavailable;
use crate::pcap::native_bound::NativeBound;
use crate::pcap::windows_batch::is_windows_batch_file;
#[cfg(windows)]
use crate::pcap::windows_batch::windows_batch_command;
use crate::process::{
    self, CommandError, CommandLimits, FailureReason, OwnedProcess, ProcessSnapshot, ProcessSpec,
    StopResult,
};
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use std::collections::HashMap;

/// Retained cleanup observation for an owned command that could not be stopped.
#[derive(Clone, Debug)]
pub struct CommandCleanup {
    pub reason: String,
    pub resources: Vec<String>,
    pub captured_truncated: bool,
}

/// One owned command whose cleanup remains unconfirmed.
pub struct RetainedCommand {
    pub owner: OwnedProcess,
    pub cleanup: CommandCleanup,
}

/// Successful or cleanup-bearing command output.
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub cleanup: Option<CommandCleanup>,
}

/// Per-command limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

/// Inputs to one owned command run.
pub struct RunOptions<'a> {
    pub operation: &'a str,
    pub command: String,
    pub arguments: Vec<String>,
    pub limits: Limits,
    /// Session environment snapshot (`process.env` in the original).
    pub environment: &'a HashMap<String, String>,
    /// Private configuration directory applied as `WIRESHARK_CONFIG_DIR`.
    pub config_dir: Option<String>,
    pub cancellation: &'a Cancellation,
    pub input_path: Option<String>,
    pub native_bound: Option<&'a NativeBound>,
    pub cwd: Option<String>,
}

fn truncated(snapshot: &ProcessSnapshot) -> bool {
    snapshot.diagnostic_truncated || snapshot.output_incomplete
}

/// `runPcapCommand`: launch, collect bounded output, classify failures.
///
/// A retained owner whose cleanup could not be confirmed is placed in
/// `retained`; the provider stores it for later retry.
pub fn run_pcap_command(
    options: RunOptions<'_>,
    retained: &mut Option<RetainedCommand>,
) -> Result<CommandOutput, AnalysisError> {
    let operation = options.operation;
    if options.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }

    // Host environment overrides: WIRESHARK_CONFIG_DIR, then LC_ALL/LANG=C.
    let mut overrides: Vec<(String, String)> = Vec::new();
    if let Some(config_dir) = &options.config_dir {
        overrides.push(("WIRESHARK_CONFIG_DIR".to_owned(), config_dir.clone()));
    }
    overrides.push(("LC_ALL".to_owned(), "C".to_owned()));
    overrides.push(("LANG".to_owned(), "C".to_owned()));

    // Windows batch-file invocation through cmd.exe.
    let (mut exec_command, mut exec_arguments) =
        (options.command.clone(), options.arguments.clone());
    #[cfg(windows)]
    if is_windows_batch_file(&options.command) {
        match windows_batch_command(options.environment, &options.command, &options.arguments) {
            Ok(batch) => {
                exec_command = batch.command;
                exec_arguments = batch.arguments;
            }
            Err(error) => {
                return Err(tool_unavailable(
                    operation,
                    &format!(
                        "Cannot run selected tool {}: {}",
                        options.command, error.message
                    ),
                ));
            }
        }
    }
    #[cfg(not(windows))]
    let _ = is_windows_batch_file(&options.command);

    // Linux prlimit limiter wrapping.
    if let Some(bound) = options.native_bound
        && let Some((limiter, limiter_arguments)) = &bound.limiter
    {
        let mut wrapped = limiter_arguments.clone();
        wrapped.push(exec_command.clone());
        wrapped.append(&mut exec_arguments);
        exec_command = limiter.clone();
        exec_arguments = wrapped;
    }

    let override_refs: Vec<(&str, &str)> = overrides
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect();
    let mut spec = ProcessSpec::new(
        exec_command,
        exec_arguments,
        options.cwd.clone(),
        options.environment,
        &override_refs,
        process::run_id("rea-pcap-"),
    );
    if let Some(bound) = options.native_bound {
        spec.memory_limit_bytes = bound.memory_limit_bytes;
    }

    let mut local_cleanup: Option<CommandCleanup> = None;
    let cwd = options.cwd.clone();
    let mut retain = |owner: OwnedProcess, reason: String| {
        let mut owner = owner;
        let resources = owner.resources(cwd.as_deref());
        let snapshot = owner.snapshot();
        let cleanup = CommandCleanup {
            reason,
            resources,
            captured_truncated: truncated(&snapshot),
        };
        local_cleanup = Some(cleanup.clone());
        *retained = Some(RetainedCommand { owner, cleanup });
    };

    let outcome = process::run_owned_command(
        &spec,
        CommandLimits {
            timeout_ms: options.limits.timeout_ms,
            diagnostic_bytes: options.limits.max_output_bytes,
            accept_nonzero_exit: false,
        },
        options.cancellation,
        Some(&mut retain),
    );

    match outcome {
        Ok(snapshot) => Ok(CommandOutput {
            stdout: snapshot.stdout.text,
            stderr: snapshot.stderr.text,
            cleanup: local_cleanup,
        }),
        Err(error) => Err(classify_failure(&options, error, retained)),
    }
}

fn classify_failure(
    options: &RunOptions<'_>,
    error: CommandError,
    retained: &mut Option<RetainedCommand>,
) -> AnalysisError {
    let operation = options.operation;
    let command = &options.command;
    let timeout_ms = options.limits.timeout_ms;
    let max_output_bytes = options.limits.max_output_bytes;

    match error {
        CommandError::Launch(failure) => {
            if options.cancellation.reason().is_some() {
                return AnalysisError::cancelled(operation);
            }
            if matches!(failure.code, Some("ENOENT" | "EACCES")) {
                return tool_unavailable(
                    operation,
                    &format!("Cannot run selected tool {command}: {}", failure.message),
                );
            }
            classify_diagnostic_with(options, &failure.message, None)
        }
        CommandError::Failed(failure) => {
            let failure = *failure;
            let snapshot = failure.snapshot.clone();

            if let Some(owner) = failure.cleanup_owner {
                let reason = failure
                    .cleanup_failure
                    .clone()
                    .unwrap_or_else(|| failure.message.clone());
                let is_truncated = snapshot.as_ref().map_or(true, truncated);
                *retained = Some(RetainedCommand {
                    owner,
                    cleanup: CommandCleanup {
                        reason,
                        resources: failure.resources.clone(),
                        captured_truncated: is_truncated,
                    },
                });
            }

            let captured = snapshot.as_ref().map(crate::errors::captured_from);
            let with =
                |analysis: AnalysisError| crate::errors::with_output(analysis, captured.as_ref());

            if options.cancellation.reason().is_some() || failure.reason == FailureReason::Cancelled
            {
                return with(AnalysisError::cancelled(operation));
            }
            if snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.memory_limit_reached)
            {
                return with(AnalysisError::resource_constraint(
                    operation,
                    "memory",
                    "The owned Windows tool tree reached its enforced committed-memory limit.",
                    Some(serde_json::json!({
                        "process_memory_limit_bytes": options
                            .native_bound
                            .and_then(|bound| bound.memory_limit_bytes)
                    })),
                ));
            }
            if let Some(signal) = snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.signal.as_deref())
                && matches!(signal, "SIGXCPU" | "SIGXFSZ")
            {
                return with(AnalysisError::resource_constraint(
                    operation,
                    if signal == "SIGXCPU" {
                        "cpu"
                    } else {
                        "file-size"
                    },
                    format!(
                        "Producer terminated with {signal}; its exact cause is not independently established."
                    ),
                    None,
                ));
            }
            if failure.reason == FailureReason::Timeout {
                return with(AnalysisError::timeout(operation, timeout_ms));
            }
            if failure.reason == FailureReason::OutputLimit {
                return with(AnalysisError::resource_constraint(
                    operation,
                    "memory",
                    "Tool output exceeded its complete-output budget",
                    Some(serde_json::json!({ "max_output_bytes": max_output_bytes })),
                ));
            }

            let diagnostic = snapshot
                .as_ref()
                .map(|snapshot| snapshot.stderr.text.trim())
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .unwrap_or_else(|| failure.message.clone());
            classify_diagnostic_with(options, &diagnostic, captured.as_ref())
        }
    }
}

/// Classify a diagnostic string, attaching captured output when present.
fn classify_diagnostic_with(
    options: &RunOptions<'_>,
    diagnostic: &str,
    captured: Option<&rea_core::analysis_error::CapturedOutput>,
) -> AnalysisError {
    let operation = options.operation;
    let command = &options.command;
    let with = |analysis: AnalysisError| crate::errors::with_output(analysis, captured);
    match &options.input_path {
        None => with(tool_unavailable(
            operation,
            &format!("The selected tool {command} cannot report its version: {diagnostic}"),
        )),
        Some(path) => {
            if is_unsupported_capture(diagnostic) {
                with(AnalysisError::unsupported_target(
                    operation, path, diagnostic,
                ))
            } else {
                with(AnalysisError::protocol(format!(
                    "Packet capture tool {command} failed: {diagnostic}"
                )))
            }
        }
    }
}

/// `/not a capture file|file.*isn't a capture file|file format.*not supported/iu`.
fn is_unsupported_capture(diagnostic: &str) -> bool {
    let lower = diagnostic.to_lowercase();
    lower.contains("not a capture file")
        || lower
            .find("file")
            .is_some_and(|start| lower[start..].contains("isn't a capture file"))
        || lower
            .find("file format")
            .is_some_and(|start| lower[start..].contains("not supported"))
}

/// Stop a retained command owner, mirroring the provider close path.
pub fn stop_retained(retained: &mut RetainedCommand) -> StopResult {
    retained.owner.stop()
}
