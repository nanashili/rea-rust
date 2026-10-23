//! Resolve, launch and verify one bounded firmware provider command.
//!
//! Compatibility owner: `src/firmware/FirmwareCommand.ts`. `resolveFirmwareCommand`
//! is Linux-only with exact capability messages; `runFirmwareCommand` launches the
//! tool under util-linux `prlimit`, polls every 100 ms, enforces the diagnostic
//! budget, deadline, cancellation and the periodic output inventory, then stops
//! with verified group cleanup.
use super::deadline::OperationDeadline;
use super::files;
use super::release::FIRMWARE_LIMITS;
use super::version::Engine;
use crate::errors::{self, map};
use crate::node::{self, AccessMode};
use crate::process::{OwnedProcess, ProcessSpec, StopResult};
use crate::resources::{AnalysisResources, RootId};
use rea_core::analysis_error::{AnalysisError, CapturedOutput, ErrorKind};
use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::time::Duration;
/// `firmwareToolUnavailable`.
pub fn tool_unavailable(
    engine: Engine,
    operation: &str,
    reason: impl Into<String>,
) -> AnalysisError {
    let reason = reason.into();
    AnalysisError::capability_unavailable(engine.id(), operation, reason.clone())
        .with_user_message(reason)
}
/// Resolved executable + limiter for one engine.
pub struct ResolvedCommand {
    pub command: String,
    pub limiter: String,
    pub sha256: String,
}
enum ReadableError {
    Read(crate::artifact::ReadError),
    NotRegular,
    Fs(crate::node::FsError),
}
/// `resolveFirmwareCommand`: resolve explicitly supplied executable paths.
pub fn resolve_command(
    environment: &HashMap<String, String>,
    engine: Engine,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<ResolvedCommand, AnalysisError> {
    let variable = match engine {
        Engine::Binwalk => "REA_BINWALK_COMMAND",
        Engine::Unblob => "REA_UNBLOB_COMMAND",
    };
    let configured = environment.get(variable).map(String::as_str);
    if !cfg!(target_os = "linux") || configured.is_none_or(|value| !node::is_absolute(value)) {
        return Err(tool_unavailable(
            engine,
            operation,
            format!(
                "This integration requires Linux and an absolute {variable} path to the caller-supplied tool"
            ),
        ));
    }
    let configured = configured.expect("configured present");
    let command = node::realpath(configured).map_err(|error| {
        tool_unavailable(
            engine,
            operation,
            format!("{variable} is unavailable: {}", error.message),
        )
    })?;
    let sha256 = (|| -> Result<String, ReadableError> {
        node::access(&command, AccessMode::ReadExecute).map_err(ReadableError::Fs)?;
        if !node::stat_is_file(&command).map_err(ReadableError::Fs)? {
            return Err(ReadableError::NotRegular);
        }
        files::hash(&command, cancellation).map_err(ReadableError::Read)
    })()
    .map_err(|error| match error {
        ReadableError::Read(read) if read.reader_reason() == Some(crate::artifact::ReaderReason::Cancelled) => {
            AnalysisError::cancelled(operation)
        }
        ReadableError::Read(read) => tool_unavailable(
            engine,
            operation,
            format!("{variable} is not a readable executable regular file: {command}: {}", read.message()),
        ),
        ReadableError::NotRegular => tool_unavailable(
            engine,
            operation,
            format!("{variable} is not a readable executable regular file: {command}: Configured path is not a regular file"),
        ),
        ReadableError::Fs(fs) => tool_unavailable(
            engine,
            operation,
            format!("{variable} is not a readable executable regular file: {command}: {}", fs.message),
        ),
    })?;
    let limiter = environment
        .get("REA_FIRMWARE_PRLIMIT_COMMAND")
        .cloned()
        .unwrap_or_else(|| "/usr/bin/prlimit".to_owned());
    if !node::is_absolute(&limiter) {
        return Err(tool_unavailable(
            engine,
            operation,
            "REA_FIRMWARE_PRLIMIT_COMMAND must be absolute",
        ));
    }
    (|| -> Result<(), crate::node::FsError> {
        node::access(&limiter, AccessMode::Execute)?;
        if !node::stat_is_file(&limiter)? {
            return Err(crate::node::FsError::plain("Configured path is not a regular file"));
        }
        Ok(())
    })()
    .map_err(|error| {
        tool_unavailable(
            engine,
            operation,
            format!(
                "Resource limiter is not an executable regular file: {limiter}: {}; provide util-linux prlimit",
                error.message
            ),
        )
    })?;
    Ok(ResolvedCommand {
        command,
        limiter,
        sha256,
    })
}
/// The streams observed from one completed command.
#[derive(Clone, Debug)]
pub struct CommandStream {
    pub text: String,
    pub bytes: usize,
}
/// The outcome of `runFirmwareCommand`.
#[derive(Clone, Debug)]
pub struct CommandExecution {
    pub stdout: CommandStream,
    pub stderr: CommandStream,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub command: String,
    pub args: Vec<String>,
    pub resource_limiter: String,
}
impl CommandExecution {
    /// `{ stdout, stderr, exit_code, signal, command, args, resource_limiter }`.
    pub fn to_value(&self) -> Value {
        errors::object([
            ("stdout", stream_value(&self.stdout)),
            ("stderr", stream_value(&self.stderr)),
            ("exit_code", json!(self.exit_code)),
            ("signal", json!(self.signal)),
            ("command", json!(self.command)),
            ("args", json!(self.args)),
            ("resource_limiter", json!(self.resource_limiter)),
        ])
    }
}
fn stream_value(stream: &CommandStream) -> Value {
    errors::object([("text", json!(stream.text)), ("bytes", json!(stream.bytes))])
}
/// Caller-provided output budget polled during extraction.
pub struct OutputBudget {
    pub root: String,
    pub bytes: u64,
    pub entries: u64,
}
/// Parameters for one `runFirmwareCommand` invocation.
pub struct RunContext<'a> {
    pub engine: Engine,
    pub operation: &'a str,
    pub command: &'a str,
    pub limiter: &'a str,
    pub args: Vec<String>,
    pub cwd: String,
    pub environment: &'a HashMap<String, String>,
    pub cancellation: &'a Cancellation,
    /// One operation-wide deadline shared by every command launch.
    pub deadline: &'a OperationDeadline<'a>,
    pub resources: &'a AnalysisResources,
    /// Retained root this command's owner is attached to on incomplete stop.
    pub root: RootId,
    pub output_budget: Option<OutputBudget>,
    pub accept_reported_extraction_failure: bool,
}
/// `runFirmwareCommand`.
pub fn run(context: &RunContext<'_>) -> Result<CommandExecution, AnalysisError> {
    let engine = context.engine;
    let operation = context.operation;
    if context.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(operation));
    }
    let run_id = format!("rea-firmware-{}", node::random_uuid());
    let fsize = context
        .output_budget
        .as_ref()
        .map_or(FIRMWARE_LIMITS.report_bytes, |budget| budget.bytes);
    let mut argv = vec![
        format!("--as={}", FIRMWARE_LIMITS.address_space_bytes),
        format!("--fsize={fsize}"),
        "--core=0".to_owned(),
        "--cpu=120".to_owned(),
        "--".to_owned(),
        context.command.to_owned(),
    ];
    argv.extend(context.args.iter().cloned());
    let overrides = [
        ("TMPDIR", context.cwd.as_str()),
        ("OMP_NUM_THREADS", "1"),
        ("OPENBLAS_NUM_THREADS", "1"),
        ("RAYON_NUM_THREADS", "1"),
        ("NO_COLOR", "1"),
    ];
    let spec = ProcessSpec::new(
        context.limiter.to_owned(),
        argv,
        Some(context.cwd.clone()),
        context.environment,
        &overrides,
        run_id.clone(),
    );
    let mut owned =
        OwnedProcess::spawn(&spec, Some(FIRMWARE_LIMITS.diagnostic_bytes)).map_err(|failure| {
            errors::provider_adapter(
                engine.id(),
                operation,
                Some(map([("reason", json!(failure.message))])),
                None,
            )
        })?;
    // The deadline is the shared operation-wide budget, not a fresh per-command
    // timer: the version launch and the main launch draw down the same 120s.
    let mut failure: Option<AnalysisError> = None;
    loop {
        if owned.wait_for_output_close(Duration::from_millis(100)) {
            break;
        }
        if let Some(error) = check_diagnostics(&mut owned, operation) {
            failure = Some(error);
            break;
        }
        if context.cancellation.reason().is_some() {
            failure = Some(AnalysisError::cancelled(operation));
            break;
        }
        if context.deadline.expired() {
            failure = Some(AnalysisError::timeout(
                operation,
                FIRMWARE_LIMITS.timeout_ms,
            ));
            break;
        }
        if let Some(budget) = &context.output_budget {
            if let Err(error) = files::inventory(
                &budget.root,
                budget.bytes,
                budget.entries,
                operation,
                context.cancellation,
            ) {
                failure = Some(error);
                break;
            }
        }
    }
    if failure.is_none() {
        if let Some(error) = check_diagnostics(&mut owned, operation) {
            failure = Some(error);
        } else if context.cancellation.reason().is_some() {
            failure = Some(AnalysisError::cancelled(operation));
        }
    }
    // The leader pid equals the process group id on POSIX (the group is created
    // at spawn), so record both from `OwnedProcess::pid()` the way
    // `spawned.ownership` reported them, before the owner is retained for retry.
    let leader_pid = owned.pid();
    let stopped = owned.stop();
    let snapshot = owned.snapshot();
    if let StopResult::Incomplete { reason } = stopped {
        // Retain the owner against its root for session-close retry.
        context.resources.retain_owner(context.root, owned);
        let diagnostics = map([
            ("reason", json!(reason)),
            ("leader_pid", json!(leader_pid)),
            ("process_group_id", json!(leader_pid)),
            ("exit_code", json!(snapshot.exit_code)),
            ("signal", json!(snapshot.signal)),
            ("stdout", json!(snapshot.stdout.text)),
            ("stderr", json!(snapshot.stderr.text)),
            ("stdout_bytes", json!(snapshot.stdout.bytes)),
            ("stderr_bytes", json!(snapshot.stderr.bytes)),
            (
                "previous_error",
                failure
                    .as_ref()
                    .map_or(Value::Null, |error| json!(error.message())),
            ),
        ]);
        return Err(errors::provider_cleanup(
            engine.id(),
            vec![run_id, context.cwd.clone()],
            diagnostics,
            operation,
        ));
    }
    if let Some(failure) = failure {
        return Err(failure);
    }
    let exit_code = snapshot.exit_code;
    let accept_exit_one = context.accept_reported_extraction_failure && exit_code == Some(1);
    if exit_code != Some(0) && !accept_exit_one {
        return Err(errors::provider_adapter(
            engine.id(),
            operation,
            Some(map([
                (
                    "reason",
                    json!(
                        "Tool failed; inspect exit status and stderr for format, dependency, sandbox or resource-limit failures"
                    ),
                ),
                ("exit_code", json!(exit_code)),
                ("signal", json!(snapshot.signal)),
                ("stdout", json!(snapshot.stdout.text)),
                ("stderr", json!(snapshot.stderr.text)),
                ("stdout_bytes", json!(snapshot.stdout.bytes)),
                ("stderr_bytes", json!(snapshot.stderr.bytes)),
            ])),
            None,
        ));
    }
    Ok(CommandExecution {
        stdout: CommandStream {
            text: snapshot.stdout.text.clone(),
            bytes: snapshot.stdout.bytes,
        },
        stderr: CommandStream {
            text: snapshot.stderr.text.clone(),
            bytes: snapshot.stderr.bytes,
        },
        exit_code,
        signal: snapshot.signal.clone(),
        command: context.command.to_owned(),
        args: context.args.clone(),
        resource_limiter: context.limiter.to_owned(),
    })
}
/// `checkDiagnostics`: fail when retained diagnostics overflowed the budget.
fn check_diagnostics(owned: &mut OwnedProcess, operation: &str) -> Option<AnalysisError> {
    if owned.diagnostic_truncated() {
        let snapshot = owned.snapshot();
        let captured = CapturedOutput {
            stdout: snapshot.stdout.text.clone(),
            stderr: snapshot.stderr.text.clone(),
            truncated: true,
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        };
        return Some(
            AnalysisError::output(
                operation,
                format!(
                    "Tool diagnostics exceeded the {}-byte capture budget",
                    FIRMWARE_LIMITS.diagnostic_bytes
                ),
            )
            .with_captured_output(captured),
        );
    }
    None
}
/// `readFirmwareCommandReport`: preserve diagnostics on an accepted exit 1.
pub fn read_report(
    path: &str,
    engine: Engine,
    operation: &str,
    execution: &CommandExecution,
    cancellation: &Cancellation,
) -> Result<Value, AnalysisError> {
    match files::report(path, operation, cancellation) {
        Ok(value) => Ok(value),
        Err(error) => {
            if matches!(error.kind, ErrorKind::Cancelled { .. }) {
                return Err(error);
            }
            if execution.exit_code == Some(1) {
                return Err(errors::provider_adapter(
                    engine.id(),
                    operation,
                    Some(map([
                        (
                            "reason",
                            json!(
                                "Tool exited 1 without a usable analysis report; inspect stderr for startup, sandbox or dependency failures"
                            ),
                        ),
                        ("report_failure", json!(error.message())),
                        ("exit_code", json!(1)),
                        ("signal", json!(execution.signal)),
                        ("stdout", json!(execution.stdout.text)),
                        ("stderr", json!(execution.stderr.text)),
                        ("stdout_bytes", json!(execution.stdout.bytes)),
                        ("stderr_bytes", json!(execution.stderr.bytes)),
                    ])),
                    None,
                ));
            }
            let diagnostics = format!(
                "stdout ({} bytes): {}; stderr ({} bytes): {}",
                execution.stdout.bytes,
                execution.stdout.text,
                execution.stderr.bytes,
                execution.stderr.text
            );
            if matches!(error.kind, ErrorKind::Output { .. }) {
                let reason = error.message();
                return Err(AnalysisError::output(
                    operation,
                    format!("{reason}; {diagnostics}"),
                ));
            }
            Err(AnalysisError::output(
                operation,
                format!("Tool did not produce the expected complete report: {path}; {diagnostics}"),
            ))
        }
    }
}
