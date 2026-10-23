//! Bounded adb invocations and the exact failure shape REA consumes.
//!
//! Compatibility owner: `src/adb/AdbCommand.ts`. adb runs through the shared
//! owned-process launcher (`common::process::run_command`) with a per-stream
//! budget matching Node `execFile`'s `maxBuffer`. The launcher kills the owned
//! process group directly rather than SIGTERM-then-SIGKILL; see the family
//! report for that deviation.
use crate::adb::device_output::is_successful_daemon_start_notice;
use crate::adb::shell_output::package_change_failure_reason;
use crate::common::process::{
    CommandFailure, CommandLimits, CommandSpec, FailureKind, OutputBudget, RetainedChild,
    run_command,
};
use rea_core::analysis_error::{AnalysisError, CapturedOutput, ErrorKind};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, json};
use std::ffi::OsString;
use std::sync::OnceLock;
use std::time::Duration;

const STDERR_EXCERPT_CHARACTERS: usize = 512;

/// Match the known host operand in adb's local-file diagnostics.
const LOCAL_FILE_DIAGNOSTICS: &[(&str, &str)] = &[
    ("cannot create", ":"),
    ("cannot create file/directory", ":"),
    ("cannot stat", ":"),
    ("cannot open", ":"),
    ("cannot write", ":"),
    ("failed to stat local file", ":"),
    ("failed to read all of", ":"),
    ("failed to access", ":"),
    ("failed to stat", ":"),
    ("failed to open", ":"),
    ("opening", " locally failed:"),
    ("reading", " locally failed:"),
];

/// Per-command limits matching the TS `AdbRunLimits`.
#[derive(Clone, Copy, Debug)]
pub struct AdbRunLimits {
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
}

impl AdbRunLimits {
    fn command_limits(self) -> CommandLimits {
        CommandLimits {
            timeout: Duration::from_millis(self.timeout_ms),
            budget: OutputBudget::PerStream(self.max_output_bytes),
        }
    }
}

/// Keep the selected device separate from the file addressed by the command.
#[derive(Clone, Debug, Default)]
pub struct AdbCommandTarget {
    pub device: String,
    /// Caller-addressed file, such as a remote path or the original APK input.
    pub path: Option<String>,
    /// Exact host operand adb consumes, including an owned input snapshot.
    pub local_path: Option<String>,
}

/// A typed adb failure, keeping the retained child and (for exit failures) the
/// parsed command output so later owners can read a device verdict from it.
pub struct AdbCommandError {
    pub error: AnalysisError,
    /// Present only for a nonzero-exit failure (`AdbProtocolError`).
    pub exit_failure: Option<ExitFailure>,
    /// A child whose cleanup could not be confirmed, retained for retry.
    pub retained: Option<RetainedChild>,
}

/// The retained output of a nonzero-exit adb run (TS `AdbProtocolError`).
#[derive(Clone, Debug)]
pub struct ExitFailure {
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub exit_code: Option<i64>,
    pub truncated: bool,
    pub message: String,
}

impl AdbCommandError {
    fn plain(error: AnalysisError) -> Self {
        Self {
            error,
            exit_failure: None,
            retained: None,
        }
    }
}

/// `adbCommandCapturedOutput(failure)` for a nonzero-exit failure.
pub fn exit_captured_output(failure: &ExitFailure) -> CapturedOutput {
    CapturedOutput {
        stdout: failure.stdout.clone(),
        stderr: failure.stderr.clone(),
        truncated: failure.truncated,
        stdout_bytes: Some(failure.stdout_bytes),
        stderr_bytes: Some(failure.stderr_bytes),
        exit_code: Some(failure.exit_code),
        signal: Some(None),
    }
}

/// adb joins shell operands into a remote POSIX command; quote at that boundary.
fn quote_shell_operand(value: &str) -> String {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    let safe = RE.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9_./:=@+,-]+$").unwrap());
    if safe.is_match(value) {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// `adbArguments(serial, arguments)`.
pub fn adb_arguments(serial: Option<&str>, arguments: &[&str]) -> Vec<String> {
    let operands: Vec<String> = if arguments.first() == Some(&"shell") {
        let mut result = vec!["shell".to_owned()];
        result.extend(arguments[1..].iter().map(|arg| quote_shell_operand(arg)));
        result
    } else {
        arguments.iter().map(|arg| (*arg).to_owned()).collect()
    };
    match serial {
        None => operands,
        Some(serial) => {
            let mut result = vec!["-s".to_owned(), serial.to_owned()];
            result.extend(operands);
            result
        }
    }
}

/// Captured bytes of a successful run.
pub struct AdbCapture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_bytes: u64,
}

/// `runAdbCapture(...)`: run one bounded adb invocation and keep its exact
/// failure shape.
pub fn run_adb_capture(
    operation: &str,
    target: &AdbCommandTarget,
    binary: &str,
    arguments: &[String],
    limits: AdbRunLimits,
    cancellation: &Cancellation,
) -> Result<AdbCapture, AdbCommandError> {
    if cancellation.reason().is_some() {
        return Err(AdbCommandError::plain(AnalysisError::cancelled(operation)));
    }
    let args: Vec<OsString> = arguments.iter().map(OsString::from).collect();
    let spec = CommandSpec::new(binary, args);
    match run_command(&spec, limits.command_limits(), cancellation, false) {
        Ok(output) => Ok(AdbCapture {
            stdout_bytes: output.stdout.len() as u64,
            stdout: output.stdout,
            stderr: output.stderr,
        }),
        Err(failure) => Err(map_capture_failure(operation, target, limits, failure)),
    }
}

/// Decoded textual result of `runAdb(...)`.
pub struct AdbResult {
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: u64,
}

/// `runAdb(...)`: decode textual adb protocols after the byte boundary.
pub fn run_adb(
    operation: &str,
    target: &AdbCommandTarget,
    binary: &str,
    arguments: &[String],
    limits: AdbRunLimits,
    cancellation: &Cancellation,
) -> Result<AdbResult, AdbCommandError> {
    let captured = run_adb_capture(operation, target, binary, arguments, limits, cancellation)?;
    Ok(AdbResult {
        stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
        stdout_bytes: captured.stdout_bytes,
    })
}

fn map_capture_failure(
    operation: &str,
    target: &AdbCommandTarget,
    limits: AdbRunLimits,
    failure: CommandFailure,
) -> AdbCommandError {
    let retained = failure.retained;
    let output = failure.output;
    match failure.kind {
        FailureKind::Cancelled { .. } => {
            let mut error = AnalysisError::cancelled(operation);
            error.captured_output = Some(output.captured());
            AdbCommandError {
                error,
                exit_failure: None,
                retained,
            }
        }
        FailureKind::Launch { .. } | FailureKind::Collection { .. } | FailureKind::Settlement => {
            // `execFileOutputFailure` returns undefined for a spawn/collection
            // failure: the TS owner raises a bare AnalysisProtocolError.
            AdbCommandError {
                error: AnalysisError::protocol(format!("adb failed for {operation}")),
                exit_failure: None,
                retained,
            }
        }
        FailureKind::OutputLimit => {
            let error = AnalysisError::resource_constraint(
                operation,
                "memory",
                format!(
                    "adb output exceeded the {}-byte capture budget",
                    limits.max_output_bytes
                ),
                Some(json!({ "max_output_bytes": limits.max_output_bytes })),
            );
            AdbCommandError {
                error,
                exit_failure: None,
                retained,
            }
        }
        FailureKind::Timeout => {
            let error = AnalysisError::timeout(operation, limits.timeout_ms);
            AdbCommandError {
                error,
                exit_failure: None,
                retained,
            }
        }
        FailureKind::Exit => {
            let stdout = output.stdout_text();
            let stderr_full = output.stderr_text();
            classify_exit(operation, target, &stdout, &stderr_full, &output, retained)
        }
    }
}

fn classify_exit(
    operation: &str,
    target: &AdbCommandTarget,
    stdout: &str,
    stderr_full: &str,
    output: &crate::common::process::CommandOutput,
    retained: Option<RetainedChild>,
) -> AdbCommandError {
    let stderr = stderr_full.trim();
    let excerpt: String = stderr.chars().take(STDERR_EXCERPT_CHARACTERS).collect();
    let diagnostic = strip_diagnostic(stderr);

    if device_verdict_regex().is_match(&diagnostic) {
        return AdbCommandError::plain(AnalysisError::unsupported_target(
            operation,
            &target.device,
            excerpt,
        ));
    }
    if file_error_regex().is_match(&diagnostic) {
        let path = resolve_file_path(target, &diagnostic);
        return AdbCommandError::plain(AnalysisError::unsupported_target(operation, path, excerpt));
    }
    // The native launcher cannot report a signal-kill; a killed child becomes a
    // `FailureKind::Timeout`, so a nonzero exit here is a genuine adb failure.
    let message = if excerpt.is_empty() {
        format!(
            "adb exited with code {} for {operation}",
            output
                .exit_code
                .map_or_else(|| "unknown".to_owned(), |code| code.to_string())
        )
    } else {
        excerpt.clone()
    };
    let exit_failure = ExitFailure {
        stdout: stdout.to_owned(),
        stderr: stderr_full.to_owned(),
        stdout_bytes: output.stdout.len() as u64,
        stderr_bytes: output.stderr.len() as u64,
        exit_code: output.exit_code,
        truncated: output.truncated,
        message: message.clone(),
    };
    AdbCommandError {
        error: AnalysisError::protocol(message),
        exit_failure: Some(exit_failure),
        retained,
    }
}

fn strip_diagnostic(stderr: &str) -> String {
    // Only leading daemon notices need line parsing.
    let mut start = 0usize;
    while start < stderr.len() {
        let newline = stderr[start..].find('\n').map(|index| start + index);
        let line_end = newline.unwrap_or(stderr.len());
        let line = stderr[start..line_end].trim_end();
        if !is_successful_daemon_start_notice(line) && !daemon_not_running_regex().is_match(line) {
            break;
        }
        start = newline.map_or(stderr.len(), |index| index + 1);
    }
    let rest = &stderr[start..];
    strip_prefix_regex().replace(rest, "").into_owned()
}

fn resolve_file_path(target: &AdbCommandTarget, diagnostic: &str) -> String {
    if let Some(local_path) = &target.local_path {
        let matches = LOCAL_FILE_DIAGNOSTICS.iter().any(|(verb, suffix)| {
            [
                local_path.clone(),
                format!("'{local_path}'"),
                format!("\"{local_path}\""),
            ]
            .iter()
            .any(|operand| diagnostic.starts_with(&format!("{verb} {operand}{suffix}")))
        });
        if matches {
            return local_path.clone();
        }
    }
    target.path.clone().unwrap_or_else(|| target.device.clone())
}

fn device_verdict_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)^(?:unauthorized\b|device(?: '[^'\n]*')? (?:unauthorized\b|offline\b|not found\b|still authorizing\b)|still authorizing\b|more than one device\b)",
        )
        .unwrap()
    })
}

fn file_error_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)No such file or directory|Permission denied|read: Permission denied",
        )
        .unwrap()
    })
}

fn daemon_not_running_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"^\* daemon not running(?:; starting now at [^\r\n]*|\. starting it now on port \d+ \*)$",
        )
        .unwrap()
    })
}

fn strip_prefix_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r"(?i)^(?:adb:\s*)?(?:error:\s*)?(?:(?:failed to get feature set|connect failed):\s*)?",
        )
        .unwrap()
    })
}

/// `packageChangeRefusal(operation, serial, error)`.
pub fn package_change_refusal(
    operation: &str,
    serial: &str,
    error: &AdbCommandError,
) -> Option<AnalysisError> {
    let failure = error.exit_failure.as_ref()?;
    let combined = format!("{}\n{}", failure.stdout, failure.stderr);
    let reason = package_change_failure_reason(&combined)?;
    Some(AnalysisError::unsupported_target(operation, serial, reason))
}

/// `probeAdbPathExistence(...)`: only the clean false result of `test -e`
/// establishes absence.
pub fn probe_adb_path_existence(
    operation: &str,
    serial: &str,
    path: &str,
    binary: &str,
    limits: AdbRunLimits,
    cancellation: &Cancellation,
) -> Result<bool, AdbCommandError> {
    let target = AdbCommandTarget {
        device: serial.to_owned(),
        path: Some(path.to_owned()),
        local_path: None,
    };
    let arguments = adb_arguments(Some(serial), &["shell", "test", "-e", path]);
    match run_adb_capture(operation, &target, binary, &arguments, limits, cancellation) {
        Ok(captured) => {
            if captured.stdout.is_empty() && captured.stderr.is_empty() {
                return Ok(true);
            }
            let mut diagnostics = Map::new();
            diagnostics.insert("destination_existence".into(), json!("unknown"));
            let mut error = AnalysisError::protocol(
                "The ADB path existence probe returned unexpected output; destination existence is unknown",
            );
            error.diagnostics = Some(diagnostics);
            error.captured_output = Some(CapturedOutput {
                stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
                truncated: false,
                stdout_bytes: Some(captured.stdout.len() as u64),
                stderr_bytes: Some(captured.stderr.len() as u64),
                exit_code: Some(Some(0)),
                signal: Some(None),
            });
            Err(AdbCommandError::plain(error))
        }
        Err(command_error) => {
            let Some(exit) = command_error.exit_failure.as_ref() else {
                return Err(command_error);
            };
            // `test -e` returns exit code 1 with no output for a missing path.
            if exit.exit_code == Some(1)
                && !exit.truncated
                && exit.stdout.is_empty()
                && exit.stderr.is_empty()
            {
                return Ok(false);
            }
            let mut diagnostics = Map::new();
            diagnostics.insert("destination_existence".into(), json!("unknown"));
            let mut error = AnalysisError::from(ErrorKind::Protocol {
                message: exit.message.clone(),
            });
            error.diagnostics = Some(diagnostics);
            error.captured_output = Some(exit_captured_output(exit));
            Err(AdbCommandError {
                error,
                exit_failure: None,
                retained: command_error.retained,
            })
        }
    }
}
