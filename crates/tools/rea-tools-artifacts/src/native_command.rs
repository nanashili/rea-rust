//! Allowlisted native host commands run without a shell.
//!
//! Compatibility owners: `src/native/CommandRunner.ts` (`XcrunCommandRunner`,
//! `resolveXcrunTool`, `captureProcess`, `failureCapture`) and
//! `src/process/OwnedCommand.ts` (`runOwnedCommand` failure reasons).
//!
//! Every child is launched through `rea_host::process::launcher` (owned process
//! group). The original composes the child environment as the host snapshot
//! plus `LC_ALL=C` and `LANG=C`; the shared launcher has no environment
//! parameter, so the child is started through `/usr/bin/env LC_ALL=C LANG=C`,
//! which `exec`s the selected tool in the same owned process with the exact
//! remaining argv.
#![allow(dead_code)]
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess, ProcessLaunchError};
use rea_host::process::windows::job::WindowsJobLimits;
use rea_mcp::SessionResource;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `NATIVE_COMMAND_TIMEOUT_MS`.
pub(crate) const NATIVE_COMMAND_TIMEOUT_MS: u64 = 60_000;
/// `NATIVE_COMMAND_OUTPUT_BUDGET_BYTES` (aggregate stdout + stderr).
pub(crate) const NATIVE_COMMAND_OUTPUT_BUDGET_BYTES: usize = 64 * 1024 * 1024;
/// `NATIVE_FAILURE_DIAGNOSTIC_BYTES` (per-stream excerpt on failure).
pub(crate) const NATIVE_FAILURE_DIAGNOSTIC_BYTES: usize = 64 * 1024;

/// `ALLOWED_TOOLS`.
const ALLOWED_TOOLS: &[&str] = &[
    "codesign",
    "dyld_info",
    "dwarfdump",
    "file",
    "lipo",
    "nm",
    "otool",
    "plutil",
    "strings",
    "swift-demangle",
    "vtool",
];

/// The fixed `versionReason` recorded for every resolved tool.
pub(crate) const VERSION_REASON: &str = "Tool exposes no uniform stable version flag; executable SHA-256 is a prelaunch file sample and does not prove atomic OS image binding.";

/// Host utility used to apply the original child locale overrides.
const ENV_UTILITY: &str = "/usr/bin/env";

/// One completed allowlisted command (`NativeCommandCapture`).
#[derive(Clone, Debug)]
pub(crate) struct NativeCommandCapture {
    pub tool: String,
    pub executable: String,
    pub executable_sha256: String,
    /// Always unresolved: tools expose no uniform version flag.
    pub tool_version: Option<String>,
    pub version_reason: Option<String>,
    pub arguments: Vec<String>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
}

/// Output observed from one child (`ProcessCapture`).
#[derive(Clone, Debug)]
pub(crate) struct ProcessCapture {
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
}

/// `NativeCommandFailure.reason`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureReason {
    Unavailable,
    Cancelled,
    Timeout,
    OutputLimit,
    NonzeroExit,
    Io,
}

impl FailureReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Cancelled => "cancelled",
            Self::Timeout => "timeout",
            Self::OutputLimit => "output-limit",
            Self::NonzeroExit => "nonzero-exit",
            Self::Io => "io",
        }
    }
}

/// Bounded failure diagnostics (`NativeCommandFailureCapture`).
#[derive(Clone, Debug)]
pub(crate) struct FailureCapture {
    pub stdout: String,
    pub stderr: String,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub exit_code: Option<i64>,
    pub signal: Option<String>,
    pub truncated: bool,
}

/// One failed native command (`NativeCommandFailure`).
#[derive(Clone, Debug)]
pub(crate) struct NativeCommandFailure {
    pub tool: String,
    pub reason: FailureReason,
    pub exit_code: Option<i64>,
    pub capture: Option<FailureCapture>,
    /// Cleanup that could not be confirmed for this command's process group.
    pub cleanup_failure: Option<String>,
    pub cleanup_resources: Vec<String>,
    /// Host-side detail, such as a launch or digest failure.
    pub detail: Option<String>,
}

impl NativeCommandFailure {
    pub(crate) fn new(tool: &str, reason: FailureReason) -> Self {
        Self {
            tool: tool.to_owned(),
            reason,
            exit_code: None,
            capture: None,
            cleanup_failure: None,
            cleanup_resources: Vec::new(),
            detail: None,
        }
    }

    fn with_capture(mut self, capture: FailureCapture) -> Self {
        self.exit_code = capture.exit_code;
        self.capture = Some(capture);
        self
    }

    fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Owned children whose process-group cleanup could not be confirmed. The
/// original runner retries them before every launch and refuses to start
/// another command while any remains (`#runAfterCleanup`).
#[derive(Default)]
pub(crate) struct CommandCleanup {
    pending: Mutex<Vec<(Vec<String>, OwnedChildProcess)>>,
}

impl CommandCleanup {
    /// Retry every retained owner; return the failures that remain.
    fn retry(&self) -> Vec<(String, Vec<String>)> {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut failures = Vec::new();
        pending.retain_mut(|(resources, child)| match child.retry_cleanup(1) {
            Ok(()) => false,
            Err(error) => {
                failures.push((error.to_string(), resources.clone()));
                true
            }
        });
        failures
    }

    fn retain(&self, resources: Vec<String>, child: OwnedChildProcess) {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push((resources, child));
    }
}

impl SessionResource for CommandCleanup {
    fn close(&self) -> Result<(), AnalysisError> {
        let failures = self.retry();
        if failures.is_empty() {
            return Ok(());
        }
        let resources = failures
            .iter()
            .flat_map(|(_, resources)| resources.clone())
            .collect::<Vec<_>>();
        let reason = failures
            .iter()
            .map(|(reason, resources)| format!("{}: {reason}", resources.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        Err(
            AnalysisError::provider_adapter("native-macos", "close_binary")
                .with_cleanup(reason, resources),
        )
    }
}

/// Run one allowlisted tool (`XcrunCommandRunner.run`).
pub(crate) fn run(
    cleanup: &CommandCleanup,
    cancellation: &Cancellation,
    tool: &str,
    arguments: &[String],
    accept_non_zero: bool,
) -> Result<NativeCommandCapture, NativeCommandFailure> {
    if !ALLOWED_TOOLS.contains(&tool) {
        return Err(NativeCommandFailure::new(tool, FailureReason::Unavailable));
    }
    let pending = cleanup.retry();
    if !pending.is_empty() {
        let mut failure = NativeCommandFailure::new(tool, FailureReason::Io);
        failure.cleanup_failure = Some(
            pending
                .iter()
                .map(|(reason, resources)| format!("{}: {reason}", resources.join(", ")))
                .collect::<Vec<_>>()
                .join("; "),
        );
        let mut resources = Vec::new();
        for (_, owned) in &pending {
            for resource in owned {
                if !resources.contains(resource) {
                    resources.push(resource.clone());
                }
            }
        }
        failure.cleanup_resources = resources;
        return Err(failure);
    }
    let resolved = resolve_xcrun_tool(cleanup, cancellation, tool)?;
    let captured = capture_process(
        cleanup,
        cancellation,
        &resolved.path,
        arguments,
        tool,
        accept_non_zero,
    )?;
    Ok(NativeCommandCapture {
        tool: tool.to_owned(),
        executable: resolved.path,
        executable_sha256: resolved.sha256,
        tool_version: None,
        version_reason: Some(VERSION_REASON.to_owned()),
        arguments: arguments.to_vec(),
        stdout: captured.stdout,
        stderr: captured.stderr,
        stdout_bytes: captured.stdout_bytes,
        stderr_bytes: captured.stderr_bytes,
        exit_code: captured.exit_code,
        signal: captured.signal,
    })
}

/// Executable identity sampled during one resolution (`ResolvedTool`).
struct ResolvedTool {
    path: String,
    sha256: String,
}

/// `resolveXcrunTool`: locate the tool through `xcrun --find` and sample its
/// executable digest.
fn resolve_xcrun_tool(
    cleanup: &CommandCleanup,
    cancellation: &Cancellation,
    tool: &str,
) -> Result<ResolvedTool, NativeCommandFailure> {
    let found = match capture_process(
        cleanup,
        cancellation,
        "/usr/bin/xcrun",
        &["--find".to_owned(), tool.to_owned()],
        "xcrun",
        false,
    ) {
        Ok(found) => found,
        Err(failure) => {
            let reason = match failure.reason {
                FailureReason::NonzeroExit | FailureReason::Unavailable => {
                    FailureReason::Unavailable
                }
                other => other,
            };
            return Err(NativeCommandFailure {
                tool: tool.to_owned(),
                reason,
                ..failure
            });
        }
    };
    if found.exit_code != Some(0) {
        return Err(NativeCommandFailure::new(tool, FailureReason::Unavailable)
            .with_capture(failure_capture(&found, false)));
    }
    let candidate = found.stdout.trim();
    if !candidate.starts_with('/') {
        return Err(NativeCommandFailure::new(tool, FailureReason::Unavailable)
            .with_capture(failure_capture(&found, false)));
    }
    let resolve = || -> std::io::Result<ResolvedTool> {
        let path = std::fs::canonicalize(candidate)?;
        let bytes = std::fs::read(&path)?;
        Ok(ResolvedTool {
            path: path.to_string_lossy().into_owned(),
            sha256: hex(&Sha256::digest(&bytes)),
        })
    };
    resolve().map_err(|error| {
        let reason = if cancellation.reason().is_some() {
            FailureReason::Cancelled
        } else {
            FailureReason::Io
        };
        NativeCommandFailure::new(tool, reason)
            .with_capture(failure_capture(&found, false))
            .with_detail(error.to_string())
    })
}

/// Launch one owned child and capture its complete output
/// (`captureProcess` over `runOwnedCommand`).
pub(crate) fn capture_process(
    cleanup: &CommandCleanup,
    cancellation: &Cancellation,
    executable: &str,
    arguments: &[String],
    tool: &str,
    accept_non_zero: bool,
) -> Result<ProcessCapture, NativeCommandFailure> {
    capture_process_with(
        cleanup,
        cancellation,
        executable,
        arguments,
        tool,
        accept_non_zero,
        NATIVE_COMMAND_TIMEOUT_MS,
        true,
    )
}

/// Launch one owned child with an explicit deadline and locale policy.
#[allow(clippy::too_many_arguments)]
pub(crate) fn capture_process_with(
    cleanup: &CommandCleanup,
    cancellation: &Cancellation,
    executable: &str,
    arguments: &[String],
    tool: &str,
    accept_non_zero: bool,
    timeout_ms: u64,
    c_locale: bool,
) -> Result<ProcessCapture, NativeCommandFailure> {
    if cancellation.reason().is_some() {
        return Err(NativeCommandFailure::new(tool, FailureReason::Cancelled));
    }
    let spec = launch_spec(executable, arguments, c_locale)
        .map_err(|detail| NativeCommandFailure::new(tool, FailureReason::Io).with_detail(detail))?;
    let mut child = OwnedChildProcess::launch(spec).map_err(|error| {
        NativeCommandFailure::new(tool, FailureReason::Io).with_detail(error.to_string())
    })?;
    let resources = vec![format!("native-command:{tool}")];
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let interruption = loop {
        match child.try_wait() {
            Ok(Some(_)) => break None,
            Ok(None) => {}
            Err(error) => break Some((FailureReason::Io, Some(error.to_string()))),
        }
        if cancellation.reason().is_some() {
            break Some((FailureReason::Cancelled, None));
        }
        if Instant::now() >= deadline {
            break Some((FailureReason::Timeout, None));
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    // Settle the owned group before interpreting output (`supervisor.stop()`).
    let settled: Result<Option<u32>, ProcessLaunchError> = match interruption {
        None => child.wait().map(|exit| Some(exit.code)),
        Some(_) => child.cancel(1).map(|()| None),
    };
    let output = child.drain_output_with(|| false);
    let (exit_code, cleanup_failure) = match settled {
        Ok(code) => (code, None),
        Err(error) => (None, Some(error.to_string())),
    };
    let output = match output {
        Ok(output) => output,
        Err(error) => {
            let mut failure =
                NativeCommandFailure::new(tool, FailureReason::Io).with_detail(error.to_string());
            if let Some(reason) = cleanup_failure {
                failure.cleanup_failure = Some(reason);
                failure.cleanup_resources = resources.clone();
                cleanup.retain(resources, child);
            }
            return Err(failure);
        }
    };
    let capture = ProcessCapture {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        stdout_bytes: output.stdout.len(),
        stderr_bytes: output.stderr.len(),
        exit_code: exit_code.map(i64::from),
        // The shared launcher does not report a terminating signal.
        signal: None,
    };
    let exceeded = output.exceeds_limit(NATIVE_COMMAND_OUTPUT_BUDGET_BYTES)
        || (interruption.is_none() && output.output_incomplete);
    let reason = match &interruption {
        Some((reason, _)) => Some(*reason),
        None if cleanup_failure.is_some() => Some(FailureReason::Io),
        None if exceeded => Some(FailureReason::OutputLimit),
        None if capture.exit_code != Some(0)
            && !(accept_non_zero && capture.exit_code.is_some()) =>
        {
            Some(FailureReason::NonzeroExit)
        }
        None => None,
    };
    if cancellation.reason().is_some() && reason.is_none() {
        return Err(NativeCommandFailure::new(tool, FailureReason::Cancelled)
            .with_capture(failure_capture(&capture, false)));
    }
    let Some(reason) = reason else {
        return Ok(capture);
    };
    let mut failure =
        NativeCommandFailure::new(tool, reason).with_capture(failure_capture(&capture, exceeded));
    if let Some((_, Some(detail))) = interruption {
        failure.detail = Some(detail);
    }
    if let Some(reason) = cleanup_failure {
        failure.cleanup_failure = Some(reason);
        failure.cleanup_resources = resources.clone();
        cleanup.retain(resources, child);
    }
    Err(failure)
}

/// Exact argv launch, with the original `LC_ALL=C`/`LANG=C` overrides applied
/// through `/usr/bin/env` on Unix hosts.
fn launch_spec(
    executable: &str,
    arguments: &[String],
    c_locale: bool,
) -> Result<ChildLaunchSpec, String> {
    let limits = WindowsJobLimits {
        memory_bytes: None,
        cpu_seconds: None,
    };
    if c_locale && cfg!(unix) {
        // `env` treats leading NAME=VALUE operands as assignments; the
        // utility operand itself must not look like one.
        if executable.contains('=') {
            return Err(format!(
                "Native command path cannot be launched with the C locale: {executable}"
            ));
        }
        let mut argv: Vec<OsString> = vec![
            "LC_ALL=C".into(),
            "LANG=C".into(),
            OsString::from(executable),
        ];
        argv.extend(arguments.iter().map(OsString::from));
        return Ok(ChildLaunchSpec {
            executable: PathBuf::from(ENV_UTILITY),
            arguments: argv,
            working_directory: None,
            protocol_stdin: false,
            limits,
        });
    }
    Ok(ChildLaunchSpec {
        executable: PathBuf::from(executable),
        arguments: arguments.iter().map(OsString::from).collect(),
        working_directory: None,
        protocol_stdin: false,
        limits,
    })
}

/// `failureCapture`: bounded excerpts with the observed byte totals.
pub(crate) fn failure_capture(capture: &ProcessCapture, truncated: bool) -> FailureCapture {
    let (stdout, stdout_truncated) =
        bounded_utf8_text(&capture.stdout, NATIVE_FAILURE_DIAGNOSTIC_BYTES);
    let (stderr, stderr_truncated) =
        bounded_utf8_text(&capture.stderr, NATIVE_FAILURE_DIAGNOSTIC_BYTES);
    FailureCapture {
        stdout,
        stderr,
        stdout_bytes: capture.stdout_bytes,
        stderr_bytes: capture.stderr_bytes,
        exit_code: capture.exit_code,
        signal: capture.signal.clone(),
        truncated: truncated || stdout_truncated || stderr_truncated,
    }
}

/// Same as [`failure_capture`] for a completed allowlisted command.
pub(crate) fn command_failure_capture(
    capture: &NativeCommandCapture,
    truncated: bool,
) -> FailureCapture {
    failure_capture(
        &ProcessCapture {
            stdout: capture.stdout.clone(),
            stderr: capture.stderr.clone(),
            stdout_bytes: capture.stdout_bytes,
            stderr_bytes: capture.stderr_bytes,
            exit_code: capture.exit_code,
            signal: capture.signal.clone(),
        },
        truncated,
    )
}

/// `boundedUtf8Text`: the longest UTF-8 prefix within `maximum` bytes.
pub(crate) fn bounded_utf8_text(text: &str, maximum: usize) -> (String, bool) {
    if text.len() <= maximum {
        return (text.to_owned(), false);
    }
    let mut end = maximum;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (text[..end].to_owned(), true)
}

/// `invocation(capture, artifactPath, alias)`: provenance with the artifact
/// path replaced by its alias.
pub(crate) fn invocation(
    capture: &NativeCommandCapture,
    artifact_path: &str,
    alias: &str,
) -> Value {
    let mut command = Vec::with_capacity(capture.arguments.len() + 1);
    command.push(Value::String(capture.executable.clone()));
    for argument in &capture.arguments {
        command.push(Value::String(if argument == artifact_path {
            alias.to_owned()
        } else {
            argument.clone()
        }));
    }
    json!({
        "tool": capture.tool,
        "command": command,
        "tool_version": capture.tool_version,
        "version_reason": capture.version_reason,
        "executable_sha256": capture.executable_sha256,
        "exit": { "code": capture.exit_code, "signal": capture.signal },
        "stdout_bytes": capture.stdout_bytes,
        "stderr_bytes": capture.stderr_bytes,
    })
}

/// Lowercase hexadecimal digest text.
pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(text, "{byte:02x}");
    }
    text
}
