//! Resolve, fingerprint and run the externally configured Wakaru command.
//!
//! Compatibility owner: `src/javascript/recovery/WakaruCommand.ts`.
//!
//! Nothing is acquired at startup. The command is resolved from `session.env`
//! and launched only through `rea_host::process::launcher`. The platform gate
//! (`linux`/`x64`) and the absolute-path requirement reproduce the TS exactly;
//! on any other host this returns the typed capability-unavailable error
//! before touching the filesystem or launching a process.
//!
//! `run_wakaru_command` is the Linux-only launch. It launches the configured
//! command through util-linux `prlimit` with the exact argv the TS builds. See
//! the module note in `execution.rs` for the shared-launcher gaps that keep
//! this launch path unverified on this host.

use std::ffi::OsString;
use std::path::Path;
use std::time::Instant;

use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess};
use rea_host::process::windows::job::WindowsJobLimits;
use rea_mcp::Session;
use serde_json::{Value, json};

use crate::javascript_recovery::OPERATION;
use crate::javascript_recovery::recovery_files::{
    FileFingerprint, fingerprint_recovery_file, recovery_failure_message,
};
use crate::javascript_recovery::release::{RECOVERY_LIMITS, WAKARU_PROVIDER_ID};

pub(crate) const WAKARU_REQUIREMENT: &str = "Provide an absolute REA_WAKARU_COMMAND pointing to a Wakaru ^1.13.0 Linux x64 binary (verified with 1.14.0); no tool is installed by REA. See docs/javascript-recovery.md#install-wakaru.";

/// Resolved engine: the real command path, the prlimit limiter and the
/// fingerprint of the configured executable bytes.
pub(crate) struct ResolvedEngine {
    pub command: String,
    pub limiter: String,
    pub sha256: String,
    pub bytes: u64,
}

/// One completed bounded command run.
pub(crate) struct CommandRun {
    pub exit_code: Option<i64>,
    pub signal: Value,
    pub stdout: String,
    pub stderr: String,
    pub command: String,
    pub arguments: Vec<String>,
    pub resource_limiter: String,
}

/// Launch coordinates shared by both Wakaru invocations.
pub(crate) struct WakaruCommandContext {
    pub command: String,
    pub limiter: String,
    pub cwd: String,
    pub deadline: Instant,
    pub cancellation: Cancellation,
}

/// `new AnalysisCapabilityUnavailableError("wakaru", OPERATION, reason, { userMessage })`.
fn capability(reason: &str) -> AnalysisError {
    AnalysisError::capability_unavailable(WAKARU_PROVIDER_ID, OPERATION, reason)
        .with_user_message(reason)
}

/// Resolve and fingerprint explicitly configured tools; acquire nothing at startup.
pub(crate) fn resolve_wakaru_command(session: &Session) -> Result<ResolvedEngine, AnalysisError> {
    let configured = session.env("REA_WAKARU_COMMAND");
    let platform_ok = std::env::consts::OS == "linux" && std::env::consts::ARCH == "x86_64";
    let configured = match configured {
        Some(value) if platform_ok && is_absolute(value) => value.to_owned(),
        _ => return Err(capability(WAKARU_REQUIREMENT)),
    };

    resolve_configured(session, &configured).map_err(|reason| {
        let reason = format!("Configured Wakaru or util-linux prlimit is unavailable: {reason}");
        capability(&reason)
    })
}

fn resolve_configured(session: &Session, configured: &str) -> Result<ResolvedEngine, String> {
    let command = std::fs::canonicalize(configured)
        .map_err(|cause| cause.to_string())?
        .to_string_lossy()
        .into_owned();

    access_executable_readable(&command)?;

    let FileFingerprint { sha256, bytes } =
        fingerprint_recovery_file(&command, RECOVERY_LIMITS.output_bytes, None)
            .map_err(|error| recovery_failure_message(&error))?;

    let limiter = session
        .env("REA_JAVASCRIPT_PRLIMIT_COMMAND")
        .unwrap_or("/usr/bin/prlimit")
        .to_owned();
    if !is_absolute(&limiter) {
        return Err("REA_JAVASCRIPT_PRLIMIT_COMMAND must be absolute".to_owned());
    }
    let metadata = Path::new(&limiter)
        .metadata()
        .map_err(|cause| cause.to_string())?;
    access_executable_from(&limiter, &metadata)?;
    if !metadata.is_file() {
        return Err(format!("Resource limiter is not a regular file: {limiter}"));
    }

    Ok(ResolvedEngine {
        command,
        limiter,
        sha256,
        bytes,
    })
}

/// Run one bounded command under util-linux prlimit and return its snapshot.
pub(crate) fn run_wakaru_command(
    context: &WakaruCommandContext,
    arguments: &[String],
    _staging: Option<&str>,
) -> Result<CommandRun, AnalysisError> {
    check_deadline(context)?;

    // Exact argv: prlimit ceilings, then the configured command and its args.
    let mut argv: Vec<String> = vec![
        format!("--as={}", RECOVERY_LIMITS.address_space_bytes),
        format!("--fsize={}", RECOVERY_LIMITS.output_bytes),
        "--core=0".to_owned(),
        "--cpu=120".to_owned(),
        "--".to_owned(),
        context.command.clone(),
    ];
    argv.extend(arguments.iter().cloned());

    let spec = ChildLaunchSpec {
        executable: Path::new(&context.limiter).to_path_buf(),
        arguments: ChildLaunchSpec::arguments(argv.iter().map(OsString::from)),
        working_directory: Some(Path::new(&context.cwd).to_path_buf()),
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };

    let mut child = OwnedChildProcess::launch(spec).map_err(|cause| {
        if context.cancellation.reason().is_some() {
            return AnalysisError::cancelled(OPERATION);
        }
        AnalysisError::provider_adapter(WAKARU_PROVIDER_ID, OPERATION).with_diagnostics(
            serde_json::Map::from_iter([
                (
                    "reason".to_owned(),
                    json!("Failed to launch configured Wakaru through util-linux prlimit"),
                ),
                ("command".to_owned(), json!(context.command)),
                ("detail".to_owned(), json!(cause.to_string())),
            ]),
        )
    })?;

    loop {
        check_deadline(context)?;
        let output = child
            .read_output()
            .map_err(|cause| AnalysisError::output(OPERATION, cause.to_string()))?;
        if output.exceeds_limit(RECOVERY_LIMITS.report_bytes as usize) {
            let _ = child.cancel(1);
            return Err(AnalysisError::output(
                OPERATION,
                "Wakaru diagnostic stream exceeds 8 MiB",
            ));
        }
        if let Some(exit) = child
            .try_wait()
            .map_err(|cause| AnalysisError::output(OPERATION, cause.to_string()))?
        {
            check_deadline(context)?;
            let final_output = child
                .drain_output()
                .map_err(|cause| AnalysisError::output(OPERATION, cause.to_string()))?;
            return Ok(CommandRun {
                exit_code: Some(i64::from(exit.code)),
                signal: exit.signal.map_or(Value::Null, |signal| json!(signal)),
                stdout: String::from_utf8_lossy(&final_output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&final_output.stderr).into_owned(),
                command: context.command.clone(),
                arguments: arguments.to_vec(),
                resource_limiter: context.limiter.clone(),
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn check_deadline(context: &WakaruCommandContext) -> Result<(), AnalysisError> {
    if context.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }
    if Instant::now() >= context.deadline {
        return Err(AnalysisError::timeout(
            OPERATION,
            RECOVERY_LIMITS.timeout_ms,
        ));
    }
    Ok(())
}

fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

#[cfg(unix)]
fn access_executable_readable(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = Path::new(path)
        .metadata()
        .map_err(|cause| cause.to_string())?;
    let mode = metadata.permissions().mode();
    if mode & 0o400 == 0 || mode & 0o100 == 0 {
        return Err(format!("Permission denied: {path}"));
    }
    Ok(())
}

#[cfg(unix)]
fn access_executable_from(path: &str, metadata: &std::fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o100 == 0 {
        return Err(format!("Permission denied: {path}"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn access_executable_readable(path: &str) -> Result<(), String> {
    if Path::new(path).exists() {
        Ok(())
    } else {
        Err(format!("No such file: {path}"))
    }
}

#[cfg(not(unix))]
fn access_executable_from(path: &str, _metadata: &std::fs::Metadata) -> Result<(), String> {
    if Path::new(path).exists() {
        Ok(())
    } else {
        Err(format!("No such file: {path}"))
    }
}
