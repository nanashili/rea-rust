//! Caller-selected apktool launcher resolution and the `--version` probe.
//!
//! Compatibility owner: `src/apktool/ApktoolConfiguration.ts`.
//! `REA_APKTOOL_COMMAND` selects the launcher and must be absolute; otherwise
//! POSIX keeps the launcher's `apktool` PATH lookup and Windows resolves the
//! command over PATH/PATHEXT. The probe runs `--version` in an owned process
//! group and decodes nothing.

use crate::common::env;
use crate::common::process::{
    CommandLimits, CommandSpec, FailureKind, OutputBudget, RetainedChild, run_command,
};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::time::Duration;

use super::version::{self, ClientIdentity, VersionOutcome};

/// Environment key selecting the caller's apktool launcher.
pub const APKTOOL_COMMAND_ENV: &str = "REA_APKTOOL_COMMAND";
pub(crate) const VERSION_TIMEOUT_MS: u64 = 20_000;
pub(crate) const VERSION_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// How the apktool launcher was selected for this provider instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    pub command: String,
    pub command_source: CommandSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandSource {
    Environment,
    Path,
}

impl CommandSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Path => "path",
        }
    }
}

/// `ApktoolConfigurationFailureCode`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    NotAbsolute,
    CommandMissing,
    /// A PATH candidate could not be inspected (Windows resolution only).
    #[cfg_attr(not(windows), allow(dead_code))]
    CommandUnresolved,
    /// The launcher cannot be run through cmd.exe. The native launcher runs
    /// the command directly, so this refusal is not produced here.
    #[allow(dead_code)]
    LauncherUnsupported,
    VersionUnresolved,
    UnsupportedVersion,
}

/// `ApktoolConfigurationFailure`: a host configuration refusal before decoding.
#[derive(Clone, Debug)]
pub struct ConfigurationFailure {
    pub code: ConfigurationFailureCode,
    pub message: String,
    pub diagnostics: Map<String, Value>,
}

impl ConfigurationFailure {
    pub fn new(
        code: ConfigurationFailureCode,
        message: impl Into<String>,
        diagnostics: Value,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostics: match diagnostics {
                Value::Object(map) => map,
                _ => Map::new(),
            },
        }
    }
}

/// `resolveApktoolCommand(environment, platform, signal)`.
pub fn resolve_apktool_command(
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<Selection, ClientProbeError> {
    if cancellation.reason().is_some() {
        return Err(ClientProbeError::Analysis(AnalysisError::cancelled(
            super::OPERATION_INSPECT,
        )));
    }
    let configured = env::lookup(environment, APKTOOL_COMMAND_ENV);
    if let Some(value) = configured {
        if !value.trim().is_empty() {
            if !env::is_absolute(value) {
                return Err(ClientProbeError::Configuration(ConfigurationFailure::new(
                    ConfigurationFailureCode::NotAbsolute,
                    format!(
                        "{APKTOOL_COMMAND_ENV} must be an absolute path to the apktool launcher"
                    ),
                    json!({ "configured_command": value }),
                )));
            }
            return Ok(Selection {
                command: value.to_owned(),
                command_source: CommandSource::Environment,
            });
        }
    }

    #[cfg(not(windows))]
    {
        let _ = environment;
        Ok(Selection {
            command: "apktool".to_owned(),
            command_source: CommandSource::Path,
        })
    }
    #[cfg(windows)]
    {
        resolve_windows_command(environment, cancellation)
    }
}

#[cfg(windows)]
fn resolve_windows_command(
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<Selection, ClientProbeError> {
    use std::path::Path;
    use std::time::Instant;

    let extensions: Vec<String> = env::lookup(environment, "PATHEXT")
        .filter(|value| !value.is_empty())
        .unwrap_or(".EXE;.COM;.BAT;.CMD")
        .split(';')
        .filter(|extension| !extension.is_empty())
        .map(str::to_owned)
        .collect();
    for extension in &extensions {
        if !extension.starts_with('.') || extension.contains(['\\', '/', ':', '\0']) {
            return Err(ClientProbeError::Configuration(ConfigurationFailure::new(
                ConfigurationFailureCode::CommandUnresolved,
                "Windows PATHEXT must contain filename extensions, not paths",
                json!({
                    "selected_command": "apktool",
                    "command_source": "path",
                    "invalid_extension": extension,
                }),
            )));
        }
    }

    let mut directories: Vec<String> = env::lookup(environment, "PATH")
        .unwrap_or("")
        .split(';')
        .filter(|directory| !directory.is_empty())
        .map(str::to_owned)
        .collect();
    if env::lookup(environment, "NODEFAULTCURRENTDIRECTORYINEXEPATH").is_none() {
        if let Ok(cwd) = std::env::current_dir() {
            directories.insert(0, cwd.display().to_string());
        }
    }

    let started = Instant::now();
    let deadline = Duration::from_millis(VERSION_TIMEOUT_MS);
    let interruption = |cancellation: &Cancellation| -> ClientProbeError {
        if cancellation.reason().is_some() {
            ClientProbeError::Analysis(AnalysisError::cancelled(super::OPERATION_INSPECT))
        } else {
            let mut error = AnalysisError::timeout(super::OPERATION_INSPECT, VERSION_TIMEOUT_MS);
            error.diagnostics = Some(
                json!({ "phase": "windows_path_lookup" })
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            );
            ClientProbeError::Analysis(error)
        }
    };

    for entry in &directories {
        let directory = if entry.starts_with('"') && entry.ends_with('"') && entry.len() >= 2 {
            &entry[1..entry.len() - 1]
        } else {
            entry.as_str()
        };
        for extension in &extensions {
            if cancellation.reason().is_some() || started.elapsed() >= deadline {
                return Err(interruption(cancellation));
            }
            let candidate = Path::new(directory).join(format!("apktool{extension}"));
            match std::fs::metadata(&candidate) {
                Ok(metadata) if metadata.is_file() => {
                    return Ok(Selection {
                        command: candidate.display().to_string(),
                        command_source: CommandSource::Path,
                    });
                }
                Ok(_) => continue,
                Err(error) => {
                    let code = crate::common::files::io_code(&error);
                    if matches!(code, Some("ENOENT") | Some("ENOTDIR")) {
                        continue;
                    }
                    return Err(ClientProbeError::Configuration(ConfigurationFailure::new(
                        ConfigurationFailureCode::CommandUnresolved,
                        format!(
                            "The PATH-selected apktool launcher could not be inspected: {}",
                            candidate.display()
                        ),
                        json!({
                            "selected_command": "apktool",
                            "command_source": "path",
                            "candidate_path": candidate.display().to_string(),
                            "filesystem_error": code,
                        }),
                    )));
                }
            }
        }
    }

    Err(ClientProbeError::Configuration(ConfigurationFailure::new(
        ConfigurationFailureCode::CommandMissing,
        "The apktool launcher was not found on the selected Windows PATH/PATHEXT",
        json!({
            "selected_command": "apktool",
            "command_source": "path",
            "remediation": format!(
                "Set {APKTOOL_COMMAND_ENV} to an absolute apktool launcher, or add its directory and extension to PATH and PATHEXT"
            ),
        }),
    )))
}

/// Outcome of the client probe.
pub enum ClientProbeError {
    Configuration(ConfigurationFailure),
    Analysis(AnalysisError),
}

/// Result of `inspectApktoolClient`: an identity.
pub struct ProbeSuccess {
    pub identity: ClientIdentity,
}

/// A probe failure that may carry an owned child whose cleanup must be retried.
pub struct ProbeFailure {
    pub error: ClientProbeError,
    pub retained: Option<RetainedChild>,
}

/// `inspectApktoolClient(selection, cleanup, options)`: probe `--version`.
pub fn inspect_apktool_client(
    selection: &Selection,
    cancellation: &Cancellation,
) -> Result<ProbeSuccess, ProbeFailure> {
    let platform = env::platform();
    let spec = CommandSpec::new(&selection.command, ["--version"]);
    let limits = CommandLimits {
        timeout: Duration::from_millis(VERSION_TIMEOUT_MS),
        budget: OutputBudget::Combined(VERSION_MAX_OUTPUT_BYTES),
    };
    match run_command(&spec, limits, cancellation, false) {
        Ok(output) => {
            let stdout = output.stdout_text();
            let stderr = output.stderr_text();
            match interpret_version(&stdout, &stderr, selection, platform) {
                Ok(identity) => Ok(ProbeSuccess { identity }),
                Err(failure) => Err(ProbeFailure {
                    error: ClientProbeError::Configuration(failure),
                    retained: None,
                }),
            }
        }
        Err(failure) => {
            let retained = failure.retained;
            let error = version_probe_failure(selection, &failure.kind, &failure.output, platform);
            Err(ProbeFailure { error, retained })
        }
    }
}

/// `interpretApktoolVersion(stdout, stderr, selection, platform)`.
fn interpret_version(
    stdout: &str,
    stderr: &str,
    selection: &Selection,
    platform: &str,
) -> Result<ClientIdentity, ConfigurationFailure> {
    match version::parse_version_output(stdout, platform) {
        VersionOutcome::Unrecognized { reported_version } => Err(ConfigurationFailure::new(
            ConfigurationFailureCode::VersionUnresolved,
            "The selected apktool launcher exited successfully but did not report a recognizable version",
            json!({
                "selected_command": selection.command,
                "command_source": selection.command_source.as_str(),
                "version_probe": "unrecognized_output",
                "reported_version": reported_version,
                "stdout": stdout,
                "stderr": stderr,
            }),
        )),
        VersionOutcome::Recognized(identity) if !identity.supports_documented_version => {
            Err(ConfigurationFailure::new(
                ConfigurationFailureCode::UnsupportedVersion,
                format!(
                    "The selected Apktool version {} is older than the supported minimum 2.7.0",
                    identity.version
                ),
                json!({
                    "selected_command": selection.command,
                    "command_source": selection.command_source.as_str(),
                    "reported_version": identity.version,
                    "minimum_version": "2.7.0",
                    "remediation": "Use Apktool 2.7.0 or newer; see docs/apktool-resource-analysis.md.",
                }),
            ))
        }
        VersionOutcome::Recognized(identity) => Ok(identity),
    }
}

/// `versionProbeFailure(cause, selection, observed)` for a command failure.
fn version_probe_failure(
    selection: &Selection,
    kind: &FailureKind,
    output: &crate::common::process::CommandOutput,
    _platform: &str,
) -> ClientProbeError {
    let operation = super::OPERATION_INSPECT;
    let captured = output.captured();
    match kind {
        FailureKind::Cancelled { .. } => {
            let mut error = AnalysisError::cancelled(operation);
            error.captured_output = Some(captured);
            ClientProbeError::Analysis(error)
        }
        FailureKind::Timeout => {
            let mut error = AnalysisError::timeout(operation, VERSION_TIMEOUT_MS);
            error.captured_output = Some(captured);
            ClientProbeError::Analysis(error)
        }
        FailureKind::Launch { .. } if kind.program_not_found() => {
            ClientProbeError::Configuration(ConfigurationFailure::new(
                ConfigurationFailureCode::CommandMissing,
                format!(
                    "The selected apktool launcher was not found: {}",
                    selection.command
                ),
                json!({
                    "selected_command": selection.command,
                    "command_source": selection.command_source.as_str(),
                    "remediation": format!(
                        "Set {APKTOOL_COMMAND_ENV} to an absolute apktool launcher (the upstream wrapper or a java -jar script)"
                    ),
                }),
            ))
        }
        FailureKind::OutputLimit => ClientProbeError::Configuration(ConfigurationFailure::new(
            ConfigurationFailureCode::VersionUnresolved,
            "The selected apktool launcher did not report a usable version",
            json!({
                "selected_command": selection.command,
                "exit_code": output.exit_code,
                "stderr_excerpt": stderr_excerpt(output),
                "max_output_bytes": VERSION_MAX_OUTPUT_BYTES,
            }),
        )),
        _ => ClientProbeError::Configuration(ConfigurationFailure::new(
            ConfigurationFailureCode::VersionUnresolved,
            "The selected apktool launcher did not report a usable version",
            json!({
                "selected_command": selection.command,
                "exit_code": output.exit_code,
                "stderr_excerpt": stderr_excerpt(output),
            }),
        )),
    }
}

fn stderr_excerpt(output: &crate::common::process::CommandOutput) -> String {
    output.stderr_text().chars().take(512).collect()
}

fn rejection_code(code: ConfigurationFailureCode) -> &'static str {
    match code {
        ConfigurationFailureCode::CommandMissing => "executable_missing",
        ConfigurationFailureCode::NotAbsolute
        | ConfigurationFailureCode::LauncherUnsupported
        | ConfigurationFailureCode::CommandUnresolved => "not_configured",
        ConfigurationFailureCode::UnsupportedVersion => "unsupported_version",
        ConfigurationFailureCode::VersionUnresolved => "version_unresolved",
    }
}

/// `apktoolConfigurationAvailability(cause)` as a `ProviderAvailability` JSON value.
pub fn configuration_availability(failure: &ConfigurationFailure) -> Value {
    json!({
        "status": "unavailable",
        "code": rejection_code(failure.code),
        "reason": failure.message,
        "diagnostics": Value::Object(failure.diagnostics.clone()),
    })
}

/// `providerConfigurationRefusal(providerId, operation, failure)`.
pub fn configuration_refusal(
    provider_id: &str,
    operation: &str,
    failure: &ConfigurationFailure,
) -> AnalysisError {
    let remediation = failure
        .diagnostics
        .get("remediation")
        .and_then(Value::as_str);
    let reason = match remediation {
        Some(remediation) => format!("{}. {}.", failure.message, remediation),
        None => format!("{}.", failure.message),
    };
    let mut error = AnalysisError::from(ErrorKind::CapabilityUnavailable {
        provider_id: provider_id.to_owned(),
        operation: operation.to_owned(),
        reason: reason.clone(),
        user_message: Some(reason),
        remediation_action: None,
        retryable: false,
    });
    error.diagnostics = Some(failure.diagnostics.clone());
    error
}
