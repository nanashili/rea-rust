//! Caller-selected adb binary resolution and the `adb version` client probe.
//!
//! Compatibility owner: `src/adb/AdbConfiguration.ts`. `REA_ADB_PATH` selects
//! the binary and must be absolute; otherwise `adb` is resolved from `PATH`
//! by the launcher at run time. The probe never contacts devices or starts
//! the adb server.
use crate::common::process::{CommandLimits, CommandSpec, FailureKind, OutputBudget, run_command};
use rea_core::analysis_error::{AnalysisError, ErrorKind};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

/// Environment key selecting the caller's adb binary.
pub const ADB_BINARY_ENV: &str = "REA_ADB_PATH";
const VERSION_TIMEOUT_MS: u64 = 10_000;
const VERSION_MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// How the adb binary was selected for this provider instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Selection {
    pub binary: String,
    pub path_source: PathSource,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathSource {
    Environment,
    Path,
}

impl PathSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Environment => "environment",
            Self::Path => "path",
        }
    }
}

/// Why the caller's adb configuration cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    NotAbsolute,
    BinaryMissing,
    VersionUnresolved,
}

/// `AdbConfigurationFailure`: a host configuration refusal before any device
/// contact. Carries the diagnostics the TS constructor set.
#[derive(Clone, Debug)]
pub struct ConfigurationFailure {
    pub code: ConfigurationFailureCode,
    pub message: String,
    pub diagnostics: Map<String, Value>,
}

impl ConfigurationFailure {
    fn new(code: ConfigurationFailureCode, message: impl Into<String>, diagnostics: Value) -> Self {
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

/// The parsed client identity from `adb version`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ClientIdentity {
    pub version: Option<String>,
    pub installed_path: Option<String>,
}

/// `resolveAdbBinary(environment)`.
pub fn resolve_adb_binary(
    environment: &HashMap<String, String>,
) -> Result<Selection, ConfigurationFailure> {
    let configured = crate::common::env::lookup(environment, ADB_BINARY_ENV);
    match configured {
        None => Ok(Selection {
            binary: "adb".to_owned(),
            path_source: PathSource::Path,
        }),
        Some(value) if value.trim().is_empty() => Ok(Selection {
            binary: "adb".to_owned(),
            path_source: PathSource::Path,
        }),
        Some(value) => {
            if !crate::common::env::is_absolute(value) {
                return Err(ConfigurationFailure::new(
                    ConfigurationFailureCode::NotAbsolute,
                    format!("{ADB_BINARY_ENV} must be an absolute path to the adb binary"),
                    json!({ "configured_path": value }),
                ));
            }
            Ok(Selection {
                binary: value.to_owned(),
                path_source: PathSource::Environment,
            })
        }
    }
}

fn build_version_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^Version\s+(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\s*$").unwrap()
    })
}

fn installed_as_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?m)^Installed as\s+(.+)$").unwrap())
}

fn protocol_regex() -> &'static regex::Regex {
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?m)^Android Debug Bridge version\s+\d+\.\d+\.\d+\s*$").unwrap()
    })
}

/// `parseAdbVersionOutput(stdout)`.
pub fn parse_adb_version_output(stdout: &str) -> ClientIdentity {
    let version = build_version_regex()
        .captures(stdout)
        .map(|caps| caps[1].trim().to_owned());
    let installed_path = installed_as_regex()
        .captures(stdout)
        .map(|caps| caps[1].trim().to_owned());
    ClientIdentity {
        version,
        installed_path,
    }
}

/// Outcome of the client probe: either a configuration refusal, or a typed
/// analysis error (cancellation, timeout, resource constraint, protocol).
pub enum ClientProbeError {
    Configuration(ConfigurationFailure),
    Analysis(AnalysisError),
}

impl From<ConfigurationFailure> for ClientProbeError {
    fn from(failure: ConfigurationFailure) -> Self {
        Self::Configuration(failure)
    }
}

/// `inspectAdbClient(selection, signal)`.
pub fn inspect_adb_client(
    selection: &Selection,
    cancellation: &Cancellation,
) -> Result<ClientIdentity, ClientProbeError> {
    let spec = CommandSpec::new(&selection.binary, ["version"]);
    let limits = CommandLimits {
        timeout: Duration::from_millis(VERSION_TIMEOUT_MS),
        budget: OutputBudget::PerStream(VERSION_MAX_OUTPUT_BYTES),
    };
    match run_command(&spec, limits, cancellation, false) {
        Ok(output) => {
            let stdout = output.stdout_text();
            let stderr = output.stderr_text();
            let identity = parse_adb_version_output(&stdout);
            let recognized_protocol = protocol_regex().is_match(&stdout);
            if identity.version.is_none() && !recognized_protocol {
                return Err(ClientProbeError::Configuration(ConfigurationFailure::new(
                    ConfigurationFailureCode::VersionUnresolved,
                    "The selected adb binary exited successfully but did not report a recognizable protocol or build version",
                    json!({
                        "selected_binary": selection.binary,
                        "path_source": selection.path_source.as_str(),
                        "version_probe": "unrecognized_output",
                        "stdout": stdout,
                        "stderr": stderr,
                    }),
                )));
            }
            Ok(identity)
        }
        Err(failure) => Err(classify_probe_failure(selection, failure)),
    }
}

fn classify_probe_failure(
    selection: &Selection,
    failure: crate::common::process::CommandFailure,
) -> ClientProbeError {
    let operation = "inspect_adb_client";
    let captured = failure.output.captured();
    match &failure.kind {
        FailureKind::Cancelled { reason } => {
            let mut error = AnalysisError::cancelled(operation);
            error.captured_output = Some(captured);
            let _ = reason;
            ClientProbeError::Analysis(error)
        }
        FailureKind::OutputLimit => {
            let mut error = AnalysisError::resource_constraint(
                operation,
                "memory",
                format!(
                    "adb version output exceeded the {VERSION_MAX_OUTPUT_BYTES}-byte capture budget"
                ),
                Some(json!({ "max_output_bytes": VERSION_MAX_OUTPUT_BYTES })),
            );
            error.captured_output = Some(captured);
            error.diagnostics = Some(configuration_diagnostics(selection, &failure));
            ClientProbeError::Analysis(error)
        }
        FailureKind::Timeout => {
            let mut error = AnalysisError::timeout(operation, VERSION_TIMEOUT_MS);
            error.captured_output = Some(captured);
            error.diagnostics = Some(configuration_diagnostics(selection, &failure));
            ClientProbeError::Analysis(error)
        }
        FailureKind::Launch { .. } if failure.kind.program_not_found() => {
            ClientProbeError::Configuration(ConfigurationFailure::new(
                ConfigurationFailureCode::BinaryMissing,
                format!(
                    "The selected adb binary was not found: {}",
                    selection.binary
                ),
                json!({
                    "selected_binary": selection.binary,
                    "path_source": selection.path_source.as_str(),
                    "remediation": format!(
                        "Set {ADB_BINARY_ENV} to an absolute path to an existing adb binary"
                    ),
                }),
            ))
        }
        FailureKind::Exit => {
            let stderr = failure.output.stderr_text();
            let excerpt: String = stderr.chars().take(512).collect();
            ClientProbeError::Configuration(ConfigurationFailure::new(
                ConfigurationFailureCode::VersionUnresolved,
                "The selected adb binary did not report a usable version",
                json!({
                    "selected_binary": selection.binary,
                    "exit_code": failure.output.exit_code,
                    "stderr_excerpt": excerpt,
                }),
            ))
        }
        _ => ClientProbeError::Configuration(ConfigurationFailure::new(
            ConfigurationFailureCode::VersionUnresolved,
            "The selected adb binary did not report a usable version",
            json!({ "selected_binary": selection.binary }),
        )),
    }
}

fn configuration_diagnostics(
    selection: &Selection,
    failure: &crate::common::process::CommandFailure,
) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("selected_binary".into(), json!(selection.binary));
    map.insert("path_source".into(), json!(selection.path_source.as_str()));
    if let Some(code) = failure.output.exit_code {
        map.insert("exit_code".into(), json!(code));
    }
    map
}

fn rejection_code(code: ConfigurationFailureCode) -> &'static str {
    match code {
        ConfigurationFailureCode::BinaryMissing => "executable_missing",
        ConfigurationFailureCode::NotAbsolute => "not_configured",
        ConfigurationFailureCode::VersionUnresolved => "version_unresolved",
    }
}

/// `adbConfigurationAvailability(cause)` as a `ProviderAvailability` JSON value.
pub fn configuration_availability(failure: &ConfigurationFailure) -> Value {
    json!({
        "status": "unavailable",
        "code": rejection_code(failure.code),
        "reason": failure.message,
        "diagnostics": Value::Object(failure.diagnostics.clone()),
    })
}

/// `providerConfigurationRefusal(providerId, operation, failure)`: convert a
/// configuration failure into a capability-unavailable Evidence-bearing error.
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
