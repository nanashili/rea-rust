//! Caller-selected JADX prerequisites: JAR path, Java launcher, JVM options
//! and the whole-operation deadline.
//!
//! Compatibility owner: `src/android/JadxConfiguration.ts`. Failures are
//! tagged at this boundary (`JadxConfigurationFailure`) and projected into the
//! shared error algebra by [`project_configuration_failure`]. The doctor
//! adapter would project remediation/classification from the kind only.

use super::java_probe::{self, JadxJavaProbeRefusal};
use super::release::{
    self, JADX_JAVA_PROBE_REMEDIATION, JADX_JAVA_RUNTIME_REMEDIATION, JADX_JVM_OPTIONS_REMEDIATION,
    JADX_PROVIDER_ID, JADX_UNSUPPORTED_HOST_REMEDIATION, JADX_WINDOWS_NATIVE_REMEDIATION,
};
use crate::common::env;
use crate::common::errors::capability_unavailable;
use crate::common::process::ProtocolChild;
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Caller-supplied tools resolved when an Android operation is selected.
#[derive(Clone, Debug)]
pub struct JadxConfiguration {
    pub jar: String,
    pub java: String,
    pub jvm_arguments: Vec<String>,
}

/// Configuration failure codes tagged at this boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationFailureCode {
    NotConfigured,
    ExecutableMissing,
    RuntimeMissing,
    RuntimeUnavailable,
    UnsupportedHost,
    UnsupportedVersion,
    VersionUnresolved,
    OpenOptionsInvalid,
}

impl ConfigurationFailureCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::ExecutableMissing => "executable_missing",
            Self::RuntimeMissing => "runtime_missing",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::UnsupportedHost => "unsupported_host",
            Self::UnsupportedVersion => "unsupported_version",
            Self::VersionUnresolved => "version_unresolved",
            Self::OpenOptionsInvalid => "open_options_invalid",
        }
    }
}

/// Failure kinds tagged at the configuration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JadxFailureKind {
    WindowsNativeArtifact,
    WindowsNativeRuntime,
    JavaRuntime,
    JavaHome,
    JvmOptions,
    OperationTimeout,
    Jar,
    JavaProbe,
    UnsupportedHost,
}

impl JadxFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WindowsNativeArtifact => "windows_native_artifact",
            Self::WindowsNativeRuntime => "windows_native_runtime",
            Self::JavaRuntime => "java_runtime",
            Self::JavaHome => "java_home",
            Self::JvmOptions => "jvm_options",
            Self::OperationTimeout => "operation_timeout",
            Self::Jar => "jar",
            Self::JavaProbe => "java_probe",
            Self::UnsupportedHost => "unsupported_host",
        }
    }
}

/// A tagged configuration boundary failure, projected by its consumers.
#[derive(Clone, Debug)]
pub struct JadxConfigurationFailure {
    pub code: ConfigurationFailureCode,
    pub message: String,
    pub diagnostics: Map<String, Value>,
    pub kind: JadxFailureKind,
}

impl JadxConfigurationFailure {
    fn new(
        code: ConfigurationFailureCode,
        message: impl Into<String>,
        diagnostics: Value,
        kind: JadxFailureKind,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            diagnostics: match diagnostics {
                Value::Object(map) => map,
                _ => Map::new(),
            },
            kind,
        }
    }
}

fn configuration_failure(
    code: ConfigurationFailureCode,
    message: impl Into<String>,
    diagnostics: Value,
    kind: JadxFailureKind,
) -> JadxConfigurationFailure {
    JadxConfigurationFailure::new(code, message, diagnostics, kind)
}

/// `projectConfigurationFailure(operation, cause)`.
pub fn project_configuration_failure(
    operation: &str,
    cause: &JadxConfigurationFailure,
) -> AnalysisError {
    let mut facts = cause.diagnostics.clone();
    let stdout = facts.remove("stdout");
    let stderr = facts.remove("stderr");
    facts.insert("failure_kind".into(), json!(cause.kind.as_str()));
    facts.insert("failure_code".into(), json!(cause.code.as_str()));
    let mut error = capability_unavailable(
        JADX_PROVIDER_ID,
        operation,
        cause.message.clone(),
        Some(cause.message.clone()),
        Some(facts),
    );
    if let (Some(Value::String(out)), Some(Value::String(err))) = (&stdout, &stderr) {
        error.captured_output = Some(CapturedOutput {
            stdout: out.clone(),
            stderr: err.clone(),
            truncated: cause.diagnostics.get("output_truncated") == Some(&Value::Bool(true)),
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        });
    }
    error
}

/// Whether the current host can own the JADX subprocess.
///
/// linux and darwin pass; win32 x64 passes because the native launcher owns
/// protocol stdin through its Job Object; other hosts fail `unsupported_host`.
fn require_supported_host() -> Result<(), JadxConfigurationFailure> {
    let platform = env::platform();
    if platform == "linux" || platform == "darwin" {
        return Ok(());
    }
    if platform == "win32" && env::architecture() == "x64" {
        return Ok(());
    }
    Err(configuration_failure(
        ConfigurationFailureCode::UnsupportedHost,
        format!(
            "Android JADX subprocess ownership is unsupported on {platform}/{}; use Linux, macOS, or Windows x64 with its bundled native controls.",
            env::architecture()
        ),
        json!({ "platform": platform }),
        JadxFailureKind::UnsupportedHost,
    ))
}

fn resolve_jar(environment: &HashMap<String, String>) -> Result<String, JadxConfigurationFailure> {
    let jar = env::lookup(environment, "REA_JADX_MCP_JAR");
    let Some(jar) = jar.filter(|value| env::is_absolute(value)) else {
        return Err(configuration_failure(
            ConfigurationFailureCode::NotConfigured,
            release::jar_configuration_remediation(),
            json!({ "jar_configured": false }),
            JadxFailureKind::Jar,
        ));
    };
    let path = Path::new(jar);
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => match std::fs::canonicalize(path) {
            Ok(real) => Ok(crate::common::target::display_canonical(real)),
            Err(error) => Err(configuration_failure(
                ConfigurationFailureCode::ExecutableMissing,
                format!(
                    "Cannot read REA_JADX_MCP_JAR {jar}: {}",
                    crate::common::files::node_io_message(&error, "realpath", jar)
                ),
                json!({ "jar_path": jar }),
                JadxFailureKind::Jar,
            )),
        },
        Ok(_) => Err(configuration_failure(
            ConfigurationFailureCode::ExecutableMissing,
            format!("REA_JADX_MCP_JAR is not a regular file: {jar}"),
            json!({ "jar_path": jar }),
            JadxFailureKind::Jar,
        )),
        Err(error) => Err(configuration_failure(
            ConfigurationFailureCode::ExecutableMissing,
            format!(
                "Cannot read REA_JADX_MCP_JAR {jar}: {}",
                crate::common::files::node_io_message(&error, "access", jar)
            ),
            json!({ "jar_path": jar }),
            JadxFailureKind::Jar,
        )),
    }
}

fn resolve_java(
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<String, JadxConfigurationFailure> {
    let windows = env::platform() == "win32";
    let executable = if windows { "java.exe" } else { "java" };
    let java_home = env::lookup(environment, "JAVA_HOME");
    let Some(java_home) = java_home else {
        if !windows {
            return Ok(executable.to_owned());
        }
        // Windows PATH search mirrors the TS fallback.
        let path = env::lookup(environment, "PATH").unwrap_or("");
        let cwd = std::env::current_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default();
        let mut directories = vec![cwd];
        directories.extend(path.split(env::PATH_DELIMITER).map(str::to_owned));
        for directory in directories {
            if cancellation.reason().is_some() {
                return Err(cancelled_marker());
            }
            let selected =
                if directory.starts_with('"') && directory.ends_with('"') && directory.len() >= 2 {
                    directory[1..directory.len() - 1].to_owned()
                } else {
                    directory
                };
            let candidate = PathBuf::from(&selected).join(executable);
            match std::fs::metadata(&candidate) {
                Ok(meta) if meta.is_file() => {
                    return match std::fs::canonicalize(&candidate) {
                        Ok(real) => Ok(crate::common::target::display_canonical(real)),
                        Err(error) => Err(configuration_failure(
                            ConfigurationFailureCode::RuntimeMissing,
                            format!(
                                "Cannot inspect selected Java executable {}: {error}",
                                candidate.display()
                            ),
                            json!({ "java_executable": candidate.display().to_string() }),
                            JadxFailureKind::JavaRuntime,
                        )),
                    };
                }
                Ok(_) => continue,
                Err(error) => {
                    let code = crate::common::files::io_code(&error);
                    if matches!(code, Some("ENOENT") | Some("ENOTDIR")) {
                        continue;
                    }
                    return Err(configuration_failure(
                        ConfigurationFailureCode::RuntimeMissing,
                        format!(
                            "Cannot inspect selected Java executable {}: {error}",
                            candidate.display()
                        ),
                        json!({ "java_executable": candidate.display().to_string() }),
                        JadxFailureKind::JavaRuntime,
                    ));
                }
            }
        }
        return Err(configuration_failure(
            ConfigurationFailureCode::RuntimeMissing,
            "Cannot find java.exe on the selected Windows PATH. Select a full JDK with JAVA_HOME or PATH, then verify it with java --list-modules. REA does not install Java.",
            json!({ "java_executable": executable }),
            JadxFailureKind::JavaRuntime,
        ));
    };
    if env::is_absolute(java_home) {
        return Ok(PathBuf::from(java_home)
            .join("bin")
            .join(executable)
            .display()
            .to_string());
    }
    Err(configuration_failure(
        ConfigurationFailureCode::OpenOptionsInvalid,
        "JAVA_HOME must select an existing JDK by absolute path; omit it to use java on PATH.",
        json!({ "java_home": java_home }),
        JadxFailureKind::JavaHome,
    ))
}

/// A sentinel configuration failure representing an observed cancellation.
/// The caller converts it into an `AnalysisCancelledError`.
fn cancelled_marker() -> JadxConfigurationFailure {
    configuration_failure(
        ConfigurationFailureCode::RuntimeMissing,
        "__cancelled__",
        json!({}),
        JadxFailureKind::JavaRuntime,
    )
}

fn require_java_home_executable(
    java_home: Option<&str>,
    java: &str,
) -> Result<(), JadxConfigurationFailure> {
    if java_home.is_none() {
        return Ok(());
    }
    let path = Path::new(java);
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => Ok(()),
        Ok(_) => Err(configuration_failure(
            ConfigurationFailureCode::RuntimeMissing,
            format!("JAVA_HOME java is not a regular file: {java}"),
            json!({ "java_executable": java }),
            JadxFailureKind::JavaRuntime,
        )),
        Err(error) => Err(configuration_failure(
            ConfigurationFailureCode::RuntimeMissing,
            format!(
                "Cannot execute JAVA_HOME java {java}: {}",
                crate::common::files::node_io_message(&error, "access", java)
            ),
            json!({ "java_executable": java }),
            JadxFailureKind::JavaRuntime,
        )),
    }
}

fn resolve_jvm_arguments(
    environment: &HashMap<String, String>,
) -> Result<Vec<String>, JadxConfigurationFailure> {
    let mut result = Vec::new();
    for (name, prefix, suffix) in [
        ("REA_JADX_HEAP_MIB", "-Xmx", "m"),
        (
            "REA_JADX_ACTIVE_PROCESSOR_COUNT",
            "-XX:ActiveProcessorCount=",
            "",
        ),
    ] {
        let Some(value) = env::lookup(environment, name) else {
            continue;
        };
        let positive_integer = !value.is_empty()
            && value.as_bytes()[0] != b'0'
            && value.bytes().all(|byte| byte.is_ascii_digit());
        let parsed = value.parse::<u64>().ok();
        if !positive_integer || parsed.is_none_or(|number| number > MAX_SAFE_INTEGER) {
            return Err(configuration_failure(
                ConfigurationFailureCode::OpenOptionsInvalid,
                format!("{name} must be a positive safe integer; received {value}."),
                json!({ "setting": name, "value": value }),
                JadxFailureKind::JvmOptions,
            ));
        }
        if name == "REA_JADX_ACTIVE_PROCESSOR_COUNT" && parsed.unwrap_or(0) > 2_147_483_647 {
            return Err(configuration_failure(
                ConfigurationFailureCode::OpenOptionsInvalid,
                format!("{name} exceeds the JVM's signed 32-bit processor-count range."),
                json!({ "setting": name, "value": value }),
                JadxFailureKind::JvmOptions,
            ));
        }
        result.push(format!("{prefix}{value}{suffix}"));
    }
    Ok(result)
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_TIMER_DELAY_MS: u64 = 2_147_483_647;

/// `readOperationTimeout(environment)`.
fn read_operation_timeout(
    environment: &HashMap<String, String>,
) -> Result<u64, JadxConfigurationFailure> {
    let Some(value) = env::lookup(environment, "REA_JADX_OPERATION_TIMEOUT_MS") else {
        return Ok(release::DEFAULT_JADX_OPERATION_TIMEOUT_MS);
    };
    let decimal = !value.is_empty()
        && value.as_bytes()[0] != b'0'
        && value.bytes().all(|byte| byte.is_ascii_digit());
    match value.parse::<u64>() {
        Ok(number) if decimal && (1..=MAX_TIMER_DELAY_MS).contains(&number) => Ok(number),
        _ => Err(configuration_failure(
            ConfigurationFailureCode::OpenOptionsInvalid,
            format!(
                "REA_JADX_OPERATION_TIMEOUT_MS must be a decimal millisecond count from 1 to 2147483647; received {value}."
            ),
            json!({ "setting": "REA_JADX_OPERATION_TIMEOUT_MS", "value": value }),
            JadxFailureKind::OperationTimeout,
        )),
    }
}

/// `resolveJadxOperationTimeout(environment, operation)`.
pub fn resolve_jadx_operation_timeout(
    environment: &HashMap<String, String>,
    operation: &str,
) -> Result<u64, AnalysisError> {
    read_operation_timeout(environment)
        .map_err(|failure| project_configuration_failure(operation, &failure))
}

/// `readJadxConfigurationInputs`.
fn read_jadx_configuration_inputs(
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Result<JadxConfiguration, JadxConfigurationFailure> {
    if cancellation.reason().is_some() {
        return Err(cancelled_marker());
    }
    require_supported_host()?;
    let jar = resolve_jar(environment)?;
    let java = resolve_java(environment, cancellation)?;
    require_java_home_executable(env::lookup(environment, "JAVA_HOME"), &java)?;
    if cancellation.reason().is_some() {
        return Err(cancelled_marker());
    }
    Ok(JadxConfiguration {
        jar,
        java,
        jvm_arguments: resolve_jvm_arguments(environment)?,
    })
}

/// Classify a tagged failure: either a real cancellation or a projected error.
fn project_or_cancel(operation: &str, failure: JadxConfigurationFailure) -> AnalysisError {
    if failure.message == "__cancelled__" {
        AnalysisError::cancelled(operation)
    } else {
        project_configuration_failure(operation, &failure)
    }
}

/// `resolveJadxConfigurationInputs(environment, operation, signal)`.
pub fn resolve_jadx_configuration_inputs(
    environment: &HashMap<String, String>,
    operation: &str,
    cancellation: &Cancellation,
) -> Result<JadxConfiguration, AnalysisError> {
    read_jadx_configuration_inputs(environment, cancellation)
        .map_err(|failure| project_or_cancel(operation, failure))
}

/// `validateJadxConfiguration(configuration, environment, operation, options)`.
///
/// `operation_deadline` is the whole-operation timeout, which also bounds the
/// Java probe; the probe keeps its own 10 s bound.
pub fn validate_jadx_configuration(
    configuration: &JadxConfiguration,
    environment: &HashMap<String, String>,
    operation: &str,
    operation_deadline: Option<u64>,
    cancellation: &Cancellation,
) -> Result<(), AnalysisError> {
    validate_contents(
        configuration,
        environment,
        operation,
        operation_deadline,
        cancellation,
    )
    .map_err(|error| error.project_or(operation))
}

fn validate_contents(
    configuration: &JadxConfiguration,
    environment: &HashMap<String, String>,
    operation: &str,
    operation_deadline: Option<u64>,
    cancellation: &Cancellation,
) -> Result<(), ValidationFailure> {
    if cancellation.reason().is_some() {
        return Err(ValidationFailure::Analysis(AnalysisError::cancelled(
            operation,
        )));
    }
    inspect_java_runtime(
        &configuration.java,
        environment,
        operation,
        operation_deadline,
        cancellation,
    )?;
    super::archive::require_engine_archive(&configuration.jar, operation, cancellation)
        .map_err(ValidationFailure::Analysis)?;
    Ok(())
}

/// A validation failure already carrying either a tagged configuration failure
/// or a fully projected analysis error.
pub enum ValidationFailure {
    Configuration(JadxConfigurationFailure),
    Analysis(AnalysisError),
}

impl ValidationFailure {
    fn project_or(self, operation: &str) -> AnalysisError {
        match self {
            Self::Configuration(failure) => project_or_cancel(operation, failure),
            Self::Analysis(error) => error,
        }
    }
}

fn inspect_java_runtime(
    java: &str,
    environment: &HashMap<String, String>,
    operation: &str,
    operation_deadline: Option<u64>,
    cancellation: &Cancellation,
) -> Result<(), ValidationFailure> {
    match java_probe::inspect_jadx_java(
        java,
        environment,
        operation,
        operation_deadline,
        cancellation,
    ) {
        Ok(_) => Ok(()),
        Err(java_probe::ProbeError::Refusal(refusal)) => Err(ValidationFailure::Configuration(
            refusal_to_configuration(refusal),
        )),
        Err(java_probe::ProbeError::Analysis(error)) => Err(ValidationFailure::Analysis(error)),
    }
}

fn refusal_to_configuration(refusal: JadxJavaProbeRefusal) -> JadxConfigurationFailure {
    let code = match refusal.code {
        java_probe::RefusalCode::RuntimeMissing => ConfigurationFailureCode::RuntimeMissing,
        java_probe::RefusalCode::RuntimeUnavailable => ConfigurationFailureCode::RuntimeUnavailable,
        java_probe::RefusalCode::VersionUnresolved => ConfigurationFailureCode::VersionUnresolved,
        java_probe::RefusalCode::UnsupportedVersion => ConfigurationFailureCode::UnsupportedVersion,
    };
    let kind = match refusal.kind {
        java_probe::RefusalKind::JavaProbe => JadxFailureKind::JavaProbe,
        java_probe::RefusalKind::JavaRuntime => JadxFailureKind::JavaRuntime,
    };
    JadxConfigurationFailure::new(
        code,
        refusal.message,
        Value::Object(refusal.diagnostics),
        kind,
    )
}

/// `inspectJadxAvailability(environment, options)` → ProviderAvailability JSON.
pub fn inspect_jadx_availability(
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
) -> Value {
    let operation = "inspect_jadx_configuration";
    match read_operation_timeout(environment) {
        Ok(operation_timeout_ms) => {
            match read_jadx_configuration_inputs(environment, cancellation) {
                Ok(configuration) => {
                    match validate_contents(
                        &configuration,
                        environment,
                        operation,
                        None,
                        cancellation,
                    ) {
                        Ok(()) => json!({
                            "status": "available",
                            "code": Value::Null,
                            "reason": Value::Null,
                            "diagnostics": {
                                "configured": true,
                                "java_executable": configuration.java,
                                "jdk_compiler": true,
                                "jar_path": configuration.jar,
                                "operation_timeout_ms": operation_timeout_ms,
                            },
                        }),
                        Err(ValidationFailure::Configuration(failure)) => {
                            availability_unavailable(&failure)
                        }
                        Err(ValidationFailure::Analysis(_)) => json!({
                            "status": "unavailable",
                            "code": "runtime_unavailable",
                            "reason": "JADX availability inspection failed",
                            "diagnostics": { "configured": true },
                        }),
                    }
                }
                Err(failure) if failure.message == "__cancelled__" => json!({
                    "status": "unavailable",
                    "code": "runtime_unavailable",
                    "reason": "JADX availability inspection cancelled",
                    "diagnostics": {},
                }),
                Err(failure) => availability_unavailable(&failure),
            }
        }
        Err(failure) => availability_unavailable(&failure),
    }
}

fn availability_unavailable(failure: &JadxConfigurationFailure) -> Value {
    let mut diagnostics = failure.diagnostics.clone();
    diagnostics.insert("failure_kind".into(), json!(failure.kind.as_str()));
    json!({
        "status": "unavailable",
        "code": failure.code.as_str(),
        "reason": failure.message,
        "diagnostics": Value::Object(diagnostics),
    })
}

/// `projectJadxFailureOutcome(kind, configured)` — doctor projection.
pub fn project_jadx_failure_outcome(
    kind: Option<JadxFailureKind>,
    configured: bool,
) -> (String, &'static str) {
    let drift = if configured {
        "config_drift"
    } else {
        "missing_analysis_engine"
    };
    match kind {
        Some(JadxFailureKind::WindowsNativeArtifact) => (
            JADX_WINDOWS_NATIVE_REMEDIATION.to_owned(),
            "missing_dependency",
        ),
        Some(JadxFailureKind::WindowsNativeRuntime) => (
            JADX_WINDOWS_NATIVE_REMEDIATION.to_owned(),
            "runtime_failure",
        ),
        Some(JadxFailureKind::JavaRuntime) => (
            JADX_JAVA_RUNTIME_REMEDIATION.to_owned(),
            "missing_dependency",
        ),
        Some(JadxFailureKind::JavaHome) => (JADX_JAVA_RUNTIME_REMEDIATION.to_owned(), drift),
        Some(JadxFailureKind::JvmOptions) => (JADX_JVM_OPTIONS_REMEDIATION.to_owned(), drift),
        Some(JadxFailureKind::OperationTimeout) => {
            (release::operation_timeout_remediation(), drift)
        }
        Some(JadxFailureKind::Jar) => (release::jar_configuration_remediation(), drift),
        Some(JadxFailureKind::JavaProbe) => (JADX_JAVA_PROBE_REMEDIATION.to_owned(), drift),
        Some(JadxFailureKind::UnsupportedHost) => (
            JADX_UNSUPPORTED_HOST_REMEDIATION.to_owned(),
            "unsupported_host",
        ),
        None => (release::jar_configuration_remediation(), drift),
    }
}

/// The required engine bridge classes (checked by [`super::archive`]).
pub const REQUIRED_ENGINE_CLASSES: [&str; 5] = [
    "com/atxx/jhmcp/JadxSession.class",
    "com/atxx/jhmcp/SessionHolder.class",
    "jadx/api/JadxDecompiler.class",
    "com/google/gson/Gson.class",
    "io/modelcontextprotocol/kotlin/sdk/server/Server.class",
];

/// Referenced to keep the embed-launch dependency visible; the configuration
/// module does not launch the probe child itself.
#[allow(dead_code)]
type UnusedProtocolChild = ProtocolChild;
