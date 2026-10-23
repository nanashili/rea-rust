//! Java module-listing probe (`java --list-modules`).
//!
//! Compatibility owner: `src/android/JadxJavaProbe.ts`. One complete module
//! listing is interpreted before cleanup. A nonzero exit is accepted and then
//! classified; ENOENT spawn failures become a `runtime_missing` refusal.

use super::release::JADX_PROVIDER_ID;
use crate::common::errors::capability_unavailable;
use crate::common::process::{CommandLimits, CommandSpec, FailureKind, OutputBudget, run_command};
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use regex::Regex;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::time::Duration;

const JAVA_MODULE_LISTING_TIMEOUT_MS: u64 = 10_000;
const JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalCode {
    RuntimeMissing,
    RuntimeUnavailable,
    VersionUnresolved,
    UnsupportedVersion,
}

impl RefusalCode {
    fn as_str(self) -> &'static str {
        match self {
            Self::RuntimeMissing => "runtime_missing",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::VersionUnresolved => "version_unresolved",
            Self::UnsupportedVersion => "unsupported_version",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusalKind {
    JavaProbe,
    JavaRuntime,
}

impl RefusalKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::JavaProbe => "java_probe",
            Self::JavaRuntime => "java_runtime",
        }
    }
}

/// A Java probe refusal (projected by the configuration boundary).
#[derive(Clone, Debug)]
pub struct JadxJavaProbeRefusal {
    pub code: RefusalCode,
    pub message: String,
    pub diagnostics: Map<String, Value>,
    pub kind: RefusalKind,
}

/// Observed modules: full JDK with a parseable `java.base` major version.
#[derive(Clone, Copy, Debug)]
pub struct JavaModules {
    pub major: u64,
}

/// A failure from the probe: either a refusal or an already-projected error.
pub enum ProbeError {
    Refusal(JadxJavaProbeRefusal),
    Analysis(AnalysisError),
}

fn refusal(
    code: RefusalCode,
    message: impl Into<String>,
    diagnostics: Value,
    kind: RefusalKind,
) -> JadxJavaProbeRefusal {
    JadxJavaProbeRefusal {
        code,
        message: message.into(),
        diagnostics: match diagnostics {
            Value::Object(map) => map,
            _ => Map::new(),
        },
        kind,
    }
}

/// `projectRefusal(failure, operation, cause, output)`.
pub fn project_refusal(
    failure: &JadxJavaProbeRefusal,
    operation: &str,
    output: Option<&CapturedOutput>,
) -> AnalysisError {
    let mut facts = failure.diagnostics.clone();
    facts.remove("stdout");
    facts.remove("stderr");
    facts.insert("failure_kind".into(), json!(failure.kind.as_str()));
    facts.insert("failure_code".into(), json!(failure.code.as_str()));
    let mut error = capability_unavailable(
        JADX_PROVIDER_ID,
        operation,
        failure.message.clone(),
        Some(failure.message.clone()),
        Some(facts),
    );
    if let Some(output) = output {
        error.captured_output = Some(output.clone());
    }
    error
}

/// `inspectJadxJava(java, environment, options)`.
///
/// `operation_deadline` (the whole-operation timeout, when known) distinguishes
/// a timeout-driven cancellation from a caller cancellation.
pub fn inspect_jadx_java(
    java: &str,
    _environment: &HashMap<String, String>,
    operation: &str,
    _operation_deadline: Option<u64>,
    cancellation: &Cancellation,
) -> Result<JavaModules, ProbeError> {
    let spec = CommandSpec::new(java, ["--list-modules"]);
    let limits = CommandLimits {
        timeout: Duration::from_millis(JAVA_MODULE_LISTING_TIMEOUT_MS),
        budget: OutputBudget::Combined(JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES),
    };
    match run_command(&spec, limits, cancellation, true) {
        Ok(output) => parse_java_modules(
            java,
            output.exit_code,
            None,
            &output.stdout_text(),
            &output.stderr_text(),
            output.truncated,
        )
        .map_err(ProbeError::Refusal),
        Err(failure) => {
            let captured = Some(failure.output.captured());
            match &failure.kind {
                FailureKind::Cancelled { reason } => {
                    // A late cancellation after a successful module listing is
                    // still a cancellation; the TS path returns the refusal only
                    // if cleanup succeeded (it did, since no child is retained).
                    let mut error = AnalysisError::cancelled(operation);
                    let _ = reason;
                    if let Some(output) = captured {
                        error.captured_output = Some(output);
                    }
                    Err(ProbeError::Analysis(error))
                }
                FailureKind::Settlement => {
                    // Cleanup could not be proven; project as a provider adapter
                    // failure. (The native launcher rarely reaches this path.)
                    let mut error = crate::common::errors::provider_adapter(
                        JADX_PROVIDER_ID,
                        operation,
                        None,
                        Some(crate::common::errors::object(json!({ "stage": "cleanup" }))),
                    );
                    error.captured_output = captured;
                    Err(ProbeError::Analysis(error))
                }
                kind => {
                    let probe_refusal = command_probe_refusal(
                        java,
                        kind,
                        &failure.output.stdout_text(),
                        &failure.output.stderr_text(),
                        failure.output.exit_code,
                        failure.output.truncated,
                    );
                    Err(ProbeError::Refusal(probe_refusal))
                }
            }
        }
    }
}

/// `commandProbeRefusal(java, command, cause, timeoutMs)` for a failed run.
fn command_probe_refusal(
    java: &str,
    kind: &FailureKind,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i64>,
    truncated: bool,
) -> JadxJavaProbeRefusal {
    let enoent = matches!(kind, FailureKind::Launch { .. }) && kind.program_not_found();
    let limited = matches!(kind, FailureKind::OutputLimit);
    let timed_out = matches!(kind, FailureKind::Timeout);
    let system_code = enoent.then_some("ENOENT");
    let code = if enoent {
        RefusalCode::RuntimeMissing
    } else if limited || timed_out {
        RefusalCode::VersionUnresolved
    } else {
        RefusalCode::RuntimeUnavailable
    };
    let refusal_kind = if enoent {
        RefusalKind::JavaRuntime
    } else {
        RefusalKind::JavaProbe
    };
    let message = if limited {
        format!(
            "The selected Java launcher {java} exceeded the {} MiB output budget while listing modules. REA retained partial output but could not establish compiler or version availability. Inspect the selected launcher for verbose or unbounded output; java --list-modules should return a concise module listing.",
            JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES / (1024 * 1024)
        )
    } else if timed_out {
        format!(
            "The selected Java launcher {java} did not finish the module-listing probe within {} seconds. Inspect its startup responsiveness and verify it with java --list-modules.",
            JAVA_MODULE_LISTING_TIMEOUT_MS / 1000
        )
    } else {
        let reason = if enoent {
            "spawn java ENOENT".to_owned()
        } else if matches!(kind, FailureKind::Launch { message, .. } if !message.is_empty()) {
            match kind {
                FailureKind::Launch { message, .. } => message.clone(),
                _ => String::new(),
            }
        } else {
            format!(
                "exit {}",
                exit_code.map_or_else(|| "unknown".to_owned(), |code| code.to_string())
            )
        };
        format!(
            "Cannot inspect selected Java runtime {java}: {reason}. Review the selected launcher and retained diagnostics."
        )
    };
    let mut diagnostics = Map::new();
    diagnostics.insert("java_executable".into(), json!(java));
    diagnostics.insert("phase".into(), json!("module-inspection"));
    diagnostics.insert("exit_code".into(), json!(exit_code));
    diagnostics.insert("process_error_code".into(), json!(system_code));
    diagnostics.insert("signal".into(), Value::Null);
    diagnostics.insert("killed".into(), Value::Null);
    diagnostics.insert("stdout".into(), json!(stdout));
    diagnostics.insert("stderr".into(), json!(stderr));
    diagnostics.insert("output_truncated".into(), json!(truncated));
    if limited {
        diagnostics.insert("failure".into(), json!("output_limit"));
        diagnostics.insert(
            "output_limit_bytes".into(),
            json!(JAVA_MODULE_LISTING_MAX_OUTPUT_BYTES),
        );
    }
    if timed_out {
        diagnostics.insert("failure".into(), json!("probe_terminated"));
        diagnostics.insert("deadline_ms".into(), json!(JAVA_MODULE_LISTING_TIMEOUT_MS));
    }
    JadxJavaProbeRefusal {
        code,
        message,
        diagnostics,
        kind: refusal_kind,
    }
}

/// `parseJavaModules(java, snapshot)`.
fn parse_java_modules(
    java: &str,
    exit_code: Option<i64>,
    signal: Option<&str>,
    stdout: &str,
    stderr: &str,
    truncated: bool,
) -> Result<JavaModules, JadxJavaProbeRefusal> {
    if exit_code != Some(0) || signal.is_some() {
        return Err(command_probe_refusal(
            java,
            &FailureKind::Exit,
            stdout,
            stderr,
            exit_code,
            truncated,
        ));
    }
    let compiler = Regex::new(r"(?m)^jdk\.compiler(?:@|$)")
        .expect("valid regex")
        .is_match(stdout);
    if !compiler {
        return Err(refusal(
            RefusalCode::RuntimeMissing,
            format!(
                "Selected Java runtime {java} does not provide jdk.compiler. Select a full JDK including jdk.compiler via JAVA_HOME or PATH; verify it with java --list-modules. A JRE cannot compile REA's source bridge."
            ),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": false,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": false,
            }),
            RefusalKind::JavaRuntime,
        ));
    }
    let base = Regex::new(r"(?m)^java\.base@(\d+)(?:[.+_-]|$)").expect("valid regex");
    let major = base.captures(stdout).map(|captures| captures[1].to_owned());
    let Some(major) = major else {
        return Err(refusal(
            RefusalCode::VersionUnresolved,
            format!(
                "The selected Java launcher {java} did not report a parseable java.base version in its module listing. Inspect the launcher output and verify it with java --list-modules."
            ),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": true,
                "java_major": Value::Null,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": false,
            }),
            RefusalKind::JavaProbe,
        ));
    };
    let major_number = major.parse::<u64>().ok();
    let Some(major_number) =
        major_number.filter(|number| *number > 0 && *number <= MAX_SAFE_INTEGER)
    else {
        return Err(refusal(
            RefusalCode::VersionUnresolved,
            format!(
                "The selected Java launcher {java} reported an invalid java.base major version. Review the retained module listing."
            ),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": true,
                "java_major": Value::Null,
                "unparsed_java_major": major,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": false,
            }),
            RefusalKind::JavaProbe,
        ));
    };
    if major_number < 17 {
        return Err(refusal(
            RefusalCode::UnsupportedVersion,
            format!(
                "Selected Java runtime {java} must be JDK 17 or newer and include jdk.compiler; verify it with java --list-modules."
            ),
            json!({
                "java_executable": java,
                "phase": "module-inspection",
                "jdk_compiler": true,
                "java_major": major,
                "stdout": stdout,
                "stderr": stderr,
                "output_truncated": false,
            }),
            RefusalKind::JavaRuntime,
        ));
    }
    Ok(JavaModules {
        major: major_number,
    })
}

const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
