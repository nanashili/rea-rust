//! Bounded Linux producers run through util-linux prlimit.
//!
//! Compatibility owners: the shared `#executeRequest`/`#failure` skeleton of
//! `src/captures/TsharkCaptureProvider.ts` and
//! `src/signals/SigrokRecordingProvider.ts`. Each request re-establishes the
//! configured tool and limiter identities, runs every command under the
//! effective inherited limits in a private runtime root, re-verifies both
//! executables after each command, and classifies failures by phase.
use crate::artifact::{self, ReadError, ReaderReason};
use crate::errors::{self, map};
use crate::limits::{self, LinuxLimits, ProducerLimits};
use crate::node::{self, AccessMode, FsError};
use crate::process::{
    self, CommandError, CommandFailure, CommandLimits, ProcessSnapshot, ProcessSpec,
};
use crate::resources::{AnalysisResources, RootId};
use crate::runtime::RuntimeRoot;
use rea_core::analysis_error::{AnalysisError, CapturedOutput};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{EvidenceProvider, SubjectTarget};
use serde_json::{Map, Value, json};
use std::collections::HashMap;

/// Static identity and wording of one bounded producer adapter.
pub struct ProducerConfig {
    pub provider_id: &'static str,
    pub provider_name: &'static str,
    pub provider_version: &'static str,
    pub command_variable: &'static str,
    pub limiter_variable: &'static str,
    pub platform_message: &'static str,
    pub configure_message: &'static str,
    pub executable_changed: &'static str,
    pub capability_suffix: &'static str,
    pub run_prefix: &'static str,
    pub root_prefix: &'static str,
}

impl ProducerConfig {
    pub fn provider(&self) -> EvidenceProvider {
        EvidenceProvider::new(
            self.provider_id,
            self.provider_name,
            Some(self.provider_version.to_owned()),
        )
    }
}

/// Request phase used to classify failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Configuration,
    Artifact,
    Workspace,
    Producer,
    Integrity,
}

/// Every failure cause the original `#failure` classified.
#[derive(Debug)]
pub enum Cause {
    /// Already typed.
    Analysis(AnalysisError),
    /// A raw `Error` with its message and optional system code.
    Raw {
        message: String,
        code: Option<&'static str>,
    },
    /// A stable-read failure.
    Read(ReadError),
    /// An owned-command failure.
    Command(Box<CommandFailure>),
    /// A representation budget was exceeded.
    Budget { message: String, limits: Value },
}

impl From<AnalysisError> for Cause {
    fn from(error: AnalysisError) -> Self {
        Self::Analysis(error)
    }
}

impl From<FsError> for Cause {
    fn from(error: FsError) -> Self {
        Self::Raw {
            message: error.message,
            code: error.code,
        }
    }
}

impl From<ReadError> for Cause {
    fn from(error: ReadError) -> Self {
        Self::Read(error)
    }
}

impl Cause {
    pub fn raw(message: impl Into<String>) -> Self {
        Self::Raw {
            message: message.into(),
            code: None,
        }
    }
}

/// One successful provider execution before Evidence identity.
#[derive(Clone, Debug)]
pub struct Execution {
    pub result: Value,
    pub subject: SubjectTarget,
    pub locations: Vec<Value>,
    pub limitations: Vec<String>,
}

/// Output of one completed producer command.
pub struct Output {
    pub snapshot: ProcessSnapshot,
}

impl Output {
    pub fn stdout(&self) -> &str {
        &self.snapshot.stdout.text
    }
    pub fn stderr(&self) -> &str {
        &self.snapshot.stderr.text
    }
}

/// Mutable request state of one bounded producer request.
pub struct Request<'a> {
    pub config: &'static ProducerConfig,
    pub resources: &'a AnalysisResources,
    pub environment: &'a HashMap<String, String>,
    pub cancellation: &'a Cancellation,
    pub operation: &'static str,
    pub limits: ProducerLimits,
    pub phase: Phase,
    pub captured: Option<CapturedOutput>,
    pub resource_path: String,
    pub effective: Option<LinuxLimits>,
    pub root: Option<RootId>,
    pub root_path: Option<String>,
    pub configured: String,
    pub command: String,
    pub tool_sha256: String,
    pub configured_limiter: String,
    pub limiter: String,
    pub limiter_sha256: String,
    pub limit_arguments: Vec<String>,
    pub overrides: Vec<(String, String)>,
    pub version: Option<Output>,
    /// Input artifact path when the request reads one.
    pub input_path: Option<String>,
}

const TOOL_BYTES: usize = 64 * 1024 * 1024;

impl<'a> Request<'a> {
    pub fn new(
        config: &'static ProducerConfig,
        resources: &'a AnalysisResources,
        environment: &'a HashMap<String, String>,
        cancellation: &'a Cancellation,
        operation: &'static str,
        limits: ProducerLimits,
        input_path: Option<String>,
        initial_resource: &str,
    ) -> Self {
        Self {
            config,
            resources,
            environment,
            cancellation,
            operation,
            limits,
            phase: Phase::Configuration,
            captured: None,
            resource_path: input_path
                .clone()
                .unwrap_or_else(|| initial_resource.to_owned()),
            effective: None,
            root: None,
            root_path: None,
            configured: String::new(),
            command: String::new(),
            tool_sha256: String::new(),
            configured_limiter: String::new(),
            limiter: String::new(),
            limiter_sha256: String::new(),
            limit_arguments: Vec::new(),
            overrides: Vec::new(),
            version: None,
            input_path,
        }
    }

    /// Establish tool and limiter identities, limits and the private root.
    pub fn prepare(&mut self) -> Result<(), Cause> {
        if self.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(self.operation).into());
        }
        self.resources.release()?;
        if !cfg!(target_os = "linux") {
            return Err(Cause::raw(self.config.platform_message));
        }
        self.configured = self
            .environment
            .get(self.config.command_variable)
            .cloned()
            .unwrap_or_default();
        if !node::is_absolute(&self.configured) {
            return Err(Cause::raw(self.config.configure_message));
        }
        self.command = node::realpath(&self.configured)?;
        node::access(&self.command, AccessMode::Execute)?;
        self.tool_sha256 =
            artifact::read_stable(&self.command, TOOL_BYTES, self.cancellation)?.sha256;
        self.configured_limiter = self
            .environment
            .get(self.config.limiter_variable)
            .cloned()
            .unwrap_or_else(|| "/usr/bin/prlimit".to_owned());
        if !node::is_absolute(&self.configured_limiter) {
            return Err(Cause::raw(format!(
                "{} must be absolute.",
                self.config.limiter_variable
            )));
        }
        self.limiter = node::realpath(&self.configured_limiter)?;
        node::access(&self.limiter, AccessMode::Execute)?;
        self.limiter_sha256 =
            artifact::read_stable(&self.limiter, TOOL_BYTES, self.cancellation)?.sha256;
        let effective = limits::read_linux_limits(self.limits.linux()).map_err(Cause::raw)?;
        self.effective = Some(effective);
        self.limit_arguments = limits::prlimit_arguments(effective, &self.command);
        self.phase = Phase::Workspace;
        let parent = node::tmpdir(self.environment);
        let root = RuntimeRoot::create_in(&parent, self.config.root_prefix).map_err(|error| {
            Cause::from(FsError::from_io(
                &error,
                "mkdtemp",
                &node::join(&parent, &format!("{}XXXXXX", self.config.root_prefix)),
            ))
        })?;
        self.root_path = Some(root.path().to_owned());
        self.root = Some(self.resources.retain_root(root));
        Ok(())
    }

    pub fn root_path(&self) -> &str {
        self.root_path.as_deref().unwrap_or_default()
    }

    /// Run one producer command under the limiter and re-verify identities.
    pub fn execute(&mut self, arguments: &[String]) -> Result<Output, Cause> {
        self.captured = None;
        let mut argv = self.limit_arguments.clone();
        argv.extend(arguments.iter().cloned());
        let overrides = self
            .overrides
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let spec = ProcessSpec::new(
            self.limiter.clone(),
            argv,
            self.root_path.clone(),
            self.environment,
            &overrides,
            process::run_id(self.config.run_prefix),
        );
        let snapshot = match process::run_owned_command(
            &spec,
            CommandLimits {
                timeout_ms: self.limits.command_timeout_ms,
                diagnostic_bytes: self.limits.output_bytes as usize,
                accept_nonzero_exit: true,
            },
            self.cancellation,
            None,
        ) {
            Ok(snapshot) => snapshot,
            Err(CommandError::Launch(failure)) => {
                return Err(Cause::Raw {
                    message: failure.message,
                    code: failure.code,
                });
            }
            Err(CommandError::Failed(mut failure)) => {
                if let (Some(root), Some(owner)) = (self.root, failure.cleanup_owner.take()) {
                    self.resources.retain_owner(root, owner);
                }
                return Err(Cause::Command(failure));
            }
        };
        let captured = errors::captured_from(&snapshot);
        self.captured = Some(captured.clone());
        let previous = self.phase;
        self.phase = Phase::Integrity;
        self.resource_path = self.command.clone();
        let current = artifact::read_stable_uncancelled(&self.command, TOOL_BYTES)?;
        self.resource_path = self.limiter.clone();
        let current_limiter = artifact::read_stable_uncancelled(&self.limiter, TOOL_BYTES)?;
        if current_limiter.sha256 != self.limiter_sha256 {
            return Err(AnalysisError::artifact_changed(
                self.operation,
                self.limiter.clone(),
                "Configured resource limiter changed during analysis.",
            )
            .with_captured_output(captured)
            .into());
        }
        if current.sha256 != self.tool_sha256 {
            return Err(AnalysisError::artifact_changed(
                self.operation,
                self.command.clone(),
                self.config.executable_changed,
            )
            .with_captured_output(captured)
            .into());
        }
        self.phase = previous;
        self.resource_path = self
            .input_path
            .clone()
            .unwrap_or_else(|| self.command.clone());
        if snapshot.exit_code != Some(0) {
            return Err(errors::provider_adapter(
                self.config.provider_id,
                self.operation,
                Some(map([
                    ("exit_code", json!(snapshot.exit_code)),
                    ("stdout", json!(snapshot.stdout.text)),
                    ("stderr", json!(snapshot.stderr.text)),
                ])),
                None,
            )
            .into());
        }
        Ok(Output { snapshot })
    }

    /// Run `--version` and retain its banner for every report.
    pub fn probe_version(&mut self) -> Result<&Output, Cause> {
        self.phase = Phase::Configuration;
        let output = self.execute(&["--version".to_owned()])?;
        self.version = Some(output);
        Ok(self.version.as_ref().expect("version was just retained"))
    }

    /// The `tool`, `resource_limiter` and `diagnostics` report members.
    pub fn tool(&self, arguments: &[String]) -> Value {
        let version = self.version.as_ref();
        errors::object([
            ("configured_path", json!(self.configured)),
            ("path", json!(self.command)),
            ("sha256", json!(self.tool_sha256)),
            (
                "version_banner",
                json!(version.map(Output::stdout).unwrap_or_default()),
            ),
            (
                "version_diagnostics",
                json!(version.map(Output::stderr).unwrap_or_default()),
            ),
            ("arguments", json!(arguments)),
        ])
    }

    pub fn resource_limiter(&self) -> Value {
        errors::object([
            ("configured_path", json!(self.configured_limiter)),
            ("path", json!(self.limiter)),
            ("sha256", json!(self.limiter_sha256)),
            ("arguments", json!(self.limit_arguments)),
        ])
    }

    pub fn limits_report(&self) -> Map<String, Value> {
        self.limits
            .report(self.effective.unwrap_or_else(|| self.limits.linux()))
    }

    /// Write the private input copy (`writeFile(path, bytes, { flag: "wx", mode: 0o400 })`).
    pub fn write_snapshot(&self, name: &str, bytes: &[u8]) -> Result<String, Cause> {
        let path = node::join(self.root_path(), name);
        write_exclusive(&path, bytes, 0o400)?;
        Ok(path)
    }

    /// Create a private subdirectory (`mkdir(path, { mode: 0o700 })`).
    pub fn make_directory(&self, name: &str) -> Result<String, Cause> {
        let path = node::join(self.root_path(), name);
        make_private_directory(&path)?;
        Ok(path)
    }

    /// Classify one failure exactly like the original `#failure`.
    pub fn failure(&self, cause: Cause) -> AnalysisError {
        let operation = self.operation;
        let observed = self.captured.as_ref();
        match cause {
            Cause::Analysis(error) => error,
            Cause::Read(error @ ReadError::Cleanup { .. }) => self.resources.read_cleanup_failure(
                &error,
                |primary| self.failure(Cause::Read(primary.clone())),
                observed,
                operation,
            ),
            Cause::Read(error) if error.reader_reason() == Some(ReaderReason::Cancelled) => {
                errors::with_output(AnalysisError::cancelled(operation), observed)
            }
            Cause::Budget { message, limits } => errors::with_output(
                AnalysisError::resource_constraint(operation, "memory", message, Some(limits)),
                observed,
            ),
            Cause::Command(failure) => AnalysisResources::command_failure(
                &failure,
                self.limits.command_timeout_ms,
                self.limits.output_bytes,
                self.effective,
                operation,
            ),
            cause => self.classify_plain(cause),
        }
    }

    fn classify_plain(&self, cause: Cause) -> AnalysisError {
        let operation = self.operation;
        let observed = self.captured.as_ref();
        let (reason, code, reader) = match &cause {
            Cause::Raw { message, code } => (message.clone(), *code, None),
            Cause::Read(error) => (error.message(), error.system_code(), error.reader_reason()),
            _ => (String::new(), None, None),
        };
        let path = self.resource_path.as_str();
        match self.phase {
            Phase::Workspace => {
                if let Some(code @ ("ENOSPC" | "EDQUOT" | "EFBIG")) = code {
                    return AnalysisError::resource_constraint(
                        operation,
                        "file-size",
                        format!("Private analysis workspace failed ({code}): {reason}"),
                        Some(json!({
                            "workspace_path": self.root_path,
                            "system_code": code,
                        })),
                    );
                }
                errors::provider_adapter(
                    self.config.provider_id,
                    operation,
                    Some(map([
                        ("stage", json!("workspace")),
                        ("workspace_path", json!(self.root_path)),
                        ("system_code", json!(code)),
                        ("reason", json!(reason)),
                    ])),
                    Some(format!(
                        "Cannot prepare the private analysis workspace: {reason}"
                    )),
                )
            }
            Phase::Integrity => {
                if matches!(
                    reader,
                    Some(ReaderReason::Limit | ReaderReason::Integrity | ReaderReason::Path)
                ) {
                    return errors::with_output(
                        AnalysisError::artifact_changed(
                            operation,
                            path,
                            format!("Post-run identity verification failed for {path}: {reason}"),
                        ),
                        observed,
                    );
                }
                errors::with_output(
                    errors::provider_adapter(
                        self.config.provider_id,
                        operation,
                        Some(map([
                            ("stage", json!("integrity")),
                            ("resource_path", json!(path)),
                            ("reason", json!(reason)),
                        ])),
                        None,
                    ),
                    observed,
                )
            }
            Phase::Configuration => errors::with_output(
                errors::capability(
                    self.config.provider_id,
                    operation,
                    &reason,
                    Some(format!("{reason}{}", self.config.capability_suffix)),
                ),
                observed,
            ),
            phase => {
                if phase == Phase::Artifact && reader == Some(ReaderReason::Limit) {
                    return AnalysisError::resource_constraint(
                        operation,
                        "file-size",
                        reason,
                        Some(json!({ "input_bytes": limits::BOUNDED_PRODUCER_LIMITS.input_bytes })),
                    );
                }
                if reader == Some(ReaderReason::Integrity) {
                    return AnalysisError::artifact_changed(operation, path, reason);
                }
                if phase == Phase::Artifact
                    && let Some(code @ ("EACCES" | "EPERM")) = code
                {
                    return AnalysisError::access_denied(operation, path, code);
                }
                if phase == Phase::Artifact {
                    return errors::input_issue(
                        operation,
                        vec![errors::segment("path")],
                        "invalid_value",
                        reason,
                    );
                }
                errors::with_output(AnalysisError::output(operation, reason), observed)
            }
        }
    }
}

/// Create a new file exclusively with the selected POSIX mode.
pub fn write_exclusive(path: &str, bytes: &[u8], mode: u32) -> Result<(), FsError> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options
        .open(path)
        .map_err(|error| FsError::from_io(&error, "open", path))?;
    file.write_all(bytes)
        .map_err(|error| FsError::from_io(&error, "write", path))?;
    Ok(())
}

/// `mkdir(path, { mode: 0o700 })`.
pub fn make_private_directory(path: &str) -> Result<(), FsError> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|error| FsError::from_io(&error, "mkdir", path))
}

/// Service-level Evidence (`#evidence`): late cancellation keeps the observation.
pub fn evidence(
    operation: &str,
    parameters: Value,
    provider: &EvidenceProvider,
    execution: Execution,
    cancellation: &Cancellation,
) -> Result<rea_core::evidence::envelope::Evidence, AnalysisError> {
    let observation =
        rea_core::evidence::envelope::Observation::new(operation, parameters, execution.result)
            .confidence("observed")
            .locations(execution.locations)
            .limitations(execution.limitations);
    let evidence = rea_mcp::support::evidence(Some(&execution.subject), provider, observation)?;
    if cancellation.reason().is_some() {
        return Err(
            AnalysisError::cancelled(operation).retain_partial_observation(evidence.into_value())
        );
    }
    Ok(evidence)
}

/// Partial Evidence for late cancellation inside the provider (`finish`).
pub fn partial_evidence(
    operation: &str,
    parameters: &Value,
    provider: &EvidenceProvider,
    execution: &Execution,
) -> Option<Value> {
    let observation = rea_core::evidence::envelope::Observation::new(
        operation,
        parameters.clone(),
        execution.result.clone(),
    )
    .confidence("observed")
    .locations(execution.locations.clone())
    .limitations(execution.limitations.clone());
    rea_mcp::support::evidence(Some(&execution.subject), provider, observation)
        .ok()
        .map(rea_core::evidence::envelope::Evidence::into_value)
}

/// Subject for an artifact or tool observed by its stable identity.
pub fn file_subject(path: &str, sha256: &str) -> SubjectTarget {
    SubjectTarget {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        format: "file".to_owned(),
        architecture: None,
    }
}

/// UTF-8 byte length of a JavaScript string argument.
pub fn utf8_length(text: &str) -> usize {
    text.len()
}
