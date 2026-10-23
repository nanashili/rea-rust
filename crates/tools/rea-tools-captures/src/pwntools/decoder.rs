//! Owned pwntools process boundary shared by both artifact adapters.
//!
//! Compatibility owner: `src/native/pwntools/PwntoolsDecoder.ts`. A thin owned
//! process adapter: all ELF parsing and heuristics come from the unchanged
//! upstream Python bridges under `bridge/pwntools/`. This module stages one
//! bounded artifact snapshot into a private runtime root, runs the configured
//! Python interpreter against the fixed sibling bridge, reads the bounded
//! reply, and classifies failures by phase.
//!
//! Bridge resolution: TypeScript resolved
//! `new URL("../../../bridge/pwntools/<script>", import.meta.url)` from
//! `dist/native/pwntools/` to `<package root>/bridge/pwntools/<script>`.
//! Natively we resolve the package root from the running executable: take
//! `std::env::current_exe()`, canonicalize it, and walk its ancestor
//! directories selecting the first that contains `bridge/<dir>/<script>`
//! (`bridge/pwntools/...` for the decoder stages, `bridge/pwndbg/...` for the
//! debugger stage). This works for the packaged layout and for dev builds
//! under `native/target/.../rea`. Reading `current_exe` is a host fact, not an
//! environment read.
use crate::artifact::{self, ReadError, ReaderReason};
use crate::node::{self, AccessMode, FsError};
use crate::process::{
    self, CommandError, CommandLimits, OwnedProcess, ProcessSnapshot, ProcessSpec,
};
use crate::pwntools::failures::{self, Cause, Context};
use crate::pwntools::release;
use crate::pwntools::resource_limits::{self, FailureEvidence};
use crate::resources::{AnalysisResources, RootId};
use crate::runtime::RuntimeRoot;
use rea_core::analysis_error::{AnalysisError, CapturedOutput, InputIssue};
use rea_core::cancellation::Cancellation;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;

/// Input-size resolution outcome (`PwntoolsInputBytes`).
pub enum InputBytes {
    Configured(u64),
    Unavailable(String),
}

/// `pwntoolsInputBytes`: resolve the admitted artifact size.
pub fn input_bytes(environment: &HashMap<String, String>) -> InputBytes {
    match environment.get("REA_PWNTOOLS_MAX_INPUT_BYTES") {
        None => InputBytes::Configured(release::INPUT_BYTES),
        Some(value) => {
            let valid = !value.is_empty()
                && value.as_bytes()[0] != b'0'
                && value.bytes().all(|byte| byte.is_ascii_digit());
            let parsed = if valid {
                value.parse::<u64>().ok()
            } else {
                None
            };
            match parsed.filter(|bytes| *bytes <= release::MAXIMUM_INPUT_BYTES) {
                Some(bytes) => InputBytes::Configured(bytes),
                None => InputBytes::Unavailable(format!(
                    "REA_PWNTOOLS_MAX_INPUT_BYTES must be a decimal integer from 1 to {} bytes, and REA never installs Python or packages.",
                    release::MAXIMUM_INPUT_BYTES
                )),
            }
        }
    }
}

/// The artifact snapshot available to a projection.
pub struct Snapshot {
    pub bytes: Vec<u8>,
    pub sha256: String,
}

/// A single owned command stage specification (`OwnedProviderProcessSpawnOptions`).
pub struct OwnedCommand {
    pub command: String,
    pub arguments: Vec<String>,
    pub cwd: String,
    pub run_id: String,
    pub overrides: Vec<(String, String)>,
}

/// Context passed to a projection after a successful payload reply.
pub struct ProjectContext<'a> {
    pub input: &'a Value,
    pub payload: Value,
    pub snapshot: &'a Snapshot,
    pub root_path: &'a str,
    pub diagnostics: &'a CapturedOutput,
    pub environment: &'a HashMap<String, String>,
    pub cancellation: &'a Cancellation,
    /// Run one additional owned command stage (debugger handoff) in the root.
    pub run_command: &'a dyn Fn(OwnedCommand, &str) -> Result<ProcessSnapshot, AnalysisError>,
}

/// Successful result of one decoder run (the projected report plus diagnostics).
pub struct DecoderReport {
    pub result: Value,
    pub subject: rea_core::evidence::envelope::SubjectTarget,
    pub confidence: &'static str,
    pub limitations: Vec<String>,
}

/// Adapter-selected semantics around the owned pwntools process boundary.
pub struct Profile {
    pub operation: &'static str,
    pub bridge_dir: &'static str,
    pub bridge_script: &'static str,
    pub runtime_prefix: &'static str,
    /// Project a successful payload reply into the final report.
    pub project: fn(ProjectContext<'_>) -> Result<DecoderReport, AnalysisError>,
}

/// Resolve `<package root>/bridge/<dir>/<script>` from the running executable.
pub fn resolve_bridge(dir: &str, script: &str) -> Result<String, AnalysisError> {
    let relative: PathBuf = ["bridge", dir, script].iter().collect();
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|error| {
            AnalysisError::provider_adapter(release::PROVIDER_ID, "inspect_binary_layout")
                .with_diagnostics(crate::errors::map([(
                    "reason",
                    json!(format!("Cannot resolve the running executable: {error}")),
                )]))
        })?;
    for ancestor in executable.ancestors().skip(1) {
        let candidate = ancestor.join(&relative);
        if candidate.is_file() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(
        AnalysisError::provider_adapter(release::PROVIDER_ID, "inspect_binary_layout")
            .with_diagnostics(crate::errors::map([(
                "reason",
                json!(format!(
                    "Cannot locate the owned pwntools bridge {}; reinstall the REA package.",
                    relative.display()
                )),
            )])),
    )
}

/// Run one inspection against the owned bridge.
pub fn inspect(
    profile: &Profile,
    resources: &AnalysisResources,
    environment: &HashMap<String, String>,
    cancellation: &Cancellation,
    input: &Value,
    path: &str,
) -> Result<DecoderReport, AnalysisError> {
    resources.run(profile.operation, cancellation, || {
        let mut run = Run::new(profile, resources, environment, cancellation, input, path);
        let result = run.execute();
        resources.finish(
            result,
            |report: &DecoderReport| Some(report.result.clone()),
            profile.operation,
            cancellation,
        )
    })
}

/// One decoder run with its mutable phase/cleanup state.
struct Run<'a> {
    profile: &'a Profile,
    resources: &'a AnalysisResources,
    environment: &'a HashMap<String, String>,
    cancellation: &'a Cancellation,
    input: &'a Value,
    path: &'a str,
    root: Option<RootId>,
    root_path: Option<String>,
    context: Context,
}

/// The reply discriminated union, mirrored from the TS `replySchema`.
enum Reply {
    Ok(Value),
    Fail {
        reason: String,
        message: String,
        reported_limits: Option<Value>,
    },
}

impl<'a> Run<'a> {
    fn new(
        profile: &'a Profile,
        resources: &'a AnalysisResources,
        environment: &'a HashMap<String, String>,
        cancellation: &'a Cancellation,
        input: &'a Value,
        path: &'a str,
    ) -> Self {
        Self {
            profile,
            resources,
            environment,
            cancellation,
            input,
            path,
            root: None,
            root_path: None,
            context: Context::new(profile.operation, release::PROVIDER_ID),
        }
    }

    fn execute(&mut self) -> Result<DecoderReport, AnalysisError> {
        // `configuration` phase.
        if self.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(self.profile.operation));
        }
        self.resources.release()?;
        if !cfg!(target_os = "linux") || !cfg!(target_arch = "x86_64") {
            return Err(failures::errors_unavailable_host(
                release::PROVIDER_ID,
                self.profile.operation,
            ));
        }
        let executable = self
            .environment
            .get("REA_PWNTOOLS_PYTHON")
            .cloned()
            .unwrap_or_default();
        if !node::is_absolute(&executable) {
            return Err(failures::errors_unavailable(
                "Set REA_PWNTOOLS_PYTHON to an absolute caller-supplied Python executable with pwntools 4.15.0, pyelftools 0.33 and Unicorn 2.1.2; REA never installs Python or packages.",
                &executable,
                None,
                None,
                &self.context,
            ));
        }
        self.configure_access(&executable)?;
        let limit = match input_bytes(self.environment) {
            InputBytes::Configured(bytes) => bytes,
            InputBytes::Unavailable(message) => {
                let mut context = self.context.clone();
                context.configuration_key = Some("REA_PWNTOOLS_MAX_INPUT_BYTES".to_owned());
                return Err(failures::errors_unavailable(
                    message,
                    &executable,
                    None,
                    None,
                    &context,
                ));
            }
        };

        // `artifact-read` phase.
        let snapshot = match artifact::read_stable(self.path, limit as usize, self.cancellation) {
            Ok(snapshot) => Snapshot {
                bytes: snapshot.bytes,
                sha256: snapshot.sha256,
            },
            Err(error) => return Err(self.artifact_read_failure(error)),
        };

        // `decoder` phase: create the private runtime root.
        let root = self.create_root()?;
        let request_path = node::join(&root, "request.json");
        let snapshot_path = node::join(&root, "object.snapshot");
        let reply_path = node::join(&root, "reply.json");
        if let Err(error) = crate::producer::write_exclusive(&snapshot_path, &snapshot.bytes, 0o600)
        {
            return Err(self.fs_failure(error));
        }
        let request = json!({ "snapshot_path": snapshot_path, "reply_path": reply_path });
        if let Err(error) =
            crate::producer::write_exclusive(&request_path, request.to_string().as_bytes(), 0o600)
        {
            return Err(self.fs_failure(error));
        }

        let bridge = resolve_bridge(self.profile.bridge_dir, self.profile.bridge_script)?;
        let command = OwnedCommand {
            command: executable.clone(),
            arguments: vec![
                "-I".to_owned(),
                bridge,
                node::join(&root, "resource.failure"),
                request_path,
            ],
            cwd: root.clone(),
            // `runId: \`rea-artifact-decoder-${randomUUID()}\``; the runtime
            // root keeps the provider-specific prefix.
            run_id: process::run_id("rea-artifact-decoder-"),
            overrides: vec![
                ("PWNLIB_NOTERM".to_owned(), "1".to_owned()),
                ("OPENBLAS_NUM_THREADS".to_owned(), "1".to_owned()),
                ("OMP_NUM_THREADS".to_owned(), "1".to_owned()),
            ],
        };
        let snapshot_output = self.run_command(command, self.path, &executable)?;
        let diagnostics = failures::captured(&snapshot_output);

        // Read the bounded reply.
        let reply = self.read_reply(&reply_path, &diagnostics)?;
        let payload = match reply {
            Reply::Ok(payload) => payload,
            Reply::Fail {
                reason,
                message,
                reported_limits,
            } => {
                return Err(self.reply_failure(
                    reason,
                    message,
                    reported_limits,
                    &diagnostics,
                    &snapshot_output,
                ));
            }
        };

        // Project the payload into the final report. The debugger handoff
        // (recorded crash) reuses the same owned runtime root.
        // The debugger stage spawns the same Python interpreter; `arg` is its
        // selected path (gdb), while the executable path stays the interpreter.
        let executable_path = executable.clone();
        let run_command =
            |command: OwnedCommand, arg: &str| self.run_command(command, arg, &executable_path);
        (self.profile.project)(ProjectContext {
            input: self.input,
            payload,
            snapshot: &snapshot,
            root_path: &root,
            diagnostics: &diagnostics,
            environment: self.environment,
            cancellation: self.cancellation,
            run_command: &run_command,
        })
    }

    fn configure_access(&self, executable: &str) -> Result<(), AnalysisError> {
        if let Err(error) = node::access(executable, AccessMode::Execute) {
            return Err(self.configuration_fs_failure(executable, error));
        }
        match node::stat_is_file(executable) {
            Ok(true) => Ok(()),
            Ok(false) => Err(failures::errors_unavailable(
                format!(
                    "Selected Python executable must be a regular executable file, not a directory: {executable}"
                ),
                executable,
                None,
                None,
                &self.context,
            )),
            Err(error) => Err(self.configuration_fs_failure(executable, error)),
        }
    }

    fn configuration_fs_failure(&self, executable: &str, error: FsError) -> AnalysisError {
        failures::decoder_failure(
            Cause::Fs {
                code: error.code,
                message: error.message,
            },
            "configuration",
            executable,
            executable,
            &FailureEvidence::default(),
            &self.context,
        )
    }

    fn artifact_read_failure(&self, error: ReadError) -> AnalysisError {
        match error.reader_reason() {
            Some(ReaderReason::Cancelled) => AnalysisError::cancelled(self.profile.operation),
            Some(ReaderReason::Integrity) => {
                AnalysisError::artifact_changed(self.profile.operation, self.path, error.message())
            }
            Some(reason @ (ReaderReason::Limit | ReaderReason::Path | ReaderReason::Format)) => {
                let issue_reason = if reason == ReaderReason::Limit {
                    "out_of_range"
                } else {
                    "invalid_format"
                };
                AnalysisError::input(
                    self.profile.operation,
                    vec![InputIssue {
                        path: vec![json!("path")],
                        reason: issue_reason,
                        message: Some(error.message()),
                        expected: None,
                        minimum: None,
                        maximum: None,
                    }],
                )
            }
            _ => failures::decoder_failure(
                Cause::Fs {
                    code: error.system_code(),
                    message: error.message(),
                },
                "artifact-read",
                self.path,
                self.path,
                &FailureEvidence::default(),
                &self.context,
            ),
        }
    }

    fn fs_failure(&self, error: FsError) -> AnalysisError {
        failures::decoder_failure(
            Cause::Fs {
                code: error.code,
                message: error.message,
            },
            "decoder",
            self.root_path.as_deref().unwrap_or_default(),
            self.path,
            &FailureEvidence::default(),
            &self.context,
        )
    }

    fn create_root(&mut self) -> Result<String, AnalysisError> {
        let parent = node::tmpdir(self.environment);
        let root =
            RuntimeRoot::create_in(&parent, self.profile.runtime_prefix).map_err(|error| {
                self.fs_failure(FsError::from_io(
                    &error,
                    "mkdtemp",
                    &node::join(&parent, &format!("{}XXXXXX", self.profile.runtime_prefix)),
                ))
            })?;
        let path = root.path().to_owned();
        self.root_path = Some(path.clone());
        self.root = Some(self.resources.retain_root(root));
        Ok(path)
    }

    /// Run one owned command stage, retaining cleanup on incomplete stop.
    fn run_command(
        &self,
        command: OwnedCommand,
        path: &str,
        executable_path: &str,
    ) -> Result<ProcessSnapshot, AnalysisError> {
        let overrides = command
            .overrides
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>();
        let spec = ProcessSpec::new(
            command.command.clone(),
            command.arguments.clone(),
            Some(command.cwd.clone()),
            self.environment,
            &overrides,
            command.run_id.clone(),
        );
        let mut retained: Option<(OwnedProcess, String)> = None;
        let outcome = {
            let mut retain = |process: OwnedProcess, reason: String| {
                retained = Some((process, reason));
            };
            process::run_owned_command(
                &spec,
                CommandLimits {
                    timeout_ms: release::TIMEOUT_MS,
                    diagnostic_bytes: release::DIAGNOSTIC_BYTES,
                    accept_nonzero_exit: false,
                },
                self.cancellation,
                Some(&mut retain),
            )
        };
        match outcome {
            Ok(snapshot) => Ok(snapshot),
            Err(CommandError::Launch(failure)) => Err(failures::decoder_failure(
                Cause::Spawn {
                    code: failure.code.unwrap_or("UNKNOWN").to_owned(),
                },
                "decoder",
                path,
                executable_path,
                &FailureEvidence::default(),
                &self.context,
            )),
            Err(CommandError::Failed(mut failure)) => {
                if let (Some(root), Some((owner, _))) = (self.root, retained.take()) {
                    self.resources.retain_owner(root, owner);
                }
                let evidence = resource_limits::read_failure_evidence(
                    Some(&failure),
                    self.root_path.as_deref(),
                );
                // The owner was moved into resources; drop any duplicate.
                failure.cleanup_owner = None;
                Err(failures::decoder_failure(
                    Cause::Command(failure),
                    "decoder",
                    path,
                    executable_path,
                    &evidence,
                    &self.context,
                ))
            }
        }
    }

    fn read_reply(
        &self,
        reply_path: &str,
        diagnostics: &CapturedOutput,
    ) -> Result<Reply, AnalysisError> {
        let snapshot = match artifact::read_stable(
            reply_path,
            release::OUTPUT_BYTES as usize,
            self.cancellation,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) if error.reader_reason() == Some(ReaderReason::Cancelled) => {
                return Err(AnalysisError::cancelled(self.profile.operation)
                    .with_captured_output(diagnostics.clone()));
            }
            Err(error) => {
                return Err(AnalysisError::output(
                    self.profile.operation,
                    format!(
                        "Owned pwntools decoder reply failed for {}: {}",
                        self.path,
                        error.message()
                    ),
                )
                .with_captured_output(diagnostics.clone()));
            }
        };
        let text = match std::str::from_utf8(&snapshot.bytes) {
            Ok(text) => text,
            Err(error) => {
                return Err(AnalysisError::output(
                    self.profile.operation,
                    format!(
                        "Owned pwntools decoder reply failed for {}: {error}",
                        self.path
                    ),
                )
                .with_captured_output(diagnostics.clone()));
            }
        };
        let value: Value = serde_json::from_str(text).map_err(|error| {
            AnalysisError::output(
                self.profile.operation,
                format!(
                    "Owned pwntools decoder reply failed for {}: {error}",
                    self.path
                ),
            )
            .with_captured_output(diagnostics.clone())
        })?;
        parse_reply(&value).ok_or_else(|| {
            AnalysisError::output(
                self.profile.operation,
                format!(
                    "Owned pwntools decoder reply failed for {}: invalid reply shape at root",
                    self.path
                ),
            )
            .with_captured_output(diagnostics.clone())
        })
    }

    fn reply_failure(
        &self,
        reason: String,
        message: String,
        reported_limits: Option<Value>,
        diagnostics: &CapturedOutput,
        snapshot: &ProcessSnapshot,
    ) -> AnalysisError {
        let output = Some(diagnostics.clone());
        match reason.as_str() {
            "unsupported-target" => failures::with_output_opt(
                AnalysisError::unsupported_target(self.profile.operation, self.path, message),
                output,
            ),
            "resource-limit" => failures::with_output_opt(
                AnalysisError::resource_constraint(
                    self.profile.operation,
                    "memory",
                    message,
                    reported_limits,
                ),
                output,
            ),
            "format" => failures::with_output_opt(
                AnalysisError::input(
                    self.profile.operation,
                    vec![InputIssue {
                        path: vec![json!("path")],
                        reason: "invalid_format",
                        message: Some(message),
                        expected: None,
                        minimum: None,
                        maximum: None,
                    }],
                ),
                output,
            ),
            "unavailable" => failures::errors_unavailable(
                message,
                self.environment
                    .get("REA_PWNTOOLS_PYTHON")
                    .map(String::as_str)
                    .unwrap_or_default(),
                None,
                output,
                &self.context,
            ),
            "unsupported" => failures::with_output_opt(
                AnalysisError::capability_unavailable(
                    release::PROVIDER_ID,
                    self.profile.operation,
                    message.clone(),
                )
                .with_user_message(message),
                output,
            ),
            "output-limit" => failures::with_output_opt(
                AnalysisError::output(self.profile.operation, message),
                output,
            ),
            other => {
                let mut diagnostics_object = crate::errors::map([
                    ("phase", json!("decoder")),
                    ("failure_kind", json!(other)),
                    ("reason", json!(message)),
                    ("stdout", json!(snapshot.stdout.text)),
                    ("stderr", json!(snapshot.stderr.text)),
                ]);
                diagnostics_object.insert(
                    "captured_output".into(),
                    json!({
                        "stdout": diagnostics.stdout,
                        "stderr": diagnostics.stderr,
                        "truncated": diagnostics.truncated,
                    }),
                );
                crate::errors::provider_adapter(
                    release::PROVIDER_ID,
                    self.profile.operation,
                    Some(diagnostics_object),
                    None,
                )
            }
        }
    }
}

/// Parse the discriminated reply (`replySchema`).
fn parse_reply(value: &Value) -> Option<Reply> {
    let object = value.as_object()?;
    match object.get("ok")?.as_bool()? {
        true => {
            if object.get("profile")?.as_str()? != release::PROVIDER_VERSION {
                return None;
            }
            Some(Reply::Ok(object.get("value")?.clone()))
        }
        false => {
            let reason = object.get("reason")?.as_str()?;
            if !matches!(
                reason,
                "format"
                    | "unsupported"
                    | "unsupported-target"
                    | "unavailable"
                    | "resource-limit"
                    | "output-limit"
                    | "decoder"
            ) {
                return None;
            }
            let message = object.get("message")?.as_str()?.to_owned();
            let reported_limits = object.get("reported_limits").and_then(|value| {
                if value.is_null() {
                    None
                } else {
                    Some(value.clone())
                }
            });
            Some(Reply::Fail {
                reason: reason.to_owned(),
                message,
                reported_limits,
            })
        }
    }
}
