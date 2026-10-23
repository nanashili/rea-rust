//! Caller-supplied WABT execution against private copies of exactly selected
//! bytes.
//!
//! Compatibility owners: `src/wasm/WabtArtifactProvider.ts`,
//! `src/wasm/WabtRuntime.ts`, `src/wasm/WabtRelease.ts`,
//! `src/wasm/WabtOutput.ts`, `src/wasm/WabtWat.ts`, `src/wasm/WabtInterface.ts`,
//! `src/wasm/WabtString.ts`, `src/wasm/WasmGlueAdapter.ts`,
//! `src/wasm/WasmInterfaceBudget.ts` and `src/wasm/WabtFailures.ts`.
//!
//! This module replaces the previous `rea_application::wasm::producer` execution
//! layer, which ran WABT against the caller's path with `std::process::Command`
//! on unix, read `REA_WABT_BIN_DIRECTORY` through `std::env`, wrote no private
//! snapshot, never re-verified that snapshot between commands, added a `\0asm`
//! precheck that the TypeScript provider does not perform, and returned a plain
//! input failure for a WABT validation rejection instead of the TypeScript
//! `AnalysisInputError` carrying complete partial Evidence plus captured output.
//!
//! The verified WAT/objdump parsing and the interface/glue projection are
//! copied from that producer (each function verified against the TypeScript
//! oracle) rather than called, because they are private there.
use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rea_core::analysis_error::{AnalysisError, CapturedOutput, CleanupObservation, InputIssue};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_host::fs::stable_file::{self, Snapshot};
use rea_host::process::launcher::{ChildLaunchSpec, OwnedChildProcess, ProcessLaunchError};
use rea_host::process::windows::job::WindowsJobLimits;
use rea_mcp::{SessionResource, ToolContext};
use serde_json::{Map, Value, json};
use sha2::Digest;

use crate::common::{HostFiles, host_files};

pub(crate) const OPERATION: &str = "inspect_wasm_artifact";

// `WABT_LIMITS` (`src/wasm/WabtRelease.ts`).
const INPUT_BYTES: usize = 8 * 1024 * 1024;
const TOOL_BYTES: usize = 64 * 1024 * 1024;
const OUTPUT_BYTES: usize = 32 * 1024 * 1024;
const TIMEOUT_MS: u64 = 30_000;
const OUTPUT_LIMIT_EXCERPT_BYTES: usize = 4096;

// `WABT_PROVIDER_IDENTITY` (`src/wasm/WabtRelease.ts`).
const PROVIDER_ID: &str = "wabt-artifact";
const PROVIDER_NAME: &str = "REA WABT artifact adapter";
const PROVIDER_VERSION: &str = "wabt@1.0.42";

const INTERFACE_KINDS: [&str; 5] = ["func", "table", "memory", "global", "tag"];
const MAX_INTERFACE_ENTRIES: usize = 10_000;
const MAX_INTERFACE_REPRESENTATION: usize = 32 * 1024 * 1024;
const VALUE_TYPES: [&str; 7] = ["i32", "i64", "f32", "f64", "v128", "funcref", "externref"];

const LIMITATIONS: [&str; 5] = [
    "WAT is a decoded representation, not original source or proof of runtime behavior. Custom annotations may retain payloads, but WAT does not establish original binary layout or round-trip byte identity. Original bytes and objdump output remain authoritative.",
    "Imports and exports retain exact top-level WABT WAT forms. Names remain escaped producer text; unescaped objdump display names are not parsed as unambiguous identifiers.",
    "JavaScript references are AST-observed static literals only. Candidate matches are associations, not proven data flow, URL-to-file identity or runtime loading. Computed references and aliases are not resolved.",
    "No target execution or implicit fetch. WABT tools are trusted caller-supplied executables; SHA-256 identifies their bytes, not publisher authenticity. No OS memory sandbox is claimed.",
    "Each subprocess has a 30-second deadline and 32 MiB combined output budget. Oversized output fails instead of producing truncated success.",
];

/// Private runtime roots whose removal failed, retried before shutdown.
///
/// Ports `WabtRuntime` + `ArtifactResourceScope`: a private root cannot be
/// removed until the commands that ran inside it have stopped. Owned children
/// whose process-group cleanup could not be confirmed are retained with their
/// root and retried before the root directory is removed again.
#[derive(Default)]
pub(crate) struct WasmRuntimeCleanup {
    retained: Mutex<Vec<RetainedRuntime>>,
}

struct RetainedRuntime {
    root: PathBuf,
    /// Owned children whose group cleanup is still unconfirmed.
    commands: Vec<OwnedChildProcess>,
}

impl WasmRuntimeCleanup {
    /// Retry every retained runtime; return the roots that remain.
    fn retry(&self) -> Vec<(String, String)> {
        let mut retained = self
            .retained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut failures = Vec::new();
        retained.retain_mut(|runtime| {
            runtime
                .commands
                .retain_mut(|child| match child.retry_cleanup(1) {
                    Ok(()) => false,
                    Err(error) => {
                        failures.push((
                            runtime.root.to_string_lossy().into_owned(),
                            error.to_string(),
                        ));
                        true
                    }
                });
            if !runtime.commands.is_empty() {
                return true;
            }
            match std::fs::remove_dir_all(&runtime.root) {
                Ok(()) => false,
                Err(error) => {
                    failures.push((
                        runtime.root.to_string_lossy().into_owned(),
                        error.to_string(),
                    ));
                    true
                }
            }
        });
        failures
    }

    fn retain(&self, root: PathBuf, commands: Vec<OwnedChildProcess>) {
        self.retained
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(RetainedRuntime { root, commands });
    }
}

impl SessionResource for WasmRuntimeCleanup {
    fn close(&self) -> Result<(), AnalysisError> {
        let failures = self.retry();
        if failures.is_empty() {
            return Ok(());
        }
        let resources = failures
            .iter()
            .map(|(root, _)| root.clone())
            .collect::<Vec<_>>();
        let reason = failures
            .iter()
            .map(|(root, reason)| format!("{root}: {reason}"))
            .collect::<Vec<_>>()
            .join("; ");
        Err(provider_cleanup(resources, reason))
    }
}

/// One observed WABT command profile (`commands[number]`).
#[derive(Clone)]
struct Command {
    tool: String,
    path: String,
    sha256: String,
    version_banner: String,
    arguments: Vec<String>,
}

impl Command {
    fn profile(&self) -> Value {
        json!({
            "tool": self.tool,
            "path": self.path,
            "sha256": self.sha256,
            "version_banner": self.version_banner,
            "arguments": self.arguments,
        })
    }
}

/// Complete output of one owned WABT command.
struct CommandOutput {
    stdout: String,
    stderr: String,
    stdout_bytes: u64,
    stderr_bytes: u64,
    exit_code: Option<i64>,
}

/// Run caller-supplied WABT against a private copy of the exactly selected
/// bytes and return complete Evidence (`WabtArtifactProvider.inspect`).
pub(crate) fn inspect(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cleanup = context.session.state::<WasmRuntimeCleanup>();
    context.session.own_once(Arc::clone(&cleanup));

    let object = input
        .as_object()
        .cloned()
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| AnalysisError::input(OPERATION, Vec::new()))?
        .to_owned();

    let mut run = InspectRun {
        context,
        cleanup: &cleanup,
        input: &object,
        parameters: input,
        path: &path,
        root: None,
        commands: Vec::new(),
    };
    let outcome = run.execute();
    run.finish(outcome)
}

struct InspectRun<'a> {
    context: &'a ToolContext<'a>,
    cleanup: &'a WasmRuntimeCleanup,
    input: &'a Map<String, Value>,
    parameters: &'a Value,
    path: &'a str,
    root: Option<PathBuf>,
    /// Owned children whose cleanup failed during this inspection.
    commands: Vec<OwnedChildProcess>,
}

impl InspectRun<'_> {
    fn execute(&mut self) -> Result<Evidence, AnalysisError> {
        // `options?.signal?.aborted` observed before admission.
        if self.context.cancellation.reason().is_some() {
            return Err(AnalysisError::cancelled(OPERATION));
        }
        // Retained cleanup must be clear before launching another command
        // (`ArtifactResourceScope.run` / `#runAfterCleanup`).
        let pending = self.cleanup.retry();
        if !pending.is_empty() {
            let resources = pending.iter().map(|(root, _)| root.clone()).collect();
            let reason = pending
                .iter()
                .map(|(root, reason)| format!("{root}: {reason}"))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(provider_cleanup(resources, reason));
        }

        // --- configuration phase ---------------------------------------
        let directory = self
            .context
            .session
            .env("REA_WABT_BIN_DIRECTORY")
            .unwrap_or("")
            .to_owned();
        if directory.is_empty() || !Path::new(&directory).is_absolute() {
            // TS throws a plain Error in `configuration`, which `wabtFailure`
            // maps to a capability-unavailable failure.
            return Err(capability_unavailable(
                "REA_WABT_BIN_DIRECTORY must be an absolute tool directory.".to_owned(),
            ));
        }

        let mut commands = Vec::new();
        for tool in ["wasm-validate", "wasm-objdump", "wasm2wat"] {
            let executable = resolve_tool(&directory, tool)?;
            let binary = self.read_tool(&executable)?;
            commands.push(Command {
                tool: tool.to_owned(),
                path: executable,
                sha256: binary.sha256,
                version_banner: String::new(),
                arguments: if tool == "wasm-objdump" {
                    vec!["-h".into(), "-x".into(), "module.wasm".into()]
                } else {
                    vec!["--enable-all".into(), "module.wasm".into()]
                },
            });
        }

        let root = create_private_root()?;
        self.root = Some(root.clone());
        let snapshot_path = root.join("module.wasm");

        // `version` is confirmed for every tool with the snapshot absent, so
        // `verifySnapshot` is a no-op until the snapshot is written.
        for command in &mut commands {
            let version = run_command(
                self.context,
                &mut self.commands,
                command,
                &["--version".to_owned()],
                &root,
                false,
            )?;
            verify_tool(command)?;
            if version.stdout.trim_end_matches('\n').trim() != "1.0.42"
                || !version.stderr.is_empty()
            {
                return Err(capability_unavailable(format!(
                    "Unsupported {} version banner; expected 1.0.42.",
                    command.tool
                )));
            }
            command.version_banner = version.stdout;
        }

        // --- artifact phase --------------------------------------------
        let selected = self.read_artifact(self.path)?;
        let selected_sha = selected.sha256.clone();
        let selected_bytes = selected.bytes.clone();
        let artifact = json!({
            "path": self.path,
            "sha256": selected_sha,
            "bytes": selected_bytes.len(),
        });

        let mut candidates = Vec::new();
        let mut candidate_paths = Vec::new();
        let mut seen = HashSet::new();
        for candidate in std::iter::once(self.path.to_owned()).chain(
            self.input
                .get("candidate_paths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned),
        ) {
            if !seen.insert(candidate.clone()) {
                continue;
            }
            let (sha256, bytes) = if candidate == self.path {
                (selected_sha.clone(), selected_bytes.len())
            } else {
                let read = self.read_artifact(&candidate)?;
                (read.sha256, read.bytes.len())
            };
            candidates.push(json!({"path": candidate, "sha256": sha256, "bytes": bytes}));
            candidate_paths.push(candidate);
        }

        let mut glue = Vec::new();
        for glue_path in self
            .input
            .get("glue_paths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            let snapshot = self.read_artifact(glue_path)?;
            // Keep source characters intact so locations match the hashed
            // artifact (`new TextDecoder("utf-8", { fatal: true })`).
            let source = String::from_utf8(snapshot.bytes.clone()).map_err(|_| {
                artifact_input("Glue artifact is not valid UTF-8 for reference association")
            })?;
            let references = collect_glue_references(glue_path, &source, &candidate_paths);
            let parse_status = glue_parse_status(&source);
            glue.push(json!({
                "artifact": {"path": glue_path, "sha256": snapshot.sha256, "bytes": snapshot.bytes.len()},
                "parse_status": parse_status,
                "references": references,
            }));
        }

        // Write the private `module.wasm` snapshot with the exact flag/mode.
        write_private_snapshot(&snapshot_path, &selected_bytes)?;
        let snapshot_hash = Some(selected_sha.clone());

        // --- producer phase --------------------------------------------
        let [validate_args, objdump_args, decode_args] = match commands.as_slice() {
            [a, b, c] => [
                a.arguments.clone(),
                b.arguments.clone(),
                c.arguments.clone(),
            ],
            _ => return Err(output("Incomplete WABT tool profile.")),
        };

        let validation = self.run_producer(
            &mut commands,
            0,
            &snapshot_path,
            &snapshot_hash,
            &validate_args,
            true,
        )?;
        if validation.exit_code != Some(0) {
            // Exact TS validation-rejection: AnalysisInputError carrying
            // complete partial Evidence plus captured output.
            return Err(self.validation_rejection(
                &selected_sha,
                &artifact,
                &commands,
                &validation,
            ));
        }

        let dump = self.run_producer(
            &mut commands,
            1,
            &snapshot_path,
            &snapshot_hash,
            &objdump_args,
            false,
        )?;
        if !dump.stderr.is_empty() {
            return Err(output("Unexpected WABT section output.")
                .with_captured_output(complete_capture(&dump)));
        }

        let wat = self.run_producer(
            &mut commands,
            2,
            &snapshot_path,
            &snapshot_hash,
            &decode_args,
            false,
        )?;
        if !wat.stdout.starts_with("(module") || !wat.stderr.is_empty() {
            return Err(output("Unexpected WABT decoding output.")
                .with_captured_output(complete_capture(&wat)));
        }

        if wat.stdout.len().saturating_add(dump.stdout.len()) > OUTPUT_BYTES {
            return Err(resource_constraint());
        }

        let forms = extract_module_forms(&wat.stdout)
            .map_err(|()| output("Unexpected WABT decoding output."))?;
        let imports = forms
            .iter()
            .filter(|form| form.raw.trim_start().starts_with("(import "))
            .map(|form| Value::String(form.raw.clone()))
            .collect::<Vec<_>>();
        let exports = forms
            .iter()
            .filter(|form| form.raw.trim_start().starts_with("(export "))
            .map(|form| Value::String(form.raw.clone()))
            .collect::<Vec<_>>();
        let interface = decode_wabt_interface(&forms).map_err(|()| resource_constraint())?;
        let (sections, headers, details) =
            parse_wabt_output(dump.stdout.as_bytes(), selected_bytes.len(), &wat.stdout)
                .map_err(|()| output("Unexpected WABT section output."))?;

        let report = json!({
            "artifact": artifact,
            "validation": "valid",
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "interface": interface,
            "headers": headers,
            "details": details,
            "wat": {
                "text": wat.stdout,
                "sha256": sha256_hex(wat.stdout.as_bytes()),
                "representation": "decoded-wat",
            },
            "tool_profile": {
                "source": "https://github.com/WebAssembly/wabt",
                "release": "1.0.42",
                "source_commit": "ff0ef7e0009402740c805a9744c09b05be063e48",
                "commands": commands.iter().map(Command::profile).collect::<Vec<_>>(),
                "timeout_ms": TIMEOUT_MS,
                "output_budget_bytes": OUTPUT_BYTES,
            },
            "candidates": candidates,
            "glue": glue,
            "runtime_execution": "not-performed",
            "network_fetch": "not-performed",
            "limitations": LIMITATIONS,
        });

        build_evidence(self.path, &selected_sha, self.parameters.clone(), report)
    }

    /// Run one producer command, re-verifying tool and snapshot identity
    /// before and after it executes (`execute`).
    fn run_producer(
        &mut self,
        commands: &mut [Command],
        index: usize,
        snapshot_path: &Path,
        snapshot_hash: &Option<String>,
        args: &[String],
        accept_non_zero: bool,
    ) -> Result<CommandOutput, AnalysisError> {
        self.verify_snapshot(snapshot_path, snapshot_hash)?;
        let root = self.root.clone().expect("runtime root created");
        let command = commands[index].clone();
        let output = run_command(
            self.context,
            &mut self.commands,
            &command,
            args,
            &root,
            accept_non_zero,
        )?;
        verify_tool(&commands[index])?;
        self.verify_snapshot(snapshot_path, snapshot_hash)?;
        Ok(output)
    }

    fn verify_snapshot(
        &self,
        snapshot_path: &Path,
        snapshot_hash: &Option<String>,
    ) -> Result<(), AnalysisError> {
        let Some(expected) = snapshot_hash else {
            return Ok(());
        };
        let bytes = stable_file::read(
            host_files(),
            snapshot_path,
            INPUT_BYTES,
            &self.context.cancellation,
        )
        .map_err(|_| {
            AnalysisError::artifact_changed(
                OPERATION,
                self.path,
                "Private WASM snapshot bytes changed.",
            )
        })?;
        if &bytes.sha256 != expected {
            return Err(AnalysisError::artifact_changed(
                OPERATION,
                self.path,
                "Private WASM snapshot bytes changed.",
            ));
        }
        Ok(())
    }

    fn read_tool(&self, executable: &str) -> Result<SelectedBytes, AnalysisError> {
        let snapshot = stable_file::read(
            host_files(),
            Path::new(executable),
            TOOL_BYTES,
            &self.context.cancellation,
        )
        .map_err(|_| {
            capability_unavailable(format!(
                "Configured WABT executable could not be read: {executable}"
            ))
        })?;
        Ok(SelectedBytes {
            sha256: snapshot.sha256,
        })
    }

    fn read_artifact(&self, path: &str) -> Result<Snapshot, AnalysisError> {
        stable_file::read(
            host_files(),
            Path::new(path),
            INPUT_BYTES,
            &self.context.cancellation,
        )
        .map_err(|failure| self.read_artifact_failure(path, *failure))
    }

    /// `wabtFailure(cause, "artifact", path)` for a stable-read failure.
    fn read_artifact_failure(
        &self,
        path: &str,
        failure: rea_host::fs::stable_file::ReadFailure<HostFiles>,
    ) -> AnalysisError {
        use rea_host::fs::stable_file::{IoKind, ReadIssue};
        if self.context.cancellation.reason().is_some() {
            return AnalysisError::cancelled(OPERATION);
        }
        match failure.primary {
            Some(ReadIssue::Cancelled(_)) => AnalysisError::cancelled(OPERATION),
            // `ArtifactReaderFailure` reason "limit", boundary "file-size".
            Some(ReadIssue::Limit { .. }) => AnalysisError::resource_constraint(
                OPERATION,
                "file-size",
                "Selected artifact exceeds the WABT input byte allowance.",
                None,
            )
            .with_remediation(
                "Select a suitable stable artifact within the reported input byte allowance. Do not truncate required bytes; retrying the unchanged oversized input will fail again.",
            ),
            // `ArtifactReaderFailure` reason "integrity".
            Some(ReadIssue::Changed(_)) => AnalysisError::artifact_changed(
                OPERATION,
                path,
                "Selected artifact changed during inspection.",
            ),
            // `EACCES`/`EPERM` access denial.
            Some(ReadIssue::Io {
                error:
                    stable_file::FileError {
                        kind: IoKind::AccessDenied,
                        system_code,
                        ..
                    },
                ..
            }) => AnalysisError::access_denied(OPERATION, path, system_code.unwrap_or("EACCES")),
            // The TypeScript artifact-phase fallback: a caller value to correct.
            _ => AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_value",
                    "Unable to read a stable regular WASM file.",
                )],
            ),
        }
    }

    /// `createEvidence` partial observation for a WABT validation rejection.
    fn validation_rejection(
        &self,
        selected_sha: &str,
        artifact: &Value,
        commands: &[Command],
        validation: &CommandOutput,
    ) -> AnalysisError {
        let result = json!({
            "artifact": artifact,
            "validation": "rejected-by-selected-profile",
            "tool_profile": {
                "source": "https://github.com/WebAssembly/wabt",
                "release": "1.0.42",
                "source_commit": "ff0ef7e0009402740c805a9744c09b05be063e48",
                "commands": commands.iter().map(Command::profile).collect::<Vec<_>>(),
            },
            "exit_code": validation.exit_code,
            "stdout": validation.stdout,
            "stderr": validation.stderr,
        });
        let limitations = vec![
            "WABT rejected these exact selected bytes with --enable-all; no complete inspection or target execution occurred.".to_owned(),
        ];
        let subject = SubjectTarget {
            path: self.path.to_owned(),
            sha256: selected_sha.to_owned(),
            format: "file".to_owned(),
            architecture: None,
        };
        let observation = Observation::new(OPERATION, self.parameters.clone(), result)
            .predicate("rea.wasm-artifact")
            .confidence("observed")
            .locations(vec![json!({"kind": "artifact-path", "path": self.path})])
            .limitations(limitations);
        let mut error = AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                "Selected bytes failed WABT validation with --enable-all; inspect retained upstream diagnostics.",
            )],
        )
        .with_captured_output(CapturedOutput {
            stdout: validation.stdout.clone(),
            stderr: validation.stderr.clone(),
            truncated: false,
            stdout_bytes: None,
            stderr_bytes: None,
            exit_code: None,
            signal: None,
        });
        if let Ok(evidence) = Evidence::create(Some(&subject), &provider_identity(), observation) {
            error = error.retain_partial_observation(evidence.into_value());
        }
        error
    }

    /// Release the private root; retain it for retry if removal failed.
    fn finish(
        mut self,
        outcome: Result<Evidence, AnalysisError>,
    ) -> Result<Evidence, AnalysisError> {
        let Some(root) = self.root.take() else {
            return outcome;
        };
        // Any owned child whose group cleanup failed during this inspection
        // keeps the root alive; retain them and report a cleanup failure.
        if !self.commands.is_empty() {
            let resources = vec![root.to_string_lossy().into_owned()];
            let commands = std::mem::take(&mut self.commands);
            self.cleanup.retain(root, commands);
            return Err(bind_cleanup(
                outcome,
                resources,
                "WABT command cleanup remains incomplete".to_owned(),
            ));
        }
        match std::fs::remove_dir_all(&root) {
            Ok(()) => outcome,
            Err(error) => {
                let resources = vec![root.to_string_lossy().into_owned()];
                self.cleanup.retain(root, Vec::new());
                Err(bind_cleanup(outcome, resources, error.to_string()))
            }
        }
    }
}

struct SelectedBytes {
    sha256: String,
}

/// `createEvidence` success envelope.
fn build_evidence(
    path: &str,
    sha256: &str,
    parameters: Value,
    report: Value,
) -> Result<Evidence, AnalysisError> {
    let subject = SubjectTarget {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        format: "file".to_owned(),
        architecture: None,
    };
    let observation = Observation::new(OPERATION, parameters, report)
        .predicate("rea.wasm-artifact")
        .confidence("observed")
        .authority("shipped-artifact")
        .locations(vec![json!({"kind": "artifact-path", "path": path})])
        .limitations(LIMITATIONS.iter().map(|text| (*text).to_owned()).collect());
    Evidence::create(Some(&subject), &provider_identity(), observation)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}

fn provider_identity() -> EvidenceProvider {
    EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, Some(PROVIDER_VERSION.into()))
}

// ---------------------------------------------------------------------------
// Tool resolution and execution
// ---------------------------------------------------------------------------

/// Resolve one tool path under the configured directory and admit it with
/// `realpath` + an executable-permission check (`realpath` /
/// `access(path, constants.X_OK)`).
fn resolve_tool(directory: &str, tool: &str) -> Result<String, AnalysisError> {
    let name = if cfg!(windows) {
        format!("{tool}.exe")
    } else {
        tool.to_owned()
    };
    let joined = Path::new(directory).join(name);
    let resolved = std::fs::canonicalize(&joined).map_err(|_| {
        capability_unavailable(format!(
            "Configured WABT executable {} could not be resolved.",
            joined.to_string_lossy()
        ))
    })?;
    if !is_executable(&resolved) {
        return Err(capability_unavailable(format!(
            "Configured WABT executable {} is not executable.",
            resolved.to_string_lossy()
        )));
    }
    Ok(resolved.to_string_lossy().into_owned())
}

/// Executable admission mirroring `access(path, constants.X_OK)`.
///
/// The crate forbids `unsafe`, so this checks the regular-file execute
/// permission bits instead of calling `libc::access`; the owner/group/other
/// execute bits approximate the effective-permission test without FFI.
#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(metadata) => metadata.is_file() && metadata.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

#[cfg(windows)]
fn is_executable(_path: &Path) -> bool {
    true
}

/// Re-sample the tool identity; `AnalysisOutputError` on a mid-run change.
fn verify_tool(command: &Command) -> Result<(), AnalysisError> {
    let bytes = std::fs::read(&command.path)
        .map_err(|_| output("Configured WABT executable changed during inspection."))?;
    if sha256_hex(&bytes) != command.sha256 {
        return Err(output(
            "Configured WABT executable changed during inspection.",
        ));
    }
    Ok(())
}

/// Launch one owned WABT command with `cwd = root`, poll with the mirrored
/// 30-second deadline and 32 MiB budget, and honor cancellation
/// (`runOwnedCommand`). Children whose group cleanup fails are retained.
fn run_command(
    context: &ToolContext<'_>,
    retained: &mut Vec<OwnedChildProcess>,
    command: &Command,
    args: &[String],
    root: &Path,
    accept_non_zero: bool,
) -> Result<CommandOutput, AnalysisError> {
    if context.cancellation.reason().is_some() {
        return Err(AnalysisError::cancelled(OPERATION));
    }
    let spec = ChildLaunchSpec {
        executable: PathBuf::from(&command.path),
        arguments: args.iter().map(OsString::from).collect(),
        working_directory: Some(root.to_path_buf()),
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    };
    let mut child = OwnedChildProcess::launch(spec).map_err(|error| {
        // `configuration`/`process`: WABT could not start.
        capability_unavailable(format!("Configured WABT could not start: {error}"))
    })?;

    let deadline = Instant::now() + Duration::from_millis(TIMEOUT_MS);
    let interruption = loop {
        match child.try_wait() {
            Ok(Some(_)) => break None,
            Ok(None) => {}
            Err(error) => break Some(Interruption::Io(error.to_string())),
        }
        if context.cancellation.reason().is_some() {
            break Some(Interruption::Cancelled);
        }
        if Instant::now() >= deadline {
            break Some(Interruption::Timeout);
        }
        std::thread::sleep(Duration::from_millis(10));
    };

    // Settle the owned group before interpreting output.
    let settled: Result<Option<u32>, ProcessLaunchError> = match &interruption {
        None => child.wait().map(|exit| Some(exit.code)),
        Some(_) => child.cancel(1).map(|()| None),
    };
    let drained = child.drain_output_with(|| false);
    let cleanup_failure = settled.as_ref().err().map(|error| error.to_string());

    let output_data = match drained {
        Ok(output_data) => output_data,
        Err(error) => {
            let mut failure = output(error.to_string());
            if let Some(reason) = cleanup_failure {
                failure = failure.with_cleanup(reason, cleanup_resources(command, root));
                retained.push(child);
            }
            return Err(failure);
        }
    };

    let stdout_bytes = output_data.stdout.len() as u64;
    let stderr_bytes = output_data.stderr.len() as u64;
    let capture = CommandOutput {
        stdout: String::from_utf8_lossy(&output_data.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output_data.stderr).into_owned(),
        stdout_bytes,
        stderr_bytes,
        exit_code: match &interruption {
            None => settled.ok().flatten().map(i64::from),
            Some(_) => None,
        },
    };

    let exceeded = output_data.exceeds_limit(OUTPUT_BYTES)
        || (interruption.is_none() && output_data.output_incomplete);

    // Resolve the interruption, cleanup, output-budget and exit status exactly
    // as `OwnedCommandFailure` / `wabtFailure`.
    let failure = match &interruption {
        Some(Interruption::Cancelled) => Some(AnalysisError::cancelled(OPERATION)),
        Some(Interruption::Timeout) => Some(AnalysisError::timeout(OPERATION, TIMEOUT_MS)),
        Some(Interruption::Io(detail)) => Some(output(detail.clone())),
        None if cleanup_failure.is_some() => Some(output("WABT command cleanup failed")),
        None if exceeded => Some(resource_constraint_excerpt(&capture)),
        None if capture.exit_code != Some(0) && !accept_non_zero => Some(
            output("Configured WABT returned a non-zero exit status.")
                .with_captured_output(complete_capture(&capture)),
        ),
        None => None,
    };

    if context.cancellation.reason().is_some() && failure.is_none() {
        let mut cancelled = AnalysisError::cancelled(OPERATION);
        if let Some(reason) = cleanup_failure {
            cancelled = cancelled.with_cleanup(reason, cleanup_resources(command, root));
            retained.push(child);
        }
        return Err(cancelled);
    }

    let Some(mut failure) = failure else {
        return Ok(capture);
    };
    if let Some(reason) = cleanup_failure {
        failure = failure.with_cleanup(reason, cleanup_resources(command, root));
        retained.push(child);
    }
    Err(failure)
}

enum Interruption {
    Cancelled,
    Timeout,
    Io(String),
}

fn cleanup_resources(command: &Command, root: &Path) -> Vec<String> {
    vec![root.to_string_lossy().into_owned(), command.path.clone()]
}

fn complete_capture(output: &CommandOutput) -> CapturedOutput {
    CapturedOutput {
        stdout: output.stdout.clone(),
        stderr: output.stderr.clone(),
        truncated: false,
        stdout_bytes: None,
        stderr_bytes: None,
        exit_code: None,
        signal: None,
    }
}

/// `outputLimitExcerpt`: a bounded prefix of each oversized stream, with the
/// observed byte totals, reported as a resource-constraint failure.
fn resource_constraint_excerpt(output: &CommandOutput) -> AnalysisError {
    let excerpt = CapturedOutput {
        stdout: bounded_utf8(&output.stdout, OUTPUT_LIMIT_EXCERPT_BYTES),
        stderr: bounded_utf8(&output.stderr, OUTPUT_LIMIT_EXCERPT_BYTES),
        truncated: true,
        stdout_bytes: Some(output.stdout_bytes),
        stderr_bytes: Some(output.stderr_bytes),
        exit_code: Some(output.exit_code),
        signal: Some(None),
    };
    resource_constraint().with_captured_output(excerpt)
}

/// `boundedUtf8Text`: a prefix within the byte budget, never splitting a
/// multi-byte character.
fn bounded_utf8(text: &str, budget: usize) -> String {
    if text.len() <= budget {
        return text.to_owned();
    }
    let mut end = budget;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Create a fresh private snapshot root (`PrivateRuntimeRoot.create`).
fn create_private_root() -> Result<PathBuf, AnalysisError> {
    tempfile::Builder::new()
        .prefix("rea-wabt-")
        .tempdir()
        .map(tempfile::TempDir::keep)
        .map_err(|error| {
            capability_unavailable(format!(
                "A private WABT runtime root could not be created: {error}"
            ))
        })
}

/// Write the private `module.wasm` snapshot with `wx` (create-new) and mode
/// `0o400`, matching `writeFile(snapshotPath, bytes, { flag: "wx", mode })`.
fn write_private_snapshot(path: &Path, bytes: &[u8]) -> Result<(), AnalysisError> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o400);
    }
    let mut file = options.open(path).map_err(|error| {
        output(format!(
            "Private WASM snapshot could not be written: {error}"
        ))
    })?;
    file.write_all(bytes).map_err(|error| {
        output(format!(
            "Private WASM snapshot could not be written: {error}"
        ))
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Typed failures (`src/wasm/WabtFailures.ts`)
// ---------------------------------------------------------------------------

fn capability_unavailable(message: String) -> AnalysisError {
    // `userMessage` appends the fixed WABT bring-your-own remediation hint.
    let user_message = format!(
        "{message} Supply WABT {PROVIDER_VERSION} via absolute REA_WABT_BIN_DIRECTORY; REA does not install tools."
    );
    AnalysisError::capability_unavailable(PROVIDER_ID, OPERATION, message)
        .with_user_message(user_message)
}

fn output(reason: impl Into<String>) -> AnalysisError {
    AnalysisError::output(OPERATION, reason)
}

fn artifact_input(message: impl Into<String>) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue::new(&["path"], "invalid_value", message)],
    )
}

fn resource_constraint() -> AnalysisError {
    AnalysisError::resource_constraint(
        OPERATION,
        "memory",
        format!("WABT output exceeded the {OUTPUT_BYTES}-byte output budget"),
        None,
    )
    .with_remediation(
        "The WABT output budget is fixed, so retrying with the same input will fail the same way.",
    )
}

/// `ProviderCleanupError` as a provider-adapter failure attaching cleanup facts.
fn provider_cleanup(resources: Vec<String>, reason: String) -> AnalysisError {
    AnalysisError::provider_adapter(PROVIDER_ID, OPERATION).with_cleanup(reason, resources)
}

/// Bind a cleanup failure to the primary outcome (`bindCleanupDependencies`).
fn bind_cleanup(
    outcome: Result<Evidence, AnalysisError>,
    resources: Vec<String>,
    reason: String,
) -> AnalysisError {
    let cleanup = CleanupObservation { reason, resources };
    match outcome {
        Ok(_) => {
            let mut failure = AnalysisError::provider_adapter(PROVIDER_ID, OPERATION);
            failure.cleanup = Some(cleanup);
            failure
        }
        Err(mut error) => {
            // First cleanup observation wins, mirroring the original binding.
            if error.cleanup.is_none() {
                error.cleanup = Some(cleanup);
            }
            error
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", sha2::Sha256::digest(bytes))
}

// ===========================================================================
// Verified WAT/objdump parsing and interface/glue projection.
//
// Copied from `rea_application::wasm::producer` (private there). Each function
// was verified against its TypeScript oracle: `WabtWat.ts`, `WabtInterface.ts`,
// `WabtString.ts`, `WabtOutput.ts`, `WasmGlueAdapter.ts`.
// ===========================================================================

#[derive(Clone, Debug)]
enum WatNode {
    Atom(String),
    String(String),
    List(Vec<WatNode>),
}

#[derive(Clone, Debug)]
struct WatForm {
    raw: String,
    node: WatNode,
}

#[derive(Clone, Debug)]
struct Definition {
    label: Option<String>,
    signature: Option<Value>,
}

fn extract_module_forms(wat: &str) -> Result<Vec<WatForm>, ()> {
    if !wat.trim_start().starts_with("(module") {
        return Err(());
    }
    let bytes = wat.as_bytes();
    let mut depth = 0usize;
    let mut closed = false;
    let mut form_start = None;
    let mut quote = false;
    let mut line_comment = false;
    let mut block_comment = 0usize;
    let mut forms = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if line_comment {
            if bytes[index] == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment > 0 {
            if bytes.get(index..index + 2) == Some(b"(;") {
                block_comment += 1;
                index += 2;
            } else if bytes.get(index..index + 2) == Some(b";)") {
                block_comment -= 1;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if quote {
            if bytes[index] == b'\\' {
                index = index.saturating_add(2);
            } else {
                quote = bytes[index] != b'"';
                index += 1;
            }
            continue;
        }
        if bytes.get(index..index + 2) == Some(b";;") {
            line_comment = true;
            index += 2;
        } else if bytes.get(index..index + 2) == Some(b"(;") {
            block_comment = 1;
            index += 2;
        } else if bytes[index] == b'"' {
            quote = true;
            index += 1;
        } else if bytes[index] == b'(' {
            if closed {
                return Err(());
            }
            if depth == 1 {
                form_start = Some(index);
            }
            depth += 1;
            index += 1;
        } else if bytes[index] == b')' {
            if depth == 0 {
                return Err(());
            }
            depth -= 1;
            if depth == 1 {
                let start = form_start.take().ok_or(())?;
                let raw = wat[start..=index].to_owned();
                forms.push(WatForm {
                    node: parse_node(&raw).ok_or(())?,
                    raw,
                });
            }
            if depth == 0 {
                closed = true;
            }
            index += 1;
        } else {
            if closed && !bytes[index].is_ascii_whitespace() {
                return Err(());
            }
            index += 1;
        }
    }
    if depth != 0 || quote || block_comment != 0 || !closed {
        return Err(());
    }
    Ok(forms)
}

fn parse_node(text: &str) -> Option<WatNode> {
    let mut parser = WatParser {
        bytes: text.as_bytes(),
        index: 0,
    };
    let node = parser.node()?;
    parser.skip_space();
    (parser.index == parser.bytes.len()).then_some(node)
}

struct WatParser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl WatParser<'_> {
    fn skip_space(&mut self) {
        loop {
            while self
                .bytes
                .get(self.index)
                .is_some_and(u8::is_ascii_whitespace)
            {
                self.index += 1;
            }
            if self.bytes.get(self.index..self.index + 2) == Some(b";;") {
                self.index += 2;
                while self.index < self.bytes.len() && self.bytes[self.index] != b'\n' {
                    self.index += 1;
                }
                continue;
            }
            if self.bytes.get(self.index..self.index + 2) != Some(b"(;") {
                break;
            }
            let mut depth = 1usize;
            self.index += 2;
            while self.index < self.bytes.len() && depth > 0 {
                if self.bytes.get(self.index..self.index + 2) == Some(b"(;") {
                    depth += 1;
                    self.index += 2;
                } else if self.bytes.get(self.index..self.index + 2) == Some(b";)") {
                    depth -= 1;
                    self.index += 2;
                } else {
                    self.index += 1;
                }
            }
        }
    }

    fn node(&mut self) -> Option<WatNode> {
        self.skip_space();
        match *self.bytes.get(self.index)? {
            b'(' => {
                self.index += 1;
                let mut items = Vec::new();
                loop {
                    self.skip_space();
                    match self.bytes.get(self.index) {
                        Some(b')') => {
                            self.index += 1;
                            return Some(WatNode::List(items));
                        }
                        Some(_) => items.push(self.node()?),
                        None => return None,
                    }
                }
            }
            b'"' => self.string().map(WatNode::String),
            _ => {
                let start = self.index;
                while self.bytes.get(self.index).is_some_and(|byte| {
                    !byte.is_ascii_whitespace() && *byte != b')' && *byte != b'('
                }) {
                    self.index += 1;
                }
                (self.index > start).then(|| {
                    WatNode::Atom(
                        String::from_utf8_lossy(&self.bytes[start..self.index]).into_owned(),
                    )
                })
            }
        }
    }

    fn string(&mut self) -> Option<String> {
        self.index += 1;
        let mut output = Vec::new();
        while let Some(byte) = self.bytes.get(self.index).copied() {
            self.index += 1;
            if byte == b'"' {
                return String::from_utf8(output).ok();
            }
            if byte != b'\\' {
                output.push(byte);
                continue;
            }
            let first = *self.bytes.get(self.index)?;
            if self
                .bytes
                .get(self.index + 1)
                .is_some_and(|byte| byte.is_ascii_hexdigit())
                && first.is_ascii_hexdigit()
            {
                let second = self.bytes[self.index + 1];
                output.push((hex(first)? << 4) | hex(second)?);
                self.index += 2;
            } else {
                output.push(match first {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'"' => b'"',
                    b'\\' => b'\\',
                    _ => return None,
                });
                self.index += 1;
            }
        }
        None
    }
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn atom(node: &WatNode) -> Option<&str> {
    match node {
        WatNode::Atom(value) => Some(value),
        _ => None,
    }
}

fn list(node: &WatNode) -> Option<&[WatNode]> {
    match node {
        WatNode::List(items) => Some(items),
        _ => None,
    }
}

fn head(node: &WatNode) -> Option<&str> {
    list(node)?.first().and_then(atom)
}

fn integer(value: &str) -> Option<String> {
    let parsed = if let Some(hex_value) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex_value, 16).ok()?
    } else {
        value.parse::<u64>().ok()?
    };
    Some(parsed.to_string())
}

fn values(form: &WatNode, category: &str) -> Option<Vec<String>> {
    let mut result = Vec::new();
    for item in list(form)?.iter().skip(1) {
        let group = list(item)?;
        if group.first().and_then(atom) != Some(category) {
            continue;
        }
        for value in group.iter().skip(1).filter_map(atom) {
            if value.starts_with('$') {
                continue;
            }
            if !VALUE_TYPES.contains(&value) {
                return None;
            }
            result.push(value.to_owned());
        }
    }
    Some(result)
}

fn function_signature(form: &WatNode, kind: &str) -> Option<Value> {
    Some(json!({
        "kind": kind,
        "params": values(form, "param")?,
        "results": values(form, "result")?,
    }))
}

fn typed_signature(
    form: &WatNode,
    type_signatures: &[Option<Value>],
    type_names: &BTreeMap<String, usize>,
    recursive_types: bool,
) -> Option<Value> {
    let parts = list(form)?;
    let kind = atom(parts.first()?)?;
    match kind {
        "func" | "tag" => {
            let reference = parts.iter().skip(1).find_map(|item| {
                let group = list(item)?;
                (group.first().and_then(atom) == Some("type"))
                    .then(|| group.get(1))?
                    .and_then(|node| atom(node))
            });
            let signature = match reference {
                None => function_signature(form, kind),
                Some(_reference) if recursive_types => None,
                Some(reference) => {
                    let index = reference
                        .strip_prefix('$')
                        .and_then(|name| type_names.get(&format!("${name}")))
                        .copied()
                        .or_else(|| reference.parse::<usize>().ok());
                    type_signatures.get(index?)?.clone()
                }
            }?;
            (signature.get("kind").and_then(Value::as_str) == Some("func")).then(|| {
                let mut signature = signature;
                signature["kind"] = Value::String(kind.to_owned());
                signature
            })
        }
        "memory" | "table" => {
            let mut page_size = "65536".to_owned();
            for group in parts.iter().skip(1).filter(|item| list(item).is_some()) {
                let declaration = list(group)?;
                if kind != "memory"
                    || declaration.len() != 2
                    || atom(declaration.first()?)? != "pagesize"
                {
                    return None;
                }
                page_size = integer(atom(declaration.get(1)?)?)?;
            }
            let mut tokens = parts
                .iter()
                .skip(1)
                .filter_map(atom)
                .filter(|token| !token.starts_with('$'))
                .collect::<Vec<_>>();
            let address_type = if matches!(tokens.first(), Some(&"i64")) {
                tokens.remove(0);
                "i64"
            } else {
                if matches!(tokens.first(), Some(&"i32")) {
                    tokens.remove(0);
                }
                "i32"
            };
            let minimum = integer(tokens.first().copied()?)?;
            tokens.remove(0);
            let maximum_token = tokens.first().copied();
            let maximum = maximum_token.and_then(integer);
            if maximum.is_some() {
                tokens.remove(0);
            }
            let shared = tokens.first().copied() == Some("shared");
            if shared {
                tokens.remove(0);
            }
            if kind == "memory" && !tokens.is_empty() {
                return None;
            }
            if kind == "memory" {
                Some(
                    json!({"kind":kind,"page_size":page_size,"address_type":address_type,"minimum":minimum,"maximum":maximum,"shared":shared}),
                )
            } else {
                let element = tokens.first().copied()?;
                if !matches!(element, "funcref" | "externref") || tokens.len() != 1 {
                    return None;
                }
                Some(
                    json!({"kind":kind,"address_type":address_type,"minimum":minimum,"maximum":maximum,"shared":shared,"element":element}),
                )
            }
        }
        "global" => {
            let declaration = parts.get(1).and_then(|node| {
                if atom(node).is_some_and(|value| value.starts_with('$')) {
                    parts.get(2)
                } else {
                    Some(node)
                }
            })?;
            let declaration_parts = list(declaration);
            let (value_type, mutable) = if let Some(group) = declaration_parts {
                (atom(group.get(1)?)?, true)
            } else {
                (atom(declaration)?, false)
            };
            VALUE_TYPES
                .contains(&value_type)
                .then(|| json!({"kind":kind,"value_type":value_type,"mutable":mutable}))
        }
        _ => None,
    }
}

fn add_definition(
    node: &WatNode,
    definitions: &mut BTreeMap<String, Vec<Definition>>,
    type_signatures: &[Option<Value>],
    type_names: &BTreeMap<String, usize>,
    recursive_types: bool,
) -> (usize, String, Option<Value>) {
    let raw_kind = head(node).unwrap_or("unknown");
    let kind = if INTERFACE_KINDS.contains(&raw_kind) {
        raw_kind
    } else {
        "unknown"
    };
    let label = list(node)
        .and_then(|parts| parts.get(1))
        .and_then(atom)
        .filter(|value| value.starts_with('$'))
        .map(str::to_owned);
    let signature = typed_signature(node, type_signatures, type_names, recursive_types);
    let space = definitions.entry(kind.to_owned()).or_default();
    let index = space.len();
    space.push(Definition {
        label,
        signature: signature.clone(),
    });
    (index, kind.to_owned(), signature)
}

fn decode_wabt_interface(forms: &[WatForm]) -> Result<Value, ()> {
    let recursive_types = forms.iter().any(|form| head(&form.node) == Some("rec"));
    let mut type_signatures = Vec::new();
    let mut type_names = BTreeMap::new();
    for form in forms.iter().filter(|form| head(&form.node) == Some("type")) {
        let parts = list(&form.node).ok_or(())?;
        if let Some(name) = parts
            .get(1)
            .and_then(atom)
            .filter(|value| value.starts_with('$'))
        {
            type_names.insert(name.to_owned(), type_signatures.len());
        }
        let body = parts.iter().find(|item| list(item).is_some());
        type_signatures.push(body.and_then(|body| {
            (!recursive_types && head(body) == Some("func"))
                .then(|| function_signature(body, "func"))?
        }));
    }
    let mut definitions: BTreeMap<String, Vec<Definition>> = BTreeMap::new();
    let mut entries = Vec::new();
    let mut representation = 0usize;
    for form in forms
        .iter()
        .filter(|form| head(&form.node) == Some("import"))
    {
        if entries.len() >= MAX_INTERFACE_ENTRIES {
            return Ok(partial_interface(
                &entries,
                "Typed interface entry count reached its bounded capacity",
            ));
        }
        let parts = list(&form.node).ok_or(())?;
        let module = match parts.get(1) {
            Some(WatNode::String(value)) => value.clone(),
            _ => return Err(()),
        };
        let name = match parts.get(2) {
            Some(WatNode::String(value)) => value.clone(),
            _ => return Err(()),
        };
        let body = parts.get(3).ok_or(())?;
        let (index, kind, signature) = add_definition(
            body,
            &mut definitions,
            &type_signatures,
            &type_names,
            recursive_types,
        );
        entries.push(json!({"direction":"import","module":module,"name":name,"kind":kind,"index":index,"signature":signature,"wat_form":form.raw,"issue":if signature.is_some(){Value::Null}else{json!("Import type is outside admitted core signature semantics")}}));
        representation = representation.saturating_add(1024 + form.raw.len().saturating_mul(6));
        if representation > MAX_INTERFACE_REPRESENTATION {
            return Ok(partial_interface(
                &entries,
                "Typed interface representation reached its bounded capacity",
            ));
        }
    }
    for form in forms
        .iter()
        .filter(|form| INTERFACE_KINDS.contains(&head(&form.node).unwrap_or("")))
    {
        if entries.len() >= MAX_INTERFACE_ENTRIES {
            return Ok(partial_interface(
                &entries,
                "Typed interface entry count reached its bounded capacity",
            ));
        }
        add_definition(
            &form.node,
            &mut definitions,
            &type_signatures,
            &type_names,
            recursive_types,
        );
    }
    for form in forms
        .iter()
        .filter(|form| head(&form.node) == Some("export"))
    {
        let parts = list(&form.node).ok_or(())?;
        let name = match parts.get(1) {
            Some(WatNode::String(value)) => value.clone(),
            _ => return Err(()),
        };
        let descriptor = list(parts.get(2).ok_or(())?).ok_or(())?;
        let kind = atom(descriptor.first().ok_or(())?).unwrap_or("unknown");
        let kind = if INTERFACE_KINDS.contains(&kind) {
            kind
        } else {
            "unknown"
        };
        let reference = descriptor.get(1).and_then(atom);
        let observed_index = reference.and_then(|reference| {
            let space = definitions.get(kind)?;
            if let Some(label) = reference.strip_prefix('$') {
                space.iter().position(|definition| {
                    definition.label.as_deref() == Some(&format!("${label}"))
                })
            } else {
                reference.parse::<usize>().ok()
            }
        });
        let signature =
            observed_index.and_then(|index| definitions.get(kind)?.get(index)?.signature.clone());
        entries.push(json!({"direction":"export","module":Value::Null,"name":name,"kind":kind,"index":observed_index,"signature":signature,"wat_form":form.raw,"issue":if signature.is_some(){Value::Null}else{json!("Export type/index is outside admitted core signature semantics")}}));
        representation = representation.saturating_add(1024 + form.raw.len().saturating_mul(6));
        if representation > MAX_INTERFACE_REPRESENTATION {
            return Ok(partial_interface(
                &entries,
                "Typed interface representation reached its bounded capacity",
            ));
        }
    }
    Ok(json!({"state":"complete","entries":entries,"issues":[]}))
}

fn partial_interface(entries: &[Value], issue: &str) -> Value {
    json!({"state":"partial","entries":entries,"issues":[issue]})
}

fn collect_glue_references(
    glue_path: &str,
    source: &str,
    candidate_paths: &[String],
) -> Vec<Value> {
    let mut references = Vec::new();
    for (line_index, line) in source.lines().enumerate() {
        for (column, raw_value) in quoted_glue_literals(line) {
            let value = decode_glue_literal(&raw_value);
            let wasm_value = value.split(['?', '#']).next().unwrap_or(value.as_str());
            if !wasm_value.to_ascii_lowercase().ends_with(".wasm") {
                continue;
            }
            let local_target = local_glue_target(glue_path, &value);
            let local_matches: Vec<String> = candidate_paths
                .iter()
                .filter(|candidate| {
                    local_target
                        .as_deref()
                        .is_some_and(|target| normalize_absolute_path(candidate) == target)
                })
                .cloned()
                .collect();
            let basename = wasm_value.rsplit(['/', '\\']).next().unwrap_or(wasm_value);
            let matches = matching_glue_candidates(candidate_paths, &local_matches, basename);
            let association = glue_association(&local_matches, &matches);
            references.push(json!({
                "value": value,
                "line": line_index + 1,
                "column": column,
                "candidate_paths": matches,
                "association": association,
                "evidence_kind": "static-literal"
            }));
        }
    }
    references
}

fn matching_glue_candidates(
    candidate_paths: &[String],
    local_matches: &[String],
    basename: &str,
) -> Vec<String> {
    if !local_matches.is_empty() {
        return local_matches.to_vec();
    }
    candidate_paths
        .iter()
        .filter(|candidate| candidate.rsplit(['/', '\\']).next() == Some(basename))
        .cloned()
        .collect()
}

fn glue_association(local_matches: &[String], matches: &[String]) -> &'static str {
    if !local_matches.is_empty() {
        "local-path-candidate"
    } else if matches.is_empty() {
        "unresolved"
    } else {
        "basename-candidates"
    }
}

fn quoted_glue_literals(line: &str) -> Vec<(usize, String)> {
    let mut literals = Vec::new();
    let mut cursor = 0usize;
    while let Some((start, delimiter)) = line[cursor..]
        .char_indices()
        .find(|(_, character)| matches!(character, '\'' | '"' | '`'))
    {
        let start = cursor + start;
        let mut end = start + delimiter.len_utf8();
        let mut escaped = false;
        while end < line.len() {
            let character = line[end..]
                .chars()
                .next()
                .expect("valid character boundary");
            end += character.len_utf8();
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == delimiter {
                literals.push((
                    start,
                    line[start + delimiter.len_utf8()..end - delimiter.len_utf8()].to_owned(),
                ));
                break;
            }
        }
        cursor = end.max(start + delimiter.len_utf8());
    }
    literals
}

fn local_glue_target(glue_path: &str, value: &str) -> Option<String> {
    if value.starts_with('/')
        || value.starts_with("\\\\")
        || value.contains('?')
        || value.contains('#')
        || has_uri_scheme(value)
    {
        return None;
    }
    let parent = Path::new(glue_path).parent()?.to_string_lossy();
    Some(normalize_absolute_path(&format!("{parent}/{value}")))
}

fn has_uri_scheme(value: &str) -> bool {
    let Some((scheme, _)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '+'
                || character == '-'
                || character == '.'
        })
}

fn normalize_absolute_path(path: &str) -> String {
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty() && *segment != ".")
        .collect::<Vec<_>>();
    format!("/{}", segments.join("/"))
}

fn decode_glue_literal(raw: &str) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let mut characters = raw.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            decoded.push(character);
            continue;
        }
        match characters.next() {
            Some('n') => decoded.push('\n'),
            Some('r') => decoded.push('\r'),
            Some('t') => decoded.push('\t'),
            Some('\\') => decoded.push('\\'),
            Some(quote @ ('\'' | '"' | '`')) => decoded.push(quote),
            Some('x') => {
                let digits = characters.by_ref().take(2).collect::<String>();
                match decode_hex(&digits).and_then(char::from_u32) {
                    Some(value) => decoded.push(value),
                    None => {
                        decoded.push('\\');
                        decoded.push('x');
                        decoded.push_str(&digits);
                    }
                }
            }
            Some('u') => {
                let mut digits = String::new();
                if characters.clone().next() == Some('{') {
                    characters.next();
                    for character in characters.by_ref() {
                        if character == '}' {
                            break;
                        }
                        digits.push(character);
                    }
                } else {
                    digits = characters.by_ref().take(4).collect();
                }
                match decode_unicode_escape(&digits) {
                    Some(value) => decoded.push(value),
                    None => {
                        decoded.push('\\');
                        decoded.push('u');
                        if !digits.is_empty() {
                            decoded.push_str(&digits);
                        }
                    }
                }
            }
            Some(other) => {
                decoded.push('\\');
                decoded.push(other);
            }
            None => decoded.push('\\'),
        }
    }
    decoded
}

fn decode_hex(digits: &str) -> Option<u32> {
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

fn decode_unicode_escape(digits: &str) -> Option<char> {
    char::from_u32(decode_hex(digits)?)
}

fn glue_parse_status(source: &str) -> &'static str {
    let mut stack = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut line_comment = false;
    let mut block_comment = false;
    let bytes = source.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if line_comment {
            if byte == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment {
            if bytes.get(index..index + 2) == Some(b"*/") {
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if let Some(delimiter) = quote {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == delimiter {
                quote = None;
            }
            index += 1;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"//") {
            line_comment = true;
            index += 2;
            continue;
        }
        if bytes.get(index..index + 2) == Some(b"/*") {
            block_comment = true;
            index += 2;
            continue;
        }
        if matches!(byte, b'\'' | b'"' | b'`') {
            quote = Some(byte);
        } else if matches!(byte, b'{' | b'[' | b'(') {
            stack.push(byte);
        } else if matches!(byte, b'}' | b']' | b')') {
            let expected = match byte {
                b'}' => b'{',
                b']' => b'[',
                _ => b'(',
            };
            if stack.pop() != Some(expected) {
                return "failed";
            }
        }
        index += 1;
    }
    if quote.is_some() || block_comment || !stack.is_empty() {
        "partial"
    } else {
        "complete"
    }
}

fn parse_wabt_output(
    bytes: &[u8],
    artifact_bytes: usize,
    wat_text: &str,
) -> Result<(Vec<Value>, String, String), ()> {
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    let sections_marker = "Sections:\n\n";
    let details_marker = "\nSection Details:\n";
    let mut expected_preamble = "\nmodule.wasm:\tfile format wasm 0x1\n".to_owned();
    for name in wat_debug_module_names(wat_text)? {
        expected_preamble.push_str("module name: <");
        expected_preamble.push_str(name.split('\0').next().unwrap_or(&name));
        expected_preamble.push_str(">\n");
    }
    expected_preamble.push_str("\nSections:\n\n");
    if !text.starts_with(&expected_preamble) {
        return Err(());
    }
    let sections_start = text.find(sections_marker).ok_or(())?;
    let details_start = text[sections_start + sections_marker.len()..]
        .find(details_marker)
        .map(|offset| sections_start + sections_marker.len() + offset)
        .ok_or(())?;
    let mut sections = Vec::new();
    let mut previous_end = 8usize;
    let section_text = &text[sections_start + sections_marker.len()..details_start];
    let custom_names = wat_custom_names(wat_text)?;
    validate_module_name_headers(text, wat_text)?;
    let mut custom_index = 0usize;
    let section_lines = section_text.lines().collect::<Vec<_>>();
    let mut line_index = 0usize;
    while line_index < section_lines.len() {
        let line = section_lines[line_index];
        line_index += 1;
        if line.trim().is_empty() {
            continue;
        }
        let kind = line.split_whitespace().next().ok_or(())?;
        let start = parse_hex_field(line, "start=0x")?;
        let end = parse_hex_field(line, "end=0x")?;
        let bytes_count = parse_hex_field(line, "(size=0x")?;
        let description_start = line.find(") ").ok_or(())? + 2;
        let mut description = line[description_start..].trim().to_owned();
        if kind == "Custom" {
            let expected = custom_names.get(custom_index).ok_or(())?;
            let displayed = expected.split('\0').next().unwrap_or(expected);
            let observed = if description.is_empty() {
                let observed = section_lines.get(line_index).ok_or(())?.trim();
                line_index += 1;
                observed
            } else {
                description.as_str()
            };
            if observed != format!("\"{displayed}\"") {
                return Err(());
            }
            description = observed.to_owned();
            custom_index += 1;
        }
        if end < start
            || end - start != bytes_count
            || end > artifact_bytes
            || start < previous_end.saturating_add(2)
            || start > previous_end.saturating_add(6)
        {
            return Err(());
        }
        previous_end = end;
        sections.push(json!({"kind":kind,"start":start,"end":end,"bytes":bytes_count,"description":description}));
    }
    if custom_index != custom_names.len() {
        return Err(());
    }
    if sections
        .last()
        .and_then(|section| section.get("end"))
        .and_then(Value::as_u64)
        != Some(artifact_bytes as u64)
    {
        return Err(());
    }
    let separator = details_start + 1;
    let details = format!(
        "{}\n{}",
        expected_preamble.trim_start_matches('\n'),
        &text[separator..]
    );
    Ok((sections, text[..separator].to_owned(), details))
}

fn validate_module_name_headers(text: &str, wat: &str) -> Result<(), ()> {
    let expected = wat_debug_module_names(wat)?;
    let displayed = text
        .lines()
        .filter_map(|line| line.strip_prefix("module name: <"))
        .filter_map(|line| line.strip_suffix('>'))
        .collect::<Vec<_>>();
    if expected.len() != displayed.len() {
        return Err(());
    }
    for (expected, displayed) in expected.iter().zip(displayed) {
        if expected.split('\0').next().unwrap_or(expected) != displayed {
            return Err(());
        }
    }
    Ok(())
}

fn wat_debug_module_names(wat: &str) -> Result<Vec<String>, ()> {
    let mut names = Vec::new();
    for (section_name, payload) in wat_custom_sections(wat)? {
        if section_name == "name" {
            let bytes = payload.as_bytes();
            let Some(module_names) = decode_name_modules(bytes) else {
                return Err(());
            };
            names.extend(module_names);
        }
    }
    Ok(names)
}

fn decode_name_modules(bytes: &[u8]) -> Option<Vec<String>> {
    let mut offset = 0usize;
    let mut names = Vec::new();
    while offset < bytes.len() {
        let (subsection, subsection_width) = read_unsigned_leb(bytes.get(offset..)?)?;
        let size_offset = offset.checked_add(subsection_width)?;
        let (size, size_width) = read_unsigned_leb(bytes.get(size_offset..)?)?;
        let start = size_offset.checked_add(size_width)?;
        let end = start.checked_add(size)?;
        let payload = bytes.get(start..end)?;
        if subsection == 0 && size != 0 {
            let (name_length, name_width) = read_unsigned_leb(payload)?;
            let name_start = name_width;
            let name_end = name_start.checked_add(name_length)?;
            if name_end != payload.len() {
                return None;
            }
            names.push(String::from_utf8(payload.get(name_start..name_end)?.to_vec()).ok()?);
            offset = end;
            continue;
        }
        offset = end;
    }
    Some(names)
}

fn read_unsigned_leb(bytes: &[u8]) -> Option<(usize, usize)> {
    let mut value = 0usize;
    for (index, byte) in bytes.iter().copied().take(5).enumerate() {
        if index == 4 && byte > 0x0f {
            return None;
        }
        value |= usize::from(byte & 0x7f).checked_shl((index * 7) as u32)?;
        if byte & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    None
}

fn wat_custom_names(wat: &str) -> Result<Vec<String>, ()> {
    Ok(wat_custom_sections(wat)?
        .into_iter()
        .map(|(name, _)| name)
        .collect())
}

fn wat_custom_sections(wat: &str) -> Result<Vec<(String, String)>, ()> {
    let forms = extract_module_forms(wat)?;
    let mut sections = Vec::new();
    for form in forms {
        let Some(parts) = list(&form.node) else {
            continue;
        };
        if atom(parts.first().ok_or(())?) != Some("@custom") {
            continue;
        }
        let Some(WatNode::String(name)) = parts.get(1) else {
            return Err(());
        };
        let Some(WatNode::String(payload)) = parts.get(2) else {
            return Err(());
        };
        sections.push((name.clone(), payload.clone()));
    }
    Ok(sections)
}

fn parse_hex_field(text: &str, marker: &str) -> Result<usize, ()> {
    let start = text
        .find(marker)
        .map(|offset| offset + marker.len())
        .ok_or(())?;
    let end = text[start..]
        .find(|character: char| !character.is_ascii_hexdigit())
        .map(|offset| start + offset)
        .unwrap_or(text.len());
    usize::from_str_radix(&text[start..end], 16).map_err(|_| ())
}
