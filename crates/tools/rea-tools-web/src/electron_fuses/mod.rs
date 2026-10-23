//! `inspect_electron_fuses`: read packaged Electron fuse wires from one
//! explicitly selected local file or app bundle, without launching it.
//!
//! Compatibility owners: `src/server/registerElectronTools.ts`
//! (`registerElectronFuseTool`), `src/application/electron/ElectronFuseService.ts`
//! (`inspect`), `src/electron/ElectronFuseProvider.ts`,
//! `src/electron/ElectronFusePath.ts`, `src/electron/ElectronFuseReader.ts`,
//! `src/electron/ElectronFuseFailures.ts`, and
//! `src/domain/electron/{electronFuses,electronFuseEvidence}.ts`. The stable
//! artifact acquisition uses `rea_host::fs::stable_file`.
mod elf;
mod jvm_class;
mod macho;
mod path;
mod pe;
mod reader;
mod report;

use path::{ResolveError, ResolvedTarget};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_host::fs::stable_file::{self, IoKind, ReadIssue};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use reader::{FuseImage, ReadError};
use report::{Format, Slice};
use serde_json::{Value, json};
use std::path::Path;
use std::sync::Arc;

#[cfg(unix)]
type HostFiles = rea_host::fs::unix_file::UnixFiles;
#[cfg(windows)]
type HostFiles = rea_host::fs::windows_file::WindowsFiles;

const OPERATION: &str = "inspect_electron_fuses";
const TOOL: &str = "inspect_electron_fuses";

/// Bundled fuse-wire reader. It does not flip fuses or launch the application.
const PROVIDER_ID: &str = "electron-fuses";
const PROVIDER_NAME: &str = "REA Electron fuse reader";
const PROVIDER_VERSION: &str = "1";

const MAXIMUM_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// Subject architectures the Evidence schema admits (`BINARY_ARCHITECTURES`).
const SUBJECT_ARCHITECTURES: [&str; 13] = [
    "x86", "x86_64", "x86_64h", "arm", "arm64", "arm64e", "arm64_32", "mips", "mipsel", "powerpc",
    "riscv", "hexagon", "raw",
];

pub(crate) fn register(registry: &mut Registry) {
    registry.handle(TOOL, |context, input| inspect(context, &input));
}

fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

fn inspect(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    if let Some(reason) = context.cancellation.reason() {
        return ToolOutput::Failure(cancelled(reason));
    }
    let path = match input.get("path").and_then(Value::as_str) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return ToolOutput::Failure(AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(&["path"], "invalid_type", "Expected text.")],
            ));
        }
    };
    if !is_absolute(path) {
        return ToolOutput::Failure(AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                "Expected an absolute filesystem path on this host.",
            )],
        ));
    }
    match run(path, &context.cancellation) {
        Ok(evidence) => complete(evidence, &context.cancellation),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// Classify completion after Evidence assembly, preserving facts on late abort.
fn complete(evidence: Evidence, cancellation: &Cancellation) -> ToolOutput {
    if let Some(reason) = cancellation.reason() {
        let mut error = cancelled(reason);
        error = error.retain_partial_observation(evidence.into_value());
        return ToolOutput::Failure(error);
    }
    ToolOutput::Evidence(evidence)
}

fn run(selected_path: &str, cancellation: &Cancellation) -> Result<Evidence, AnalysisError> {
    let resolved = path::resolve_target(selected_path)
        .map_err(|error| resolve_failure(error, selected_path))?;
    let ResolvedTarget {
        selected_path: selected,
        resolved_path,
    } = resolved;
    let snapshot = read_stable(&resolved_path, cancellation)?;
    let image = reader::read_image(&snapshot.bytes, &resolved_path)
        .map_err(|error| read_failure(error, selected_path))?;
    let report = build_report(
        &image,
        &selected,
        &resolved_path,
        snapshot.bytes.len(),
        &snapshot.sha256,
    );
    build_evidence(&selected, &resolved_path, &snapshot.sha256, &image, report)
}

/// Acquire the stable snapshot and map read failures to the fuse error algebra.
fn read_stable(
    path: &str,
    cancellation: &Cancellation,
) -> Result<stable_file::Snapshot, AnalysisError> {
    match stable_file::read(
        Arc::new(HostFiles {}),
        Path::new(path),
        MAXIMUM_INPUT_BYTES as usize,
        cancellation,
    ) {
        Ok(snapshot) => Ok(snapshot),
        Err(failure) => {
            let failure = *failure;
            // A failed close surfaces as the primary outcome's error; the
            // reader owns no retained cleanup state after acquisition here.
            Err(read_issue_failure(failure.primary, path))
        }
    }
}

fn read_issue_failure(primary: Option<ReadIssue>, path: &str) -> AnalysisError {
    match primary {
        Some(ReadIssue::Cancelled(reason)) => cancelled(&reason),
        Some(ReadIssue::InvalidPath) => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                format!("Expected a regular file without a symlink: {path}"),
            )],
        ),
        Some(ReadIssue::Changed(stage)) => AnalysisError::artifact_changed(
            OPERATION,
            path,
            format!("Artifact changed {stage}: {path}"),
        ),
        Some(ReadIssue::Limit { maximum_bytes })
        | Some(ReadIssue::Allocation {
            requested_bytes: maximum_bytes,
        }) => resource_file_size(path, maximum_bytes),
        Some(ReadIssue::InvalidRead) | None => AnalysisError::artifact_changed(
            OPERATION,
            path,
            format!("Artifact read failed: {path}"),
        ),
        Some(ReadIssue::Io { error, .. }) => io_failure(error, path),
    }
}

fn io_failure(error: stable_file::FileError, path: &str) -> AnalysisError {
    match error.kind {
        IoKind::AccessDenied => {
            AnalysisError::access_denied(OPERATION, path, error.system_code.unwrap_or("EACCES"))
        }
        IoKind::NotFound | IoKind::NotDirectory | IoKind::SymlinkLoop | IoKind::NameTooLong => {
            let code = error.system_code.unwrap_or(match error.kind {
                IoKind::NotFound => "ENOENT",
                IoKind::NotDirectory => "ENOTDIR",
                IoKind::SymlinkLoop => "ELOOP",
                _ => "ENAMETOOLONG",
            });
            AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_value",
                    format!("Selected artifact could not be read ({code}): {path}."),
                )],
            )
        }
        _ => AnalysisError::provider_adapter(PROVIDER_ID, OPERATION)
            .with_diagnostics(diagnostics(path, &error.to_string())),
    }
}

/// Translate a path-admission failure.
fn resolve_failure(error: ResolveError, path: &str) -> AnalysisError {
    match error {
        ResolveError::Path(failure) => AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(&["path"], failure.reason, failure.message)],
        ),
        ResolveError::Io { code, error } => match code {
            Some(code @ ("EACCES" | "EPERM")) => {
                AnalysisError::access_denied(OPERATION, path, code)
            }
            Some(code @ ("ENOENT" | "ENOTDIR" | "ELOOP" | "ENAMETOOLONG")) => AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "invalid_value",
                    format!("Selected artifact could not be read ({code}): {path}."),
                )],
            ),
            _ => AnalysisError::provider_adapter(PROVIDER_ID, OPERATION)
                .with_diagnostics(diagnostics(path, &error.to_string())),
        },
    }
}

/// Translate a reader decode failure.
fn read_failure(error: ReadError, path: &str) -> AnalysisError {
    match error {
        ReadError::Format(failure) => {
            if failure.is_unsupported() {
                AnalysisError::unsupported_target(OPERATION, path, failure.message().to_owned())
            } else {
                AnalysisError::input(
                    OPERATION,
                    vec![InputIssue::new(
                        &["path"],
                        "invalid_format",
                        format!("Selected artifact {path}: {}", failure.message()),
                    )],
                )
            }
        }
        ReadError::Resource(failure) => {
            if failure.file_size {
                resource_file_size(path, MAXIMUM_INPUT_BYTES as usize)
            } else {
                AnalysisError::resource_constraint(
                    OPERATION,
                    "capacity",
                    failure.message,
                    Some(json!({ "maximum_sentinels_per_slice": 32 })),
                )
            }
        }
    }
}

fn resource_file_size(path: &str, maximum: usize) -> AnalysisError {
    AnalysisError::resource_constraint(
        OPERATION,
        "file-size",
        format!("Selected artifact exceeds {maximum} bytes: {path}"),
        Some(json!({ "maximum_input_bytes": MAXIMUM_INPUT_BYTES })),
    )
}

fn cancelled(_reason: &str) -> AnalysisError {
    AnalysisError::cancelled(OPERATION)
}

fn diagnostics(path: &str, reason: &str) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    map.insert("path".into(), Value::String(path.to_owned()));
    map.insert("reason".into(), Value::String(reason.to_owned()));
    map
}

fn is_absolute(path: &str) -> bool {
    Path::new(path).is_absolute()
}

/// Build the normalized fuse report value (`electronFuseReportSchema` shape).
fn build_report(
    image: &FuseImage,
    selected_path: &str,
    resolved_path: &str,
    bytes: usize,
    sha256: &str,
) -> Value {
    let findings = report::describe_findings(&image.slices, image.format);
    let mut limitations = findings.limitations;
    limitations.push(reader::read_limitation());
    json!({
        "artifact": {
            "selected_path": selected_path,
            "resolved_path": resolved_path,
            "sha256": sha256,
            "bytes": bytes,
            "format": image.format.as_str(),
        },
        "slices": image.slices,
        "runtime_implications": findings.runtime_implications,
        "limitations": limitations,
    })
}

fn build_evidence(
    selected_path: &str,
    resolved_path: &str,
    sha256: &str,
    image: &FuseImage,
    report_value: Value,
) -> Result<Evidence, AnalysisError> {
    let architecture = subject_architecture(image);
    let subject = SubjectTarget {
        path: resolved_path.to_owned(),
        sha256: sha256.to_owned(),
        format: image.format.as_str().to_owned(),
        architecture,
    };
    let limitations = report_value
        .get("limitations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let locations = locations_for(selected_path, resolved_path, &image.slices);
    let observation = Observation::new(OPERATION, json!({ "path": selected_path }), report_value)
        .confidence("observed")
        .limitations(limitations)
        .locations(locations);
    Evidence::create(Some(&subject), &provider(), observation)
        .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}

/// Port of `subjectArchitecture`: a thin single-slice format reports its arch
/// when it is a recognized subject architecture.
fn subject_architecture(image: &FuseImage) -> Option<String> {
    if image.format == Format::MachOUniversal {
        return None;
    }
    if image.slices.len() != 1 {
        return None;
    }
    let name = image.slices[0].architecture.as_deref()?;
    SUBJECT_ARCHITECTURES
        .iter()
        .find(|&&value| value == name)
        .map(|&value| value.to_owned())
}

/// Port of `locationsFor`: selected path, resolved path when it differs, then
/// one file-offset per reported sentinel.
fn locations_for(selected_path: &str, resolved_path: &str, slices: &[Slice]) -> Vec<Value> {
    let mut locations = vec![json!({ "kind": "artifact-path", "path": selected_path })];
    if resolved_path != selected_path {
        locations.push(json!({ "kind": "artifact-path", "path": resolved_path }));
    }
    for slice in slices {
        for sentinel in &slice.sentinels {
            locations.push(json!({ "kind": "file-offset", "offset": sentinel.sentinel_offset }));
        }
    }
    locations
}
