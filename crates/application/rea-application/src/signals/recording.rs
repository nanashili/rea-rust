//! Application-owned projection for `decode_signal_recording`.
//!
//! The sigrok display stream is deliberately retained as producer text.  This
//! module does not reinterpret annotation labels, sample ranges, or unknown
//! decoder records as protocol facts.  A host adapter supplies the bounded
//! command execution and the stable source snapshot; this module owns input
//! admission, output paging, version identity, and Evidence provenance.

use rea_core::{
    evidence::{ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject},
    failure::{Detail, Failure},
};
use rea_host::fs::stable_file::Snapshot;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const OPERATION: &str = "decode_signal_recording";
pub const PROVIDER: Provider = Provider {
    id: "sigrok-recording",
    name: "REA sigrok recording adapter",
    version: Some("sigrok-cli@0.7.2"),
};
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_SELECTOR_UTF16: usize = 8 * 1024;
pub const MAX_SELECTOR_ARGUMENT_BYTES: usize = 32 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub path: String,
    pub decoders: String,
    pub input_format: Option<String>,
    pub annotations: Option<String>,
    pub line_offset: usize,
    pub line_limit: Option<usize>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub command_timeout_ms: u64,
    pub address_space_bytes: u64,
    pub file_bytes: u64,
    pub cpu_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolIdentity {
    pub configured_path: String,
    pub path: String,
    pub sha256: String,
    pub version_banner: String,
    pub version_diagnostics: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimiterIdentity {
    pub configured_path: String,
    pub path: String,
    pub sha256: String,
    pub arguments: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputWindow {
    pub total_lines: usize,
    pub returned_lines: usize,
    pub has_more: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub artifact: Artifact,
    pub selection: Selection,
    pub annotations_text: String,
    pub output_window: OutputWindow,
    pub diagnostics: String,
    pub tool: ToolIdentity,
    pub resource_limiter: LimiterIdentity,
    pub limits: Limits,
    pub hardware_acquisition: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    pub path: String,
    pub sha256: String,
    pub bytes: usize,
}

/// Validate a caller-supplied decode report or retained Evidence projection.
/// This boundary never opens a recording path or invokes sigrok.
pub fn project_captured(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| input_failure(OPERATION, "captured input must be an object"))?;

    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    let candidate = ["normalized_result", "result", "report", "tool_output"]
        .iter()
        .find_map(|field| object.get(*field))
        .ok_or_else(|| {
            input_failure(
                OPERATION,
                "supply captured report or authenticated Evidence",
            )
        })?;
    let report: Report = serde_json::from_value(candidate.clone()).map_err(|error| {
        input_failure(OPERATION, &format!("captured report is malformed: {error}"))
    })?;

    validate_captured_report(&report)?;
    let result = serde_json::to_value(report).map_err(|error| {
        input_failure(
            OPERATION,
            &format!("captured report is not serializable: {error}"),
        )
    })?;
    Ok(serde_json::json!({
        "result": result,
        "provenance": {"source": "caller-supplied-captured-recording", "execution": "none"}
    }))
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity_failure(&error.to_string()))?;
    let record = rea_core::evidence::record::EvidenceRecord::parse(&raw)
        .map_err(|error| integrity_failure(&error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity_failure(
            "Evidence operation does not match decode_signal_recording",
        ));
    }

    let report: Report =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            integrity_failure(&format!("captured Evidence result is malformed: {error}"))
        })?;
    validate_captured_report(&report)?;
    let result =
        serde_json::to_value(report).map_err(|error| integrity_failure(&error.to_string()))?;
    Ok(serde_json::json!({
        "evidence_id": record.evidence_id(),
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"}
    }))
}

fn validate_captured_report(report: &Report) -> Result<(), Failure> {
    if !Path::new(&report.artifact.path).is_absolute() || report.artifact.path.contains('\0') {
        return Err(input_failure(
            OPERATION,
            "captured artifact path must be absolute and NUL-free",
        ));
    }
    if report.selection.path != report.artifact.path {
        return Err(input_failure(
            OPERATION,
            "selection.path must match artifact.path",
        ));
    }
    if report.artifact.sha256.len() != 64
        || !report
            .artifact
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(input_failure(
            OPERATION,
            "captured artifact has an invalid lower-case SHA-256 identity",
        ));
    }
    if report.artifact.bytes > MAX_INPUT_BYTES {
        return Err(input_failure(
            OPERATION,
            "captured recording exceeds the 32 MiB input limit",
        ));
    }
    if report.annotations_text.len() > MAX_OUTPUT_BYTES {
        return Err(input_failure(
            OPERATION,
            "captured annotations exceed the 4 MiB output limit",
        ));
    }
    if report.output_window.returned_lines > report.output_window.total_lines
        || (report.output_window.has_more
            && report.output_window.returned_lines == report.output_window.total_lines)
    {
        return Err(input_failure(
            OPERATION,
            "captured output window is inconsistent",
        ));
    }
    if report.hardware_acquisition != "not-performed" {
        return Err(input_failure(
            OPERATION,
            "hardware acquisition must be not-performed",
        ));
    }
    validate_selection(&report.selection, report.artifact.bytes)
}

fn integrity_failure(reason: &str) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide authenticated, intact Evidence for decode_signal_recording.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

/// Result of one bounded producer invocation.  The adapter must retain all
/// bytes up to `MAX_OUTPUT_BYTES`; overflow is a failure, never a truncation.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

/// Host-owned command boundary.  Implementations must execute a private copy
/// and enforce timeout, output, and process-resource limits before launch.
pub trait DecoderRunner {
    fn run_version(&mut self) -> Result<CommandOutput, Failure>;
    fn run_decode(&mut self, arguments: &[String]) -> Result<CommandOutput, Failure>;
    fn tool(&self) -> ToolIdentity;
    fn limiter(&self) -> LimiterIdentity;
    fn limits(&self) -> Limits;
}

/// Decode one stable recording snapshot and commit its result as artifact Evidence.
pub fn decode_signal_recording<R: DecoderRunner>(
    selection: Selection,
    snapshot: Snapshot,
    runner: &mut R,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    validate_selection(&selection, snapshot.bytes.len())?;
    validate_source_identity(&selection.path, &snapshot)?;

    let version = runner.run_version()?;
    validate_version(&version.stdout)?;

    let arguments = decoder_arguments(&selection);
    let output = runner.run_decode(&arguments)?;
    if output.exit_code != Some(0) {
        return Err(producer_failure(
            "sigrok decoder exited unsuccessfully",
            &selection.path,
            output.stderr,
        ));
    }
    validate_output_size(&output)?;

    let (annotations_text, output_window) = page_output(&output.stdout, &selection);
    let tool = ToolIdentity {
        arguments,
        version_banner: version.stdout,
        version_diagnostics: version.stderr,
        ..runner.tool()
    };
    let report = Report {
        artifact: Artifact {
            path: selection.path.clone(),
            sha256: snapshot.sha256.clone(),
            bytes: snapshot.bytes.len(),
        },
        selection: selection.clone(),
        annotations_text,
        output_window,
        diagnostics: output.stderr,
        tool,
        resource_limiter: runner.limiter(),
        limits: runner.limits(),
        hardware_acquisition: "not-performed".into(),
    };
    let subject = Subject::new(
        &selection.path,
        snapshot.sha256,
        NativeFormat::Directory,
        None,
    )
    .map_err(|error| execution_failure(&selection.path, error.to_string()))?;
    let evidence = ArtifactEvidence::new_with_exact_parameters(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result: report,
            limitations: vec![
                "Sigrok annotations remain producer text; unknown records and sample ranges are not reinterpreted as protocol facts.".into(),
                "Only a private copy is decoded. Hardware acquisition and target execution are not performed.".into(),
                "Empty output does not establish absence of traffic.".into(),
            ],
            locations: vec![Location::ArtifactPath {
                path: selection.path.clone(),
            }],
        },
        selection,
    )
    .map_err(|error| execution_failure("Evidence", error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn validate_selection(selection: &Selection, input_bytes: usize) -> Result<(), Failure> {
    if !Path::new(&selection.path).is_absolute() || selection.path.contains('\0') {
        return Err(input_failure(
            &selection.path,
            "expected an absolute NUL-free path",
        ));
    }
    if input_bytes > MAX_INPUT_BYTES {
        return Err(input_failure(
            &selection.path,
            "recording exceeds the 32 MiB input limit",
        ));
    }
    if selection.decoders.is_empty()
        || !selector_is_bounded(&selection.decoders)
        || !selection
            .input_format
            .as_deref()
            .map(selector_is_bounded)
            .unwrap_or(true)
        || !selection
            .annotations
            .as_deref()
            .map(selector_is_bounded)
            .unwrap_or(true)
    {
        return Err(input_failure(
            &selection.path,
            "selector is empty, contains NUL, or exceeds its UTF-16 limit",
        ));
    }
    let argument_bytes = selector_argument_bytes(selection);
    if argument_bytes > MAX_SELECTOR_ARGUMENT_BYTES {
        return Err(input_failure(
            &selection.path,
            "selector arguments exceed the 32 KiB budget",
        ));
    }
    if selection.line_limit == Some(0) {
        return Err(input_failure(
            &selection.path,
            "line_limit must be positive or null",
        ));
    }
    Ok(())
}

fn validate_source_identity(path: &str, snapshot: &Snapshot) -> Result<(), Failure> {
    if snapshot.sha256.len() != 64
        || !snapshot
            .sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(input_failure(
            path,
            "stable snapshot has an invalid lower-case SHA-256 identity",
        ));
    }
    Ok(())
}

fn validate_version(version: &str) -> Result<(), Failure> {
    if !version.starts_with("sigrok-cli 0.7.2\n") && !version.starts_with("sigrok-cli 0.7.2\r\n") {
        return Err(input_failure(
            "sigrok-cli",
            "ambiguous or unsupported sigrok-cli version",
        ));
    }
    if !version.contains("libsigrokdecode") {
        return Err(input_failure(
            "sigrok-cli",
            "sigrok-cli version does not identify libsigrokdecode",
        ));
    }
    Ok(())
}

fn selector_is_bounded(value: &str) -> bool {
    !value.contains('\0') && value.encode_utf16().count() <= MAX_SELECTOR_UTF16
}

fn selector_argument_bytes(selection: &Selection) -> usize {
    let mut bytes = argument_bytes("--protocol-decoders=", &selection.decoders);
    if let Some(value) = &selection.input_format {
        bytes += argument_bytes("--input-format=", value);
    }
    if let Some(value) = &selection.annotations {
        bytes += argument_bytes("--protocol-decoder-annotations=", value);
    }
    bytes
}

fn argument_bytes(prefix: &str, value: &str) -> usize {
    prefix.len() + value.len() + 9
}

fn decoder_arguments(selection: &Selection) -> Vec<String> {
    let mut arguments = vec![
        "--dont-scan".into(),
        "--input-file=recording".into(),
        format!("--protocol-decoders={}", selection.decoders),
        "--protocol-decoder-samplenum".into(),
    ];
    if let Some(value) = &selection.input_format {
        arguments.push(format!("--input-format={value}"));
    }
    if let Some(value) = &selection.annotations {
        arguments.push(format!("--protocol-decoder-annotations={value}"));
    }
    arguments
}

fn validate_output_size(output: &CommandOutput) -> Result<(), Failure> {
    let bytes = output.stdout.len().saturating_add(output.stderr.len());
    if bytes > MAX_OUTPUT_BYTES {
        return Err(execution_failure(
            OPERATION,
            "sigrok output exceeded the 4 MiB limit".into(),
        ));
    }
    Ok(())
}

fn page_output(text: &str, selection: &Selection) -> (String, OutputWindow) {
    let lines: Vec<&str> = if text.is_empty() {
        Vec::new()
    } else {
        text.split_inclusive('\n').collect()
    };
    let total_lines = lines.len();
    let start = selection.line_offset.min(total_lines);
    let end = match selection.line_limit {
        Some(limit) => start.saturating_add(limit).min(total_lines),
        None => total_lines,
    };
    let selected = lines[start..end].concat();
    (
        selected,
        OutputWindow {
            total_lines,
            returned_lines: end.saturating_sub(start),
            has_more: end < total_lines,
        },
    )
}

fn input_failure(path: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_format",
        reason.into(),
        false,
        "Correct the selected recording or decoder settings and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
        ]),
    )
}

fn producer_failure(message: &str, path: &str, diagnostics: String) -> Failure {
    let mut failure = execution_failure(path, message.into());
    failure.detail("diagnostics", Detail::Text(diagnostics));
    failure
}

fn execution_failure(path: &str, reason: String) -> Failure {
    Failure::new(
        "execution_failed",
        "provider_execution",
        reason,
        true,
        "Review the selected sigrok installation and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("path", Detail::Text(path.into())),
        ]),
    )
}
