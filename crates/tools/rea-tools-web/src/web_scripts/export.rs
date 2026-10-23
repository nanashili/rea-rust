//! `export_web_scripts`: publish one local capture through the shared
//! application workflow.
//!
//! Compatibility owners: `src/application/WebScriptExportService.ts`,
//! `src/server/registerWebScriptTool.ts` and
//! `src/browser/assets/ScriptCaptureAdapters.ts`.
use super::capture::{self, SelectedCapture};
use super::errors;
use super::node;
use super::publish;
use rea_core::analysis_error::AnalysisError;
use rea_core::cancellation::Cancellation;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_host::fs::stable_file::{self, FileError, IoKind, ReadIssue};
use rea_mcp::ToolContext;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

const OPERATION: &str = "export_web_scripts";
const PROVIDER_ID: &str = "rea-web-script-export";
const PROVIDER_NAME: &str = "REA captured script export";

type HostFiles = rea_host::fs::unix_file::UnixFiles;

/// `exportWebScriptsValidated`.
pub fn export(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let cancellation = &context.cancellation;
    let capture_path = rea_mcp::support::string(input, "capture_path").to_owned();
    let output_directory = rea_mcp::support::string(input, "output_directory").to_owned();

    if !node::is_absolute(&capture_path) || !node::is_absolute(&output_directory) {
        return Err(errors::input_issue(
            OPERATION,
            Vec::new(),
            "invalid_format",
            "capture_path and output_directory must be absolute filesystem paths on this host.",
        ));
    }

    if cancellation.reason().is_some() {
        return Err(errors::cancelled(OPERATION));
    }

    let bytes = read_capture(&capture_path, cancellation)?;
    let capture_sha256 = format!("{:x}", Sha256::digest(&bytes));
    let selected = parse_capture(&bytes)?;

    if cancellation.reason().is_some() {
        return Err(errors::cancelled(OPERATION));
    }

    let publication =
        publish::publish(&capture_path, &output_directory, &capture_sha256, &selected).map_err(
            |failure| {
                // `mapExportFailure`: an `ArtifactReaderFailure` with no cleanup is
                // projected through `WebScriptExportError` with the raw
                // caller-selected `output_directory` target.
                errors::web_script_export(failure.reason, &output_directory, &failure.message)
            },
        )?;

    build_evidence(
        &capture_path,
        &output_directory,
        &capture_sha256,
        &selected,
        &publication,
    )
}

/// `readCapture`: a missing, non-file or unreadable selection is a caller or
/// host-permission failure, not an export failure.
fn read_capture(path: &str, cancellation: &Cancellation) -> Result<Vec<u8>, AnalysisError> {
    match stable_file::read(
        Arc::new(HostFiles {}),
        Path::new(path),
        usize::MAX,
        cancellation,
    ) {
        Ok(snapshot) => Ok(snapshot.bytes),
        Err(failure) => Err(capture_read_failure((*failure).primary, path)),
    }
}

fn capture_read_failure(primary: Option<ReadIssue>, path: &str) -> AnalysisError {
    match primary {
        Some(ReadIssue::Cancelled(_)) => errors::cancelled(OPERATION),
        Some(ReadIssue::InvalidPath) => invalid_value(&format!(
            "Selected capture is a directory, not a file: {path}"
        )),
        Some(ReadIssue::Changed(_)) | Some(ReadIssue::InvalidRead) | None => invalid_value(
            &format!("Selected capture could not be read (ENOENT): {path}"),
        ),
        Some(ReadIssue::Limit { .. }) | Some(ReadIssue::Allocation { .. }) => {
            errors::web_script_export("limit", path, "Selected capture exceeds the read budget")
        }
        Some(ReadIssue::Io { error, .. }) => io_capture_failure(error, path),
    }
}

fn io_capture_failure(error: FileError, path: &str) -> AnalysisError {
    match error.kind {
        IoKind::AccessDenied => {
            errors::access_denied(OPERATION, path, error.system_code.unwrap_or("EACCES"))
        }
        IoKind::NotFound | IoKind::NotDirectory => {
            let code = error.system_code.unwrap_or(match error.kind {
                IoKind::NotFound => "ENOENT",
                _ => "ENOTDIR",
            });
            invalid_value(&format!(
                "Selected capture could not be read ({code}): {path}"
            ))
        }
        _ => {
            let code = error.system_code.unwrap_or("EIO");
            errors::web_script_export(
                "io",
                path,
                &format!("Selected capture could not be read ({code}): {path}"),
            )
        }
    }
}

fn invalid_value(message: &str) -> AnalysisError {
    errors::input_issue(
        OPERATION,
        vec![errors::segment("capture_path")],
        "invalid_value",
        message,
    )
}

/// `parseCapture` + `selectScriptCapture`.
fn parse_capture(bytes: &[u8]) -> Result<SelectedCapture, AnalysisError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        errors::input_issue(
            OPERATION,
            vec![errors::segment("capture_path")],
            "invalid_format",
            "Capture is not valid UTF-8 JSON evidence.",
        )
    })?;
    let value: Value = serde_json::from_str(text).map_err(|error| {
        errors::input_issue(
            OPERATION,
            vec![errors::segment("capture_path")],
            "invalid_format",
            error.to_string(),
        )
    })?;
    capture::select_script_capture(&value).ok_or_else(|| {
        errors::input_issue(
            OPERATION,
            vec![errors::segment("capture_path")],
            "invalid_format",
            "Expected a valid inspect_web_page or capture_browser_scenario capture, with retained script sources or response bytes. Evidence envelopes must have a matching operation and semantic identifier.",
        )
    })
}

/// `createEvidence(...)` for the export result.
fn build_evidence(
    capture_path: &str,
    output_directory: &str,
    capture_sha256: &str,
    selected: &SelectedCapture,
    publication: &publish::Publication,
) -> Result<Evidence, AnalysisError> {
    // The inline result is the manifest object with the `manifest` identity
    // appended (the TS `webScriptExportResultSchema` extends the manifest).
    let mut normalized = publication.manifest.clone();
    if let Value::Object(object) = &mut normalized {
        object.insert(
            "manifest".into(),
            json!({
                "path": publication.manifest_path,
                "sha256": publication.manifest_sha256,
                "bytes": publication.manifest_bytes,
            }),
        );
    }

    let limitations: Vec<String> = publication.manifest["limitations"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let subject = SubjectTarget {
        path: capture_path.to_owned(),
        sha256: capture_sha256.to_owned(),
        format: "file".to_owned(),
        architecture: None,
    };

    let observation = Observation::new(
        OPERATION,
        json!({
            "capture_path": capture_path,
            "output_directory": output_directory,
        }),
        normalized,
    )
    .predicate("rea.web-script-export")
    .confidence("derived")
    .authority("historical-reference")
    .limitations(limitations)
    .locations(vec![json!({
        "kind": "artifact-path",
        "path": publication.manifest_path,
    })])
    .links(
        selected
            .source_evidence_id
            .clone()
            .map(|id| vec![id])
            .unwrap_or_default(),
    );

    let provider = EvidenceProvider::new(PROVIDER_ID, PROVIDER_NAME, Some("1".to_owned()));
    rea_mcp::support::evidence(Some(&subject), &provider, observation)
}
