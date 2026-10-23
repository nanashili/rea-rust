//! `inspect_desktop_application`: bounded, read-only desktop directory facts.
//!
//! Owners: `src/server/registerDesktopApplicationTool.ts`,
//! `src/application/artifacts/DesktopApplicationService.ts`,
//! `src/artifacts/DesktopApplicationReader.ts`,
//! `src/artifacts/DesktopFileInspection.ts`,
//! `src/domain/desktopApplication*.ts`.
//!
//! The directory reader produces one desktop report; the service validates the
//! absolute-path refinement and the returned root, builds one Evidence record
//! (`createDesktopApplicationEvidence`), and delivers either the retained
//! summary view (`detail: "summary"`, the default) or the complete Evidence.

use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Evidence, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Value, json};
use std::path::Path;

use crate::common;

mod convention;
mod inspection;
mod managed;
mod pe;
mod projection;
mod reader;

const OPERATION: &str = "inspect_desktop_application";

/// Bind the desktop contract to its single handler.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle(OPERATION, |context: &ToolContext<'_>, input: Value| {
        handle(context, input)
    });
}

fn handle(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    // Delivery selection is stripped before the service, exactly as the TS
    // registration destructures `{ detail, ...input }`.
    let detail = input
        .get("detail")
        .and_then(Value::as_str)
        .unwrap_or("summary")
        .to_owned();
    let summary = detail == "summary";

    common::run_service_tool(context, || inspect(context, &input, summary))
}

/// `DesktopApplicationService.inspect` plus the registration's summary
/// delivery, as one admitted operation.
fn inspect(
    context: &ToolContext<'_>,
    input: &Value,
    summary: bool,
) -> Result<Evidence, AnalysisError> {
    context.check_cancelled()?;

    let path = input
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AnalysisError::input(
                OPERATION,
                vec![InputIssue::new(
                    &["path"],
                    "missing_argument",
                    "path is required.",
                )],
            )
        })?
        .to_owned();

    // Zod refinement that JSON Schema cannot express: the path must be absolute
    // on this host.
    if !Path::new(&path).is_absolute() {
        return Err(AnalysisError::input(
            OPERATION,
            vec![InputIssue::new(
                &["path"],
                "invalid_format",
                "Expected an absolute directory path on this host.",
            )],
        ));
    }

    let max_entries = input
        .get("max_entries")
        .and_then(Value::as_u64)
        .unwrap_or(20_000) as usize;
    let max_probe_bytes = input
        .get("max_probe_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(8 * 1024 * 1024) as usize;

    context.progress.report(OPERATION, "started");
    let report = reader::inspect(&path, max_entries, max_probe_bytes, &context.cancellation);
    context.progress.report(
        OPERATION,
        if report.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    let report = report?;

    // The directory inspection must not have changed the selected root.
    let root_path = report
        .get("root")
        .and_then(|root| root.get("path"))
        .and_then(Value::as_str);
    if root_path != Some(path.as_str()) {
        return Err(AnalysisError::output(
            OPERATION,
            "Directory inspection changed the selected root or returned malformed facts.",
        ));
    }

    let evidence = create_desktop_application_evidence(input, &report)?;

    if summary {
        common::summary_view(context, evidence)
    } else {
        Ok(evidence)
    }
}

/// `createDesktopApplicationEvidence(input, report, ARTIFACT_GRAPH_PROVIDER)`.
fn create_desktop_application_evidence(
    input: &Value,
    report: &Value,
) -> Result<Evidence, AnalysisError> {
    let root = report.get("root").cloned().unwrap_or(Value::Null);
    let snapshot = root
        .get("snapshot_sha256")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let root_path = root
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let input_path = input
        .get("path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();

    let subject = SubjectTarget {
        path: root_path,
        sha256: snapshot,
        format: "directory".to_owned(),
        architecture: None,
    };

    // `parameters` are the service input with the delivery-only `detail`
    // removed, exactly as the service receives `{ detail, ...input }`.
    let parameters = Value::Object(common::without_detail(input));

    let limitations: Vec<String> = report
        .get("limitations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    let observation = Observation::new(OPERATION, parameters, report.clone())
        .confidence("observed")
        .limitations(limitations)
        .locations(vec![json!({ "kind": "artifact-path", "path": input_path })]);

    Evidence::create(
        Some(&subject),
        &common::artifact_graph_provider(),
        observation,
    )
    .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))
}
