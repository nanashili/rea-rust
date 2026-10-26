//! Artifact-graph provider tools: `inspect_artifact` and `extract_artifact`.
//!
//! Compatibility owners: `src/server/registerArtifactTools.ts`,
//! `src/artifacts/ArtifactProvider.ts` (the `ArtifactClient.execute` arms for
//! `inspect_artifact`, `extract_artifact` and the internal `inventory_artifact`
//! primitive), `src/contracts/artifactToolContracts.ts` and
//! `src/application/artifacts/ArtifactExtractionDestination.ts`.
//!
//! Scope and fail-closed boundary: directory, ZIP-package, ASAR, universal
//! Mach-O (`lipo`) and DMG (`hdiutil`) readers preserve the TypeScript reader
//! contracts. Native macOS readers remain unavailable on non-macOS hosts.
mod asar;
mod classify;
pub(crate) mod directory_reader;
mod extraction;
mod graph;
mod inspection;
mod javascript_acquisition;
mod scan;
mod zip_reader;

pub use javascript_acquisition::{JavaScriptArtifactReaderHandle, open_javascript_artifact_reader};

/// The shared reader contract (also implemented by the macOS readers).
use crate::artifact_reader as reader;

use crate::common::{
    self, ArtifactCause, Execution, ProviderCall, ProviderOutcome,
    ReaderFailure as CommonReaderFailure, artifact_graph_provider, source_or_path,
    translate_artifact_failure, without_detail,
};
pub use graph::ArtifactInventoryResult;
use rea_analysis::BinaryTarget;
use rea_core::analysis_error::AnalysisError;
use rea_core::analysis_error::InputIssue;
use rea_core::evidence::envelope::SubjectTarget;
use rea_core::evidence::record::EvidenceRecord;
use rea_mcp::{Registry, ToolContext, ToolOutput};
use reader::{ReaderCleanupOwner, ReaderFailure};
use serde_json::{Map, Value, value::RawValue};
use std::sync::Arc;
use std::{fs, io, path::Path};

const JAVASCRIPT_ARTIFACT_OPERATION: &str = "analyze_javascript_application";

pub(crate) fn register(registry: &mut Registry) {
    registry.handle("inspect_artifact", inspect_artifact);
    registry.handle("extract_artifact", extract_artifact);
}

/// Translate a local reader failure into the common `ArtifactCause` so the
/// shared `translate_artifact_failure` projects the exact `ArtifactOperationError`.
fn to_cause(context: &ToolContext<'_>, mut failure: ReaderFailure) -> ArtifactCause {
    if let Some(owner) = failure.retained_file.take() {
        context.session.own(Arc::new(owner));
    }
    if let Some(owner) = ReaderCleanupOwner::from_failure(&mut failure) {
        context.session.own(owner);
    }
    ArtifactCause::Reader(CommonReaderFailure {
        reason: failure.reason,
        message: failure.message,
        details: failure.details,
        cleanup: failure.cleanup,
        partial_observation: failure.partial_observation,
    })
}

/// Inventory input admitted by the JavaScript artifact workflow.
pub fn inventory_for_javascript(
    input_path: &str,
    integrity_fail: bool,
    cancellation: &rea_core::cancellation::Cancellation,
) -> Result<ArtifactInventoryResult, ReaderFailure> {
    scan::inventory_artifact(input_path, integrity_fail, cancellation)
}

/// Open a JavaScript reader after applying the application's input admission
/// contract. Filesystem selection failures are typed before any reader work;
/// reader failures still transfer their exact cleanup owners through `to_cause`.
pub fn open_javascript_artifact_reader_for_analysis(
    context: &ToolContext<'_>,
    input_path: &str,
    expected_format: &str,
) -> Result<JavaScriptArtifactReaderHandle, AnalysisError> {
    let canonical_path = admit_javascript_input(input_path)?;
    let observed_format = observed_javascript_format(&canonical_path, input_path)?;

    if expected_format != "auto" && expected_format != observed_format {
        return Err(AnalysisError::input(
            JAVASCRIPT_ARTIFACT_OPERATION,
            vec![InputIssue {
                path: vec![serde_json::Value::String("format".to_owned())],
                reason: "invalid_value",
                message: Some(format!(
                    "Requested {expected_format} input, but the selected input is {}: {input_path}",
                    if observed_format == "asar" {
                        "an .asar file"
                    } else {
                        "a directory"
                    }
                )),
                expected: Some(serde_json::json!(["auto", observed_format])),
                minimum: None,
                maximum: None,
            }],
        ));
    }

    open_javascript_artifact_reader(&canonical_path, observed_format, &context.cancellation)
        .map_err(|failure| translate_javascript_reader_failure(context, failure))
}

fn admit_javascript_input(input_path: &str) -> Result<String, AnalysisError> {
    let canonical =
        fs::canonicalize(input_path).map_err(|error| map_input_path_error(input_path, error))?;
    let canonical_path = canonical.to_str().ok_or_else(|| {
        AnalysisError::input(
            JAVASCRIPT_ARTIFACT_OPERATION,
            vec![InputIssue::new(
                &["input_path"],
                "invalid_value",
                format!("Selected input path is not representable as UTF-8: {input_path}"),
            )],
        )
    })?;

    let metadata =
        fs::metadata(&canonical).map_err(|error| map_input_path_error(input_path, error))?;
    let read_result = if metadata.is_dir() {
        fs::read_dir(&canonical).map(|_| ())
    } else {
        fs::File::open(&canonical).map(|_| ())
    };
    read_result.map_err(|error| map_input_path_error(input_path, error))?;
    Ok(canonical_path.to_owned())
}

fn observed_javascript_format(
    path: &str,
    selected_path: &str,
) -> Result<&'static str, AnalysisError> {
    let path_ref = Path::new(path);
    let metadata = fs::metadata(path_ref).map_err(|error| map_input_path_error(path, error))?;
    if metadata.is_dir() {
        return Ok("directory");
    }
    if metadata.is_file()
        && path_ref
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("asar"))
    {
        return Ok("asar");
    }

    Err(AnalysisError::unsupported_target(
        JAVASCRIPT_ARTIFACT_OPERATION,
        selected_path,
        "JavaScript application analysis accepts only a directory or an .asar file",
    )
    .with_remediation(
        "Select an extracted application directory, an app bundle, or an .asar file such as Contents/Resources/app.asar.",
    ))
}

fn map_input_path_error(path: &str, error: io::Error) -> AnalysisError {
    match error.kind() {
        io::ErrorKind::PermissionDenied => AnalysisError::access_denied(
            JAVASCRIPT_ARTIFACT_OPERATION,
            path,
            if error.raw_os_error() == Some(1) {
                "EPERM"
            } else {
                "EACCES"
            },
        ),
        io::ErrorKind::NotFound | io::ErrorKind::NotADirectory => AnalysisError::input(
            JAVASCRIPT_ARTIFACT_OPERATION,
            vec![InputIssue::new(
                &["input_path"],
                "invalid_value",
                format!(
                    "No file or directory exists at the selected input path ({}): {path}",
                    if error.kind() == io::ErrorKind::NotADirectory {
                        "ENOTDIR"
                    } else {
                        "ENOENT"
                    },
                ),
            )],
        ),
        _ => AnalysisError::input(
            JAVASCRIPT_ARTIFACT_OPERATION,
            vec![InputIssue::new(
                &["input_path"],
                "invalid_value",
                format!("Could not read the selected input path: {error}"),
            )],
        ),
    }
}

/// Translate a provider reader failure while retaining any exact resource
/// owners on the caller's session for retry or cleanup.
pub fn translate_javascript_reader_failure(
    context: &ToolContext<'_>,
    failure: ReaderFailure,
) -> AnalysisError {
    translate_artifact_failure(JAVASCRIPT_ARTIFACT_OPERATION, to_cause(context, failure))
}

/// `subjectFor(path, manifest)`.
fn subject_for(path: &str, inventory: &ArtifactInventoryResult) -> SubjectTarget {
    SubjectTarget {
        path: path.to_owned(),
        sha256: inventory.manifest.root_sha256.clone(),
        format: inventory.manifest.root_format.clone(),
        architecture: None,
    }
}

fn subject_json(subject: &SubjectTarget) -> rea_application::javascript::graph::json::Json {
    let name = std::path::Path::new(&subject.path)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("artifact");
    rea_application::javascript::graph::json::Obj::new()
        .with("name", name)
        .with(
            "digest",
            rea_application::javascript::graph::json::Obj::new()
                .with("sha256", subject.sha256.clone()),
        )
        .with("local_path", subject.path.clone())
        .with("format", subject.format.clone())
        .with("architecture", subject.architecture.clone())
        .into()
}

fn integrity_fail(parameters: &Map<String, Value>) -> bool {
    // Zod default is "fail"; the frozen inputSchema applies it before dispatch.
    parameters
        .get("integrity_policy")
        .and_then(Value::as_str)
        .map(|value| value == "fail")
        .unwrap_or(true)
}

/// `inspect_artifact`. Execution parameters drop the delivery-only `detail`;
/// Evidence parameters keep it. Delivery is a summary view when `detail` is
/// `"summary"`.
fn inspect_artifact(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let detail = input
        .get("detail")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let summary = detail.as_deref() == Some("summary");
    let execution_parameters = without_detail(&input);
    // Evidence identity keeps the explicit detail (inspect_artifact retains it).
    let evidence_parameters = input.clone();

    let call = ProviderCall {
        execution_parameters,
        evidence_parameters,
        summary,
        unavailable: None,
    };

    if let Err(error) = common::admit(context) {
        return error.into();
    }
    context.progress.report("inspect_artifact", "started");
    let result = (|| {
        common::admit(context)?;
        let target = common::active_target(context)?;
        let (inspection, source) = inspect_execute_raw(
            context,
            &target,
            &call.execution_parameters,
            &call.evidence_parameters,
        )?;
        context.session.record_raw(source.raw())?;
        if call.summary {
            // The derived summary links to the complete inspection Evidence;
            // retain that parent before creating the view so same-session
            // parent resolution can authenticate the link.
            context.session.record_raw(inspection.raw())?;
            let parent = rea_application::javascript::graph::json::parse(inspection.raw().get())
                .map_err(|error| {
                    AnalysisError::output("inspect_analysis_view", error.to_string())
                })?;
            let view: rea_application::javascript::graph::json::Json =
                rea_application::javascript::graph::json::Obj::new()
                    .with("kind", "summary")
                    .into();
            let raw = rea_application::artifacts::inventory_view::project_raw(&parent, &view)
                .map_err(common::adopt_failure)?;
            EvidenceRecord::parse(&raw)
                .map_err(|error| AnalysisError::output("inspect_analysis_view", error.to_string()))
        } else {
            Ok(inspection)
        }
    })();
    context.progress.report(
        "inspect_artifact",
        if result.is_ok() {
            "completed"
        } else {
            "failed"
        },
    );
    match result {
        Ok(evidence) => ToolOutput::RawEvidence(evidence),
        Err(error) => error.into(),
    }
}

fn inspect_execute_raw(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    parameters: &Map<String, Value>,
    evidence_parameters: &Value,
) -> Result<(EvidenceRecord, EvidenceRecord), AnalysisError> {
    let fail = integrity_fail(parameters);
    let source_path = source_or_path(target).to_owned();
    context
        .progress
        .report("inspect_artifact.inventory", "inventory substep started");
    let inventory =
        scan::inventory_artifact(&source_path, fail, &context.cancellation).map_err(|failure| {
            translate_artifact_failure("inspect_artifact", to_cause(context, failure))
        })?;
    let subject = subject_for(&source_path, &inventory);
    let inventory_json = rea_application::javascript::graph::json::parse(
        &serde_json::to_string(&inventory)
            .map_err(|error| AnalysisError::output("inventory_artifact", error.to_string()))?,
    )
    .map_err(|error| AnalysisError::output("inventory_artifact", error.to_string()))?;
    let inventory_parameters = rea_application::javascript::graph::json::Obj::new().with(
        "integrity_policy",
        parameters
            .get("integrity_policy")
            .and_then(Value::as_str)
            .unwrap_or("fail"),
    );
    let inventory_unsigned = rea_application::javascript::graph::json::Obj::new()
        .with("subject", subject_json(&subject))
        .with(
            "provider",
            rea_application::javascript::graph::json::Obj::new()
                .with("id", "rea-artifact-graph")
                .with("name", "REA safe artifact graph provider")
                .with("version", "1"),
        )
        .with(
            "analysis_profile",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with("predicate_type", "rea.analysis")
        .with("operation", "inventory_artifact")
        .with("parameters", inventory_parameters)
        .with(
            "raw_result",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with("normalized_result", inventory_json)
        .with("confidence", "observed")
        .with("authority", "shipped-artifact")
        .with(
            "environment",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with(
            "limitations",
            rea_application::javascript::graph::json::Json::array(
                inventory
                    .limitations
                    .iter()
                    .cloned()
                    .map(Into::into)
                    .collect(),
            ),
        )
        .with(
            "relationship_coverage",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with(
            "locations",
            Vec::<rea_application::javascript::graph::json::Json>::new(),
        )
        .with(
            "evidence_links",
            Vec::<rea_application::javascript::graph::json::Json>::new(),
        );
    let inventory_json: rea_application::javascript::graph::json::Json = inventory_unsigned.into();
    let inventory_raw = RawValue::from_string(inventory_json.stringify())
        .map_err(|error| AnalysisError::output("inventory_artifact", error.to_string()))?;
    let inventory_evidence = EvidenceRecord::create_unsigned(&inventory_raw)
        .map_err(|error| AnalysisError::output("inventory_artifact", error.to_string()))?;
    context
        .progress
        .report("inspect_artifact.inventory", "inventory substep completed");
    let inspection = inspection::create_artifact_inspection(&inventory_evidence, &inventory);
    let inspection_limitations = inspection
        .at("limitations")
        .arr()
        .iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    let inspection_unsigned = rea_application::javascript::graph::json::Obj::new()
        .with("subject", subject_json(&subject))
        .with(
            "provider",
            rea_application::javascript::graph::json::Obj::new()
                .with("id", "rea-artifact-graph")
                .with("name", "REA safe artifact graph provider")
                .with("version", "1"),
        )
        .with(
            "analysis_profile",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with("predicate_type", "rea.analysis")
        .with("operation", "inspect_artifact")
        .with(
            "parameters",
            rea_application::javascript::graph::json::parse(
                &serde_json::to_string(evidence_parameters).map_err(|error| {
                    AnalysisError::output("inspect_artifact", error.to_string())
                })?,
            )
            .map_err(|error| AnalysisError::output("inspect_artifact", error.to_string()))?,
        )
        .with(
            "raw_result",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with("normalized_result", inspection)
        .with("confidence", "observed")
        .with("authority", "shipped-artifact")
        .with(
            "environment",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with(
            "limitations",
            rea_application::javascript::graph::json::Json::array(
                inspection_limitations.into_iter().map(Into::into).collect(),
            ),
        )
        .with(
            "relationship_coverage",
            rea_application::javascript::graph::json::Json::Null,
        )
        .with(
            "locations",
            Vec::<rea_application::javascript::graph::json::Json>::new(),
        )
        .with(
            "evidence_links",
            vec![rea_application::javascript::graph::json::Json::from(
                inventory_evidence.evidence_id(),
            )],
        );
    let inspection_json: rea_application::javascript::graph::json::Json =
        inspection_unsigned.into();
    let raw = RawValue::from_string(inspection_json.stringify())
        .map_err(|error| AnalysisError::output("inspect_artifact", error.to_string()))?;
    let inspection_evidence = EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| AnalysisError::output("inspect_artifact", error.to_string()))?;
    Ok((inspection_evidence, inventory_evidence))
}

/// `extract_artifact`. Execution parameters add the REA-chosen `output_root`.
fn extract_artifact(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    let mut execution_parameters = input.as_object().cloned().unwrap_or_default();
    let output_root = extraction::create_extraction_destination();
    execution_parameters.insert("output_root".into(), Value::String(output_root));
    let evidence_parameters = input.clone();

    let call = ProviderCall {
        execution_parameters,
        evidence_parameters,
        summary: false,
        unavailable: None,
    };

    common::run_provider_tool(context, call, |target, parameters| {
        extract_execute(context, target, parameters)
    })
}

fn extract_execute(
    context: &ToolContext<'_>,
    target: &BinaryTarget,
    parameters: &Map<String, Value>,
) -> Result<ProviderOutcome, AnalysisError> {
    let fail = integrity_fail(parameters);
    let output_root = parameters
        .get("output_root")
        .and_then(Value::as_str)
        .ok_or_else(|| AnalysisError::artifact_operation("extract_artifact", "io"))?
        .to_owned();
    let source_path = source_or_path(target).to_owned();
    let input_format = target.format.clone();

    let result = extraction::extract_artifact(
        &source_path,
        &input_format,
        &output_root,
        fail,
        &context.cancellation,
    )
    .map_err(|failure| {
        // A non-extractable format is a caller-selection (unsupported target)
        // failure, not an I/O fault; preserve the TS AnalysisUnsupportedTargetError.
        if failure.reason == "format"
            && failure
                .message
                .starts_with("Artifact format has no extraction reader")
        {
            return AnalysisError::unsupported_target(
                "extract_artifact",
                &source_path,
                failure.message.clone(),
            );
        }
        if failure.reason == "format" && failure.message.contains("is encrypted") {
            return AnalysisError::unsupported_target(
                "extract_artifact",
                &source_path,
                failure.message.clone(),
            );
        }
        translate_artifact_failure("extract_artifact", to_cause(context, failure))
    })?;

    // subject = subjectFor(sourcePath, result.manifest).
    let manifest = result.get("manifest").cloned().unwrap_or(Value::Null);
    let subject = SubjectTarget {
        path: source_path.clone(),
        sha256: manifest
            .get("root_sha256")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        format: manifest
            .get("root_format")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        architecture: None,
    };
    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut execution = Execution::new(result, artifact_graph_provider());
    // rawResult: null (default), locations: [] (default).
    execution.limitations = limitations;
    execution.subject = Some(subject);
    Ok(ProviderOutcome::from(execution))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::cancellation::Cancellation;
    use rea_mcp::{Progress, Session, catalog};
    use std::sync::{Arc, Mutex};

    struct CleanupProbe {
        close_calls: Arc<Mutex<u32>>,
        close_failures: Arc<Mutex<u32>>,
    }

    impl reader::ArtifactReader for CleanupProbe {
        fn format(&self) -> &'static str {
            "test"
        }

        fn entries(
            &mut self,
            _cancellation: &Cancellation,
            _omissions: &mut Vec<reader::ArtifactTraversalOmission>,
        ) -> Result<Vec<reader::ArtifactEntry>, reader::ReaderFailure> {
            Ok(Vec::new())
        }

        fn open(
            &mut self,
            _entry: &reader::ArtifactEntry,
            _cancellation: &Cancellation,
        ) -> Result<Vec<u8>, reader::ReaderFailure> {
            Ok(Vec::new())
        }

        fn close(&mut self) -> Result<(), reader::ReaderFailure> {
            *self.close_calls.lock().expect("test close counter lock") += 1;
            let mut failures = self
                .close_failures
                .lock()
                .expect("test failure counter lock");
            if *failures == 0 {
                Ok(())
            } else {
                *failures -= 1;
                Err(reader::ReaderFailure::new("io", "close failed"))
            }
        }
    }

    #[test]
    fn adapter_translation_registers_retained_reader_with_session() {
        let close_calls = Arc::new(Mutex::new(0));
        let failure_count = Arc::new(Mutex::new(1));
        let mut failure = reader::ReaderFailure::new("io", "primary failure");
        failure.retain_reader(reader::RetainedReader::new(
            "test reader".to_owned(),
            Box::new(CleanupProbe {
                close_calls: Arc::clone(&close_calls),
                close_failures: Arc::clone(&failure_count),
            }),
        ));

        let session = Arc::new(Session::default());
        let context = ToolContext {
            contract: catalog()
                .tool("inspect_artifact")
                .expect("inspect_artifact contract"),
            session: &session,
            cancellation: Cancellation::default(),
            progress: Progress::silent(),
        };
        let error = translate_artifact_failure("inspect_artifact", to_cause(&context, failure));

        assert!(error.cleanup.is_none());
        assert!(session.close().is_err());
        assert_eq!(*close_calls.lock().expect("test close counter lock"), 1);
        assert!(session.close().is_ok());
        assert_eq!(*close_calls.lock().expect("test close counter lock"), 2);
    }
}
