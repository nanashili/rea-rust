//! Authenticated Evidence construction for JavaScript application analysis.
//!
//! The reconstruction stages deliberately use the application graph `Json`
//! type rather than `serde_json::Value`.  This adapter keeps that ownership at
//! the Evidence boundary too: a source path containing an unpaired UTF-16
//! code unit is serialized as its JSON escape and is never converted through a
//! Rust UTF-8 string.

use rea_application::javascript::semantic::value_types::JsString;
use rea_application::javascript::{
    application_view_exact,
    graph::json::{self, Json, Obj},
};
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use rea_mcp::{ToolContext, ToolOutput};
use serde_json::value::RawValue;

const OPERATION: &str = "analyze_javascript_application";
const PREDICATE: &str = "rea.javascript-application-analysis";
const PROVIDER_ID: &str = "rea-javascript-application";
const PROVIDER_NAME: &str = "REA JavaScript application analyzer";
const PROVIDER_VERSION: &str = "1";

/// Inputs needed to turn a completed reconstruction into authenticated
/// application Evidence.
///
/// `parameters` is already validated by the application boundary.  It stays
/// as graph `Json` so the caller can preserve exact source strings there as
/// well.  The path and artifact identity are supplied separately because the
/// reconstructed result is the authoritative source of those values.
pub struct ReconstructionEvidenceInput<'a> {
    /// The validated analysis parameters, excluding `detail`.
    pub parameters: &'a Json,
    /// The assembled reconstruction result containing `electron_summary`.
    pub result: Json,
    /// The caller-selected input path, including any unpaired UTF-16 units.
    /// The resolved subject path is read from the completed result instead.
    pub input_path: JsString,
    /// The caller-requested artifact format (`auto`, `asar`, or `directory`).
    pub format: String,
    /// The authenticated root artifact digest.
    pub root_artifact_sha256: String,
}

/// Create and authenticate the complete JavaScript application Evidence.
///
/// The result projection follows the TypeScript service: `electron_summary`
/// becomes `summary`, and the top-level limitations are the graph's
/// limitations.  The returned record retains its canonical raw JSON, which is
/// the form required for session retention without a lossy `Value` round trip.
pub fn create(
    input: ReconstructionEvidenceInput<'_>,
) -> Result<EvidenceRecord, EvidenceRecordError> {
    let parameters = analysis_parameters(&input)?;
    let resolved_subject = resolved_subject(&input.result)?;
    let subject_path = resolved_subject.path.clone();
    let subject_format = resolved_subject.format.to_owned();

    validate_root_artifact_digest(&input.result, &input.root_artifact_sha256)?;
    let limitations = graph_limitations(&input.result)?;
    let normalized_result = application_result(input.result, &limitations)?;

    let subject = Obj::new()
        .with("name", display_name(&subject_path))
        .with(
            "digest",
            Obj::new().with("sha256", input.root_artifact_sha256),
        )
        .with("local_path", subject_path)
        .with("format", subject_format)
        .with("architecture", Json::Null);
    let provider = Obj::new()
        .with("id", PROVIDER_ID)
        .with("name", PROVIDER_NAME)
        .with("version", PROVIDER_VERSION);
    let locations = Json::Array(vec![
        Obj::new()
            .with("kind", "artifact-path")
            .with("path", "artifact-root")
            .into(),
    ]);

    let unsigned = Obj::new()
        .with("subject", subject)
        .with("provider", provider)
        .with("analysis_profile", Json::Null)
        .with("predicate_type", PREDICATE)
        .with("operation", OPERATION)
        .with("parameters", parameters)
        .with("raw_result", Json::Null)
        .with("normalized_result", normalized_result)
        .with("confidence", "derived")
        .with("authority", "shipped-artifact")
        .with("environment", Json::Null)
        .with("limitations", limitations)
        .with("relationship_coverage", Json::Null)
        .with("locations", locations)
        .with("evidence_links", Json::Array(Vec::new()));

    let raw = RawValue::from_string(Json::from(unsigned).stringify())
        .map_err(EvidenceRecordError::Json)?;
    EvidenceRecord::create_unsigned(&raw)
}

struct ResolvedSubject<'a> {
    path: &'a JsString,
    format: &'a str,
}

fn resolved_subject(result: &Json) -> Result<ResolvedSubject<'_>, EvidenceRecordError> {
    let path = result
        .get("input_path")
        .and_then(Json::as_js_string)
        .ok_or_else(|| invalid("JavaScript application result is missing input_path"))?;
    let format = result
        .get("format")
        .and_then(Json::as_str)
        .ok_or_else(|| invalid("JavaScript application result is missing format"))?;
    Ok(ResolvedSubject { path, format })
}

fn validate_root_artifact_digest(result: &Json, expected: &str) -> Result<(), EvidenceRecordError> {
    let actual = result
        .get("root_artifact_sha256")
        .and_then(Json::as_str)
        .ok_or_else(|| invalid("JavaScript application result is missing root_artifact_sha256"))?;
    if actual != expected {
        return Err(invalid(
            "JavaScript application result root_artifact_sha256 differs from the authenticated artifact digest",
        ));
    }
    Ok(())
}

/// Build a successful or interrupted result while retaining the exact
/// completed observation in the session ledger.
///
/// Cancellation and resource failures keep the same error algebra as the
/// ordinary handler path, but carry the partial record separately so the
/// error projection never has to decode its source strings into `Value`.
pub fn deliver(
    context: &ToolContext<'_>,
    input: ReconstructionEvidenceInput<'_>,
    detail: Option<&str>,
    interruption: Option<AnalysisError>,
) -> ToolOutput {
    let evidence = match create(input) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(AnalysisError::evidence_integrity(error.to_string()));
        }
    };
    match interruption {
        Some(error) => ToolOutput::RawFailure { evidence, error },
        None if detail == Some("summary") => match summarize(context, evidence) {
            Ok(summary) => ToolOutput::RawEvidence(summary),
            Err(error) => ToolOutput::Failure(error),
        },
        None => ToolOutput::RawEvidence(evidence),
    }
}

/// Retain the complete parent before returning the authenticated summary
/// projection. The complete record remains the source for later views and
/// comparisons; the projected record is only the caller-facing delivery.
fn summarize(
    context: &ToolContext<'_>,
    evidence: EvidenceRecord,
) -> Result<EvidenceRecord, AnalysisError> {
    context.session.record_raw(evidence.raw())?;

    let view: Json = Obj::new().with("kind", "summary").into();
    let raw = application_view_exact::project_exact_evidence(&evidence, &view)?;
    let summary = EvidenceRecord::parse(&raw).map_err(|error| {
        AnalysisError::evidence_integrity(format!(
            "JavaScript summary Evidence was invalid after projection: {error}"
        ))
    })?;
    if let Some(root) = rea_mcp::schema::published_view_result_schema() {
        let normalized_result =
            json::parse(summary.normalized_result().get()).map_err(|error| {
                AnalysisError::evidence_integrity(format!(
                    "JavaScript summary normalized_result is not exact JSON: {error}"
                ))
            })?;
        rea_application::javascript::application_view_validation::validate(
            &normalized_result,
            &root,
        )?;
    }
    Ok(summary)
}

fn analysis_parameters(
    input: &ReconstructionEvidenceInput<'_>,
) -> Result<Json, EvidenceRecordError> {
    let Json::Object(mut parameters) = input.parameters.clone() else {
        return Err(invalid("analysis parameters must be an object"));
    };

    parameters.set("input_path", input.input_path.clone());
    parameters.set("format", input.format.clone());
    parameters.remove("detail");
    Ok(parameters.into())
}

fn application_result(result: Json, limitations: &Json) -> Result<Json, EvidenceRecordError> {
    let Json::Object(mut result) = result else {
        return Err(invalid("JavaScript application result must be an object"));
    };

    let Some(summary) = result.remove("electron_summary") else {
        return Err(invalid(
            "JavaScript application result is missing electron_summary",
        ));
    };
    result.set("summary", summary);
    result.set("limitations", limitations.clone());
    Ok(result.into())
}

fn graph_limitations(result: &Json) -> Result<Json, EvidenceRecordError> {
    let graph = result
        .get("graph")
        .ok_or_else(|| invalid("JavaScript application result is missing graph"))?;
    let limitations = graph
        .get("limitations")
        .ok_or_else(|| invalid("JavaScript application graph is missing limitations"))?;
    if !matches!(limitations, Json::Array(_)) {
        return Err(invalid(
            "JavaScript application graph limitations must be an array",
        ));
    }
    Ok(limitations.clone())
}

fn display_name(path: &JsString) -> JsString {
    let units = path.units();
    let last_separator = units
        .iter()
        .rposition(|unit| *unit == b'/' as u16 || *unit == b'\\' as u16);
    let name = last_separator.map_or(units, |index| &units[index + 1..]);
    if name.is_empty() {
        JsString::from("artifact")
    } else {
        JsString::from_utf16(name.to_vec())
    }
}

fn invalid(message: &str) -> EvidenceRecordError {
    EvidenceRecordError::Invalid(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rea_core::cancellation::Cancellation;
    use rea_mcp::{Progress, Session, catalog::catalog};
    use std::collections::HashMap;
    use std::sync::Arc;

    #[test]
    fn retains_unpaired_path_and_maps_electron_summary() {
        let digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let path =
            JsString::from_utf16([b'/' as u16, b't' as u16, 0xd800, b'/' as u16, b'a' as u16]);
        let caller_path = JsString::from("./relative/app");
        let graph = Obj::new().with(
            "limitations",
            Json::Array(vec![Json::String(JsString::from_utf16([0xdc00]))]),
        );
        let result: Json = Obj::new()
            .with("input_path", path.clone())
            .with("format", "directory")
            .with("root_artifact_sha256", digest)
            .with("graph", graph)
            .with("electron_summary", Obj::new().with("status", "complete"))
            .into();
        let parameters = Obj::new()
            .with("integrity_policy", "strict")
            .with("input_path", "./relative/app")
            .with("format", "auto")
            .with("detail", "full")
            .into();

        let evidence = create(ReconstructionEvidenceInput {
            parameters: &parameters,
            result: result.clone(),
            input_path: caller_path.clone(),
            format: "auto".to_owned(),
            root_artifact_sha256: digest.to_owned(),
        })
        .expect("exact application Evidence");
        let raw = evidence.raw().get();
        assert!(raw.contains("\\ud800"));
        assert!(raw.contains("\\udc00"));
        assert!(raw.contains("\"summary\""));
        assert!(!raw.contains("electron_summary"));
        assert!(raw.contains("\"input_path\":\"./relative/app\""));
        assert!(raw.contains("\"format\":\"auto\""));
        assert!(raw.contains("\"local_path\":\"/t\\ud800/a\""));
        assert!(raw.contains("\"format\":\"directory\""));
        assert!(!raw.contains("\"detail\""));
    }

    #[test]
    fn interruption_keeps_exact_partial_record_separate_from_error() {
        let digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let resolved_path = JsString::from_utf16([b'/' as u16, b'a' as u16, 0xd800]);
        let caller_path = JsString::from("./app");
        let graph = Obj::new().with("limitations", Json::Array(Vec::new()));
        let result = Obj::new()
            .with("input_path", resolved_path)
            .with("format", "directory")
            .with("root_artifact_sha256", digest)
            .with("graph", graph)
            .with("electron_summary", Obj::new().with("status", "cancelled"))
            .into();
        let parameters = Obj::new().into();
        let contract = catalog()
            .tool(OPERATION)
            .expect("application operation is catalogued");
        let session = Arc::new(Session::new(HashMap::new()));
        let context = ToolContext {
            contract,
            session: &session,
            cancellation: Cancellation::default(),
            progress: Progress::silent(),
        };

        let output = deliver(
            &context,
            ReconstructionEvidenceInput {
                parameters: &parameters,
                result,
                input_path: caller_path,
                format: "auto".to_owned(),
                root_artifact_sha256: digest.to_owned(),
            },
            None,
            Some(AnalysisError::cancelled(OPERATION)),
        );

        let ToolOutput::RawFailure { evidence, error } = output else {
            panic!("interrupted analysis must retain raw partial Evidence");
        };
        assert!(evidence.raw().get().contains("\\ud800"));
        assert!(evidence.raw().get().contains(digest));
        assert_eq!(error.code(), "cancelled");
    }
}
