//! `compare_process_captures` handler.
//!
//! Compatibility owner: `registerProcessComparisonTool`
//! (`src/server/registerProcessComparisonTool.ts`), with
//! `recordSessionEvidenceSources`, `runDerivedOperation` and
//! `recordDerivedEvidence`.
use crate::capture;
use crate::comparison::{self, Comparison, DIMENSIONS};
use crate::trace::spec::{self, Specification};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation};
use rea_core::evidence::record::{EvidenceRecord, EvidenceRecordError};
use rea_mcp::session::record_error;
use rea_mcp::{Session, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const CAPTURE_OPERATION: &str = "capture_process_scenario";
const CAPTURE_PREDICATE: &str = "rea.process-capture";

/// `PROCESS_PROVIDER` (`processEvidenceProvider.ts`).
fn provider() -> EvidenceProvider {
    EvidenceProvider::new("rea-process", "REA process capture", Some("3".to_owned()))
}

/// `isProcessEvidenceProvider`: the current and legacy names of provider v3.
fn is_process_provider(provider: &Value) -> bool {
    provider["id"] == "rea-process"
        && provider["version"] == "3"
        && matches!(
            provider["name"].as_str(),
            Some("REA process capture" | "REA deterministic process harness")
        )
}

/// `describeValidationFailure` for an Evidence authentication failure.
fn describe_evidence_failure(error: &EvidenceRecordError) -> String {
    match error {
        EvidenceRecordError::SemanticIdMismatch => {
            "at evidence_id: Evidence semantic identifier does not match its record".to_owned()
        }
        other => other.to_string(),
    }
}

/// `parseEvidence`: authenticate the caller's record and keep its projection.
fn parse_evidence(value: &Value) -> Result<Evidence, EvidenceRecordError> {
    let raw = serde_json::value::to_raw_value(value).map_err(EvidenceRecordError::Json)?;
    let record = EvidenceRecord::parse(&raw)?;
    Ok(Evidence::from_authenticated(
        record.evidence_id().to_owned(),
        value.clone(),
    ))
}

struct Side {
    record: Evidence,
    capture: Value,
}

fn input_issue(path: Vec<Value>, message: String) -> InputIssue {
    InputIssue {
        path,
        reason: "invalid_value",
        message: Some(message),
        expected: None,
        minimum: None,
        maximum: None,
    }
}

/// `parseCaptureSide`.
fn parse_side(operation: &str, side: &str, value: &Value) -> Result<Side, AnalysisError> {
    let record = parse_evidence(value).map_err(|error| {
        AnalysisError::evidence_integrity(format!("{side} Evidence failed validation"))
            .with_user_message(format!(
                "The {side} Evidence failed validation ({}). Supply unmodified capture Evidence from capture_process_scenario.",
                describe_evidence_failure(&error)
            ))
    })?;
    let evidence = record.value();
    let operation_name = evidence["operation"].as_str().unwrap_or_default();
    let predicate = evidence["predicate_type"].as_str().unwrap_or_default();
    if operation_name != CAPTURE_OPERATION || predicate != CAPTURE_PREDICATE {
        return Err(AnalysisError::input(
            operation,
            vec![input_issue(
                vec![json!(side)],
                format!(
                    "Expected process capture Evidence (operation {CAPTURE_OPERATION}, predicate {CAPTURE_PREDICATE}); the {side} Evidence has operation {operation_name} and predicate {predicate}."
                ),
            )],
        ));
    }
    let provider = &evidence["provider"];
    if !is_process_provider(provider) {
        let version = match &provider["version"] {
            Value::String(version) => version.clone(),
            other => other.to_string(),
        };
        return Err(AnalysisError::input(
            operation,
            vec![input_issue(
                vec![json!(side), json!("provider")],
                format!(
                    "The {side} Evidence provider {} v{version} ({}) is not the current or supported legacy rea-process v3 process capture provider.",
                    provider["id"].as_str().unwrap_or_default(),
                    provider["name"].as_str().unwrap_or_default(),
                ),
            )],
        ));
    }
    let capture = capture::parse(&evidence["normalized_result"]).map_err(|error| {
        AnalysisError::evidence_integrity(format!("{side} process capture failed validation"))
            .with_user_message(format!(
                "The {side} Evidence has an invalid process capture result ({}). Recreate the capture with capture_process_scenario.",
                error.describe()
            ))
    })?;
    Ok(Side { record, capture })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

/// `runDerivedOperation`: progress phases and cancellation guards.
fn run_derived<T>(
    context: &ToolContext<'_>,
    compute: impl FnOnce() -> Result<T, AnalysisError>,
) -> Result<T, AnalysisError> {
    let operation = context.name();
    context
        .progress
        .report("prepare", &format!("Preparing {operation}"));
    context.check_cancelled()?;
    let value = compute()?;
    context
        .progress
        .report("compute", &format!("Computed {operation}"));
    context.check_cancelled()?;
    context
        .progress
        .report("complete", &format!("Completed {operation}"));
    context.check_cancelled()?;
    Ok(value)
}

/// `comparisonUnknownInput`.
fn unknown_input(
    left_id: &str,
    right_id: &str,
    comparison_id: &str,
    comparison: &Comparison,
) -> Option<Value> {
    if comparison.status == "unchanged" {
        return None;
    }
    let scopes = DIMENSIONS
        .iter()
        .filter(|dimension| comparison.dimensions.get(dimension) != "unchanged")
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let contradictory = comparison.status == "changed" && left_id != right_id;
    let lead = if contradictory {
        "Process captures disagree".to_owned()
    } else {
        format!("Process comparison is {}", comparison.status)
    };
    let mut supporting = vec![left_id.to_owned()];
    if !contradictory && right_id != left_id {
        supporting.push(right_id.to_owned());
    }
    let contradicting = if contradictory {
        vec![right_id.to_owned()]
    } else {
        Vec::new()
    };
    let mut object = Map::new();
    object.insert(
        "question".into(),
        json!(format!(
            "{lead} across: {scopes} (comparison {comparison_id})"
        )),
    );
    object.insert("severity".into(), json!("high"));
    object.insert("domain".into(), json!("process-comparison"));
    object.insert("supporting_evidence_ids".into(), json!(supporting));
    object.insert("contradicting_evidence_ids".into(), json!(contradicting));
    object.insert("required_authority".into(), json!("controlled-replay"));
    object.insert("required_confidence".into(), json!("observed"));
    object.insert("required_environment".into(), Value::Null);
    object.insert(
        "recommended_probes".into(),
        json!([{
            "operation": CAPTURE_OPERATION,
            "rationale": "Repeat both scenarios under the same controlled environment.",
        }]),
    );
    object.insert("relationships".into(), json!([]));
    Some(Value::Object(object))
}

/// `recordDerivedEvidence`: retain derived Evidence, atomically with its
/// unknown when one applies.
fn record_derived(
    session: &Arc<Session>,
    evidence: &Evidence,
    unknown: Option<Value>,
) -> Result<(), AnalysisError> {
    let Some(unknown) = unknown else {
        return session.record(evidence);
    };
    let integrity = |error: serde_json::Error| AnalysisError::evidence_integrity(error.to_string());
    let evidence_raw = evidence.to_raw().map_err(integrity)?;
    let unknown_raw = serde_json::value::to_raw_value(&unknown).map_err(integrity)?;
    session
        .records()
        .record_evidence_with_unknown(&evidence_raw, &unknown_raw)
        .map_err(record_error)
}

fn locations(evidence: &Evidence) -> Vec<Value> {
    evidence.value()["locations"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// Handler for `compare_process_captures`.
pub fn compare_process_captures(context: &ToolContext<'_>, input: Value) -> ToolOutput {
    if let Some(trace_spec) = input.get("trace_spec") {
        let issues = spec::refinements(trace_spec);
        if !issues.is_empty() {
            let issues = issues
                .into_iter()
                .map(|(path, message)| (std::iter::once("trace_spec".to_owned()).chain(path).collect(), message))
                .collect();
            return crate::input_failure::refinement_failure(context, issues);
        }
    }
    // Session admission admits Evidence-only work; it still honors a
    // cancellation that arrived before the operation started.
    if let Err(error) = context.check_cancelled() {
        return ToolOutput::Failure(error);
    }
    match run(context, &input) {
        Ok(evidence) => ToolOutput::Evidence(evidence),
        Err(error) => ToolOutput::Failure(error),
    }
}

fn run(context: &ToolContext<'_>, input: &Value) -> Result<Evidence, AnalysisError> {
    let operation = context.name();
    let left = parse_side(operation, "left", &input["left"])?;
    let right = parse_side(operation, "right", &input["right"])?;
    let max_capture_age_ms = input.get("max_capture_age_ms").and_then(Value::as_u64);
    let specification = input.get("trace_spec").map(Specification::from_value);
    let comparison = run_derived(context, || {
        comparison::compare(
            &left.capture,
            &right.capture,
            max_capture_age_ms,
            now_ms(),
            specification.as_ref(),
        )
    })?;
    let left_id = left.record.id().to_owned();
    let right_id = right.record.id().to_owned();
    let mut parameters = Map::new();
    parameters.insert("left_evidence_id".into(), json!(left_id));
    parameters.insert("right_evidence_id".into(), json!(right_id));
    parameters.insert(
        "left_normalization".into(),
        left.capture["normalization"].clone(),
    );
    parameters.insert(
        "right_normalization".into(),
        right.capture["normalization"].clone(),
    );
    if let Some(maximum) = max_capture_age_ms {
        parameters.insert("max_capture_age_ms".into(), json!(maximum));
    }
    if let Some(specification) = &specification {
        parameters.insert("trace_spec".into(), specification.to_value());
    }
    let mut source_locations = locations(&left.record);
    source_locations.extend(locations(&right.record));
    let observation = Observation::new(
        operation,
        Value::Object(parameters),
        comparison.value.clone(),
    )
    .predicate("rea.process-comparison")
    .confidence("derived")
    .authority("analyst-inference")
    .limitations(comparison.limitations.clone())
    .locations(source_locations)
    .links(vec![left_id.clone(), right_id.clone()]);
    let evidence = Evidence::create(None, &provider(), observation)
        .map_err(|error| AnalysisError::output(operation, error.to_string()))?;
    // `recordSessionEvidenceSources`: sources first, in order.
    context.session.record(&left.record)?;
    context.session.record(&right.record)?;
    let unknown = unknown_input(&left_id, &right_id, evidence.id(), &comparison);
    record_derived(context.session, &evidence, unknown)?;
    Ok(evidence)
}
