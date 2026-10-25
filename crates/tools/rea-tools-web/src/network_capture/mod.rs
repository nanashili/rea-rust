//! Historical network-capture inspection (`inspect_web_network_capture`).
//!
//! Compatibility owners: `src/server/registerWebNetworkCaptureTool.ts`,
//! `src/application/WebNetworkCaptureService.ts`, `src/domain/webNetworkCapture*.ts`,
//! `src/domain/explicitSensitiveFailure.ts`, `src/domain/inputIssueProjection.ts`
//! and `src/browser/history/*`.
//!
//! The tool reads one explicit retained capture, decodes it offline without
//! contacting its recorded destinations, and returns the selected complete
//! records inline as Evidence. HAR is decoded in-process (the TS isolates the
//! decode in an owned Node process only for heap bounds) with the same 32 MiB
//! input, 96 MiB reply and 64-level nesting budgets and the same reply and
//! failure semantics. SAZ and qlog use the shared bounded native decoder in
//! `rea-application`; mitmproxy (which needs an external Linux `mitmdump`)
//! remains an explicit host capability.
mod errors;
mod har;
mod json_capture;
mod limits;
mod mitmproxy;
mod redaction;

use rea_application::analysis_view;
use rea_core::analysis_error::AnalysisError;
use rea_core::evidence::envelope::{Evidence, EvidenceProvider, Observation, SubjectTarget};
use rea_mcp::{Registry, ToolContext, ToolOutput};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const OPERATION: &str = "inspect_web_network_capture";

const CAPTURE_LIMITATIONS: [&str; 4] = [
    "This is retained producer evidence, without live browser transaction IDs, scenario provenance, execution attribution or deployment authenticity. Recorded URLs are never fetched.",
    "Every record is decoded before selection; no partial success is returned on malformed input or a resource limit.",
    "Known authentication headers/cookies and explicitly marked literal values are excluded. Unknown extension names do not establish sensitivity.",
    "A 32 MiB input, 96 MiB reply and 64-level nesting budget bound complete evidence. HAR/SAZ/qlog use a 192 MiB Node old-generation heap; mitmproxy decoding uses a 768 MiB Linux address-space limit. Each owned command has a 30-second deadline with independent cleanup.",
];

const SAZ_LIMITATIONS: [&str; 4] = [
    "SAZ ordinals follow first session-member occurrence in ZIP directory order, not chronology or numeric session ID.",
    "HTTP fields use byte-preserving Latin-1 text; start-line separators and header delimiters are not projected. Bodies retain stored bytes without transfer/content decoding. Absent members are null, distinct from empty bodies.",
    "XML preserves node order and attribute/text values, not its original byte serialization. WebSocket and gRPC members retain opaque message-file bytes, not decoded protocol events.",
    "Non-session archive members are inventoried but their content is not decoded.",
];

/// Bind the tool to its named contract.
pub(crate) fn register(registry: &mut Registry) {
    registry.handle_application_validated(OPERATION, |context, input| inspect(context, &input));
}

/// `inspect_web_network_capture`: complete Evidence inline, or its summary view.
fn inspect(context: &ToolContext<'_>, input: &Value) -> ToolOutput {
    if context.cancellation.reason().is_some() {
        return ToolOutput::Failure(AnalysisError::cancelled(OPERATION));
    }

    let parsed = match rea_mcp::schema::parse_application_input(OPERATION, input) {
        Ok(parsed) => parsed,
        Err(error) => return ToolOutput::Failure(error),
    };
    let sensitive_values = sensitive_values(&parsed);
    let detail = rea_mcp::support::optional_string(&parsed, "detail").unwrap_or("complete");

    let evidence = match run(context, &parsed, &sensitive_values) {
        Ok(evidence) => evidence,
        Err(error) => {
            return ToolOutput::Failure(redact_failure(error, &sensitive_values));
        }
    };

    if detail != "summary" {
        return ToolOutput::Evidence(evidence);
    }
    match summarize_retained(context, evidence) {
        Ok(view) => ToolOutput::Evidence(view),
        Err(error) => ToolOutput::Failure(error),
    }
}

/// Decode the selected capture and project its complete Evidence.
fn run(
    context: &ToolContext<'_>,
    input: &Value,
    sensitive_values: &[String],
) -> Result<Evidence, AnalysisError> {
    let capture_path = rea_mcp::support::string(input, "capture_path").to_owned();
    let format = rea_mcp::support::string(input, "format").to_owned();
    let record_ordinals = record_ordinals(input);

    // Service refinement: absolute path on this host.
    if !std::path::Path::new(&capture_path).is_absolute() {
        return Err(errors::input_issue(
            "capture_path",
            "invalid_format",
            "Expected an absolute filesystem path on this host.",
        ));
    }
    // Service refinement: each requested ordinal occurs once.
    if let Some(ordinals) = &record_ordinals {
        let mut seen = std::collections::HashSet::new();
        if !ordinals.iter().all(|value| seen.insert(*value)) {
            return Err(errors::input_issue(
                "record_ordinals",
                "invalid_format",
                "Each requested producer ordinal must occur once.",
            ));
        }
    }

    // mitmproxy needs an external Linux engine. SAZ and qlog are decoded by
    // the bounded application decoder, which owns their ZIP/XML and qlog
    // boundary handling.
    match format.as_str() {
        "har" => {}
        "mitmproxy" => {
            let result = mitmproxy::decode(
                input,
                sensitive_values,
                context.session.env("REA_MITMDUMP_COMMAND"),
                &context.cancellation,
                context.session,
            )?;
            return finish_native_capture(input, sensitive_values, result);
        }
        "saz" | "qlog" => return run_native_capture(input, sensitive_values),
        _ => {
            return Err(AnalysisError::capability_unavailable(
                &format,
                OPERATION,
                "No adapter is configured for the selected capture format.",
            ));
        }
    }

    let snapshot = read_capture(&capture_path)?;

    let text = json_capture::decode_capture_text(&snapshot.bytes, "HAR")
        .map_err(|error| errors::from_capture_error(&format, error))?;
    let decoded = har::decode_har_capture(&text, sensitive_values)
        .map_err(|error| errors::from_capture_error(&format, error))?;

    project_capture(
        &capture_path,
        &format,
        &record_ordinals,
        sensitive_values,
        &snapshot,
        decoded,
    )
}

/// Decode SAZ/qlog through the application-owned bounded producer. Keeping
/// this call at the format boundary avoids a second ZIP/XML implementation in
/// the web tool while preserving the same Evidence envelope used by HAR.
fn run_native_capture(
    input: &Value,
    sensitive_values: &[String],
) -> Result<Evidence, AnalysisError> {
    if input.get("format").and_then(Value::as_str) == Some("qlog") {
        let path = input
            .get("capture_path")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let snapshot = read_capture(path)?;
        let text = json_capture::decode_capture_text(&snapshot.bytes, "qlog")
            .map_err(|error| errors::from_capture_error("qlog", error))?;
        json_capture::parse_capture_json(&text, "qlog")
            .map_err(|error| errors::from_capture_error("qlog", error))?;
    }
    let result = rea_application::web::network_capture::inspect(input).map_err(|error| {
        AnalysisError::provider_adapter(
            input
                .get("format")
                .and_then(Value::as_str)
                .unwrap_or("capture"),
            OPERATION,
        )
        .with_user_message(redaction::redact_explicit_text(
            &error.to_string(),
            sensitive_values,
        ))
    })?;

    finish_native_capture(input, sensitive_values, result)
}

/// Add the shared Evidence envelope after a native format-specific producer
/// has returned its complete, unselected record sequence.
fn finish_native_capture(
    input: &Value,
    sensitive_values: &[String],
    mut result: Value,
) -> Result<Evidence, AnalysisError> {
    let source_path = input
        .get("capture_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let path_hidden = sensitive_values
        .iter()
        .any(|literal| source_path.contains(literal));
    let path = if path_hidden {
        String::new()
    } else {
        redaction::redact_explicit_text(source_path, sensitive_values)
    };
    if path_hidden {
        result["artifact"]["path"] = Value::String(String::new());
    }
    let mut result_limitations = format_limitations(input, sensitive_values, &path);
    if path_hidden {
        result_limitations.push(
            "The explicitly sensitive artifact path is excluded; its size remains available."
                .to_owned(),
        );
    }
    result["limitations"] = Value::Array(
        result_limitations
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    select_native_records(&mut result, input.get("record_ordinals"))?;
    let digest = result
        .get("artifact")
        .and_then(|artifact| artifact.get("sha256"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let provider_value = result.get("decoder").cloned().unwrap_or_else(|| {
        json!({"id": "rea-native-capture", "name": "REA native capture adapter", "version": "1"})
    });
    let provider = EvidenceProvider::new(
        provider_value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("rea-native-capture"),
        provider_value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("REA native capture adapter"),
        provider_value
            .get("version")
            .and_then(Value::as_str)
            .map(str::to_owned),
    );
    let parameters = sanitized_parameters(input, sensitive_values, &result);
    let limitations = result_limitations;
    let qlog_profile = result.get("qlog").and_then(|qlog| {
        Some(json!({
            "provider": provider_value.clone(),
            "parameters": {
                "qlog_profile": qlog.get("profile")?,
                "clock": qlog.get("clock")?,
                "scope": qlog.get("scope")?,
            }
        }))
    });
    let locations = if path.is_empty() {
        Vec::new()
    } else {
        vec![json!({"kind":"artifact-path","path":path})]
    };
    let mut observation = Observation::new(OPERATION, parameters, result)
        .confidence("observed")
        .authority("historical-reference")
        .limitations(limitations)
        .locations(locations);
    if let Some(profile) = qlog_profile {
        let parameters = profile
            .get("parameters")
            .cloned()
            .unwrap_or_else(|| json!({}));
        let unsigned = json!({"provider": provider_value, "parameters": parameters});
        let digest = rea_core::canonical_json::digest(&unsigned)
            .map_err(|error| AnalysisError::output(OPERATION, error.to_string()))?;
        let mut profile = unsigned;
        profile["digest"] = json!(digest);
        observation = observation.profile(profile);
    }
    let target = if digest.is_empty() {
        None
    } else {
        Some(SubjectTarget {
            path: path.clone(),
            sha256: digest.to_owned(),
            format: "file".to_owned(),
            architecture: None,
        })
    };
    rea_mcp::support::evidence(target.as_ref(), &provider, observation)
}

fn select_native_records(
    result: &mut Value,
    requested: Option<&Value>,
) -> Result<(), AnalysisError> {
    let Some(requested) = requested else {
        return Ok(());
    };
    let Some(ordinals) = requested.as_array() else {
        return Err(errors::input_issue(
            "record_ordinals",
            "invalid_format",
            "Each requested producer ordinal must be a non-negative integer.",
        ));
    };
    let Some(records) = result.get("records").and_then(Value::as_array).cloned() else {
        return Err(AnalysisError::output(
            OPERATION,
            "Native capture decoder omitted records.",
        ));
    };
    let mut selected = Vec::with_capacity(ordinals.len());
    for ordinal in ordinals {
        let Some(index) = ordinal.as_u64() else {
            return Err(errors::input_issue(
                "record_ordinals",
                "invalid_format",
                "Each requested producer ordinal must be a non-negative integer.",
            ));
        };
        let Some(record) = records.get(index as usize) else {
            return Err(errors::input_issue(
                "record_ordinals",
                "invalid_format",
                &format!("Producer ordinal {index} is outside the retained capture."),
            ));
        };
        selected.push(record.clone());
    }
    result["records"] = Value::Array(selected);
    Ok(())
}

fn sanitized_parameters(input: &Value, sensitive_values: &[String], result: &Value) -> Value {
    let mut parameters = Map::new();
    let source_path = input
        .get("capture_path")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let safe_path = if sensitive_values
        .iter()
        .any(|literal| source_path.contains(literal))
    {
        String::new()
    } else {
        redaction::redact_explicit_text(source_path, sensitive_values)
    };
    parameters.insert("capture_path".into(), Value::String(safe_path));

    if let Some(format) = input.get("format") {
        parameters.insert("format".into(), format.clone());
    }

    let total_records = result
        .get("total_records")
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let ordinals = input
        .get("record_ordinals")
        .cloned()
        .unwrap_or_else(|| Value::Array((0..total_records).map(Value::from).collect()));
    parameters.insert("record_ordinals".into(), ordinals);

    parameters.insert(
        "sensitive_value_count".into(),
        json!(sensitive_values.len()),
    );
    Value::Object(parameters)
}

fn format_limitations(
    input: &Value,
    _sensitive_values: &[String],
    _safe_path: &str,
) -> Vec<String> {
    let mut limitations = CAPTURE_LIMITATIONS
        .iter()
        .map(|limitation| (*limitation).to_owned())
        .collect::<Vec<_>>();
    if input.get("format").and_then(Value::as_str) == Some("saz") {
        limitations.splice(
            0..0,
            SAZ_LIMITATIONS
                .iter()
                .map(|limitation| (*limitation).to_owned()),
        );
    }
    limitations
}

/// Capture snapshot facts: resident bytes and the observed digest.
struct Snapshot {
    bytes: Vec<u8>,
    sha256: String,
}

/// Read and digest the selected capture, mapping failures like the oracle.
fn read_capture(path: &str) -> Result<Snapshot, AnalysisError> {
    let metadata = std::fs::metadata(path).map_err(|error| map_io(path, &error))?;
    if metadata.len() as usize > limits::CAPTURE_INPUT_BYTES {
        return Err(errors::over_input_limit(&format!(
            "Capture exceeds the {}-byte input budget",
            limits::CAPTURE_INPUT_BYTES
        )));
    }
    let bytes = std::fs::read(path).map_err(|error| map_io(path, &error))?;
    if bytes.len() > limits::CAPTURE_INPUT_BYTES {
        return Err(errors::over_input_limit(&format!(
            "Capture exceeds the {}-byte input budget",
            limits::CAPTURE_INPUT_BYTES
        )));
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let sha256 = format!("{:x}", hasher.finalize());
    Ok(Snapshot { bytes, sha256 })
}

/// Map a filesystem error to the oracle's typed capture-read failure.
fn map_io(path: &str, error: &std::io::Error) -> AnalysisError {
    use std::io::ErrorKind;
    match error.kind() {
        ErrorKind::NotFound => errors::not_found(path, "ENOENT"),
        ErrorKind::PermissionDenied => errors::access_denied(path, "EACCES"),
        _ => {
            if let Some(20) = error.raw_os_error() {
                // ENOTDIR.
                return errors::not_found(path, "ENOTDIR");
            }
            errors::not_found(path, &io_code(error))
        }
    }
}

fn io_code(error: &std::io::Error) -> String {
    match error.raw_os_error() {
        Some(2) => "ENOENT".to_owned(),
        Some(20) => "ENOTDIR".to_owned(),
        Some(code) => format!("OS error {code}"),
        None => "unknown".to_owned(),
    }
}

/// `#projectCapture`: exclude coordinates, select records and build Evidence.
fn project_capture(
    capture_path: &str,
    format: &str,
    record_ordinals: &Option<Vec<u64>>,
    sensitive_values: &[String],
    snapshot: &Snapshot,
    decoded: har::DecodedCapture,
) -> Result<Evidence, AnalysisError> {
    let artifact_sha256 = &snapshot.sha256;

    // Exclude marked source coordinates from the whole capture.
    let (container, mut records, base_limitations, coordinates_excluded) =
        exclude_coordinates(decoded, sensitive_values);

    let redact_text = |text: &str| redaction::redact_explicit_text(text, sensitive_values);

    let total_records = records.len();
    let selected: Vec<u64> = match record_ordinals {
        Some(ordinals) => ordinals.clone(),
        None => (0..total_records as u64).collect(),
    };

    let mut selected_records = Vec::with_capacity(selected.len());
    for ordinal in &selected {
        let record = records.get(*ordinal as usize).cloned().ok_or_else(|| {
            errors::input_issue(
                "record_ordinals",
                "invalid_format",
                &format!(
                    "Producer ordinal {ordinal} is outside the retained capture ({total_records} records)."
                ),
            )
        })?;
        // Redact each record limitation.
        let mut record = record;
        if let Some(limitations) = record.get_mut("limitations").and_then(Value::as_array_mut) {
            for limitation in limitations.iter_mut() {
                if let Some(text) = limitation.as_str() {
                    *limitation = Value::String(redact_text(text));
                }
            }
        }
        selected_records.push(record);
    }
    let _ = &mut records;

    let safe_path = if sensitive_values
        .iter()
        .any(|literal| capture_path.contains(literal.as_str()))
    {
        String::new()
    } else {
        capture_path.to_owned()
    };
    let safe_sha256 = if sensitive_values
        .iter()
        .any(|literal| artifact_sha256.contains(literal.as_str()))
    {
        None
    } else {
        Some(artifact_sha256.clone())
    };
    let subject_unavailable_reason = redact_text(
        "The explicitly sensitive artifact digest is excluded; its cryptographic identity is unknown in this Evidence.",
    );

    // Limitations: base (capture + coordinate note) plus the excluded-path note.
    let mut limitation_sources = base_limitations.clone();
    if safe_path.is_empty() {
        limitation_sources.push(
            "The explicitly sensitive artifact path is excluded; its size remains available."
                .to_owned(),
        );
    }
    let limitations: Vec<String> = limitation_sources
        .iter()
        .map(|text| redact_text(text))
        .collect();

    // Parameters: redact path/format, keep selected ordinals and literal count.
    let mut parameters = Map::new();
    parameters.insert("capture_path".into(), json!(safe_path));
    if !sensitive_values
        .iter()
        .any(|literal| format.contains(literal.as_str()))
    {
        parameters.insert("format".into(), json!(format));
    }
    parameters.insert(
        "record_ordinals".into(),
        Value::Array(selected.iter().map(|value| json!(value)).collect()),
    );
    parameters.insert(
        "sensitive_value_count".into(),
        json!(sensitive_values.len()),
    );

    // Build the result object (safeValue projection + selected records).
    let mut result = Map::new();
    result.insert(
        "decoder".into(),
        json!({ "id": har::HAR_ID, "name": har::HAR_NAME, "version": har::HAR_VERSION }),
    );
    result.insert(
        "container".into(),
        json!({
            "reported": container.reported,
            "numeric_literals": container.numeric_literals,
            "redactions": container.redactions,
            "records_pointer": container.records_pointer,
        }),
    );
    result.insert("total_records".into(), json!(total_records));
    result.insert("records".into(), Value::Array(selected_records));
    result.insert(
        "artifact".into(),
        json!({
            "path": safe_path,
            "sha256": safe_sha256.clone().map_or(Value::Null, Value::String),
            "bytes": snapshot.bytes.len(),
        }),
    );
    result.insert("runtime_attribution".into(), json!("unknown"));
    let mut result_limitations = limitations.clone();
    if safe_sha256.is_none() {
        result_limitations.push(subject_unavailable_reason.clone());
    }
    result.insert(
        "limitations".into(),
        Value::Array(result_limitations.into_iter().map(Value::String).collect()),
    );
    result.insert("format".into(), json!(format));

    let provider = EvidenceProvider::new(
        har::HAR_ID,
        har::HAR_NAME,
        Some(har::HAR_VERSION.to_owned()),
    );

    let target = safe_sha256.as_ref().map(|sha256| SubjectTarget {
        path: safe_path.clone(),
        sha256: sha256.clone(),
        format: "file".to_owned(),
        architecture: None,
    });

    let locations = if safe_path.is_empty() {
        Vec::new()
    } else {
        vec![json!({ "kind": "artifact-path", "path": safe_path })]
    };

    let mut observation =
        Observation::new(OPERATION, Value::Object(parameters), Value::Object(result))
            .confidence("observed")
            .authority("historical-reference")
            .limitations(limitations)
            .locations(locations);
    if safe_sha256.is_none() {
        observation = observation.subject_unavailable(subject_unavailable_reason);
    }
    let _ = coordinates_excluded;

    rea_mcp::support::evidence(target.as_ref(), &provider, observation)
}

/// `excludeCaptureCoordinates`: drop marked source coordinates and sidecars.
///
/// Returns the container facts, the records, the capture-level limitations and
/// whether any coordinate was excluded.
fn exclude_coordinates(
    decoded: har::DecodedCapture,
    sensitive_values: &[String],
) -> (ContainerOut, Vec<Value>, Vec<String>, bool) {
    let mut base_limitations: Vec<String> =
        CAPTURE_LIMITATIONS.iter().map(|s| s.to_string()).collect();
    let container = ContainerOut {
        reported: decoded.container.reported,
        numeric_literals: decoded.container.numeric_literals,
        redactions: decoded.container.redactions,
        records_pointer: decoded
            .container
            .records_pointer
            .map_or(Value::Null, Value::String),
    };

    if sensitive_values.is_empty() {
        return (container, decoded.records, base_limitations, false);
    }

    let sensitive = |pointer: &str| {
        sensitive_values
            .iter()
            .any(|literal| pointer.contains(literal.as_str()))
    };
    let mut excluded = false;

    let filter_sidecars = |items: &mut Vec<Value>, excluded: &mut bool| {
        items.retain(|item| {
            let pointer = item.get("pointer").and_then(Value::as_str).unwrap_or("");
            if sensitive(pointer) {
                *excluded = true;
                false
            } else {
                true
            }
        });
    };

    let mut records = decoded.records;
    for record in &mut records {
        // Location exclusion.
        if let Some(location) = record.get("location").cloned() {
            let kind = location.get("kind").and_then(Value::as_str).unwrap_or("");
            let excise = match kind {
                "json-pointer" => location
                    .get("pointer")
                    .and_then(Value::as_str)
                    .map(|p| sensitive(p))
                    .unwrap_or(false),
                "archive-members" => location
                    .get("members")
                    .and_then(Value::as_array)
                    .map(|members| {
                        members
                            .iter()
                            .any(|m| m.as_str().map(|p| sensitive(p)).unwrap_or(false))
                    })
                    .unwrap_or(false),
                "byte-range" => {
                    let offset = location
                        .get("offset")
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    let bytes = location
                        .get("bytes")
                        .map(|v| v.to_string())
                        .unwrap_or_default();
                    sensitive(&offset) || sensitive(&bytes)
                }
                _ => false,
            };
            if excise {
                excluded = true;
                record.as_object_mut().unwrap().insert(
                    "location".into(),
                    json!({ "kind": "unknown", "reason": "explicit-sensitive-value" }),
                );
            }
        }
        if let Some(items) = record
            .get_mut("binary_fields")
            .and_then(Value::as_array_mut)
        {
            filter_sidecars(items, &mut excluded);
        }
        if let Some(items) = record
            .get_mut("numeric_literals")
            .and_then(Value::as_array_mut)
        {
            filter_sidecars(items, &mut excluded);
        }
        if let Some(items) = record.get_mut("redactions").and_then(Value::as_array_mut) {
            filter_sidecars(items, &mut excluded);
        }
    }

    // Container sidecars + records_pointer.
    let mut container = container;
    filter_sidecars(&mut container.numeric_literals, &mut excluded);
    filter_sidecars(&mut container.redactions, &mut excluded);
    if let Some(pointer) = container.records_pointer.as_str() {
        if sensitive(pointer) {
            excluded = true;
            container.records_pointer = Value::Null;
        }
    }

    if excluded {
        base_limitations.push(redaction::redact_explicit_text(
            "Marked source coordinates and their sidecars are excluded; affected record locations remain unknown.",
            sensitive_values,
        ));
    }

    (container, records, base_limitations, excluded)
}

/// Container facts with sidecar arrays retained as `Value`s for filtering.
struct ContainerOut {
    reported: Value,
    numeric_literals: Vec<Value>,
    redactions: Vec<Value>,
    records_pointer: Value,
}

/// Read `sensitive_values`, defaulting to the empty list.
fn sensitive_values(input: &Value) -> Vec<String> {
    input
        .get("sensitive_values")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Read `record_ordinals` when present.
fn record_ordinals(input: &Value) -> Option<Vec<u64>> {
    input
        .get("record_ordinals")
        .and_then(Value::as_array)
        .map(|values| values.iter().filter_map(Value::as_u64).collect())
}

/// Apply `redactExplicitFailure` to a failure before delivery.
///
/// Redacts the input-issue messages and paths the oracle redacts for the
/// service-level and decoder failures observed here. The full failure algebra
/// (captured output, cleanup, provider diagnostics) is preserved by the error
/// projection; literal redaction of free text is applied here.
fn redact_failure(mut error: AnalysisError, sensitive_values: &[String]) -> AnalysisError {
    if sensitive_values.is_empty() {
        return error;
    }
    use rea_core::analysis_error::ErrorKind;
    let text = |value: &str| redaction::redact_explicit_text(value, sensitive_values);
    match &mut error.kind {
        ErrorKind::Input { issues, .. } => {
            for issue in issues.iter_mut() {
                if let Some(message) = &issue.message {
                    issue.message = Some(text(message));
                }
                // Redact literal field-name path segments; keep numeric indices.
                let ordinary = issue.reason == "unknown_argument";
                let mut retained: Vec<Value> = Vec::new();
                for part in &issue.path {
                    match part {
                        Value::String(segment) => {
                            if !ordinary && segment.starts_with('/') {
                                let pointer =
                                    redaction::redact_explicit_pointer(segment, sensitive_values);
                                let changed = pointer != *segment;
                                retained.push(Value::String(pointer));
                                if changed {
                                    break;
                                }
                            } else if sensitive_values
                                .iter()
                                .any(|literal| segment.contains(literal.as_str()))
                            {
                                break;
                            } else {
                                retained.push(Value::String(segment.clone()));
                            }
                        }
                        other => retained.push(other.clone()),
                    }
                }
                issue.path = retained;
            }
        }
        ErrorKind::CapabilityUnavailable {
            reason,
            user_message,
            ..
        } => {
            *reason = text(reason);
            if let Some(message) = user_message {
                *user_message = Some(text(message));
            }
        }
        ErrorKind::Output { reason, .. } => {
            *reason = text(reason);
        }
        _ => {}
    }
    error
}

/// `summarizeRetainedAnalysis`: record Evidence and project its summary view.
fn summarize_retained(
    context: &ToolContext<'_>,
    evidence: Evidence,
) -> Result<Evidence, AnalysisError> {
    context.session.record(&evidence)?;
    let parent = evidence.into_value();
    let raw = analysis_view::project(&parent, &json!({ "kind": "summary" }))
        .map_err(AnalysisError::from)?;
    let value: Value = serde_json::from_str(raw.get())
        .map_err(|error| AnalysisError::output("inspect_analysis_view", error.to_string()))?;
    rea_mcp::support::adopt_evidence(value)
}
