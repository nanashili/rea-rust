//! `capture_browser_scenario` network transactions as capture records.
//!
//! Compatibility owners: `src/domain/analysisView/scenarioCaptureRecords.ts`
//! (manifest purpose) and the refinements of `browserScenarioCaptureSchema`
//! (`browserScenarioCapture.ts`, `browserScenarioCaptureValues.ts`,
//! `browserNetworkEvidence.ts`, `webScreenshot.ts`) that the JSON contract
//! cannot express.
use super::super::web_network::budget::Budget;
use crate::common::json::sha256_hex;
use crate::common::schema;
use crate::common::view::{OPERATION, Parent, view_error};
use base64::Engine;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

const SCENARIO_OPERATION: &str = "capture_browser_scenario";

/// `ScenarioCaptureRecords`.
pub struct ScenarioRecords {
    pub records: Vec<Value>,
    pub total_records: usize,
    pub limitations: Vec<String>,
}

fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn kind(event: &Value) -> &str {
    event
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

fn number(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64)
}

fn base64_engine() -> &'static base64::engine::GeneralPurpose {
    &base64::engine::general_purpose::STANDARD
}

/// Strict canonical base64 (the original's re-encoding comparison).
fn canonical_base64(text: &str) -> Option<Vec<u8>> {
    let bytes = base64_engine().decode(text).ok()?;
    (base64_engine().encode(&bytes) == text).then_some(bytes)
}

/// The JSON-contract-inexpressible refinements of the scenario capture.
fn refined(capture: &Value) -> bool {
    let events = capture.get("events").unwrap_or(&Value::Null);
    let event_items = items(events, "items");
    let mut by_sequence: HashMap<u64, &Value> = HashMap::new();
    for event in event_items {
        if let Some(sequence) = number(event.get("sequence")) {
            by_sequence.insert(sequence.to_bits(), event);
        }
    }
    if by_sequence.len() != event_items.len() {
        return false;
    }
    for event in event_items {
        // `browserScenarioEventSchema` redirect refinement.
        if event
            .get("redirected_from_transaction_id")
            .is_some_and(|value| !value.is_null())
            && event.get("redirected_from_transaction_state").is_some()
        {
            return false;
        }
        if kind(event) == "network-content" {
            let source = number(event.get("source_event_sequence"))
                .and_then(|sequence| by_sequence.get(&sequence.to_bits()));
            let matches = source.is_some_and(|source| {
                source.get("kind") == event.get("phase")
                    && source.get("transaction_id") == event.get("transaction_id")
                    && number(source.get("sequence")) < number(event.get("sequence"))
            });
            if !matches || !body_refined(event.get("body").unwrap_or(&Value::Null)) {
                return false;
            }
        }
    }
    if number(events.get("retained")) != Some(event_items.len() as f64) {
        return false;
    }
    let omitted: f64 = items(events.get("omissions").unwrap_or(&Value::Null), "by_kind")
        .iter()
        .filter_map(|omission| number(omission.get("count")))
        .sum();
    if Some(omitted) != number(events.get("dropped")) {
        return false;
    }
    let steps = items(capture, "steps");
    let actions = number(
        capture
            .get("scenario")
            .and_then(|scenario| scenario.get("action_count")),
    );
    if Some(steps.len() as f64) != actions.map(|count| count + 1.0) {
        return false;
    }
    if steps
        .iter()
        .enumerate()
        .any(|(index, step)| number(step.get("step_index")) != Some(index as f64))
    {
        return false;
    }
    if event_items.iter().any(|event| {
        number(event.get("step_index")).is_some_and(|index| index >= steps.len() as f64)
    }) {
        return false;
    }
    steps.iter().all(step_artifacts_refined)
}

/// `browserNetworkBodySchema` captured-body refinement.
fn body_refined(body: &Value) -> bool {
    if body.get("state").and_then(Value::as_str) != Some("captured") {
        return true;
    }
    let content = body
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(bytes) = canonical_base64(content) else {
        return false;
    };
    number(body.get("bytes")) == Some(bytes.len() as f64)
        && body.get("sha256").and_then(Value::as_str) == Some(sha256_hex(&bytes).as_str())
}

/// Text-artifact and screenshot refinements of each step's captured artifacts.
fn step_artifacts_refined(step: &Value) -> bool {
    let artifacts = step.get("artifacts").unwrap_or(&Value::Null);
    let captured = |key: &str| {
        artifacts
            .get(key)
            .filter(|state| state.get("state").and_then(Value::as_str) == Some("captured"))
            .and_then(|state| state.get("value"))
    };
    for key in ["dom", "accessibility"] {
        if let Some(artifact) = captured(key) {
            let text = artifact
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if number(artifact.get("bytes")) != Some(text.len() as f64)
                || artifact.get("sha256").and_then(Value::as_str)
                    != Some(sha256_hex(text.as_bytes()).as_str())
            {
                return false;
            }
        }
    }
    if let Some(screenshot) = captured("screenshot") {
        let data = screenshot
            .get("data_base64")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if data.is_empty() || data.len() % 4 != 0 {
            return false;
        }
        let Some(bytes) = canonical_base64(data) else {
            return false;
        };
        if number(screenshot.get("bytes")) != Some(bytes.len() as f64)
            || screenshot.get("sha256").and_then(Value::as_str) != Some(sha256_hex(&bytes).as_str())
        {
            return false;
        }
    }
    true
}

/// `browserScenarioCaptureSchema.safeParse`, cached for immutable parents.
fn parse_scenario(parent: &Parent<'_>) -> Result<Option<Arc<Value>>, AnalysisError> {
    let parsed = parent.cached("browser_scenario_capture", || {
        let Some(root) = schema::tool_result_schema(SCENARIO_OPERATION) else {
            return Err(AnalysisError::output(
                OPERATION,
                format!("The {SCENARIO_OPERATION} result contract is unavailable."),
            ));
        };
        Ok(schema::parse_strict(&root, parent.normalized_result)
            .ok()
            .filter(refined)
            .map(Arc::new))
    })?;
    Ok((*parsed).clone())
}

/// `admitScenarioCaptureParent`.
pub fn admit_scenario_capture_parent(
    parent: &Parent<'_>,
    budget: &mut Budget,
) -> Result<ScenarioRecords, AnalysisError> {
    budget.admit_capture_clone(parent.normalized_result, true)?;
    let Some(capture) = parse_scenario(parent)? else {
        return Err(view_error(
            &["source"],
            "invalid_value",
            "Parent Evidence result does not match capture_browser_scenario.",
        ));
    };
    let content = capture
        .get("scenario")
        .and_then(|scenario| scenario.get("network_content"))
        .unwrap_or(&Value::Null);
    let selected = |key: &str| content.get(key).and_then(Value::as_bool) == Some(true);
    if !selected("response_body") && !selected("header_values") {
        return Err(AnalysisError::unsupported_target(
            OPERATION,
            parent.evidence_id,
            "environment-manifest needs a capture_browser_scenario capture with capture.network.response_body or header_values selected.",
        ));
    }
    Ok(scenario_capture_records(&capture))
}

/// `TransactionIndex`.
struct TransactionIndex<'a> {
    requests: Vec<(&'a Value, usize)>,
    request_counts: HashMap<String, usize>,
    responses: HashMap<String, Vec<&'a Value>>,
    contents: HashMap<u64, Vec<&'a Value>>,
}

fn transaction_id(event: &Value) -> String {
    event
        .get("transaction_id")
        .map(Value::to_string)
        .unwrap_or_default()
}

fn sequence_key(value: Option<&Value>) -> Option<u64> {
    number(value).map(f64::to_bits)
}

fn index_transactions(events: &[Value]) -> TransactionIndex<'_> {
    let mut index = TransactionIndex {
        requests: Vec::new(),
        request_counts: HashMap::new(),
        responses: HashMap::new(),
        contents: HashMap::new(),
    };
    for (item, event) in events.iter().enumerate() {
        match kind(event) {
            "request" => {
                index.requests.push((event, item));
                *index
                    .request_counts
                    .entry(transaction_id(event))
                    .or_default() += 1;
            }
            "response" => index
                .responses
                .entry(transaction_id(event))
                .or_default()
                .push(event),
            "network-content" => {
                if let Some(sequence) = sequence_key(event.get("source_event_sequence")) {
                    index.contents.entry(sequence).or_default().push(event);
                }
            }
            _ => {}
        }
    }
    index
}

impl<'a> TransactionIndex<'a> {
    fn contents_of(&self, sequence: Option<&Value>) -> &[&'a Value] {
        sequence_key(sequence)
            .and_then(|sequence| self.contents.get(&sequence))
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// `onlyContent`.
    fn only_content(&self, sequence: Option<&Value>) -> Option<&'a Value> {
        match self.contents_of(sequence) {
            [content] => Some(content),
            _ => None,
        }
    }
}

/// `captured(content)`.
fn captured(content: Option<&Value>) -> Option<&Value> {
    content
        .and_then(|content| content.get("body"))
        .filter(|body| body.get("state").and_then(Value::as_str) == Some("captured"))
}

/// `retainedBody`: a captured body unless redaction emptied it.
fn retained_body(content: Option<&Value>) -> Option<&Value> {
    captured(content).filter(|body| {
        !(body.get("redacted").and_then(Value::as_bool) == Some(true)
            && number(body.get("bytes")) == Some(0.0))
    })
}

/// `headerValue(headers, name)`.
fn header_value(headers: Option<&Value>, name: &str) -> Option<String> {
    let headers = headers?;
    if headers.get("state").and_then(Value::as_str) != Some("captured") {
        return None;
    }
    let item = items(headers, "items").iter().find(|item| {
        item.get("name")
            .and_then(Value::as_str)
            .is_some_and(|candidate| candidate.to_lowercase() == name)
    })?;
    item.get("value").and_then(Value::as_str).map(str::to_owned)
}

/// `mediaType(content)`.
fn media_type(content: Option<&Value>) -> Option<String> {
    captured(content)
        .and_then(|body| body.get("media_type"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            header_value(
                content.and_then(|content| content.get("headers")),
                "content-type",
            )
        })
}

/// `utf8Text`: strict UTF-8 that keeps a byte-order mark.
fn utf8_text(body: &Value) -> Option<String> {
    let bytes = base64_engine()
        .decode(
            body.get("content")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// `reportedRequest(request, content, "manifest")`.
fn reported_request(request: &Value, content: Option<&Value>) -> Value {
    let url = request.get("url").unwrap_or(&Value::Null);
    let mut reported = serde_json::Map::new();
    reported.insert(
        "method".into(),
        request.get("method").cloned().unwrap_or(Value::Null),
    );
    reported.insert(
        "url".into(),
        if url.get("redacted").and_then(Value::as_bool) == Some(true) {
            Value::Null
        } else {
            url.get("url").cloned().unwrap_or(Value::Null)
        },
    );
    let text = captured(content).and_then(utf8_text);
    if let (Some(text), Some(mime_type)) = (text, media_type(content)) {
        reported.insert(
            "postData".into(),
            json!({ "mimeType": mime_type, "text": text }),
        );
    }
    Value::Object(reported)
}

struct Projected {
    record: Value,
    represented: bool,
    body: bool,
    redacted: bool,
}

/// `record(ordinal, observed, index, "manifest")`.
fn record(ordinal: usize, request: &Value, item: usize, index: &TransactionIndex<'_>) -> Projected {
    let location = json!({ "kind": "json-pointer", "pointer": format!("/events/items/{item}") });
    let build = |reported: Value, binary_fields: Vec<Value>| {
        json!({
            "ordinal": ordinal,
            "location": location,
            "reported": reported,
            "binary_fields": binary_fields,
            "numeric_literals": [],
            "redactions": [],
            "limitations": [],
        })
    };
    let id = transaction_id(request);
    let responses = index
        .responses
        .get(&id)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let response = if responses.len() == 1 {
        Some(responses[0])
    } else {
        None
    };
    if index.request_counts.get(&id).copied() != Some(1)
        || responses.len() > 1
        || index.contents_of(request.get("sequence")).len() > 1
        || response.is_some_and(|response| index.contents_of(response.get("sequence")).len() > 1)
    {
        return Projected {
            record: build(json!({}), Vec::new()),
            represented: false,
            body: false,
            redacted: false,
        };
    }
    let request_content = index.only_content(request.get("sequence"));
    let response_content =
        response.and_then(|response| index.only_content(response.get("sequence")));
    let body = retained_body(response_content);
    let mime_type = media_type(response_content).unwrap_or_default();
    let mut reported = serde_json::Map::new();
    reported.insert("request".into(), reported_request(request, request_content));
    if let Some(response) = response {
        let content = match body {
            None => json!({ "mimeType": mime_type }),
            Some(body) => json!({
                "mimeType": mime_type,
                "text": body.get("content").cloned().unwrap_or(Value::Null),
                "encoding": "base64",
            }),
        };
        reported.insert(
            "response".into(),
            json!({ "status": response.get("status").cloned().unwrap_or(Value::Null), "content": content }),
        );
    }
    let binary_fields = match body {
        None => Vec::new(),
        Some(body) => vec![json!({
            "pointer": "/response/content/text",
            "representation": "har-base64-content",
            "state": "retained",
            "bytes": body.get("bytes").cloned().unwrap_or(Value::Null),
            "sha256": body.get("sha256").cloned().unwrap_or(Value::Null),
            "content_base64": body.get("content").cloned().unwrap_or(Value::Null),
        })],
    };
    let url_redacted = request
        .get("url")
        .and_then(|url| url.get("redacted"))
        .and_then(Value::as_bool)
        == Some(true);
    Projected {
        record: build(Value::Object(reported), binary_fields),
        represented: !url_redacted,
        body: body.is_some(),
        redacted: body
            .and_then(|body| body.get("redacted"))
            .and_then(Value::as_bool)
            == Some(true),
    }
}

/// `scenarioCaptureRecords(capture, "manifest")`.
fn scenario_capture_records(capture: &Value) -> ScenarioRecords {
    let events = capture.get("events").unwrap_or(&Value::Null);
    let index = index_transactions(items(events, "items"));
    let mut records = Vec::new();
    let mut without_body = 0usize;
    let mut represented = 0usize;
    let mut redacted_bodies = 0usize;
    for (ordinal, (request, item)) in index.requests.iter().enumerate() {
        let projected = record(ordinal, request, *item, &index);
        records.push(projected.record);
        if !projected.represented {
            continue;
        }
        represented += 1;
        if !projected.body {
            without_body += 1;
        }
        if projected.redacted {
            redacted_bodies += 1;
        }
    }
    let mut limitations = vec![
        "Scenario records are the capture's network transactions in request order; each record ordinal is the transaction's zero-based position.".to_owned(),
    ];
    let dropped = number(events.get("dropped")).unwrap_or(0.0);
    if dropped > 0.0 {
        limitations.push(format!(
            "The scenario capture omitted {} events; the manifest covers only retained transactions.",
            dropped as u64
        ));
    }
    if without_body > 0 {
        limitations.push(format!(
            "{without_body} of {represented} scenario transactions with a usable request line retained no response body; tools citing them replay only the recorded status and content type, either of which may be absent."
        ));
    }
    if redacted_bodies > 0 {
        limitations.push(format!(
            "{redacted_bodies} of {represented} scenario transactions with a usable request line retained a response body with declared secret values replaced by redaction markers; tools citing them replay the redacted bytes."
        ));
    }
    let total_records = records.len();
    ScenarioRecords {
        records,
        total_records,
        limitations,
    }
}
