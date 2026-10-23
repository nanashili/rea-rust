//! Capture-specific parsing and source selection, a direct port of
//! `src/browser/assets/ScriptCaptureAdapters.ts`, `PageScriptCapture.ts` and
//! `ScenarioScriptCapture.ts`. The publisher never reinterprets raw capture
//! bytes; it consumes these projected `CapturedWebScript` records.
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;

/// Projected source record, independent of publication.
pub struct CapturedWebScript {
    pub source: Value,
    pub url: String,
    pub content: CapturedContent,
}

/// Captured bytes or an explicit unavailability reason.
pub enum CapturedContent {
    Captured {
        bytes: Vec<u8>,
        sha256: String,
        media_type: Option<String>,
        redacted: Option<bool>,
        representation: String,
    },
    Unavailable {
        reason: String,
        message: String,
    },
}

/// Verified source records with the original capture coverage and limitations.
pub struct SelectedCapture {
    pub kind: &'static str,
    pub completeness: Value,
    pub limitations: Vec<String>,
    pub scripts: Vec<CapturedWebScript>,
    pub source_evidence_id: Option<String>,
}

/// `selectScriptCapture`: reject unsupported/malformed captures and tampered
/// Evidence before writing. Returns `None` for an unsupported capture, which
/// the caller maps to the TS `TypeError`.
pub fn select_script_capture(raw: &Value) -> Option<SelectedCapture> {
    let has_envelope = raw.as_object().is_some_and(|object| {
        object.contains_key("normalized_result") || object.contains_key("evidence_id")
    });
    if has_envelope {
        let operation = raw.get("operation").and_then(Value::as_str)?;
        let normalized = raw.get("normalized_result")?;
        let evidence_id = raw.get("evidence_id").and_then(Value::as_str)?.to_owned();
        let selected = parse_adapter(operation, normalized)?;
        return Some(SelectedCapture {
            source_evidence_id: Some(evidence_id),
            ..selected
        });
    }
    for operation in ["inspect_web_page", "capture_browser_scenario"] {
        if let Some(selected) = parse_adapter(operation, raw) {
            return Some(SelectedCapture {
                source_evidence_id: None,
                ..selected
            });
        }
    }
    None
}

fn parse_adapter(operation: &str, body: &Value) -> Option<SelectedCapture> {
    match operation {
        "inspect_web_page" => parse_page(body),
        "capture_browser_scenario" => parse_scenario(body),
        _ => None,
    }
}

fn string_array(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// `pageScripts`: project verified Debugger sources without fetching URLs.
fn parse_page(body: &Value) -> Option<SelectedCapture> {
    let items = body.get("scripts")?.get("items")?.as_array()?;
    let mut scripts = Vec::with_capacity(items.len());
    for script in items {
        let script_key = script.get("script_key").and_then(Value::as_str)?;
        if script_key.is_empty() {
            return None;
        }
        let url = script.get("url").and_then(Value::as_str)?.to_owned();
        let language = script.get("language").and_then(Value::as_str);
        let source = script.get("source");
        let included = source
            .and_then(|value| value.get("included"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let content = if !included {
            let reason = source
                .and_then(|value| value.get("reason"))
                .and_then(Value::as_str)
                .filter(|reason| !reason.is_empty())
                .unwrap_or("Debugger source was not included.")
                .to_owned();
            CapturedContent::Unavailable {
                reason: "source-not-included".into(),
                message: reason,
            }
        } else if language.is_some_and(|language| language != "JavaScript") {
            CapturedContent::Unavailable {
                reason: "unsupported-language".into(),
                message: format!(
                    "Debugger reported language {}; JavaScript export was not inferred.",
                    language.unwrap_or_default()
                ),
            }
        } else {
            let artifact = source?.get("artifact")?;
            let text = artifact.get("text").and_then(Value::as_str)?;
            CapturedContent::Captured {
                bytes: text.as_bytes().to_vec(),
                sha256: artifact.get("sha256").and_then(Value::as_str)?.to_owned(),
                media_type: nullable_string(artifact.get("media_type")),
                redacted: None,
                representation: "debugger-source-utf8".into(),
            }
        };
        scripts.push(CapturedWebScript {
            source: serde_json::json!({
                "kind": "page-script",
                "script_key": script_key,
                "frame_id": nullable(script.get("frame_id")),
                "is_module": nullable(script.get("is_module")),
                "language": nullable(script.get("language")),
                "source_map_url": nullable(script.get("source_map_url")),
            }),
            url,
            content,
        });
    }
    Some(SelectedCapture {
        kind: "page-inspection",
        completeness: body.get("completeness").cloned().unwrap_or(Value::Null),
        limitations: string_array(body.get("limitations")),
        scripts,
        source_evidence_id: None,
    })
}

/// `scenarioScripts`: join script response bytes only through explicit
/// transaction and event identity, preserving event order.
fn parse_scenario(body: &Value) -> Option<SelectedCapture> {
    let items = body.get("events")?.get("items")?.as_array()?;
    // `indexResponses`.
    let mut request_counts: HashMap<String, u64> = HashMap::new();
    let mut responses: HashMap<String, Vec<&Value>> = HashMap::new();
    let mut contents: HashMap<u64, Vec<&Value>> = HashMap::new();
    for event in items {
        match event.get("kind").and_then(Value::as_str) {
            Some("request") => {
                if let Some(id) = event.get("transaction_id").and_then(Value::as_str) {
                    *request_counts.entry(id.to_owned()).or_insert(0) += 1;
                }
            }
            Some("response") => {
                if let Some(id) = event.get("transaction_id").and_then(Value::as_str) {
                    responses.entry(id.to_owned()).or_default().push(event);
                }
            }
            Some("network-content")
                if event.get("phase").and_then(Value::as_str) == Some("response") =>
            {
                if let Some(sequence) = event.get("source_event_sequence").and_then(Value::as_u64) {
                    contents.entry(sequence).or_default().push(event);
                }
            }
            _ => {}
        }
    }
    let mut scripts = Vec::new();
    for request in items {
        if request.get("kind").and_then(Value::as_str) != Some("request")
            || request.get("resource_type").and_then(Value::as_str) != Some("script")
        {
            continue;
        }
        scripts.push(project_request(
            request,
            &request_counts,
            &responses,
            &contents,
        )?);
    }
    Some(SelectedCapture {
        kind: "browser-scenario",
        completeness: body.get("completeness").cloned().unwrap_or(Value::Null),
        limitations: string_array(body.get("limitations")),
        scripts,
        source_evidence_id: None,
    })
}

fn project_request(
    request: &Value,
    request_counts: &HashMap<String, u64>,
    responses: &HashMap<String, Vec<&Value>>,
    contents: &HashMap<u64, Vec<&Value>>,
) -> Option<CapturedWebScript> {
    let id = request.get("transaction_id").and_then(Value::as_str)?;
    let request_sequence = request.get("sequence").and_then(Value::as_u64)?;
    let matches = responses.get(id).cloned().unwrap_or_default();
    let response = (matches.len() == 1).then(|| matches[0]);
    let response_sequence =
        response.and_then(|event| event.get("sequence").and_then(Value::as_u64));
    let bodies = response_sequence
        .and_then(|sequence| contents.get(&sequence).cloned())
        .unwrap_or_default();
    let body = (bodies.len() == 1).then(|| bodies[0].get("body")).flatten();
    let ambiguous =
        request_counts.get(id).copied() != Some(1) || matches.len() > 1 || bodies.len() > 1;
    let (response_sequence_value, status_value) = if ambiguous {
        (Value::Null, Value::Null)
    } else {
        (
            response_sequence.map(Value::from).unwrap_or(Value::Null),
            response
                .and_then(|event| event.get("status"))
                .cloned()
                .unwrap_or(Value::Null),
        )
    };
    let url = request
        .get("url")?
        .get("url")
        .and_then(Value::as_str)?
        .to_owned();
    let content = project_body(body, ambiguous)?;
    Some(CapturedWebScript {
        source: serde_json::json!({
            "kind": "scenario-response",
            "transaction_id": id,
            "request_sequence": request_sequence,
            "response_sequence": response_sequence_value,
            "status": status_value,
        }),
        url,
        content,
    })
}

/// `projectBody`.
fn project_body(body: Option<&Value>, ambiguous: bool) -> Option<CapturedContent> {
    if ambiguous {
        return Some(unavailable(
            "ambiguous-transaction",
            "The capture does not identify one request, response, and content record for this transaction.",
        ));
    }
    let Some(body) = body else {
        return Some(unavailable(
            "response-content-not-retained",
            "No selected, completed script response bytes were retained for this request.",
        ));
    };
    let state = body
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if state == "unavailable" {
        return Some(unavailable(
            body.get("reason").and_then(Value::as_str)?,
            body.get("message").and_then(Value::as_str)?,
        ));
    }
    if state != "captured" {
        return Some(unavailable(
            state,
            "No selected, completed script response bytes were retained for this request.",
        ));
    }
    let representation = body.get("representation").and_then(Value::as_str)?;
    if representation != "playwright-response-body-bytes"
        && representation != "browser-decoded-response-bytes"
    {
        return Some(unavailable(
            "unsupported-body-representation",
            &format!("Captured representation {representation} is not script response bytes."),
        ));
    }
    let encoded = body.get("content").and_then(Value::as_str)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .ok()?;
    Some(CapturedContent::Captured {
        bytes,
        sha256: body.get("sha256").and_then(Value::as_str)?.to_owned(),
        media_type: nullable_string(body.get("media_type")),
        redacted: body.get("redacted").and_then(Value::as_bool),
        representation: representation.to_owned(),
    })
}

fn unavailable(reason: &str, message: &str) -> CapturedContent {
    CapturedContent::Unavailable {
        reason: reason.to_owned(),
        message: message.to_owned(),
    }
}

fn nullable(value: Option<&Value>) -> Value {
    value.cloned().unwrap_or(Value::Null)
}

fn nullable_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(str::to_owned)
}
