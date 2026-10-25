//! Contract boundary for publishing captured website JavaScript sources.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use tempfile::Builder;

pub const OPERATION: &str = "export_web_scripts";
const MAX_SCRIPTS: usize = 4_096;
const MAX_LIMITATIONS: usize = 512;
const MAX_EXPORTED_BYTES: u64 = 256 * 1024 * 1024;

/// Publish a caller-selected capture using the same application-owned
/// publication boundary as the CLI and MCP adapters.
///
/// The adapters only select paths and presentation. This function owns capture
/// parsing, source projection, path planning, manifest construction, and the
/// atomic directory commit.
pub fn export_capture(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let capture_path = input["capture_path"].as_str().expect("validated path");
    let output_directory = input["output_directory"].as_str().expect("validated path");
    let bytes = fs::read(capture_path).map_err(|error| io_failure(capture_path, error))?;
    let capture_sha256 = digest_bytes(&bytes);
    let raw: Value = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(&format!("capture is not valid JSON: {error}")))?;
    let selected = select_capture(&raw)?;
    publish_capture(capture_path, output_directory, &capture_sha256, selected)
}

#[derive(Debug)]
struct SelectedCapture {
    kind: &'static str,
    source_evidence_id: Option<String>,
    completeness: Value,
    limitations: Vec<String>,
    scripts: Vec<CapturedScript>,
}

#[derive(Debug)]
struct CapturedScript {
    source: Value,
    url: String,
    content: CapturedContent,
}

#[derive(Debug)]
enum CapturedContent {
    Exported {
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

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("web script export input must be an object"))?;

    reject_unknown_fields(object, &["capture_path", "output_directory"], "input")?;
    absolute_path(object.get("capture_path"), "capture_path")?;
    absolute_path(object.get("output_directory"), "output_directory")?;
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_manifest_result(input, &result)?;
    Ok(result)
}

fn select_capture(raw: &Value) -> Result<SelectedCapture, Failure> {
    let (body, evidence_id) = match raw.as_object() {
        Some(object) if object.contains_key("normalized_result") => (
            raw.get("normalized_result")
                .ok_or_else(|| invalid("capture Evidence has no normalized_result"))?,
            Some(
                object
                    .get("evidence_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("capture Evidence has no evidence_id"))?
                    .to_owned(),
            ),
        ),
        _ => (raw, None),
    };
    if let Some(operation) = raw.get("operation").and_then(Value::as_str) {
        if operation != "inspect_web_page" && operation != "capture_browser_scenario" {
            return Err(invalid("capture operation is not a supported web capture"));
        }
    }
    if body
        .get("scripts")
        .and_then(|value| value.get("items"))
        .is_some()
    {
        return select_page_capture(body, evidence_id);
    }
    if body
        .get("events")
        .and_then(|value| value.get("items"))
        .is_some()
    {
        return select_scenario_capture(body, evidence_id);
    }
    Err(invalid(
        "capture must be inspect_web_page or capture_browser_scenario evidence",
    ))
}

fn select_page_capture(
    body: &Value,
    evidence_id: Option<String>,
) -> Result<SelectedCapture, Failure> {
    let scripts = body["scripts"]["items"]
        .as_array()
        .ok_or_else(|| invalid("page capture scripts.items must be an array"))?;
    let mut projected = Vec::with_capacity(scripts.len());
    for script in scripts {
        let source_object = script
            .as_object()
            .ok_or_else(|| invalid("page script must be an object"))?;
        let source = serde_json::json!({
            "kind": "page-script",
            "script_key": required_string(source_object.get("script_key"), "script_key")?,
            "frame_id": script.get("frame_id").cloned().unwrap_or(Value::Null),
            "is_module": script.get("is_module").cloned().unwrap_or(Value::Null),
            "language": script.get("language").cloned().unwrap_or(Value::Null),
            "source_map_url": script.get("source_map_url").cloned().unwrap_or(Value::Null),
        });
        let url = required_string(script.get("url"), "script.url")?;
        let content = match script.get("source") {
            Some(source) if source.get("included").and_then(Value::as_bool) == Some(true) => {
                let language = script.get("language").and_then(Value::as_str);
                if language.is_some_and(|language| language != "JavaScript") {
                    CapturedContent::Unavailable {
                        reason: "unsupported-language".into(),
                        message: format!(
                            "Debugger reported language {}; JavaScript export was not inferred.",
                            language.unwrap()
                        ),
                    }
                } else {
                    let artifact = source
                        .get("artifact")
                        .ok_or_else(|| invalid("included page source has no artifact"))?;
                    let text = required_string(artifact.get("text"), "source.artifact.text")?;
                    CapturedContent::Exported {
                        bytes: text.into_bytes(),
                        sha256: required_digest(artifact.get("sha256"), "source.artifact.sha256")?,
                        media_type: optional_string_value(artifact.get("media_type"))?,
                        redacted: None,
                        representation: "debugger-source-utf8".into(),
                    }
                }
            }
            Some(source) => CapturedContent::Unavailable {
                reason: "source-not-included".into(),
                message: source
                    .get("reason")
                    .and_then(Value::as_str)
                    .filter(|v| !v.is_empty())
                    .unwrap_or("Debugger source was not included.")
                    .into(),
            },
            None => CapturedContent::Unavailable {
                reason: "source-not-included".into(),
                message: "Debugger source was not included.".into(),
            },
        };
        projected.push(CapturedScript {
            source,
            url,
            content,
        });
    }
    Ok(SelectedCapture {
        kind: "page-inspection",
        source_evidence_id: evidence_id,
        completeness: body
            .get("completeness")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        limitations: string_array(body.get("limitations"))?,
        scripts: projected,
    })
}

fn select_scenario_capture(
    body: &Value,
    evidence_id: Option<String>,
) -> Result<SelectedCapture, Failure> {
    let events = body["events"]["items"]
        .as_array()
        .ok_or_else(|| invalid("scenario events.items must be an array"))?;
    let mut requests = BTreeMap::<String, Vec<&Value>>::new();
    let mut responses = BTreeMap::<String, Vec<&Value>>::new();
    let mut bodies = BTreeMap::<u64, Vec<&Value>>::new();
    for event in events {
        match event.get("kind").and_then(Value::as_str) {
            Some("request")
                if event.get("resource_type").and_then(Value::as_str) == Some("script") =>
            {
                requests
                    .entry(required_string(
                        event.get("transaction_id"),
                        "transaction_id",
                    )?)
                    .or_default()
                    .push(event);
            }
            Some("response") => {
                responses
                    .entry(required_string(
                        event.get("transaction_id"),
                        "transaction_id",
                    )?)
                    .or_default()
                    .push(event);
            }
            Some("network-content")
                if event.get("phase").and_then(Value::as_str) == Some("response") =>
            {
                bodies
                    .entry(required_u64(
                        event.get("source_event_sequence"),
                        "source_event_sequence",
                    )?)
                    .or_default()
                    .push(event);
            }
            _ => {}
        }
    }
    let mut scripts = Vec::new();
    for request in requests.values().flatten() {
        let transaction_id = required_string(request.get("transaction_id"), "transaction_id")?;
        let request_sequence = required_u64(request.get("sequence"), "request.sequence")?;
        let matches = responses.get(&transaction_id).cloned().unwrap_or_default();
        let response = (matches.len() == 1).then(|| matches[0]);
        let response_sequence =
            response.and_then(|event| event.get("sequence").and_then(Value::as_u64));
        let selected_body = response_sequence
            .and_then(|sequence| bodies.get(&sequence))
            .filter(|items| items.len() == 1)
            .and_then(|items| items.first().copied());
        let ambiguous = requests
            .get(&transaction_id)
            .map_or(true, |items| items.len() != 1)
            || matches.len() > 1
            || response_sequence.is_some_and(|sequence| {
                bodies.get(&sequence).map_or(false, |items| items.len() > 1)
            });
        let source = serde_json::json!({
            "kind": "scenario-response", "transaction_id": transaction_id,
            "request_sequence": request_sequence,
            "response_sequence": if ambiguous { Value::Null } else { response_sequence.map(Value::from).unwrap_or(Value::Null) },
            "status": if ambiguous { Value::Null } else { response.and_then(|event| event.get("status")).cloned().unwrap_or(Value::Null) },
        });
        let url = request
            .get("url")
            .and_then(|value| value.get("url"))
            .and_then(Value::as_str)
            .or_else(|| request.get("url").and_then(Value::as_str))
            .ok_or_else(|| invalid("script request has no URL"))?
            .to_owned();
        let content = if ambiguous {
            unavailable(
                "ambiguous-transaction",
                "The capture does not identify one request, response, and content record for this transaction.",
            )
        } else {
            project_body(selected_body)?
        };
        scripts.push(CapturedScript {
            source,
            url,
            content,
        });
    }
    Ok(SelectedCapture {
        kind: "browser-scenario",
        source_evidence_id: evidence_id,
        completeness: body
            .get("completeness")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({})),
        limitations: string_array(body.get("limitations"))?,
        scripts,
    })
}

fn project_body(body: Option<&Value>) -> Result<CapturedContent, Failure> {
    let Some(body) = body else {
        return Ok(unavailable(
            "response-content-not-retained",
            "No selected, completed script response bytes were retained for this request.",
        ));
    };
    if body.get("state").and_then(Value::as_str) != Some("captured") {
        return Ok(unavailable(
            required_string(body.get("reason"), "body.reason")?,
            required_string(body.get("message"), "body.message")?,
        ));
    }
    let representation = required_string(body.get("representation"), "body.representation")?;
    if representation != "playwright-response-body-bytes"
        && representation != "browser-decoded-response-bytes"
    {
        return Ok(unavailable(
            "unsupported-body-representation",
            format!("Captured representation {representation} is not script response bytes."),
        ));
    }
    let encoded = required_string(body.get("content"), "body.content")?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|error| invalid(&format!("body.content is not valid base64: {error}")))?;
    Ok(CapturedContent::Exported {
        bytes,
        sha256: required_digest(body.get("sha256"), "body.sha256")?,
        media_type: optional_string_value(body.get("media_type"))?,
        redacted: body.get("redacted").and_then(Value::as_bool),
        representation,
    })
}

fn unavailable(reason: impl Into<String>, message: impl Into<String>) -> CapturedContent {
    CapturedContent::Unavailable {
        reason: reason.into(),
        message: message.into(),
    }
}
fn required_string(value: Option<&Value>, field: &str) -> Result<String, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}
fn required_u64(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    value
        .and_then(Value::as_u64)
        .filter(|v| *v > 0)
        .ok_or_else(|| invalid(&format!("{field} must be a positive integer")))
}
fn optional_string_value(value: Option<&Value>) -> Result<Option<String>, Failure> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    value
        .as_str()
        .map(str::to_owned)
        .map(Some)
        .ok_or_else(|| invalid("optional string field has an invalid value"))
}
fn required_digest(value: Option<&Value>, field: &str) -> Result<String, Failure> {
    let value = required_string(value, field)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(&format!(
            "{field} must be a lowercase SHA-256 digest"
        )));
    }
    Ok(value)
}
fn string_array(value: Option<&Value>) -> Result<Vec<String>, Failure> {
    value.map_or(Ok(Vec::new()), |value| {
        value
            .as_array()
            .ok_or_else(|| invalid("limitations must be an array"))
            .and_then(|items| {
                items
                    .iter()
                    .map(|item| required_string(Some(item), "limitation"))
                    .collect()
            })
    })
}

fn publish_capture(
    capture_path: &str,
    output_directory: &str,
    capture_sha256: &str,
    capture: SelectedCapture,
) -> Result<Value, Failure> {
    let output = Path::new(output_directory);
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or_else(|| invalid("output_directory must have an existing parent"))?;
    if output.exists() {
        return Err(invalid("output_directory must not already exist"));
    }
    let staging = Builder::new()
        .prefix(".rea-web-script-")
        .tempdir_in(parent)
        .map_err(|error| io_failure(output_directory, error))?;
    let staging_path = staging.path().to_owned();
    let mut records = Vec::with_capacity(capture.scripts.len());
    let mut exported_any = false;
    for (index, script) in capture.scripts.iter().enumerate() {
        let (record, relative_path) = plan_script(script, index, &capture.scripts)?;
        if let Some(relative_path) = relative_path {
            write_script(&staging_path, &relative_path, script)?;
            exported_any = true;
        }
        records.push(record);
    }
    let analysis_input = if exported_any {
        Some(
            serde_json::json!({ "input_path": format!("{output_directory}/files"), "format": "directory" }),
        )
    } else {
        None
    };
    let manifest = serde_json::json!({
        "capture_path": capture_path,
        "capture_sha256": capture_sha256,
        "capture_kind": capture.kind,
        "source_evidence_id": capture.source_evidence_id,
        "capture_completeness": capture.completeness,
        "output_directory": output_directory,
        "analysis_input": analysis_input,
        "scripts": records,
        "limitations": capture.limitations,
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|error| invalid(&format!("failed to encode export manifest: {error}")))?;
    let mut persisted = manifest_bytes.clone();
    persisted.push(b'\n');
    fs::write(staging_path.join("manifest.json"), &persisted)
        .map_err(|error| io_failure(output_directory, error))?;
    fs::rename(&staging_path, output).map_err(|error| io_failure(output_directory, error))?;
    let manifest_digest = digest_bytes(&persisted);
    Ok(serde_json::json!({
        "capture_path": capture_path,
        "capture_sha256": capture_sha256,
        "capture_kind": capture.kind,
        "source_evidence_id": capture.source_evidence_id,
        "capture_completeness": manifest["capture_completeness"],
        "output_directory": output_directory,
        "analysis_input": manifest["analysis_input"],
        "scripts": manifest["scripts"],
        "limitations": manifest["limitations"],
        "manifest": { "path": format!("{output_directory}/manifest.json"), "sha256": manifest_digest, "bytes": persisted.len() },
    }))
}

fn plan_script(
    script: &CapturedScript,
    index: usize,
    scripts: &[CapturedScript],
) -> Result<(Value, Option<String>), Failure> {
    let CapturedContent::Exported {
        bytes,
        sha256,
        media_type,
        redacted,
        representation,
    } = &script.content
    else {
        let CapturedContent::Unavailable { reason, message } = &script.content else {
            unreachable!()
        };
        return Ok((
            serde_json::json!({ "source": script.source, "url": script.url, "content": { "state": "unavailable", "reason": reason, "message": message } }),
            None,
        ));
    };
    let candidate = candidate_path(&script.url);
    let conflict = candidate
        .as_ref()
        .is_some_and(|path| path_conflicts(path, index, scripts));
    let layout_reason = if conflict {
        Some("Captured paths collide by content version or file/directory prefix.")
    } else {
        None
    };
    let (relative_path, layout, reason) = match (candidate, layout_reason) {
        (Some(path), None) => (path, "url-path", Value::Null),
        (_, reason) => (
            isolated_path(&script.source, index),
            "isolated",
            Value::String(
                reason
                    .unwrap_or("URL path is not an ordinary portable JavaScript module path.")
                    .into(),
            ),
        ),
    };
    let record = serde_json::json!({
        "source": script.source, "url": script.url,
        "content": { "state": "exported", "relative_path": relative_path, "layout": layout, "layout_reason": reason,
          "sha256": sha256, "bytes": bytes.len(), "media_type": media_type, "redacted": redacted, "representation": representation }
    });
    let path = record["content"]["relative_path"]
        .as_str()
        .map(str::to_owned);
    Ok((record, path))
}

fn candidate_path(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" && scheme != "https" {
        return None;
    }
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    if authority.contains('@') {
        return None;
    }
    let path_end = rest.find(['?', '#']).unwrap_or(rest.len());
    let path = &rest[authority_end..path_end];
    let segments = path.strip_prefix('/')?.split('/').collect::<Vec<_>>();
    if segments.is_empty()
        || !segments.last().is_some_and(|segment| {
            [".js", ".mjs", ".cjs"]
                .iter()
                .any(|suffix| segment.ends_with(suffix))
        })
    {
        return None;
    }
    if segments.iter().any(|segment| {
        segment.is_empty()
            || *segment == "."
            || *segment == ".."
            || segment.ends_with('.')
            || !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_~.-".contains(&byte))
            || ["con", "prn", "aux", "nul"]
                .iter()
                .any(|reserved| segment.eq_ignore_ascii_case(reserved))
    }) {
        return None;
    }
    Some(format!(
        "origins/{}/{}",
        digest_string(&format!("{scheme}://{authority}")),
        segments.join("/")
    ))
}

fn path_conflicts(path: &str, index: usize, scripts: &[CapturedScript]) -> bool {
    scripts.iter().enumerate().any(|(other_index, other)| {
        other_index != index
            && candidate_path(&other.url).is_some_and(|candidate| {
                candidate == path
                    || candidate.starts_with(&format!("{path}/"))
                    || path.starts_with(&format!("{candidate}/"))
            })
    })
}

fn isolated_path(source: &Value, index: usize) -> String {
    format!(
        "isolated/source-{}-{}.js",
        index + 1,
        digest_string(&source.to_string())
    )
}
fn write_script(
    staging: &Path,
    relative_path: &str,
    script: &CapturedScript,
) -> Result<(), Failure> {
    let CapturedContent::Exported { bytes, .. } = &script.content else {
        return Ok(());
    };
    let path = staging.join("files").join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_failure(relative_path, error))?;
    }
    fs::write(path, bytes).map_err(|error| io_failure(relative_path, error))
}
fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn digest_string(value: &str) -> String {
    digest_bytes(value.as_bytes())
}
fn io_failure(path: &str, error: std::io::Error) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        format!("{path}: {error}"),
        true,
        "Check the selected capture and output paths.".into(),
        BTreeMap::from([("operation".into(), Detail::Text(OPERATION.into()))]),
    )
}

fn absolute_path(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let path = value
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty path")))?;
    if path.contains('\0') {
        return Err(invalid(&format!("{field} must not contain NUL bytes")));
    }
    if !path.starts_with('/') {
        return Err(invalid(&format!("{field} must be absolute")));
    }
    Ok(())
}

fn validate_manifest_result(input: &Value, result: &Value) -> Result<(), Failure> {
    let result = result
        .as_object()
        .ok_or_else(|| invalid("web script export result must be an object"))?;
    reject_unknown_fields(
        result,
        &[
            "capture_path",
            "capture_sha256",
            "capture_kind",
            "source_evidence_id",
            "capture_completeness",
            "output_directory",
            "analysis_input",
            "scripts",
            "limitations",
            "manifest",
        ],
        "result",
    )?;

    exact_string(
        result,
        "capture_path",
        input["capture_path"].as_str().unwrap(),
    )?;
    digest(result.get("capture_sha256"), "capture_sha256")?;
    enum_string(
        result.get("capture_kind"),
        "capture_kind",
        &["page-inspection", "browser-scenario"],
    )?;
    optional_evidence_id(result.get("source_evidence_id"))?;
    result
        .get("capture_completeness")
        .filter(|value| value.is_object())
        .ok_or_else(|| invalid("capture_completeness must be an object"))?;
    absolute_path(result.get("output_directory"), "output_directory")?;
    validate_analysis_input(result.get("analysis_input"))?;

    let scripts = result
        .get("scripts")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("scripts must be an array"))?;
    if scripts.len() > MAX_SCRIPTS {
        return Err(invalid("scripts exceed the bounded export item limit"));
    }
    let mut exported_bytes = 0u64;
    for script in scripts {
        exported_bytes = exported_bytes
            .checked_add(validate_script(script)?)
            .ok_or_else(|| invalid("exported script byte count is too large"))?;
    }
    if exported_bytes > MAX_EXPORTED_BYTES {
        return Err(invalid(
            "exported script bytes exceed the bounded result limit",
        ));
    }

    let limitations = result
        .get("limitations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("limitations must be an array"))?;
    if limitations.len() > MAX_LIMITATIONS
        || limitations
            .iter()
            .any(|item| item.as_str().is_none_or(|limitation| limitation.is_empty()))
    {
        return Err(invalid(
            "limitations must contain bounded non-empty strings",
        ));
    }
    validate_manifest_descriptor(result.get("manifest"))
}

fn validate_script(script: &Value) -> Result<u64, Failure> {
    let script = script
        .as_object()
        .ok_or_else(|| invalid("each script must be an object"))?;
    reject_unknown_fields(script, &["source", "url", "content"], "script")?;
    let source = script
        .get("source")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("script.source must be an object"))?;
    validate_source(source)?;
    script
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("script.url must be a string"))?;

    let content = script
        .get("content")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("script.content must be an object"))?;
    match content.get("state").and_then(Value::as_str) {
        Some("unavailable") => {
            reject_unknown_fields(
                content,
                &["state", "reason", "message"],
                "unavailable content",
            )?;
            non_empty_string(content.get("reason"), "content.reason")?;
            non_empty_string(content.get("message"), "content.message")?;
            Ok(0)
        }
        Some("exported") => {
            reject_unknown_fields(
                content,
                &[
                    "state",
                    "relative_path",
                    "layout",
                    "layout_reason",
                    "sha256",
                    "bytes",
                    "media_type",
                    "redacted",
                    "representation",
                ],
                "exported content",
            )?;
            non_empty_string(content.get("relative_path"), "content.relative_path")?;
            enum_string(
                content.get("layout"),
                "content.layout",
                &["url-path", "isolated"],
            )?;
            optional_string(content.get("layout_reason"), "content.layout_reason")?;
            digest(content.get("sha256"), "content.sha256")?;
            let bytes = non_negative_integer(content.get("bytes"), "content.bytes")?;
            optional_string(content.get("media_type"), "content.media_type")?;
            optional_boolean(content.get("redacted"), "content.redacted")?;
            enum_string(
                content.get("representation"),
                "content.representation",
                &[
                    "debugger-source-utf8",
                    "playwright-response-body-bytes",
                    "browser-decoded-response-bytes",
                ],
            )?;
            Ok(bytes)
        }
        _ => Err(invalid("content.state must be exported or unavailable")),
    }
}

fn validate_source(source: &Map<String, Value>) -> Result<(), Failure> {
    match source.get("kind").and_then(Value::as_str) {
        Some("page-script") => {
            reject_unknown_fields(
                source,
                &[
                    "kind",
                    "script_key",
                    "frame_id",
                    "is_module",
                    "language",
                    "source_map_url",
                ],
                "page-script source",
            )?;
            non_empty_string(source.get("script_key"), "source.script_key")?;
            optional_string(source.get("frame_id"), "source.frame_id")?;
            optional_boolean(source.get("is_module"), "source.is_module")?;
            optional_string(source.get("language"), "source.language")?;
            optional_string(source.get("source_map_url"), "source.source_map_url")
        }
        Some("scenario-response") => {
            reject_unknown_fields(
                source,
                &[
                    "kind",
                    "transaction_id",
                    "request_sequence",
                    "response_sequence",
                    "status",
                ],
                "scenario-response source",
            )?;
            non_empty_string(source.get("transaction_id"), "source.transaction_id")?;
            positive_integer(source.get("request_sequence"), "source.request_sequence")?;
            optional_positive_integer(source.get("response_sequence"), "source.response_sequence")?;
            optional_integer(source.get("status"), "source.status")
        }
        _ => Err(invalid(
            "source.kind must be page-script or scenario-response",
        )),
    }
}

fn validate_analysis_input(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Err(invalid("analysis_input is required"));
    };
    if value.is_null() {
        return Ok(());
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid("analysis_input must be an object or null"))?;
    reject_unknown_fields(object, &["input_path", "format"], "analysis_input")?;
    absolute_path(object.get("input_path"), "analysis_input.input_path")?;
    enum_string(
        object.get("format"),
        "analysis_input.format",
        &["directory"],
    )
}

fn validate_manifest_descriptor(value: Option<&Value>) -> Result<(), Failure> {
    let manifest = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("manifest must be an object"))?;
    reject_unknown_fields(manifest, &["path", "sha256", "bytes"], "manifest")?;
    absolute_path(manifest.get("path"), "manifest.path")?;
    digest(manifest.get("sha256"), "manifest.sha256")?;
    non_negative_integer(manifest.get("bytes"), "manifest.bytes").map(|_| ())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    subject: &str,
) -> Result<(), Failure> {
    let allowed = allowed.iter().copied().collect::<BTreeSet<_>>();
    if object.keys().any(|key| !allowed.contains(key.as_str())) {
        return Err(invalid(&format!("{subject} contains an unknown field")));
    }
    Ok(())
}

fn exact_string(object: &Map<String, Value>, field: &str, expected: &str) -> Result<(), Failure> {
    let actual = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} must be a string")))?;
    if actual != expected {
        return Err(invalid(&format!(
            "{field} must preserve the selected capture path"
        )));
    }
    Ok(())
}

fn non_empty_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str).is_none_or(str::is_empty) {
        return Err(invalid(&format!("{field} must be a non-empty string")));
    }
    Ok(())
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_null() && value.as_str().is_none()) {
        return Err(invalid(&format!("{field} must be a string or null")));
    }
    Ok(())
}

fn optional_boolean(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_null() && value.as_bool().is_none()) {
        return Err(invalid(&format!("{field} must be a boolean or null")));
    }
    Ok(())
}

fn enum_string(value: Option<&Value>, field: &str, allowed: &[&str]) -> Result<(), Failure> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} must be a string")))?;
    if !allowed.contains(&value) {
        return Err(invalid(&format!("{field} has an unsupported value")));
    }
    Ok(())
}

fn non_negative_integer(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(&format!("{field} must be a non-negative integer")))
}

fn positive_integer(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    let value = non_negative_integer(value, field)?;
    if value == 0 {
        return Err(invalid(&format!("{field} must be positive")));
    }
    Ok(value)
}

fn optional_positive_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if let Some(value) = value.filter(|value| !value.is_null()) {
        positive_integer(Some(value), field)?;
    }
    Ok(())
}

fn optional_integer(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_null() && value.as_i64().is_none()) {
        return Err(invalid(&format!("{field} must be an integer or null")));
    }
    Ok(())
}

fn digest(value: Option<&Value>, field: &str) -> Result<(), Failure> {
    let value = value
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(&format!("{field} must be a SHA-256 hex digest")))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(&format!("{field} must be a SHA-256 hex digest")));
    }
    Ok(())
}

fn optional_evidence_id(value: Option<&Value>) -> Result<(), Failure> {
    if value.is_some_and(|value| !value.is_null()) {
        let id = value
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("source_evidence_id must be a string or null"))?;
        if !id.starts_with("ev_") || id.len() != 68 {
            return Err(invalid(
                "source_evidence_id must preserve an Evidence identifier",
            ));
        }
        digest(
            Some(&Value::String(id[3..].to_owned())),
            "source_evidence_id",
        )?;
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a saved browser capture and an absent absolute output directory for verified JavaScript exports.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "capture_path": "/analysis/capture.json",
            "output_directory": "/analysis/exported-scripts"
        })
    }

    #[test]
    fn accepts_absolute_export_paths() {
        validate_input(&input()).expect("valid web script export input");
        assert!(retain_result(&input(), result()).is_ok());
    }

    fn result() -> Value {
        serde_json::json!({
            "capture_path": "/analysis/capture.json",
            "capture_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "capture_kind": "page-inspection",
            "source_evidence_id": null,
            "capture_completeness": {},
            "output_directory": "/analysis/exported-scripts",
            "analysis_input": null,
            "scripts": [],
            "limitations": ["No script bytes were exportable."],
            "manifest": {
                "path": "/analysis/exported-scripts/manifest.json",
                "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
                "bytes": 0
            }
        })
    }

    #[test]
    fn rejects_incomplete_export_manifest() {
        assert!(retain_result(&input(), serde_json::json!({"scripts": []})).is_err());
    }

    #[test]
    fn rejects_relative_capture_path() {
        let mut invalid_input = input();
        invalid_input["capture_path"] = serde_json::json!("capture.json");
        assert!(validate_input(&invalid_input).is_err());
    }

    #[test]
    fn rejects_relative_output_directory() {
        let mut invalid_input = input();
        invalid_input["output_directory"] = serde_json::json!("exported-scripts");
        assert!(validate_input(&invalid_input).is_err());
    }
}
