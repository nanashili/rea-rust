//! Public read-only workflow boundary for web capture comparisons and traces.
//!
//! The format-specific producers own decoding. This module exposes the exact
//! operation names used by the CLI/MCP contract and keeps the orchestration
//! free of browser execution, network access, and filesystem reads.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const COMPARE_CAPTURES: &str = "compare_web_captures";
pub const COMPARE_SCREENSHOTS: &str = "compare_web_screenshots";
pub const TRACE_SOURCE_LOCATION: &str = "trace_web_source_location";

/// Compare passive page captures or complete recorded browser scenarios.
pub fn compare_web_captures(input: &Value) -> Result<Value, Failure> {
    super::capture_comparison::compare(input)
}

/// Compare two self-verifying PNG artifacts using local pixel metrics.
pub fn compare_web_screenshots(input: &Value) -> Result<Value, Failure> {
    super::screenshot_comparison::compare(input)
}

/// Trace a selected generated position through a caller-supplied source map.
pub fn trace_web_source_location(input: &Value, source_map_text: &str) -> Result<Value, Failure> {
    super::source_location::trace_web_source_location(input, source_map_text)
}

/// Trace a map point while preserving the selected capture's artifact identity.
///
/// The native decoder only needs the map text. This boundary owns the
/// cross-artifact checks that make the resulting report attributable to the
/// captured manifest and script selected by the caller.
pub fn trace_web_source_location_with_evidence(
    input: &Value,
    source_map_text: &str,
    artifacts: &Value,
) -> Result<Value, Failure> {
    super::source_location::validate_input(input)?;

    let selected = SelectedScript::from_artifacts(input, artifacts, source_map_text)?;
    let map_file = verify_source_map(input, source_map_text)?;
    let generated_offset = generated_offset(&selected.source, input)?;
    let mut report = super::source_location::trace_web_source_location(input, source_map_text)?;
    let report_object = report
        .as_object_mut()
        .ok_or_else(|| invalid_evidence("native source-map decoder returned a non-object"))?;

    report_object.insert("manifest".into(), selected.manifest_identity);
    report_object.insert(
        "source".into(),
        serde_json::json!({
            "path": selected.source_file.path,
            "sha256": selected.source_file.sha256,
            "bytes": selected.source_file.bytes,
            "script_index": selected.script_index,
            "script": selected.script,
        }),
    );
    report_object.insert(
        "source_map".into(),
        serde_json::json!({
            "path": map_file.path,
            "sha256": map_file.sha256,
            "bytes": map_file.bytes,
            "url": selected.map_url,
            "association": "caller-selected",
        }),
    );
    report_object.insert(
        "generated_offset".into(),
        serde_json::json!(generated_offset),
    );
    report_object.insert(
        "source_authenticity".into(),
        Value::String("unknown".into()),
    );
    report_object.insert("execution".into(), Value::String("unknown".into()));
    report_object.insert(
        "limitations".into(),
        serde_json::json!([
            "The source/map pairing and source-map URL context are caller-selected. Deployment authenticity and execution remain unknown.",
            "Capture metadata is retained as historical context; this trace verifies the selected manifest, source and map byte identities independently.",
            "Source names and sourceRoot are reported declarations. No original source is fetched or executed.",
            "Lookup returns all segments at the greatest generated position not greater than the selected point, including earlier lines and generated-only segments.",
            "The native producer supports regular source maps; indexed sections are retained as an explicit partial result.",
        ]),
    );

    Ok(report)
}

#[derive(Clone)]
struct ArtifactFile {
    path: String,
    sha256: String,
    bytes: usize,
}

struct SelectedScript {
    manifest_identity: Value,
    source_file: ArtifactFile,
    source: String,
    script_index: usize,
    script: Value,
    map_url: String,
}

impl SelectedScript {
    fn from_artifacts(
        input: &Value,
        artifacts: &Value,
        source_map_text: &str,
    ) -> Result<Self, Failure> {
        let object = artifacts
            .as_object()
            .ok_or_else(|| invalid_evidence("selected web-script artifacts must be an object"))?;
        let manifest = object
            .get("manifest")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid_evidence("selected web-script artifacts require manifest"))?;
        for field in [
            "output_directory",
            "capture_path",
            "capture_sha256",
            "capture_kind",
            "capture_completeness",
            "source_evidence_id",
        ] {
            if !manifest.contains_key(field) {
                return Err(invalid_evidence(&format!(
                    "manifest.{field} is required for captured identity"
                )));
            }
        }
        let manifest_file = artifact_file(object.get("manifestFile"), "manifestFile")?;
        let source_file = artifact_file(object.get("sourceFile"), "sourceFile")?;
        let source = object
            .get("source")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_evidence("selected web-script artifacts require source text"))?
            .to_owned();
        let manifest_path = input
            .get("manifest_path")
            .and_then(Value::as_str)
            .expect("validated source-location input has manifest_path");
        if manifest_file.path != manifest_path {
            return Err(invalid_evidence(
                "manifest artifact path differs from the selected manifest_path",
            ));
        }
        if source_file.bytes != source.len() || hex_digest(source.as_bytes()) != source_file.sha256
        {
            return Err(invalid_evidence(
                "source artifact bytes or digest differs from retained source text",
            ));
        }

        let script_index = input
            .get("script_index")
            .and_then(Value::as_u64)
            .expect("validated source-location input has script_index")
            as usize;
        let script = manifest
            .get("scripts")
            .and_then(Value::as_array)
            .and_then(|scripts| scripts.get(script_index))
            .ok_or_else(|| invalid_evidence("script_index is outside the captured manifest"))?;
        let exported = script
            .as_object()
            .and_then(|script| script.get("content"))
            .and_then(Value::as_object)
            .filter(|content| content.get("state") == Some(&Value::String("exported".to_owned())))
            .ok_or_else(|| invalid_evidence("selected manifest script has no exported content"))?;
        if exported.get("sha256") != Some(&Value::String(source_file.sha256.clone()))
            || exported.get("bytes") != Some(&serde_json::json!(source_file.bytes))
        {
            return Err(invalid_evidence(
                "selected script identity differs from retained source artifact",
            ));
        }

        let source_map = input
            .get("source_map")
            .and_then(Value::as_object)
            .expect("validated source-location input has source_map");
        let map_url = source_map
            .get("url")
            .and_then(Value::as_str)
            .expect("validated source-location input has source_map.url")
            .to_owned();
        if let Some(source_map_artifact) = object.get("sourceMap") {
            verify_selected_source_map(source_map_artifact, source_map, source_map_text)?;
        }
        let manifest_identity = serde_json::json!({
            "path": manifest_file.path,
            "sha256": manifest_file.sha256,
            "bytes": manifest_file.bytes,
            "reported_output_directory": manifest["output_directory"].clone(),
            "capture_path": manifest["capture_path"].clone(),
            "capture_sha256": manifest["capture_sha256"].clone(),
            "capture_kind": manifest["capture_kind"].clone(),
            "capture_completeness": manifest["capture_completeness"].clone(),
            "source_evidence_id": manifest["source_evidence_id"].clone(),
        });

        Ok(Self {
            manifest_identity,
            source_file,
            source,
            script_index,
            script: script.clone(),
            map_url,
        })
    }
}

fn verify_selected_source_map(
    value: &Value,
    selected: &serde_json::Map<String, Value>,
    text: &str,
) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid_evidence("sourceMap must be an object"))?;
    let file = artifact_file(object.get("file"), "sourceMap.file")?;
    let expected_path = selected
        .get("path")
        .and_then(Value::as_str)
        .expect("validated source-location input has source_map.path");
    let expected_url = selected
        .get("url")
        .and_then(Value::as_str)
        .expect("validated source-location input has source_map.url");
    let actual_url = object
        .get("url")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_evidence("sourceMap.url must be non-empty"))?;
    if file.path != expected_path
        || actual_url != expected_url
        || file.bytes != text.len()
        || file.sha256 != hex_digest(text.as_bytes())
    {
        return Err(invalid_evidence(
            "source-map artifact differs from the selected map path, URL or bytes",
        ));
    }
    if let Some(declared_text) = object.get("text").and_then(Value::as_str) {
        if declared_text != text {
            return Err(invalid_evidence(
                "source-map artifact text differs from supplied source-map data",
            ));
        }
    }
    Ok(())
}

fn artifact_file(value: Option<&Value>, field: &str) -> Result<ArtifactFile, Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid_evidence(&format!("{field} must be an artifact file object")))?;
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| invalid_evidence(&format!("{field}.path must be non-empty")))?;
    let sha256 = object
        .get("sha256")
        .and_then(Value::as_str)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| invalid_evidence(&format!("{field}.sha256 must be a SHA-256 digest")))?;
    let bytes = object.get("bytes").and_then(Value::as_u64).ok_or_else(|| {
        invalid_evidence(&format!("{field}.bytes must be a non-negative integer"))
    })?;
    Ok(ArtifactFile {
        path: path.to_owned(),
        sha256: sha256.to_owned(),
        bytes: usize::try_from(bytes)
            .map_err(|_| invalid_evidence(&format!("{field}.bytes exceeds native limits")))?,
    })
}

fn verify_source_map(input: &Value, text: &str) -> Result<ArtifactFile, Failure> {
    let source_map = input
        .get("source_map")
        .and_then(Value::as_object)
        .expect("validated source-location input has source_map");
    let path = source_map
        .get("path")
        .and_then(Value::as_str)
        .expect("validated source-location input has source_map.path");
    Ok(ArtifactFile {
        path: path.to_owned(),
        sha256: hex_digest(text.as_bytes()),
        bytes: text.len(),
    })
}

fn generated_offset(source: &str, input: &Value) -> Result<usize, Failure> {
    let position = input
        .get("generated_position")
        .and_then(Value::as_object)
        .expect("validated source-location input has generated_position");
    let requested_line = position.get("line").and_then(Value::as_u64).unwrap() as usize;
    let requested_column = position.get("column").and_then(Value::as_u64).unwrap() as usize;
    let mut line = 1usize;
    let mut line_start_byte = 0usize;
    let mut line_start_utf16 = 0usize;
    for (index, character) in source.char_indices() {
        if line == requested_line && utf16_len(&source[line_start_byte..index]) >= requested_column
        {
            return Ok(line_start_utf16 + requested_column);
        }
        if matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}') {
            let boundary =
                if character == '\r' && source[index + character.len_utf8()..].starts_with('\n') {
                    index + 2
                } else {
                    index + character.len_utf8()
                };
            if line == requested_line {
                return (requested_column <= utf16_len(&source[line_start_byte..index]))
                    .then_some(line_start_utf16 + requested_column)
                    .ok_or_else(|| {
                        invalid_evidence("generated position is outside retained source text")
                    });
            }
            line += 1;
            line_start_byte = boundary;
            line_start_utf16 = utf16_len(&source[..boundary]);
        }
    }
    if line == requested_line && requested_column <= utf16_len(&source[line_start_byte..]) {
        return Ok(line_start_utf16 + requested_column);
    }
    Err(invalid_evidence(
        "generated position is outside retained source text",
    ))
}

fn utf16_len(value: &str) -> usize {
    value.encode_utf16().count()
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn invalid_evidence(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide unchanged selected manifest, source and source-map evidence.".into(),
        BTreeMap::from([(
            "operation".into(),
            Detail::Text(TRACE_SOURCE_LOCATION.into()),
        )]),
    )
}

/// Validate one of the comparison workflow contracts before dispatch.
pub fn validate_comparison(operation: &str, input: &Value) -> Result<(), Failure> {
    match operation {
        COMPARE_CAPTURES => super::capture_comparison::validate_input(input),
        COMPARE_SCREENSHOTS => super::screenshot_comparison::validate_input(input),
        _ => Err(invalid_operation(operation)),
    }
}

/// Validate the source-location contract independently of map decoding.
pub fn validate_source_location(input: &Value) -> Result<(), Failure> {
    super::source_location::validate_input(input)
}

/// Validate a comparison result using the same input contract as production.
pub fn retain_comparison_result(
    operation: &str,
    input: &Value,
    result: Value,
) -> Result<Value, Failure> {
    match operation {
        COMPARE_CAPTURES => super::capture_comparison::retain_result(input, result),
        COMPARE_SCREENSHOTS => super::screenshot_comparison::retain_result(input, result),
        _ => Err(invalid_operation(operation)),
    }
}

/// Validate a source-location result without re-decoding its source map.
pub fn retain_source_location_result(input: &Value, result: Value) -> Result<Value, Failure> {
    super::source_location::retain_result(input, result)
}

fn invalid_operation(operation: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("unsupported web capture workflow operation: {operation}"),
        false,
        "Use compare_web_captures, compare_web_screenshots or trace_web_source_location.".into(),
        std::collections::BTreeMap::new(),
    )
}
