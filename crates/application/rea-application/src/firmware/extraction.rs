//! Bounded, read-only firmware extraction projection.
//!
//! The runtime adapter may supply a report produced by an approved extractor.
//! This module owns the caller contract, selected-byte identity, report
//! binding, and publication metadata. It never executes extracted bytes or
//! creates an output directory; the adapter that owns those capabilities can
//! publish the returned file plan after these facts have been authenticated.

use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rea_core::{
    evidence::is_sha256,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const OPERATION: &str = "extract_firmware";
pub const MAX_INPUT_BYTES: u64 = 128 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_OUTPUT_FILES: u64 = 100_000;
pub const MAX_DEPTH: u64 = 10;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

fn failure(code: &'static str, category: &'static str, message: impl Into<String>) -> Failure {
    Failure::new(
        code,
        category,
        message.into(),
        true,
        "Correct the request or provide a complete bounded extractor report and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid(message: impl Into<String>) -> Failure {
    failure("invalid_request", "invalid_input", message)
}

fn provider(message: impl Into<String>) -> Failure {
    failure("provider_error", "provider", message)
}

fn resource(message: impl Into<String>) -> Failure {
    failure("resource_constraint", "memory", message)
}

fn text<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a str, Failure> {
    object
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{key} must be a non-empty string")))
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), Failure> {
    if let Some(key) = object
        .keys()
        .find(|key| !allowed.iter().any(|allowed| *allowed == key.as_str()))
    {
        return Err(provider(format!("unknown {context} field: {key}")));
    }
    Ok(())
}

fn non_negative_integer(value: Option<&Value>, field: &str) -> Result<u64, Failure> {
    let value = value
        .and_then(Value::as_u64)
        .ok_or_else(|| provider(format!("{field} must be a non-negative integer")))?;
    if value > MAX_SAFE_INTEGER {
        return Err(provider(format!(
            "{field} exceeds the JSON-safe integer limit"
        )));
    }
    Ok(value)
}

fn optional_string(object: &Map<String, Value>, key: &str) -> Result<(), Failure> {
    match object.get(key) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::String(value)) if !value.is_empty() => Ok(()),
        _ => Err(provider(format!(
            "{key} must be a non-empty string or null"
        ))),
    }
}

fn u64_field(object: &Map<String, Value>, key: &str, default: u64) -> Result<u64, Failure> {
    match object.get(key) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .ok_or_else(|| invalid(format!("{key} must be a non-negative integer"))),
    }
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_relative_path(path: &str) -> Result<(), Failure> {
    if path.is_empty()
        || path.contains('\0')
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(provider(format!(
            "extractor reported unsafe relative path: {path}"
        )));
    }
    Ok(())
}

/// Validate the strict extraction request. `report` and `entries` are adapter
/// inputs rather than public tool fields, and are therefore supplied to
/// [`extract`] separately.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("extract_firmware input must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "path"
                | "output_directory"
                | "range"
                | "max_depth"
                | "max_output_bytes"
                | "max_output_files"
        ) {
            return Err(invalid(format!("unknown extract_firmware field: {key}")));
        }
    }
    let path = text(object, "path")?;
    let output = text(object, "output_directory")?;
    if path.contains('\0') || output.contains('\0') {
        return Err(invalid(
            "path and output_directory must not contain NUL bytes",
        ));
    }
    if !Path::new(path).is_absolute() || !Path::new(output).is_absolute() {
        return Err(invalid("path and output_directory must be absolute paths"));
    }
    if path == output {
        return Err(invalid(
            "output_directory must differ from the selected source",
        ));
    }
    let depth = u64_field(object, "max_depth", 3)?;
    let bytes = u64_field(object, "max_output_bytes", 256 * 1024 * 1024)?;
    let files = u64_field(object, "max_output_files", 10_000)?;
    if !(1..=MAX_DEPTH).contains(&depth)
        || !(1..=MAX_OUTPUT_BYTES).contains(&bytes)
        || !(1..=MAX_OUTPUT_FILES).contains(&files)
    {
        return Err(invalid(
            "max_depth, max_output_bytes, or max_output_files exceeds the extraction limits",
        ));
    }
    if let Some(range) = object.get("range") {
        let range = range
            .as_object()
            .ok_or_else(|| invalid("range must be an object"))?;
        for key in range.keys() {
            if !matches!(key.as_str(), "offset" | "length") {
                return Err(invalid(format!("unknown range field: {key}")));
            }
        }
        let offset = range
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("range.offset must be a non-negative integer"))?;
        let length = range
            .get("length")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("range.length must be a positive integer"))?;
        if offset > MAX_SAFE_INTEGER
            || length > MAX_SAFE_INTEGER
            || length == 0
            || offset.checked_add(length).is_none()
        {
            return Err(invalid(
                "range must have a positive, representable JSON-safe length",
            ));
        }
    }
    Ok(())
}

fn selection(input: &Map<String, Value>, source_len: u64) -> Result<(u64, u64), Failure> {
    let Some(range) = input.get("range") else {
        return Ok((0, source_len));
    };
    let range = range
        .as_object()
        .ok_or_else(|| invalid("range must be an object"))?;
    let offset = range
        .get("offset")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("range.offset is invalid"))?;
    let length = range
        .get("length")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("range.length is invalid"))?;
    if length == 0 || offset > source_len || length > source_len - offset {
        return Err(invalid(format!(
            "selected range must be within the {source_len}-byte firmware file"
        )));
    }
    Ok((offset, length))
}

fn object<'a>(value: &'a Value, name: &str) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| provider(format!("{name} must be an object")))
}

fn validate_report_arrays(report: &Map<String, Value>, max_files: u64) -> Result<(), Failure> {
    reject_unknown_fields(
        report,
        &[
            "engine",
            "entries",
            "coverage",
            "unpublished_entries",
            "chunks",
            "derivations",
            "depth_limited_paths",
            "diagnostics",
            "extraction_gaps",
            "extraction_continuations",
            "failed_extraction_stages",
            "missing_dependencies",
            "chunk_missing_dependencies",
        ],
        "extractor report",
    )?;
    for key in [
        "unpublished_entries",
        "chunks",
        "derivations",
        "depth_limited_paths",
        "diagnostics",
        "extraction_gaps",
        "extraction_continuations",
        "failed_extraction_stages",
        "missing_dependencies",
        "chunk_missing_dependencies",
    ] {
        if let Some(value) = report.get(key) {
            let Some(items) = value.as_array() else {
                return Err(provider(format!(
                    "extractor report field {key} must be an array"
                )));
            };
            if items.len() as u64 > max_files {
                return Err(resource(format!(
                    "extractor report field {key} exceeds the entry budget"
                )));
            }
        }
    }

    for key in ["depth_limited_paths"] {
        if let Some(items) = report.get(key).and_then(Value::as_array) {
            if items
                .iter()
                .any(|item| item.as_str().is_none_or(str::is_empty))
            {
                return Err(provider(format!(
                    "extractor report field {key} must contain non-empty strings"
                )));
            }
        }
    }

    if let Some(items) = report
        .get("extraction_continuations")
        .and_then(Value::as_array)
    {
        for item in items {
            let item = object(item, "extraction continuation")?;
            reject_unknown_fields(item, &["id", "instruction"], "extraction continuation")?;
            text(item, "id")?;
            text(item, "instruction")?;
        }
    }

    Ok(())
}

fn validate_entry_metadata(entry: &Map<String, Value>, relative_path: &str) -> Result<(), Failure> {
    reject_unknown_fields(
        entry,
        &[
            "relative_path",
            "bytes_base64",
            "sha256",
            "mime_type",
            "analysis_depth",
        ],
        "entry",
    )?;
    if let Some(value) = entry.get("sha256") {
        if !value.is_null() {
            let sha256 = value.as_str().ok_or_else(|| {
                provider(format!(
                    "invalid sha256 for extracted path: {relative_path}"
                ))
            })?;
            if !is_sha256(sha256) {
                return Err(provider(format!(
                    "invalid sha256 for extracted path: {relative_path}"
                )));
            }
        }
    }
    optional_string(entry, "mime_type")?;
    if let Some(value) = entry.get("analysis_depth") {
        if !value.is_null() {
            non_negative_integer(Some(value), "analysis_depth")?;
        }
    }
    Ok(())
}

fn continuation_id(instruction: &str) -> String {
    digest(instruction.as_bytes())
}

fn gap_row(
    kind: &str,
    input_path: &str,
    relative_path: Value,
    handler: Value,
    provider_id: Value,
    range: Value,
    root_file_range: Value,
    continuation_id: String,
) -> Value {
    serde_json::json!({
        "kind": kind,
        "input_path": input_path,
        "relative_path": relative_path,
        "handler": handler,
        "provider_id": provider_id,
        "range": range,
        "root_file_range": root_file_range,
        "dependencies": [],
        "continuation_id": continuation_id,
    })
}

/// Derive recovery rows when the producer retained only normalized chunk facts.
///
/// The TypeScript publication owner derives these rows after it has materialized
/// files. The native projection cannot publish files, but it can still preserve
/// the same actionable uncertainty from chunk, depth, and unpublished metadata.
const NAMED_DEPENDENCY_CONTINUATION: &str = "REA installs nothing. Add the named dependency to your own environment and rerun extract_firmware on the same immutable input with a fresh output_directory to re-evaluate the affected region; otherwise it stays unextracted.";
const UNNAMED_DEPENDENCY_CONTINUATION: &str = "The producer reported a missing extractor dependency without naming it; its identity is unavailable in this evidence. No specific installation or rerun can be prescribed from this report. Retain the gap as unextracted unless additional provider evidence establishes the dependency. REA installs nothing.";

fn dependency_continuation(dependencies: &[Value]) -> (&'static str, Vec<Value>) {
    let names = dependencies
        .iter()
        .filter_map(Value::as_str)
        .filter(|name| !name.is_empty())
        .map(|name| Value::String(name.to_owned()))
        .collect::<Vec<_>>();
    let mut names = names;
    names.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
    names.dedup();
    if names.is_empty() {
        (UNNAMED_DEPENDENCY_CONTINUATION, names)
    } else {
        (NAMED_DEPENDENCY_CONTINUATION, names)
    }
}

fn push_dependency_gap(
    gaps: &mut Vec<Value>,
    continuation_ids: &mut BTreeMap<String, String>,
    input_path: &str,
    provider_id: Value,
    handler: Value,
    dependencies: Vec<Value>,
) {
    let (instruction, dependencies) = dependency_continuation(&dependencies);
    let id = continuation_ids
        .entry(instruction.to_owned())
        .or_insert_with(|| continuation_id(instruction))
        .clone();
    gaps.push(serde_json::json!({
        "kind": "missing-extractor-dependency",
        "input_path": input_path,
        "relative_path": null,
        "handler": handler,
        "provider_id": provider_id,
        "range": null,
        "root_file_range": null,
        "dependencies": dependencies,
        "continuation_id": id,
    }));
}

fn derive_extraction_evidence(
    report: &Map<String, Value>,
    max_depth: u64,
) -> (Vec<Value>, Vec<Value>) {
    let existing_gaps = report
        .get("extraction_gaps")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty());
    let existing_continuations = report
        .get("extraction_continuations")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty());
    if let Some(gaps) = existing_gaps {
        return (
            gaps.clone(),
            existing_continuations.cloned().unwrap_or_default(),
        );
    }

    let instructions = [
        (
            "unknown-chunk-handler",
            "Run inspect_firmware_regions on the same input for signature hypotheses when Binwalk is configured; otherwise retain the region as unexamined.",
        ),
        (
            "encrypted-chunk",
            "Static extraction does not continue past encryption; retain the region as unexamined rather than empty or corrupt.",
        ),
        (
            "extractor-failure",
            "Review the retained extraction failure, correct its cause, and rerun extract_firmware on the same immutable input with a fresh output directory.",
        ),
        (
            "depth-limited",
            "Rerun extract_firmware with a higher max_depth and a fresh output directory to descend into this path.",
        ),
        (
            "unpublished-entry",
            "The entry is retained as metadata; only regular files are published without executable permission bits.",
        ),
    ];
    let instruction_for = |kind: &str| {
        instructions
            .iter()
            .find(|(name, _)| *name == kind)
            .map(|(_, text)| *text)
            .unwrap_or(
                "The producer retained an extraction gap; review its diagnostics before retrying.",
            )
    };
    let mut gaps = Vec::new();
    let mut continuation_ids = BTreeMap::new();
    let continuation = |kind: &str, ids: &mut BTreeMap<String, String>| {
        let instruction = instruction_for(kind).to_owned();
        ids.entry(instruction.clone())
            .or_insert_with(|| continuation_id(&instruction))
            .clone()
    };

    if let Some(items) = report
        .get("chunk_missing_dependencies")
        .and_then(Value::as_array)
    {
        for item in items {
            let Some(item) = item.as_object() else {
                continue;
            };
            let Some(input_path) = item.get("input_path").and_then(Value::as_str) else {
                continue;
            };
            let Some(provider_id) = item.get("provider_id").and_then(Value::as_str) else {
                continue;
            };
            let dependencies = item
                .get("dependencies")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let chunk = report
                .get("chunks")
                .and_then(Value::as_array)
                .and_then(|chunks| {
                    chunks.iter().find(|chunk| {
                        chunk.get("input_path").and_then(Value::as_str) == Some(input_path)
                            && chunk.get("provider_id").and_then(Value::as_str) == Some(provider_id)
                    })
                });
            push_dependency_gap(
                &mut gaps,
                &mut continuation_ids,
                input_path,
                Value::String(provider_id.to_owned()),
                chunk
                    .and_then(|chunk| chunk.get("handler"))
                    .cloned()
                    .unwrap_or(Value::Null),
                dependencies,
            );
        }
    }

    if let Some(items) = report
        .get("failed_extraction_stages")
        .and_then(Value::as_array)
    {
        for item in items {
            let Some(item) = item.as_object() else {
                continue;
            };
            if item.get("kind").and_then(Value::as_str) != Some("missing-extractor-dependency") {
                continue;
            }
            let Some(input_path) = item.get("input_path").and_then(Value::as_str) else {
                continue;
            };
            let dependencies = item
                .get("dependencies")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            push_dependency_gap(
                &mut gaps,
                &mut continuation_ids,
                input_path,
                item.get("provider_id").cloned().unwrap_or(Value::Null),
                item.get("handler").cloned().unwrap_or(Value::Null),
                dependencies,
            );
        }
    }

    if let Some(items) = report.get("missing_dependencies").and_then(Value::as_array) {
        for item in items {
            let Some(item) = item.as_object() else {
                continue;
            };
            let Some(input_path) = item.get("input_path").and_then(Value::as_str) else {
                continue;
            };
            let dependencies = item
                .get("dependencies")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            push_dependency_gap(
                &mut gaps,
                &mut continuation_ids,
                input_path,
                Value::Null,
                Value::Null,
                dependencies,
            );
        }
    }

    let dependency_chunk_keys = report
        .get("chunk_missing_dependencies")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let item = item.as_object()?;
                    Some((
                        item.get("input_path")?.as_str()?.to_owned(),
                        item.get("provider_id")?.as_str()?.to_owned(),
                    ))
                })
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();

    if let Some(chunks) = report.get("chunks").and_then(Value::as_array) {
        for chunk in chunks {
            let Some(chunk) = chunk.as_object() else {
                continue;
            };
            let Some(input_path) = chunk.get("input_path").and_then(Value::as_str) else {
                continue;
            };
            let kind = if chunk.get("handler").is_some_and(Value::is_null) {
                Some("unknown-chunk-handler")
            } else if chunk.get("encrypted").and_then(Value::as_bool) == Some(true) {
                Some("encrypted-chunk")
            } else if chunk.get("extraction_failed").and_then(Value::as_bool) == Some(true)
                && !dependency_chunk_keys.contains(&(
                    input_path.to_owned(),
                    chunk
                        .get("provider_id")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                ))
            {
                Some("extractor-failure")
            } else {
                None
            };
            let Some(kind) = kind else {
                continue;
            };
            gaps.push(gap_row(
                kind,
                input_path,
                Value::Null,
                chunk.get("handler").cloned().unwrap_or(Value::Null),
                chunk.get("provider_id").cloned().unwrap_or(Value::Null),
                chunk.get("range").cloned().unwrap_or(Value::Null),
                chunk.get("root_file_range").cloned().unwrap_or(Value::Null),
                continuation(kind, &mut continuation_ids),
            ));
        }
    }

    if let Some(paths) = report.get("depth_limited_paths").and_then(Value::as_array) {
        for input_path in paths.iter().filter_map(Value::as_str) {
            let kind = "depth-limited";
            let instruction = if max_depth < MAX_DEPTH {
                instruction_for(kind).to_owned()
            } else {
                "The extraction reached its maximum depth; rerun from an eligible published child or retain the path as unexamined.".into()
            };
            let id = continuation_ids
                .entry(instruction.clone())
                .or_insert_with(|| continuation_id(&instruction))
                .clone();
            gaps.push(gap_row(
                kind,
                input_path,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                id,
            ));
        }
    }

    if let Some(entries) = report.get("unpublished_entries").and_then(Value::as_array) {
        for entry in entries {
            let Some(entry) = entry.as_object() else {
                continue;
            };
            let Some(relative_path) = entry.get("relative_path").and_then(Value::as_str) else {
                continue;
            };
            let kind = "unpublished-entry";
            let input_path = format!("$output/{relative_path}");
            gaps.push(gap_row(
                kind,
                &input_path,
                Value::String(relative_path.into()),
                Value::Null,
                Value::Null,
                Value::Null,
                Value::Null,
                continuation(kind, &mut continuation_ids),
            ));
        }
    }

    gaps.sort_by_key(|gap| {
        (
            gap.get("input_path")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            gap.get("kind")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
        )
    });
    let continuations = continuation_ids
        .into_iter()
        .map(|(instruction, id)| serde_json::json!({"id": id, "instruction": instruction}))
        .collect();
    (gaps, continuations)
}

/// Build an authenticated extraction result from bytes and an extractor
/// report. The report format intentionally mirrors the normalized Unblob facts
/// consumed by the TypeScript publication owner: `entries`, `chunks`,
/// `derivations`, `depth_limited_paths`, `diagnostics`, and `gaps`.
pub fn extract(input: &Value, report: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let request = input.as_object().expect("validated request");
    let source_path = text(request, "path")?;
    let output_directory = text(request, "output_directory")?;
    let source = fs::read(source_path)
        .map_err(|error| provider(format!("unable to read firmware: {error}")))?;
    if source.is_empty() || source.len() as u64 > MAX_INPUT_BYTES {
        return Err(resource("firmware input exceeds the 128 MiB limit"));
    }
    let (offset, length) = selection(request, source.len() as u64)?;
    let selected = &source[offset as usize..(offset + length) as usize];
    let report = object(report, "extractor report")?;
    let max_files = u64_field(request, "max_output_files", 10_000)?;
    validate_report_arrays(report, max_files)?;
    let engine = report
        .get("engine")
        .and_then(Value::as_object)
        .ok_or_else(|| provider("extractor report must contain engine identity"))?;
    reject_unknown_fields(
        engine,
        &[
            "name",
            "version",
            "executable_path",
            "executable_sha256",
            "source_revision",
            "worker_count",
        ],
        "engine",
    )?;
    for key in ["name", "version", "executable_path", "executable_sha256"] {
        if engine
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(provider(format!("extractor engine field {key} is missing")));
        }
    }
    if !is_sha256(engine["executable_sha256"].as_str().unwrap_or_default()) {
        return Err(provider(
            "extractor executable_sha256 is not a lowercase SHA-256 digest",
        ));
    }
    if engine.get("source_revision") != Some(&Value::Null)
        || engine.get("worker_count").and_then(Value::as_u64) != Some(1)
    {
        return Err(provider(
            "extractor engine must declare source_revision null and worker_count 1",
        ));
    }
    let entries = report
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| provider("extractor report must contain entries"))?;
    if let Some(coverage) = report.get("coverage") {
        if !matches!(coverage.as_str(), Some("complete") | Some("partial")) {
            return Err(provider(
                "extractor report coverage must be complete or partial",
            ));
        }
    }
    let max_bytes = u64_field(request, "max_output_bytes", 256 * 1024 * 1024)?;
    let max_depth = u64_field(request, "max_depth", 3)?;
    if entries.len() as u64 > max_files {
        return Err(resource("staging entry budget exceeded"));
    }
    let mut files = Vec::new();
    let mut published_bytes = 0u64;
    let mut seen = BTreeSet::new();
    for entry in entries {
        let entry = object(entry, "entry")?;
        let relative_path = text(entry, "relative_path")?;
        validate_relative_path(relative_path)?;
        validate_entry_metadata(entry, relative_path)?;
        if !seen.insert(relative_path.to_owned()) {
            return Err(provider(format!(
                "duplicate extracted path: {relative_path}"
            )));
        }
        let bytes_text = text(entry, "bytes_base64")?;
        let bytes = BASE64
            .decode(bytes_text)
            .map_err(|_| provider(format!("invalid bytes_base64 for {relative_path}")))?;
        published_bytes = published_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| resource("published byte count overflow"))?;
        if published_bytes > max_bytes {
            return Err(resource("staging byte budget exceeded"));
        }
        let computed = digest(&bytes);
        if let Some(reported) = entry.get("sha256").and_then(Value::as_str) {
            if !is_sha256(reported) {
                return Err(provider(format!(
                    "invalid sha256 for extracted path: {relative_path}"
                )));
            }
            if reported != computed {
                return Err(provider(format!(
                    "digest mismatch for extracted path: {relative_path}"
                )));
            }
        }
        files.push(serde_json::json!({
            "relative_path": relative_path,
            "path": format!("{output_directory}/{relative_path}"),
            "size": bytes.len(),
            "sha256": computed,
            "reported_sha256": entry.get("sha256").cloned().unwrap_or(Value::Null),
            "mime_type": entry.get("mime_type").cloned().unwrap_or(Value::Null),
            "analysis_depth": entry.get("analysis_depth").cloned().unwrap_or(Value::Null),
            "runtime_address": Value::Null,
            "original_file_range": Value::Null,
        }));
    }
    files.sort_by(|left, right| {
        left["relative_path"]
            .as_str()
            .cmp(&right["relative_path"].as_str())
    });
    let mut result = Map::new();
    result.insert("engine".into(), Value::Object(engine.clone()));
    result.insert(
        "selection".into(),
        serde_json::json!({"offset": offset, "length": length, "sha256": digest(selected)}),
    );
    result.insert(
        "output_directory".into(),
        Value::String(output_directory.to_owned()),
    );
    result.insert(
        "coverage".into(),
        Value::String(
            if report.get("coverage").and_then(Value::as_str) == Some("complete") {
                "complete"
            } else {
                "partial"
            }
            .into(),
        ),
    );
    result.insert("files".into(), Value::Array(files));
    let (derived_gaps, derived_continuations) = derive_extraction_evidence(report, max_depth);
    for key in [
        "unpublished_entries",
        "chunks",
        "derivations",
        "depth_limited_paths",
        "diagnostics",
        "extraction_gaps",
        "extraction_continuations",
    ] {
        let value = match key {
            "extraction_gaps" => Value::Array(derived_gaps.clone()),
            "extraction_continuations" => Value::Array(derived_continuations.clone()),
            _ => report
                .get(key)
                .cloned()
                .unwrap_or_else(|| Value::Array(Vec::new())),
        };
        result.insert(key.into(), value);
    }
    result.insert("published_bytes".into(), Value::from(published_bytes));
    Ok(Value::Object(result))
}
