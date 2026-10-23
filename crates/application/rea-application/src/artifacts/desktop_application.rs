//! Read-only projection of retained desktop application Evidence.
//!
//! Directory traversal and byte probing remain owned by the desktop reader.
//! This module accepts only an authenticated Evidence record and returns its
//! normalized report after validating the public desktop contract.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_desktop_application";
const MAX_FILES: usize = 100_000;
const MAX_OMISSIONS: usize = 100_000;
const MAX_FACTS_PER_FILE: usize = 10_000;

/// Project one retained desktop application Evidence record.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let request = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    require_only(request, &["evidence"])?;

    let evidence = request
        .get("evidence")
        .ok_or_else(|| invalid("evidence is required"))?;
    let raw = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(&format!("evidence could not be encoded: {error}")))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid(
            "evidence operation must be inspect_desktop_application",
        ));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("desktop Evidence result is invalid JSON: {error}")))?;
    validate_report(&result)?;
    Ok(result)
}

fn validate_report(value: &Value) -> Result<(), Failure> {
    let object = object(value, "desktop result")?;
    require_only(
        object,
        &[
            "root",
            "files",
            "omissions",
            "candidates",
            "components",
            "next_probes",
            "coverage",
            "limitations",
        ],
    )?;
    validate_root(required(object, "root")?)?;
    validate_files(required(object, "files")?)?;
    validate_omissions(required(object, "omissions")?)?;
    validate_candidates(required(object, "candidates")?)?;
    validate_components(required(object, "components")?)?;
    validate_probes(required(object, "next_probes")?)?;
    validate_coverage(required(object, "coverage")?)?;
    validate_strings(required(object, "limitations")?, "limitations")
}

fn validate_root(value: &Value) -> Result<(), Failure> {
    let root_fields = object(value, "root")?;
    require_only(
        root_fields,
        &[
            "path",
            "canonical_path",
            "namespace_id",
            "identity",
            "snapshot_sha256",
            "identity_scope",
        ],
    )?;
    local_path(required(root_fields, "path")?, "root.path")?;
    local_path(
        required(root_fields, "canonical_path")?,
        "root.canonical_path",
    )?;
    prefixed_digest(
        required(root_fields, "namespace_id")?,
        "dsr",
        "root.namespace_id",
    )?;
    let identity = object(required(root_fields, "identity")?, "root.identity")?;
    require_only(identity, &["device", "inode"])?;
    text(required(identity, "device")?, "root.identity.device")?;
    text(required(identity, "inode")?, "root.identity.inode")?;
    sha256(
        required(root_fields, "snapshot_sha256")?,
        "root.snapshot_sha256",
    )?;
    exact_text(
        required(root_fields, "identity_scope")?,
        "examined-metadata-and-read-ranges",
        "root.identity_scope",
    )
}

fn validate_files(value: &Value) -> Result<(), Failure> {
    let files = array(value, "files")?;
    bounded(files.len(), MAX_FILES, "files")?;
    for (index, file) in files.iter().enumerate() {
        let object = object(file, &format!("files[{index}]"))?;
        require_only(
            object,
            &[
                "file_id",
                "path",
                "local_path",
                "kind",
                "bytes",
                "identity",
                "read_status",
                "ranges",
                "facts",
                "issues",
            ],
        )?;
        prefixed_digest(required(object, "file_id")?, "dsf", "file_id")?;
        text(required(object, "path")?, "file.path")?;
        local_path(required(object, "local_path")?, "file.local_path")?;
        one_of(
            required(object, "kind")?,
            &["file", "directory", "symlink"],
            "file.kind",
        )?;
        nullable_nonnegative(required(object, "bytes")?, "file.bytes")?;
        validate_file_identity(required(object, "identity")?)?;
        one_of(
            required(object, "read_status")?,
            &["not-selected", "examined", "partial", "unavailable"],
            "file.read_status",
        )?;
        validate_ranges(required(object, "ranges")?)?;
        let facts = array(required(object, "facts")?, "file.facts")?;
        bounded(facts.len(), MAX_FACTS_PER_FILE, "file.facts")?;
        for fact in facts {
            validate_fact(fact)?;
        }
        validate_strings(required(object, "issues")?, "file.issues")?;
    }
    Ok(())
}

fn validate_file_identity(value: &Value) -> Result<(), Failure> {
    if value.is_null() {
        return Ok(());
    }
    let identity = object(value, "file.identity")?;
    require_only(
        identity,
        &["device", "inode", "size", "mode", "mtime_ns", "ctime_ns"],
    )?;
    for field in ["device", "inode", "size", "mode", "mtime_ns", "ctime_ns"] {
        text(required(identity, field)?, field)?;
    }
    Ok(())
}

fn validate_ranges(value: &Value) -> Result<(), Failure> {
    for (index, range) in array(value, "ranges")?.iter().enumerate() {
        let object = object(range, &format!("ranges[{index}]"))?;
        require_only(object, &["offset", "bytes", "sha256"])?;
        nonnegative(required(object, "offset")?, "range.offset")?;
        nonnegative(required(object, "bytes")?, "range.bytes")?;
        sha256(required(object, "sha256")?, "range.sha256")?;
    }
    Ok(())
}

fn validate_fact(value: &Value) -> Result<(), Failure> {
    let object = object(value, "desktop fact")?;
    let kind = required(object, "kind")?
        .as_str()
        .ok_or_else(|| invalid("fact.kind must be a string"))?;
    let allowed = match kind {
        "pe-cli-directory" => vec!["kind", "offset", "value"],
        "unity-assembly-reference" => vec!["kind", "offset", "value"],
        "native-image-header" => vec!["kind", "offset", "value"],
        "il2cpp-metadata-header" => vec!["kind", "offset", "value"],
        "godot-pck-header" => vec!["kind", "offset", "value"],
        "gamemaker-form-header" => vec!["kind", "offset", "value"],
        "il2cpp-library-convention" | "electron-asar-convention" => vec!["kind", "offset", "value"],
        "unreal-container-convention" => vec!["kind", "offset", "value"],
        _ => return Err(invalid("fact.kind is unsupported")),
    };
    require_only(object, &allowed)?;
    let offset = required(object, "offset")?;
    if matches!(
        kind,
        "il2cpp-library-convention" | "electron-asar-convention"
    ) {
        if !offset.is_null() {
            return Err(invalid("convention fact offset must be null"));
        }
    } else if kind == "unreal-container-convention" {
        nullable_nonnegative(offset, "fact.offset")?;
    } else {
        nonnegative(offset, "fact.offset")?;
    }
    validate_fact_value(kind, required(object, "value")?)
}

fn validate_fact_value(kind: &str, value: &Value) -> Result<(), Failure> {
    match kind {
        "pe-cli-directory" => validate_object_fields(value, &["rva", "bytes"]),
        "unity-assembly-reference" => {
            validate_object_text_fields(value, &["name", "token", "managed_directory"])
        }
        "native-image-header" => validate_native_header(value),
        "il2cpp-metadata-header" => {
            let object = object(value, "IL2CPP metadata header")?;
            require_only(object, &["magic", "raw_version"])?;
            exact_text(required(object, "magic")?, "0xfab11baf", "IL2CPP magic")?;
            nonnegative(required(object, "raw_version")?, "IL2CPP raw version")
        }
        "godot-pck-header" => {
            let object = object(value, "Godot PCK header")?;
            require_only(object, &["pack_version", "engine_version", "placement"])?;
            nonnegative(required(object, "pack_version")?, "Godot pack version")?;
            let versions = array(required(object, "engine_version")?, "Godot engine version")?;
            if versions.len() != 3 {
                return Err(invalid("Godot engine_version must contain three numbers"));
            }
            for version in versions {
                nonnegative(version, "Godot engine version")?;
            }
            one_of(
                required(object, "placement")?,
                &["standalone", "embedded-trailer"],
                "Godot placement",
            )
        }
        "gamemaker-form-header" => {
            let object = object(value, "GameMaker FORM header")?;
            require_only(object, &["container", "first_chunk"])?;
            exact_text(
                required(object, "container")?,
                "FORM",
                "GameMaker container",
            )?;
            exact_text(
                required(object, "first_chunk")?,
                "GEN8",
                "GameMaker first chunk",
            )
        }
        "il2cpp-library-convention" | "electron-asar-convention" => text(value, "fact.value"),
        "unreal-container-convention" => {
            if value.as_str().is_some() {
                return Ok(());
            }
            let object = object(value, "unreal convention")?;
            require_only(object, &["format"])?;
            exact_text(required(object, "format")?, "IoStore TOC", "unreal format")
        }
        _ => Err(invalid("unsupported desktop fact")),
    }
}

fn validate_native_header(value: &Value) -> Result<(), Failure> {
    let object = object(value, "native image header")?;
    let format = required(object, "format")?
        .as_str()
        .ok_or_else(|| invalid("native header format must be text"))?;
    require_only(
        object,
        &[
            "format",
            if format == "pe" {
                "machine"
            } else {
                "signature"
            },
        ],
    )?;
    match format {
        "pe" => {
            nonnegative(required(object, "machine")?, "native machine")?;
            Ok(())
        }
        "elf" | "mach-o" => {
            text(required(object, "signature")?, "native signature")?;
            Ok(())
        }
        _ => Err(invalid("native header format is unsupported")),
    }
}

fn validate_object_fields(value: &Value, fields: &[&str]) -> Result<(), Failure> {
    let object = object(value, "fact value")?;
    require_only(object, fields)?;
    for field in fields {
        nonnegative(required(object, field)?, field)?;
    }
    Ok(())
}

fn validate_object_text_fields(value: &Value, fields: &[&str]) -> Result<(), Failure> {
    let object = object(value, "fact value")?;
    require_only(object, fields)?;
    for field in fields {
        text(required(object, field)?, field)?;
    }
    Ok(())
}

fn validate_omissions(value: &Value) -> Result<(), Failure> {
    let omissions = array(value, "omissions")?;
    bounded(omissions.len(), MAX_OMISSIONS, "omissions")?;
    for omission in omissions {
        let object = object(omission, "omission")?;
        require_only(object, &["omission_id", "path", "kind"])?;
        prefixed_digest(required(object, "omission_id")?, "dso", "omission_id")?;
        text(required(object, "path")?, "omission.path")?;
        one_of(
            required(object, "kind")?,
            &[
                "fifo",
                "socket",
                "block-device",
                "character-device",
                "unsupported",
                "directory-descendants",
            ],
            "omission.kind",
        )?;
    }
    Ok(())
}

fn validate_candidates(value: &Value) -> Result<(), Failure> {
    for candidate in array(value, "candidates")? {
        let object = object(candidate, "candidate")?;
        require_only(
            object,
            &[
                "candidate_id",
                "family",
                "confidence",
                "basis_file_ids",
                "rationale",
            ],
        )?;
        prefixed_digest(required(object, "candidate_id")?, "dsc", "candidate_id")?;
        one_of(
            required(object, "family")?,
            &[
                "dotnet",
                "unity-mono",
                "unity-il2cpp",
                "unreal",
                "godot",
                "gamemaker",
                "electron",
            ],
            "candidate.family",
        )?;
        one_of(
            required(object, "confidence")?,
            &["derived", "inferred"],
            "candidate.confidence",
        )?;
        validate_digest_array(required(object, "basis_file_ids")?, "dsf")?;
        text(required(object, "rationale")?, "candidate.rationale")?;
    }
    Ok(())
}

fn validate_components(value: &Value) -> Result<(), Failure> {
    for component in array(value, "components")? {
        let object = object(component, "component")?;
        require_only(
            object,
            &[
                "component_id",
                "name",
                "category",
                "basis_file_ids",
                "confidence",
                "runtime_presence",
            ],
        )?;
        prefixed_digest(required(object, "component_id")?, "dsm", "component_id")?;
        text(required(object, "name")?, "component.name")?;
        one_of(
            required(object, "category")?,
            &["mod-loader", "protection"],
            "component.category",
        )?;
        validate_digest_array(required(object, "basis_file_ids")?, "dsf")?;
        exact_text(
            required(object, "confidence")?,
            "inferred",
            "component.confidence",
        )?;
        exact_text(
            required(object, "runtime_presence")?,
            "unknown",
            "component.runtime_presence",
        )?;
    }
    Ok(())
}

fn validate_probes(value: &Value) -> Result<(), Failure> {
    for probe in array(value, "next_probes")? {
        let object = object(probe, "probe")?;
        require_only(
            object,
            &[
                "probe_id",
                "operation",
                "path",
                "file_id",
                "rationale",
                "confidence",
            ],
        )?;
        prefixed_digest(required(object, "probe_id")?, "dsp", "probe_id")?;
        one_of(
            required(object, "operation")?,
            &[
                "inspect_managed_artifact",
                "inspect_il2cpp_metadata",
                "open_binary",
                "analyze_javascript_application",
            ],
            "probe.operation",
        )?;
        local_path(required(object, "path")?, "probe.path")?;
        prefixed_digest(required(object, "file_id")?, "dsf", "probe.file_id")?;
        text(required(object, "rationale")?, "probe.rationale")?;
        exact_text(
            required(object, "confidence")?,
            "inferred",
            "probe.confidence",
        )?;
    }
    Ok(())
}

fn validate_coverage(value: &Value) -> Result<(), Failure> {
    let coverage_fields = object(value, "coverage")?;
    require_only(
        coverage_fields,
        &[
            "status",
            "entries_examined",
            "files_probed",
            "bytes_read",
            "symlinks_not_followed",
            "special_entries_omitted",
            "limits",
        ],
    )?;
    one_of(
        required(coverage_fields, "status")?,
        &["complete-within-scan", "partial"],
        "coverage.status",
    )?;
    for field in [
        "entries_examined",
        "files_probed",
        "bytes_read",
        "symlinks_not_followed",
        "special_entries_omitted",
    ] {
        nonnegative(required(coverage_fields, field)?, field)?;
    }
    let limits = object(required(coverage_fields, "limits")?, "coverage.limits")?;
    require_only(limits, &["max_entries", "max_probe_bytes"])?;
    nonnegative(
        required(limits, "max_entries")?,
        "coverage.limits.max_entries",
    )?;
    nonnegative(
        required(limits, "max_probe_bytes")?,
        "coverage.limits.max_probe_bytes",
    )
}

fn validate_digest_array(value: &Value, prefix: &str) -> Result<(), Failure> {
    let values = array(value, "digest array")?;
    if values.is_empty() {
        return Err(invalid("digest array must not be empty"));
    }
    for value in values {
        prefixed_digest(value, prefix, "digest")?;
    }
    Ok(())
}

fn validate_strings(value: &Value, field: &str) -> Result<(), Failure> {
    for item in array(value, field)? {
        if item.as_str().is_none() {
            return Err(invalid(&format!("{field} must contain strings")));
        }
    }
    Ok(())
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid(&format!("{field} must be an object")))
}

fn array<'a>(value: &'a Value, field: &str) -> Result<&'a Vec<Value>, Failure> {
    value
        .as_array()
        .ok_or_else(|| invalid(&format!("{field} must be an array")))
}

fn required<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a Value, Failure> {
    object
        .get(field)
        .ok_or_else(|| invalid(&format!("{field} is required")))
}

fn require_only(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown desktop field: {field}")));
    }
    if allowed.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid("desktop result is missing a required field"));
    }
    Ok(())
}

fn bounded(length: usize, maximum: usize, field: &str) -> Result<(), Failure> {
    if length > maximum {
        Err(invalid(&format!(
            "{field} exceeds its representation limit"
        )))
    } else {
        Ok(())
    }
}

fn text(value: &Value, field: &str) -> Result<(), Failure> {
    if value.as_str().is_some() {
        Ok(())
    } else {
        Err(invalid(&format!("{field} must be a string")))
    }
}

fn local_path(value: &Value, field: &str) -> Result<(), Failure> {
    let text = value
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))?;
    if text.contains('\0') {
        Err(invalid(&format!("{field} must not contain NUL")))
    } else {
        Ok(())
    }
}

fn exact_text(value: &Value, expected: &str, field: &str) -> Result<(), Failure> {
    if value.as_str() == Some(expected) {
        Ok(())
    } else {
        Err(invalid(&format!("{field} must be {expected}")))
    }
}

fn one_of(value: &Value, choices: &[&str], field: &str) -> Result<(), Failure> {
    if value.as_str().is_some_and(|value| choices.contains(&value)) {
        Ok(())
    } else {
        Err(invalid(&format!("{field} has an unsupported value")))
    }
}

fn nonnegative(value: &Value, field: &str) -> Result<(), Failure> {
    if value.as_u64().is_some() {
        Ok(())
    } else {
        Err(invalid(&format!("{field} must be a non-negative integer")))
    }
}

fn nullable_nonnegative(value: &Value, field: &str) -> Result<(), Failure> {
    if value.is_null() {
        Ok(())
    } else {
        nonnegative(value, field)
    }
}

fn prefixed_digest(value: &Value, prefix: &str, field: &str) -> Result<(), Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a digest")))?;
    let expected = format!("{prefix}_");
    let valid = text.starts_with(&expected)
        && text.len() == expected.len() + 64
        && text[expected.len()..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(invalid(&format!(
            "{field} must be a lowercase {prefix} digest"
        )))
    }
}

fn sha256(value: &Value, field: &str) -> Result<(), Failure> {
    let text = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a SHA-256 digest")))?;
    let valid = text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
    if valid {
        Ok(())
    } else {
        Err(invalid(&format!(
            "{field} must be a lowercase SHA-256 digest"
        )))
    }
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Desktop application Evidence input is invalid.".into(),
        false,
        "Provide retained inspect_desktop_application Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}
