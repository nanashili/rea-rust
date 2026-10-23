//! Application-owned Electron fuse inspection.

use crate::artifacts::inspection::{ArtifactAnalyzer, ArtifactInspection, Completion};
use rea_core::{
    evidence::{
        Architecture, ArtifactEvidence, Location, NativeFormat, Observation, Provider, Subject,
    },
    failure::{Detail, Failure},
    json_output,
};
use rea_host::fs::stable_file::Snapshot;
use rea_rust_analysis::electron_fuses;
use serde::Serialize;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const OPERATION: &str = "inspect_electron_fuses";
const PROVIDER: Provider = Provider {
    id: "rust-electron-fuses",
    name: "REA Rust Electron fuse reader",
    version: Some("1"),
};
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Validate and project caller-owned Electron fuse facts without acquiring a
/// file, starting Electron, or connecting to a running application.
///
/// The accepted input is either the report object itself or a complete
/// `inspect_electron_fuses` Evidence record.  Evidence envelopes are retained
/// byte-for-byte by returning the supplied value; report inputs are returned
/// after strict boundary validation.  This keeps the static producer's
/// original values, provenance fields, and explicit unknowns authoritative.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    if is_evidence_record(input) {
        validate_evidence(input)?;
        return Ok(input.clone());
    }

    validate_report(input)?;
    Ok(input.clone())
}

fn is_evidence_record(input: &Value) -> bool {
    input
        .as_object()
        .is_some_and(|object| object.get("normalized_result").is_some())
}

fn validate_evidence(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_static("Evidence must be an object"))?;
    if object.get("operation").and_then(Value::as_str) != Some(OPERATION) {
        return Err(invalid_static(
            "Evidence operation must be inspect_electron_fuses",
        ));
    }
    let normalized = object
        .get("normalized_result")
        .ok_or_else(|| invalid_static("Evidence must include normalized_result"))?;
    validate_report(normalized)
}

fn validate_report(value: &Value) -> Result<(), Failure> {
    let object = object(value, "fuse report")?;
    exact_fields(
        object,
        &["artifact", "slices", "runtime_implications", "limitations"],
        "fuse report",
    )?;

    let artifact = object_required(object, "artifact", "fuse report")?;
    exact_fields(
        artifact,
        &[
            "selected_path",
            "resolved_path",
            "sha256",
            "bytes",
            "format",
        ],
        "artifact",
    )?;
    nonempty_string(artifact, "selected_path", "artifact")?;
    nonempty_string(artifact, "resolved_path", "artifact")?;
    let digest = nonempty_string(artifact, "sha256", "artifact")?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid_static(
            "artifact.sha256 must be a lowercase SHA-256 digest",
        ));
    }
    nonnegative_integer(artifact, "bytes", "artifact")?;
    let format = artifact
        .get("format")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_static("artifact.format must be text"))?;
    if !matches!(format, "mach-o" | "mach-o-universal" | "pe" | "elf") {
        return Err(invalid_static("artifact.format is unsupported"));
    }

    let slices = array(object.get("slices"), "slices")?;
    let artifact_bytes = nonnegative_integer(artifact, "bytes", "artifact")?;
    for (index, slice) in slices.iter().enumerate() {
        validate_slice(slice, index as u64, artifact_bytes)?;
    }
    let implications = array(object.get("runtime_implications"), "runtime_implications")?;
    for implication in implications {
        validate_implication(implication, slices, format)?;
    }
    let limitations = array(object.get("limitations"), "limitations")?;
    for limitation in limitations {
        if limitation.as_str().is_none_or(str::is_empty) {
            return Err(invalid_static("limitations must contain non-empty text"));
        }
    }
    Ok(())
}

fn validate_slice(value: &Value, expected_index: u64, artifact_bytes: u64) -> Result<(), Failure> {
    let object = object(value, "slice")?;
    exact_fields(
        object,
        &[
            "index",
            "file_offset",
            "size",
            "architecture",
            "sentinel_count",
            "sentinels",
        ],
        "slice",
    )?;
    let index = nonnegative_integer(object, "index", "slice")?;
    if index != expected_index {
        return Err(invalid_static("slice.index must match its position"));
    }
    let file_offset = nonnegative_integer(object, "file_offset", "slice")?;
    let size = nonnegative_integer(object, "size", "slice")?;
    if file_offset > artifact_bytes || size > artifact_bytes - file_offset {
        return Err(invalid_static("slice range extends outside the artifact"));
    }
    match object.get("architecture") {
        Some(Value::Null) => {}
        Some(Value::String(value)) if !value.is_empty() => {}
        _ => return Err(invalid_static("slice.architecture must be text or null")),
    }
    let sentinel_count = nonnegative_integer(object, "sentinel_count", "slice")?;
    let sentinels = array(object.get("sentinels"), "slice.sentinels")?;
    if sentinel_count != sentinels.len() as u64 {
        return Err(invalid_static("slice.sentinel_count must match sentinels"));
    }
    for sentinel in sentinels {
        validate_sentinel(sentinel, file_offset, size)?;
    }
    Ok(())
}

fn validate_sentinel(value: &Value, slice_offset: u64, slice_size: u64) -> Result<(), Failure> {
    let object = object(value, "sentinel")?;
    exact_fields(
        object,
        &[
            "sentinel_offset",
            "wire_version",
            "declared_length",
            "fuses",
            "complete",
        ],
        "sentinel",
    )?;
    let sentinel_offset = nonnegative_integer(object, "sentinel_offset", "sentinel")?;
    let wire_version = nullable_byte_value(object.get("wire_version"), "sentinel.wire_version")?;
    let declared_length =
        nullable_byte_value(object.get("declared_length"), "sentinel.declared_length")?;
    let complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid_static("sentinel.complete must be boolean"))?;
    let sentinel_end = sentinel_offset
        .checked_add(32)
        .ok_or_else(|| invalid_static("sentinel range overflows"))?;
    if sentinel_offset < slice_offset || sentinel_end > slice_offset + slice_size {
        return Err(invalid_static("sentinel is outside its slice"));
    }
    if wire_version.is_none() && declared_length.is_some() {
        return Err(invalid_static(
            "a wire without a version cannot declare a fuse count",
        ));
    }
    let fuse_count = array(object.get("fuses"), "sentinel.fuses")?.len() as u64;
    let wire_end = sentinel_end
        .checked_add(if wire_version.is_some() { 1 } else { 0 })
        .and_then(|end| end.checked_add(if declared_length.is_some() { 1 } else { 0 }))
        .and_then(|end| end.checked_add(fuse_count))
        .ok_or_else(|| invalid_static("sentinel wire range overflows"))?;
    if wire_end > slice_offset + slice_size {
        return Err(invalid_static("sentinel wire extends outside its slice"));
    }
    if complete && (declared_length.is_none() || fuse_count != u64::from(declared_length.unwrap()))
    {
        return Err(invalid_static(
            "a complete wire must contain every declared fuse byte",
        ));
    }
    if !complete && declared_length.is_some_and(|length| fuse_count >= u64::from(length)) {
        return Err(invalid_static(
            "an incomplete wire must omit a declared fuse byte",
        ));
    }
    for (index, fuse) in array(object.get("fuses"), "sentinel.fuses")?
        .iter()
        .enumerate()
    {
        validate_fuse(fuse, index as u64, wire_version)?;
    }
    Ok(())
}

fn validate_fuse(
    value: &Value,
    expected_index: u64,
    wire_version: Option<u8>,
) -> Result<(), Failure> {
    let object = object(value, "fuse")?;
    exact_fields(object, &["index", "name", "state", "raw_byte"], "fuse")?;
    let index = nonnegative_integer(object, "index", "fuse")?;
    if index != expected_index {
        return Err(invalid_static("fuse.index must match its wire position"));
    }
    let name = match object.get("name") {
        Some(Value::Null) => None,
        Some(Value::String(value)) if !value.is_empty() => Some(value.as_str()),
        _ => return Err(invalid_static("fuse.name must be text or null")),
    };
    let raw_byte = byte(object.get("raw_byte"), "fuse.raw_byte")?;
    let expected_state = match raw_byte {
        0x30 => "disabled",
        0x31 => "enabled",
        0x72 => "removed",
        _ => "unknown",
    };
    if object.get("state").and_then(Value::as_str) != Some(expected_state) {
        return Err(invalid_static("fuse.state must match its raw byte"));
    }
    if name != expected_fuse_name(wire_version, index) {
        return Err(invalid_static(
            "fuse.name must match its wire version and index",
        ));
    }
    Ok(())
}

fn expected_fuse_name(wire_version: Option<u8>, index: u64) -> Option<&'static str> {
    if wire_version != Some(1) {
        return None;
    }
    [
        "RunAsNode",
        "EnableCookieEncryption",
        "EnableNodeOptionsEnvironmentVariable",
        "EnableNodeCliInspectArguments",
        "EnableEmbeddedAsarIntegrityValidation",
        "OnlyLoadAppFromAsar",
        "LoadBrowserProcessSpecificV8Snapshot",
        "GrantFileProtocolExtraPrivileges",
        "WasmTrapHandlers",
    ]
    .get(index as usize)
    .copied()
}

fn validate_implication(value: &Value, slices: &[Value], format: &str) -> Result<(), Failure> {
    let fields = object(value, "runtime implication")?;
    exact_fields(
        fields,
        &[
            "relationship",
            "slice_index",
            "sentinel_offset",
            "subject",
            "fuse_index",
            "outcome",
        ],
        "runtime implication",
    )?;
    if fields.get("relationship").and_then(Value::as_str) != Some("derivation") {
        return Err(invalid_static(
            "runtime implication relationship is unsupported",
        ));
    }
    let slice_index = nonnegative_integer(fields, "slice_index", "runtime implication")?;
    let sentinel_offset = nonnegative_integer(fields, "sentinel_offset", "runtime implication")?;
    let subject = fields
        .get("subject")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_static("runtime implication subject must be text"))?;
    let fuse_index = nonnegative_integer(fields, "fuse_index", "runtime implication")?;
    let outcome = fields
        .get("outcome")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_static("runtime implication outcome must be text"))?;
    let slice = slices
        .get(usize::try_from(slice_index).map_err(|_| invalid_static("slice index is too large"))?)
        .ok_or_else(|| invalid_static("runtime implication references an unknown slice"))?;
    let sentinels = object(slice, "slice")?.get("sentinels");
    let sentinel = array(sentinels, "slice.sentinels")?
        .iter()
        .find(|sentinel| sentinel.get("sentinel_offset") == Some(&Value::from(sentinel_offset)))
        .ok_or_else(|| invalid_static("runtime implication references an unknown sentinel"))?;
    let sentinel = object(sentinel, "sentinel")?;
    let fuse = array(sentinel.get("fuses"), "sentinel.fuses")?
        .iter()
        .find(|fuse| fuse.get("index") == Some(&Value::from(fuse_index)))
        .ok_or_else(|| invalid_static("runtime implication references an unknown fuse"))?;
    let state = fuse
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_static("fuse state must be text"))?;
    let applicability_unknown = subject == "embedded_asar_integrity_validation"
        && !matches!(format, "mach-o" | "mach-o-universal" | "pe");
    let expected_outcome =
        expected_implication_outcome(subject, fuse_index, state, applicability_unknown)
            .ok_or_else(|| invalid_static("runtime implication does not match its pinned fuse"))?;
    if outcome != expected_outcome {
        return Err(invalid_static(
            "runtime implication outcome is not supported by the fuse",
        ));
    }
    Ok(())
}

fn expected_implication_outcome(
    subject: &str,
    fuse_index: u64,
    state: &str,
    applicability_unknown: bool,
) -> Option<&'static str> {
    let (expected_index, enabled, inactive) = match subject {
        "node_cli_inspect_arguments" => (3, "honored", "not_honored"),
        "electron_run_as_node" => (0, "honored", "not_honored"),
        "embedded_asar_integrity_validation" => (4, "enforced", "not_enforced"),
        "only_load_app_from_asar" => (5, "restricted_to_app_asar", "not_restricted_to_app_asar"),
        _ => return None,
    };
    if fuse_index != expected_index {
        return None;
    }
    if applicability_unknown || state == "unknown" {
        return Some("unknown");
    }
    Some(if state == "enabled" {
        enabled
    } else {
        inactive
    })
}

fn object<'a>(value: &'a Value, field: &str) -> Result<&'a Map<String, Value>, Failure> {
    value
        .as_object()
        .ok_or_else(|| invalid_static(&format!("{field} must be an object")))
}

fn object_required<'a>(
    fields: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    object(
        fields
            .get(key)
            .ok_or_else(|| invalid_static(&format!("{field}.{key} is required")))?,
        &format!("{field}.{key}"),
    )
}

fn array<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a [Value], Failure> {
    value
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid_static(&format!("{field} must be an array")))
}

fn exact_fields(
    object: &Map<String, Value>,
    expected: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if object.len() != expected.len() || expected.iter().any(|key| !object.contains_key(*key)) {
        return Err(invalid_static(&format!(
            "{field} has unsupported or missing fields"
        )));
    }
    Ok(())
}

fn nonempty_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<&'a str, Failure> {
    let value = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_static(&format!("{field}.{key} must be text")))?;
    if value.is_empty() {
        return Err(invalid_static(&format!("{field}.{key} must not be empty")));
    }
    if value.contains('\0') {
        return Err(invalid_static(&format!(
            "{field}.{key} must not contain NUL"
        )));
    }
    Ok(value)
}

fn nonnegative_integer(
    object: &Map<String, Value>,
    key: &str,
    field: &str,
) -> Result<u64, Failure> {
    object
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_static(&format!("{field}.{key} must be a nonnegative integer")))
}

fn byte(value: Option<&Value>, field: &str) -> Result<u8, Failure> {
    let value = value
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid_static(&format!("{field} must be a byte")))?;
    u8::try_from(value).map_err(|_| invalid_static(&format!("{field} must be a byte")))
}

fn nullable_byte_value(value: Option<&Value>, field: &str) -> Result<Option<u8>, Failure> {
    if value.is_some_and(Value::is_null) {
        return Ok(None);
    }
    byte(value, field).map(Some)
}

fn invalid_static(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Electron fuse facts are invalid. Check the supplied static report or Evidence and retry."
            .into(),
        false,
        "Provide a complete inspect_electron_fuses report or Evidence record.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(reason.into())),
        ]),
    )
}

#[derive(Default)]
pub struct Analyzer;

impl ArtifactAnalyzer for Analyzer {
    const OPERATION: &'static str = OPERATION;
    const PROVIDER: Provider = PROVIDER;
    const MAX_INPUT_BYTES: usize = 1024 * 1024 * 1024;
    fn build_evidence(path: &str, snapshot: Snapshot) -> Result<Arc<ArtifactEvidence>, Failure> {
        build_evidence(path, path, snapshot)
    }
}

pub struct ElectronFuseInspection<F: rea_host::fs::stable_file::FileAccess> {
    inner: ArtifactInspection<F, Analyzer>,
}

impl<F: rea_host::fs::stable_file::FileAccess> ElectronFuseInspection<F> {
    pub fn new(access: Arc<F>) -> Self {
        Self {
            inner: ArtifactInspection::new(access),
        }
    }
    pub fn close(&mut self) -> Result<(), Failure> {
        self.inner.close()
    }
    pub fn inspect(
        &mut self,
        selected_path: &str,
        cancellation: &rea_core::cancellation::Cancellation,
        completion: Completion,
    ) -> Result<Arc<ArtifactEvidence>, Failure> {
        let resolved = resolve_target(selected_path)?;
        self.inner.inspect_with(
            &resolved,
            Analyzer::MAX_INPUT_BYTES,
            cancellation,
            completion,
            move |path, snapshot, _| build_evidence(selected_path, path, snapshot),
        )
    }
}

#[derive(Debug, Serialize)]
struct ResultEnvelope {
    artifact: Artifact,
    slices: Vec<electron_fuses::Slice>,
    runtime_implications: Vec<electron_fuses::Implication>,
    limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
struct Artifact {
    selected_path: String,
    resolved_path: String,
    sha256: String,
    bytes: usize,
    format: String,
}

fn build_evidence(
    selected_path: &str,
    resolved_path: &str,
    snapshot: Snapshot,
) -> Result<Arc<ArtifactEvidence>, Failure> {
    let report = electron_fuses::inspect(&snapshot.bytes, snapshot.sha256.clone())
        .map_err(|reason| invalid(resolved_path, reason))?;
    let result = ResultEnvelope {
        artifact: Artifact {
            selected_path: selected_path.into(),
            resolved_path: resolved_path.into(),
            sha256: report.artifact.sha256.clone(),
            bytes: report.artifact.bytes,
            format: report.artifact.format.into(),
        },
        slices: report.slices,
        runtime_implications: report.runtime_implications,
        limitations: report.limitations,
    };
    let length = json_output::admitted_length(&result, MAX_OUTPUT_BYTES)
        .map_err(|error| resource(resolved_path, error))?;
    let _ = length;
    let (format, architecture) = format_identity(&result.artifact.format, &result.slices);
    let subject = Subject::new(
        resolved_path,
        result.artifact.sha256.clone(),
        format,
        architecture,
    )
    .map_err(|error| execution(resolved_path, error.to_string()))?;
    let locations = vec![Location::ArtifactPath {
        path: resolved_path.into(),
    }];
    let limitations = result.limitations.clone();
    let evidence = ArtifactEvidence::new(
        subject,
        PROVIDER,
        Observation {
            operation: OPERATION,
            result,
            limitations,
            locations,
        },
    )
    .map_err(|error| execution(resolved_path, error.to_string()))?;
    Ok(Arc::new(evidence))
}

fn resolve_target(selected: &str) -> Result<String, Failure> {
    let path = Path::new(selected);
    let metadata = std::fs::metadata(path).map_err(|error| input(selected, error.to_string()))?;
    if metadata.is_file() {
        return Ok(path.to_string_lossy().into_owned());
    }
    if !metadata.is_dir() {
        return Err(input(
            selected,
            "Expected a regular file or Electron bundle.".into(),
        ));
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let root = if name.ends_with(".app") {
        path.join("Contents/Frameworks/Electron Framework.framework")
    } else if name == "Electron Framework.framework" {
        path.to_path_buf()
    } else {
        return Err(input(
            selected,
            "Expected an Electron .app bundle or Framework directory.".into(),
        ));
    };
    for candidate in [
        root.join("Electron"),
        root.join("Versions/Current/Electron"),
        root.join("Versions/A/Electron"),
    ] {
        if std::fs::metadata(&candidate).is_ok() {
            return Ok(candidate.to_string_lossy().into_owned());
        }
    }
    Err(input(
        selected,
        "Electron Framework binary was not found.".into(),
    ))
}

fn format_identity(
    format: &str,
    slices: &[electron_fuses::Slice],
) -> (NativeFormat, Option<Architecture>) {
    let native = match format {
        "pe" => NativeFormat::Pe,
        "elf" => NativeFormat::Elf,
        _ => NativeFormat::MachO,
    };
    let architecture = slices
        .first()
        .and_then(|slice| slice.architecture.as_deref())
        .and_then(|value| match value {
            "x86" => Some(Architecture::X86),
            "x86_64" => Some(Architecture::X86_64),
            "arm" => Some(Architecture::Arm),
            "arm64" => Some(Architecture::Arm64),
            _ => None,
        });
    (native, architecture)
}

fn input(path: &str, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Unable to select Electron fuse target {path}: {reason}"),
        false,
        "Select an existing Electron bundle or executable.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn invalid(path: &str, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_format",
        format!("Unable to decode Electron fuse target {path}: {reason}"),
        false,
        "Select a supported Mach-O, PE, or ELF executable.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn execution(path: &str, reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "execution_failure",
        format!("Electron fuse inspection failed for {path}: {reason}"),
        false,
        "Review the reported details.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn resource(path: &str, error: json_output::Error) -> Failure {
    Failure::new(
        "resource_constraint",
        "resource_constraint",
        format!("Electron fuse output for {path} exceeds the inline output budget: {error}"),
        false,
        "Select an artifact with a bounded fuse report.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("resource", Detail::Text("output".into())),
        ]),
    )
}
