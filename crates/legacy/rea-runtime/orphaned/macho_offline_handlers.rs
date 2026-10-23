//! Offline Mach-O inspection from caller-supplied bytes or retained Evidence.
//!
//! This adapter owns no filesystem, provider, or target authority. The caller
//! supplies one bounded byte snapshot, while the Rust Mach-O reader owns the
//! format interpretation and its limitations.

use base64::Engine;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_rust_analysis::{image, macho};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_macho";

const LIMITATIONS: [&str; 22] = [
    "Mach-O facts are decoded from the caller-supplied stable byte snapshot without launching the target or invoking Apple tooling.",
    "Imports and exports are sourced from LC_SYMTAB, dyld export/bind streams, and supported chained-fixup import tables. Bounded dyld rebase streams, LC_FUNCTION_STARTS entries, LC_DATA_IN_CODE records, and structural code-signature metadata are decoded. Code-signature facts do not validate trust or authenticity.",
    "Encryption metadata preserves LC_ENCRYPTION_INFO command ranges, cryptid values, explicit encrypted or unencrypted state, and unknown state for invalid ranges; it does not decrypt bytes or verify protection.",
    "LC_NOTE owner bytes and bounded file ranges are preserved as opaque metadata; note payloads are not interpreted.",
    "LC_MAIN entry offsets are mapped to VM addresses only when a file-backed segment proves the mapping. Supported x86_64 and arm64 LC_UNIXTHREAD PC fields are decoded without execution; other thread states remain raw.",
    "LC_FILESET_ENTRY metadata is decoded without recursively inspecting child images; entry IDs and bounded file offsets are preserved.",
    "LC_BUILD_VERSION platform values are retained with minimum OS, SDK, and bounded tool-version records; enum values are not normalized away.",
    "LC_RPATH and LC_DYLD_ENVIRONMENT strings retain raw bytes, decoded values, exact command and string source ranges, and explicit invalid state for unterminated or out-of-command strings.",
    "LC_LOAD_DYLINKER and LC_ID_DYLINKER paths retain bounded raw bytes, decoded values, command offsets, and malformed string issues.",
    "Dylib load, weak, reexport, and upward commands retain bounded names, timestamps, compatibility versions, and current versions.",
    "LC_UUID retains the raw 16-byte UUID and bounded command provenance alongside its hexadecimal value.",
    "Section metadata retains the raw alignment exponent, normalized alignment bytes, flags, reserved fields, and bounded segment-derived layout.",
    "Section flags retain the raw value and recognized Mach-O type and attribute names.",
    "Build metadata preserves raw platform codes and recognized platform names.",
    "Segment permissions preserve decoded read/write/execute bits and the raw protection value.",
    "Code-signature child slots and CodeDirectory hash metadata are structural facts only; signature verification is not performed.",
    "LC_SYMTAB nlist entries retain raw type, section, description, value, bounded names, and source offsets; unresolved string indexes remain invalid facts.",
    "LC_DYSYMTAB offsets and indirect entries retain raw values; only exact local and absolute sentinels receive special classifications.",
    "LC_DYLD_CHAINED_FIXUPS metadata retains bounded command data and header-relative starts/imports/symbol offsets; pointer facts are emitted only for decoded formats.",
    "Chained-fixup imports retain raw table entry ranges, library ordinals, weak flags, addends, and bounded symbol names; unsupported formats remain explicit.",
    "LC_LINKER_OPTION strings retain bounded raw and decoded option records; truncated options remain invalid facts.",
    "Universal Mach-O containers require an explicit architecture selection and are rejected until the caller supplies one.",
];

/// Inspect a caller-supplied Mach-O snapshot, or project matching Evidence.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    let object = input_object(&input)?;

    if let Some(evidence) = object.get("evidence") {
        validate_evidence_input(object)?;
        return project_evidence(evidence);
    }

    validate_bytes_input(object)?;
    let source = MachoBytes::from_input(object)?;
    inspect_bytes(source)
}

fn validate_evidence_input(object: &Map<String, Value>) -> Result<(), Failure> {
    if object.len() != 1 {
        return Err(invalid(
            "captured Evidence input must contain only evidence".into(),
        ));
    }

    Ok(())
}

fn validate_bytes_input(object: &Map<String, Value>) -> Result<(), Failure> {
    let allowed = ["path", "bytes_base64", "sha256"];
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(format!("input contains unknown field: {field}")));
    }

    Ok(())
}

fn inspect_bytes(source: MachoBytes) -> Result<Value, Failure> {
    let image = macho::read(&source.bytes)
        .map_err(|error| malformed(error.to_string()))?;
    let mut result = serde_json::to_value(image)
        .map_err(|error| serialization(error.to_string()))?;
    let result_object = result
        .as_object_mut()
        .ok_or_else(|| serialization("Mach-O image did not serialize as an object".into()))?;

    result_object.insert("artifact".into(), source.artifact_identity());
    result_object.insert(
        "limitations".into(),
        Value::Array(
            LIMITATIONS
                .iter()
                .map(|limitation| Value::String((*limitation).to_owned()))
                .collect(),
        ),
    );
    result_object.insert(
        "provenance".into(),
        json!({"source": "caller-supplied-macho-bytes", "execution": "none"}),
    );

    Ok(result)
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity(error.to_string()))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity(error.to_string()))?;
    if !record.operation_matches(OPERATION) {
        return Err(integrity("captured Evidence operation does not match inspect_macho".into()));
    }

    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(error.to_string()))?;
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| integrity(error.to_string()))?;

    Ok(json!({
        "evidence_id": record.evidence_id(),
        "subject": subject,
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

struct MachoBytes {
    path: String,
    bytes: Vec<u8>,
}

impl MachoBytes {
    fn from_input(object: &Map<String, Value>) -> Result<Self, Failure> {
        let path = required_text(object, "path")?.to_owned();
        if path.contains('\0') {
            return Err(invalid("path must not contain NUL".into()));
        }
        let encoded = required_text(object, "bytes_base64")?;
        let maximum_encoded_length = image::MAX_INPUT_BYTES
            .saturating_add(2)
            .saturating_mul(4)
            .div_ceil(3);
        if encoded.len() > maximum_encoded_length {
            return Err(resource("Mach-O bytes exceed the input limit".into()));
        }

        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|error| invalid(format!("bytes_base64 is invalid: {error}")))?;
        if bytes.len() > image::MAX_INPUT_BYTES {
            return Err(resource("Mach-O bytes exceed the input limit".into()));
        }

        let computed = digest(&bytes);
        if let Some(declared) = object.get("sha256") {
            let declared = declared
                .as_str()
                .filter(|value| is_sha256(value))
                .ok_or_else(|| invalid("sha256 must be a 64-character hexadecimal digest".into()))?;
            if !declared.eq_ignore_ascii_case(&computed) {
                return Err(invalid("sha256 does not match bytes_base64".into()));
            }
        }

        Ok(Self { path, bytes })
    }

    fn artifact_identity(&self) -> Value {
        json!({"path": self.path, "sha256": digest(&self.bytes), "bytes": self.bytes.len()})
    }
}

fn input_object(input: &Value) -> Result<&Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid("input must be an object".into()))
}

fn required_text<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(format!("{field} is required")))
}

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn invalid(reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason,
        false,
        "Provide one bounded Mach-O byte snapshot or authenticated Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn malformed(reason: String) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_format",
        reason,
        false,
        "Provide a valid caller-supplied Mach-O byte snapshot.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn resource(reason: String) -> Failure {
    Failure::new(
        "resource_limit",
        "resource_limit",
        reason,
        false,
        "Provide a smaller Mach-O byte snapshot or use retained Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn integrity(reason: String) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason,
        false,
        "Provide an authenticated, intact inspect_macho Evidence record.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn serialization(reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "analysis_output",
        reason,
        false,
        "Review the serialized Mach-O projection.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
