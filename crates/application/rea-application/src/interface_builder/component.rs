//! Operation-specific adapter for `decode_interface_builder`.
//!
//! This adapter accepts bytes supplied by the caller or an already retained,
//! authenticated Evidence value. It delegates plist, keyed-archive, and
//! NIBArchive decoding to their owning producers and only assembles the
//! operation result. It never opens paths, extracts files, or contacts targets.

use crate::{
    interface_builder, interface_builder::keyed_archive as interface_builder_keyed_archive,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rea_core::evidence::record::EvidenceRecord;
use rea_core::failure::{Detail, Failure};
use rea_rust_analysis::{nib, plist};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const OPERATION: &str = "decode_interface_builder";
pub const MAX_INPUT_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_DOCUMENTS: usize = 64;
pub const MAX_OBJECTS: usize = 20_000;
pub const MAX_CONNECTIONS: usize = 40_000;
pub const MAX_OUTPUT_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_documents: usize,
    pub max_objects: usize,
    pub max_connections: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_documents: MAX_DOCUMENTS,
            max_objects: MAX_OBJECTS,
            max_connections: MAX_CONNECTIONS,
        }
    }
}

impl Limits {
    pub fn bounded(
        max_documents: Option<usize>,
        max_objects: Option<usize>,
        max_connections: Option<usize>,
    ) -> Result<Self, Failure> {
        let limits = Self {
            max_documents: max_documents.unwrap_or(MAX_DOCUMENTS),
            max_objects: max_objects.unwrap_or(MAX_OBJECTS),
            max_connections: max_connections.unwrap_or(MAX_CONNECTIONS),
        };
        if !(1..=MAX_DOCUMENTS).contains(&limits.max_documents)
            || !(1..=MAX_OBJECTS).contains(&limits.max_objects)
            || !(1..=MAX_CONNECTIONS).contains(&limits.max_connections)
        {
            return Err(invalid(
                "requested Interface Builder limits are outside the supported bounds",
            ));
        }
        Ok(limits)
    }
}

/// Decode one caller-supplied archive. The path is a source label only.
pub fn decode_bytes(path: &str, bytes: &[u8], limits: Limits) -> Result<Value, Failure> {
    if path.is_empty() || path.contains('\0') {
        return Err(invalid("archive path must be non-empty"));
    }
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(resource("archive bytes exceed the 32 MiB input limit"));
    }
    let digest = sha256(bytes);
    let document = if bytes.starts_with(b"NIBArchive") {
        decode_nib(path, bytes, &digest, &limits)?
    } else {
        decode_plist(path, bytes, &digest, &limits)?
    };
    admit(&document)
}

/// Project a previously retained Evidence result without reopening or
/// decoding its source. The digest in `subject.sha256` authenticates any
/// retained raw archive bytes when present.
pub fn decode_evidence(evidence: &Value, limits: Limits) -> Result<Value, Failure> {
    let raw_evidence = serde_json::value::to_raw_value(evidence)
        .map_err(|error| invalid(format!("authenticated Evidence is not valid JSON: {error}")))?;
    let record = EvidenceRecord::parse(&raw_evidence)
        .map_err(|error| invalid(format!("authenticated Evidence is invalid: {error}")))?;
    if !record.operation_matches(OPERATION) {
        return Err(invalid(
            "Evidence operation must be decode_interface_builder",
        ));
    }
    let object: Value = serde_json::from_str(record.raw().get())
        .map_err(|error| invalid(format!("authenticated Evidence JSON is invalid: {error}")))?;
    let object = object
        .as_object()
        .ok_or_else(|| invalid("authenticated Evidence must be an object"))?;
    let subject = object
        .get("subject")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("Evidence subject is missing"))?;
    let expected = subject
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|digest| digest.get("sha256"))
        .or_else(|| subject.get("sha256"))
        .and_then(Value::as_str)
        .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or_else(|| invalid("Evidence subject must contain a SHA-256 digest"))?;
    if let Some(raw) = object.get("raw_result") {
        if let Some(encoded) = raw.get("archive_bytes_base64").and_then(Value::as_str) {
            let bytes = BASE64
                .decode(encoded)
                .map_err(|_| invalid("retained archive bytes are malformed"))?;
            if !sha256(&bytes).eq_ignore_ascii_case(expected) {
                return Err(invalid(
                    "retained archive bytes do not match the Evidence digest",
                ));
            }
            let path = subject
                .get("path")
                .and_then(Value::as_str)
                .or_else(|| subject.get("local_path").and_then(Value::as_str))
                .unwrap_or("retained-archive");
            return decode_bytes(path, &bytes, limits);
        }
    }
    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(format!("retained normalized result is invalid: {error}")))?;
    let mut result = normalized.clone();
    let result_object = result
        .as_object_mut()
        .ok_or_else(|| invalid("retained normalized result must be an object"))?;
    result_object.insert(
        "source_kind".into(),
        Value::String("retained-evidence".into()),
    );
    result_object.insert("source_sha256".into(), Value::String(expected.to_owned()));
    admit(&result)
}

/// Boundary adapter. Exactly one of `bytes_base64` or `evidence` is accepted.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    validate_input_fields(object)?;

    let limits = Limits::bounded(
        optional_u64(object, "max_documents")?,
        optional_u64(object, "max_objects")?,
        optional_u64(object, "max_connections")?,
    )?;
    match (object.get("bytes_base64"), object.get("evidence")) {
        (Some(_), Some(_)) => Err(invalid("supply bytes_base64 or evidence, not both")),
        (Some(encoded), None) => {
            let encoded = encoded
                .as_str()
                .ok_or_else(|| invalid("bytes_base64 must be a string"))?;
            let bytes = BASE64
                .decode(encoded)
                .map_err(|_| invalid("bytes_base64 is malformed"))?;
            let path = object
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("caller-supplied-archive");
            decode_bytes(path, &bytes, limits)
        }
        (None, Some(evidence)) => decode_evidence(evidence, limits),
        (None, None) => Err(invalid("supply bytes_base64 or authenticated evidence")),
    }
}

fn validate_input_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED: &[&str] = &[
        "path",
        "bytes_base64",
        "evidence",
        "max_documents",
        "max_objects",
        "max_connections",
    ];
    if let Some(field) = object
        .keys()
        .find(|field| !ALLOWED.contains(&field.as_str()))
    {
        return Err(invalid(format!(
            "unexpected Interface Builder field: {field}"
        )));
    }

    let has_evidence = object.contains_key("evidence");
    let has_bytes = object.contains_key("path") || object.contains_key("bytes_base64");
    if has_evidence && has_bytes {
        return Err(invalid(
            "Interface Builder input cannot combine Evidence with byte fields",
        ));
    }
    if !has_evidence && (!object.contains_key("path") || !object.contains_key("bytes_base64")) {
        return Err(invalid("Byte input requires path and bytes_base64"));
    }
    if let Some(path) = object.get("path") {
        let path = path
            .as_str()
            .ok_or_else(|| invalid("path must be a string"))?;
        if path.is_empty() || path.contains('\0') {
            return Err(invalid("path must be non-empty and NUL-free"));
        }
    }
    Ok(())
}

fn decode_plist(path: &str, bytes: &[u8], digest: &str, limits: &Limits) -> Result<Value, Failure> {
    let decoded = plist::read_with_provenance(bytes, path.to_owned())
        .map_err(|error| provider(error.to_string()))?;
    let is_keyed_archive = decoded
        .report
        .value
        .get("$archiver")
        .and_then(Value::as_str)
        == Some("NSKeyedArchiver");
    let projection_limits = interface_builder::ProjectionLimits {
        max_objects: limits.max_objects,
        max_connections: limits.max_connections,
        max_hierarchy_nodes: limits.max_objects,
    };
    let keyed = if is_keyed_archive {
        interface_builder_keyed_archive::project(
            path.to_owned(),
            digest,
            &decoded.report.value,
            &decoded.binary_uid_paths,
            &projection_limits,
        )
    } else {
        None
    };
    let keyed_unprojected = is_keyed_archive && keyed.is_none();
    let projection = keyed.unwrap_or_else(|| {
        interface_builder::project_value(
            path.to_owned(),
            digest,
            &decoded.report.value,
            projection_limits,
        )
    });
    let mut limitations = decoded.report.limitations.clone();
    limitations.extend(projection.limitations.clone());
    if keyed_unprojected {
        limitations.push(
            "The NSKeyedArchiver object table or class graph could not be projected; decoded plist data is retained.".into(),
        );
    }
    Ok(json!({
        "relative_path": path,
        "archive_sha256": digest,
        "archive_format": format_plist(&decoded.report.format),
        "decoded": serde_json::to_value(&decoded.report)
            .map_err(|_| provider("unable to serialize decoded plist"))?,
        "projection": projection,
        "limitations": limitations,
        "provenance": {"binary_uid_paths": decoded.binary_uid_paths.len(), "source_path": path},
    }))
}

fn decode_nib(path: &str, bytes: &[u8], digest: &str, limits: &Limits) -> Result<Value, Failure> {
    let archive = nib::decode_nib_archive_with_budget(bytes, nib::DecodeBudget::default())
        .map_err(|error| provider(error.to_string()))?;
    let omitted_objects = (archive.object_count as usize).saturating_sub(limits.max_objects);
    let omitted_connections =
        (archive.connection_object_count as usize).saturating_sub(limits.max_connections);
    let partial = omitted_objects > 0 || omitted_connections > 0;
    let mut limitations = vec![
        "NIBArchive object provenance is retained; hierarchy projection requires the bundle producer's NIB-specific graph adapter.".to_owned(),
    ];
    if omitted_objects > 0 {
        limitations.push(format!(
            "{omitted_objects} NIBArchive object(s) exceed the selected projection limit and remain outside bounded projection coverage."
        ));
    }
    if omitted_connections > 0 {
        limitations.push(format!(
            "{omitted_connections} NIBArchive connection object(s) exceed the selected projection limit and remain outside bounded projection coverage."
        ));
    }
    let decoded = serde_json::to_value(&archive)
        .map_err(|_| provider("unable to serialize decoded NIBArchive"))?;
    Ok(json!({
        "relative_path": path,
        "archive_sha256": digest,
        "archive_format": "nib_archive",
        "decoded": decoded,
        "projection": Value::Null,
        "limitations": limitations,
        "coverage": {
            "objects_examined": archive.object_count,
            "connections_examined": archive.connection_object_count,
            "objects_omitted": omitted_objects,
            "connections_omitted": omitted_connections,
            "partial": partial,
            "max_objects": limits.max_objects,
            "max_connections": limits.max_connections
        },
    }))
}

fn optional_u64(object: &Map<String, Value>, field: &str) -> Result<Option<usize>, Failure> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .map(|value| value as usize)
                .ok_or_else(|| invalid(format!("{field} must be a non-negative integer")))
        })
        .transpose()
}

fn format_plist(format: &plist::Format) -> &'static str {
    match format {
        plist::Format::Binary => "binary_plist",
        plist::Format::Xml => "xml_plist",
        plist::Format::OpenStep => "openstep_plist",
    }
}

fn sha256(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);

    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn admit(value: &Value) -> Result<Value, Failure> {
    let serialized = serde_json::to_vec(value)
        .map_err(|_| provider("unable to serialize Interface Builder result"))?;
    if serialized.len() > MAX_OUTPUT_BYTES {
        return Err(resource(
            "Interface Builder result exceeds the output limit",
        ));
    }

    Ok(value.clone())
}

fn failure(
    code: &'static str,
    category: &'static str,
    message: impl Into<String>,
    action: &'static str,
) -> Failure {
    Failure::new(
        code,
        category,
        message.into(),
        true,
        action.into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

fn invalid(message: impl Into<String>) -> Failure {
    failure(
        "invalid_request",
        "invalid_input",
        message,
        "Correct the archive input and retry.",
    )
}

fn provider(message: impl Into<String>) -> Failure {
    failure(
        "provider_error",
        "decoder",
        message,
        "Supply a supported Interface Builder archive and retry.",
    )
}

fn resource(message: &str) -> Failure {
    failure(
        "resource_constraint",
        "memory",
        message,
        "Reduce the archive or selected bounds and retry.",
    )
}
