//! Offline dispatch for Apple application workflows.
//!
//! The runtime adapter accepts retained Evidence, explicit artifact bytes, or
//! already-decoded catalog facts.  It never opens a path, invokes Apple tools,
//! contacts a provider, or writes a temporary artifact.  Acquisition and
//! Evidence retention remain owned by the caller and the application crate.

use base64::Engine;
use rea_application::{
    apple,
    interface_builder,
};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_rust_analysis::{nib, plist};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Apple workflows supported by this offline adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppleOperation {
    ProjectApplicationGraph,
    InspectAssetCatalog,
    DecodeInterfaceBuilder,
    InspectKeyedArchive,
    InspectNibArchive,
}

impl AppleOperation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "project_apple_application_graph" => Ok(Self::ProjectApplicationGraph),
            "inspect_asset_catalog" => Ok(Self::InspectAssetCatalog),
            "decode_interface_builder" => Ok(Self::DecodeInterfaceBuilder),
            "inspect_keyed_archive" => Ok(Self::InspectKeyedArchive),
            "inspect_nib_archive" => Ok(Self::InspectNibArchive),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::ProjectApplicationGraph => "project_apple_application_graph",
            Self::InspectAssetCatalog => "inspect_asset_catalog",
            Self::DecodeInterfaceBuilder => "decode_interface_builder",
            Self::InspectKeyedArchive => "inspect_keyed_archive",
            Self::InspectNibArchive => "inspect_nib_archive",
        }
    }
}

/// Dispatch one Apple workflow without acquiring or reopening an artifact.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = AppleOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

pub fn dispatch_typed(operation: AppleOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        AppleOperation::ProjectApplicationGraph => {
            apple::application_graph::project_evidence(input)
                .and_then(|evidence| {
                    serde_json::from_str(evidence.get()).map_err(|error| {
                        invalid(
                            "project_apple_application_graph",
                            &format!("producer returned invalid Evidence JSON: {error}"),
                        )
                    })
                })
        }
        AppleOperation::InspectAssetCatalog => inspect_asset_catalog(input),
        AppleOperation::DecodeInterfaceBuilder => decode_interface_builder(input),
        AppleOperation::InspectKeyedArchive => inspect_keyed_archive(input),
        AppleOperation::InspectNibArchive => inspect_nib_archive(input),
    }
}

fn inspect_asset_catalog(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, "inspect_asset_catalog")?;

    if let Some(evidence) = object.get("evidence") {
        if object.len() != 1 || !evidence.is_object() {
            return Err(invalid(
                "inspect_asset_catalog",
                "Evidence input must contain only a non-empty evidence object",
            ));
        }
        return project_asset_catalog_evidence(evidence);
    }

    validate_asset_catalog_byte_input(object)?;
    let target_sha256 = required_sha256(object, "target_sha256", "inspect_asset_catalog")?;
    let catalog = decode_catalog(object)?;
    let offset = bounded_integer(object, "offset", 0, "inspect_asset_catalog")?;
    let limit = bounded_integer(object, "limit", 1_000, "inspect_asset_catalog")?;
    let references = object
        .get("resource_references")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let resource_references = serde_json::from_value(references).map_err(|error| {
        invalid(
            "inspect_asset_catalog",
            &format!("resource_references is invalid: {error}"),
        )
    })?;
    let page = apple::asset_catalog::project_asset_catalog_page(
        apple::asset_catalog::AssetCatalogPageInput {
            target_sha256,
            catalogs: vec![catalog],
            offset,
            limit,
            resource_references,
        },
    )
    .map_err(|error| invalid("inspect_asset_catalog", &error.to_string()))?;
    let mut output = serde_json::to_value(page)
        .map_err(|error| invalid("inspect_asset_catalog", &error.to_string()))?;
    let output_object = output.as_object_mut().ok_or_else(|| {
        invalid(
            "inspect_asset_catalog",
            "asset catalog projection did not serialize as an object",
        )
    })?;
    output_object.insert(
        "provenance".into(),
        json!({"source": "caller-supplied-asset-catalog-bytes", "execution": "none"}),
    );
    Ok(output)
}

fn decode_catalog(
    object: &Map<String, Value>,
) -> Result<apple::asset_catalog::AssetCatalog, Failure> {
    let path = required_text(object, "catalog_path", "inspect_asset_catalog")?;
    let encoded = required_text(object, "bytes_base64", "inspect_asset_catalog")?;
    if encoded.len() > maximum_catalog_base64_length() {
        return Err(resource_limit(
            "inspect_asset_catalog",
            "asset catalog bytes exceed the 64 MiB input limit",
        ));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            invalid(
                "inspect_asset_catalog",
                &format!("bytes_base64 is invalid: {error}"),
            )
        })?;
    if bytes.len() > rea_application::apple::asset_catalog_workflow::MAX_CATALOG_BYTES {
        return Err(resource_limit(
            "inspect_asset_catalog",
            "asset catalog bytes exceed the 64 MiB input limit",
        ));
    }
    let digest = hex_digest(&bytes);

    if let Some(declared) = object.get("catalog_sha256") {
        let declared = declared
            .as_str()
            .filter(|value| is_sha256(value))
            .ok_or_else(|| {
                invalid(
                    "inspect_asset_catalog",
                    "catalog_sha256 must be a 64-character hexadecimal digest",
                )
            })?;
        if !declared.eq_ignore_ascii_case(&digest) {
            return Err(invalid(
                "inspect_asset_catalog",
                "catalog_sha256 does not match bytes_base64",
            ));
        }
    }

    let report: Value = serde_json::from_slice(&bytes).map_err(|error| {
        invalid(
            "inspect_asset_catalog",
            &format!("asset catalog report is not valid JSON: {error}"),
        )
    })?;
    let records = apple::asset_catalog::parse_asset_catalog_records(&report)
        .map_err(|error| invalid("inspect_asset_catalog", &error.to_string()))?;

    Ok(apple::asset_catalog::AssetCatalog {
        path,
        sha256: digest,
        records,
    })
}

fn validate_asset_catalog_byte_input(object: &Map<String, Value>) -> Result<(), Failure> {
    let allowed = [
        "target_sha256",
        "catalog_path",
        "bytes_base64",
        "catalog_sha256",
        "resource_references",
        "offset",
        "limit",
    ];
    if let Some(field) = object.keys().find(|field| !allowed.contains(&field.as_str())) {
        return Err(invalid(
            "inspect_asset_catalog",
            &format!("unexpected field: {field}"),
        ));
    }
    if !object.contains_key("catalog_path") || !object.contains_key("bytes_base64") {
        return Err(invalid(
            "inspect_asset_catalog",
            "byte input requires catalog_path and bytes_base64",
        ));
    }
    Ok(())
}

fn project_asset_catalog_evidence(value: &Value) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| integrity("inspect_asset_catalog", &error.to_string()))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| integrity("inspect_asset_catalog", &error.to_string()))?;
    if !record.operation_matches("inspect_asset_catalog") {
        return Err(integrity(
            "inspect_asset_catalog",
            "captured Evidence operation does not match inspect_asset_catalog",
        ));
    }
    let result: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity("inspect_asset_catalog", &error.to_string()))?;

    // Evidence is an authenticated transport envelope, but its normalized
    // payload still belongs to this operation's contract.  Parse it through
    // the application-owned result type so malformed or cross-operation
    // payloads cannot be projected as a successful catalog inspection.  The
    // original JSON value is retained below so any producer metadata remains
    // available to the caller.
    serde_json::from_value::<apple::asset_catalog::AssetCatalogPage>(result.clone())
        .map_err(|error| {
            integrity(
                "inspect_asset_catalog",
                &format!("captured catalog result is invalid: {error}"),
            )
        })?;

    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| integrity("inspect_asset_catalog", &error.to_string()))?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "subject": subject,
        "result": result,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

fn decode_interface_builder(input: &Value) -> Result<Value, Failure> {
    interface_builder::component::inspect(input)
}

fn inspect_keyed_archive(input: &Value) -> Result<Value, Failure> {
    let (path, bytes, sha256) = artifact_bytes(input, "inspect_keyed_archive")?;
    let decoded = plist::read_keyed_archive_with_provenance(&bytes, path.clone())
        .map_err(|error| invalid("inspect_keyed_archive", &error.to_string()))?;
    Ok(json!({
        "archive_path": path,
        "archive_sha256": sha256,
        "archive_format": decoded.report.format,
        "value": decoded.report.value,
        "typed_scalar_paths": decoded.typed_scalar_paths,
        "binary_uid_paths": decoded.binary_uid_paths,
        "limitations": decoded.report.limitations,
    }))
}

fn inspect_nib_archive(input: &Value) -> Result<Value, Failure> {
    let (path, bytes, sha256) = artifact_bytes(input, "inspect_nib_archive")?;
    let report = nib::decode_nib_archive(&bytes)
        .map_err(|error| invalid("inspect_nib_archive", &error.to_string()))?;
    Ok(json!({
        "archive_path": path,
        "archive_sha256": sha256,
        "report": report,
        "limitations": ["The adapter decodes serialized archive values and never instantiates archived classes."],
    }))
}

fn artifact_bytes(input: &Value, operation: &str) -> Result<(String, Vec<u8>, String), Failure> {
    let object = input_object(input, operation)?;
    let path = required_text(object, "path", operation)?;
    let encoded = required_text(object, "bytes_base64", operation)?;
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .map_err(|error| invalid(operation, &format!("bytes_base64 is invalid: {error}")))?;
    let computed = hex_digest(&bytes);
    if let Some(declared) = object.get("sha256").and_then(Value::as_str)
        && !declared.eq_ignore_ascii_case(&computed)
    {
        return Err(invalid(operation, "sha256 does not match bytes_base64"));
    }
    Ok((path, bytes, computed))
}

fn input_object<'a>(input: &'a Value, operation: &str) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid(operation, "input must be an object"))
}

fn required_text(
    object: &Map<String, Value>,
    field: &str,
    operation: &str,
) -> Result<String, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(operation, &format!("{field} is required")))
}

fn required_sha256(
    object: &Map<String, Value>,
    field: &str,
    operation: &str,
) -> Result<String, Failure> {
    let value = required_text(object, field, operation)?;
    if !is_lowercase_sha256(&value) {
        return Err(invalid(operation, &format!("{field} must be a SHA-256 digest")));
    }
    Ok(value)
}

fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn bounded_integer(
    object: &Map<String, Value>,
    field: &str,
    default: usize,
    operation: &str,
) -> Result<usize, Failure> {
    match object.get(field) {
        None => Ok(default),
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value > 0 || field == "offset")
            .ok_or_else(|| {
                invalid(
                    operation,
                    &format!("{field} must be a non-negative integer"),
                )
            }),
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn maximum_catalog_base64_length() -> usize {
    rea_application::apple::asset_catalog_workflow::MAX_CATALOG_BYTES
        .saturating_add(2)
        .saturating_mul(4)
        .div_ceil(3)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Apple operation is unknown: {name}"),
        false,
        "Select a supported offline Apple workflow.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide retained Evidence, decoded facts, or explicit artifact bytes.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}

fn integrity(operation: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide an authenticated, intact inspect_asset_catalog Evidence record.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}

fn resource_limit(operation: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "resource_limit",
        "resource_limit",
        reason.into(),
        false,
        "Provide a smaller asset catalog report or use retained Evidence.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(operation.into()))]),
    )
}
