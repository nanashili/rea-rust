//! Offline Android package handlers for an isolated runtime adapter.
//!
//! The caller owns acquisition.  This module accepts package bytes or an
//! already authenticated Evidence record and never opens a path, talks to
//! ADB, installs an APK, or launches application code.  The normal runtime
//! dispatcher can adopt this module without changing the application-owned
//! Android parsers.

use rea_application::android;
use rea_application::android::package as android_package_application;
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use rea_rust_analysis::{android_package, managed};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATIONS: [&str; 6] = [
    "inspect_android_package",
    "search_android_classes",
    "inspect_android_class",
    "inspect_android_method",
    "trace_android_references",
    "project_android_application_graph",
];

/// Return one retained Android class projection without reopening its APK.
///
/// The caller must provide Evidence produced by `inspect_android_class`.
/// Returning the complete source record alongside the normalized projection
/// keeps artifact identity, offsets, limitations, and unknowns available to
/// downstream adapters without reinterpreting provider output.
pub fn inspect_android_class(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("evidence")
        .ok_or_else(|| invalid("inspect_android_class", "evidence is required"))?;
    let (record, normalized) = captured_record(
        "inspect_android_class",
        evidence,
        android::analysis::CLASS_OPERATION,
    )?;
    Ok(json!({
        "evidence": evidence,
        "evidence_id": record.evidence_id(),
        "result": normalized,
        "provenance": {
            "source": "authenticated-captured-evidence",
            "execution": "unknown",
            "producer_operation": android::analysis::CLASS_OPERATION,
        },
    }))
}

/// Dispatch one offline Android workflow from explicit bytes or Evidence.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation == android::application_graph::OPERATION {
        return project_graph(&input);
    }
    if !OPERATIONS.contains(&operation) {
        return Err(invalid(
            operation,
            format!("Unsupported Android operation: {operation}"),
        ));
    }

    let detail = delivery_detail(operation, &input)?;

    if operation == android::analysis::CLASS_OPERATION {
        if input.get("evidence").is_some() {
            return inspect_android_class(&input);
        }
    }
    if let Some(evidence) = input.get("evidence") {
        return project_captured_evidence(operation, evidence, detail);
    }

    let source = PackageBytes::from_input(&input, operation)?;
    let report = read_package(&source, operation)?;
    let artifact = source.artifact_identity();

    dispatch_package_operation(operation, &input, &report, artifact, detail)
}

fn read_package(
    source: &PackageBytes,
    operation: &str,
) -> Result<android_package::Report, Failure> {
    android_package::read(&source.bytes).map_err(|error| malformed(operation, error.to_string()))
}

fn dispatch_package_operation(
    operation: &str,
    input: &Value,
    report: &android_package::Report,
    artifact: Value,
    detail: DeliveryDetail,
) -> Result<Value, Failure> {
    match operation {
        "inspect_android_package" => {
            if detail == DeliveryDetail::Summary {
                return Err(invalid(
                    operation,
                    "summary delivery requires authenticated inspect_android_package Evidence",
                ));
            }
            let mut result = serde_json::to_value(report)
                .map_err(|error| malformed(operation, error.to_string()))?;
            let result_object = result
                .as_object_mut()
                .ok_or_else(|| malformed(operation, "package report is not an object".into()))?;
            result_object.insert("artifact".into(), artifact);

            Ok(json!({
                "result": result,
                "provenance": {"source": "caller-supplied-package-bytes", "execution": "none"},
            }))
        }
        "search_android_classes" => {
            let query = required_text(&input, "query", operation)?;
            let projection = android::analysis::search_android_classes(report, query);
            Ok(package_projection(artifact, projection))
        }
        "inspect_android_class" => {
            let class_name = required_text(&input, "class_name", operation)?;
            let projection = android::analysis::inspect_android_class(&report, class_name)?;
            Ok(package_projection(artifact, projection))
        }
        "inspect_android_method" => {
            let class_name = required_text(&input, "class_name", operation)?;
            let method_name = required_text(&input, "method_name", operation)?;
            let overload_index = optional_index(&input, "overload_index", operation)?;
            let projection = android::analysis::inspect_android_method(
                report,
                class_name,
                method_name,
                overload_index,
            )?;
            Ok(package_projection(artifact, projection))
        }
        "trace_android_references" => {
            let class_name = required_text(&input, "class_name", operation)?;
            let method_name = optional_text(&input, "method_name", operation)?;
            let overload_index = optional_index(&input, "overload_index", operation)?;
            if method_name.is_none() && overload_index.is_some() {
                return Err(invalid(operation, "overload_index requires method_name"));
            }
            let projection = android::analysis::trace_android_references(
                report,
                class_name,
                method_name,
                overload_index,
            )?;
            Ok(package_projection(artifact, projection))
        }
        _ => unreachable!("operation set checked above"),
    }
}

fn package_projection<T: serde::Serialize>(artifact: Value, projection: T) -> Value {
    json!({
        "artifact": artifact,
        "projection": projection,
        "provenance": {"source": "caller-supplied-package-bytes", "execution": "none"},
    })
}

/// Project authenticated inventory Evidence without decoding or executing it.
fn project_graph(input: &Value) -> Result<Value, Failure> {
    android::application_graph::project_evidence(input)
        .map(|raw| serde_json::from_str(raw.get()).expect("Evidence is valid JSON"))
        .map_err(|error| invalid(android::application_graph::OPERATION, error.to_string()))
}

fn project_captured_evidence(
    operation: &str,
    value: &Value,
    detail: DeliveryDetail,
) -> Result<Value, Failure> {
    if operation == android_package_application::OPERATION && detail == DeliveryDetail::Summary {
        let projected = android::package_view::project(value, &json!({"kind": "summary"}))
            .map_err(|error| invalid(operation, error.to_string()))?;
        return serde_json::from_str(projected.get())
            .map_err(|error| integrity(operation, error.to_string()));
    }
    let (record, normalized) = captured_record(operation, value, operation)?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "subject": serde_json::from_str::<Value>(record.subject().get()).unwrap_or(Value::Null),
        "result": normalized,
        "provenance": {"source": "authenticated-captured-evidence", "execution": "unknown"},
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DeliveryDetail {
    Complete,
    Summary,
}

fn delivery_detail(operation: &str, input: &Value) -> Result<DeliveryDetail, Failure> {
    let Some(detail) = input.get("detail") else {
        return Ok(DeliveryDetail::Complete);
    };

    if operation != android_package_application::OPERATION {
        return Err(invalid(
            operation,
            "detail is only supported for inspect_android_package",
        ));
    }

    match detail.as_str() {
        Some("complete") => Ok(DeliveryDetail::Complete),
        Some("summary") => Ok(DeliveryDetail::Summary),
        Some(_) => Err(invalid(operation, "detail must be complete or summary")),
        None => Err(invalid(operation, "detail must be a string")),
    }
}

fn captured_record(
    operation: &str,
    value: &Value,
    expected_operation: &str,
) -> Result<(EvidenceRecord, Value), Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(operation, error.to_string()))?;
    let record =
        EvidenceRecord::parse(&raw).map_err(|error| integrity(operation, error.to_string()))?;
    if !record.operation_matches(expected_operation) {
        return Err(integrity(
            operation,
            format!("captured Evidence operation does not match {expected_operation}"),
        ));
    }
    let normalized = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| integrity(operation, error.to_string()))?;
    Ok((record, normalized))
}

struct PackageBytes {
    path: String,
    bytes: Vec<u8>,
}

impl PackageBytes {
    fn artifact_identity(&self) -> Value {
        json!({
            "path": self.path,
            "sha256": managed::digest(&self.bytes),
            "bytes": self.bytes.len(),
        })
    }

    fn from_input(input: &Value, operation: &str) -> Result<Self, Failure> {
        let object = input
            .as_object()
            .ok_or_else(|| invalid(operation, "input must be an object"))?;
        let path = required_text(input, "path", operation)?.to_owned();
        let bytes = match (object.get("bytes_base64"), object.get("bytes")) {
            (Some(Value::String(encoded)), None) => decode_base64(encoded)
                .map_err(|reason| invalid(operation, format!("bytes_base64 {reason}")))?,
            (None, Some(Value::Array(values))) => values
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .filter(|byte| *byte <= 255)
                        .map(|byte| byte as u8)
                })
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                    invalid(operation, "bytes must contain integers from 0 through 255")
                })?,
            (Some(_), Some(_)) => {
                return Err(invalid(operation, "supply only one byte representation"));
            }
            (None, None) => return Err(invalid(operation, "supply bytes_base64 or bytes")),
            _ => return Err(invalid(operation, "bytes_base64 must be a string")),
        };
        if bytes.len() > android_package::MAX_PACKAGE_BYTES {
            return Err(invalid(
                operation,
                "package bytes exceed the Android package limit",
            ));
        }
        Ok(Self { path, bytes })
    }
}

fn required_text<'a>(input: &'a Value, field: &str, operation: &str) -> Result<&'a str, Failure> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(operation, format!("{field} is required")))
}

fn optional_text<'a>(
    input: &'a Value,
    field: &str,
    operation: &str,
) -> Result<Option<&'a str>, Failure> {
    match input.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value)),
        _ => Err(invalid(
            operation,
            format!("{field} must be a non-empty string or null"),
        )),
    }
}

fn optional_index(input: &Value, field: &str, operation: &str) -> Result<Option<usize>, Failure> {
    match input.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .map(Some)
            .ok_or_else(|| invalid(operation, format!("{field} must be a non-negative integer"))),
        _ => Err(invalid(
            operation,
            format!("{field} must be a non-negative integer"),
        )),
    }
}

fn decode_base64(encoded: &str) -> Result<Vec<u8>, &'static str> {
    if encoded.len() % 4 != 0 {
        return Err("has incomplete padding");
    }
    let mut output = Vec::with_capacity(encoded.len() * 3 / 4);
    let quartets = encoded.as_bytes().chunks_exact(4);
    let quartet_count = quartets.len();
    for (position, quartet) in quartets.enumerate() {
        let padding = usize::from(quartet[3] == b'=') + usize::from(quartet[2] == b'=');
        let values = [
            base64_value(quartet[0])?,
            base64_value(quartet[1])?,
            if quartet[2] == b'=' {
                0
            } else {
                base64_value(quartet[2])?
            },
            if quartet[3] == b'=' {
                0
            } else {
                base64_value(quartet[3])?
            },
        ];
        if quartet[0] == b'=' || quartet[1] == b'=' || (quartet[2] == b'=' && quartet[3] != b'=') {
            return Err("has invalid padding");
        }
        if padding > 0 && position + 1 != quartet_count {
            return Err("has padding before the final quartet");
        }
        output.push((values[0] << 2) | (values[1] >> 4));
        if padding < 2 {
            output.push((values[1] << 4) | (values[2] >> 2));
        }
        if padding == 0 {
            output.push((values[2] << 6) | values[3]);
        }
    }
    Ok(output)
}

fn base64_value(byte: u8) -> Result<u8, &'static str> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err("is not valid standard base64"),
    }
}

fn invalid(operation: &str, reason: impl Into<String>) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide caller-supplied Android package bytes or authenticated Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

fn integrity(operation: &str, reason: impl Into<String>) -> Failure {
    Failure::new(
        "integrity_failure",
        "integrity_failure",
        reason.into(),
        false,
        "Provide an authenticated, intact Evidence record.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}

fn malformed(operation: &str, reason: String) -> Failure {
    Failure::new(
        "analysis_input",
        "invalid_format",
        reason,
        false,
        "Provide valid caller-supplied APK or Android package bytes.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
