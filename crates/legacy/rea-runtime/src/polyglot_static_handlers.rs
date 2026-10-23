//! Offline dispatch for captured polyglot and native static observations.
//!
//! This adapter owns no artifact, host, provider, or process authority.  It
//! accepts caller-supplied inventories and captured command output, then
//! delegates interpretation to the application-layer producers.

use rea_application::{
    apple::signature_inspection, native::architecture_inventory, native::objc_metadata,
    native::swift_demangle, native::swift_types,
};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolyglotStaticOperation {
    AnalyzeSwiftTypes,
    DemangleSwift,
    GetObjcClasses,
    GetObjcProtocols,
    IdentifyFlutterBuild,
    InspectDartAot,
    InspectSignature,
    ListArchitectures,
    InspectDesktopApplication,
}

impl PolyglotStaticOperation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "analyze_swift_types" => Ok(Self::AnalyzeSwiftTypes),
            "demangle_swift" => Ok(Self::DemangleSwift),
            "get_objc_classes" => Ok(Self::GetObjcClasses),
            "get_objc_protocols" => Ok(Self::GetObjcProtocols),
            "identify_flutter_build" => Ok(Self::IdentifyFlutterBuild),
            "offline_identify_flutter_build" => Ok(Self::IdentifyFlutterBuild),
            "inspect_dart_aot" => Ok(Self::InspectDartAot),
            "inspect_signature" => Ok(Self::InspectSignature),
            "list_architectures" => Ok(Self::ListArchitectures),
            "inspect_desktop_application" => Ok(Self::InspectDesktopApplication),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::AnalyzeSwiftTypes => "analyze_swift_types",
            Self::DemangleSwift => "demangle_swift",
            Self::GetObjcClasses => "get_objc_classes",
            Self::GetObjcProtocols => "get_objc_protocols",
            Self::IdentifyFlutterBuild => "identify_flutter_build",
            Self::InspectDartAot => "inspect_dart_aot",
            Self::InspectSignature => "inspect_signature",
            Self::ListArchitectures => "list_architectures",
            Self::InspectDesktopApplication => "inspect_desktop_application",
        }
    }
}

pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = PolyglotStaticOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

pub fn dispatch_typed(operation: PolyglotStaticOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        PolyglotStaticOperation::AnalyzeSwiftTypes => swift_types::project(input),
        PolyglotStaticOperation::DemangleSwift => demangle_swift(input),
        PolyglotStaticOperation::GetObjcClasses => objc_metadata::classes(input),
        PolyglotStaticOperation::GetObjcProtocols => objc_metadata::protocols(input),
        PolyglotStaticOperation::IdentifyFlutterBuild => identify_flutter_build(input),
        PolyglotStaticOperation::InspectDartAot => captured_result(input, operation),
        PolyglotStaticOperation::InspectSignature => {
            signature_inspection::inspect(input).and_then(|raw| parse_raw(raw, operation))
        }
        PolyglotStaticOperation::ListArchitectures => architecture_inventory::project(input),
        PolyglotStaticOperation::InspectDesktopApplication => Err(unsupported(
            operation,
            "desktop application inspection has no offline Rust producer",
        )),
    }
}

fn demangle_swift(input: &Value) -> Result<Value, Failure> {
    let object = object_input(input, "demangle_swift")?;
    validate_demangle_fields(object)?;
    let symbols = object
        .get("symbols")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("demangle_swift", "symbols is required and must be an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("demangle_swift", "symbols must contain strings"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let stdout = object
        .get("stdout")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("demangle_swift", "stdout is required"))?;
    let provenance = object
        .get("provenance")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let limitations = string_array(object, "limitations", "demangle_swift")?;
    let result = swift_demangle::result(&symbols, stdout, provenance, limitations)
        .map_err(|reason| invalid("demangle_swift", &reason))?;
    Ok(result)
}

fn validate_demangle_fields(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in object.keys() {
        if !matches!(
            field.as_str(),
            "symbols" | "stdout" | "provenance" | "limitations"
        ) {
            return Err(invalid("demangle_swift", "input contains an unknown field"));
        }
    }
    if object.get("symbols").and_then(Value::as_array).is_none() {
        return Err(invalid(
            "demangle_swift",
            "symbols is required and must be an array",
        ));
    }
    if object.get("stdout").and_then(Value::as_str).is_none() {
        return Err(invalid("demangle_swift", "stdout is required"));
    }
    if let Some(provenance) = object.get("provenance") {
        if !provenance.is_array() {
            return Err(invalid("demangle_swift", "provenance must be an array"));
        }
    }
    Ok(())
}

fn captured_result(input: &Value, operation: PolyglotStaticOperation) -> Result<Value, Failure> {
    let object = object_input(input, operation.name())?;
    let result = object
        .get("result")
        .or_else(|| object.get("normalized_result"))
        .ok_or_else(|| invalid(operation.name(), "result is required"))?;
    if !result.is_object() {
        return Err(invalid(operation.name(), "result must be an object"));
    }
    Ok(result.clone())
}

/// Project a captured Flutter identification while enforcing the fields that
/// make the offline contract useful to callers.  APK acquisition and parsing
/// belong to the provider that produced the capture; this adapter only owns
/// the operation boundary.
fn identify_flutter_build(input: &Value) -> Result<Value, Failure> {
    let object = object_input(input, PolyglotStaticOperation::IdentifyFlutterBuild.name())?;
    let result = if let Some(evidence) = object.get("evidence") {
        let raw = serde_json::value::to_raw_value(evidence)
            .map_err(|error| invalid("identify_flutter_build", &error.to_string()))?;
        let record = EvidenceRecord::parse(&raw)
            .map_err(|error| invalid("identify_flutter_build", &error.to_string()))?;
        if !record.operation_matches(PolyglotStaticOperation::IdentifyFlutterBuild.name()) {
            return Err(invalid(
                "identify_flutter_build",
                "Evidence operation does not match identify_flutter_build",
            ));
        }
        serde_json::from_str(record.normalized_result().get())
            .map_err(|error| invalid("identify_flutter_build", &error.to_string()))?
    } else {
        captured_result(input, PolyglotStaticOperation::IdentifyFlutterBuild)?
    };
    validate_flutter_result(&result)?;
    Ok(result)
}

fn validate_flutter_result(result: &Value) -> Result<(), Failure> {
    let object = result.as_object().ok_or_else(|| {
        invalid(
            PolyglotStaticOperation::IdentifyFlutterBuild.name(),
            "result must be an object",
        )
    })?;

    reject_unknown_fields(
        object,
        &["target", "flutter_detected", "abis", "coverage"],
        PolyglotStaticOperation::IdentifyFlutterBuild.name(),
    )?;

    for field in ["target", "flutter_detected", "abis", "coverage"] {
        if !object.contains_key(field) {
            return Err(invalid(
                PolyglotStaticOperation::IdentifyFlutterBuild.name(),
                &format!("result is missing required field: {field}"),
            ));
        }
    }

    if !object["target"].is_object() {
        return Err(invalid(
            PolyglotStaticOperation::IdentifyFlutterBuild.name(),
            "result.target must be an object",
        ));
    }

    validate_flutter_target(object["target"].as_object().expect("checked object"))?;
    if !object["flutter_detected"].is_boolean() {
        return Err(invalid(
            PolyglotStaticOperation::IdentifyFlutterBuild.name(),
            "result.flutter_detected must be a boolean",
        ));
    }
    if !object["abis"].is_array() {
        return Err(invalid(
            PolyglotStaticOperation::IdentifyFlutterBuild.name(),
            "result.abis must be an array",
        ));
    }

    for abi in object["abis"].as_array().expect("checked array") {
        validate_flutter_abi(abi)?;
    }
    if !matches!(object["coverage"].as_str(), Some("complete" | "partial")) {
        return Err(invalid(
            PolyglotStaticOperation::IdentifyFlutterBuild.name(),
            "result.coverage must be complete or partial",
        ));
    }

    Ok(())
}

fn validate_flutter_target(target: &Map<String, Value>) -> Result<(), Failure> {
    let operation = PolyglotStaticOperation::IdentifyFlutterBuild.name();
    reject_unknown_fields(target, &["path", "bytes", "sha256"], operation)?;

    if target.get("path").and_then(Value::as_str).is_none() {
        return Err(invalid(operation, "result.target.path must be a string"));
    }
    if !is_nonnegative_integer(target.get("bytes")) {
        return Err(invalid(
            operation,
            "result.target.bytes must be a non-negative integer",
        ));
    }
    if !is_sha256(target.get("sha256")) {
        return Err(invalid(
            operation,
            "result.target.sha256 must be a lowercase SHA-256 digest",
        ));
    }
    Ok(())
}

fn validate_flutter_abi(value: &Value) -> Result<(), Failure> {
    let operation = PolyglotStaticOperation::IdentifyFlutterBuild.name();
    let abi = value
        .as_object()
        .ok_or_else(|| invalid(operation, "result.abis entries must be objects"))?;
    reject_unknown_fields(abi, &["abi", "libapp", "libflutter"], operation)?;

    if abi
        .get("abi")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid(operation, "result.abis[].abi must be non-empty"));
    }

    validate_flutter_library(
        abi.get("libapp")
            .ok_or_else(|| invalid(operation, "result.abis[].libapp is required"))?,
        true,
    )?;
    validate_flutter_library(
        abi.get("libflutter")
            .ok_or_else(|| invalid(operation, "result.abis[].libflutter is required"))?,
        false,
    )?;
    Ok(())
}

fn validate_flutter_library(value: &Value, is_app: bool) -> Result<(), Failure> {
    let operation = PolyglotStaticOperation::IdentifyFlutterBuild.name();
    let library = value
        .as_object()
        .ok_or_else(|| invalid(operation, "result.abis library entries must be objects"))?;
    let fields: &[&str] = if is_app {
        &[
            "present",
            "bytes",
            "sha256",
            "elf_header_valid",
            "snapshot_hash_sources",
            "snapshot_hash_candidates",
            "snapshot_hash",
        ]
    } else {
        &[
            "present",
            "bytes",
            "sha256",
            "build_id",
            "build_id_candidates",
            "dart_version",
            "dart_version_capped",
            "toolchain_lines",
            "toolchain_capped",
        ]
    };
    reject_unknown_fields(library, fields, operation)?;

    for field in fields {
        if !library.contains_key(*field) {
            return Err(invalid(
                operation,
                &format!("result.abis library is missing required field: {field}"),
            ));
        }
    }
    if !library["present"].is_boolean() {
        return Err(invalid(
            operation,
            "result.abis[].present must be a boolean",
        ));
    }
    if !is_nullable_nonnegative_integer(library.get("bytes")) {
        return Err(invalid(
            operation,
            "result.abis[].bytes must be a non-negative integer or null",
        ));
    }
    if !is_nullable_sha256(library.get("sha256")) {
        return Err(invalid(
            operation,
            "result.abis[].sha256 must be a lowercase SHA-256 digest or null",
        ));
    }

    if is_app {
        if !library["elf_header_valid"].is_boolean() && !library["elf_header_valid"].is_null() {
            return Err(invalid(
                operation,
                "result.abis[].elf_header_valid must be a boolean or null",
            ));
        }
        if !is_nonnegative_integer(library.get("snapshot_hash_sources"))
            || !is_hash_array(library.get("snapshot_hash_candidates"), 32)
            || !is_nullable_hash(library.get("snapshot_hash"), 32)
        {
            return Err(invalid(operation, "invalid Flutter snapshot hash fields"));
        }
    } else {
        if !is_nullable_hex_id(library.get("build_id"), 8, 128)
            || !is_hash_array(library.get("build_id_candidates"), 8)
            || !is_nullable_string(library.get("dart_version"))
            || !library["dart_version_capped"].is_boolean()
            || !is_string_array(library.get("toolchain_lines"))
            || !library["toolchain_capped"].is_boolean()
        {
            return Err(invalid(operation, "invalid Flutter engine fields"));
        }
    }
    Ok(())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    operation: &str,
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(operation, "result contains an unknown field"));
    }
    Ok(())
}

fn is_nonnegative_integer(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.as_u64().is_some())
}

fn is_nullable_nonnegative_integer(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.as_u64().is_some())
}

fn is_sha256(value: Option<&Value>) -> bool {
    is_hex_string(value, 64, 64)
}

fn is_nullable_sha256(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || is_sha256(Some(value)))
}

fn is_nullable_hash(value: Option<&Value>, length: usize) -> bool {
    value.is_some_and(|value| value.is_null() || is_hex_string(Some(value), length, length))
}

fn is_hash_array(value: Option<&Value>, length: usize) -> bool {
    value.is_some_and(|value| {
        value.as_array().is_some_and(|items| {
            items
                .iter()
                .all(|item| is_hex_string(Some(item), length, length))
        })
    })
}

fn is_nullable_hex_id(value: Option<&Value>, minimum: usize, maximum: usize) -> bool {
    value.is_some_and(|value| value.is_null() || is_hex_string(Some(value), minimum, maximum))
}

fn is_hex_string(value: Option<&Value>, minimum: usize, maximum: usize) -> bool {
    value.is_some_and(|value| {
        value.as_str().is_some_and(|text| {
            (minimum..=maximum).contains(&text.len())
                && text.bytes().all(|byte| byte.is_ascii_hexdigit())
                && text == text.to_ascii_lowercase()
        })
    })
}

fn is_nullable_string(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.is_string())
}

fn is_string_array(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
    })
}

fn parse_raw(
    raw: Box<serde_json::value::RawValue>,
    operation: PolyglotStaticOperation,
) -> Result<Value, Failure> {
    serde_json::from_str(raw.get()).map_err(|error| {
        invalid(
            operation.name(),
            &format!("producer returned invalid JSON: {error}"),
        )
    })
}

fn object_input<'a>(input: &'a Value, operation: &str) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid(operation, "input must be an object"))
}

fn string_array(
    object: &Map<String, Value>,
    field: &str,
    operation: &str,
) -> Result<Vec<String>, Failure> {
    object
        .get(field)
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| invalid(operation, &format!("{field} must be an array")))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(ToOwned::to_owned)
                        .ok_or_else(|| invalid(operation, &format!("{field} must contain strings")))
                })
                .collect()
        })
        .transpose()
        .map(|value| value.unwrap_or_default())
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide bounded caller-supplied polyglot evidence or captured output.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}

fn unsupported(operation: PolyglotStaticOperation, reason: &str) -> Failure {
    Failure::new(
        "unsupported_request",
        "unsupported_request",
        reason.into(),
        false,
        "Use an adapter with an existing retained desktop application producer.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}

fn unknown_operation(name: &str) -> Failure {
    invalid(
        name,
        "operation is not a supported offline polyglot workflow",
    )
}
