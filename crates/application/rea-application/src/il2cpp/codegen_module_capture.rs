//! Captured-only projection of one IL2CPP `CodeGenModule` record.
//!
//! The layout decoder owns byte interpretation.  This boundary adds the
//! caller's exact image/module identity and exposes the decoded facts in the
//! row shape consumed by the IL2CPP token-to-pointer workflows.  It never
//! opens a file, consults a provider, dereferences an address, or fills an
//! omitted capture from a guess.

use base64::Engine;
use rea_core::evidence::is_sha256;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_il2cpp_codegen_module_capture";
const PROJECT_OPERATION: &str = "capture_il2cpp_codegen_module";

/// Decode the public capture contract and return its stable inspection shape.
///
/// The shared layout decoder intentionally requires explicit internal fields
/// (`record_size`, `method_pointer_count_width`, and `variant`).  The public
/// capture contract derives those values from the caller's bounded record and
/// pointer width so unknown layout fields remain rejected at the boundary.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_public_input(input)?;

    let normalized_input = normalize_layout(input)?;
    let projected = project(&normalized_input)?;
    let object = projected
        .as_object()
        .ok_or_else(|| invalid("projection", "Capture projection returned a non-object"))?;

    let identity = serde_json::json!({
        "module_name": object.get("module_name").cloned().unwrap_or(Value::Null),
        "name_pointer": object.get("name_pointer").cloned().unwrap_or(Value::Null),
        "method_pointers_pointer": object
            .get("method_pointers_pointer")
            .cloned()
            .unwrap_or(Value::Null),
    });

    Ok(serde_json::json!({
        "operation": OPERATION,
        "layout": public_layout(object.get("layout"))?,
        "module_name": object.get("module_name").cloned().unwrap_or(Value::Null),
        "name_pointer": object.get("name_pointer").cloned().unwrap_or(Value::Null),
        "method_pointer_count": object
            .get("method_pointer_count")
            .cloned()
            .unwrap_or(Value::Null),
        "method_pointers_pointer": object
            .get("method_pointers_pointer")
            .cloned()
            .unwrap_or(Value::Null),
        "method_pointers": object.get("method_pointers").cloned().unwrap_or(Value::Null),
        "identity": identity,
        "limitations": [
            "Pointer values are preserved from caller-supplied bytes; no process address is dereferenced.",
            "Only caller-supplied bounded record, name, and pointer-table captures are examined.",
            "The explicit layout descriptor does not establish that a pointer belongs to a live target.",
        ],
    }))
}

/// Decode bounded static captures and project one normalized CodeGenModule row.
///
/// The accepted byte and layout fields are the same as
/// [`il2cpp_codegen_module_layout::parse`].  Optional identity aliases are
/// accepted for callers that already use the metadata join vocabulary:
/// `image_index`/`image_id`, `image_name`/`assembly_name`/`image`, and
/// `module_name`/`module`.  Image indices accept either JSON non-negative
/// integers or the decimal/hexadecimal text used by some metadata captures.
/// If aliases disagree, the request is rejected.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let identity = root
        .get("identity")
        .map(|value| {
            value
                .as_object()
                .ok_or_else(|| invalid("identity", "Identity must be an object"))
        })
        .transpose()?;

    let parsed = super::codegen_module_layout::parse(input)?;
    let parsed_object = parsed
        .as_object()
        .ok_or_else(|| invalid("layout_result", "Layout decoder returned a non-object"))?;

    let module_name = reconcile_text(
        root,
        identity,
        parsed_object.get("module_name").and_then(Value::as_str),
        &["module_name", "module"],
        "module_name",
    )?;
    let image_index =
        reconcile_number(root, identity, &["image_index", "image_id"], "image_index")?;
    let image_name = reconcile_text(
        root,
        identity,
        None,
        &["image_name", "assembly_name", "image"],
        "image_name",
    )?;
    let binary_sha256 = reconcile_digest(root, identity)?;
    let address_space = reconcile_text(
        root,
        identity,
        None,
        &["address_space", "addressSpace"],
        "address_space",
    )?;

    let mut normalized = Map::new();
    normalized.insert("operation".into(), Value::String(PROJECT_OPERATION.into()));
    normalized.insert("module_name".into(), optional_string(module_name.clone()));
    normalized.insert("image_index".into(), optional_number(image_index));
    normalized.insert("image_name".into(), optional_string(image_name.clone()));

    for field in [
        "layout",
        "name_pointer",
        "method_pointer_count",
        "method_pointers",
        "method_pointer_slots",
        "method_pointers_pointer",
        "source",
    ] {
        let value = parsed_object
            .get(field)
            .cloned()
            .ok_or_else(|| invalid("layout_result", &format!("Layout decoder omitted {field}")))?;
        normalized.insert(field.into(), value);
    }

    let source = normalized
        .get_mut("source")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| invalid("layout_result.source", "Capture source must be an object"))?;
    if let Some(mappings) = root.get("method_pointer_mappings") {
        source.insert("method_pointer_mappings".into(), mappings.clone());
    }
    if let Some(spans) = capture_spans(root)? {
        source.insert("capture_spans".into(), spans);
    }
    let unknown_fields = unknown_root_fields(root);
    if !unknown_fields.is_empty() {
        source.insert("unknown_fields".into(), Value::Object(unknown_fields));
    }

    normalized.insert(
        "identity".into(),
        serde_json::json!({
            "module_name": optional_string(module_name.clone()),
            "image_index": optional_number(image_index),
            "image_name": optional_string(image_name.clone()),
            "binary_sha256": optional_string(binary_sha256.clone()),
            "address_space": optional_string(address_space.clone()),
        }),
    );

    normalized.insert("binary_sha256".into(), optional_string(binary_sha256));
    normalized.insert("address_space".into(), optional_string(address_space));

    Ok(Value::Object(normalized))
}

/// Retain caller fields that the layout decoder does not interpret.
///
/// Capture adapters commonly carry row labels, selection notes, and producer
/// metadata alongside the bytes.  Those values are evidence and must survive
/// projection even though they do not participate in layout decoding.
fn unknown_root_fields(root: &Map<String, Value>) -> Map<String, Value> {
    let known = [
        "layout",
        "record_bytes_base64",
        "name_bytes_base64",
        "method_pointers_bytes_base64",
        "method_pointer_mappings",
        "module_name",
        "identity",
        "artifact",
        "source",
        "capture",
        "source_spans",
        "capture_spans",
        "record_file_offset",
        "record_virtual_address",
        "name_file_offset",
        "name_virtual_address",
        "method_pointers_file_offset",
        "method_pointers_virtual_address",
        "record_length",
        "pointer_table_length",
    ];

    root.iter()
        .filter(|(field, _)| !known.contains(&field.as_str()))
        .map(|(field, value)| (field.clone(), value.clone()))
        .collect()
}

fn reconcile_digest(
    root: &Map<String, Value>,
    identity: Option<&Map<String, Value>>,
) -> Result<Option<String>, Failure> {
    let mut value = None;
    for source in [Some(root), identity] {
        let Some(source) = source else {
            continue;
        };
        for alias in ["binary_sha256", "binary_digest", "sha256"] {
            let Some(candidate) = source.get(alias) else {
                continue;
            };
            if candidate.is_null() {
                continue;
            }
            let digest = candidate
                .as_str()
                .filter(|digest| is_sha256(digest))
                .ok_or_else(|| {
                    invalid("binary_sha256", "Binary digest must be lowercase SHA-256")
                })?;
            if let Some(existing) = &value {
                if existing != digest {
                    return Err(invalid("binary_sha256", "Digest aliases disagree"));
                }
            } else {
                value = Some(digest.to_owned());
            }
        }
    }
    if let Some(artifact) = root.get("artifact").and_then(Value::as_object) {
        if let Some(candidate) = artifact.get("sha256") {
            if !candidate.is_null() {
                let digest = candidate
                    .as_str()
                    .filter(|digest| is_sha256(digest))
                    .ok_or_else(|| {
                        invalid(
                            "artifact.sha256",
                            "Artifact digest must be lowercase SHA-256",
                        )
                    })?;
                if let Some(existing) = &value {
                    if existing != digest {
                        return Err(invalid("binary_sha256", "Digest aliases disagree"));
                    }
                } else {
                    value = Some(digest.to_owned());
                }
            }
        }
    }
    Ok(value)
}

fn capture_spans(root: &Map<String, Value>) -> Result<Option<Value>, Failure> {
    let mut spans = Map::new();
    for alias in ["source", "capture", "source_spans", "capture_spans"] {
        let Some(value) = root.get(alias) else {
            continue;
        };
        let object = value
            .as_object()
            .ok_or_else(|| invalid(alias, "Capture spans must be an object"))?;
        for (key, value) in object {
            if let Some(existing) = spans.get(key) {
                if existing != value {
                    return Err(invalid(alias, "Capture span aliases disagree"));
                }
            } else {
                spans.insert(key.clone(), value.clone());
            }
        }
    }
    for field in [
        "record_file_offset",
        "record_virtual_address",
        "name_file_offset",
        "name_virtual_address",
        "method_pointers_file_offset",
        "method_pointers_virtual_address",
        "record_length",
        "pointer_table_length",
    ] {
        if let Some(value) = root.get(field) {
            spans.insert(field.into(), value.clone());
        }
    }
    Ok((!spans.is_empty()).then_some(Value::Object(spans)))
}

/// Named alias for adapters that distinguish a captured projection from a
/// provider-backed inspection.
pub fn project_captured(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Capture-oriented alias for callers that use operation names as functions.
pub fn capture(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn validate_public_input(input: &Value) -> Result<(), Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    validate_allowed_fields(
        root,
        &[
            "layout",
            "record_bytes_base64",
            "name_bytes_base64",
            "method_pointers_bytes_base64",
            "method_pointer_mappings",
            "module_name",
            "module",
            "image_index",
            "image_id",
            "image_name",
            "assembly_name",
            "image",
            "binary_sha256",
            "binary_digest",
            "sha256",
            "address_space",
            "addressSpace",
            "identity",
            "artifact",
            "source",
            "capture",
            "source_spans",
            "capture_spans",
            "record_file_offset",
            "record_virtual_address",
            "name_file_offset",
            "name_virtual_address",
            "method_pointers_file_offset",
            "method_pointers_virtual_address",
            "record_length",
            "pointer_table_length",
        ],
        "Unknown capture field",
    )?;

    validate_identity(root.get("identity"))?;
    validate_artifact(root.get("artifact"))?;
    validate_capture_span_objects(root)?;

    validate_pointer_mappings(root.get("method_pointer_mappings"))?;

    let layout = root
        .get("layout")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout", "An explicit layout descriptor is required"))?;
    for field in layout.keys() {
        if ![
            "version",
            "pointer_width",
            "endianness",
            "name_pointer_offset",
            "method_pointer_count_offset",
            "method_pointers_offset",
        ]
        .contains(&field.as_str())
        {
            return Err(invalid(field, "Unknown layout field"));
        }
    }

    Ok(())
}

fn validate_pointer_mappings(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };

    if !value.is_array() {
        return Err(invalid(
            "method_pointer_mappings",
            "Method pointer mappings must be an array",
        ));
    }

    Ok(())
}

fn validate_allowed_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    reason: &str,
) -> Result<(), Failure> {
    for field in object.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(invalid(field, reason));
        }
    }
    Ok(())
}

fn validate_identity(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(identity) = value.as_object() else {
        return Err(invalid("identity", "Identity must be an object"));
    };
    validate_allowed_fields(
        identity,
        &[
            "module_name",
            "module",
            "image_index",
            "image_id",
            "image_name",
            "assembly_name",
            "image",
            "binary_sha256",
            "binary_digest",
            "sha256",
            "address_space",
            "addressSpace",
        ],
        "Unknown identity field",
    )
}

fn validate_artifact(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let Some(artifact) = value.as_object() else {
        return Err(invalid("artifact", "Artifact must be an object"));
    };
    validate_allowed_fields(artifact, &["sha256"], "Unknown artifact field")
}

fn validate_capture_span_objects(root: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["source", "capture", "source_spans", "capture_spans"] {
        if let Some(value) = root.get(field) {
            if !value.is_object() {
                return Err(invalid(field, "Capture spans must be an object"));
            }
        }
    }
    Ok(())
}

fn normalize_layout(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let layout = root
        .get("layout")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout", "An explicit layout descriptor is required"))?;
    let record_text = root
        .get("record_bytes_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("record_bytes_base64", "A base64 record capture is required"))?;
    let record_size = base64::engine::general_purpose::STANDARD
        .decode(record_text)
        .map_err(|_| invalid("record_bytes_base64", "Record capture must be valid base64"))?
        .len();
    let mut normalized = root.clone();
    let mut normalized_layout = layout.clone();
    normalized_layout
        .entry("record_size".to_string())
        .or_insert_with(|| Value::from(record_size));
    normalized_layout
        .entry("method_pointer_count_width".to_string())
        // Il2CppCodeGenModule::methodPointerCount is a uint32_t even when
        // the captured pointers use the 64-bit layout.
        .or_insert_with(|| Value::from(4));
    normalized_layout
        .entry("variant".to_string())
        .or_insert_with(|| Value::String("capture".into()));
    normalized.insert("layout".into(), Value::Object(normalized_layout));
    Ok(Value::Object(normalized))
}

fn public_layout(value: Option<&Value>) -> Result<Value, Failure> {
    let layout = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("layout_result", "Decoded layout must be an object"))?;
    let mut public = Map::new();
    for field in [
        "version",
        "pointer_width",
        "endianness",
        "name_pointer_offset",
        "method_pointer_count_offset",
        "method_pointers_offset",
    ] {
        let value = layout
            .get(field)
            .cloned()
            .ok_or_else(|| invalid("layout_result", &format!("Layout omitted {field}")))?;
        public.insert(field.into(), value);
    }
    Ok(Value::Object(public))
}

fn reconcile_text(
    root: &Map<String, Value>,
    identity: Option<&Map<String, Value>>,
    decoded: Option<&str>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<String>, Failure> {
    let mut value = decoded.map(str::to_owned).filter(|text| !text.is_empty());
    if decoded.is_some() && value.is_none() {
        return Err(invalid(field, "Identity text must be non-empty"));
    }
    for source in [Some(root), identity] {
        let Some(source) = source else {
            continue;
        };
        for alias in aliases {
            let Some(candidate) = source.get(*alias) else {
                continue;
            };
            if candidate.is_null() {
                continue;
            }
            let text = candidate
                .as_str()
                .filter(|text| !text.is_empty())
                .ok_or_else(|| invalid(field, "Identity text must be non-empty"))?;
            if let Some(existing) = &value {
                if existing != text {
                    return Err(invalid(field, "Identity aliases disagree"));
                }
            } else {
                value = Some(text.to_owned());
            }
        }
    }
    Ok(value)
}

fn reconcile_number(
    root: &Map<String, Value>,
    identity: Option<&Map<String, Value>>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<u64>, Failure> {
    let mut value = None;
    for source in [Some(root), identity] {
        let Some(source) = source else {
            continue;
        };
        for alias in aliases {
            let Some(candidate) = source.get(*alias) else {
                continue;
            };
            if candidate.is_null() {
                continue;
            }
            let number = parse_identity_number(candidate, field)?;
            if let Some(existing) = value {
                if existing != number {
                    return Err(invalid(field, "Identity aliases disagree"));
                }
            } else {
                value = Some(number);
            }
        }
    }
    Ok(value)
}

fn parse_identity_number(value: &Value, field: &str) -> Result<u64, Failure> {
    if let Some(number) = value.as_u64() {
        return Ok(number);
    }

    let text = value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(field, "Identity index must be a non-negative integer"))?;
    let (digits, radix) = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or((text, 10), |digits| (digits, 16));

    u64::from_str_radix(digits, radix)
        .map_err(|_| invalid(field, "Identity index must be a non-negative integer"))
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn optional_number(value: Option<u64>) -> Value {
    value.map_or(Value::Null, Value::from)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP CodeGenModule capture is invalid.".into(),
        false,
        "Provide an explicit layout, bounded captures, and consistent module identity.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
