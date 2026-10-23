//! Captured-only adapter for `trace_dylib_resolution`.
//!
//! Acquisition owns directory walking, Mach-O decoding, and hashing.  This
//! module accepts those retained facts and runs the same deterministic dyld
//! model as the provider-neutral application producer.  It deliberately has
//! no filesystem or provider access.

use crate::apple::dylib_resolution::{
    DylibResolutionRequest, DylibTreeEntry, DylibTreeView, MachoDependency, MachoImageFacts,
    MachoSlice, TreePathLookup, resolve_tree_path, trace_dylib_loading,
};
use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, convert::Infallible};

pub const OPERATION: &str = "trace_dylib_resolution";
const MAX_IMAGES: usize = 200_000;
const MAX_ENTRIES: usize = 500_000;

/// Project caller-supplied static facts or a complete authenticated Evidence
/// record.  No path in `input` is opened or canonicalized.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("captured dylib input must be an object"))?;
    if let Some(evidence) = object.get("evidence") {
        return project_evidence(evidence);
    }

    let root_path = required_text(object, "root_path")?;
    let target_sha256 = required_digest(object, "target_sha256")?;
    let target_path = object
        .get("target_path")
        .map(|value| {
            value
                .as_str()
                .filter(|path| !path.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("target_path must be non-empty text"))
        })
        .transpose()?;
    let roots = parse_paths(object.get("roots"), "roots")?;
    let unclassified = parse_paths(object.get("unclassified"), "unclassified")?;
    let architecture = object
        .get("architecture")
        .map(|value| {
            value
                .as_str()
                .filter(|name| matches!(*name, "arm64" | "arm64e" | "x86_64"))
                .ok_or_else(|| invalid("architecture must be arm64, arm64e, or x86_64"))
        })
        .transpose()?;
    let entries = parse_entries(object.get("entries").or_else(|| object.get("filesystem")))?;
    let (images, digests) = parse_images(object.get("images"))?;
    if roots.is_empty() {
        return Err(invalid("captured dylib input requires at least one root"));
    }
    if let Some(target_path) = target_path {
        validate_relative_path(&target_path)?;
        if digests.get(&target_path) != Some(&target_sha256) {
            return Err(invalid(
                "target_sha256 does not match the captured target image",
            ));
        }
    }

    let view = CapturedView { entries, images };
    let roots = roots
        .iter()
        .map(|root| match resolve_tree_path(&view, root) {
            Ok(TreePathLookup::File(path)) => Ok(path),
            Ok(TreePathLookup::Escapes) => Err(invalid(
                "a captured root resolves outside the analyzed root",
            )),
            Ok(TreePathLookup::Absent | TreePathLookup::NotFile) => {
                Err(invalid("a captured root must resolve to a regular file"))
            }
            Err(error) => Err(invalid(&format!("captured root lookup failed: {error}"))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let trace = trace_dylib_loading(
        &view,
        DylibResolutionRequest {
            roots: &roots,
            unclassified: &unclassified,
            architecture: architecture.as_deref(),
            cancelled: None,
        },
    )
    .map_err(|error| {
        invalid(&format!(
            "captured dylib facts could not be traced: {error}"
        ))
    })?;
    let result = trace_value(&trace, &root_path, &target_sha256, &digests);
    validate_result_shape(&result)?;
    Ok(result)
}

/// Named alias for adapters that distinguish captured projection from live
/// provider tracing at their call site.
pub fn project_captured(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn project_evidence(value: &Value) -> Result<Value, Failure> {
    let raw =
        serde_json::value::to_raw_value(value).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw)
        .map_err(|error| invalid(&format!("invalid authenticated Evidence: {error}")))?;
    let operation: String = serde_json::from_str(record.operation().get())
        .map_err(|_| invalid("Evidence operation is not a JSON string"))?;
    if operation != OPERATION {
        return Err(invalid(
            "Evidence operation does not match trace_dylib_resolution",
        ));
    }
    serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("Evidence normalized_result is invalid: {error}")))
}

struct CapturedView {
    entries: BTreeMap<String, DylibTreeEntry>,
    images: BTreeMap<String, MachoImageFacts>,
}

impl DylibTreeView for CapturedView {
    type Error = Infallible;
    fn entry(&self, path: &str) -> Result<Option<DylibTreeEntry>, Self::Error> {
        Ok(self.entries.get(path).cloned())
    }
    fn image(&self, path: &str) -> Result<MachoImageFacts, Self::Error> {
        Ok(self
            .images
            .get(path)
            .cloned()
            .unwrap_or(MachoImageFacts::NotMachO))
    }
}

fn parse_entries(value: Option<&Value>) -> Result<BTreeMap<String, DylibTreeEntry>, Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("entries must be an object keyed by root-relative path"))?;
    if object.len() > MAX_ENTRIES {
        return Err(invalid("entries exceed the captured snapshot limit"));
    }
    object
        .iter()
        .map(|(path, value)| {
            validate_relative_path(path)?;
            let item = value
                .as_object()
                .ok_or_else(|| invalid("filesystem entries must be objects"))?;
            let kind = item
                .get("kind")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("filesystem entries require kind"))?;
            let entry = match kind {
                "file" => DylibTreeEntry::File,
                "directory" => DylibTreeEntry::Directory,
                "symlink" => DylibTreeEntry::Symlink {
                    target: item
                        .get("target")
                        .and_then(Value::as_str)
                        .ok_or_else(|| invalid("symlink entries require target"))?
                        .to_owned(),
                },
                _ => {
                    return Err(invalid(
                        "filesystem entry kind must be file, directory, or symlink",
                    ));
                }
            };
            Ok((path.clone(), entry))
        })
        .collect()
}

fn parse_images(
    value: Option<&Value>,
) -> Result<(BTreeMap<String, MachoImageFacts>, BTreeMap<String, String>), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("images must be an object keyed by root-relative path"))?;
    if object.len() > MAX_IMAGES {
        return Err(invalid("images exceed the captured snapshot limit"));
    }
    let mut images = BTreeMap::new();
    let mut digests = BTreeMap::new();
    for (path, value) in object {
        validate_relative_path(path)?;
        let item = value
            .as_object()
            .ok_or_else(|| invalid("image facts must be objects"))?;
        let status = item
            .get("status")
            .or_else(|| item.get("parse_status"))
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("image facts require status"))?;
        if let Some(digest) = item.get("sha256") {
            digests.insert(path.clone(), parse_digest(digest, "sha256")?);
        }
        let facts = match status {
            "parsed" => MachoImageFacts::Parsed {
                slices: parse_slices(item.get("slices"))?,
            },
            "malformed" => MachoImageFacts::Malformed {
                reason: required_text(item, "reason")?,
            },
            "unsupported" => MachoImageFacts::Unsupported {
                reason: required_text(item, "reason")?,
            },
            "not-mach-o" => MachoImageFacts::NotMachO,
            _ => {
                return Err(invalid(
                    "image status must be parsed, malformed, unsupported, or not-mach-o",
                ));
            }
        };
        images.insert(path.clone(), facts);
    }
    Ok((images, digests))
}

fn parse_slices(value: Option<&Value>) -> Result<Vec<MachoSlice>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("parsed image facts require slices"))?;
    values.iter().map(parse_slice).collect()
}

fn parse_slice(value: &Value) -> Result<MachoSlice, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("Mach-O slices must be objects"))?;
    let text = |key: &str| required_text(object, key);
    let number = |key: &str| {
        object
            .get(key)
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid(&format!("slice {key} must be a non-negative integer")))
    };
    let optional_number = |key: &str| {
        object
            .get(key)
            .map(|value| {
                value
                    .as_u64()
                    .ok_or_else(|| invalid(&format!("slice {key} must be an integer")))
            })
            .transpose()
    };
    Ok(MachoSlice {
        architecture: text("architecture")?,
        slice_offset: number("slice_offset")?,
        slice_size: number("slice_size")?,
        cpu_type: number("cpu_type")? as u32,
        cpu_subtype: number("cpu_subtype")? as u32,
        fat_cpu_type: optional_number("fat_cpu_type")?.map(|v| v as u32),
        fat_cpu_subtype: optional_number("fat_cpu_subtype")?.map(|v| v as u32),
        fat_alignment_exponent: optional_number("fat_alignment_exponent")?.map(|v| v as u8),
        file_type: text("file_type")?,
        file_type_code: number("file_type_code")? as u32,
        platform: optional_number("platform")?.map(|v| v as u32),
        platforms: parse_numbers(object.get("platforms"), "platforms")?,
        install_name: optional_text(object, "install_name")?,
        dependencies: parse_dependencies(object.get("dependencies"))?,
        rpaths: parse_texts(object.get("rpaths"), "rpaths")?,
        dyld_environment: parse_texts(object.get("dyld_environment"), "dyld_environment")?,
        code_signature_present: object
            .get("code_signature_present")
            .and_then(Value::as_bool)
            .ok_or_else(|| invalid("slice code_signature_present must be boolean"))?,
    })
}

fn parse_dependencies(value: Option<&Value>) -> Result<Vec<MachoDependency>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("slice dependencies must be an array"))?;
    values
        .iter()
        .map(|value| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid("dependencies must be objects"))?;
            Ok(MachoDependency {
                command: required_text(object, "command")?,
                encoding: required_text(object, "encoding")?,
                install_name: required_text(object, "install_name")?,
                weak: required_bool(object, "weak")?,
                upward: required_bool(object, "upward")?,
                reexport: required_bool(object, "reexport")?,
                delayed_init: required_bool(object, "delayed_init")?,
                current_version: required_text(object, "current_version")?,
                compatibility_version: required_text(object, "compatibility_version")?,
            })
        })
        .collect()
}

fn trace_value(
    trace: &crate::apple::dylib_resolution::DylibTrace,
    root_path: &str,
    target_sha256: &str,
    digests: &BTreeMap<String, String>,
) -> Value {
    json!({"root_path": root_path, "target_sha256": target_sha256, "roots": trace.roots.iter().map(|root| json!({"image":root.image,"architecture":root.architecture})).collect::<Vec<_>>(), "images": trace.images.iter().map(|image| json!({"path":image.path,"sha256":digests.get(&image.path),"parse_status":image.parse_status,"reason":image.reason,"slices":image.slices.iter().map(slice_value).collect::<Vec<_>>() })).collect::<Vec<_>>(), "edges": trace.edges.iter().map(edge_value).collect::<Vec<_>>(), "findings": trace.findings.iter().map(|finding| json!({"kind":finding.kind,"edge_index":finding.edge_index,"image":finding.image,"basis":finding.basis,"explanation":finding.explanation})).collect::<Vec<_>>(), "coverage":{"status":trace.coverage.status,"unparsed_images":trace.coverage.unparsed_images,"roots_without_architecture":trace.coverage.roots_without_architecture}, "limitations":trace.limitations})
}

fn edge_value(edge: &crate::apple::dylib_resolution::DylibEdge) -> Value {
    json!({"root":edge.root,"architecture":edge.architecture,"loader":edge.loader,"via":edge.via,"command":edge.dependency.command,"encoding":edge.dependency.encoding,"install_name":edge.dependency.install_name,"weak":edge.dependency.weak,"upward":edge.dependency.upward,"reexport":edge.dependency.reexport,"delayed_init":edge.dependency.delayed_init,"current_version":edge.dependency.current_version,"compatibility_version":edge.dependency.compatibility_version,"candidates":edge.candidates.iter().map(|c| json!({"path":c.path,"source":c.source,"rpath":c.rpath,"rpath_owner":c.rpath_owner,"outcome":c.outcome,"resolved_path":c.resolved_path})).collect::<Vec<_>>(),"resolution":{"status":edge.resolution.status,"image":edge.resolution.image},"install_name_matches":edge.install_name_matches,"loader_conditional":edge.loader_conditional})
}
fn slice_value(slice: &crate::apple::dylib_resolution::MachoSliceSummary) -> Value {
    json!({"architecture":slice.architecture,"slice_offset":slice.slice_offset,"slice_size":slice.slice_size,"cpu_type":slice.cpu_type,"cpu_subtype":slice.cpu_subtype,"fat_cpu_type":slice.fat_cpu_type,"fat_cpu_subtype":slice.fat_cpu_subtype,"fat_alignment_exponent":slice.fat_alignment_exponent,"file_type":slice.file_type,"file_type_code":slice.file_type_code,"platform":slice.platform,"platforms":slice.platforms,"install_name":slice.install_name,"rpaths":slice.rpaths,"dyld_environment":slice.dyld_environment,"code_signature_present":slice.code_signature_present})
}

fn validate_result_shape(result: &Value) -> Result<(), Failure> {
    if !result
        .get("images")
        .and_then(Value::as_array)
        .is_some_and(|images| {
            images
                .iter()
                .all(|image| image.get("sha256").and_then(Value::as_str).is_some())
        })
    {
        return Err(invalid(
            "every captured image requires an authenticated sha256",
        ));
    }
    Ok(())
}
fn parse_paths(value: Option<&Value>, field: &str) -> Result<Vec<String>, Failure> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            let path = value
                .as_str()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| invalid(&format!("{field} must contain non-empty paths")))?;
            validate_relative_path(path)?;
            Ok(path.to_owned())
        })
        .collect()
}
fn parse_texts(value: Option<&Value>, field: &str) -> Result<Vec<String>, Failure> {
    let Some(value) = value else {
        return Err(invalid(&format!("{field} must be an array")));
    };
    let values = value
        .as_array()
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid(&format!("{field} must contain text")))
        })
        .collect()
}
fn required_text(object: &Map<String, Value>, field: &str) -> Result<String, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(&format!("{field} must be non-empty text")))
}
fn optional_text(object: &Map<String, Value>, field: &str) -> Result<Option<String>, Failure> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid(&format!("{field} must be a string or null")))
        })
        .transpose()
}
fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool, Failure> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid(&format!("{field} must be boolean")))
}
fn parse_numbers(value: Option<&Value>, field: &str) -> Result<Vec<u32>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{field} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .filter(|v| *v <= u32::MAX as u64)
                .map(|v| v as u32)
                .ok_or_else(|| invalid(&format!("{field} must contain u32 integers")))
        })
        .collect()
}
fn required_digest(object: &Map<String, Value>, field: &str) -> Result<String, Failure> {
    parse_digest(
        object
            .get(field)
            .ok_or_else(|| invalid(&format!("{field} is required")))?,
        field,
    )
}
fn parse_digest(value: &Value, field: &str) -> Result<String, Failure> {
    let digest = value
        .as_str()
        .ok_or_else(|| invalid(&format!("{field} must be a string")))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(&format!("{field} must be lowercase SHA-256")));
    }
    Ok(digest.to_owned())
}
fn validate_relative_path(path: &str) -> Result<(), Failure> {
    if path.is_empty()
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains("//")
        || path.contains('\\')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid(
            "snapshot paths must be normalized root-relative paths",
        ));
    }
    Ok(())
}
fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide a bounded captured dylib snapshot or authenticated Evidence.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (
                String::from("authority"),
                Detail::Text("offline_capture_only".into()),
            ),
        ]),
    )
}
