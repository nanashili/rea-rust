//! Joins IL2CPP metadata images with captured CodeGenModule facts.
//!
//! This module deliberately performs identity matching only.  It does not use
//! row order, string similarity, or a guessed assembly-to-module relationship.
//! A caller may request a separately labelled case-folded candidate, but that
//! candidate never changes the exact-match result.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "join_il2cpp_assemblies";
const MAX_ROWS: usize = 200_000;

pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    validate_input_shape(root)?;

    let metadata = object_alias(root, "metadata")?;
    let binary = object_alias(root, "binary")?;
    let images = rows(metadata, &["images", "metadata_images"], "images")?;
    let assemblies = rows(
        metadata,
        &["assemblies", "metadata_assemblies"],
        "assemblies",
    )?;
    let modules = rows(binary, &["codegen_modules", "modules"], "codegen_modules")?;
    let normalization_requested = requested_case_folding(root.get("normalization"));

    let mut results = Vec::with_capacity(images.len());
    let mut exact = 0usize;
    let mut ambiguous = 0usize;
    let mut unmatched = 0usize;
    let mut normalized_only = 0usize;

    for (row, image) in images.iter().enumerate() {
        let image_object = image
            .as_object()
            .ok_or_else(|| invalid_row("images", row, "Expected an object"))?;
        let image_key = identity(image_object, assemblies)?;
        let exact_matches: Vec<usize> = modules
            .iter()
            .enumerate()
            .filter_map(|(index, module)| {
                exact_match(&image_key, module.as_object()?).then_some(index)
            })
            .collect();
        let normalized_matches = if normalization_requested {
            modules
                .iter()
                .enumerate()
                .filter_map(|(index, module)| {
                    normalized_match(image_object, &image_key, module.as_object()?).then_some(index)
                })
                .collect()
        } else {
            Vec::new()
        };

        let status = if image_key.conflicted {
            ambiguous += 1;
            "ambiguous"
        } else {
            match exact_matches.len() {
                0 => {
                    unmatched += 1;
                    if normalized_matches.len() == 1 {
                        normalized_only += 1;
                        "unmatched"
                    } else {
                        "unmatched"
                    }
                }
                1 => {
                    exact += 1;
                    "matched"
                }
                _ => {
                    ambiguous += 1;
                    "ambiguous"
                }
            }
        };
        let exact_rows = exact_matches
            .iter()
            .map(|index| modules[*index].clone())
            .collect::<Vec<_>>();
        let normalized_rows = normalized_matches
            .iter()
            .map(|index| modules[*index].clone())
            .collect::<Vec<_>>();
        results.push(serde_json::json!({
            "image": image,
            "identity": identity_value(&image_key),
            "status": status,
            "exact_matches": exact_rows,
            "normalized_candidates": normalized_rows,
        }));
    }

    let status = if ambiguous > 0 || unmatched > 0 {
        "partial"
    } else {
        "complete"
    };
    Ok(serde_json::json!({
        "status": status,
        "images": results,
        "coverage": {
            "images": images.len(),
            "assemblies": assemblies.len(),
            "codegen_modules": modules.len(),
            "exact_matched": exact,
            "ambiguous": ambiguous,
            "unmatched": unmatched,
            "normalized_only": normalized_only,
            "normalization_requested": normalization_requested,
        }
    }))
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    reject_unknown_fields(root, &["metadata", "binary", "normalization"], "input")?;

    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("metadata", "Expected an object"))?;
    reject_unknown_fields(
        metadata,
        &[
            "images",
            "metadata_images",
            "assemblies",
            "metadata_assemblies",
        ],
        "metadata",
    )?;

    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("binary", "Expected an object"))?;
    reject_unknown_fields(binary, &["codegen_modules", "modules"], "binary")?;

    if let Some(normalization) = root.get("normalization") {
        if !normalization.is_null() {
            let normalization = normalization
                .as_object()
                .ok_or_else(|| invalid("normalization", "Expected an object or null"))?;
            reject_unknown_fields(
                normalization,
                &["case_fold", "case_insensitive"],
                "normalization",
            )?;
        }
    }

    for object in [metadata, binary] {
        for (field, value) in object {
            let is_rows = matches!(
                field.as_str(),
                "images"
                    | "metadata_images"
                    | "assemblies"
                    | "metadata_assemblies"
                    | "codegen_modules"
                    | "modules"
            );
            if is_rows {
                let rows = value
                    .as_array()
                    .ok_or_else(|| invalid(field, "Expected an array"))?;
                for (row, value) in rows.iter().enumerate() {
                    let object = value
                        .as_object()
                        .ok_or_else(|| invalid_row(field, row, "Expected an object"))?;
                    reject_unknown_identity_fields(object, field, row)?;
                    validate_identity_values(object, field, row)?;
                }
            }
        }
    }

    Ok(())
}

fn validate_identity_values(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<(), Failure> {
    const NUMERIC_FIELDS: &[&str] = &["image_index", "image_id", "index", "assembly_index"];
    const TEXT_FIELDS: &[&str] = &[
        "image_name",
        "name",
        "image",
        "assembly_name",
        "assembly",
        "module_name",
        "module",
        "binary_sha256",
        "sha256",
        "binary_digest",
        "architecture",
        "arch",
        "address_space",
    ];

    for field in NUMERIC_FIELDS {
        let Some(value) = object.get(*field) else {
            continue;
        };
        if !value.is_null() && parse_u64(value).is_none() {
            return Err(invalid_row(
                collection,
                row,
                &format!("`{field}` must be a non-negative integer or null"),
            ));
        }
    }

    for field in TEXT_FIELDS {
        let Some(value) = object.get(*field) else {
            continue;
        };
        let Some(text) = value.as_str() else {
            if value.is_null() {
                continue;
            }
            return Err(invalid_row(
                collection,
                row,
                &format!("`{field}` must be a non-empty string or null"),
            ));
        };
        if text.is_empty() {
            return Err(invalid_row(
                collection,
                row,
                &format!("`{field}` must be a non-empty string or null"),
            ));
        }
        if matches!(*field, "binary_sha256" | "sha256" | "binary_digest") && !is_sha256(text) {
            return Err(invalid_row(
                collection,
                row,
                &format!("`{field}` must be a lowercase hexadecimal SHA-256 digest"),
            ));
        }
    }

    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn reject_unknown_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(
            field,
            &format!("Unknown field `{unknown}` is not permitted"),
        ));
    }
    Ok(())
}

fn reject_unknown_identity_fields(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<(), Failure> {
    const ALLOWED: &[&str] = &[
        "image_index",
        "image_id",
        "index",
        "image_name",
        "name",
        "image",
        "assembly_name",
        "assembly",
        "module_name",
        "module",
        "assembly_index",
        "binary_sha256",
        "sha256",
        "binary_digest",
        "architecture",
        "arch",
        "address_space",
    ];

    if let Some(unknown) = object.keys().find(|key| !ALLOWED.contains(&key.as_str())) {
        return Err(invalid_row(
            collection,
            row,
            &format!("Unknown field `{unknown}` is not permitted"),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct Identity {
    image_index: Option<u64>,
    image_name: Option<String>,
    assembly_name: Option<String>,
    module_name: Option<String>,
    binary_sha256: Option<String>,
    architecture: Option<String>,
    address_space: Option<String>,
    conflicted: bool,
}

fn identity(image: &Map<String, Value>, assemblies: &[Value]) -> Result<Identity, Failure> {
    let mut result = identity_from_object(image);
    if let Some(assembly_index) = image.get("assembly_index").and_then(parse_u64) {
        let resolution = resolve_assembly(assemblies, assembly_index);
        let Some(assembly) = resolution.row else {
            // An explicit assembly reference that cannot be resolved must not
            // silently fall back to a weaker image or display-name match.
            result.conflicted = true;
            return Ok(result);
        };

        // Duplicate source indices are ambiguous even when the duplicate rows
        // happen to carry the same display name. Preserve that uncertainty at
        // the identity boundary instead of allowing a positional or textual
        // fallback to manufacture a match.
        result.conflicted |= resolution.ambiguous;

        let assembly_identity = identity_from_object(assembly);
        result.conflicted |= assembly_identity.conflicted;

        let assembly_name = assembly_identity
            .assembly_name
            .or(assembly_identity.image_name);
        if let Some(assembly_name) = assembly_name {
            merge_text(
                &mut result.assembly_name,
                assembly_name,
                &mut result.conflicted,
            );
        }
    }
    if result.image_index.is_none() && result.image_name.is_none() && result.assembly_name.is_none()
    {
        return Err(invalid(
            "images",
            "Each image needs an exact index, image name, or assembly name",
        ));
    }
    Ok(result)
}

struct AssemblyResolution<'a> {
    row: Option<&'a Map<String, Value>>,
    ambiguous: bool,
}

/// Resolve an assembly reference by its declared source index.
///
/// Metadata rows are caller-provided facts and their order is not an identity
/// contract. Looking up by array position would silently join a reordered
/// capture to the wrong assembly. A missing explicit index therefore remains
/// unresolved, while duplicate indices remain ambiguous.
fn resolve_assembly<'a>(assemblies: &'a [Value], requested: u64) -> AssemblyResolution<'a> {
    let mut row = None;
    let mut matches = 0usize;
    let mut conflicted = false;

    for value in assemblies {
        let Some(object) = value.as_object() else {
            continue;
        };
        let (index, aliases_conflict) = number(object, &["assembly_index", "index"]);
        let Some(index) = index else {
            continue;
        };
        if index == requested {
            matches += 1;
            row = Some(object);
            conflicted |= aliases_conflict;
        }
    }

    AssemblyResolution {
        row: if matches == 1 && !conflicted {
            row
        } else {
            None
        },
        ambiguous: matches > 1 || conflicted,
    }
}

fn identity_from_object(object: &Map<String, Value>) -> Identity {
    let (image_index, image_index_conflict) = number(object, &["image_index", "image_id", "index"]);
    let (image_name, image_name_conflict) = text(object, &["image_name", "name", "image"]);
    let (assembly_name, assembly_name_conflict) = text(object, &["assembly_name", "assembly"]);
    let (module_name, module_name_conflict) = text(object, &["module_name", "module"]);
    let (binary_sha256, binary_sha256_conflict) =
        text(object, &["binary_sha256", "sha256", "binary_digest"]);
    let (architecture, architecture_conflict) = text(object, &["architecture", "arch"]);
    let (address_space, address_space_conflict) = text(object, &["address_space"]);

    Identity {
        image_index,
        image_name,
        assembly_name,
        module_name,
        binary_sha256,
        architecture,
        address_space,
        conflicted: image_index_conflict
            || image_name_conflict
            || assembly_name_conflict
            || module_name_conflict
            || binary_sha256_conflict
            || architecture_conflict
            || address_space_conflict,
    }
}

fn exact_match(key: &Identity, module: &Map<String, Value>) -> bool {
    let candidate = identity_from_object(module);
    !key.conflicted
        && !candidate.conflicted
        && shared_exact(key.image_index, candidate.image_index)
        && shared_exact(key.image_name.as_deref(), candidate.image_name.as_deref())
        && shared_exact(
            key.assembly_name.as_deref(),
            candidate.assembly_name.as_deref(),
        )
        && shared_exact(key.module_name.as_deref(), candidate.module_name.as_deref())
        && shared_exact(
            key.binary_sha256.as_deref(),
            candidate.binary_sha256.as_deref(),
        )
        && shared_exact(
            key.architecture.as_deref(),
            candidate.architecture.as_deref(),
        )
        && shared_exact(
            key.address_space.as_deref(),
            candidate.address_space.as_deref(),
        )
        && has_shared_identity(key, &candidate)
}

fn normalized_match(
    _image: &Map<String, Value>,
    key: &Identity,
    module: &Map<String, Value>,
) -> bool {
    let candidate = identity_from_object(module);
    if key.conflicted || candidate.conflicted {
        return false;
    }

    let name_matches = [
        key.image_name
            .as_deref()
            .zip(candidate.image_name.as_deref()),
        key.assembly_name
            .as_deref()
            .zip(candidate.assembly_name.as_deref()),
        key.module_name
            .as_deref()
            .zip(candidate.module_name.as_deref()),
    ]
    .into_iter()
    .flatten()
    .any(|(left, right)| left.eq_ignore_ascii_case(right));

    name_matches
        && normalized_text(key.image_name.as_deref(), candidate.image_name.as_deref())
        && normalized_text(
            key.assembly_name.as_deref(),
            candidate.assembly_name.as_deref(),
        )
        && normalized_text(key.module_name.as_deref(), candidate.module_name.as_deref())
        && shared_exact(key.image_index, candidate.image_index)
        && shared_exact(
            key.binary_sha256.as_deref(),
            candidate.binary_sha256.as_deref(),
        )
        && shared_exact(
            key.architecture.as_deref(),
            candidate.architecture.as_deref(),
        )
        && shared_exact(
            key.address_space.as_deref(),
            candidate.address_space.as_deref(),
        )
        && has_shared_normalized_identity(key, &candidate)
}

fn has_shared_identity(left: &Identity, right: &Identity) -> bool {
    left.image_index
        .zip(right.image_index)
        .is_some_and(|(a, b)| a == b)
        || left
            .image_name
            .as_deref()
            .zip(right.image_name.as_deref())
            .is_some_and(|(a, b)| a == b)
        || left
            .assembly_name
            .as_deref()
            .zip(right.assembly_name.as_deref())
            .is_some_and(|(a, b)| a == b)
        || left
            .module_name
            .as_deref()
            .zip(right.module_name.as_deref())
            .is_some_and(|(a, b)| a == b)
        || left
            .binary_sha256
            .as_deref()
            .zip(right.binary_sha256.as_deref())
            .is_some_and(|(a, b)| a == b)
}

fn has_shared_normalized_identity(left: &Identity, right: &Identity) -> bool {
    left.image_index
        .zip(right.image_index)
        .is_some_and(|(a, b)| a == b)
        || normalized_text(left.image_name.as_deref(), right.image_name.as_deref())
            && left.image_name.is_some()
            && right.image_name.is_some()
        || normalized_text(
            left.assembly_name.as_deref(),
            right.assembly_name.as_deref(),
        ) && left.assembly_name.is_some()
            && right.assembly_name.is_some()
        || normalized_text(left.module_name.as_deref(), right.module_name.as_deref())
            && left.module_name.is_some()
            && right.module_name.is_some()
}

fn normalized_text(left: Option<&str>, right: Option<&str>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        _ => true,
    }
}

fn merge_text(target: &mut Option<String>, candidate: String, conflicted: &mut bool) {
    if let Some(existing) = target {
        if existing != &candidate {
            *conflicted = true;
        }
    } else {
        *target = Some(candidate);
    }
}

fn shared_exact<T: PartialEq>(left: Option<T>, right: Option<T>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn identity_value(identity: &Identity) -> Value {
    serde_json::json!({
        "image_index": identity.image_index,
        "image_name": identity.image_name,
        "assembly_name": identity.assembly_name,
        "module_name": identity.module_name,
        "binary_sha256": identity.binary_sha256,
        "architecture": identity.architecture,
        "address_space": identity.address_space,
    })
}

fn object_alias<'a>(
    root: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    root.get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(key, "Expected an object"))
}
fn rows<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let provided = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();
    let (_, value) = provided
        .first()
        .copied()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if provided
        .iter()
        .skip(1)
        .any(|(_, candidate)| *candidate != value)
    {
        return Err(invalid(
            field,
            "Conflicting aliases describe different row collections",
        ));
    }
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the IL2CPP row limit"));
    }
    Ok(rows)
}
fn requested_case_folding(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_object)
        .and_then(|object| {
            object
                .get("case_fold")
                .or_else(|| object.get("case_insensitive"))
        })
        .and_then(Value::as_bool)
        .unwrap_or(false)
}
fn number(object: &Map<String, Value>, fields: &[&str]) -> (Option<u64>, bool) {
    let values = fields
        .iter()
        .filter_map(|field| object.get(*field).and_then(parse_u64))
        .collect::<Vec<_>>();
    let value = values.first().copied();
    let conflicted = values.iter().any(|candidate| Some(*candidate) != value);
    (value, conflicted)
}
fn text(object: &Map<String, Value>, fields: &[&str]) -> (Option<String>, bool) {
    let values = fields
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        })
        .collect::<Vec<_>>();
    let value = values.first().cloned();
    let conflicted = values
        .iter()
        .any(|candidate| Some(candidate) != value.as_ref());
    (value, conflicted)
}
fn parse_u64(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| {
        let text = value.as_str()?.trim();
        text.strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .map_or_else(
                || text.parse::<u64>().ok(),
                |digits| u64::from_str_radix(digits, 16).ok(),
            )
    })
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "IL2CPP assembly correlation input is invalid.".into(),
        false,
        "Supply exact metadata image and CodeGenModule identities and retry.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (String::from("field"), Detail::Text(field.into())),
            (String::from("reason"), Detail::Text(reason.into())),
        ]),
    )
}
