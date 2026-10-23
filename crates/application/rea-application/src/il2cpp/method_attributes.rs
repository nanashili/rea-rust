//! Decode caller-supplied IL2CPP method attribute bit fields.
//!
//! This module owns no metadata or binary reader.  It only interprets the
//! `MethodAttributes` and `MethodImplAttributes` integers already established
//! by an upstream parser, retaining both raw values and bits that this
//! version does not understand.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_il2cpp_method_attributes";
const MAX_ROWS: usize = 200_000;

const MEMBER_ACCESS_MASK: u16 = 0x0007;
const KNOWN_METHOD_BITS: u16 = 0xffff;
const KNOWN_IMPL_BITS: u16 = 0x177f;
const MAX_SAFE_INDEX: i64 = 9_007_199_254_740_991;
const MIN_SAFE_INDEX: i64 = -MAX_SAFE_INDEX;

/// Decode method rows from a normalized, caller-supplied report.
///
/// Rows may be supplied directly as `methods`, beneath `metadata.methods`, or
/// under the aliases `method_definitions` and `metadata_methods`.  Each row
/// must provide `method_attributes` (or `attributes`) and
/// `method_impl_attributes` (or `impl_attributes`).  An explicit
/// `declaring_type` is carried through as ownership evidence; absent or
/// conflicting ownership remains unresolved rather than being inferred from
/// row order.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let rows = ["methods", "method_definitions", "metadata_methods"]
        .iter()
        .find_map(|name| metadata.get(*name))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("methods", "Expected an array of parsed method rows"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "methods",
            "Collection exceeds the method row limit",
        ));
    }

    let metadata_version = metadata_version(root, metadata);

    let mut items = Vec::with_capacity(rows.len());
    let mut unresolved_owners = 0usize;
    let mut ambiguous_owners = 0usize;
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row(row, "Expected a method row object"))?;
        let method_raw = raw_field(
            object,
            &["method_attributes", "methodAttributes", "attributes"],
            row,
            "method_attributes",
        )?;
        let impl_raw = raw_field(
            object,
            &[
                "method_impl_attributes",
                "methodImplAttributes",
                "impl_attributes",
                "implAttributes",
            ],
            row,
            "method_impl_attributes",
        )?;
        let owner = owner_projection(object);
        let owner_status = owner_status(&owner);
        if owner_status != "resolved" {
            unresolved_owners += 1;
        }
        if owner_status == "ambiguous" {
            ambiguous_owners += 1;
        }
        let method_name = explicit_method_name(object);
        items.push(json!({
            "row": value,
            "owner": owner,
            "owner_status": owner_status,
            "method_attributes": decode_method_attributes(method_raw, method_name.as_deref(), metadata_version),
            "method_impl_attributes": decode_impl_attributes(impl_raw, metadata_version),
        }));
    }

    Ok(json!({
        "operation": OPERATION,
        "metadata_version": metadata_version,
        "items": items,
        "coverage": {
            "methods": rows.len(),
            "decoded": rows.len(),
            "unresolved_owners": unresolved_owners,
            "ambiguous_owners": ambiguous_owners
        },
        "limitations": [
            "Flag names follow the ECMA-335 MethodAttributes and MethodImplAttributes bit assignments.",
            "Unknown bits are retained and are not assigned a guessed semantic."
        ]
    }))
}

fn metadata_version(root: &Map<String, Value>, metadata: &Map<String, Value>) -> Option<u32> {
    ["metadata_version", "metadataVersion", "version"]
        .iter()
        .find_map(|name| metadata.get(*name).or_else(|| root.get(*name)))
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
}

fn explicit_method_name(object: &Map<String, Value>) -> Option<String> {
    let names = ["method_name", "methodName", "name"];
    let mut values = BTreeSet::new();
    let mut malformed = false;
    for name in names {
        let Some(value) = object.get(name) else {
            continue;
        };
        let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
            malformed = true;
            continue;
        };
        values.insert(value);
    }

    if malformed || values.len() != 1 {
        return None;
    }
    values.into_iter().next().map(str::to_owned)
}

fn raw_field(
    object: &Map<String, Value>,
    names: &[&str],
    row: usize,
    label: &str,
) -> Result<u16, Failure> {
    let mut values = BTreeSet::new();
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let value = nested_raw_value(value, row, label)?;
        let raw = value
            .as_u64()
            .ok_or_else(|| invalid_row(row, &format!("{label} must be an unsigned integer")))?;
        let raw = u16::try_from(raw)
            .map_err(|_| invalid_row(row, &format!("{label} must fit in 16 bits")))?;
        values.insert(raw);
    }

    match values.len() {
        0 => Err(invalid_row(row, &format!("Missing {label}"))),
        1 => Ok(*values.first().expect("one value is present")),
        _ => Err(invalid_row(
            row,
            &format!("Conflicting aliases supplied for {label}"),
        )),
    }
}

fn nested_raw_value<'a>(value: &'a Value, row: usize, label: &str) -> Result<&'a Value, Failure> {
    let Some(object) = value.as_object() else {
        return Ok(value);
    };

    let raw = object.get("raw");
    let value_alias = object.get("value");
    if let (Some(raw), Some(value_alias)) = (raw, value_alias) {
        if raw != value_alias {
            return Err(invalid_row(
                row,
                &format!("Conflicting raw and value aliases supplied for {label}"),
            ));
        }
    }

    Ok(raw.or(value_alias).unwrap_or(value))
}

fn owner_projection(object: &Map<String, Value>) -> Value {
    let mut candidates = BTreeSet::new();
    let mut invalid_claims = Vec::new();

    let aliases = [
        "declaring_type",
        "declaringType",
        "owner_type_index",
        "ownerTypeIndex",
    ];
    let mut sources = vec![object];
    for name in [
        "member_identity",
        "memberIdentity",
        "method_identity",
        "methodIdentity",
    ] {
        if let Some(identity) = object.get(name).and_then(Value::as_object) {
            sources.push(identity);
        }
    }

    for source in sources {
        for name in aliases {
            let Some(value) = source.get(name) else {
                continue;
            };
            if let Some(index) = value.as_i64() {
                if (MIN_SAFE_INDEX..=MAX_SAFE_INDEX).contains(&index) {
                    candidates.insert(index);
                } else {
                    invalid_claims.push(value.clone());
                }
            } else {
                invalid_claims.push(value.clone());
            }
        }
    }

    if !invalid_claims.is_empty() {
        return json!({ "invalid_claims": invalid_claims });
    }

    match candidates.len() {
        0 => Value::Null,
        1 => json!({ "kind": "type", "index": candidates.into_iter().next() }),
        _ => json!({
            "kind": "type",
            "indices": candidates.into_iter().collect::<Vec<_>>()
        }),
    }
}

fn owner_status(owner: &Value) -> &'static str {
    let Some(object) = owner.as_object() else {
        return "unknown";
    };
    if object.get("invalid_claims").is_some() {
        return "invalid";
    }
    if object.get("indices").is_some() {
        return "ambiguous";
    }
    match object.get("index").and_then(Value::as_i64) {
        Some(index) if index >= 0 => "resolved",
        // Metadata uses -1 as the explicit sentinel for an absent declaring
        // type. Preserve that distinction as unknown rather than treating a
        // valid unresolved claim as malformed input.
        Some(-1) => "unknown",
        Some(_) => "invalid",
        None => "unknown",
    }
}

fn decode_method_attributes(
    raw: u16,
    method_name: Option<&str>,
    metadata_version: Option<u32>,
) -> Value {
    let member_access = match raw & MEMBER_ACCESS_MASK {
        0 => "private_scope",
        1 => "private",
        2 => "fam_and_assem",
        3 => "assembly",
        4 => "family",
        5 => "fam_or_assem",
        6 => "public",
        _ => "unknown",
    };
    let constructor = constructor_projection(method_name);
    json!({
        "raw": raw,
        "member_access_raw": raw & MEMBER_ACCESS_MASK,
        "member_access": member_access,
        "unmanaged_export": raw & 0x0008 != 0,
        "static": raw & 0x0010 != 0,
        "final": raw & 0x0020 != 0,
        "virtual": raw & 0x0040 != 0,
        "hide_by_sig": raw & 0x0080 != 0,
        "new_slot": raw & 0x0100 != 0,
        "check_access_on_override": raw & 0x0200 != 0,
        "abstract": raw & 0x0400 != 0,
        "special_name": raw & 0x0800 != 0,
        "runtime_special_name": raw & 0x1000 != 0,
        "pinvoke_impl": raw & 0x2000 != 0,
        "has_security": raw & 0x4000 != 0,
        "require_sec_object": raw & 0x8000 != 0,
        "flag_projection": {
            "visibility": member_access,
            "is_static": raw & 0x0010 != 0,
            "is_virtual": raw & 0x0040 != 0,
            "is_abstract": raw & 0x0400 != 0,
            "is_final": raw & 0x0020 != 0,
            "is_constructor": constructor["is_constructor"],
            "constructor_kind": constructor["constructor_kind"],
            "metadata_version": metadata_version,
            "version_scope": "ecma_335_method_attributes"
        },
        "unknown_bits": u16::from(raw & !KNOWN_METHOD_BITS)
    })
}

fn decode_impl_attributes(raw: u16, metadata_version: Option<u32>) -> Value {
    let code_type = match raw & 0x0003 {
        0 => "il",
        1 => "native",
        2 => "optil",
        _ => "runtime",
    };
    json!({
        "raw": raw,
        "code_type": code_type,
        "managed": raw & 0x0004 == 0,
        "unmanaged": raw & 0x0004 != 0,
        "no_inlining": raw & 0x0008 != 0,
        "forward_ref": raw & 0x0010 != 0,
        "synchronized": raw & 0x0020 != 0,
        "no_optimization": raw & 0x0040 != 0,
        "preserve_sig": raw & 0x0080 != 0,
        "aggressive_inlining": raw & 0x0100 != 0,
        "aggressive_optimization": raw & 0x0200 != 0,
        "internal_call": raw & 0x1000 != 0,
        "flag_projection": {
            "code_type": code_type,
            "is_managed": raw & 0x0004 == 0,
            "no_inlining": raw & 0x0008 != 0,
            "forward_ref": raw & 0x0010 != 0,
            "synchronized": raw & 0x0020 != 0,
            "no_optimization": raw & 0x0040 != 0,
            "preserve_signature": raw & 0x0080 != 0,
            "aggressive_inlining": raw & 0x0100 != 0,
            "aggressive_optimization": raw & 0x0200 != 0,
            "internal_call": raw & 0x1000 != 0,
            "metadata_version": metadata_version,
            "version_scope": "ecma_335_method_impl_attributes"
        },
        "unknown_bits": u16::from(raw & !KNOWN_IMPL_BITS)
    })
}

fn constructor_projection(method_name: Option<&str>) -> Value {
    match method_name {
        Some(".ctor") => json!({ "is_constructor": true, "constructor_kind": "instance" }),
        Some(".cctor") => json!({ "is_constructor": true, "constructor_kind": "static" }),
        Some(_) => json!({ "is_constructor": false, "constructor_kind": Value::Null }),
        None => json!({ "is_constructor": Value::Null, "constructor_kind": Value::Null }),
    }
}

fn invalid_row(row: usize, reason: &str) -> Failure {
    invalid(&format!("methods[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP method attributes input is invalid.".into(),
        false,
        "Supply parsed method rows with 16-bit attribute values and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
