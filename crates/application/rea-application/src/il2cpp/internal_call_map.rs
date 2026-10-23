//! Projection of captured IL2CPP internal-call registries.
//!
//! This module joins facts that an adapter has already decoded.  It never asks
//! the host to resolve an internal call, loads a native image, or executes a
//! managed method.  Registry spelling, address representation, and optional
//! architecture identity are retained in every projected item.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "map_il2cpp_internal_calls";
const MAX_ROWS: usize = 200_000;

/// Project caller-supplied internal-call rows against caller-supplied managed
/// signature rows.  Matching is exact and case-sensitive.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let registry = rows_from_aliases(
        binary,
        &[
            "internal_calls",
            "internal_call_registry",
            "registry",
            "calls",
        ],
        "internal_calls",
    )?;
    let methods = optional_rows_from_aliases(
        metadata,
        &[
            "methods",
            "managed_methods",
            "signatures",
            "managed_signatures",
        ],
        "methods",
    )?;
    let expected_architecture = root.get("architecture");

    let method_index = index_methods(methods)?;
    let method_identity_index = index_method_metadata_indices(methods)?;
    let address_names = index_address_names(registry)?;
    let mut items = Vec::with_capacity(registry.len());
    let mut counts = Counts::default();
    let mut unresolved_names = Vec::new();
    let mut unresolved_name_set = BTreeSet::new();

    for (row, registry_row) in registry.iter().enumerate() {
        let object = registry_row
            .as_object()
            .ok_or_else(|| invalid_row("internal_calls", row, "Expected an object"))?;
        let (name, name_alias_conflict) = string_alias_with_conflict(
            object,
            &["name", "internal_call", "mangled_name", "symbol"],
        );
        let (address, address_alias_conflict) = address_alias_with_conflict(object);
        let (signature, signature_alias_conflict) = string_alias_with_conflict(
            object,
            &[
                "signature",
                "managed_signature",
                "method_signature",
                "type_signature",
            ],
        );
        let (calling_convention, calling_convention_alias_conflict) = string_alias_with_conflict(
            object,
            &["calling_convention", "call_convention", "callingConvention"],
        );
        let (module, module_alias_conflict) =
            string_alias_with_conflict(object, &["module", "module_name", "image", "assembly"]);
        let (method_metadata_index, method_metadata_index_conflict) = numeric_alias_with_conflict(
            object,
            &[
                "method_index",
                "metadata_index",
                "method_metadata_index",
                "methodIndex",
                "metadataIndex",
            ],
        );
        let row_architecture = object.get("architecture");
        let architecture_matches = match (expected_architecture, row_architecture) {
            (Some(expected), Some(actual)) => expected == actual,
            _ => true,
        };
        let name_rows = name
            .as_deref()
            .and_then(|value| method_index.get(value))
            .cloned()
            .unwrap_or_default();
        let name_rows = narrow_method_matches(
            name_rows,
            method_metadata_index,
            method_metadata_index
                .and_then(|index| method_identity_index.get(&index))
                .map(Vec::as_slice),
        );
        let name_duplicate = name
            .as_deref()
            .is_some_and(|value| address_names.name_count(value) > 1);
        let address_duplicate = address
            .as_ref()
            .and_then(address_key)
            .is_some_and(|value| address_names.address_count(&value) > 1);
        let identity = Identity {
            signature: signature.as_deref(),
            calling_convention: calling_convention.as_deref(),
            module: module.as_deref(),
        };
        let identity_alias_conflict =
            signature_alias_conflict || calling_convention_alias_conflict || module_alias_conflict;
        let identity_matches = name_rows
            .iter()
            .filter(|(_, method_row)| identity.matches(method_row))
            .count();
        let method_identity_alias_conflict = name_rows
            .iter()
            .any(|(_, method_row)| has_identity_alias_conflict(method_row));
        let method_call_name_alias_conflict = name_rows.iter().any(|(_, method_row)| {
            method_row
                .as_object()
                .is_some_and(method_call_name_alias_conflict)
        });
        let identity_mismatch =
            !name_rows.is_empty() && identity.has_values() && identity_matches == 0;

        let resolution = classify(
            name.as_deref(),
            address.as_ref(),
            &name_rows,
            name_duplicate,
            address_duplicate,
            name_alias_conflict || address_alias_conflict,
            method_metadata_index_conflict,
            architecture_matches,
            identity_alias_conflict,
            method_identity_alias_conflict,
            method_call_name_alias_conflict,
            identity_mismatch,
            identity_matches,
        );
        counts.record(resolution);
        if matches!(resolution, "unresolved" | "unknown") {
            if let Some(name) = name.as_ref() {
                if unresolved_name_set.insert(name.clone()) {
                    unresolved_names.push(name.clone());
                }
            }
        }

        let mut item = Map::new();
        item.insert("registry_row".into(), registry_row.clone());
        item.insert("name".into(), name.map_or(Value::Null, Value::String));
        item.insert("address".into(), address.clone().unwrap_or(Value::Null));
        item.insert(
            "signature".into(),
            signature.clone().map_or(Value::Null, Value::String),
        );
        item.insert(
            "calling_convention".into(),
            calling_convention
                .clone()
                .map_or(Value::Null, Value::String),
        );
        item.insert(
            "module".into(),
            module.clone().map_or(Value::Null, Value::String),
        );
        item.insert(
            "name_alias_conflict".into(),
            Value::Bool(name_alias_conflict),
        );
        item.insert(
            "address_alias_conflict".into(),
            Value::Bool(address_alias_conflict),
        );
        item.insert(
            "signature_alias_conflict".into(),
            Value::Bool(signature_alias_conflict),
        );
        item.insert(
            "calling_convention_alias_conflict".into(),
            Value::Bool(calling_convention_alias_conflict),
        );
        item.insert(
            "module_alias_conflict".into(),
            Value::Bool(module_alias_conflict),
        );
        item.insert("identity_mismatch".into(), Value::Bool(identity_mismatch));
        item.insert(
            "matching_identity_methods".into(),
            Value::Array(
                name_rows
                    .iter()
                    .filter(|(_, value)| identity.matches(value))
                    .map(|(row, _)| Value::from(*row))
                    .collect(),
            ),
        );
        item.insert(
            "architecture".into(),
            row_architecture.cloned().unwrap_or(Value::Null),
        );
        item.insert(
            "architecture_matches".into(),
            Value::Bool(architecture_matches),
        );
        item.insert("resolution".into(), Value::String(resolution.into()));
        item.insert(
            "matching_methods".into(),
            Value::Array(name_rows.iter().map(|(row, _)| Value::from(*row)).collect()),
        );
        item.insert(
            "matching_method_rows".into(),
            Value::Array(
                name_rows
                    .iter()
                    .map(|(_, value)| (*value).clone())
                    .collect(),
            ),
        );
        items.push(Value::Object(item));
    }

    Ok(serde_json::json!({
        "status": if counts.ambiguous > 0 || counts.unresolved > 0 || counts.unknown > 0 { "partial" } else { "complete" },
        "items": items,
        "architecture": expected_architecture.cloned().unwrap_or(Value::Null),
        "coverage": {
            "registry_rows": registry.len(),
            "managed_method_rows": methods.len(),
            "resolved": counts.resolved,
            "ambiguous": counts.ambiguous,
            "unresolved": counts.unresolved,
            "unknown": counts.unknown,
            "unresolved_names": unresolved_names,
        }
    }))
}

#[derive(Default)]
struct Counts {
    resolved: usize,
    ambiguous: usize,
    unresolved: usize,
    unknown: usize,
}

impl Counts {
    fn record(&mut self, resolution: &str) {
        match resolution {
            "resolved" => self.resolved += 1,
            "ambiguous" => self.ambiguous += 1,
            "unresolved" => self.unresolved += 1,
            _ => self.unknown += 1,
        }
    }
}

type MethodMatch<'a> = (usize, &'a Value);

struct Identity<'a> {
    signature: Option<&'a str>,
    calling_convention: Option<&'a str>,
    module: Option<&'a str>,
}

impl Identity<'_> {
    fn has_values(&self) -> bool {
        self.signature.is_some() || self.calling_convention.is_some() || self.module.is_some()
    }

    fn matches(&self, value: &Value) -> bool {
        let Some(object) = value.as_object() else {
            return false;
        };

        matches_alias(
            object,
            self.signature,
            &[
                "signature",
                "managed_signature",
                "method_signature",
                "type_signature",
            ],
        ) && matches_alias(
            object,
            self.calling_convention,
            &["calling_convention", "call_convention", "callingConvention"],
        ) && matches_alias(
            object,
            self.module,
            &["module", "module_name", "image", "assembly"],
        )
    }
}

fn matches_alias(object: &Map<String, Value>, expected: Option<&str>, aliases: &[&str]) -> bool {
    let Some(expected) = expected else {
        return true;
    };

    let mut found = false;
    for alias in aliases {
        let Some(value) = object.get(*alias).and_then(Value::as_str) else {
            continue;
        };

        found = true;
        if value != expected {
            return false;
        }
    }

    found
}

fn has_identity_alias_conflict(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };

    let string_conflict = [
        [
            "signature",
            "managed_signature",
            "method_signature",
            "type_signature",
        ]
        .as_slice(),
        ["calling_convention", "call_convention", "callingConvention"].as_slice(),
        ["module", "module_name", "image", "assembly"].as_slice(),
    ]
    .into_iter()
    .any(|aliases| alias_values_conflict(object, aliases));

    string_conflict || numeric_alias_with_conflict(object, &method_index_aliases()).1
}

fn alias_values_conflict(object: &Map<String, Value>, aliases: &[&str]) -> bool {
    let mut selected = None;
    for alias in aliases {
        let Some(raw_value) = object.get(*alias) else {
            continue;
        };
        let Some(value) = raw_value.as_str().filter(|value| !value.is_empty()) else {
            return true;
        };

        if selected.is_some_and(|existing| existing != value) {
            return true;
        }
        selected = Some(value);
    }
    false
}

fn index_methods<'a>(rows: &'a [Value]) -> Result<BTreeMap<String, Vec<MethodMatch<'a>>>, Failure> {
    let mut index = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("methods", row, "Expected an object"))?;
        for name in method_call_names(object) {
            index
                .entry(name)
                .or_insert_with(Vec::new)
                .push((row, value));
        }
    }
    Ok(index)
}

/// Return the spellings used by IL2CPP's internal-call registry for a method.
///
/// Captured metadata commonly stores the method name and declaring type in
/// separate fields, whereas the runtime registry uses `Type::Method` (with an
/// optional namespace).  Keep the source-provided aliases and add only the
/// canonical joined forms when all required pieces are present.
fn method_call_names(object: &Map<String, Value>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();

    if let Some(name) = consistent_string_alias(
        object,
        &["internal_call", "internal_call_name", "name", "symbol"],
    ) {
        names.insert(name);
    }

    // Metadata producers use both explicit aliases and the generic `name`
    // field.  If present aliases disagree, the canonical spelling is
    // unknown; selecting by alias order could attribute the row to the wrong
    // managed method.
    let method_name = consistent_string_alias(object, &["method_name", "name"]);
    let type_name = consistent_string_alias(
        object,
        &[
            "declaring_type_name",
            "declaring_type",
            "type_name",
            "class_name",
            "owner_name",
        ],
    );
    let Some(method_name) = method_name else {
        return names;
    };
    let Some(type_name) = type_name else {
        return names;
    };

    let namespace = consistent_string_alias(object, &["namespace", "declaring_namespace"]);
    let qualified_type = namespace
        .filter(|value| !value.is_empty())
        .map(|value| format!("{value}.{type_name}"))
        .unwrap_or(type_name);
    names.insert(format!("{qualified_type}::{method_name}"));

    names
}

fn method_call_name_alias_conflict(object: &Map<String, Value>) -> bool {
    alias_values_conflict(
        object,
        &["internal_call", "internal_call_name", "name", "symbol"],
    )
}

/// Return one non-empty string when all present aliases agree.
///
/// Missing aliases are valid because captures use several row shapes.
/// Malformed or conflicting aliases leave the canonical spelling unknown so
/// callers retain the row as unresolved instead of guessing.
fn consistent_string_alias(object: &Map<String, Value>, aliases: &[&str]) -> Option<String> {
    let mut selected = None;

    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let Some(value) = value.as_str().filter(|value| !value.is_empty()) else {
            return None;
        };

        if selected
            .as_deref()
            .is_some_and(|existing| existing != value)
        {
            return None;
        }
        selected = Some(value.to_owned());
    }

    selected
}

fn index_method_metadata_indices<'a>(
    rows: &'a [Value],
) -> Result<BTreeMap<u64, Vec<MethodMatch<'a>>>, Failure> {
    let mut index = BTreeMap::new();

    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("methods", row, "Expected an object"))?;
        let (metadata_index, alias_conflict) =
            numeric_alias_with_conflict(object, &method_index_aliases());
        if alias_conflict {
            continue;
        }
        let Some(metadata_index) = metadata_index else {
            continue;
        };

        index
            .entry(metadata_index)
            .or_insert_with(Vec::new)
            .push((row, value));
    }

    Ok(index)
}

fn narrow_method_matches<'a>(
    name_rows: Vec<MethodMatch<'a>>,
    method_metadata_index: Option<u64>,
    indexed_rows: Option<&[MethodMatch<'a>]>,
) -> Vec<MethodMatch<'a>> {
    let Some(_) = method_metadata_index else {
        return name_rows;
    };
    let Some(indexed_rows) = indexed_rows else {
        return Vec::new();
    };

    name_rows
        .into_iter()
        .filter(|(row, _)| {
            indexed_rows
                .iter()
                .any(|(indexed_row, _)| indexed_row == row)
        })
        .collect()
}

fn method_index_aliases() -> [&'static str; 6] {
    [
        "method_index",
        "metadata_index",
        "method_metadata_index",
        "methodIndex",
        "metadataIndex",
        "index",
    ]
}

fn numeric_alias_with_conflict(
    object: &Map<String, Value>,
    aliases: &[&str],
) -> (Option<u64>, bool) {
    let mut selected = None;
    let mut conflict = false;

    for alias in aliases {
        let Some(raw_value) = object.get(*alias) else {
            continue;
        };
        if raw_value.is_null() {
            continue;
        }
        let Some(value) = raw_value.as_u64() else {
            conflict = true;
            continue;
        };

        if let Some(existing) = selected {
            if existing != value {
                conflict = true;
            }
        } else {
            selected = Some(value);
        }
    }

    (selected, conflict)
}

#[derive(Default)]
struct AddressNames {
    names: BTreeMap<String, usize>,
    addresses: BTreeMap<String, usize>,
}

impl AddressNames {
    fn name_count(&self, value: &str) -> usize {
        self.names.get(value).copied().unwrap_or(0)
    }
    fn address_count(&self, value: &str) -> usize {
        self.addresses.get(value).copied().unwrap_or(0)
    }
}

fn index_address_names(rows: &[Value]) -> Result<AddressNames, Failure> {
    let mut index = AddressNames::default();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("internal_calls", row, "Expected an object"))?;
        if let Some(name) =
            string_alias(object, &["name", "internal_call", "mangled_name", "symbol"])
        {
            *index.names.entry(name).or_default() += 1;
        }
        if let Some(address) = address_value(object).as_ref().and_then(address_key) {
            *index.addresses.entry(address).or_default() += 1;
        }
    }
    Ok(index)
}

fn classify(
    name: Option<&str>,
    address: Option<&Value>,
    methods: &[MethodMatch<'_>],
    duplicate_name: bool,
    duplicate_address: bool,
    alias_conflict: bool,
    method_metadata_index_conflict: bool,
    architecture_matches: bool,
    identity_alias_conflict: bool,
    method_identity_alias_conflict: bool,
    method_call_name_alias_conflict: bool,
    identity_mismatch: bool,
    identity_matches: usize,
) -> &'static str {
    if !architecture_matches {
        return "unknown";
    }
    if duplicate_name
        || duplicate_address
        || alias_conflict
        || identity_alias_conflict
        || method_identity_alias_conflict
        || method_call_name_alias_conflict
        || method_metadata_index_conflict
        || methods.len() > 1 && identity_matches != 1
        || identity_matches > 1
    {
        return "ambiguous";
    }
    if address.is_none() {
        return "unknown";
    }
    if name.is_none() || methods.is_empty() || identity_mismatch {
        return "unresolved";
    }
    "resolved"
}

fn rows_from_aliases<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let value = aliases.iter().find_map(|alias| object.get(*alias));
    let rows = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the internal-call row limit",
        ));
    }
    Ok(rows)
}

fn optional_rows_from_aliases<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    match aliases.iter().find_map(|alias| object.get(*alias)) {
        None => Ok(&[]),
        Some(value) => {
            let rows = value
                .as_array()
                .ok_or_else(|| invalid(field, "Expected an array"))?;
            if rows.len() > MAX_ROWS {
                return Err(invalid(
                    field,
                    "Collection exceeds the managed-method row limit",
                ));
            }
            Ok(rows)
        }
    }
}

fn string_alias(object: &Map<String, Value>, aliases: &[&str]) -> Option<String> {
    aliases.iter().find_map(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .map(str::to_owned)
    })
}

fn string_alias_with_conflict(
    object: &Map<String, Value>,
    aliases: &[&str],
) -> (Option<String>, bool) {
    let mut selected = None;
    let mut conflict = false;

    for field in aliases {
        let Some(raw_value) = object.get(*field) else {
            continue;
        };
        let Some(value) = raw_value.as_str() else {
            conflict = true;
            continue;
        };
        if value.is_empty() {
            conflict = true;
        }

        if let Some(existing) = selected.as_ref() {
            if existing != value {
                conflict = true;
            }
        } else {
            selected = Some(value.to_owned());
        }
    }

    (selected, conflict)
}

fn address_value(object: &Map<String, Value>) -> Option<Value> {
    ["address", "pointer", "method_pointer", "native_address"]
        .iter()
        .find_map(|field| object.get(*field).cloned())
}

fn address_alias_with_conflict(object: &Map<String, Value>) -> (Option<Value>, bool) {
    let mut selected = None;
    let mut conflict = false;

    for field in ["address", "pointer", "method_pointer", "native_address"] {
        let Some(value) = object.get(field) else {
            continue;
        };

        if let Some(existing) = selected.as_ref() {
            if existing != value {
                conflict = true;
            }
        } else {
            selected = Some(value.clone());
        }
    }

    (selected, conflict)
}

fn address_key(value: &Value) -> Option<String> {
    (!value.is_null()).then(|| value.to_string())
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP internal-call mapping input is invalid.".into(),
        false,
        "Supply captured internal-call rows and optional managed signatures and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
