//! Build a caller-ordered native selector plan for closed IL2CPP generics.
//!
//! This module only joins already-normalized projections.  It does not infer
//! a native implementation from a managed name, and it keeps every unresolved
//! or ambiguous row beside the selectors that can safely be sent to a host
//! provider.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "plan_il2cpp_generic_decompilation";
const MAX_ROWS: usize = 200_000;

/// Produce a stable selector list from MethodSpec, generic-method, and
/// method-address projections.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let method_specs = rows(root, &["method_specs", "methodSpecs"], "method_specs")?;
    let generic_methods = rows(
        root,
        &["generic_methods", "genericMethods", "generic_method_map"],
        "generic_methods",
    )?;
    let method_addresses = rows(
        root,
        &[
            "method_addresses",
            "methodAddressMappings",
            "method_address_map",
        ],
        "method_addresses",
    )?;

    let mut selectors = Vec::new();
    let mut unresolved = Vec::new();

    for (index, spec) in method_specs.iter().enumerate() {
        let spec_object = spec
            .as_object()
            .ok_or_else(|| invalid_row("method_specs", index, "Expected an object"))?;
        let spec_index_claim = index_claim(
            spec_object,
            &["method_spec_index", "methodSpecIndex", "index"],
        );
        let generic_index_claim = index_claim(
            spec_object,
            &[
                "generic_method_index",
                "genericMethodIndex",
                "generic_index",
            ],
        );
        let spec_index = spec_index_claim.value();
        let generic_index = generic_index_claim.value();
        let generic_match = unique_match(
            generic_methods,
            spec_index_claim,
            generic_index_claim,
            |row| nested_index(row, "generic_method", &["generic_method_index", "index"]),
        );
        let address_match = unique_match(
            method_addresses,
            spec_index_claim,
            generic_index_claim,
            |row| nested_index(row, "method_mapping", &["method_spec_index", "index"]),
        );

        let reason = match (spec_index, &generic_match, &address_match) {
            (None, _, _) if spec_index_claim.is_missing() => {
                Some("MethodSpec has no stable method_spec_index.")
            }
            (None, _, _) => Some("MethodSpec method_spec_index aliases conflict."),
            (_, _, _) if generic_index_claim.is_conflicting() => {
                Some("MethodSpec generic_method_index aliases conflict.")
            }
            (_, Match::Missing, _) => Some("No generic-method projection matches this MethodSpec."),
            (_, Match::Ambiguous, _) | (_, _, Match::Ambiguous) => {
                Some("Multiple normalized rows match this generic MethodSpec.")
            }
            (_, Match::Found(generic), Match::Missing) => {
                let _ = generic;
                Some("No native method-address mapping matches this generic MethodSpec.")
            }
            (_, Match::Found(generic), Match::Found(address)) => {
                if !is_closed(spec_object, generic) {
                    Some("Generic arguments remain open or unresolved.")
                } else if !mapped_address(address) {
                    Some("Native method address is unknown or ambiguous.")
                } else {
                    None
                }
            }
        };

        if let Some(reason) = reason {
            unresolved.push(json!({
                "input_index": index,
                "method_spec": spec,
                "method_spec_index": spec_index,
                "generic_method_index": generic_index,
                "status": "unknown",
                "reason": reason,
            }));
            continue;
        }

        let generic = match generic_match {
            Match::Found(value) => value,
            _ => unreachable!("validated generic match"),
        };
        let address = match address_match {
            Match::Found(value) => value,
            _ => unreachable!("validated address match"),
        };
        let native_address = address_value(address).expect("validated native address");
        selectors.push(json!({
            "input_index": index,
            "selector": native_address,
            "address": native_address,
            "method_spec_index": spec_index,
            "generic_method_index": generic_index,
            "method_spec": spec,
            "generic_method": generic,
            "method_address": address,
            "status": "resolved",
        }));
    }

    let status = if unresolved.is_empty() {
        "complete"
    } else {
        "partial"
    };
    Ok(json!({
        "operation": OPERATION,
        "status": status,
        "selectors": selectors,
        "unresolved": unresolved,
        "coverage": {
            "method_specs": method_specs.len(),
            "selectors": selectors.len(),
            "unresolved": unresolved.len(),
        },
        "limitations": [
            "Only explicitly closed generic arguments produce native selectors.",
            "Native addresses are accepted only from an unambiguous normalized mapping."
        ]
    }))
}

pub fn plan(input: &Value) -> Result<Value, Failure> {
    project(input)
}

enum Match<'a> {
    Missing,
    Ambiguous,
    Found(&'a Value),
}

fn unique_match<'a, F>(
    rows: &'a [Value],
    method_spec_index: IndexClaim,
    generic_method_index: IndexClaim,
    nested: F,
) -> Match<'a>
where
    F: Fn(&Value) -> (IndexClaim, IndexClaim),
{
    let mut found = None;
    let mut conflicting = false;
    for row in rows {
        let object = match row.as_object() {
            Some(object) => object,
            None => continue,
        };
        let direct_spec = index_claim(object, &["method_spec_index", "methodSpecIndex"]);
        let direct_generic = index_claim(
            object,
            &[
                "generic_method_index",
                "genericMethodIndex",
                "generic_index",
            ],
        );
        let (nested_spec, nested_generic) = nested(row);
        let (spec_matches, spec_conflict) =
            identity_match(method_spec_index, direct_spec, nested_spec);
        let (generic_matches, generic_conflict) =
            identity_match(generic_method_index, direct_generic, nested_generic);
        if !(spec_matches || generic_matches) {
            continue;
        }
        if spec_conflict || generic_conflict {
            conflicting = true;
            continue;
        }
        if found.is_some() {
            return Match::Ambiguous;
        }
        found = Some(row);
    }
    if conflicting {
        return Match::Ambiguous;
    }
    found.map_or(Match::Missing, Match::Found)
}

fn identity_match(wanted: IndexClaim, direct: IndexClaim, nested: IndexClaim) -> (bool, bool) {
    let direct_value = direct.value();
    let nested_value = nested.value();
    let matches = match wanted.value() {
        Some(expected) => direct_value == Some(expected) || nested_value == Some(expected),
        None => false,
    };
    let aliases_conflict = direct.is_conflicting()
        || nested.is_conflicting()
        || direct_value
            .zip(nested_value)
            .is_some_and(|(left, right)| left != right);
    let requested_value_conflicts = wanted.value().is_some_and(|expected| {
        direct_value
            .or(nested_value)
            .is_some_and(|actual| expected != actual)
    });
    (
        matches,
        aliases_conflict || requested_value_conflicts || wanted.is_conflicting(),
    )
}

fn is_closed(spec: &Map<String, Value>, generic: &Value) -> bool {
    let Some(generic_object) = generic.as_object() else {
        return false;
    };
    let instance = match generic_object.get("generic_instance") {
        Some(Value::Object(instance)) => Some(instance),
        Some(Value::Null) | None => None,
        Some(_) => return false,
    };

    let flags = [Some(spec), Some(generic_object), instance]
        .into_iter()
        .flatten()
        .map(closed_flag)
        .collect::<Vec<_>>();
    if flags.iter().any(|flag| *flag == AliasValue::Conflict)
        || flags.iter().any(|flag| *flag == AliasValue::Value(false))
    {
        return false;
    }
    let explicitly_closed = flags.iter().any(|flag| *flag == AliasValue::Value(true));

    let mut selected_arguments = None;
    for object in [Some(generic_object), instance, Some(spec)]
        .into_iter()
        .flatten()
    {
        match method_argument_claim(object) {
            AliasValue::Missing => {}
            AliasValue::Conflict => return false,
            AliasValue::Value(arguments) => {
                if selected_arguments
                    .as_ref()
                    .is_some_and(|existing| existing != &arguments)
                {
                    return false;
                }
                selected_arguments = Some(arguments);
            }
        }
    }

    let Some(arguments) = selected_arguments else {
        return explicitly_closed;
    };
    argument_list_is_resolved(&arguments)
        && (explicitly_closed || argument_list(&arguments).is_some_and(|items| !items.is_empty()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AliasValue<T> {
    Missing,
    Value(T),
    Conflict,
}

fn closed_flag(object: &Map<String, Value>) -> AliasValue<bool> {
    let mut selected = None;
    for field in ["closed", "is_closed"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Some(value) = value.as_bool() else {
            return AliasValue::Conflict;
        };
        if selected.is_some_and(|existing| existing != value) {
            return AliasValue::Conflict;
        }
        selected = Some(value);
    }
    selected.map_or(AliasValue::Missing, AliasValue::Value)
}

fn method_argument_claim(object: &Map<String, Value>) -> AliasValue<Value> {
    let mut selected = None;
    for field in ["method_arguments", "generic_arguments", "arguments"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        if selected
            .as_ref()
            .is_some_and(|existing: &Value| existing != value)
        {
            return AliasValue::Conflict;
        }
        selected = Some(value.clone());
    }
    selected.map_or(AliasValue::Missing, AliasValue::Value)
}

fn argument_list_is_resolved(value: &Value) -> bool {
    let Some(arguments) = argument_list(value) else {
        return false;
    };
    if arguments.is_empty() {
        return false;
    }

    if let Some(wrapper_status) = value.as_object().and_then(|object| object.get("status")) {
        let Some(wrapper_status) = wrapper_status.as_str() else {
            return false;
        };
        if !is_resolved_status(wrapper_status) {
            return false;
        }
    }

    arguments.iter().all(argument_is_resolved)
}

fn argument_list(value: &Value) -> Option<&[Value]> {
    value.as_array().map(Vec::as_slice).or_else(|| {
        value
            .get("arguments")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
    })
}

fn argument_is_resolved(value: &Value) -> bool {
    if value.is_null() {
        return false;
    }
    let Some(object) = value.as_object() else {
        return false;
    };

    let mut has_resolution_status = false;
    for field in ["status", "resolution_status"] {
        let Some(status) = object.get(field) else {
            continue;
        };
        let Some(status) = status.as_str() else {
            return false;
        };
        if !is_resolved_status(status) {
            return false;
        }
        has_resolution_status = true;
    }
    has_resolution_status
}

fn is_resolved_status(status: &str) -> bool {
    matches!(status, "resolved" | "mapped" | "ok")
}

fn mapped_address(value: &Value) -> bool {
    value.get("resolution").and_then(Value::as_str) == Some("mapped")
        && address_value(value).is_some()
}

fn address_value(value: &Value) -> Option<String> {
    let Some(object) = value.as_object() else {
        return parse_address(value).map(|address| address.display);
    };

    let mut selected = None;
    for field in ["address", "target_virtual_address", "virtual_address"] {
        if let Some(raw) = object.get(field) {
            let candidate = parse_address(raw)?;
            if !same_address(selected.as_ref(), &candidate) {
                return None;
            }
            selected.get_or_insert(candidate);
        }
    }

    for field in ["method_pointer", "pointer"] {
        let Some(pointer) = object.get(field) else {
            continue;
        };
        let candidate = pointer_address(pointer)?;
        if !same_address(selected.as_ref(), &candidate) {
            return None;
        }
        selected.get_or_insert(candidate);
    }

    selected.map(|address| address.display)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AddressClaim {
    display: String,
    identity: AddressIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AddressIdentity {
    Number(u64),
    Text(String),
}

fn pointer_address(value: &Value) -> Option<AddressClaim> {
    let mut selected = None;
    let mut current = value;

    for _ in 0..16 {
        let Some(object) = current.as_object() else {
            let candidate = parse_address(current)?;
            if !same_address(selected.as_ref(), &candidate) {
                return None;
            }
            selected.get_or_insert(candidate);
            return selected;
        };

        for field in ["address", "target_virtual_address", "virtual_address"] {
            if let Some(raw) = object.get(field) {
                let candidate = parse_address(raw)?;
                if !same_address(selected.as_ref(), &candidate) {
                    return None;
                }
                selected.get_or_insert(candidate);
            }
        }

        let Some(nested) = object.get("pointer") else {
            return selected;
        };
        current = nested;
    }

    None
}

fn parse_address(value: &Value) -> Option<AddressClaim> {
    if let Some(address) = value.as_u64() {
        return Some(AddressClaim {
            display: format!("0x{address:x}"),
            identity: AddressIdentity::Number(address),
        });
    }

    let address = value.as_str()?.trim();
    if address.is_empty() {
        return None;
    }

    let numeric = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .or_else(|| address.parse::<u64>().ok());
    let identity = numeric.map_or_else(
        || AddressIdentity::Text(address.to_owned()),
        AddressIdentity::Number,
    );

    Some(AddressClaim {
        display: address.to_owned(),
        identity,
    })
}

fn same_address(existing: Option<&AddressClaim>, candidate: &AddressClaim) -> bool {
    existing.is_none_or(|existing| existing.identity == candidate.identity)
}

fn nested_index(value: &Value, field: &str, aliases: &[&str]) -> (IndexClaim, IndexClaim) {
    match value.get(field) {
        Some(Value::Object(object)) => (
            index_claim(object, &["method_spec_index", "methodSpecIndex"]),
            index_claim(object, aliases),
        ),
        Some(Value::Null) | None => (IndexClaim::Missing, IndexClaim::Missing),
        Some(_) => (IndexClaim::Conflicting, IndexClaim::Conflicting),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexClaim {
    Missing,
    Resolved(u64),
    Conflicting,
}

impl IndexClaim {
    fn value(self) -> Option<u64> {
        match self {
            Self::Resolved(value) => Some(value),
            Self::Missing | Self::Conflicting => None,
        }
    }

    fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }

    fn is_conflicting(self) -> bool {
        matches!(self, Self::Conflicting)
    }
}

fn index_claim(object: &Map<String, Value>, aliases: &[&str]) -> IndexClaim {
    let mut selected = None;

    for alias in aliases {
        let Some(value) = object.get(*alias) else {
            continue;
        };
        let Some(candidate) = parse_index(value) else {
            return IndexClaim::Conflicting;
        };
        if selected.is_some_and(|existing| existing != candidate) {
            return IndexClaim::Conflicting;
        }
        selected = Some(candidate);
    }

    selected.map_or(IndexClaim::Missing, IndexClaim::Resolved)
}

/// Preserve Unity captures that encode metadata indexes as decimal or
/// hexadecimal text, matching the MethodSpec projection's identity parser.
fn parse_index(value: &Value) -> Option<u64> {
    if let Some(number) = value.as_u64() {
        return Some(number);
    }

    let text = value.as_str()?.trim();
    if text.is_empty() {
        return None;
    }

    text.strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map_or_else(
            || text.parse::<u64>().ok(),
            |digits| u64::from_str_radix(digits, 16).ok(),
        )
}

fn rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let mut selected = None;

    for alias in aliases {
        if let Some(value) = root.get(*alias) {
            selected = select_rows(selected, value, field)?;
        }
    }

    if let Some(metadata) = root.get("metadata") {
        let metadata = metadata
            .as_object()
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        for alias in aliases {
            if let Some(value) = metadata.get(*alias) {
                selected = select_rows(selected, value, field)?;
            }
        }
    }

    let rows = selected.ok_or_else(|| invalid(field, "Collection is required"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the supported row limit"));
    }
    Ok(rows)
}

fn select_rows<'a>(
    selected: Option<&'a [Value]>,
    value: &'a Value,
    field: &str,
) -> Result<Option<&'a [Value]>, Failure> {
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the supported row limit"));
    }
    if selected.is_some_and(|existing| existing != rows) {
        return Err(invalid(field, "Collection aliases conflict"));
    }
    Ok(Some(rows))
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP generic decompilation plan input is invalid.".into(),
        false,
        "Provide normalized MethodSpec, generic-method, and method-address projections and retry."
            .into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
