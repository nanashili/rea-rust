//! Stable, evidence-preserving display labels for decoded IL2CPP facts.
//!
//! A label is a managed metadata presentation.  It is deliberately separate
//! from a native symbol, address, or recovered body: those facts require an
//! independent binary mapping and are returned as unknown here.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "label_il2cpp_symbols";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INDEX: i64 = 9_007_199_254_740_991;

/// Build stable labels from normalized type and method rows.
///
/// The accepted shape is either direct `types`/`methods` arrays or the same
/// arrays beneath a `metadata` object.  Source rows are copied into each item
/// so display labels never discard provider-specific evidence.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let source = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let types = rows(source, "types")?;
    let methods = rows(source, "methods")?;
    let type_index = index_types(types)?;
    let native_symbols = native_symbols(root, source)?;
    let native_index = index_native_symbols(&native_symbols)?;

    let mut type_items = Vec::with_capacity(types.len());
    let mut resolved_types = 0usize;
    for (row, value) in types.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
        let index = index_of(object, "types", row)?;
        let (label, status) = type_label(index, &type_index)?;
        let native = resolve_native_symbol(object, &native_index);
        if status == "resolved" {
            resolved_types += 1;
        }
        type_items.push(json!({
            "source": value,
            "metadata_index": index,
            "managed_label": label,
            "label_status": status,
            "native_symbol": native.value,
            "native_symbol_status": native.status,
            "native_body": Value::Null,
        }));
    }

    let mut method_items = Vec::with_capacity(methods.len());
    let mut resolved_methods = 0usize;
    for (row, value) in methods.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("methods", row, "Expected an object"))?;
        let index = index_of(object, "methods", row)?;
        let (label, status) = method_label(object, &type_index)?;
        let native = resolve_native_symbol(object, &native_index);
        if status == "resolved" {
            resolved_methods += 1;
        }
        method_items.push(json!({
            "source": value,
            "metadata_index": index,
            "managed_label": label,
            "label_status": status,
            "signature_status": signature_status(object),
            "native_symbol": native.value,
            "native_symbol_status": native.status,
            "native_body": Value::Null,
        }));
    }

    let complete = resolved_types == types.len() && resolved_methods == methods.len();
    Ok(json!({
        "status": if complete { "complete" } else { "partial" },
        "types": type_items,
        "methods": method_items,
        "coverage": {
            "types": types.len(),
            "resolved_types": resolved_types,
            "methods": methods.len(),
            "resolved_methods": resolved_methods,
            "native_symbols": native_symbols.len(),
            "native_bodies": "unknown"
        }
    }))
}

pub fn label(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn rows<'a>(source: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], Failure> {
    let rows = source
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Collection exceeds the IL2CPP row limit"));
    }
    Ok(rows)
}

#[derive(Clone)]
struct NativeSymbol {
    address: u64,
    identity: NativeIdentity,
    source: Value,
}

#[derive(Clone, Default, Eq, PartialEq)]
struct NativeIdentity {
    image_index: Option<i64>,
    image_name: Option<String>,
    module_name: Option<String>,
    contradictory: bool,
}

struct NativeResolution {
    value: Value,
    status: &'static str,
}

fn native_symbols<'a>(
    root: &'a Map<String, Value>,
    metadata: &'a Map<String, Value>,
) -> Result<Vec<NativeSymbol>, Failure> {
    let rows = root
        .get("native_symbols")
        .or_else(|| root.get("symbols"))
        .or_else(|| metadata.get("native_symbols"))
        .or_else(|| metadata.get("symbols"));
    let Some(rows) = rows else {
        return Ok(Vec::new());
    };
    let rows = rows
        .as_array()
        .ok_or_else(|| invalid("native_symbols", "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "native_symbols",
            "Collection exceeds the IL2CPP row limit",
        ));
    }

    rows.iter()
        .enumerate()
        .map(|(row, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row("native_symbols", row, "Expected an object"))?;
            let address = native_address(object).ok_or_else(|| {
                invalid_row("native_symbols", row, "An exact native address is required")
            })?;
            Ok(NativeSymbol {
                address,
                identity: native_identity(object),
                source: value.clone(),
            })
        })
        .collect()
}

fn index_native_symbols(
    symbols: &[NativeSymbol],
) -> Result<BTreeMap<u64, Vec<&NativeSymbol>>, Failure> {
    let mut index = BTreeMap::new();
    for symbol in symbols {
        index
            .entry(symbol.address)
            .or_insert_with(Vec::new)
            .push(symbol);
    }
    Ok(index)
}

fn resolve_native_symbol(
    object: &Map<String, Value>,
    index: &BTreeMap<u64, Vec<&NativeSymbol>>,
) -> NativeResolution {
    let Some(address) = native_address(object) else {
        return NativeResolution {
            value: Value::Null,
            status: "unknown",
        };
    };
    let Some(candidates) = index.get(&address) else {
        return NativeResolution {
            value: Value::Null,
            status: "unknown",
        };
    };

    let identity = native_identity(object);
    let compatible = candidates
        .iter()
        .filter(|candidate| identities_compatible(&identity, &candidate.identity))
        .collect::<Vec<_>>();
    match compatible.as_slice() {
        [candidate] => NativeResolution {
            value: json!({
                "address": candidate.address,
                "name": symbol_name(&candidate.source),
                "source": candidate.source,
            }),
            status: "resolved",
        },
        [] => NativeResolution {
            value: Value::Null,
            status: "unknown",
        },
        _ => NativeResolution {
            value: json!({
                "address": address,
                "candidates": compatible
                    .iter()
                    .map(|candidate| candidate.source.clone())
                    .collect::<Vec<_>>(),
            }),
            status: "ambiguous",
        },
    }
}

fn symbol_name(value: &Value) -> Value {
    value
        .as_object()
        .and_then(|object| {
            ["name", "symbol", "label"]
                .into_iter()
                .find_map(|field| object.get(field).and_then(Value::as_str))
        })
        .map_or(Value::Null, |name| Value::String(name.to_owned()))
}

fn native_address(object: &Map<String, Value>) -> Option<u64> {
    let direct = [
        object.get("native_address"),
        object.get("method_pointer"),
        object.get("address"),
        object.get("virtual_address"),
        object.get("target_virtual_address"),
    ]
    .into_iter()
    .flatten()
    .find_map(parse_u64);
    if direct.is_some() {
        return direct;
    }

    object
        .get("method_pointer")
        .and_then(Value::as_object)
        .and_then(native_address)
}

fn native_identity(object: &Map<String, Value>) -> NativeIdentity {
    NativeIdentity {
        image_index: ["image_index", "image_id"]
            .into_iter()
            .find_map(|field| object.get(field).and_then(parse_i64)),
        image_name: ["image_name", "assembly_name", "image"]
            .into_iter()
            .find_map(|field| object.get(field).and_then(Value::as_str))
            .map(str::to_owned),
        module_name: ["module_name", "module"]
            .into_iter()
            .find_map(|field| object.get(field).and_then(Value::as_str))
            .map(str::to_owned),
        contradictory: conflicting_numeric_aliases(object, &["image_index", "image_id"])
            || conflicting_text_aliases(object, &["image_name", "assembly_name", "image"])
            || conflicting_text_aliases(object, &["module_name", "module"]),
    }
}

fn identities_compatible(left: &NativeIdentity, right: &NativeIdentity) -> bool {
    !left.contradictory
        && !right.contradictory
        && identity_field_matches(left.image_index, right.image_index)
        && identity_field_matches(left.image_name.as_deref(), right.image_name.as_deref())
        && identity_field_matches(left.module_name.as_deref(), right.module_name.as_deref())
}

fn conflicting_numeric_aliases(object: &Map<String, Value>, fields: &[&str]) -> bool {
    let values = fields
        .iter()
        .filter_map(|field| object.get(*field).and_then(parse_i64))
        .collect::<BTreeSet<_>>();
    values.len() > 1
}

fn conflicting_text_aliases(object: &Map<String, Value>, fields: &[&str]) -> bool {
    let values = fields
        .iter()
        .filter_map(|field| object.get(*field).and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    values.len() > 1
}

fn identity_field_matches<T: PartialEq>(left: Option<T>, right: Option<T>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn index_types<'a>(
    rows: &'a [Value],
) -> Result<BTreeMap<i64, Vec<&'a Map<String, Value>>>, Failure> {
    let mut result: BTreeMap<i64, Vec<&'a Map<String, Value>>> = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
        let index = index_of(object, "types", row)?;
        result.entry(index).or_default().push(object);
    }
    Ok(result)
}

fn type_label(
    index: i64,
    types: &BTreeMap<i64, Vec<&Map<String, Value>>>,
) -> Result<(Value, &'static str), Failure> {
    let mut stack = BTreeSet::new();
    let label = render_type(index, types, &mut stack);
    Ok(match label {
        Some(label) => (Value::String(label), "resolved"),
        None => (Value::Null, "unknown"),
    })
}

fn render_type(
    index: i64,
    types: &BTreeMap<i64, Vec<&Map<String, Value>>>,
    stack: &mut BTreeSet<i64>,
) -> Option<String> {
    let rows = types.get(&index)?;
    let [object] = rows.as_slice() else {
        return None;
    };
    if !stack.insert(index) {
        return None;
    }
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())?;
    let namespace = object
        .get("namespace")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    let parent = object
        .get("declaring_type")
        .or_else(|| object.get("declaring_type_index"))
        .and_then(parse_i64);
    let mut prefix = if let Some(parent) = parent {
        format!("{}.", render_type(parent, types, stack)?)
    } else {
        namespace.map(|v| format!("{v}.")).unwrap_or_default()
    };
    prefix.push_str(name);
    let arity = explicit_generic_arity(object).ok().flatten()?;
    if arity > 0 {
        prefix.push('<');
        prefix.push_str(
            &(0..arity)
                .map(|i| format!("!{i}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        prefix.push('>');
    }
    Some(prefix)
}

fn method_label(
    object: &Map<String, Value>,
    types: &BTreeMap<i64, Vec<&Map<String, Value>>>,
) -> Result<(Value, &'static str), Failure> {
    let name = object
        .get("name")
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty());
    let declaring = object
        .get("declaring_type")
        .or_else(|| object.get("declaring_type_index"))
        .and_then(parse_i64);
    let Some(name) = name else {
        return Ok((Value::Null, "unknown"));
    };
    let Some(declaring) = declaring else {
        return Ok((Value::Null, "unknown"));
    };
    let Some(type_name) = render_type(declaring, types, &mut BTreeSet::new()) else {
        return Ok((Value::Null, "unknown"));
    };
    let Some(arity) = method_generic_arity(object) else {
        return Ok((Value::Null, "unknown"));
    };
    let suffix = if arity == 0 {
        String::new()
    } else {
        format!(
            "<{}>",
            (0..arity)
                .map(|i| format!("!!{i}"))
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let token = object
        .get("token")
        .and_then(parse_u64)
        .map(|v| format!(" [token=0x{v:08x}]"))
        .unwrap_or_default();
    Ok((
        Value::String(format!("{type_name}.{name}{suffix}{token}")),
        "resolved",
    ))
}

/// A `generic_container` of `-1` is the normalized IL2CPP marker for a
/// non-generic method.  Preserve the distinction between that explicit fact
/// and an absent or malformed arity, which remains unresolved.
fn method_generic_arity(object: &Map<String, Value>) -> Option<u64> {
    match explicit_generic_arity(object) {
        Ok(Some(arity)) => return Some(arity),
        Err(()) => return None,
        Ok(None) => {}
    }

    object
        .get("generic_container")
        .is_some_and(is_minus_one)
        .then_some(0)
}

fn explicit_generic_arity(object: &Map<String, Value>) -> Result<Option<u64>, ()> {
    let mut selected = None;

    for field in ["generic_arity", "generic_parameter_count"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        if value.is_null() {
            continue;
        }

        let Some(arity) = parse_u64(value).filter(|value| *value <= MAX_ROWS as u64) else {
            return Err(());
        };
        if selected.is_some_and(|previous| previous != arity) {
            return Err(());
        }
        selected = Some(arity);
    }

    Ok(selected)
}

fn is_minus_one(value: &Value) -> bool {
    value.as_i64() == Some(-1) || value.as_str().is_some_and(|text| text.trim() == "-1")
}

fn signature_status(object: &Map<String, Value>) -> &'static str {
    match object
        .get("signature")
        .or_else(|| object.get("signature_text"))
    {
        Some(Value::String(value)) if !value.is_empty() => "resolved",
        Some(Value::Null) | None => "unknown",
        _ => "invalid",
    }
}

fn index_of(object: &Map<String, Value>, field: &str, row: usize) -> Result<i64, Failure> {
    object
        .get("metadata_index")
        .or_else(|| object.get("type_index"))
        .or_else(|| object.get("method_index"))
        .or_else(|| object.get("index"))
        .and_then(parse_i64)
        .ok_or_else(|| invalid_row(field, row, "metadata_index is required"))
}

fn parse_i64(value: &Value) -> Option<i64> {
    let parsed = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => {
            let text = text.trim();
            text.strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .map_or_else(
                    || text.parse::<i64>().ok(),
                    |digits| {
                        u64::from_str_radix(digits, 16)
                            .ok()
                            .and_then(|value| i64::try_from(value).ok())
                    },
                )
        }
        _ => None,
    }?;

    (0..=MAX_SAFE_INDEX).contains(&parsed).then_some(parsed)
}

fn parse_u64(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => parse_integer(text),
        _ => None,
    }
}

fn parse_integer(text: &str) -> Option<u64> {
    let text = text.trim();
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

fn invalid_row(field: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{field}[{row}]: {reason}"), reason)
}
fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP symbol-label input is invalid.".into(),
        false,
        "Supply normalized IL2CPP metadata rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
