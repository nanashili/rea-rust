//! Pure correlation of retained IL2CPP generic-method facts.
//!
//! The metadata and binary readers own decoding.  This module consumes their
//! already-normalized rows and keeps MethodSpec identity, generic method
//! identity, pointer-table slots, and adjustor thunks as separate facts.  It
//! does not read files, inspect a target, or infer a generic implementation
//! from a base method address.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "map_il2cpp_generic_methods";
const MAX_ROWS: usize = 200_000;

/// Correlate caller-supplied normalized IL2CPP metadata and binary facts.
///
/// The accepted input is:
///
/// ```text
/// {
///   "method_specs": [{ "method_spec_index": 0, ... }],
///   "generic_method_pointers": [{ "generic_method_index": 0, "address": "..." }],
///   "generic_adjustor_thunk_pointers": [{ "generic_method_index": 0, "address": "..." }]
/// }
/// ```
///
/// `metadata` and `binary` wrappers are also accepted when the three arrays
/// are placed beneath those objects.  Every source row is retained in the
/// result so callers can carry its evidence and provider-specific fields
/// forward without this mapper reinterpreting them.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let (metadata, binary) = input_sections(root)?;

    let specs = rows(metadata, "method_specs")?;
    let method_pointers = rows(binary, "generic_method_pointers")?;
    let adjustor_pointers = rows(binary, "generic_adjustor_thunk_pointers")?;

    let method_index = PointerIndex::build(method_pointers, "generic_method_pointers")?;
    let adjustor_index = PointerIndex::build(adjustor_pointers, "generic_adjustor_thunk_pointers")?;

    let mut items = Vec::with_capacity(specs.len());
    let mut mapped = 0usize;
    let mut unknown = 0usize;
    let mut unmapped = Vec::new();

    for (row, spec) in specs.iter().enumerate() {
        let spec_object = spec
            .as_object()
            .ok_or_else(|| invalid_row("method_specs", row, "Expected an object"))?;
        validate_row_keys(
            spec_object,
            &[
                "method_spec_index",
                "generic_method_index",
                "pointer_index",
                "pointer_table_index",
            ],
            "method_specs",
            row,
        )?;
        let spec_index = required_index(spec_object, "method_spec_index", "method_specs", row)?;
        let generic_index =
            optional_index(spec_object, "generic_method_index", "method_specs", row)?;
        let pointer_index = row_pointer_index(spec_object, "method_specs", row)?;
        let pointer_index_conflict = pointer_aliases_conflict(spec_object, "method_specs", row)?;

        let identity = Identity {
            method_spec_index: Some(spec_index),
            generic_method_index: generic_index,
            pointer_index,
            pointer_index_conflict,
        };
        let method_pointer = method_index.lookup(identity);
        let adjustor_pointer = adjustor_index.lookup(identity);
        let resolution = resolution(&method_pointer, &adjustor_pointer);

        match resolution {
            "mapped" => mapped += 1,
            "unmapped" => unmapped.push(Value::from(spec_index)),
            "unknown" => unknown += 1,
            _ => unreachable!("resolution returns a known classification"),
        }

        let mut item = Map::new();
        item.insert("method_spec".into(), spec.clone());
        item.insert("method_pointer".into(), pointer_value(&method_pointer));
        item.insert(
            "adjustor_thunk_pointer".into(),
            pointer_value(&adjustor_pointer),
        );
        item.insert("resolution".into(), Value::from(resolution));
        items.push(Value::Object(item));
    }

    let status = if unknown > 0 || !unmapped.is_empty() {
        "partial"
    } else {
        "complete"
    };

    Ok(serde_json::json!({
        "status": status,
        "items": items,
        "coverage": {
            "method_specs": specs.len(),
            "mapped": mapped,
            "unknown": unknown,
            "unmapped": unmapped.len(),
            "unmapped_method_spec_indices": unmapped,
            "generic_method_pointer_rows": method_pointers.len(),
            "generic_adjustor_thunk_pointer_rows": adjustor_pointers.len()
        }
    }))
}

fn input_sections<'a>(
    root: &'a Map<String, Value>,
) -> Result<(&'a Map<String, Value>, &'a Map<String, Value>), Failure> {
    let wrapped = root.contains_key("metadata") || root.contains_key("binary");

    if wrapped {
        validate_keys(root, &["metadata", "binary"], "input")?;

        let metadata = root
            .get("metadata")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("metadata", "Expected an object"))?;
        let binary = root
            .get("binary")
            .and_then(Value::as_object)
            .ok_or_else(|| invalid("binary", "Expected an object"))?;

        validate_keys(metadata, &["method_specs"], "metadata")?;
        validate_keys(
            binary,
            &["generic_method_pointers", "generic_adjustor_thunk_pointers"],
            "binary",
        )?;

        return Ok((metadata, binary));
    }

    validate_keys(
        root,
        &[
            "method_specs",
            "generic_method_pointers",
            "generic_adjustor_thunk_pointers",
        ],
        "input",
    )?;

    Ok((root, root))
}

fn validate_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(unknown) = object
        .keys()
        .find(|key| !allowed.iter().any(|allowed| *allowed == key.as_str()))
    {
        return Err(invalid(field, &format!("Unexpected property `{unknown}`")));
    }

    for required in allowed {
        if !object.contains_key(*required) {
            return Err(invalid(
                field,
                &format!("Missing required property `{required}`"),
            ));
        }
    }

    Ok(())
}

fn rows<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a [Value], Failure> {
    let rows = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the generic-method row limit",
        ));
    }
    Ok(rows)
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum IdentityKey {
    GenericMethod(u64),
    MethodSpec(u64),
    PointerSlot(u64),
}

#[derive(Clone, Copy, Debug, Default)]
struct Identity {
    method_spec_index: Option<u64>,
    generic_method_index: Option<u64>,
    pointer_index: Option<u64>,
    pointer_index_conflict: bool,
}

struct PointerIndex<'a> {
    rows: &'a [Value],
    by_key: BTreeMap<IdentityKey, Vec<usize>>,
}

impl<'a> PointerIndex<'a> {
    fn build(rows: &'a [Value], field: &str) -> Result<Self, Failure> {
        let mut by_key: BTreeMap<IdentityKey, Vec<usize>> = BTreeMap::new();

        for (row, value) in rows.iter().enumerate() {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row(field, row, "Expected an object"))?;
            validate_row_keys(
                object,
                &[
                    "generic_method_index",
                    "pointer_index",
                    "pointer_table_index",
                    "method_spec_index",
                    "address",
                ],
                field,
                row,
            )?;
            validate_pointer_address(object, field, row)?;
            let identity = pointer_identity(object, field, row)?;
            for key in identity.keys() {
                by_key.entry(key).or_default().push(row);
            }
        }

        Ok(Self { rows, by_key })
    }

    fn lookup(&self, identity: Identity) -> PointerMatch<'a> {
        if identity.pointer_index_conflict {
            return PointerMatch::Ambiguous(Vec::new());
        }
        let keys = identity.keys().collect::<Vec<_>>();
        if keys.is_empty() {
            return PointerMatch::Missing;
        }

        // A producer can key a row by any one of the available identities.
        // Search every supplied key and deduplicate row indices so a
        // MethodSpec-specific row is still found when the query also carries
        // a generic-method index.
        let mut candidate_rows = Vec::new();
        for key in keys {
            if let Some(rows) = self.by_key.get(&key) {
                candidate_rows.extend(rows.iter().copied());
            }
        }
        candidate_rows.sort_unstable();
        candidate_rows.dedup();

        let mut matching = Vec::new();
        let mut conflicting = Vec::new();
        for row in candidate_rows {
            let value = &self.rows[row];
            match identity.match_quality(value.as_object()) {
                IdentityMatch::Exact | IdentityMatch::Partial => matching.push((value, row)),
                IdentityMatch::Conflict => conflicting.push(value),
                IdentityMatch::Missing => {}
            }
        }

        if !conflicting.is_empty() {
            let mut candidates = matching.iter().map(|(value, _)| *value).collect::<Vec<_>>();
            candidates.extend(conflicting);
            let source = candidates[0];
            return PointerMatch::Conflicting { source, candidates };
        }

        match matching.as_slice() {
            [] => PointerMatch::Missing,
            [(row, _)] if identity.is_partial(row.as_object()) => PointerMatch::PartiallyKnown {
                source: *row,
                candidates: vec![*row],
            },
            [(row, _)] => PointerMatch::Found(*row),
            _ => PointerMatch::Ambiguous(matching.iter().map(|(value, _)| *value).collect()),
        }
    }
}

fn validate_row_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    collection: &str,
    row: usize,
) -> Result<(), Failure> {
    if let Some(unknown) = object
        .keys()
        .find(|key| !allowed.iter().any(|allowed| *allowed == key.as_str()))
    {
        return Err(invalid_row(
            collection,
            row,
            &format!("Unexpected property `{unknown}`"),
        ));
    }

    Ok(())
}

fn validate_pointer_address(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<(), Failure> {
    let Some(address) = object.get("address") else {
        return Ok(());
    };
    if address.is_null() || address.as_str().is_some_and(|value| !value.is_empty()) {
        return Ok(());
    }
    Err(invalid_row(
        collection,
        row,
        "address must be a non-empty string or null",
    ))
}

enum PointerMatch<'a> {
    Missing,
    Ambiguous(Vec<&'a Value>),
    Found(&'a Value),
    /// A source row matched one identity but omitted another requested one.
    /// Keep both the selected source and every matching candidate for callers
    /// that need to explain why the projection cannot claim an exact match.
    PartiallyKnown {
        source: &'a Value,
        candidates: Vec<&'a Value>,
    },
    /// At least one supplied identity disagreed with a candidate row.  The
    /// source and candidate rows remain attached even though the projection
    /// must not select a pointer from conflicting evidence.
    Conflicting {
        source: &'a Value,
        candidates: Vec<&'a Value>,
    },
}

fn pointer_identity(
    object: &Map<String, Value>,
    field: &str,
    row: usize,
) -> Result<Identity, Failure> {
    let identity = Identity {
        method_spec_index: optional_row_index(object, "method_spec_index", field, row)?,
        generic_method_index: optional_row_index(object, "generic_method_index", field, row)?,
        pointer_index: row_pointer_index(object, field, row)?,
        pointer_index_conflict: pointer_aliases_conflict(object, field, row)?,
    };
    let has_resolvable_identity = identity.method_spec_index.is_some()
        || identity.generic_method_index.is_some()
        || identity.pointer_index.is_some()
        || identity.pointer_index_conflict;
    if !has_resolvable_identity {
        return Err(invalid_row(
            field,
            row,
            "A pointer row needs an explicit generic method, MethodSpec, or pointer-table index",
        ));
    }
    Ok(identity)
}

impl Identity {
    fn keys(self) -> impl Iterator<Item = IdentityKey> {
        self.generic_method_index
            .into_iter()
            .map(IdentityKey::GenericMethod)
            .chain(self.pointer_index.into_iter().map(IdentityKey::PointerSlot))
            .chain(
                self.method_spec_index
                    .into_iter()
                    .map(IdentityKey::MethodSpec),
            )
    }

    fn match_quality(self, object: Option<&Map<String, Value>>) -> IdentityMatch {
        if self.pointer_index_conflict {
            return IdentityMatch::Conflict;
        }
        let Some(object) = object else {
            return IdentityMatch::Missing;
        };

        if pointer_aliases_conflict_in_object(object) {
            return IdentityMatch::Conflict;
        }

        let generic = index_match(object, "generic_method_index", self.generic_method_index);
        let pointer = pointer_match(object, self.pointer_index);
        let method_spec = index_match(object, "method_spec_index", self.method_spec_index);
        let match_kinds = [generic, pointer, method_spec];
        if match_kinds
            .iter()
            .any(|match_kind| matches!(match_kind, IndexMatch::Conflict))
        {
            return IdentityMatch::Conflict;
        }
        if match_kinds
            .iter()
            .any(|match_kind| matches!(match_kind, IndexMatch::Missing))
        {
            return IdentityMatch::Missing;
        }
        if match_kinds
            .iter()
            .any(|match_kind| matches!(match_kind, IndexMatch::Partial))
        {
            IdentityMatch::Partial
        } else {
            IdentityMatch::Exact
        }
    }

    fn is_partial(self, object: Option<&Map<String, Value>>) -> bool {
        matches!(self.match_quality(object), IdentityMatch::Partial)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexMatch {
    Exact,
    Partial,
    Conflict,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IdentityMatch {
    Exact,
    Partial,
    Conflict,
    Missing,
}

fn index_match(object: &Map<String, Value>, field: &str, expected: Option<u64>) -> IndexMatch {
    let Some(expected) = expected else {
        return IndexMatch::Exact;
    };
    match object.get(field) {
        None => IndexMatch::Partial,
        Some(value) if value.as_u64() == Some(expected) => IndexMatch::Exact,
        Some(_) => IndexMatch::Conflict,
    }
}

fn pointer_match(object: &Map<String, Value>, expected: Option<u64>) -> IndexMatch {
    let Some(expected) = expected else {
        return IndexMatch::Exact;
    };
    match pointer_index_from_object(object) {
        None => IndexMatch::Partial,
        Some(actual) if actual == expected => IndexMatch::Exact,
        Some(_) => IndexMatch::Conflict,
    }
}

fn pointer_value(pointer: &PointerMatch<'_>) -> Value {
    match pointer {
        PointerMatch::Missing | PointerMatch::Ambiguous(_) | PointerMatch::Conflicting { .. } => {
            Value::Null
        }
        PointerMatch::Found(value) => (*value).clone(),
        PointerMatch::PartiallyKnown { source, .. } => (*source).clone(),
    }
}

fn resolution(
    method_pointer: &PointerMatch<'_>,
    adjustor_pointer: &PointerMatch<'_>,
) -> &'static str {
    // The output contract deliberately has one unresolved state. Keep the
    // richer internal causes in the match value, but expose all ambiguity,
    // conflicting evidence, and incomplete identity as `unknown`.
    if matches!(
        method_pointer,
        PointerMatch::Ambiguous(_)
            | PointerMatch::Conflicting { .. }
            | PointerMatch::PartiallyKnown { .. }
    ) || matches!(
        adjustor_pointer,
        PointerMatch::Ambiguous(_)
            | PointerMatch::Conflicting { .. }
            | PointerMatch::PartiallyKnown { .. }
    ) {
        return "unknown";
    }
    if matches!(method_pointer, PointerMatch::Missing) {
        return "unmapped";
    }
    let method_known = match method_pointer {
        PointerMatch::Found(pointer) => pointer_has_address(pointer),
        PointerMatch::Missing
        | PointerMatch::Ambiguous(_)
        | PointerMatch::PartiallyKnown { .. }
        | PointerMatch::Conflicting { .. } => false,
    };
    let adjustor_known = match adjustor_pointer {
        PointerMatch::Missing => true,
        PointerMatch::Ambiguous(_)
        | PointerMatch::PartiallyKnown { .. }
        | PointerMatch::Conflicting { .. } => false,
        PointerMatch::Found(pointer) => pointer_has_address(pointer),
    };
    if method_known && adjustor_known {
        "mapped"
    } else {
        "unknown"
    }
}

fn pointer_has_address(pointer: &Value) -> bool {
    pointer
        .as_object()
        .and_then(|object| object.get("address"))
        .is_some_and(|address| !address.is_null())
}

fn required_index(
    object: &Map<String, Value>,
    field: &str,
    collection: &str,
    row: usize,
) -> Result<u64, Failure> {
    object.get(field).and_then(Value::as_u64).ok_or_else(|| {
        invalid_row(
            collection,
            row,
            &format!("{field} must be a non-negative integer"),
        )
    })
}

fn optional_index(
    object: &Map<String, Value>,
    field: &str,
    collection: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            invalid_row(
                collection,
                row,
                &format!("{field} must be a non-negative integer or null"),
            )
        }),
    }
}

fn optional_row_index(
    object: &Map<String, Value>,
    field: &str,
    collection: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            invalid_row(
                collection,
                row,
                &format!("{field} must be a non-negative integer or null"),
            )
        }),
    }
}

fn row_pointer_index(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<Option<u64>, Failure> {
    let pointer_index = optional_row_index(object, "pointer_index", collection, row)?;
    let table_index = optional_row_index(object, "pointer_table_index", collection, row)?;
    Ok(pointer_index.or(table_index))
}

fn pointer_aliases_conflict(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<bool, Failure> {
    let pointer_index = optional_row_index(object, "pointer_index", collection, row)?;
    let table_index = optional_row_index(object, "pointer_table_index", collection, row)?;
    Ok(pointer_index.is_some() && table_index.is_some() && pointer_index != table_index)
}

fn pointer_aliases_conflict_in_object(object: &Map<String, Value>) -> bool {
    let pointer_index = object.get("pointer_index").and_then(Value::as_u64);
    let table_index = object.get("pointer_table_index").and_then(Value::as_u64);
    pointer_index.is_some() && table_index.is_some() && pointer_index != table_index
}

fn pointer_index_from_object(object: &Map<String, Value>) -> Option<u64> {
    object
        .get("pointer_index")
        .or_else(|| object.get("pointer_table_index"))
        .and_then(Value::as_u64)
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP generic-method mapping input is invalid.".into(),
        false,
        "Supply normalized MethodSpec and pointer-table facts and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
