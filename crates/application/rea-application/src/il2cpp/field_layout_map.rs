//! Correlation of IL2CPP field metadata rows with recovered field offsets.
//!
//! Metadata decoding and native layout discovery own their respective input
//! formats.  This module only joins normalized rows supplied by an adapter.
//! An absent layout row remains `unmapped`, while a present row whose offset
//! is unavailable remains `unknown`; neither case is silently treated as a
//! zero offset.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "map_il2cpp_field_layouts";
const MAX_ROWS: usize = 200_000;

/// Correlate metadata fields with caller-supplied field-layout rows.
///
/// The input accepts direct arrays or `metadata`/`binary` wrappers:
///
/// ```text
/// {
///   "metadata": {
///     "types": [{ "metadata_index": 0, "field_start": 0, "field_count": 2 }],
///     "fields": [{ "metadata_index": 0, "name": "value" }]
///   },
///   "binary": {
///     "field_layouts": [{ "field_index": 0, "offset": 16 }]
///   }
/// }
/// ```
///
/// A field's declaring type is retained when supplied by the producer.  When
/// it is omitted, the type ranges are used only if exactly one range owns the
/// field.  Overlapping ranges remain unknown rather than selecting an owner.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let binary = root
        .get("binary")
        .and_then(Value::as_object)
        .unwrap_or(root);

    let types = rows_from_aliases(metadata, &["types", "type_definitions"], "types")?;
    let fields = rows_from_aliases(metadata, &["fields", "field_definitions"], "fields")?;
    let layouts = rows_from_aliases(
        binary,
        &["field_layouts", "field_offsets", "field_layout_rows"],
        "field_layouts",
    )?;
    let type_ranges = index_type_ranges(types)?;
    let layout_index = index_layouts(layouts)?;
    let field_identity_counts = count_field_identities(fields)?;

    let mut resolved_fields = Vec::with_capacity(fields.len());
    let mut mapped = 0usize;
    let mut unknown = 0usize;
    let mut unmapped = Vec::new();

    for (row, field) in fields.iter().enumerate() {
        let field_object = field
            .as_object()
            .ok_or_else(|| invalid_row("fields", row, "Expected an object"))?;
        let identity = field_identity(field_object, "fields", row)?;
        let field_index = identity
            .field_index
            .or(identity.member_index)
            .ok_or_else(|| invalid_row("fields", row, "field identity is required"))?;
        let owner = identity
            .field_index
            .map(|index| owner_for_field(field_object, index, &type_ranges))
            .unwrap_or_else(unknown_owner);
        let source_layouts = matching_layouts(&layout_index, &identity);
        let layout_candidates = select_layout_candidates(&source_layouts, field_object);
        let layout = if layout_candidates.len() == 1 {
            layout_candidates.first().copied()
        } else {
            None
        };
        let identity_ambiguous =
            identity.ambiguous || field_identity_counts.is_duplicate(&identity);
        let resolution = match layout_candidates.as_slice() {
            [] if identity_ambiguous => {
                unknown += 1;
                "unknown"
            }
            [] => {
                unmapped.push(Value::from(field_index));
                "unmapped"
            }
            [value]
                if !identity_ambiguous
                    && layout_offset(value).is_some_and(|offset| offset.as_u64().is_some()) =>
            {
                mapped += 1;
                "mapped"
            }
            _ => {
                unknown += 1;
                "unknown"
            }
        };

        resolved_fields.push(ResolvedField {
            field,
            field_index,
            owner,
            storage: resolve_storage_kind(field_object, layout_candidates.as_slice()),
            type_reference: resolve_type_reference(field_object, layout_candidates.as_slice()),
            layout,
            layouts: source_layouts,
            resolution,
            identity_ambiguous,
        });
    }

    let mut items = Vec::with_capacity(resolved_fields.len());
    for (position, resolved) in resolved_fields.iter().enumerate() {
        let mut item = Map::new();
        item.insert("field".into(), resolved.field.clone());
        item.insert("field_index".into(), Value::from(resolved.field_index));
        let member_identity = member_identity(resolved.field, resolved.field_index);
        item.insert("member_identity".into(), member_identity.value.clone());
        item.insert(
            "member_identity_source".into(),
            Value::from(member_identity.source),
        );
        item.insert("declaring_type".into(), resolved.owner.value.clone());
        item.insert("storage_kind".into(), resolved.storage.value.clone());
        item.insert(
            "storage_kind_source".into(),
            Value::from(resolved.storage.source),
        );
        item.insert(
            "type_reference".into(),
            resolved.type_reference.value.clone(),
        );
        item.insert(
            "type_reference_source".into(),
            Value::from(resolved.type_reference.source),
        );
        item.insert(
            "field_layout".into(),
            resolved.layout.map_or(Value::Null, |value| value.clone()),
        );
        item.insert(
            "field_layout_rows".into(),
            Value::Array(
                resolved
                    .layouts
                    .iter()
                    .map(|value| (*value).clone())
                    .collect(),
            ),
        );
        item.insert("resolution".into(), Value::from(resolved.resolution));
        let offset = resolve_offset(
            resolved.layout,
            &resolved.layouts,
            resolved.identity_ambiguous,
        );
        item.insert("source_offset".into(), offset.value);
        item.insert("source_offset_source".into(), Value::from(offset.source));
        item.insert(
            "storage_offset".into(),
            item.get("source_offset").cloned().unwrap_or(Value::Null),
        );
        item.insert("storage_offset_source".into(), Value::from(offset.source));
        item.insert(
            "owner_resolution".into(),
            Value::from(resolved.owner.source),
        );
        let size = field_size(&resolved_fields, position);
        item.insert("field_size".into(), size.value);
        item.insert("field_size_source".into(), Value::from(size.source));
        item.insert("field_size_state".into(), Value::from(size.state));
        let mut diagnostics: Vec<Value> = resolved
            .owner
            .diagnostics
            .iter()
            .map(|diagnostic| Value::from(*diagnostic))
            .collect();
        if resolved.identity_ambiguous {
            diagnostics.push(Value::from(
                if field_identity_is_ambiguous(
                    resolved.field.as_object().expect("field rows are objects"),
                ) {
                    "conflicting_field_identity_aliases"
                } else {
                    "duplicate_field_identity"
                },
            ));
        }
        if offset.source == "ambiguous" {
            diagnostics.push(Value::from("ambiguous_field_offset"));
        }
        if member_identity.source == "ambiguous" {
            diagnostics.push(Value::from("ambiguous_member_identity"));
        }
        if size.state == "ambiguous" {
            diagnostics.push(Value::from("ambiguous_field_size"));
        }
        if resolved.storage.source == "ambiguous" {
            diagnostics.push(Value::from("ambiguous_storage_kind"));
        }
        if resolved.type_reference.source == "ambiguous" {
            diagnostics.push(Value::from("ambiguous_type_reference"));
        }
        item.insert("diagnostics".into(), Value::Array(diagnostics));
        items.push(Value::Object(item));
    }

    let unmatched_layout_rows: Vec<Value> = layouts
        .iter()
        .filter(|layout| {
            let Some(object) = layout.as_object() else {
                return true;
            };
            field_identity_is_ambiguous(object)
                || !field_identity_counts.contains_layout_identity(object)
        })
        .cloned()
        .collect();
    let projection_is_partial = resolved_fields.iter().any(|field| {
        field.owner.source == "unknown"
            || field.storage.source == "ambiguous"
            || field.type_reference.source == "ambiguous"
            || field.identity_ambiguous
    });

    Ok(serde_json::json!({
        "status": if projection_is_partial || unknown > 0 || !unmapped.is_empty() || !unmatched_layout_rows.is_empty() { "partial" } else { "complete" },
        "items": items,
        "coverage": {
            "types": types.len(),
            "fields": fields.len(),
            "mapped": mapped,
            "unknown": unknown,
            "unmapped": unmapped.len(),
            "unmapped_field_indices": unmapped,
            "field_layout_rows": layouts.len(),
            "unmatched_field_layout_rows": unmatched_layout_rows.len()
        },
        "unmatched_field_layout_rows": unmatched_layout_rows
    }))
}

struct ResolvedField<'a> {
    field: &'a Value,
    field_index: u64,
    owner: OwnerResolution,
    storage: ValueResolution,
    type_reference: ValueResolution,
    layout: Option<&'a Value>,
    layouts: Vec<&'a Value>,
    resolution: &'static str,
    identity_ambiguous: bool,
}

#[derive(Clone, Copy)]
struct FieldIdentity {
    field_index: Option<u64>,
    member_index: Option<u64>,
    ambiguous: bool,
}

struct OwnerResolution {
    value: Value,
    source: &'static str,
    diagnostics: Vec<&'static str>,
    type_index: Option<u64>,
}

struct FieldSize {
    value: Value,
    source: &'static str,
    state: &'static str,
}

struct ValueResolution {
    value: Value,
    source: &'static str,
}

fn field_size(fields: &[ResolvedField<'_>], position: usize) -> FieldSize {
    let current = &fields[position];
    if current.identity_ambiguous {
        return FieldSize {
            value: Value::Null,
            source: "ambiguous",
            state: "ambiguous",
        };
    }
    let Some(layout) = current.layout else {
        return FieldSize {
            value: Value::Null,
            source: if current.layouts.is_empty() {
                "unknown"
            } else {
                "ambiguous"
            },
            state: if current.layouts.is_empty() {
                "unmapped"
            } else {
                "ambiguous"
            },
        };
    };
    if let Some(size) = layout_size(layout) {
        return match size.as_u64() {
            Some(size) => FieldSize {
                value: Value::from(size),
                source: "observed",
                state: "resolved",
            },
            None => FieldSize {
                value: Value::Null,
                source: "unknown",
                state: "unknown",
            },
        };
    }
    let Some(owner) = current.owner.type_index else {
        return FieldSize {
            value: Value::Null,
            source: "unknown",
            state: "unknown",
        };
    };
    let Some(offset) = layout_offset(layout).and_then(Value::as_u64) else {
        return FieldSize {
            value: Value::Null,
            source: "unknown",
            state: "unknown",
        };
    };
    let storage_kind = layout_storage_kind(layout).map(|kind| storage_kind_key(&kind));
    let next_offset = fields
        .iter()
        .filter(|field| field.owner.type_index == Some(owner))
        .filter_map(|field| {
            let candidate = field.layout?;
            if layout_storage_kind(candidate).map(|kind| storage_kind_key(&kind)) != storage_kind {
                return None;
            }
            layout_offset(candidate)?.as_u64()
        })
        .filter(|next| *next > offset)
        .min();
    let Some(next_offset) = next_offset else {
        return FieldSize {
            value: Value::Null,
            source: "unknown",
            state: "unknown",
        };
    };
    FieldSize {
        value: Value::from(next_offset - offset),
        source: "inferred",
        state: "resolved",
    }
}

fn select_layout_candidates<'a>(
    layouts: &[&'a Value],
    field: &Map<String, Value>,
) -> Vec<&'a Value> {
    let Some(field_storage) = field_storage_kind(field) else {
        return layouts.to_vec();
    };
    let expected_storage = storage_kind_key(&field_storage);
    let matching: Vec<&Value> = layouts
        .iter()
        .copied()
        .filter(|layout| {
            layout_storage_kind(layout)
                .is_some_and(|kind| storage_kind_key(&kind) == expected_storage)
        })
        .collect();

    let has_conflicting_storage = layouts.iter().any(|layout| {
        layout_storage_kind(layout).is_some_and(|kind| storage_kind_key(&kind) != expected_storage)
    });
    if matching.is_empty() || has_conflicting_storage {
        layouts.to_vec()
    } else {
        matching
    }
}

fn resolve_offset(
    layout: Option<&Value>,
    layouts: &[&Value],
    identity_ambiguous: bool,
) -> ValueResolution {
    if layouts.is_empty() {
        return ValueResolution {
            value: Value::Null,
            source: "unmapped",
        };
    }
    if identity_ambiguous || layout.is_none() {
        return ValueResolution {
            value: Value::Null,
            source: "ambiguous",
        };
    }
    let raw_offsets: Vec<&Value> = layouts
        .iter()
        .filter_map(|row| layout_offset(row))
        .collect();
    if raw_offsets.len() != layouts.len() {
        return ValueResolution {
            value: Value::Null,
            source: "unknown",
        };
    }
    let offsets: Vec<u64> = layouts
        .iter()
        .filter_map(|row| layout_offset(row).and_then(Value::as_u64))
        .collect();
    if offsets.len() != raw_offsets.len() && !offsets.is_empty() {
        return ValueResolution {
            value: Value::Null,
            source: "unknown",
        };
    }
    if offsets.is_empty() {
        let unique_raw_offsets: BTreeSet<String> = raw_offsets
            .iter()
            .filter_map(|offset| serde_json::to_string(offset).ok())
            .collect();
        if unique_raw_offsets.len() == 1 {
            return ValueResolution {
                value: raw_offsets[0].clone(),
                source: "unknown",
            };
        }
        return ValueResolution {
            value: Value::Null,
            source: if unique_raw_offsets.is_empty() {
                "unknown"
            } else {
                "ambiguous"
            },
        };
    }
    let unique_offsets: BTreeSet<u64> = offsets.iter().copied().collect();
    if unique_offsets.len() != 1 {
        return ValueResolution {
            value: Value::Null,
            source: "ambiguous",
        };
    }
    ValueResolution {
        value: Value::from(offsets[0]),
        source: "observed",
    }
}

struct MemberIdentityResolution {
    value: Value,
    source: &'static str,
}

fn member_identity(field: &Value, field_index: u64) -> MemberIdentityResolution {
    let Some(object) = field.as_object() else {
        return MemberIdentityResolution {
            value: Value::Null,
            source: "unknown",
        };
    };

    let Ok(identity) = field_identity(object, "fields", 0) else {
        return MemberIdentityResolution {
            value: Value::Null,
            source: "unknown",
        };
    };
    if identity.ambiguous {
        return MemberIdentityResolution {
            value: Value::Null,
            source: "ambiguous",
        };
    }

    if let Some(identity) = object
        .get("member_identity")
        .or_else(|| object.get("memberIdentity"))
    {
        return MemberIdentityResolution {
            value: identity.clone(),
            source: "observed",
        };
    }

    let identity = identity
        .member_index
        .or(identity.field_index)
        .map(Value::from)
        .unwrap_or_else(|| Value::from(field_index));
    MemberIdentityResolution {
        value: identity,
        source: "observed",
    }
}

fn field_storage_kind(field: &Map<String, Value>) -> Option<String> {
    field
        .get("storage_kind")
        .or_else(|| field.get("storageKind"))
        .or_else(|| field.get("storage"))
        .or_else(|| field.get("kind"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn layout_offset(layout: &Value) -> Option<&Value> {
    let object = layout.as_object()?;
    [
        "storage_offset",
        "storageOffset",
        "offset",
        "field_offset",
        "fieldOffset",
        "static_offset",
        "staticOffset",
        "thread_static_offset",
        "threadStaticOffset",
    ]
    .iter()
    .find_map(|key| object.get(*key))
}

fn layout_size(layout: &Value) -> Option<&Value> {
    let object = layout.as_object()?;
    ["size", "field_size", "fieldSize"]
        .iter()
        .find_map(|key| object.get(*key))
}

fn resolve_storage_kind(field: &Map<String, Value>, layouts: &[&Value]) -> ValueResolution {
    let field_kind = field_storage_kind(field);
    let layout_kinds: BTreeSet<String> = layouts
        .iter()
        .filter_map(|layout| layout_storage_kind(layout))
        .collect();
    if field_kind.is_some()
        && layout_kinds
            .iter()
            .any(|kind| storage_kind_key(kind) != storage_kind_key(field_kind.as_ref().unwrap()))
    {
        return ValueResolution {
            value: Value::Null,
            source: "ambiguous",
        };
    }
    if let Some(field_kind) = field_kind {
        return ValueResolution {
            value: Value::from(field_kind),
            source: "observed",
        };
    }
    if layout_kinds.len() == 1 {
        return ValueResolution {
            value: Value::from(layout_kinds.into_iter().next().unwrap()),
            source: "observed",
        };
    }
    ValueResolution {
        value: Value::Null,
        source: if layout_kinds.is_empty() {
            "unknown"
        } else {
            "ambiguous"
        },
    }
}

fn storage_kind_key(kind: &str) -> String {
    kind.trim().to_ascii_lowercase().replace('-', "_")
}

fn type_reference(object: &Map<String, Value>) -> Option<Value> {
    [
        "type_reference",
        "typeReference",
        "type_ref",
        "typeRef",
        "field_type",
        "fieldType",
    ]
    .iter()
    .find_map(|key| object.get(*key).cloned())
}

fn resolve_type_reference(field: &Map<String, Value>, layouts: &[&Value]) -> ValueResolution {
    let field_reference = type_reference(field);
    let layout_references: Vec<Value> = layouts
        .iter()
        .filter_map(|layout| layout.as_object().and_then(type_reference))
        .collect();
    if let Some(reference) = field_reference {
        if layout_references
            .iter()
            .any(|candidate| candidate != &reference)
        {
            return ValueResolution {
                value: Value::Null,
                source: "ambiguous",
            };
        }
        return ValueResolution {
            value: reference,
            source: "observed",
        };
    }
    let unique_references: BTreeSet<String> = layout_references
        .iter()
        .filter_map(|reference| serde_json::to_string(reference).ok())
        .collect();
    if unique_references.len() == 1 {
        return ValueResolution {
            value: layout_references[0].clone(),
            source: "observed",
        };
    }
    ValueResolution {
        value: Value::Null,
        source: if unique_references.is_empty() {
            "unknown"
        } else {
            "ambiguous"
        },
    }
}

fn layout_storage_kind(layout: &Value) -> Option<String> {
    let object = layout.as_object()?;
    object
        .get("storage_kind")
        .or_else(|| object.get("storageKind"))
        .or_else(|| object.get("storage"))
        .or_else(|| object.get("kind"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn rows_from_aliases<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let rows = aliases.iter().find_map(|alias| object.get(*alias));
    let rows = rows
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(field, "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            field,
            "Collection exceeds the IL2CPP field row limit",
        ));
    }
    Ok(rows)
}

struct TypeRange {
    type_index: u64,
    start: Option<u64>,
    end: Option<u64>,
}

fn index_type_ranges(rows: &[Value]) -> Result<Vec<TypeRange>, Failure> {
    let mut ranges = Vec::with_capacity(rows.len());
    let mut identifiers = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
        let type_index = object
            .get("metadata_index")
            .or_else(|| object.get("type_index"))
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                invalid_row(
                    "types",
                    row,
                    "metadata_index must be a non-negative integer",
                )
            })?;
        if identifiers.insert(type_index, row).is_some() {
            return Err(invalid_row(
                "types",
                row,
                "Duplicate type index makes field ownership ambiguous",
            ));
        }
        let start = object
            .get("field_start")
            .or_else(|| object.get("fieldStart"))
            .and_then(Value::as_u64);
        let count = object
            .get("field_count")
            .or_else(|| object.get("fieldCount"))
            .and_then(Value::as_u64);
        let end = match (start, count) {
            (Some(start), Some(count)) => Some(
                start
                    .checked_add(count)
                    .ok_or_else(|| invalid_row("types", row, "field range overflows"))?,
            ),
            _ => None,
        };
        ranges.push(TypeRange {
            type_index,
            start,
            end,
        });
    }
    Ok(ranges)
}

struct LayoutIndex<'a> {
    by_field_index: BTreeMap<u64, Vec<(usize, &'a Value)>>,
    by_member_index: BTreeMap<u64, Vec<(usize, &'a Value)>>,
}

fn index_layouts<'a>(rows: &'a [Value]) -> Result<LayoutIndex<'a>, Failure> {
    let mut by_field_index = BTreeMap::new();
    let mut by_member_index = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("field_layouts", row, "Expected an object"))?;
        let identity = field_identity(object, "field_layouts", row)?;
        if identity.ambiguous {
            continue;
        }
        if let Some(field_index) = identity.field_index {
            by_field_index
                .entry(field_index)
                .or_insert_with(Vec::new)
                .push((row, value));
        }
        if let Some(member_index) = identity.member_index {
            by_member_index
                .entry(member_index)
                .or_insert_with(Vec::new)
                .push((row, value));
        }
        if identity.field_index.is_none() && identity.member_index.is_none() {
            return Err(invalid_row(
                "field_layouts",
                row,
                "field or member identity is required",
            ));
        }
    }
    Ok(LayoutIndex {
        by_field_index,
        by_member_index,
    })
}

fn matching_layouts<'a>(index: &LayoutIndex<'a>, field: &FieldIdentity) -> Vec<&'a Value> {
    let mut candidates = Vec::new();
    if let Some(field_index) = field.field_index {
        candidates.extend(
            index
                .by_field_index
                .get(&field_index)
                .into_iter()
                .flatten()
                .copied(),
        );
    }
    if let Some(member_index) = field.member_index {
        candidates.extend(
            index
                .by_member_index
                .get(&member_index)
                .into_iter()
                .flatten()
                .copied(),
        );
    }
    candidates.sort_by_key(|(row, _)| *row);
    candidates.dedup_by_key(|(row, _)| *row);
    candidates
        .into_iter()
        .filter(|(_, value)| {
            let Some(object) = value.as_object() else {
                return false;
            };
            let Ok(layout_identity) = field_identity(object, "field_layouts", 0) else {
                return false;
            };
            if layout_identity.ambiguous {
                return false;
            }
            if field.member_index.is_some()
                && layout_identity.member_index.is_some()
                && field.member_index != layout_identity.member_index
            {
                return false;
            }
            if field.field_index.is_some()
                && layout_identity.field_index.is_some()
                && field.field_index != layout_identity.field_index
            {
                return false;
            }
            true
        })
        .map(|(_, value)| value)
        .collect()
}

fn field_identity(
    object: &Map<String, Value>,
    collection: &str,
    row: usize,
) -> Result<FieldIdentity, Failure> {
    let nested = object
        .get("member_identity")
        .or_else(|| object.get("memberIdentity"))
        .and_then(Value::as_object);
    let field_values =
        identity_alias_values(object, nested, &["metadata_index", "field_index", "index"]);
    let member_values = identity_alias_values(
        object,
        nested,
        &[
            "member_index",
            "memberIndex",
            "slot",
            "table_slot",
            "field_slot",
            "offset_slot",
        ],
    );
    if field_values.is_empty() && member_values.is_empty() {
        return Err(invalid_row(
            collection,
            row,
            "field or member identity is required",
        ));
    }
    let field_index = first_integer_alias(&field_values);
    let member_index = first_integer_alias(&member_values);
    let ambiguous = aliases_conflict(&field_values) || aliases_conflict(&member_values);
    Ok(FieldIdentity {
        field_index,
        member_index,
        ambiguous,
    })
}

fn identity_alias_values<'a>(
    object: &'a Map<String, Value>,
    nested: Option<&'a Map<String, Value>>,
    aliases: &[&str],
) -> Vec<&'a Value> {
    let mut values = aliases
        .iter()
        .filter_map(|alias| object.get(*alias))
        .collect::<Vec<_>>();
    if let Some(nested) = nested {
        values.extend(aliases.iter().filter_map(|alias| nested.get(*alias)));
    }
    values
}

fn first_integer_alias(values: &[&Value]) -> Option<u64> {
    values.iter().find_map(|value| value.as_u64())
}

fn aliases_conflict(values: &[&Value]) -> bool {
    if values.len() <= 1 {
        return values.iter().any(|value| value.as_u64().is_none());
    }
    let mut identities = BTreeSet::new();
    for value in values {
        let Some(identity) = value.as_u64() else {
            return true;
        };
        identities.insert(identity);
    }
    identities.len() > 1
}

fn field_identity_is_ambiguous(object: &Map<String, Value>) -> bool {
    field_identity(object, "field", 0)
        .map(|identity| identity.ambiguous)
        .unwrap_or(true)
}

struct FieldIdentityCounts {
    field_indices: BTreeMap<u64, usize>,
    member_indices: BTreeMap<u64, usize>,
}

impl FieldIdentityCounts {
    fn is_duplicate(&self, identity: &FieldIdentity) -> bool {
        if let Some(field_index) = identity.field_index {
            return self
                .field_indices
                .get(&field_index)
                .is_some_and(|count| *count > 1);
        }

        identity
            .member_index
            .and_then(|index| self.member_indices.get(&index))
            .is_some_and(|count| *count > 1)
    }

    fn contains_layout_identity(&self, object: &Map<String, Value>) -> bool {
        let Ok(identity) = field_identity(object, "field_layouts", 0) else {
            return false;
        };
        identity
            .field_index
            .is_some_and(|index| self.field_indices.contains_key(&index))
            || identity
                .member_index
                .is_some_and(|index| self.member_indices.contains_key(&index))
    }
}

fn count_field_identities(rows: &[Value]) -> Result<FieldIdentityCounts, Failure> {
    let mut field_indices = BTreeMap::new();
    let mut member_indices = BTreeMap::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("fields", row, "Expected an object"))?;
        let identity = field_identity(object, "fields", row)?;
        if identity.ambiguous {
            continue;
        }
        if let Some(index) = identity.field_index {
            *field_indices.entry(index).or_insert(0) += 1;
        }
        if let Some(index) = identity.member_index {
            *member_indices.entry(index).or_insert(0) += 1;
        }
    }
    Ok(FieldIdentityCounts {
        field_indices,
        member_indices,
    })
}

fn owner_for_field(
    field: &Map<String, Value>,
    field_index: u64,
    ranges: &[TypeRange],
) -> OwnerResolution {
    if field_identity_is_ambiguous(field) {
        return OwnerResolution {
            value: Value::Null,
            source: "unknown",
            diagnostics: Vec::new(),
            type_index: None,
        };
    }

    if let Some(owner) = field
        .get("declaring_type")
        .or_else(|| field.get("declaring_type_index"))
    {
        let explicit_type = owner.as_u64();
        let matching_ranges: Vec<&TypeRange> = ranges
            .iter()
            .filter(|range| {
                range
                    .start
                    .zip(range.end)
                    .is_some_and(|(start, end)| field_index >= start && field_index < end)
            })
            .collect();
        let conflict = explicit_type.is_some_and(|type_index| {
            matching_ranges
                .iter()
                .any(|range| range.type_index != type_index)
        });
        return OwnerResolution {
            value: if conflict || explicit_type.is_none() {
                Value::Null
            } else {
                owner.clone()
            },
            source: if conflict || explicit_type.is_none() {
                "unknown"
            } else {
                "observed"
            },
            diagnostics: if conflict {
                vec!["declaring_type_conflicts_with_field_range"]
            } else if explicit_type.is_none() {
                vec!["declaring_type_is_not_an_integer"]
            } else {
                Vec::new()
            },
            type_index: if conflict { None } else { explicit_type },
        };
    }
    let owners: Vec<&TypeRange> = ranges
        .iter()
        .filter(|range| {
            range
                .start
                .zip(range.end)
                .is_some_and(|(start, end)| field_index >= start && field_index < end)
        })
        .collect();
    if owners.len() == 1 {
        OwnerResolution {
            value: Value::from(owners[0].type_index),
            source: "inferred",
            diagnostics: Vec::new(),
            type_index: Some(owners[0].type_index),
        }
    } else if owners.len() > 1 {
        OwnerResolution {
            value: Value::Null,
            source: "unknown",
            diagnostics: vec!["overlapping_field_ranges"],
            type_index: None,
        }
    } else {
        OwnerResolution {
            value: Value::Null,
            source: "unknown",
            diagnostics: vec!["field_not_in_type_range"],
            type_index: None,
        }
    }
}

fn unknown_owner() -> OwnerResolution {
    OwnerResolution {
        value: Value::Null,
        source: "unknown",
        diagnostics: vec!["member_index_without_field_index"],
        type_index: None,
    }
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP field-layout mapping input is invalid.".into(),
        false,
        "Supply normalized IL2CPP field metadata and layout rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

#[cfg(test)]
mod tests {
    use super::project;
    use serde_json::json;

    #[test]
    fn maps_offsets_and_infers_a_unique_declaring_type() {
        let result = project(&json!({
            "metadata": {
                "types": [{"metadata_index": 7, "field_start": 0, "field_count": 1}],
                "fields": [{"metadata_index": 0, "name": "value"}]
            },
            "binary": {"field_layouts": [{"field_index": 0, "offset": 16}]}
        }))
        .expect("field layout should map");

        assert_eq!(result["status"], "complete");
        assert_eq!(result["items"][0]["declaring_type"], 7);
        assert_eq!(result["items"][0]["field_layout"]["offset"], 16);
    }

    #[test]
    fn distinguishes_missing_and_unknown_offsets() {
        let result = project(&json!({
            "types": [],
            "fields": [{"metadata_index": 0}, {"metadata_index": 1}],
            "field_layouts": [{"field_index": 1, "offset": null}]
        }))
        .expect("partial field layout should be accepted");

        assert_eq!(result["status"], "partial");
        assert_eq!(result["items"][0]["resolution"], "unmapped");
        assert_eq!(result["items"][1]["resolution"], "unknown");
    }

    #[test]
    fn preserves_duplicate_layout_rows_as_ambiguous() {
        let result = project(&json!({
            "types": [],
            "fields": [{"metadata_index": 0}],
            "field_layouts": [
                {"field_index": 0, "offset": 1},
                {"field_index": 0, "offset": 2}
            ]
        }))
        .expect("duplicate layout rows remain observable");

        assert_eq!(result["status"], "partial");
        assert_eq!(result["items"][0]["source_offset_source"], "ambiguous");
        assert_eq!(
            result["items"][0]["field_layout_rows"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn matches_a_field_identity_when_layout_omits_an_optional_member_identity() {
        let result = project(&json!({
            "types": [],
            "fields": [{"metadata_index": 0, "member_index": 4}],
            "field_layouts": [{"field_index": 0, "offset": 16}]
        }))
        .expect("field layout should match by field index");

        assert_eq!(result["items"][0]["resolution"], "mapped");
        assert_eq!(result["items"][0]["source_offset"], 16);
    }

    #[test]
    fn treats_duplicate_member_only_identities_as_ambiguous() {
        let result = project(&json!({
            "types": [],
            "fields": [
                {"member_index": 4},
                {"member_index": 4}
            ],
            "field_layouts": [
                {"member_index": 4, "offset": 16},
                {"member_index": 4, "offset": 24}
            ]
        }))
        .expect("duplicate member identities should remain observable");

        assert_eq!(result["items"][0]["resolution"], "unknown");
        assert_eq!(result["items"][1]["resolution"], "unknown");
    }

    #[test]
    fn preserves_conflicting_storage_kinds_as_ambiguous() {
        let result = project(&json!({
            "types": [],
            "fields": [{"metadata_index": 0, "storage_kind": "instance"}],
            "field_layouts": [
                {"field_index": 0, "storage_kind": "instance", "offset": 16},
                {"field_index": 0, "storage_kind": "static", "offset": 24}
            ]
        }))
        .expect("conflicting layout rows should remain observable");

        assert_eq!(result["items"][0]["resolution"], "unknown");
        assert_eq!(result["items"][0]["source_offset_source"], "ambiguous");
        assert_eq!(result["items"][0]["storage_kind_source"], "ambiguous");
    }
}
