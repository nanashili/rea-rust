//! Captured IL2CPP class field-layout projection.
//!
//! This workflow joins normalized metadata rows with caller-supplied native
//! layout facts.  It never treats an absent offset as zero and never turns a
//! size inferred from field ends into an observed size.  Ambiguous ownership,
//! overlapping ranges, and incomplete rows remain explicit in the result.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_field_layouts";
const MAX_ROWS: usize = 200_000;
const MAX_ROW_PROPERTIES: usize = 128;

/// Project type/field metadata and captured offset facts into class layouts.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = nested_object(root, "metadata");
    let binary = nested_object(root, "binary");

    let types = array_alias(metadata, &["types", "type_definitions"], "types")?;
    let fields = array_alias(metadata, &["fields", "field_definitions"], "fields")?;
    let layouts = array_alias(
        binary,
        &["field_layouts", "field_offsets", "field_layout_rows"],
        "field_layouts",
    )?;
    ensure_bound("types", types)?;
    ensure_bound("fields", fields)?;
    ensure_bound("field_layouts", layouts)?;

    let type_rows = collect_types(types)?;
    let (field_owners, field_rows, field_conflicts) = collect_field_rows(fields, &type_rows)?;
    let (layout_rows, layout_conflicts) = collect_layouts(layouts)?;
    let metadata_source = source_context(root, metadata);
    let binary_source = source_context(root, binary);
    let mut classes = Vec::with_capacity(type_rows.len());
    let mut diagnostics = duplicate_type_diagnostics(&type_rows);
    diagnostics.extend(field_range_diagnostics(&type_rows, fields.len()));
    diagnostics.extend(unresolved_owner_diagnostics(&field_owners, &field_rows));
    diagnostics.extend(field_conflicts);
    diagnostics.extend(layout_conflicts);
    diagnostics.extend(layout_rows.iter().filter_map(|(field_index, layout)| {
        (!field_owners.contains_key(field_index)).then(|| {
            json!({
                "kind": "orphan_field_layout",
                "field_index": field_index,
                "layout": layout,
            })
        })
    }));
    let mut mapped = 0usize;
    let mut unknown = 0usize;
    let mut unmapped = 0usize;
    let mut contradictory = 0usize;
    let mut unknown_facts = 0usize;

    for type_row in &type_rows {
        let mut class_fields = Vec::new();
        let mut observed_ends = Vec::new();
        for (field_index, owner) in &field_owners {
            if owner.as_ref() != Some(&type_row.index) {
                continue;
            }
            let field = field_rows.get(field_index).cloned().unwrap_or(Value::Null);
            let layout = layout_rows.get(field_index).cloned();
            let status = layout_status(layout.as_ref());
            let field_size = resolve_field_fact(
                field.as_object(),
                layout.as_ref().and_then(Value::as_object),
                &["size", "field_size", "fieldSize"],
            );
            let field_alignment = resolve_field_fact(
                field.as_object(),
                layout.as_ref().and_then(Value::as_object),
                &["alignment", "field_alignment", "fieldAlignment"],
            );

            if field_size.source == "unknown" {
                unknown_facts += 1;
            }
            if field_alignment.source == "unknown" {
                unknown_facts += 1;
            }

            match status {
                "mapped" => mapped += 1,
                "unknown" => unknown += 1,
                _ => unmapped += 1,
            }
            if field_size.source == "contradictory" || field_alignment.source == "contradictory" {
                contradictory += 1;
                diagnostics.push(json!({
                    "kind": "contradictory_field_layout_fact",
                    "type_index": type_row.index,
                    "field_index": field_index,
                    "size_source": field_size.source,
                    "alignment_source": field_alignment.source,
                }));
            }
            if let Some(end) = observed_end(layout.as_ref(), field_size.value) {
                observed_ends.push(end);
            }
            class_fields.push(json!({
                "field_index": field_index,
                "field": field,
                "layout": layout.unwrap_or(Value::Null),
                "status": status,
                "facts": {
                    "size": fact_value(&field_size),
                    "size_source": field_size.source,
                    "size_sources": field_size.sources,
                    "alignment": fact_value(&field_alignment),
                    "alignment_source": field_alignment.source,
                    "alignment_sources": field_alignment.sources,
                },
                "sources": {
                    "metadata": metadata_source.clone(),
                    "binary": binary_source.clone(),
                },
            }));
        }

        let overlaps = find_overlaps(&class_fields);
        diagnostics.extend(overlaps.iter().map(|overlap| {
            json!({
                "kind": "overlapping_fields",
                "type_index": type_row.index,
                "fields": overlap,
            })
        }));

        let explicit_size = resolve_fact(
            type_row.source.as_object(),
            &["size", "instance_size"],
            "metadata",
        );
        let inferred_size = observed_ends.into_iter().max();
        let size = if explicit_size.source == "contradictory" {
            None
        } else {
            explicit_size.value.or(inferred_size)
        };
        let size_source = if explicit_size.source == "contradictory" {
            contradictory += 1;
            diagnostics.push(json!({
                "kind": "contradictory_type_layout_fact",
                "type_index": type_row.index,
                "fact": "size",
                "sources": explicit_size.sources,
            }));
            "contradictory"
        } else if explicit_size.value.is_some() {
            "observed"
        } else if inferred_size.is_some() {
            "inferred_from_field_ends"
        } else {
            "unknown"
        };
        if size_source == "unknown" {
            unknown_facts += 1;
        }

        let explicit_alignment = resolve_fact(
            type_row.source.as_object(),
            &["alignment", "instance_alignment"],
            "metadata",
        );
        let alignment_source = if explicit_alignment.source == "contradictory" {
            contradictory += 1;
            diagnostics.push(json!({
                "kind": "contradictory_type_layout_fact",
                "type_index": type_row.index,
                "fact": "alignment",
                "sources": explicit_alignment.sources,
            }));
            "contradictory"
        } else if explicit_alignment.value.is_some() {
            "observed"
        } else {
            "unknown"
        };
        if alignment_source == "unknown" {
            unknown_facts += 1;
        }

        let class_status = class_layout_status(
            &class_fields,
            &overlaps,
            size,
            size_source,
            alignment_source,
        );

        classes.push(json!({
            "type_index": type_row.index,
            "type": type_row.source,
            "parent_type": type_row.parent,
            "fields": class_fields,
            "sources": {
                "metadata": metadata_source.clone(),
                "binary": binary_source.clone(),
            },
            "layout": {
                "size": size,
                "size_source": size_source,
                "alignment": explicit_alignment.value,
                "alignment_source": alignment_source,
                "alignment_sources": explicit_alignment.sources,
                "overlap_count": overlaps.len(),
            },
            "status": class_status,
        }));
    }

    let unresolved_owners = field_owners
        .values()
        .filter(|owner| owner.is_none())
        .count();
    Ok(json!({
        "operation": OPERATION,
        "status": if unresolved_owners == 0
            && diagnostics.is_empty()
            && classes.iter().all(|class| class["status"] == "complete")
        {
            "complete"
        } else {
            "partial"
        },
        "classes": classes,
        "sources": {
            "metadata": metadata_source,
            "binary": binary_source,
        },
        "coverage": {
            "type_rows": types.len(),
            "field_rows": fields.len(),
            "layout_rows": layouts.len(),
            "mapped_fields": mapped,
            "unknown_fields": unknown,
            "unmapped_fields": unmapped,
            "contradictory_facts": contradictory,
            "unknown_facts": unknown_facts,
            "unresolved_owners": unresolved_owners,
        },
        "diagnostics": diagnostics,
        "limitations": ["Class size is inferred only when no captured size is supplied; alignment is never inferred."],
    }))
}

fn class_layout_status(
    fields: &[Value],
    overlaps: &[Vec<u64>],
    size: Option<u64>,
    size_source: &str,
    alignment_source: &str,
) -> &'static str {
    let has_complete_fields = fields.iter().all(field_layout_is_complete);

    if overlaps.is_empty()
        && size.is_some()
        && size_source != "contradictory"
        && alignment_source == "observed"
        && has_complete_fields
    {
        "complete"
    } else {
        "partial"
    }
}

fn field_layout_is_complete(field: &Value) -> bool {
    let facts = field.get("facts").and_then(Value::as_object);
    let size_source = facts
        .and_then(|facts| facts.get("size_source"))
        .and_then(Value::as_str);
    let alignment_source = facts
        .and_then(|facts| facts.get("alignment_source"))
        .and_then(Value::as_str);

    field.get("status").and_then(Value::as_str) == Some("mapped")
        && size_source == Some("observed")
        && alignment_source == Some("observed")
}

struct TypeRow {
    index: u64,
    parent: Value,
    source: Value,
    field_start: i64,
    field_count: u64,
}

fn collect_types(rows: &[Value]) -> Result<Vec<TypeRow>, Failure> {
    rows.iter()
        .enumerate()
        .map(|(row, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
            ensure_row_properties("types", row, object)?;
            let index = integer_alias(object, &["metadata_index", "type_index", "index"])
                .unwrap_or(row as u64);
            let field_start =
                signed_integer_alias(object, &["field_start", "fieldStart"]).unwrap_or(0);
            let field_count = integer_alias(object, &["field_count", "fieldCount"]).unwrap_or(0);
            if field_start >= 0 {
                u64::try_from(field_start)
                    .ok()
                    .and_then(|start| start.checked_add(field_count))
                    .ok_or_else(|| invalid_row("types", row, "Field range overflows"))?;
            }
            let parent = object
                .get("parent_type")
                .or_else(|| object.get("base_type"))
                .cloned()
                .unwrap_or(Value::Null);
            Ok(TypeRow {
                index,
                parent,
                source: value.clone(),
                field_start,
                field_count,
            })
        })
        .collect()
}

fn duplicate_type_diagnostics(types: &[TypeRow]) -> Vec<Value> {
    let mut rows_by_index: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    for type_row in types {
        rows_by_index
            .entry(type_row.index)
            .or_default()
            .push(type_row.source.clone());
    }

    rows_by_index
        .into_iter()
        .filter_map(|(type_index, rows)| {
            (rows.len() > 1).then(|| {
                json!({
                    "kind": "conflicting_type_identity",
                    "type_index": type_index,
                    "types": rows,
                })
            })
        })
        .collect()
}

fn field_range_diagnostics(types: &[TypeRow], field_total: usize) -> Vec<Value> {
    types
        .iter()
        .filter_map(|type_row| {
            let valid = if type_row.field_count == 0 {
                type_row.field_start >= -1
                    && u64::try_from(type_row.field_start)
                        .map_or(true, |start| start <= field_total as u64)
            } else {
                u64::try_from(type_row.field_start)
                    .ok()
                    .and_then(|start| start.checked_add(type_row.field_count))
                    .is_some_and(|end| end <= field_total as u64)
            };
            (!valid).then(|| {
                json!({
                    "kind": "malformed_type_field_range",
                    "type_index": type_row.index,
                    "field_start": type_row.field_start,
                    "field_count": type_row.field_count,
                    "available_fields": field_total,
                    "type": type_row.source,
                })
            })
        })
        .collect()
}

fn collect_field_rows(
    fields: &[Value],
    types: &[TypeRow],
) -> Result<(BTreeMap<u64, Option<u64>>, BTreeMap<u64, Value>, Vec<Value>), Failure> {
    let mut owners = BTreeMap::new();
    let mut rows = BTreeMap::new();
    let mut conflicts = Vec::new();
    for (row, value) in fields.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("fields", row, "Expected an object"))?;
        ensure_row_properties("fields", row, object)?;
        let index = integer_alias(object, &["metadata_index", "field_index", "index"])
            .unwrap_or(row as u64);
        let explicit = object
            .get("declaring_type")
            .or_else(|| object.get("declaring_type_index"))
            .or_else(|| nested_identity_value(object, &["declaring_type", "declaring_type_index"]));
        let owner = if let Some(value) = explicit {
            let owner = value
                .as_u64()
                .ok_or_else(|| invalid_row("fields", row, "declaring_type must be an integer"))?;
            let matching_types = types.iter().filter(|ty| ty.index == owner).count();
            (matching_types == 1).then_some(owner)
        } else {
            let matches: Vec<u64> = types
                .iter()
                .filter(|ty| {
                    u64::try_from(ty.field_start)
                        .ok()
                        .and_then(|start| start.checked_add(ty.field_count).map(|end| (start, end)))
                        .is_some_and(|(start, end)| index >= start && index < end)
                })
                .map(|ty| ty.index)
                .collect();
            if matches.len() == 1 {
                matches.first().copied()
            } else {
                None
            }
        };
        if owners.insert(index, owner).is_some() {
            owners.insert(index, None);
            conflicts.push(json!({
                "kind": "conflicting_field_identity",
                "field_index": index,
                "fields": [rows.get(&index).cloned().unwrap_or(Value::Null), value],
            }));
            continue;
        }
        rows.insert(index, value.clone());
    }
    Ok((owners, rows, conflicts))
}

fn collect_layouts(rows: &[Value]) -> Result<(BTreeMap<u64, Value>, Vec<Value>), Failure> {
    let mut result = BTreeMap::new();
    let mut conflicts = Vec::new();
    let mut conflicted = BTreeSet::new();
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("field_layouts", row, "Expected an object"))?;
        ensure_row_properties("field_layouts", row, object)?;
        let index = integer_alias(object, &["field_index", "metadata_index", "index"])
            .ok_or_else(|| invalid_row("field_layouts", row, "field_index is required"))?;
        if conflicted.contains(&index) {
            conflicts.push(json!({
                "kind": "conflicting_field_layout_identity",
                "field_index": index,
                "layouts": [value],
            }));
            continue;
        }
        if let Some(previous) = result.remove(&index) {
            conflicted.insert(index);
            conflicts.push(json!({
                "kind": "conflicting_field_layout_identity",
                "field_index": index,
                "layouts": [previous, value],
            }));
        } else {
            result.insert(index, value.clone());
        }
    }
    Ok((result, conflicts))
}

fn layout_status(layout: Option<&Value>) -> &'static str {
    match layout.and_then(Value::as_object) {
        Some(row) if row.get("offset").and_then(Value::as_u64).is_some() => "mapped",
        Some(_) => "unknown",
        None => "unmapped",
    }
}

#[derive(Clone)]
struct FactResolution {
    value: Option<u64>,
    source: &'static str,
    sources: Vec<&'static str>,
    present: bool,
}

fn resolve_field_fact(
    field: Option<&Map<String, Value>>,
    layout: Option<&Map<String, Value>>,
    aliases: &[&str],
) -> FactResolution {
    let mut resolution = resolve_fact(field, aliases, "metadata");
    let layout_resolution = resolve_fact(layout, aliases, "binary");

    if resolution.source == "contradictory" || layout_resolution.source == "contradictory" {
        resolution.value = None;
        resolution.source = "contradictory";
    } else if let (Some(field_value), Some(layout_value)) =
        (resolution.value, layout_resolution.value)
    {
        if field_value != layout_value {
            resolution.value = None;
            resolution.source = "contradictory";
        }
    } else if resolution.value.is_none() {
        resolution.value = layout_resolution.value;
        if layout_resolution.value.is_some() {
            resolution.source = "observed";
        }
    }

    if layout_resolution.present {
        resolution.sources.push("binary");
    }
    resolution.sources.sort_unstable();
    resolution.sources.dedup();
    resolution
}

fn resolve_fact(
    object: Option<&Map<String, Value>>,
    aliases: &[&str],
    source: &'static str,
) -> FactResolution {
    let Some(object) = object else {
        return FactResolution {
            value: None,
            source: "unknown",
            sources: Vec::new(),
            present: false,
        };
    };

    let values: Vec<u64> = aliases
        .iter()
        .filter_map(|alias| object.get(*alias).and_then(Value::as_u64))
        .collect();
    let has_fact = aliases.iter().any(|alias| object.contains_key(*alias));
    let value = values.first().copied();
    let source_name = if values.windows(2).any(|pair| pair[0] != pair[1]) {
        "contradictory"
    } else if value.is_some() {
        "observed"
    } else if has_fact {
        "unknown"
    } else {
        "unknown"
    };

    FactResolution {
        value: if source_name == "contradictory" {
            None
        } else {
            value
        },
        source: source_name,
        sources: if has_fact { vec![source] } else { Vec::new() },
        present: has_fact,
    }
}

fn fact_value(fact: &FactResolution) -> Option<u64> {
    fact.value
}

fn observed_end(layout: Option<&Value>, size: Option<u64>) -> Option<u64> {
    let object = layout?.as_object()?;
    let offset = object.get("offset")?.as_u64()?;
    let size = size?;
    offset.checked_add(size)
}

fn find_overlaps(fields: &[Value]) -> Vec<Vec<u64>> {
    let mut spans = Vec::new();
    for field in fields {
        let Some(layout) = field.get("layout").and_then(Value::as_object) else {
            continue;
        };
        let Some(offset) = layout.get("offset").and_then(Value::as_u64) else {
            continue;
        };
        let size = field
            .get("facts")
            .and_then(Value::as_object)
            .and_then(|facts| facts.get("size"))
            .and_then(Value::as_u64)
            .or_else(|| layout.get("size").and_then(Value::as_u64));
        let Some(size) = size else {
            continue;
        };
        if let Some(index) = field.get("field_index").and_then(Value::as_u64) {
            spans.push((offset, offset.saturating_add(size), index));
        }
    }
    let mut overlaps = Vec::new();
    for (position, (start, end, index)) in spans.iter().enumerate() {
        for (other_start, other_end, other_index) in spans.iter().skip(position + 1) {
            if *start < *other_end && *other_start < *end {
                overlaps.push(vec![*index, *other_index]);
            }
        }
    }
    overlaps
}

fn unresolved_owner_diagnostics(
    owners: &BTreeMap<u64, Option<u64>>,
    fields: &BTreeMap<u64, Value>,
) -> Vec<Value> {
    owners
        .iter()
        .filter_map(|(field_index, owner)| {
            owner.is_none().then(|| {
                json!({
                    "kind": "unresolved_field_owner",
                    "field_index": field_index,
                    "field": fields.get(field_index).cloned().unwrap_or(Value::Null),
                })
            })
        })
        .collect()
}

fn nested_object<'a>(root: &'a Map<String, Value>, key: &str) -> &'a Map<String, Value> {
    root.get(key).and_then(Value::as_object).unwrap_or(root)
}

fn source_context(root: &Map<String, Value>, nested: &Map<String, Value>) -> Value {
    const SOURCE_KEYS: [&str; 6] = [
        "source_evidence",
        "source_evidence_id",
        "evidence",
        "artifact_sha256",
        "artifact_path",
        "source",
    ];

    let mut source = Map::new();
    for key in SOURCE_KEYS {
        let value = nested.get(key).or_else(|| root.get(key));
        if let Some(value) = value {
            source.insert(key.into(), value.clone());
        }
    }
    Value::Object(source)
}

fn array_alias<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    aliases
        .iter()
        .find_map(|alias| object.get(*alias))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(field, "Expected an array"))
}

fn ensure_bound(field: &str, rows: &[Value]) -> Result<(), Failure> {
    if rows.len() > MAX_ROWS {
        Err(invalid(
            field,
            "Collection exceeds the IL2CPP field-layout limit",
        ))
    } else {
        Ok(())
    }
}

fn ensure_row_properties(
    collection: &str,
    row: usize,
    object: &Map<String, Value>,
) -> Result<(), Failure> {
    if object.len() > MAX_ROW_PROPERTIES {
        return Err(invalid_row(
            collection,
            row,
            "Source row exceeds the 128-property limit",
        ));
    }

    Ok(())
}

fn integer_alias(object: &Map<String, Value>, aliases: &[&str]) -> Option<u64> {
    aliases
        .iter()
        .find_map(|alias| object.get(*alias).and_then(Value::as_u64))
        .or_else(|| {
            [
                "member_identity",
                "memberIdentity",
                "field_identity",
                "fieldIdentity",
                "type_identity",
                "typeIdentity",
            ]
            .iter()
            .filter_map(|key| object.get(*key).and_then(Value::as_object))
            .find_map(|identity| {
                aliases
                    .iter()
                    .find_map(|alias| identity.get(*alias).and_then(Value::as_u64))
            })
        })
}

fn signed_integer_alias(object: &Map<String, Value>, aliases: &[&str]) -> Option<i64> {
    aliases
        .iter()
        .find_map(|alias| object.get(*alias).and_then(Value::as_i64))
        .or_else(|| {
            aliases.iter().find_map(|alias| {
                object
                    .get(*alias)
                    .and_then(Value::as_u64)
                    .and_then(|value| i64::try_from(value).ok())
            })
        })
        .or_else(|| {
            [
                "member_identity",
                "memberIdentity",
                "field_identity",
                "fieldIdentity",
                "type_identity",
                "typeIdentity",
            ]
            .iter()
            .filter_map(|key| object.get(*key).and_then(Value::as_object))
            .find_map(|identity| signed_integer_alias(identity, aliases))
        })
}

fn nested_identity_value<'a>(
    object: &'a Map<String, Value>,
    aliases: &[&str],
) -> Option<&'a Value> {
    [
        "member_identity",
        "memberIdentity",
        "field_identity",
        "fieldIdentity",
        "type_identity",
        "typeIdentity",
    ]
    .iter()
    .filter_map(|key| object.get(*key).and_then(Value::as_object))
    .find_map(|identity| aliases.iter().find_map(|alias| identity.get(*alias)))
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP field-layout workflow input is invalid.".into(),
        false,
        "Supply bounded normalized IL2CPP metadata and captured field-layout rows and retry."
            .into(),
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
    fn reports_each_unresolved_owner_once() {
        let result = project(&json!({
            "types": [
                {"metadata_index": 1, "field_start": 0, "field_count": 0},
                {"metadata_index": 2, "field_start": 1, "field_count": 0}
            ],
            "fields": [{"metadata_index": 9}],
            "field_layouts": []
        }))
        .expect("workflow should retain unresolved ownership");

        assert_eq!(result["diagnostics"].as_array().unwrap().len(), 1);
        assert_eq!(result["diagnostics"][0]["field_index"], 9);
    }

    #[test]
    fn detects_overlap_when_size_is_supplied_by_metadata() {
        let result = project(&json!({
            "types": [{"metadata_index": 1, "field_start": 0, "field_count": 2}],
            "fields": [
                {"metadata_index": 0, "size": 8},
                {"metadata_index": 1, "size": 8}
            ],
            "field_layouts": [
                {"field_index": 0, "offset": 16},
                {"field_index": 1, "offset": 20}
            ]
        }))
        .expect("workflow should project metadata field sizes");

        assert_eq!(result["classes"][0]["layout"]["overlap_count"], 1);
        assert_eq!(result["diagnostics"][0]["kind"], "overlapping_fields");
    }
}
