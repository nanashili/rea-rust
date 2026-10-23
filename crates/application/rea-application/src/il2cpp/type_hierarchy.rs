//! Projection of IL2CPP type-definition relationships supplied by a caller.
//!
//! This module does not decode bytes or select a preferred interpretation of
//! malformed metadata.  It retains every type row and reports unresolved,
//! duplicate, and cyclic relationships explicitly.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "project_il2cpp_type_hierarchy";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Project type-definition rows into a relationship graph.
///
/// The input may contain `types` directly or under `metadata.types`.  A type
/// identity is read from `metadata_index`, `type_index`, or `index`; when a
/// normalized row omits those fields, its array position is retained as the
/// row identity.  References are never silently discarded.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    validate_input_shape(root)?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let rows = metadata
        .get("types")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("types", "Expected an array of type-definition rows"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid("types", "Type-definition collection is too large"));
    }
    validate_type_rows(rows)?;

    let identities = collect_identities(rows)?;
    let identity_index = IdentityIndex::new(&identities);
    let duplicate_indices = duplicate_indices(&identities);
    let nested_rows = metadata.get("nested_types").and_then(Value::as_array);
    let methods = metadata.get("methods").and_then(Value::as_array);
    let fields = metadata.get("fields").and_then(Value::as_array);
    let interface_rows = metadata.get("interfaces").and_then(Value::as_array);
    let mut items = Vec::with_capacity(rows.len());
    let mut unresolved = 0usize;
    let mut relationship_edges = 0usize;
    let mut range_diagnostics = Vec::new();
    let mut nested_references = BTreeSet::new();

    for (row_number, row) in rows.iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| invalid_row("types", row_number, "Expected an object"))?;
        let identity = identities[row_number].0;
        let declaring = relationship(object, &["declaring_type", "declaringType"])?;
        let parent = relationship(
            object,
            &["parent_type", "parent", "base_type", "parent_index"],
        )?;
        let nested = interface_relationships_named(
            object,
            &["nested_types", "nested_type_indices", "nestedTypeIndices"],
        )?;
        let interfaces = interface_relationships(object)?;
        let vtable = vtable_range(object)?;
        let ranges = collect_ranges(
            object,
            row_number,
            [
                ("methods", methods.map(Vec::len)),
                ("fields", fields.map(Vec::len)),
                ("interfaces", interface_rows.map(Vec::len)),
                ("nested_types", nested_rows.map(Vec::len)),
            ],
            &mut range_diagnostics,
        )?;

        let mut relations = Vec::new();
        append_relation(
            &mut relations,
            "declaring_type",
            &declaring,
            &identity_index,
            &mut unresolved,
        );
        append_relation(
            &mut relations,
            "parent_type",
            &parent,
            &identity_index,
            &mut unresolved,
        );
        for child in nested {
            append_reference_relation(
                &mut relations,
                "nested_type",
                Some(child),
                &identity_index,
                &mut unresolved,
            );
        }
        if let Some(nested_range) = ranges.get("nested_types") {
            for index in range_indices(nested_range, nested_rows.map(Vec::len)) {
                if let Some(value) = nested_rows.and_then(|rows| rows.get(index)) {
                    nested_references.insert(index);
                    if let Some(child) = reference_value(value) {
                        append_reference_relation(
                            &mut relations,
                            "nested_type",
                            Some(child),
                            &identity_index,
                            &mut unresolved,
                        );
                    } else {
                        append_unresolved_relation(
                            &mut relations,
                            "nested_type",
                            index as u64,
                            &mut unresolved,
                        );
                    }
                } else {
                    append_unresolved_relation(
                        &mut relations,
                        "nested_type",
                        index as u64,
                        &mut unresolved,
                    );
                }
            }
        }
        for interface in interfaces {
            append_reference_relation(
                &mut relations,
                "interface",
                Some(interface),
                &identity_index,
                &mut unresolved,
            );
        }
        if relations.len() > MAX_ROWS {
            return Err(invalid_row(
                "types",
                row_number,
                "Projected relationship collection is too large",
            ));
        }
        relationship_edges += relations.len();

        items.push(json!({
            "index": identity,
            "row": row_number,
            "source": row,
            "relationships": relations,
            "ranges": ranges,
            "vtable": vtable,
        }));
    }

    let cycles = find_cycles(&items);
    append_range_overlaps(&items, &mut range_diagnostics);
    let duplicate_count = duplicate_indices.len();
    let orphan_nested_rows = nested_rows
        .map(|rows| {
            (0..rows.len())
                .filter(|index| !nested_references.contains(index))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let orphan_rows = BTreeMap::from([
        ("methods", orphan_table_rows(&items, "methods", methods)),
        ("fields", orphan_table_rows(&items, "fields", fields)),
        (
            "interfaces",
            orphan_table_rows(&items, "interfaces", interface_rows),
        ),
        (
            "nested_types",
            orphan_table_rows(&items, "nested_types", nested_rows),
        ),
    ]);
    let has_orphan_rows = orphan_rows.values().any(|rows| !rows.is_empty());
    let partial = unresolved > 0
        || duplicate_count > 0
        || !cycles.is_empty()
        || !range_diagnostics.is_empty()
        || !orphan_nested_rows.is_empty()
        || has_orphan_rows;
    Ok(json!({
        "status": if partial { "partial" } else { "complete" },
        "types": items,
        "coverage": {
            "type_rows": rows.len(),
            "unique_type_indices": identity_index.known.len(),
            "relationship_edges": relationship_edges,
            "unresolved_relationships": unresolved,
            "duplicate_type_indices": duplicate_count,
            "cycles": cycles.len(),
            "range_diagnostics": range_diagnostics.len(),
            "orphan_nested_rows": orphan_nested_rows.len(),
        },
        "diagnostics": {
            "duplicate_type_indices": duplicate_indices,
            "cycles": cycles,
            "range_diagnostics": range_diagnostics,
            "orphan_nested_rows": orphan_nested_rows,
            "orphan_rows": orphan_rows,
        },
    }))
}

fn validate_input_shape(root: &Map<String, Value>) -> Result<(), Failure> {
    if let Some(metadata_value) = root.get("metadata") {
        if root.len() != 1 {
            return Err(invalid(
                "input",
                "Metadata input cannot contain direct tables or unknown fields",
            ));
        }
        let metadata = metadata_value
            .as_object()
            .ok_or_else(|| invalid("metadata", "Metadata must be an object"))?;
        validate_allowed_keys(
            metadata,
            &["types", "nested_types", "methods", "fields", "interfaces"],
            "metadata",
        )?;
        if !metadata.contains_key("types") {
            return Err(invalid("metadata.types", "Metadata types are required"));
        }
        validate_tables(metadata)?;
        return Ok(());
    }

    validate_allowed_keys(
        root,
        &["types", "nested_types", "methods", "fields", "interfaces"],
        "input",
    )?;
    if !root.contains_key("types") {
        return Err(invalid("types", "Type-definition rows are required"));
    }
    validate_tables(root)
}

fn validate_allowed_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    field: &str,
) -> Result<(), Failure> {
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(field, &format!("Unknown field: {key}")));
    }
    Ok(())
}

fn validate_tables(object: &Map<String, Value>) -> Result<(), Failure> {
    for table in ["types", "nested_types", "methods", "fields", "interfaces"] {
        let Some(value) = object.get(table) else {
            continue;
        };
        let rows = value
            .as_array()
            .ok_or_else(|| invalid(table, "Expected an array"))?;
        if rows.len() > MAX_ROWS {
            return Err(invalid(table, "Collection is too large"));
        }
    }
    Ok(())
}

fn validate_type_rows(rows: &[Value]) -> Result<(), Failure> {
    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
        if object.len() > 128 {
            return Err(invalid_row(
                "types",
                row,
                "Type row contains too many fields",
            ));
        }
        for field in [
            "nested_types",
            "nested_type_indices",
            "nestedTypeIndices",
            "interfaces",
            "interface_indices",
            "interface_types",
        ] {
            if object
                .get(field)
                .and_then(Value::as_array)
                .is_some_and(|values| values.len() > MAX_ROWS)
            {
                return Err(invalid_row(
                    "types",
                    row,
                    "Relationship collection is too large",
                ));
            }
        }
    }
    Ok(())
}

fn collect_identities(rows: &[Value]) -> Result<Vec<(u64, &'static str)>, Failure> {
    rows.iter()
        .enumerate()
        .map(|(row, value)| {
            let object = value
                .as_object()
                .ok_or_else(|| invalid_row("types", row, "Expected an object"))?;
            let mut selected = None;
            for (field, source) in [
                ("metadata_index", "metadata_index"),
                ("type_index", "type_index"),
                ("index", "index"),
                ("source_index", "source_index"),
                ("sourceIndex", "sourceIndex"),
            ] {
                if let Some(value) = object.get(field) {
                    if selected.is_some() && source.starts_with("source") {
                        continue;
                    }
                    let index = value.as_u64().ok_or_else(|| {
                        invalid_row("types", row, "Type identity must be a non-negative integer")
                    })?;
                    if index > MAX_SAFE_INTEGER {
                        return Err(invalid_row(
                            "types",
                            row,
                            "Type identity must be at most Number.MAX_SAFE_INTEGER",
                        ));
                    }
                    if let Some((selected_index, selected_source)) = selected {
                        if selected_index != index {
                            return Err(invalid_row(
                                "types",
                                row,
                                "Type identity aliases disagree",
                            ));
                        }
                        selected = Some((selected_index, selected_source));
                    } else {
                        selected = Some((index, source));
                    }
                }
            }
            Ok(selected.unwrap_or((row as u64, "row")))
        })
        .collect()
}

fn duplicate_indices(identities: &[(u64, &str)]) -> Vec<u64> {
    let mut counts = BTreeMap::new();
    for (index, _) in identities {
        *counts.entry(*index).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .filter_map(|(index, count)| (count > 1).then_some(index))
        .collect()
}

struct IdentityIndex {
    known: BTreeSet<u64>,
    duplicates: BTreeSet<u64>,
    row_identities: Vec<u64>,
}

impl IdentityIndex {
    fn new(identities: &[(u64, &str)]) -> Self {
        let mut counts = BTreeMap::new();
        for (index, _) in identities {
            *counts.entry(*index).or_insert(0usize) += 1;
        }

        Self {
            known: counts.keys().copied().collect(),
            duplicates: counts
                .into_iter()
                .filter_map(|(index, count)| (count > 1).then_some(index))
                .collect(),
            row_identities: identities.iter().map(|(index, _)| *index).collect(),
        }
    }

    fn resolve(&self, reference: u64) -> ResolvedReference {
        // Captured metadata commonly stores relationships as positions in the
        // source type table, while normalized rows may expose an explicit
        // metadata or type identity.  Keep both interpretations until they
        // agree; choosing one would turn a source-index collision into a
        // false relationship.
        let identity_target = self.known.contains(&reference).then_some(reference);
        let row_target = usize::try_from(reference)
            .ok()
            .and_then(|row| self.row_identities.get(row).copied());

        match (identity_target, row_target) {
            (Some(identity_target), Some(row_target)) if identity_target != row_target => {
                ResolvedReference {
                    target: reference,
                    ambiguous: true,
                }
            }
            (Some(identity_target), _) => ResolvedReference {
                target: identity_target,
                ambiguous: false,
            },
            (None, Some(row_target)) => ResolvedReference {
                target: row_target,
                ambiguous: false,
            },
            (None, None) => ResolvedReference {
                target: reference,
                ambiguous: false,
            },
        }
    }
}

struct ResolvedReference {
    target: u64,
    ambiguous: bool,
}

struct RelationshipValues {
    targets: Vec<u64>,
    ambiguous: bool,
}

fn relationship(
    object: &Map<String, Value>,
    aliases: &[&str],
) -> Result<RelationshipValues, Failure> {
    let mut targets = Vec::new();
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            let reference = parse_reference(value)?;
            if let Some(reference) = reference {
                if !targets.contains(&reference) {
                    targets.push(reference);
                }
            }
        }
    }
    Ok(RelationshipValues {
        ambiguous: targets.len() > 1,
        targets,
    })
}

fn parse_reference(value: &Value) -> Result<Option<u64>, Failure> {
    if value.is_null() {
        return Ok(None);
    }
    if let Some(index) = reference_value(value) {
        return Ok(Some(index));
    }
    let signed = value
        .as_i64()
        .ok_or_else(|| invalid("relationship", "Reference must be an integer or null"))?;
    if signed == -1 {
        return Ok(None);
    }
    if signed < -1 {
        return Err(invalid(
            "relationship",
            "Reference must be -1 or a non-negative integer",
        ));
    }
    let index = signed as u64;
    if index > MAX_SAFE_INTEGER {
        return Err(invalid(
            "relationship",
            "Reference must be at most Number.MAX_SAFE_INTEGER",
        ));
    }
    Ok(Some(index))
}

fn interface_relationships(object: &Map<String, Value>) -> Result<Vec<u64>, Failure> {
    interface_relationships_named(
        object,
        &["interfaces", "interface_indices", "interface_types"],
    )
}

fn interface_relationships_named(
    object: &Map<String, Value>,
    aliases: &[&str],
) -> Result<Vec<u64>, Failure> {
    let mut selected = None;
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            let values = value
                .as_array()
                .ok_or_else(|| invalid(alias, "Interfaces must be an array"))?;
            let values = values
                .iter()
                .map(parse_required_reference)
                .collect::<Result<Vec<_>, _>>()?;
            if let Some(selected_values) = &selected {
                if selected_values != &values {
                    return Err(invalid(aliases[0], "Interface aliases disagree"));
                }
            } else {
                selected = Some(values);
            }
        }
    }
    Ok(selected.unwrap_or_default())
}

fn parse_required_reference(value: &Value) -> Result<u64, Failure> {
    parse_reference(value)?
        .ok_or_else(|| invalid("interfaces", "Interface reference cannot be null"))
}

fn vtable_range(object: &Map<String, Value>) -> Result<Value, Failure> {
    let start = first_u64(object, &["vtable_start", "vtableStart"])?;
    let count = first_u64(object, &["vtable_count", "vtableCount"])?;
    match (start, count) {
        (None, None) => Ok(Value::Null),
        (Some(start), Some(count)) => {
            let end = safe_range_end(start, count, "vtable")?;
            Ok(json!({ "start": start, "count": count, "end": end }))
        }
        _ => Err(invalid(
            "vtable",
            "Vtable start and count must be supplied together",
        )),
    }
}

fn collect_ranges(
    object: &Map<String, Value>,
    row: usize,
    tables: [(&str, Option<usize>); 4],
    diagnostics: &mut Vec<Value>,
) -> Result<Map<String, Value>, Failure> {
    let mut ranges = Map::new();
    for (name, table_len) in tables {
        let (start_aliases, count_aliases) = range_aliases(name);
        let start = first_signed(object, start_aliases)?;
        let count = first_u64(object, count_aliases)?;
        let Some(start) = start else {
            if count.is_some() {
                diagnostics.push(json!({"kind":"incomplete-range", "row":row, "table":name}));
            }
            continue;
        };
        let Some(count) = count else {
            diagnostics.push(json!({
                "kind": "incomplete-range",
                "row": row,
                "table": name,
                "start": start,
                "count": Value::Null,
            }));

            // A missing count is unknown, rather than an empty range.  Keep
            // the range null so coverage and overlap checks cannot claim that
            // the table rows are accounted for by a fabricated endpoint.
            ranges.insert(name.to_owned(), Value::Null);
            continue;
        };
        if start < 0 {
            if count != 0 {
                diagnostics.push(json!({"kind":"incomplete-range", "row":row, "table":name, "start":start, "count":count}));
            }
            ranges.insert(name.to_owned(), Value::Null);
            continue;
        }
        let start = start as u64;
        let end = safe_range_end(start, count, name)?;
        let start = usize::try_from(start)
            .map_err(|_| invalid(name, "Range start does not fit the host index type"))?;
        let end = usize::try_from(end)
            .map_err(|_| invalid(name, "Range end does not fit the host index type"))?;
        if let Some(length) = table_len {
            if end > length {
                diagnostics.push(json!({"kind":"range-out-of-bounds", "row":row, "table":name, "start":start, "count":count, "table_length":length}));
            }
        }
        ranges.insert(
            name.to_owned(),
            json!({"start":start, "count":count, "end":end}),
        );
    }
    Ok(ranges)
}

fn range_aliases(name: &str) -> (&'static [&'static str], &'static [&'static str]) {
    match name {
        "methods" => (
            &[
                "methods_start",
                "methodsStart",
                "method_start",
                "methodStart",
            ],
            &[
                "methods_count",
                "methodsCount",
                "method_count",
                "methodCount",
            ],
        ),
        "fields" => (
            &["fields_start", "fieldsStart", "field_start", "fieldStart"],
            &["fields_count", "fieldsCount", "field_count", "fieldCount"],
        ),
        "interfaces" => (
            &[
                "interfaces_start",
                "interfacesStart",
                "interface_start",
                "interfaceStart",
            ],
            &[
                "interfaces_count",
                "interfacesCount",
                "interface_count",
                "interfaceCount",
            ],
        ),
        "nested_types" => (
            &[
                "nested_types_start",
                "nested_typesStart",
                "nested_type_start",
                "nestedTypeStart",
            ],
            &[
                "nested_types_count",
                "nested_typesCount",
                "nested_type_count",
                "nestedTypeCount",
            ],
        ),
        _ => (&[], &[]),
    }
}

fn safe_range_end(start: u64, count: u64, field: &str) -> Result<u64, Failure> {
    let end = start
        .checked_add(count)
        .ok_or_else(|| invalid(field, "Range overflows"))?;
    if end > MAX_SAFE_INTEGER {
        return Err(invalid(
            field,
            "Range end must be at most Number.MAX_SAFE_INTEGER",
        ));
    }
    Ok(end)
}

fn first_signed(object: &Map<String, Value>, aliases: &[&str]) -> Result<Option<i64>, Failure> {
    let mut selected = None;
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            let value = value
                .as_i64()
                .ok_or_else(|| invalid(alias, "Value must be an integer"));
            let value = value?;
            if !(-1..=MAX_SAFE_INTEGER as i64).contains(&value) {
                return Err(invalid(
                    alias,
                    "Value must be between -1 and Number.MAX_SAFE_INTEGER",
                ));
            }
            if let Some(selected_value) = selected {
                if selected_value != value {
                    return Err(invalid(aliases[0], "Range aliases disagree"));
                }
            } else {
                selected = Some(value);
            }
        }
    }
    Ok(selected)
}

fn range_indices(range: &Value, table_length: Option<usize>) -> Vec<usize> {
    let Some(object) = range.as_object() else {
        return Vec::new();
    };
    let Some(start) = object.get("start").and_then(Value::as_u64) else {
        return Vec::new();
    };
    let Some(end) = object.get("end").and_then(Value::as_u64) else {
        return Vec::new();
    };
    let end = table_length
        .map(|length| end.min(length as u64))
        .unwrap_or(end);
    (start..end)
        .filter_map(|value| usize::try_from(value).ok())
        .collect()
}

fn append_range_overlaps(items: &[Value], diagnostics: &mut Vec<Value>) {
    let mut ranges: BTreeMap<String, Vec<(u64, u64, u64)>> = BTreeMap::new();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(index) = object.get("index").and_then(Value::as_u64) else {
            continue;
        };
        let Some(type_ranges) = object.get("ranges").and_then(Value::as_object) else {
            continue;
        };
        for (table, range) in type_ranges {
            let Some(range_object) = range.as_object() else {
                continue;
            };
            let Some(start) = range_object.get("start").and_then(Value::as_u64) else {
                continue;
            };
            let Some(end) = range_object.get("end").and_then(Value::as_u64) else {
                continue;
            };
            ranges
                .entry(table.clone())
                .or_default()
                .push((start, end, index));
        }
    }
    for (table, mut entries) in ranges {
        entries.sort_unstable_by_key(|entry| (entry.0, entry.1, entry.2));
        for pair in entries.windows(2) {
            let left = pair[0];
            let right = pair[1];
            if right.0 < left.1 {
                diagnostics.push(json!({"kind":"overlapping-range", "table":table, "left_type":left.2, "right_type":right.2, "left_start":left.0, "left_end":left.1, "right_start":right.0, "right_end":right.1}));
            }
        }
    }
}

fn orphan_table_rows(items: &[Value], table: &str, rows: Option<&Vec<Value>>) -> Vec<usize> {
    let Some(rows) = rows else { return Vec::new() };
    let mut covered = BTreeSet::new();
    for item in items {
        let Some(range) = item.get("ranges").and_then(|ranges| ranges.get(table)) else {
            continue;
        };
        covered.extend(range_indices(range, Some(rows.len())));
    }
    (0..rows.len())
        .filter(|index| !covered.contains(index))
        .collect()
}

fn reference_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .filter(|index| *index <= MAX_SAFE_INTEGER)
        .or_else(|| {
            value
                .as_object()
                .and_then(|object| {
                    object
                        .get("metadata_index")
                        .or_else(|| object.get("type_index"))
                        .or_else(|| object.get("index"))
                        .or_else(|| object.get("source_index"))
                        .or_else(|| object.get("sourceIndex"))
                })
                .and_then(Value::as_u64)
                .filter(|index| *index <= MAX_SAFE_INTEGER)
        })
}

fn first_u64(object: &Map<String, Value>, aliases: &[&str]) -> Result<Option<u64>, Failure> {
    let mut selected = None;
    for alias in aliases {
        if let Some(value) = object.get(*alias) {
            let value = value
                .as_u64()
                .ok_or_else(|| invalid(alias, "Value must be a non-negative integer"));
            let value = value?;
            if value > MAX_SAFE_INTEGER {
                return Err(invalid(
                    alias,
                    "Value must be at most Number.MAX_SAFE_INTEGER",
                ));
            }
            if let Some(selected_value) = selected {
                if selected_value != value {
                    return Err(invalid(aliases[0], "Numeric aliases disagree"));
                }
            } else {
                selected = Some(value);
            }
        }
    }
    Ok(selected)
}

fn append_relation(
    relations: &mut Vec<Value>,
    kind: &str,
    relationship: &RelationshipValues,
    identity_index: &IdentityIndex,
    unresolved: &mut usize,
) {
    for raw_target in &relationship.targets {
        let resolved = identity_index.resolve(*raw_target);
        let status = if relationship.ambiguous || resolved.ambiguous {
            *unresolved += 1;
            "unresolved"
        } else if identity_index.duplicates.contains(&resolved.target) {
            *unresolved += 1;
            "unresolved"
        } else if identity_index.known.contains(&resolved.target) {
            "resolved"
        } else {
            *unresolved += 1;
            "unresolved"
        };
        relations.push(Value::Object(Map::from_iter([
            ("kind".to_owned(), json!(kind)),
            ("target".to_owned(), json!(resolved.target)),
            ("status".to_owned(), json!(status)),
        ])));
    }
}

fn append_reference_relation(
    relations: &mut Vec<Value>,
    kind: &str,
    target: Option<u64>,
    identity_index: &IdentityIndex,
    unresolved: &mut usize,
) {
    let Some(target) = target else {
        return;
    };
    append_relation(
        relations,
        kind,
        &RelationshipValues {
            targets: vec![target],
            ambiguous: false,
        },
        identity_index,
        unresolved,
    );
}

fn append_unresolved_relation(
    relations: &mut Vec<Value>,
    kind: &str,
    target: u64,
    unresolved: &mut usize,
) {
    *unresolved += 1;
    relations.push(Value::Object(Map::from_iter([
        ("kind".to_owned(), json!(kind)),
        ("target".to_owned(), json!(target)),
        ("status".to_owned(), json!("unresolved")),
    ])));
}

fn find_cycles(items: &[Value]) -> Vec<Vec<u64>> {
    let mut graph: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for item in items {
        let Some(object) = item.as_object() else {
            continue;
        };
        let Some(index) = object.get("index").and_then(Value::as_u64) else {
            continue;
        };
        let targets = object
            .get("relationships")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|relation| relation.get("status").and_then(Value::as_str) == Some("resolved"))
            .filter_map(|relation| relation.get("target").and_then(Value::as_u64))
            .collect();
        graph.insert(index, targets);
    }
    let mut cycles = BTreeSet::new();
    for start in graph.keys().copied() {
        let mut path = Vec::new();
        visit_cycle(start, start, &graph, &mut path, &mut cycles);
    }
    cycles
        .into_iter()
        .map(|cycle| cycle.into_iter().collect())
        .collect()
}

fn visit_cycle(
    start: u64,
    current: u64,
    graph: &BTreeMap<u64, Vec<u64>>,
    path: &mut Vec<u64>,
    cycles: &mut BTreeSet<Vec<u64>>,
) {
    if path.len() > graph.len() {
        return;
    }
    path.push(current);
    for target in graph.get(&current).into_iter().flatten() {
        if *target == start {
            let mut cycle = path.clone();
            cycle.sort_unstable();
            cycle.dedup();
            cycles.insert(cycle);
        } else if !path.contains(target) {
            visit_cycle(start, *target, graph, path, cycles);
        }
    }
    path.pop();
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "IL2CPP type hierarchy input is invalid.".into(),
        false,
        "Supply normalized IL2CPP type-definition rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}
