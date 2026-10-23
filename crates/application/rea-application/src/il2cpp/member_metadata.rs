//! Captured projection of IL2CPP member-definition rows.
//!
//! The byte decoder in [`crate::il2cpp::metadata_member_rows`] deliberately
//! accepts section descriptors selected by its caller.  This module owns the
//! public captured boundary: it decodes a bounded Base64 snapshot, retains
//! source offsets and raw indices, and attaches caller-supplied ownership
//! facts without guessing a declaring type from row order.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

use crate::il2cpp::metadata_member_rows::{
    MemberSectionDescriptors, SectionDescriptor, parse_member_rows_for_version,
};

pub const OPERATION: &str = "inspect_il2cpp_member_metadata";
const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_ROWS: usize = 200_000;
const FIELD_DEFINITION_SIZE: usize = 16;

/// Decode and project caller-supplied member-table bytes.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let version = root
        .get("metadata_version")
        .or_else(|| root.get("version"))
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("metadata_version", "Metadata version is required"))?;
    if !matches!(version, 29 | 31 | 39) {
        return Err(invalid(
            "metadata_version",
            "Only metadata versions 29, 31, and 39 are supported",
        ));
    }
    let encoded = root
        .get("bytes_base64")
        .or_else(|| root.get("bytes"))
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("bytes_base64", "A Base64 metadata snapshot is required"))?;
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| invalid("bytes_base64", "Metadata snapshot is not valid Base64"))?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(invalid(
            "bytes_base64",
            "Metadata snapshot exceeds the byte limit",
        ));
    }

    let sections = parse_sections(root.get("sections"))?;
    ensure_row_budget(version, sections)?;
    let rows = parse_member_rows_for_version(version as u32, &bytes, &sections)
        .map_err(|error| invalid("sections", &error.to_string()))?;
    let total =
        rows.fields.len() + rows.properties.len() + rows.events.len() + rows.parameters.len();
    if total > MAX_ROWS {
        return Err(invalid("sections", "Member rows exceed the row limit"));
    }

    let ownership = root.get("ownership").and_then(Value::as_object);
    let methods = root.get("methods").and_then(Value::as_array);
    let fields = project_fields(&rows.fields, ownership.and_then(|v| v.get("fields")));
    let properties = project_properties(
        &rows.properties,
        ownership.and_then(|v| v.get("properties")),
        methods.map(Vec::as_slice),
    );
    let events = project_events(
        &rows.events,
        ownership.and_then(|v| v.get("events")),
        methods.map(Vec::as_slice),
    );
    let parameters = project_parameters(
        &rows.parameters,
        ownership.and_then(|v| v.get("parameters")),
    );

    Ok(json!({
        "operation": OPERATION,
        "metadata_version": version,
        "sections": {
            "fields": section_json(sections.fields),
            "properties": section_json(sections.properties),
            "events": section_json(sections.events),
            "parameters": section_json(sections.parameters)
        },
        "fields": fields,
        "properties": properties,
        "events": events,
        "parameters": parameters,
        "coverage": {
            "field_rows": rows.fields.len(),
            "property_rows": rows.properties.len(),
            "event_rows": rows.events.len(),
            "parameter_rows": rows.parameters.len(),
            "ownership": if ownership.is_some() { "caller-supplied" } else { "unresolved" }
        },
        "limitations": ["Member names and declaring types require caller-supplied string and type tables."]
    }))
}

fn parse_sections(value: Option<&Value>) -> Result<MemberSectionDescriptors, Failure> {
    let sections = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("sections", "Four member section descriptors are required"))?;
    Ok(MemberSectionDescriptors {
        fields: parse_section(sections, "fields")?,
        properties: parse_section(sections, "properties")?,
        events: parse_section(sections, "events")?,
        parameters: parse_section(sections, "parameters")?,
    })
}

fn parse_section(
    sections: &Map<String, Value>,
    name: &'static str,
) -> Result<SectionDescriptor, Failure> {
    let object = sections
        .get(name)
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(name, "Section descriptor is required"))?;
    let offset = object
        .get("offset")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(name, "offset is required"))?;
    let size = object
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid(name, "size is required"))?;
    let offset =
        usize::try_from(offset).map_err(|_| invalid(name, "offset exceeds platform bounds"))?;
    let size = usize::try_from(size).map_err(|_| invalid(name, "size exceeds platform bounds"))?;
    let count = match object.get("count") {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) => {
            let count = value
                .as_u64()
                .ok_or_else(|| invalid(name, "count must be an integer"))?;
            Some(
                usize::try_from(count)
                    .map_err(|_| invalid(name, "count exceeds platform bounds"))?,
            )
        }
    };
    Ok(SectionDescriptor::new(offset, size, count))
}

fn section_json(section: SectionDescriptor) -> Value {
    json!({ "offset": section.offset, "size": section.size, "count": section.count })
}

fn ensure_row_budget(version: u64, sections: MemberSectionDescriptors) -> Result<(), Failure> {
    let record_sizes = [FIELD_DEFINITION_SIZE, 20, 24, 20];
    let descriptors = [
        sections.fields,
        sections.properties,
        sections.events,
        sections.parameters,
    ];
    let counted = version == 39;
    let mut total = 0usize;

    for (descriptor, record_size) in descriptors.into_iter().zip(record_sizes) {
        let row_count = if counted {
            descriptor.count.ok_or_else(|| {
                invalid(
                    "sections",
                    "Version 39 requires a count for every member section",
                )
            })?
        } else {
            descriptor
                .size
                .checked_div(record_size)
                .ok_or_else(|| invalid("sections", "Member section size cannot be divided"))?
        };
        total = total
            .checked_add(row_count)
            .ok_or_else(|| invalid("sections", "Member row count exceeds the row limit"))?;
        if total > MAX_ROWS {
            return Err(invalid("sections", "Member rows exceed the row limit"));
        }
    }

    Ok(())
}

fn project_fields(
    rows: &[crate::il2cpp::metadata_member_rows::FieldRow],
    owners: Option<&Value>,
) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let mut value = json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "source_row": source_row(
                    "fields",
                    row.index,
                    row.source_offset,
                    FIELD_DEFINITION_SIZE,
                ),
                "name_index": row.name_index,
                "type_index": row.type_index,
                "custom_attribute_index": row.custom_attribute_index,
                "token": row.token
            });
            attach_owner(
                &mut value,
                owners,
                row.index,
                row.source_offset,
                "fields",
                row.token,
            );
            value
        })
        .collect()
}

fn project_properties(
    rows: &[crate::il2cpp::metadata_member_rows::PropertyRow],
    owners: Option<&Value>,
    methods: Option<&[Value]>,
) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let mut value = json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "source_row": source_row("properties", row.index, row.source_offset, 20),
                "name_index": row.name_index,
                "getter_index": row.getter_index,
                "setter_index": row.setter_index,
                "attributes": row.attributes,
                "token": row.token
            });
            attach_owner(
                &mut value,
                owners,
                row.index,
                row.source_offset,
                "properties",
                row.token,
            );
            attach_accessor_relationships(
                &mut value,
                methods,
                [
                    ("getter_index", row.getter_index),
                    ("setter_index", row.setter_index),
                ],
            );
            value
        })
        .collect()
}

fn project_events(
    rows: &[crate::il2cpp::metadata_member_rows::EventRow],
    owners: Option<&Value>,
    methods: Option<&[Value]>,
) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let mut value = json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "source_row": source_row("events", row.index, row.source_offset, 24),
                "name_index": row.name_index,
                "type_index": row.type_index,
                "add_index": row.add_index,
                "remove_index": row.remove_index,
                "raise_index": row.raise_index,
                "token": row.token
            });
            attach_owner(
                &mut value,
                owners,
                row.index,
                row.source_offset,
                "events",
                row.token,
            );
            attach_accessor_relationships(
                &mut value,
                methods,
                [
                    ("add_index", row.add_index),
                    ("remove_index", row.remove_index),
                    ("raise_index", row.raise_index),
                ],
            );
            value
        })
        .collect()
}

fn attach_accessor_relationships<const N: usize>(
    value: &mut Value,
    methods: Option<&[Value]>,
    accessors: [(&'static str, i32); N],
) {
    let Some(methods) = methods else {
        return;
    };

    let mut relationships = Map::new();
    for (name, index) in accessors {
        relationships.insert(name.into(), resolve_accessor(methods, index));
    }
    value
        .as_object_mut()
        .expect("projected member rows are objects")
        .insert(
            "accessor_relationships".into(),
            Value::Object(relationships),
        );
}

fn resolve_accessor(methods: &[Value], index: i32) -> Value {
    if index < 0 {
        return json!({
            "status": "unknown",
            "method_index": index,
            "reason": "Accessor uses the metadata missing-index sentinel."
        });
    }

    let index = index as usize;
    let candidates = methods
        .iter()
        .filter(|method| method_index(method) == Some(index))
        .collect::<Vec<_>>();

    match candidates.as_slice() {
        [] => json!({
            "status": "unknown",
            "method_index": index,
            "reason": "Accessor method index is not present in the supplied method rows."
        }),
        [method] => json!({
            "status": "resolved",
            "method_index": index,
            "method": method,
        }),
        _ => json!({
            "status": "ambiguous",
            "method_index": index,
            "methods": candidates,
            "reason": "Multiple supplied method rows claim the accessor index."
        }),
    }
}

fn method_index(method: &Value) -> Option<usize> {
    let object = method.as_object()?;
    for field in ["metadata_index", "method_index", "index"] {
        if let Some(value) = object.get(field) {
            if let Some(index) = value.as_u64() {
                return usize::try_from(index).ok();
            }
            if let Some(text) = value.as_str() {
                let text = text.trim();
                let parsed = text
                    .strip_prefix("0x")
                    .or_else(|| text.strip_prefix("0X"))
                    .map(|hex| usize::from_str_radix(hex, 16))
                    .unwrap_or_else(|| text.parse::<usize>());
                if let Ok(index) = parsed {
                    return Some(index);
                }
            }
        }
    }
    None
}

fn project_parameters(
    rows: &[crate::il2cpp::metadata_member_rows::ParameterRow],
    owners: Option<&Value>,
) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            let mut value = json!({
                "metadata_index": row.index,
                "source_offset": row.source_offset,
                "source_row": source_row("parameters", row.index, row.source_offset, 20),
                "name_index": row.name_index,
                "token": row.token,
                "type_index": row.type_index,
                "custom_attribute_index": row.custom_attribute_index,
                "flags": row.flags
            });
            attach_owner(
                &mut value,
                owners,
                row.index,
                row.source_offset,
                "parameters",
                row.token,
            );
            value
        })
        .collect()
}

fn source_row(section: &'static str, index: usize, offset: usize, size: usize) -> Value {
    json!({
        "section": section,
        "index": index,
        "offset": offset,
        "size": size,
        "end": offset.saturating_add(size),
    })
}

fn attach_owner(
    value: &mut Value,
    owners: Option<&Value>,
    index: usize,
    source_offset: usize,
    collection: &'static str,
    token: u32,
) {
    let matching_owners = owners
        .and_then(Value::as_array)
        .map(|rows| {
            rows.iter()
                .filter(|row| owner_row_indices(row).contains(&index))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let owner = match matching_owners.as_slice() {
        [] => None,
        [owner] => Some(enrich_owner(owner, collection, index, source_offset, token)),
        owners => Some(Value::Array(
            owners
                .iter()
                .map(|owner| enrich_owner(owner, collection, index, source_offset, token))
                .collect(),
        )),
    };
    let object = value
        .as_object_mut()
        .expect("projected member rows are objects");
    object.insert("ownership".into(), owner.clone().unwrap_or(Value::Null));
    let ownership_status = owner.as_ref().map(classify_owner).unwrap_or("unresolved");
    object.insert("ownership_status".into(), Value::from(ownership_status));
}

/// Add a stable member identity to caller-supplied ownership claims while
/// retaining the claim's original fields and provenance.  The byte decoder
/// cannot infer ownership, but downstream joins can now identify exactly
/// which member row a claim refers to without reconstructing collection
/// context from array position.
fn enrich_owner(
    owner: &Value,
    collection: &'static str,
    index: usize,
    source_offset: usize,
    token: u32,
) -> Value {
    let Some(object) = owner.as_object() else {
        return owner.clone();
    };

    let mut enriched = object.clone();
    enriched.insert(
        "member_identity".into(),
        json!({
            "collection": collection,
            "metadata_index": index,
            "source_offset": source_offset,
            "token": token,
        }),
    );
    Value::Object(enriched)
}

fn owner_row_indices(owner: &Value) -> Vec<usize> {
    let Some(object) = owner.as_object() else {
        return Vec::new();
    };

    let mut indices = Vec::new();
    for field in ["row_index", "metadata_index", "member_index", "index"] {
        let Some(index) = object.get(field).and_then(value_index) else {
            continue;
        };
        if !indices.contains(&index) {
            indices.push(index);
        }
    }
    indices
}

fn owner_row_index_conflict(owner: &Value) -> bool {
    let Some(object) = owner.as_object() else {
        return false;
    };

    let mut selected = None;
    for field in ["row_index", "metadata_index", "member_index", "index"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let Some(index) = value_index(value) else {
            return true;
        };
        if selected.is_some_and(|existing| existing != index) {
            return true;
        }
        selected = Some(index);
    }
    false
}

fn value_index(value: &Value) -> Option<usize> {
    if let Some(index) = value.as_u64() {
        return usize::try_from(index).ok();
    }

    let text = value.as_str()?.trim();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .map(|hex| usize::from_str_radix(hex, 16))
        .unwrap_or_else(|| text.parse::<usize>());
    digits.ok()
}

/// Classify a caller-supplied ownership row without collapsing duplicate
/// claims.  The metadata decoder cannot establish declaring types itself, so
/// an empty or ambiguous claim remains unresolved; duplicate and multiple
/// explicit type candidates stay verbatim in `ownership`.
fn classify_owner(owner: &Value) -> &'static str {
    if owner.is_array() {
        return "unresolved";
    }

    let Some(object) = owner.as_object() else {
        return "unresolved";
    };

    if owner_row_index_conflict(owner) {
        return "unresolved";
    }

    owner_type_identity(object)
        .map(|_| "provided")
        .unwrap_or("unresolved")
}

/// Resolve all supplied scalar and array owner aliases as one claim.
///
/// Each alias is useful on its own, but choosing the first one would hide a
/// contradictory owner claim elsewhere on the same row.  The projection can
/// report an owner only when every supplied representation names one type.
fn owner_type_identity(object: &Map<String, Value>) -> Option<usize> {
    let mut selected = None;

    for field in ["owner_type_indices", "owner_type_ids"] {
        let Some(value) = object.get(field) else {
            continue;
        };
        let candidates = value.as_array()?;
        if candidates.len() != 1 {
            return None;
        }
        reconcile_owner_type_candidate(&mut selected, &candidates[0])?;
    }

    for field in ["owner_type_index", "owner_type_id", "declaring_type"] {
        let Some(candidate) = object.get(field) else {
            continue;
        };
        reconcile_owner_type_candidate(&mut selected, candidate)?;
    }

    selected
}

fn reconcile_owner_type_candidate(selected: &mut Option<usize>, candidate: &Value) -> Option<()> {
    if candidate.is_null() || value_is_missing_index(candidate) {
        return None;
    }

    let index = value_index(candidate)?;
    if index > u32::MAX as usize || selected.is_some_and(|existing| existing != index) {
        return None;
    }

    *selected = Some(index);
    Some(())
}

fn value_is_missing_index(value: &Value) -> bool {
    value.as_i64().is_some_and(|index| index == -1)
        || value
            .as_str()
            .map(str::trim)
            .is_some_and(|text| text == "-1")
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP member metadata input is invalid.".into(),
        false,
        "Supply bounded member-table bytes and explicit section descriptors, then retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
