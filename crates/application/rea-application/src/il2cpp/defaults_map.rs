//! Projection of IL2CPP field and parameter default-value rows.
//!
//! The metadata reader owns decoding the row tables.  This module only joins
//! those rows to a caller-supplied `fieldAndParameterDefaultValueData` blob.
//! A default is decoded only when its element type and byte width are explicit;
//! otherwise the raw bytes and an unresolved reason are retained.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "map_il2cpp_default_values";
const MAX_ROWS: usize = 200_000;
const MAX_DATA: usize = 256 * 1024 * 1024;
const MAX_ROOT_PROPERTIES: usize = 64;
const MAX_ROW_PROPERTIES: usize = 32;

/// Project field and parameter default rows against a captured data blob.
///
/// The input accepts `default_data_base64` (or `data_base64`) and arrays named
/// `field_defaults` and `parameter_defaults`.  A row must provide an integer
/// `data_index`/`data_offset` and an explicit `data_size`/`data_length` to be
/// decoded.  Rows without those facts remain unknown rather than becoming a
/// guessed zero or null value.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    if root.len() > MAX_ROOT_PROPERTIES {
        return Err(invalid("input", "Input exceeds the property limit"));
    }
    let metadata = match root.get("metadata") {
        Some(value) => {
            let metadata = value
                .as_object()
                .ok_or_else(|| invalid("metadata", "Metadata must be an object"))?;
            if metadata.len() > MAX_ROOT_PROPERTIES {
                return Err(invalid("metadata", "Metadata exceeds the property limit"));
            }
            metadata
        }
        None => root,
    };
    let data = select_default_data(root, metadata)?;

    let fields = rows_from_sources(
        root,
        metadata,
        &["field_defaults", "fieldDefaultValues"],
        "field_defaults",
    )?;
    let parameters = rows_from_sources(
        root,
        metadata,
        &["parameter_defaults", "parameterDefaultValues"],
        "parameter_defaults",
    )?;
    let owners = OwnerFacts::from_metadata(metadata)?;
    let field_result = project_rows("field", fields, &data, &owners)?;
    let parameter_result = project_rows("parameter", parameters, &data, &owners)?;

    let mut items = Vec::with_capacity(field_result.items.len() + parameter_result.items.len());
    items.extend(field_result.items);
    items.extend(parameter_result.items);
    let unknown = field_result.unknown + parameter_result.unknown;
    let overlapping = field_result.overlapping + parameter_result.overlapping;
    let status = if unknown == 0 && overlapping == 0 {
        "complete"
    } else {
        "partial"
    };
    let mapped = items
        .iter()
        .filter(|item| item.get("resolution").and_then(Value::as_str) == Some("mapped"))
        .count();

    Ok(json!({
        "status": status,
        "items": items,
        "coverage": {
            "field_defaults": fields.len(),
            "parameter_defaults": parameters.len(),
            "mapped": mapped,
            "unknown": unknown,
            "overlapping": overlapping,
            "data_bytes": data.len()
        },
        "limitations": ["Only explicit primitive and string encodings are decoded; unresolved type identities remain unknown."]
    }))
}

fn select_default_data(
    root: &Map<String, Value>,
    metadata: &Map<String, Value>,
) -> Result<Vec<u8>, Failure> {
    const ALIASES: &[&str] = &[
        "default_data_base64",
        "data_base64",
        "default_value_data_base64",
        "defaultDataBase64",
        "dataBase64",
        "defaultValueDataBase64",
    ];

    let mut selected: Option<Vec<u8>> = None;
    let mut found = false;

    for source in [root, metadata] {
        for alias in ALIASES {
            let Some(value) = source.get(*alias) else {
                continue;
            };
            found = true;
            let encoded = value
                .as_str()
                .ok_or_else(|| invalid(alias, "Default-data base64 must be text"))?;
            let candidate = BASE64
                .decode(encoded)
                .map_err(|_| invalid(alias, "Default-data base64 is malformed"))?;
            if candidate.len() > MAX_DATA {
                return Err(invalid(alias, "Default-data blob exceeds the size limit"));
            }

            if selected
                .as_ref()
                .is_some_and(|existing| existing.as_slice() != candidate.as_slice())
            {
                return Err(invalid(
                    "default_data_base64",
                    "Default-data sources contain conflicting decoded bytes",
                ));
            }
            selected = Some(candidate);
        }
    }

    if !found {
        return Err(invalid(
            "default_data_base64",
            "A base64 default-data blob is required",
        ));
    }

    Ok(selected.expect("found default-data source has decoded bytes"))
}

struct Projected {
    items: Vec<Value>,
    unknown: usize,
    overlapping: usize,
}

#[derive(Default)]
struct OwnerFacts {
    field: BTreeMap<u64, Vec<Value>>,
    parameter: BTreeMap<u64, Vec<Value>>,
    identity: BTreeMap<(String, u64), Vec<Value>>,
}

impl OwnerFacts {
    fn from_metadata(metadata: &Map<String, Value>) -> Result<Self, Failure> {
        let mut facts = Self::default();
        facts.add_explicit(metadata, "field", &["fields", "field_definitions"])?;
        facts.add_explicit(
            metadata,
            "parameter",
            &["parameters", "parameter_definitions"],
        )?;
        facts.add_ranges(metadata, "field", &["field_ranges", "type_definitions"])?;
        facts.add_ranges(
            metadata,
            "parameter",
            &["parameter_ranges", "method_definitions"],
        )?;
        Ok(facts)
    }

    fn add_explicit(
        &mut self,
        metadata: &Map<String, Value>,
        kind: &str,
        names: &[&str],
    ) -> Result<(), Failure> {
        let Some(value) = names.iter().find_map(|name| metadata.get(*name)) else {
            return Ok(());
        };
        let rows = value
            .as_array()
            .ok_or_else(|| invalid(kind, "Owner facts must be an array"))?;
        if rows.len() > MAX_ROWS {
            return Err(invalid(kind, "Owner facts exceed the size limit"));
        }
        for (position, row) in rows.iter().enumerate() {
            let object = row
                .as_object()
                .ok_or_else(|| invalid_row(kind, position, "Owner fact must be an object"))?;
            if object.len() > MAX_ROW_PROPERTIES {
                return Err(invalid_row(
                    kind,
                    position,
                    "Owner fact exceeds the property limit",
                ));
            }
            let index = object
                .get(&format!("{kind}_index"))
                .or_else(|| {
                    object.get(if kind == "field" {
                        "fieldIndex"
                    } else {
                        "parameterIndex"
                    })
                })
                .or_else(|| object.get("metadata_index"))
                .or_else(|| object.get("metadataIndex"))
                .or_else(|| object.get("index"))
                .and_then(Value::as_u64);
            let Some(index) = index else { continue };
            let owner = object
                .get("declaring_type")
                .or_else(|| object.get("declaringType"))
                .or_else(|| object.get("owner"))
                .or_else(|| object.get("method_index"))
                .or_else(|| object.get("methodIndex"))
                .or_else(|| object.get("type_index"))
                .or_else(|| object.get("typeIndex"));
            if let Some(owner) = owner {
                self.insert(kind, index, owner.clone());
            }

            if let Some(identity) = member_identity(kind, index, object) {
                self.insert_identity(kind, index, identity);
            }
        }
        Ok(())
    }

    fn add_ranges(
        &mut self,
        metadata: &Map<String, Value>,
        kind: &str,
        names: &[&str],
    ) -> Result<(), Failure> {
        let Some(value) = names.iter().find_map(|name| metadata.get(*name)) else {
            return Ok(());
        };
        let rows = value
            .as_array()
            .ok_or_else(|| invalid(kind, "Owner ranges must be an array"))?;
        if rows.len() > MAX_ROWS {
            return Err(invalid(kind, "Owner ranges exceed the size limit"));
        }
        let start_name = if kind == "field" {
            "field_start"
        } else {
            "parameter_start"
        };
        let camel_start_name = if kind == "field" {
            "fieldStart"
        } else {
            "parameterStart"
        };
        let count_name = if kind == "field" {
            "field_count"
        } else {
            "parameter_count"
        };
        let camel_count_name = if kind == "field" {
            "fieldCount"
        } else {
            "parameterCount"
        };
        for (position, row) in rows.iter().enumerate() {
            let object = row
                .as_object()
                .ok_or_else(|| invalid_row(kind, position, "Owner range must be an object"))?;
            if object.len() > MAX_ROW_PROPERTIES {
                return Err(invalid_row(
                    kind,
                    position,
                    "Owner range exceeds the property limit",
                ));
            }
            let Some(start) = object
                .get(start_name)
                .or_else(|| object.get(camel_start_name))
                .and_then(Value::as_u64)
            else {
                continue;
            };
            let Some(count) = object
                .get(count_name)
                .or_else(|| object.get(camel_count_name))
                .and_then(Value::as_u64)
            else {
                continue;
            };
            let end = start
                .checked_add(count)
                .ok_or_else(|| invalid_row(kind, position, "Owner range overflows"))?;
            let owner = object
                .get("declaring_type")
                .or_else(|| object.get("declaringType"))
                .or_else(|| object.get("owner"))
                .or_else(|| object.get("method_index"))
                .or_else(|| object.get("methodIndex"))
                .or_else(|| object.get("type_index"))
                .or_else(|| object.get("typeIndex"));
            let Some(owner) = owner else { continue };
            for index in start..end {
                self.insert(kind, index, owner.clone());
            }
        }
        Ok(())
    }

    fn insert(&mut self, kind: &str, index: u64, owner: Value) {
        let map = if kind == "field" {
            &mut self.field
        } else {
            &mut self.parameter
        };
        let owners = map.entry(index).or_default();
        if !owners.iter().any(|existing| existing == &owner) {
            owners.push(owner);
        }
    }

    fn get(&self, kind: &str, index: u64) -> Option<&[Value]> {
        let map = if kind == "field" {
            &self.field
        } else {
            &self.parameter
        };
        map.get(&index).map(Vec::as_slice)
    }

    fn insert_identity(&mut self, kind: &str, index: u64, identity: Value) {
        let identities = self.identity.entry((kind.to_owned(), index)).or_default();
        if !identities.iter().any(|existing| existing == &identity) {
            identities.push(identity);
        }
    }

    fn identity(&self, kind: &str, index: u64) -> Option<&[Value]> {
        self.identity
            .get(&(kind.to_owned(), index))
            .map(Vec::as_slice)
    }
}

fn project_rows(
    kind: &str,
    rows: &[Value],
    data: &[u8],
    owners: &OwnerFacts,
) -> Result<Projected, Failure> {
    let mut items = Vec::with_capacity(rows.len());
    let mut unknown = 0;
    let mut overlapping = 0;
    let mut ranges: Vec<(usize, usize)> = Vec::new();

    for (row_number, row) in rows.iter().enumerate() {
        let object = row
            .as_object()
            .ok_or_else(|| invalid_row(kind, row_number, "Expected an object"))?;
        if object.len() > MAX_ROW_PROPERTIES {
            return Err(invalid_row(
                kind,
                row_number,
                "Default row exceeds the property limit",
            ));
        }
        let source_index_aliases = if kind == "field" {
            [
                "field_index",
                "fieldIndex",
                "metadata_index",
                "metadataIndex",
                "index",
            ]
        } else {
            [
                "parameter_index",
                "parameterIndex",
                "metadata_index",
                "metadataIndex",
                "index",
            ]
        };
        let source_index_conflict = has_conflicting_numeric_aliases(object, &source_index_aliases);
        let source_index = if source_index_conflict {
            None
        } else {
            parse_nonnegative(object, &source_index_aliases)
        };
        let offset_aliases = ["data_index", "data_offset", "dataIndex", "dataOffset"];
        let length_aliases = [
            "data_size",
            "data_length",
            "size",
            "length",
            "dataSize",
            "dataLength",
        ];
        let offset = parse_nonnegative(
            object,
            &["data_index", "data_offset", "dataIndex", "dataOffset"],
        );
        let length = parse_nonnegative(
            object,
            &[
                "data_size",
                "data_length",
                "size",
                "length",
                "dataSize",
                "dataLength",
            ],
        );
        let declared_representation = declared_representation(object);
        let mut ambiguous_owner = false;
        let mut item = Map::new();
        item.insert("kind".into(), Value::String(kind.into()));
        item.insert("source".into(), row.clone());
        item.insert(
            "source_index".into(),
            source_index.map(Value::from).unwrap_or(Value::Null),
        );
        item.insert(
            "data_offset".into(),
            offset.map(Value::from).unwrap_or(Value::Null),
        );
        item.insert(
            "data_length".into(),
            length.map(Value::from).unwrap_or(Value::Null),
        );

        if let Some(representation) = declared_representation {
            item.insert(
                "representation".into(),
                Value::String(representation.into()),
            );
        }

        let source_index_u64 = source_index.and_then(|index| u64::try_from(index).ok());
        item.insert(
            "ownership".into(),
            ownership_projection(kind, object, source_index_u64),
        );

        let metadata_identities = source_index_u64.and_then(|index| owners.identity(kind, index));
        let mut ambiguous_identity = false;
        if let Some(identities) = metadata_identities {
            if identities.len() == 1 {
                item.insert("metadata_identity".into(), identities[0].clone());
                item.insert(
                    "metadata_identity_status".into(),
                    Value::String("resolved".into()),
                );
            } else if !identities.is_empty() {
                item.insert(
                    "metadata_identities".into(),
                    Value::Array(identities.to_vec()),
                );
                item.insert(
                    "metadata_identity_status".into(),
                    Value::String("ambiguous".into()),
                );
                ambiguous_identity = true;
                unknown += 1;
            }
        }
        if metadata_identities.is_none() && source_index.is_some() {
            item.insert(
                "metadata_identity_status".into(),
                Value::String("unknown".into()),
            );
        }

        if has_conflicting_numeric_aliases(object, &offset_aliases)
            || has_conflicting_numeric_aliases(object, &length_aliases)
        {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(&mut item, "default row contains conflicting range aliases");
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        }

        if source_index_conflict {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(
                &mut item,
                "default row contains conflicting member-index aliases",
            );
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        }

        if let Some(index) = source_index {
            let mut owner_rows = u64::try_from(index)
                .ok()
                .and_then(|index| owners.get(kind, index))
                .map_or_else(Vec::new, ToOwned::to_owned);
            if let Some(explicit_owner) = object
                .get("owner")
                .or_else(|| object.get("declaring_type"))
                .or_else(|| object.get("declaringType"))
                .or_else(|| object.get("method_index"))
                .or_else(|| object.get("methodIndex"))
                .or_else(|| object.get("type_index"))
                .or_else(|| object.get("typeIndex"))
            {
                if !owner_rows.iter().any(|owner| owner == explicit_owner) {
                    owner_rows.push(explicit_owner.clone());
                }
            }
            if !owner_rows.is_empty() {
                item.insert("owners".into(), Value::Array(owner_rows.clone()));
                if owner_rows.len() != 1 {
                    unresolved(&mut item, "metadata ownership is ambiguous");
                    item.insert("owner_status".into(), Value::String("ambiguous".into()));
                    ambiguous_owner = true;
                    unknown += 1;
                } else {
                    item.insert("owner".into(), owner_rows[0].clone());
                    item.insert("owner_status".into(), Value::String("resolved".into()));
                }
            } else {
                item.insert("owner_status".into(), Value::String("unknown".into()));
            }
        } else {
            item.insert("owner_status".into(), Value::String("unknown".into()));
        }

        if is_null_reference(object) {
            item.insert(
                "representation".into(),
                Value::String("null_reference".into()),
            );
            item.insert("resolution".into(), Value::String("mapped".into()));
            item.insert("value".into(), Value::Null);
            items.push(Value::Object(item));
            continue;
        }

        let Some(offset) = offset else {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(&mut item, "data_offset is missing");
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        };
        let Some(length) = length else {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(&mut item, "data_length is missing");
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        };
        let Some(end) = offset.checked_add(length) else {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(&mut item, "data range overflows");
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        };
        if end > data.len() {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(&mut item, "data range is outside the supplied blob");
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        }
        let overlaps = ranges
            .iter()
            .any(|(start, finish)| offset < *finish && *start < end);
        if overlaps {
            overlapping += 1;
        }
        ranges.push((offset, end));
        let raw = &data[offset..end];
        item.insert("raw_bytes_base64".into(), Value::String(BASE64.encode(raw)));
        if overlaps {
            item.insert("representation".into(), Value::String("unavailable".into()));
            unresolved(&mut item, "data range overlaps another default row");
            unknown += 1;
            items.push(Value::Object(item));
            continue;
        }

        if ambiguous_owner || ambiguous_identity {
            unresolved(&mut item, "metadata ownership is ambiguous");
            items.push(Value::Object(item));
            continue;
        }

        match declared_representation {
            Some("rva_bytes") => {
                item.insert("resolution".into(), Value::String("mapped".into()));
                items.push(Value::Object(item));
                continue;
            }
            Some("unsupported") => {
                unresolved(&mut item, "default representation is unsupported");
                unknown += 1;
                items.push(Value::Object(item));
                continue;
            }
            Some("unavailable") => {
                unresolved(&mut item, "default representation is unavailable");
                unknown += 1;
                items.push(Value::Object(item));
                continue;
            }
            _ => {}
        }

        match decode_explicit(object, raw) {
            Some(Ok(value)) => {
                if !item.contains_key("representation") {
                    item.insert("representation".into(), Value::String("literal".into()));
                }
                item.insert("resolution".into(), Value::String("mapped".into()));
                item.insert("value".into(), value);
            }
            Some(Err(reason)) => {
                if !item.contains_key("representation") {
                    item.insert("representation".into(), Value::String("unsupported".into()));
                }
                unresolved(&mut item, reason);
                unknown += 1;
            }
            None => {
                item.insert("representation".into(), Value::String("unsupported".into()));
                unresolved(&mut item, "type encoding is not explicit or unsupported");
                unknown += 1;
            }
        }
        items.push(Value::Object(item));
    }
    Ok(Projected {
        items,
        unknown,
        overlapping,
    })
}

fn decode_explicit(
    object: &Map<String, Value>,
    bytes: &[u8],
) -> Option<Result<Value, &'static str>> {
    let name = object
        .get("value_type")
        .or_else(|| object.get("valueType"))
        .or_else(|| object.get("type_name"))
        .or_else(|| object.get("typeName"))
        .or_else(|| object.get("encoding"))?
        .as_str()?
        .to_ascii_lowercase();
    let fail = |reason: &'static str| Some(Err(reason));
    let endian = object
        .get("endianness")
        .or_else(|| object.get("byte_order"))
        .or_else(|| object.get("byteOrder"))
        .and_then(Value::as_str)
        .and_then(parse_endian);
    match name.as_str() {
        "null" | "none" => Some(Ok(Value::Null)),
        "bool" | "boolean" => {
            if bytes.len() == 1 {
                Some(Ok(Value::Bool(bytes[0] != 0)))
            } else {
                fail("boolean default must contain exactly one byte")
            }
        }
        "i8" | "int8" => fixed(
            bytes,
            1,
            |bytes| json!(bytes[0] as i8),
            "int8 default has the wrong width",
        ),
        "u8" | "byte" => fixed(
            bytes,
            1,
            |bytes| json!(bytes[0]),
            "uint8 default has the wrong width",
        ),
        "i16" | "int16" => fixed_endian(
            bytes,
            2,
            endian,
            |b, endian| json!(endian.i16(b)),
            "int16 default has the wrong width or missing endianness",
        ),
        "u16" | "uint16" | "char16" => fixed_endian(
            bytes,
            2,
            endian,
            |b, endian| json!(endian.u16(b)),
            "uint16 default has the wrong width or missing endianness",
        ),
        "i32" | "int32" => fixed_endian(
            bytes,
            4,
            endian,
            |b, endian| json!(endian.i32(b)),
            "int32 default has the wrong width or missing endianness",
        ),
        "u32" | "uint32" => fixed_endian(
            bytes,
            4,
            endian,
            |b, endian| json!(endian.u32(b)),
            "uint32 default has the wrong width or missing endianness",
        ),
        "i64" | "int64" => fixed_endian(
            bytes,
            8,
            endian,
            |b, endian| json!(endian.i64(b)),
            "int64 default has the wrong width or missing endianness",
        ),
        "u64" | "uint64" => fixed_endian(
            bytes,
            8,
            endian,
            |b, endian| json!(endian.u64(b)),
            "uint64 default has the wrong width or missing endianness",
        ),
        "f32" | "single" => fixed_endian(
            bytes,
            4,
            endian,
            |b, endian| json!(endian.f32(b)),
            "single default has the wrong width or missing endianness",
        ),
        "f64" | "double" => fixed_endian(
            bytes,
            8,
            endian,
            |b, endian| json!(endian.f64(b)),
            "double default has the wrong width or missing endianness",
        ),
        "string_utf8" | "utf8" => std::str::from_utf8(bytes)
            .map(|s| Ok(Value::String(s.to_owned())))
            .ok()
            .or(Some(Err("UTF-8 string default is malformed"))),
        "string_utf16" | "utf16" => {
            if bytes.len() % 2 != 0 {
                fail("UTF-16 string default has an odd byte length")
            } else {
                let Some(endian) = endian else {
                    return fail("UTF-16 string default is missing endianness");
                };
                let units = bytes
                    .chunks_exact(2)
                    .map(|pair| endian.u16(pair))
                    .collect::<Vec<_>>();
                String::from_utf16(&units)
                    .map(|s| Ok(Value::String(s)))
                    .ok()
                    .or(Some(Err("UTF-16 string default is malformed")))
            }
        }
        _ => None,
    }
}

/// Preserve each ownership axis independently.  A field's declaring type and
/// a parameter's declaring method are different facts; neither is inferred
/// from the row position or from the other axis.
fn ownership_projection(
    kind: &str,
    object: &Map<String, Value>,
    source_index: Option<u64>,
) -> Value {
    let field = if kind == "field" {
        source_index.map(Value::from).unwrap_or(Value::Null)
    } else {
        object
            .get("field_index")
            .or_else(|| object.get("fieldIndex"))
            .or_else(|| object.get("field_owner"))
            .or_else(|| object.get("fieldOwner"))
            .cloned()
            .unwrap_or(Value::Null)
    };
    let method = object
        .get("method_index")
        .or_else(|| object.get("methodIndex"))
        .or_else(|| object.get("method_owner"))
        .or_else(|| object.get("methodOwner"))
        .cloned()
        .unwrap_or(Value::Null);
    let type_owner = object
        .get("declaring_type")
        .or_else(|| object.get("declaringType"))
        .or_else(|| object.get("type_index"))
        .or_else(|| object.get("typeIndex"))
        .or_else(|| object.get("type_owner"))
        .or_else(|| object.get("typeOwner"))
        .cloned()
        .unwrap_or(Value::Null);

    json!({
        "field": field,
        "method": method,
        "type": type_owner,
    })
}

/// Preserve the exact metadata row that established a member identity.  The
/// default-value index is only a join key; it must never be treated as the
/// surrounding array position or as a token by inference.  `metadata_index`
/// and `name_index` remain raw producer values because resolving them requires
/// the metadata string table, which this projection does not own.
fn member_identity(kind: &str, index: u64, object: &Map<String, Value>) -> Option<Value> {
    let mut identity = Map::new();
    identity.insert("collection".into(), Value::String(format!("{kind}s")));
    identity.insert("metadata_index".into(), Value::from(index));

    for (output, aliases) in [
        (
            "token",
            &["token", "metadata_token", "metadataToken"] as &[&str],
        ),
        (
            "name_index",
            &[
                "name_index",
                "nameIndex",
                "member_name_index",
                "memberNameIndex",
            ],
        ),
        ("name", &["name", "member_name", "memberName"]),
    ] {
        if let Some(value) = aliases.iter().find_map(|alias| object.get(*alias)) {
            identity.insert(output.into(), value.clone());
        }
    }

    (identity.len() > 2).then_some(Value::Object(identity))
}

/// Read a representation declaration supplied by the metadata producer.
///
/// A producer declaration is authoritative only for the representation name;
/// it never supplies missing bytes or a guessed value.  RVA-backed data is
/// kept as bytes because its interpretation belongs to the native image
/// owner, not this metadata join.
fn declared_representation(object: &Map<String, Value>) -> Option<&'static str> {
    let declared = object
        .get("representation")
        .or_else(|| object.get("default_representation"))
        .or_else(|| object.get("defaultRepresentation"))
        .or_else(|| object.get("default_kind"))
        .or_else(|| object.get("defaultKind"))
        .and_then(Value::as_str)
        .map(str::to_ascii_lowercase);

    match declared.as_deref() {
        Some("rva") | Some("rva_bytes") | Some("relative_virtual_address") => Some("rva_bytes"),
        Some("null") | Some("none") | Some("null_reference") | Some("null-reference") => {
            Some("null_reference")
        }
        Some("literal") | Some("literal_value") => Some("literal"),
        Some("unsupported") => Some("unsupported"),
        Some("unavailable") => Some("unavailable"),
        Some(_) => Some("unsupported"),
        None => {
            let has_rva = object.contains_key("rva")
                || object.contains_key("rva_offset")
                || object.contains_key("rva_bytes_base64");
            has_rva.then_some("rva_bytes")
        }
    }
}

fn is_null_reference(object: &Map<String, Value>) -> bool {
    if object
        .get("is_null")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return true;
    }

    matches!(
        object
            .get("representation")
            .or_else(|| object.get("default_representation"))
            .or_else(|| object.get("defaultRepresentation"))
            .or_else(|| object.get("default_kind"))
            .or_else(|| object.get("defaultKind"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("null") | Some("none") | Some("null_reference") | Some("null-reference")
    ) || matches!(
        object
            .get("value_type")
            .or_else(|| object.get("valueType"))
            .or_else(|| object.get("type_name"))
            .or_else(|| object.get("typeName"))
            .or_else(|| object.get("encoding"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("null") | Some("none") | Some("null_reference") | Some("null-reference")
    )
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

fn parse_endian(value: &str) -> Option<Endian> {
    match value.to_ascii_lowercase().as_str() {
        "little" | "le" => Some(Endian::Little),
        "big" | "be" => Some(Endian::Big),
        _ => None,
    }
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        if matches!(self, Self::Little) {
            u16::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u16::from_be_bytes(bytes.try_into().unwrap())
        }
    }
    fn i16(self, bytes: &[u8]) -> i16 {
        if matches!(self, Self::Little) {
            i16::from_le_bytes(bytes.try_into().unwrap())
        } else {
            i16::from_be_bytes(bytes.try_into().unwrap())
        }
    }
    fn u32(self, bytes: &[u8]) -> u32 {
        if matches!(self, Self::Little) {
            u32::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u32::from_be_bytes(bytes.try_into().unwrap())
        }
    }
    fn i32(self, bytes: &[u8]) -> i32 {
        if matches!(self, Self::Little) {
            i32::from_le_bytes(bytes.try_into().unwrap())
        } else {
            i32::from_be_bytes(bytes.try_into().unwrap())
        }
    }
    fn u64(self, bytes: &[u8]) -> u64 {
        if matches!(self, Self::Little) {
            u64::from_le_bytes(bytes.try_into().unwrap())
        } else {
            u64::from_be_bytes(bytes.try_into().unwrap())
        }
    }
    fn i64(self, bytes: &[u8]) -> i64 {
        if matches!(self, Self::Little) {
            i64::from_le_bytes(bytes.try_into().unwrap())
        } else {
            i64::from_be_bytes(bytes.try_into().unwrap())
        }
    }
    fn f32(self, bytes: &[u8]) -> f32 {
        f32::from_bits(self.u32(bytes))
    }
    fn f64(self, bytes: &[u8]) -> f64 {
        f64::from_bits(self.u64(bytes))
    }
}

fn fixed_endian(
    bytes: &[u8],
    size: usize,
    endian: Option<Endian>,
    decode: impl FnOnce(&[u8], Endian) -> Value,
    reason: &'static str,
) -> Option<Result<Value, &'static str>> {
    match (bytes.len() == size, endian) {
        (true, Some(endian)) => Some(Ok(decode(bytes, endian))),
        _ => Some(Err(reason)),
    }
}

fn fixed(
    bytes: &[u8],
    size: usize,
    decode: impl FnOnce(&[u8]) -> Value,
    reason: &'static str,
) -> Option<Result<Value, &'static str>> {
    if bytes.len() == size {
        Some(Ok(decode(bytes)))
    } else {
        Some(Err(reason))
    }
}

fn unresolved(item: &mut Map<String, Value>, reason: &str) {
    item.insert("resolution".into(), Value::String("unknown".into()));
    item.insert("reason".into(), Value::String(reason.into()));
}

fn parse_nonnegative(object: &Map<String, Value>, names: &[&str]) -> Option<usize> {
    names.iter().find_map(|name| {
        object
            .get(*name)
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
    })
}

/// Detect contradictory aliases before the first alias wins.  Captured
/// producers may expose both legacy and normalized names; silently selecting
/// one would turn an identity conflict into a fabricated byte range.
fn has_conflicting_numeric_aliases(object: &Map<String, Value>, names: &[&str]) -> bool {
    let mut values = Vec::new();
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let Some(value) = value.as_u64().and_then(|value| usize::try_from(value).ok()) else {
            return true;
        };
        values.push(value);
    }
    values.windows(2).any(|pair| pair[0] != pair[1])
}

fn rows<'a>(
    object: &'a Map<String, Value>,
    names: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let supplied = names
        .iter()
        .filter_map(|name| object.get(*name).map(|value| (*name, value)))
        .collect::<Vec<_>>();
    let (_, value) = supplied
        .first()
        .copied()
        .ok_or_else(|| invalid(field, "Default rows are required"))?;
    if supplied
        .iter()
        .skip(1)
        .any(|(_, candidate)| *candidate != value)
    {
        return Err(invalid(field, "Default rows contain conflicting aliases"));
    }
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Default rows must be an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Default rows exceed the size limit"));
    }
    Ok(rows)
}

fn rows_from_sources<'a>(
    root: &'a Map<String, Value>,
    metadata: &'a Map<String, Value>,
    names: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    if std::ptr::eq(root, metadata) {
        return rows(root, names, field);
    }

    let mut supplied = Vec::new();
    for name in names {
        if let Some(value) = root.get(*name) {
            supplied.push((*name, value));
        }
        if let Some(value) = metadata.get(*name) {
            supplied.push((*name, value));
        }
    }
    let (_, value) = supplied
        .first()
        .copied()
        .ok_or_else(|| invalid(field, "Default rows are required"))?;
    if supplied
        .iter()
        .skip(1)
        .any(|(_, candidate)| *candidate != value)
    {
        return Err(invalid(field, "Default rows contain conflicting aliases"));
    }
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Default rows must be an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(field, "Default rows exceed the size limit"));
    }
    Ok(rows)
}

fn invalid_row(kind: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{kind}_defaults[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP default-value input is invalid.".into(),
        false,
        "Supply bounded default rows and an explicit data blob and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
