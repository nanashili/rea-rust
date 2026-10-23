//! Project normalized IL2CPP method-semantics links.
//!
//! The metadata reader owns table decoding.  This module only validates and
//! classifies caller-supplied rows; it never infers a property/event link from
//! a method name or from neighboring rows.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_il2cpp_method_semantics";
const MAX_ROWS: usize = 200_000;
const MAX_SAFE_INDEX: u64 = 9_007_199_254_740_991;
const MAX_ROW_PROPERTIES: usize = 128;
const KNOWN_BITS: u32 = 0x3f;

/// Project method-semantics rows and retain every source fact.
///
/// Accepted input is an array, an object containing `method_semantics`, or a
/// `metadata` wrapper containing that array.  Index fields use the aliases
/// emitted by common IL2CPP metadata readers (`method_index`/`methodIndex`,
/// `association_index`/`associationIndex`).
pub fn project(input: &Value) -> Result<Value, Failure> {
    let rows = match input {
        Value::Array(rows) => rows,
        Value::Object(root) => {
            reject_unknown_fields(
                root,
                &[
                    "method_semantics",
                    "methodSemantics",
                    "semantics",
                    "metadata",
                ],
            )?;
            if let Some(metadata) = root.get("metadata") {
                let metadata = metadata
                    .as_object()
                    .ok_or_else(|| invalid("metadata", "Expected an object"))?;
                reject_unknown_fields(
                    metadata,
                    &["method_semantics", "methodSemantics", "semantics"],
                )?;
            }
            let metadata = root
                .get("metadata")
                .and_then(Value::as_object)
                .unwrap_or(root);
            selected_rows(
                metadata,
                &["method_semantics", "methodSemantics", "semantics"],
            )?
        }
        _ => return Err(invalid("input", "Expected an array or object")),
    };
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "method_semantics",
            "Collection exceeds the row limit",
        ));
    }

    let mut items = Vec::with_capacity(rows.len());
    let mut linked = 0usize;
    let mut invalid_links = 0usize;
    let mut unknown_semantics = 0usize;
    let mut seen = BTreeSet::new();
    let mut duplicate_links = 0usize;

    for (row, value) in rows.iter().enumerate() {
        let object = value
            .as_object()
            .ok_or_else(|| invalid_row(row, "Expected a row object"))?;
        if object.len() > MAX_ROW_PROPERTIES {
            return Err(invalid_row(row, "Row exceeds the property limit"));
        }
        let method_index = optional_index(object, &["method_index", "methodIndex"]);
        let method_index_ambiguous =
            conflicting_index_aliases(object, &["method_index", "methodIndex"]);
        let explicit_association_index =
            optional_index(object, &["association_index", "associationIndex"]);
        let explicit_association_index_ambiguous =
            conflicting_index_aliases(object, &["association_index", "associationIndex"]);
        let explicit_association_kind = object
            .get("association_kind")
            .or_else(|| object.get("associationKind"))
            .and_then(Value::as_str);
        let explicit_kind_ambiguous =
            conflicting_text_aliases(object, "association_kind", "associationKind");
        let coded_association = optional_index(
            object,
            &[
                "association_coded_index",
                "associationCodedIndex",
                "association_token",
            ],
        );
        let coded_association_ambiguous = conflicting_index_aliases(
            object,
            &[
                "association_coded_index",
                "associationCodedIndex",
                "association_token",
            ],
        );
        let decoded_association = coded_association.and_then(decode_association);
        let association_index =
            explicit_association_index.or_else(|| decoded_association.map(|(index, _)| index));
        let association_kind =
            explicit_association_kind.or_else(|| decoded_association.map(|(_, kind)| kind));
        let association_conflict = explicit_association_index.is_some()
            && coded_association.is_some()
            && decoded_association.is_some_and(|(index, kind)| {
                Some(index) != explicit_association_index || Some(kind) != explicit_association_kind
            });
        let association_kind_ambiguous = explicit_kind_ambiguous || association_conflict;
        let raw = raw_semantics(object, row)?;
        let labels = labels(raw);
        let unknown_bits = raw & !KNOWN_BITS;
        let valid_link = method_index.is_some()
            && association_index.is_some()
            && !method_index_ambiguous
            && !explicit_association_index_ambiguous
            && !coded_association_ambiguous
            && !association_kind_ambiguous
            && association_kind.is_some_and(|kind| matches!(kind, "property" | "event"));
        if valid_link {
            linked += 1;
            let key = (
                method_index.unwrap(),
                association_index.unwrap(),
                association_kind.unwrap(),
            );
            if !seen.insert(key) {
                duplicate_links += 1;
            }
        } else {
            invalid_links += 1;
        }
        if unknown_bits != 0 {
            unknown_semantics += 1;
        }
        items.push(json!({
            "row": value,
            "method_index": method_index,
            "association_index": association_index,
            "association_kind": association_kind,
            "semantics": { "raw": raw, "flags": labels, "unknown_bits": unknown_bits },
            "resolution": if valid_link { "linked" } else { "invalid" }
        }));
    }

    Ok(json!({
        "operation": OPERATION,
        "items": items,
        "coverage": {
            "rows": rows.len(),
            "linked": linked,
            "invalid_links": invalid_links,
            "duplicate_links": duplicate_links,
            "unknown_semantics": unknown_semantics
        },
        "limitations": ["Links are classified only from explicit or coded indices and association_kind; names are never used."]
    }))
}

fn selected_rows<'a>(
    object: &'a serde_json::Map<String, Value>,
    aliases: &[&str],
) -> Result<&'a [Value], Failure> {
    let mut selected = None;
    for alias in aliases {
        let Some(candidate) = object.get(*alias) else {
            continue;
        };
        if let Some(existing) = selected {
            if existing != candidate {
                return Err(invalid(
                    "method_semantics",
                    "Equivalent row aliases disagree",
                ));
            }
        } else {
            selected = Some(candidate);
        }
    }
    selected
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or_else(|| invalid("method_semantics", "Expected an array"))
}

fn raw_semantics(object: &serde_json::Map<String, Value>, row: usize) -> Result<u32, Failure> {
    let value = ["semantics", "method_semantics", "methodSemantics"]
        .iter()
        .find_map(|name| object.get(*name))
        .ok_or_else(|| invalid_row(row, "Missing semantics"))?;
    if let Some(raw_object) = value.as_object() {
        if raw_object.len() > 2 {
            return Err(invalid_row(
                row,
                "Semantics object exceeds the property limit",
            ));
        }
        reject_unknown_fields(raw_object, &["raw", "value"])
            .map_err(|_| invalid_row(row, "Semantics object contains an unknown field"))?;
    }
    let value = value
        .get("raw")
        .or_else(|| value.get("value"))
        .unwrap_or(value);
    value
        .as_u64()
        .and_then(|raw| u32::try_from(raw).ok())
        .ok_or_else(|| invalid_row(row, "Semantics must be an unsigned 32-bit integer"))
}

fn optional_index(object: &serde_json::Map<String, Value>, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| {
        object
            .get(*name)
            .and_then(Value::as_u64)
            .filter(|index| *index <= MAX_SAFE_INDEX)
    })
}

fn conflicting_index_aliases(object: &serde_json::Map<String, Value>, names: &[&str]) -> bool {
    let mut selected = None;
    for name in names {
        let Some(value) = object.get(*name) else {
            continue;
        };
        let Some(candidate) = value.as_u64().filter(|index| *index <= MAX_SAFE_INDEX) else {
            return true;
        };
        if selected.is_some_and(|existing| existing != candidate) {
            return true;
        }
        selected = Some(candidate);
    }
    false
}

fn decode_association(value: u64) -> Option<(u64, &'static str)> {
    let kind = match value & 1 {
        0 => "event",
        1 => "property",
        _ => return None,
    };
    Some((value >> 1, kind))
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.iter().any(|candidate| candidate == field))
    {
        return Err(invalid(field, "Unknown field"));
    }
    Ok(())
}

fn conflicting_text_aliases(
    object: &serde_json::Map<String, Value>,
    first: &str,
    second: &str,
) -> bool {
    let Some(first) = object.get(first).and_then(Value::as_str) else {
        return false;
    };
    let Some(second) = object.get(second).and_then(Value::as_str) else {
        return false;
    };
    first != second
}

fn labels(raw: u32) -> Vec<&'static str> {
    [
        (1, "setter"),
        (2, "getter"),
        (4, "other"),
        (8, "add"),
        (16, "remove"),
        (32, "raise"),
    ]
    .into_iter()
    .filter_map(|(bit, label)| (raw & bit != 0).then_some(label))
    .collect()
}

fn invalid_row(row: usize, reason: &str) -> Failure {
    invalid(&format!("method_semantics[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP method semantics input is invalid.".into(),
        false,
        "Supply normalized method-semantics rows and retry.".into(),
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
    fn accepts_rows_as_a_direct_array() {
        let result = project(&json!([
            {
                "method_index": 3,
                "association_index": 7,
                "association_kind": "property",
                "semantics": 2
            }
        ]))
        .expect("direct method-semantics arrays are valid input");

        assert_eq!(result["coverage"]["rows"], 1);
        assert_eq!(result["coverage"]["linked"], 1);
        assert_eq!(result["items"][0]["resolution"], "linked");
    }

    #[test]
    fn rejects_scalars_before_reading_method_semantics() {
        let error = project(&json!("method semantics")).expect_err("scalar input is invalid");

        assert_eq!(error.code(), "invalid_request");
        assert_eq!(error.operation(), Some(super::OPERATION));
    }
}
