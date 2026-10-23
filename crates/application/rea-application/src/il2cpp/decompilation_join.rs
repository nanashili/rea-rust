//! Join retained IL2CPP method-address rows with native function Evidence.
//!
//! This is a captured-data projection.  It authenticates each complete
//! Evidence envelope, then compares caller-supplied binary identity, address
//! space, and exact start-address strings.  It never opens an artifact or
//! asks a provider to resolve a method.

use rea_core::{
    evidence::is_sha256,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};

pub const OPERATION: &str = "join_il2cpp_decompilation";

const MAX_ROWS: usize = 200_000;
const NATIVE_OPERATIONS: &[&str] = &[
    "analyze_function",
    "procedure_info",
    "procedure_pseudo_code",
    "batch_decompile",
];

/// Join IL2CPP mapping rows with already retained native Evidence.
///
/// The accepted shape is `{ "mappings": [...], "evidence": [...] }`.
/// `method_addresses` and `method_address_mappings` are accepted as aliases
/// for `mappings`; `native_evidence` and `decompilation_evidence` are accepted
/// as aliases for `evidence`.  A mapping row must contain a non-empty
/// `binary_sha256`, `address_space`, and `start_address` (the `address` field
/// is accepted as a spelling of `start_address`).
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;

    reject_unknown_root_fields(root)?;

    let mappings = selected_rows(
        root,
        &["mappings", "method_addresses", "method_address_mappings"],
        "mappings",
    )?;
    let evidence = selected_rows(
        root,
        &["evidence", "native_evidence", "decompilation_evidence"],
        "evidence",
    )?;
    if mappings.len() > MAX_ROWS || evidence.len() > MAX_ROWS {
        return Err(resource(
            "mapping and Evidence rows exceed the supported limit",
        ));
    }

    let candidates = authenticate_evidence(evidence)?;
    let mut items = Vec::with_capacity(mappings.len());
    let mut mapped = 0usize;
    let mut ambiguous = 0usize;
    let mut unknown = 0usize;
    let mut unmapped = 0usize;

    for (row_index, mapping) in mappings.iter().enumerate() {
        let row = mapping
            .as_object()
            .ok_or_else(|| invalid_row("mappings", row_index, "Expected an object"))?;
        let (binary_sha256, address_space, start_address) = mapping_identity(row, row_index)?;

        let matches: Vec<Value> = candidates
            .iter()
            .filter(|candidate| {
                candidate.binary_sha256 == binary_sha256
                    && candidate.address_space == address_space
                    && candidate.start_address == start_address
            })
            .map(Candidate::as_value)
            .collect();

        let status = match matches.len() {
            0 if candidates
                .iter()
                .any(|candidate| candidate.binary_sha256 == binary_sha256) =>
            {
                unknown += 1;
                "unknown"
            }
            0 => {
                unmapped += 1;
                "unmapped"
            }
            1 => {
                mapped += 1;
                "mapped"
            }
            _ => {
                ambiguous += 1;
                "ambiguous"
            }
        };

        let mut item = Map::new();
        item.insert("mapping".into(), mapping.clone());
        item.insert("status".into(), Value::String(status.into()));
        item.insert("matches".into(), Value::Array(matches));
        if status == "unknown" {
            item.insert(
                "unknowns".into(),
                Value::Array(vec![Value::String(
                    "No authenticated native Evidence matched the exact address space and start address.".into(),
                )]),
            );
        }
        items.push(Value::Object(item));
    }

    Ok(serde_json::json!({
        "status": if ambiguous > 0 || unknown > 0 || unmapped > 0 { "partial" } else { "complete" },
        "items": items,
        "coverage": {
            "mapping_rows": mappings.len(),
            "authenticated_evidence_rows": candidates.len(),
            "mapped": mapped,
            "ambiguous": ambiguous,
            "unknown": unknown,
            "unmapped": unmapped,
        }
    }))
}

/// Alias for operation-oriented application adapters.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

struct Candidate {
    evidence_id: String,
    operation: String,
    binary_sha256: String,
    address_space: String,
    start_address: String,
    normalized_result: Value,
}

impl Candidate {
    fn as_value(&self) -> Value {
        serde_json::json!({
            "source_evidence_id": self.evidence_id,
            "operation": self.operation,
            "binary_sha256": self.binary_sha256,
            "address_space": self.address_space,
            "start_address": self.start_address,
            "result": self.normalized_result,
        })
    }
}

fn authenticate_evidence(rows: &[Value]) -> Result<Vec<Candidate>, Failure> {
    rows.iter()
        .enumerate()
        .map(|(index, value)| {
            let raw = serde_json::value::to_raw_value(value)
                .map_err(|error| invalid_row("evidence", index, &error.to_string()))?;
            let record = EvidenceRecord::parse(&raw)
                .map_err(|error| invalid_row("evidence", index, &error.to_string()))?;
            let operation = serde_json::from_str::<String>(record.operation().get())
                .map_err(|error| invalid_row("evidence", index, &error.to_string()))?;
            if !NATIVE_OPERATIONS.contains(&operation.as_str()) {
                return Err(invalid_row(
                    "evidence",
                    index,
                    "Evidence operation is not a native function or decompilation operation",
                ));
            }
            let normalized_result: Value =
                serde_json::from_str(record.normalized_result().get())
                    .map_err(|error| invalid_row("evidence", index, &error.to_string()))?;
            let sources = source_objects(&normalized_result);
            if sources.is_empty() {
                return Err(invalid_row(
                    "evidence",
                    index,
                    "normalized_result must be an object",
                ));
            }
            let binary_sha256 =
                consistent_digest(record.subject_sha256(), &sources).ok_or_else(|| {
                    invalid_row(
                        "evidence",
                        index,
                        "Evidence binary SHA-256 is missing or contradictory",
                    )
                })?;
            if !is_sha256(binary_sha256) {
                return Err(invalid_row(
                    "evidence",
                    index,
                    "Evidence binary SHA-256 is invalid",
                ));
            }
            let start_addresses = if operation == "batch_decompile" {
                batch_start_addresses(&normalized_result)
                    .map_err(|_| {
                        invalid_row(
                            "evidence",
                            index,
                            "Batch Evidence contains contradictory procedure addresses",
                        )
                    })?
                    .ok_or_else(|| {
                        invalid_row(
                            "evidence",
                            index,
                            "Batch Evidence has no resolved procedure addresses",
                        )
                    })?
            } else {
                vec![
                    consistent_start_address(&sources)
                        .ok_or_else(|| {
                            invalid_row(
                                "evidence",
                                index,
                                "Evidence start address is missing or contradictory",
                            )
                        })?
                        .to_owned(),
                ]
            };

            start_addresses
                .into_iter()
                .map(|start_address| {
                    let address_space = consistent_address_space(&sources, &start_address)
                        .ok_or_else(|| {
                            invalid_row(
                                "evidence",
                                index,
                                "Evidence address space is missing or contradictory",
                            )
                        })?;
                    Ok(Candidate {
                        evidence_id: record.evidence_id().to_owned(),
                        operation: operation.clone(),
                        binary_sha256: binary_sha256.to_owned(),
                        address_space,
                        start_address,
                        normalized_result: normalized_result.clone(),
                    })
                })
                .collect::<Result<Vec<_>, Failure>>()
        })
        .try_fold(Vec::new(), |mut candidates, result| {
            candidates.extend(result?);
            Ok(candidates)
        })
}

fn batch_start_addresses(result: &Value) -> Result<Option<Vec<String>>, ()> {
    let Some(items) = result.get("items").and_then(Value::as_array) else {
        return Ok(None);
    };
    let mut seen = HashSet::new();
    let addresses = items
        .iter()
        .filter_map(|item| {
            let item_object = item.as_object()?;
            let procedure = item_object.get("procedure")?.as_object()?;
            if procedure.get("status")?.as_str() != Some("resolved") {
                return None;
            }

            let mut claims = procedure_address_claims(item_object);
            claims.extend(procedure_address_claims(procedure));
            let address = claims.first().copied()?;
            if claims.iter().any(|claim| *claim != address) {
                return Some(Err(()));
            }
            seen.insert(address).then_some(Ok(address.to_owned()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((!addresses.is_empty()).then_some(addresses))
}

fn procedure_address_claims<'a>(object: &'a Map<String, Value>) -> Vec<&'a str> {
    [
        "address",
        "start_address",
        "entrypoint",
        "function_address",
        "native_address",
    ]
    .iter()
    .filter_map(|field| text_at(object, &[*field]))
    .collect()
}

fn consistent_digest<'a>(
    subject: Option<&'a str>,
    sources: &[&'a Map<String, Value>],
) -> Option<&'a str> {
    let mut values = Vec::new();
    if let Some(value) = subject {
        values.push(value);
    }
    for source in sources {
        for field in ["binary_sha256", "artifact_sha256", "sha256"] {
            if let Some(raw) = source.get(field) {
                values.push(raw.as_str()?);
            }
        }
        if let Some(artifact) = source.get("artifact") {
            let artifact = artifact.as_object()?;
            if let Some(raw) = artifact.get("sha256") {
                values.push(raw.as_str()?);
            }
        }
    }
    let first = values.first().copied()?;
    values.iter().all(|value| *value == first).then_some(first)
}

fn text_at<'a>(object: &'a Map<String, Value>, fields: &[&str]) -> Option<&'a str> {
    fields.iter().find_map(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    })
}

fn nested_text<'a>(object: &'a Map<String, Value>, parent: &str, field: &str) -> Option<&'a str> {
    object
        .get(parent)
        .and_then(Value::as_object)
        .and_then(|value| value.get(field))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn consistent_start_address<'a>(sources: &[&'a Map<String, Value>]) -> Option<&'a str> {
    let mut values = Vec::new();
    for source in sources {
        for field in ["start_address", "entrypoint", "address", "function_address"] {
            if let Some(value) = text_at(source, &[field]) {
                values.push(value);
            }
        }
        for wrapper in ["procedure", "function"] {
            for field in ["start_address", "entrypoint", "address", "function_address"] {
                if let Some(value) = nested_text(source, wrapper, field) {
                    values.push(value);
                }
            }
        }
    }
    let first = values.first().copied()?;
    values.iter().all(|value| *value == first).then_some(first)
}

fn consistent_address_space<'a>(
    sources: &[&'a Map<String, Value>],
    start_address: &str,
) -> Option<String> {
    let mut values = Vec::new();
    for source in sources {
        values.extend(text_at(source, &["address_space"]));
        values.extend(nested_text(source, "procedure", "address_space"));
        values.extend(nested_text(source, "function", "address_space"));
    }
    if values.is_empty() {
        return address_space_from(start_address).map(str::to_owned);
    }
    let first = values[0];
    values
        .iter()
        .all(|value| *value == first)
        .then_some(first.to_owned())
}

fn source_objects<'a>(result: &'a Value) -> Vec<&'a Map<String, Value>> {
    let Some(object) = result.as_object() else {
        return Vec::new();
    };

    let mut sources = vec![object];
    let mut index = 0;

    // Native Evidence may place identity facts in a normalized result,
    // procedure, or function wrapper. Walk those owners so every retained
    // identity claim participates in contradiction checks without flattening
    // or replacing the original source row.
    while index < sources.len() {
        let source = sources[index];
        for wrapper in [
            "result",
            "normalized_result",
            "dossier",
            "procedure",
            "function",
            "native_function",
        ] {
            if let Some(nested) = source.get(wrapper).and_then(Value::as_object) {
                sources.push(nested);
            }
        }
        index += 1;
    }

    sources
}

fn mapping_identity<'a>(
    row: &'a Map<String, Value>,
    index: usize,
) -> Result<(&'a str, &'a str, &'a str), Failure> {
    let binary_sha256 = unique_text(row, &["binary_sha256"], "binary_sha256", index)?
        .filter(|value| is_sha256(value))
        .ok_or_else(|| invalid_row("mappings", index, "binary_sha256 must be lowercase SHA-256"))?;
    let address_space = unique_text(row, &["address_space"], "address_space", index)?
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| {
            invalid_row(
                "mappings",
                index,
                "address_space must be non-empty text of at most 128 bytes",
            )
        })?;
    let start_address = unique_text(row, &["start_address", "address"], "start_address", index)?
        .filter(|value| !value.is_empty() && value.len() <= 128)
        .ok_or_else(|| {
            invalid_row(
                "mappings",
                index,
                "start_address must be non-empty text of at most 128 bytes",
            )
        })?;

    Ok((binary_sha256, address_space, start_address))
}

fn unique_text<'a>(
    object: &'a Map<String, Value>,
    fields: &[&str],
    name: &str,
    index: usize,
) -> Result<Option<&'a str>, Failure> {
    let mut values = Vec::new();
    for field in fields {
        if let Some(value) = object.get(*field) {
            let text = value.as_str().ok_or_else(|| {
                invalid_row("mappings", index, &format!("{name} aliases must be text"))
            })?;
            values.push(text);
        }
    }
    if values.windows(2).any(|pair| pair[0] != pair[1]) {
        return Err(invalid_row(
            "mappings",
            index,
            &format!("{name} aliases disagree across retained facts"),
        ));
    }
    Ok(values.first().copied())
}

fn address_space_from(address: &str) -> Option<&str> {
    let (space, offset) = address.rsplit_once(':')?;
    (!space.is_empty() && !offset.is_empty()).then_some(space)
}

fn selected_rows<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a [Value], Failure> {
    let present = aliases
        .iter()
        .filter_map(|alias| root.get(*alias).map(|value| (*alias, value)))
        .collect::<Vec<_>>();
    if present.len() > 1 {
        return Err(invalid(
            field,
            "Multiple aliases were supplied for the same collection",
        ));
    }
    let value = present
        .first()
        .map(|(_, value)| *value)
        .ok_or_else(|| invalid(field, "Collection is required"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| invalid(field, "Collection must be an array"))?;
    if rows.is_empty() {
        return Err(invalid(field, "Collection must contain at least one row"));
    }
    Ok(rows)
}

fn reject_unknown_root_fields(root: &Map<String, Value>) -> Result<(), Failure> {
    const ALLOWED_FIELDS: &[&str] = &[
        "mappings",
        "method_addresses",
        "method_address_mappings",
        "evidence",
        "native_evidence",
        "decompilation_evidence",
    ];

    if let Some(field) = root
        .keys()
        .find(|field| !ALLOWED_FIELDS.contains(&field.as_str()))
    {
        return Err(invalid("input", &format!("Unknown field `{field}`")));
    }

    Ok(())
}

fn invalid_row(collection: &str, row: usize, reason: &str) -> Failure {
    invalid(&format!("{collection}[{row}]"), reason)
}

fn resource(reason: &str) -> Failure {
    Failure::new_with_details(
        "resource_exhausted",
        "resource_limit",
        reason.into(),
        false,
        "Reduce the retained row set and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        "IL2CPP decompilation join input is invalid.".into(),
        false,
        "Provide complete authenticated Evidence and exact mapping identities and retry.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (String::from("field"), Detail::Text(field.into())),
            (String::from("reason"), Detail::Text(reason.into())),
        ]),
    )
}
