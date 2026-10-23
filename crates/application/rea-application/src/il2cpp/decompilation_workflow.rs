//! Captured-only IL2CPP metadata, CodeGenModule, and native decompilation correlation.
//!
//! This workflow composes the existing normalized projections.  It does not
//! reopen artifacts, inspect paths, invoke a provider, or execute a target.

use rea_core::{
    evidence::is_sha256,
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "correlate_il2cpp_decompilation";
const MAX_ROWS: usize = 200_000;
const CODEGEN_OPERATIONS: &[&str] = &[
    "capture_il2cpp_codegen_module",
    "inspect_il2cpp_codegen_module_capture",
    "inspect_il2cpp_codegen_module_layout",
    "discover_il2cpp_codegen_modules",
];

/// Correlate captured metadata methods with native decompilation Evidence.
///
/// Metadata is authenticated through `project_captured_evidence`.  Method
/// pointers are resolved only through the exact token/image/module identity
/// rules in `il2cpp_method_address_map`; the final join delegates to
/// `il2cpp_decompilation_join`, which authenticates native Evidence and
/// compares binary digest, address space, and start address exactly.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata_capture = required_value(root, &["metadata_evidence"], "metadata_evidence")?;
    let metadata_evidence = evidence_record_from_capture(metadata_capture, "metadata_evidence")?;
    let metadata_result = super::metadata::project_captured_evidence(&json!({
        "evidence": metadata_evidence,
    }))?;
    let metadata_source = evidence_source(metadata_evidence, "metadata_evidence")?;
    let modules = codegen_modules_from_captures(root)?;
    let native_evidence = selected_rows(
        root,
        &[
            "native_evidence",
            "batch_evidence",
            "decompilation_evidence",
        ],
        "native_evidence",
    )?;
    if native_evidence.is_empty() {
        return Err(invalid(
            "native_evidence",
            "At least one native Evidence record is required",
        ));
    }
    if modules.len() > MAX_ROWS || native_evidence.len() > MAX_ROWS {
        return Err(resource(
            "CodeGenModule or native Evidence rows exceed the supported limit",
        ));
    }

    let method_mapping = super::method_address_map::project(&json!({
        "metadata": metadata_result.clone(),
        "binary": { "codegen_modules": modules },
    }))?;
    let mapping_items = method_mapping
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(
                "method_mapping.items",
                "Method-address projection returned no items",
            )
        })?;
    if mapping_items.len() > MAX_ROWS {
        return Err(resource("Metadata method rows exceed the supported limit"));
    }

    let mut join_mappings = Vec::new();
    let mut unresolved = Vec::new();
    for (index, item) in mapping_items.iter().enumerate() {
        let mapping = match exact_join_mapping(item, index)? {
            Some(mapping) => mapping,
            None => {
                unresolved.push(item.clone());
                continue;
            }
        };
        join_mappings.push(mapping);
    }

    let joined = super::decompilation_join::project(&json!({
        "mappings": join_mappings,
        "evidence": native_evidence,
    }))?;
    let joined_items = joined
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(
                "decompilation_join.items",
                "Decompilation join returned no items",
            )
        })?;
    let mut items = Vec::with_capacity(mapping_items.len());
    let mut joined_index = 0usize;
    for (index, item) in mapping_items.iter().enumerate() {
        if exact_join_mapping(item, index)?.is_some() {
            items.push(enrich_joined_item(
                joined_items.get(joined_index).ok_or_else(|| {
                    invalid(
                        "decompilation_join.items",
                        "Joined item count is inconsistent",
                    )
                })?,
                &metadata_source,
            ));
            joined_index += 1;
        } else {
            items.push(unresolved_item(item, &metadata_source));
        }
    }
    debug_assert_eq!(joined_index, joined_items.len());

    let selection = project_selection(root, metadata_evidence)?;
    let attribution = project_batch_attribution(&metadata_result, native_evidence)?;
    let generic_plan = project_generic_plan(root)?;
    let selectors = selection.get("selectors").cloned().unwrap_or(Value::Null);
    let selector_items = selection.get("items").cloned().unwrap_or(Value::Null);

    let unresolved_count = unresolved.len();
    let join_coverage = joined.get("coverage").cloned().unwrap_or(Value::Null);
    let partial = unresolved_count > 0
        || joined.get("status").and_then(Value::as_str) != Some("complete")
        || method_mapping.get("status").and_then(Value::as_str) != Some("complete")
        || projection_is_partial(&selection)
        || projection_is_partial(&attribution)
        || projection_is_partial(&generic_plan);
    Ok(json!({
        "operation": OPERATION,
        "status": if partial { "partial" } else { "complete" },
        "items": items,
        "unresolved_method_rows": unresolved,
        "metadata": {
            "source_evidence": metadata_source,
            "result": metadata_result,
        },
        "selection": selection,
        "selectors": selectors,
        "selector_items": selector_items,
        "attribution": attribution,
        "generic_plan": generic_plan,
        "coverage": {
            "methods": mapping_items.len(),
            "unresolved_method_rows": unresolved_count,
            "codegen_modules": modules.len(),
            "native_evidence": native_evidence.len(),
            "decompilation_join": join_coverage,
        },
    }))
}

/// Project an optional closed-generic plan without changing the native join.
///
/// The plan owns selector order and unresolved/ambiguous MethodSpec rows.  It
/// is retained beside the address join so a caller can distinguish a generic
/// method that was never safely selectable from one whose selected batch later
/// failed.
fn project_generic_plan(root: &Map<String, Value>) -> Result<Value, Failure> {
    let has_plan_input = [
        "method_specs",
        "methodSpecs",
        "generic_methods",
        "genericMethods",
        "generic_method_map",
        "method_addresses",
        "methodAddressMappings",
        "method_address_map",
    ]
    .iter()
    .any(|field| root.contains_key(*field));

    if !has_plan_input {
        return Ok(Value::Null);
    }

    let mut plan_input = Map::new();
    for (field, aliases) in [
        ("method_specs", &["method_specs", "methodSpecs"][..]),
        (
            "generic_methods",
            &["generic_methods", "genericMethods", "generic_method_map"][..],
        ),
        (
            "method_addresses",
            &[
                "method_addresses",
                "methodAddressMappings",
                "method_address_map",
            ][..],
        ),
    ] {
        if let Some(value) = optional_alias_value(root, aliases, field)? {
            plan_input.insert(field.into(), value.clone());
        }
    }

    super::generic_decompile_plan::project(&Value::Object(plan_input))
}

fn project_selection(
    root: &Map<String, Value>,
    metadata_evidence: &Value,
) -> Result<Value, Failure> {
    let Some(mapping_evidence) = optional_alias_value(
        root,
        &[
            "method_address_evidence",
            "method_addresses_evidence",
            "mapping_evidence",
        ],
        "method_address_evidence",
    )?
    else {
        return Ok(Value::Null);
    };

    super::decompile_selection::project(&json!({
        "metadata": metadata_evidence,
        "method_addresses": mapping_evidence,
    }))
}

fn project_batch_attribution(
    metadata_result: &Value,
    native_evidence: &[Value],
) -> Result<Value, Failure> {
    let methods = metadata_result
        .get("methods")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("metadata.methods", "Metadata methods are missing"))?;
    let mut attributions = Vec::new();

    for (index, evidence) in native_evidence.iter().enumerate() {
        if evidence_operation(evidence, index)? != "batch_decompile" {
            continue;
        }

        attributions.push(super::decompile_attribution::project(&json!({
            "methods": methods,
            "evidence": evidence,
        }))?);
    }

    Ok(match attributions.len() {
        0 => Value::Null,
        1 => attributions.remove(0),
        _ => Value::Array(attributions),
    })
}

fn evidence_operation(evidence: &Value, index: usize) -> Result<&str, Failure> {
    let object = evidence.as_object().ok_or_else(|| {
        invalid_row(
            "native_evidence",
            index,
            "Evidence record must be an object",
        )
    })?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid_row("native_evidence", index, "Evidence operation is missing"))?;
    Ok(operation)
}

fn optional_alias_value<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<Option<&'a Value>, Failure> {
    let mut selected = None;
    for alias in aliases {
        let Some(value) = root.get(*alias) else {
            continue;
        };
        if selected.is_some_and(|existing| existing != value) {
            return Err(invalid(field, "Input aliases conflict"));
        }
        selected = Some(value);
    }
    Ok(selected)
}

fn projection_is_partial(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.get("status").and_then(Value::as_str) == Some("partial"),
        Value::Array(values) => values.iter().any(projection_is_partial),
        _ => false,
    }
}

/// Alias used by operation-oriented application adapters.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Alias used by the runtime operation adapter.
pub fn correlate(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn exact_join_mapping(item: &Value, index: usize) -> Result<Option<Value>, Failure> {
    let object = item
        .as_object()
        .ok_or_else(|| invalid_row("method_mapping.items", index, "Expected an object"))?;
    if object.get("resolution").and_then(Value::as_str) != Some("mapped") {
        return Ok(None);
    }
    let module = match object.get("codegen_module") {
        None => return Ok(None),
        Some(Value::Object(module)) => module,
        Some(_) => {
            return Err(invalid_row(
                "method_mapping.items",
                index,
                "Mapped CodeGenModule must be an object",
            ));
        }
    };
    let Some(pointer) = object.get("method_pointer") else {
        return Ok(None);
    };
    let Some((start_address, pointer_address_space)) = pointer_address(pointer, index)? else {
        return Ok(None);
    };
    let module_address_space = text(module, &["address_space"]).or_else(|| {
        module
            .get("identity")
            .and_then(Value::as_object)
            .and_then(|identity| text(identity, &["address_space"]))
    });
    let address_space = match (module_address_space, pointer_address_space) {
        (Some(module), Some(pointer)) if module != pointer => return Ok(None),
        (Some(module), _) => Some(module),
        (None, pointer) => pointer,
    };
    let Some(address_space) = address_space else {
        return Ok(None);
    };
    let Some(binary_sha256) = module_digest(module) else {
        return Ok(None);
    };
    if !is_sha256(&binary_sha256) {
        return Err(invalid_row(
            "codegen_modules",
            index,
            "binary SHA-256 must be lowercase hexadecimal",
        ));
    }
    Ok(Some(json!({
        "method_mapping": item,
        "binary_sha256": binary_sha256,
        "address_space": address_space,
        "start_address": start_address,
    })))
}

fn pointer_address(
    pointer: &Value,
    index: usize,
) -> Result<Option<(String, Option<String>)>, Failure> {
    let object = pointer.as_object();
    let address = if let Some(object) = object {
        let mut claims = Vec::new();
        let mut invalid_claim = false;
        for field in [
            "address",
            "target_virtual_address",
            "virtual_address",
            "pointer",
        ] {
            let Some(value) = object.get(field) else {
                continue;
            };
            match pointer_text(value) {
                Some(claim) => claims.push(claim),
                None => invalid_claim = true,
            }
        }
        if invalid_claim {
            return Ok(None);
        }
        if claims.windows(2).any(|pair| pair[0] != pair[1]) {
            return Ok(None);
        }
        claims.into_iter().next()
    } else {
        pointer_text(pointer)
    }
    .ok_or_else(|| {
        invalid_row(
            "method_mapping.items",
            index,
            "Mapped pointer address must be non-empty text",
        )
    })?;
    let address_space = object.and_then(|value| text(value, &["address_space"]));
    Ok(Some((address, address_space)))
}

fn pointer_text(value: &Value) -> Option<String> {
    if let Some(address) = value.as_str().filter(|address| !address.is_empty()) {
        return Some(address.to_owned());
    }
    value.as_u64().map(|address| format!("0x{address:x}"))
}

fn module_digest(module: &Map<String, Value>) -> Option<String> {
    text(module, &["binary_sha256", "binary_digest", "sha256"]).or_else(|| {
        module
            .get("identity")
            .and_then(Value::as_object)
            .and_then(|identity| text(identity, &["binary_sha256", "binary_digest", "sha256"]))
    })
}

fn enrich_joined_item(item: &Value, metadata_source: &Value) -> Value {
    let mut result = item.as_object().cloned().unwrap_or_default();
    result.insert("metadata_source_evidence".into(), metadata_source.clone());
    Value::Object(result)
}

fn unresolved_item(item: &Value, metadata_source: &Value) -> Value {
    let mapping_resolution = item
        .get("resolution")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let resolution = if mapping_resolution == "mapped" {
        "unknown"
    } else {
        mapping_resolution
    };
    let explanation = match mapping_resolution {
        "ambiguous" => "Multiple exact image/module candidates remain for this method token.",
        "unmapped" => {
            "No exact image/module CodeGenModule candidate contains this method token RID."
        }
        "mapped" => {
            "The mapped method lacks one consistent binary address identity for decompilation."
        }
        _ => "The method pointer remains unknown.",
    };
    json!({
        "method_mapping": item,
        "status": resolution,
        "matches": [],
        "unknowns": [explanation],
        "metadata_source_evidence": metadata_source,
    })
}

fn evidence_source(value: &Value, field: &str) -> Result<Value, Failure> {
    let raw = serde_json::value::to_raw_value(value)
        .map_err(|error| invalid(field, &error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(field, &error.to_string()))?;
    let operation = serde_json::from_str::<String>(record.operation().get())
        .map_err(|error| invalid(field, &error.to_string()))?;
    Ok(json!({
        "evidence_id": record.evidence_id(),
        "operation": operation,
    }))
}

fn evidence_record_from_capture<'a>(capture: &'a Value, field: &str) -> Result<&'a Value, Failure> {
    if !capture.is_object() {
        return Err(invalid(
            field,
            "An authenticated Evidence object is required",
        ));
    }
    Ok(capture)
}

fn codegen_modules_from_captures(root: &Map<String, Value>) -> Result<Vec<Value>, Failure> {
    let captures = root
        .get("codegen_evidence")
        .ok_or_else(|| invalid("codegen_evidence", "Collection is required"))?
        .as_array()
        .ok_or_else(|| invalid("codegen_evidence", "Collection must be an array"))?;
    if captures.is_empty() {
        return Err(invalid(
            "codegen_evidence",
            "At least one Evidence record is required",
        ));
    }
    if captures.len() > MAX_ROWS {
        return Err(resource("CodeGen Evidence rows exceed the supported limit"));
    }
    let mut modules = Vec::new();

    for (index, capture) in captures.iter().enumerate() {
        let record = capture
            .as_object()
            .and_then(|object| object.get("evidence"))
            .unwrap_or(capture);
        let raw = serde_json::value::to_raw_value(record)
            .map_err(|error| invalid(&format!("codegen_evidence[{index}]"), &error.to_string()))?;
        let parsed = EvidenceRecord::parse(&raw)
            .map_err(|error| invalid(&format!("codegen_evidence[{index}]"), &error.to_string()))?;
        let operation =
            serde_json::from_str::<String>(parsed.operation().get()).map_err(|error| {
                invalid(
                    &format!("codegen_evidence[{index}].operation"),
                    &error.to_string(),
                )
            })?;
        if !CODEGEN_OPERATIONS.contains(&operation.as_str()) {
            return Err(invalid(
                &format!("codegen_evidence[{index}].operation"),
                "Evidence operation does not produce CodeGenModule rows",
            ));
        }
        let evidence_id = parsed.evidence_id().to_owned();
        let subject_sha256 = parsed.subject_sha256().map(str::to_owned);
        let normalized: Value =
            serde_json::from_str(parsed.normalized_result().get()).map_err(|error| {
                invalid(
                    &format!("codegen_evidence[{index}].normalized_result"),
                    &error.to_string(),
                )
            })?;
        let rows = normalized_codegen_rows(&normalized, index)?;

        for row in rows {
            let mut row = row
                .as_object()
                .ok_or_else(|| invalid("codegen_evidence", "CodeGenModule rows must be objects"))?
                .clone();
            if !row.contains_key("binary_sha256") {
                if let Some(digest) = &subject_sha256 {
                    row.insert("binary_sha256".into(), Value::String(digest.clone()));
                }
            }
            row.insert(
                "source_evidence_id".into(),
                Value::String(evidence_id.clone()),
            );
            modules.push(Value::Object(row));
        }
    }

    Ok(modules)
}

fn normalized_codegen_rows(normalized: &Value, index: usize) -> Result<Vec<Value>, Failure> {
    let field = format!("codegen_evidence[{index}]");

    if let Some(rows) = normalized
        .get("codegen_modules")
        .or_else(|| normalized.get("modules"))
        .and_then(Value::as_array)
    {
        return Ok(rows.clone());
    }

    if let Some(items) = normalized.get("items").and_then(Value::as_array) {
        let rows = items
            .iter()
            .filter_map(|item| item.get("codegen_module"))
            .cloned()
            .collect();
        return Ok(rows);
    }

    if let Some(candidates) = normalized.get("candidates").and_then(Value::as_array) {
        return candidates.iter().map(candidate_codegen_module).collect();
    }

    if normalized.is_object() {
        return Ok(vec![normalized.clone()]);
    }

    Err(invalid(
        &field,
        "Normalized result has no CodeGenModule rows",
    ))
}

fn candidate_codegen_module(candidate: &Value) -> Result<Value, Failure> {
    let mut module = candidate
        .as_object()
        .ok_or_else(|| {
            invalid(
                "codegen_evidence",
                "CodeGenModule candidates must be objects",
            )
        })?
        .clone();
    let pointers = module
        .get("method_pointers")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            invalid(
                "codegen_evidence",
                "CodeGenModule candidate has no method pointers",
            )
        })?;
    let normalized_pointers = pointers
        .iter()
        .map(|pointer| {
            let mut pointer = pointer.as_object().cloned().unwrap_or_default();
            if let Some(address) = pointer
                .get("target_virtual_address")
                .and_then(Value::as_u64)
            {
                pointer.insert("address".into(), Value::String(format!("0x{address:x}")));
            }
            Value::Object(pointer)
        })
        .collect();
    module.insert("method_pointers".into(), Value::Array(normalized_pointers));
    Ok(Value::Object(module))
}

fn required_value<'a>(
    root: &'a Map<String, Value>,
    aliases: &[&str],
    field: &str,
) -> Result<&'a Value, Failure> {
    aliases
        .iter()
        .find_map(|alias| root.get(*alias))
        .ok_or_else(|| invalid(field, "Captured metadata Evidence is required"))
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
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| invalid(field, "Collection must be an array"))
}

fn text(object: &Map<String, Value>, fields: &[&str]) -> Option<String> {
    fields.iter().find_map(|field| {
        object
            .get(*field)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    })
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
        "Reduce the retained captured rows and retry.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new_with_details("invalid_request", "invalid_input", "IL2CPP decompilation workflow input is invalid.".into(), false, "Provide one authenticated metadata Evidence record, normalized CodeGenModule facts, and authenticated native Evidence.".into(), BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into())), (String::from("field"), Detail::Text(field.into())), (String::from("reason"), Detail::Text(reason.into()))]))
}
