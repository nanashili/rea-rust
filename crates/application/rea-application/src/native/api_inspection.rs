//! Provider-neutral projection of a native function's API boundary.
//!
//! The provider owns decompilation and type recovery.  This module only reads
//! an authenticated `analyze_function` Evidence record and preserves every
//! boundary fact, limitation, and unresolved question without guessing.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_native_api";

/// Project one caller-selected function dossier into the native API workflow.
///
/// Adapters may pass the Evidence directly or under `function`/`evidence`.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let evidence = input
        .get("function")
        .or_else(|| input.get("evidence"))
        .unwrap_or(input);
    project(evidence)
}

/// Project an authenticated `analyze_function` Evidence record.
pub fn project(evidence: &Value) -> Result<Value, Failure> {
    validate_evidence(evidence)?;
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("function Evidence is missing its result"))?;
    let dossier = result.get("dossier").unwrap_or(result);
    let procedure = dossier
        .get("procedure")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("function dossier must contain procedure"))?;
    let address = required_text(procedure.get("address"), "procedure.address")?;
    let name = required_text(procedure.get("name"), "procedure.name")?;

    let boundary = match dossier.get("native_api") {
        Some(value) if !value.is_null() => validate_boundary(value.clone())?,
        _ => unavailable_boundary(),
    };
    let residual_unknowns = if boundary.get("available").and_then(Value::as_bool) == Some(true) {
        available_unknowns(&boundary)
    } else {
        strings(&boundary, "residual_unknowns")
    };
    let available = boundary.get("available").and_then(Value::as_bool) == Some(true);
    let unsupported_branches = if available {
        Vec::new()
    } else {
        vec![
            "structured-boundary-types".to_owned(),
            "jump-table-data-mapping".to_owned(),
        ]
    };
    let substeps = vec![
        json!({
            "operation": "analyze_function",
            "status": "completed",
            "observations": [
                "provider function dossier",
                "provider pseudocode classification",
                "provider control-flow observations"
            ]
        }),
        json!({
            "operation": "project_native_api_boundary",
            "status": if available { "completed" } else { "unsupported" },
            "observations": if available {
                json!(["return and parameter boundary types", "confidence and inference evidence", "jump-table dispatch, data, and target addresses"])
            } else {
                json!([boundary.get("reason").and_then(Value::as_str).unwrap_or("structured boundary is unavailable")])
            }
        }),
        json!({
            "operation": "preserve_residual_unknowns",
            "status": "completed",
            "observations": if residual_unknowns.is_empty() {
                json!(["no additional structured-boundary unknowns"])
            } else {
                json!(residual_unknowns)
            }
        }),
    ];
    Ok(json!({
        "procedure": { "address": address, "name": name },
        "boundary": boundary,
        "substeps": substeps,
        "unsupported_branches": unsupported_branches,
        "residual_unknowns": residual_unknowns,
    }))
}

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let evidence = input
        .get("function")
        .or_else(|| input.get("evidence"))
        .unwrap_or(input);
    validate_evidence(evidence)
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    if evidence.get("operation").and_then(Value::as_str) != Some("analyze_function") {
        return Err(invalid(
            "native API inspection requires analyze_function Evidence",
        ));
    }
    if evidence
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("function Evidence must include evidence_id"));
    }
    if evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .is_none()
    {
        return Err(invalid(
            "function Evidence must include normalized_result or result",
        ));
    }
    Ok(())
}

fn unavailable_boundary() -> Value {
    json!({
        "available": false,
        "reason": "The selected provider did not expose a structured native API boundary model.",
        "residual_unknowns": [
            "What are the function's return and parameter boundary types?",
            "Does this function dispatch through a jump table with recoverable data addresses?"
        ]
    })
}

fn validate_boundary(value: Value) -> Result<Value, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("native_api must be an object"))?;
    match object.get("available").and_then(Value::as_bool) {
        Some(false) => {
            require_text(object.get("reason"), "native_api.reason")?;
            let unknowns = object
                .get("residual_unknowns")
                .and_then(Value::as_array)
                .ok_or_else(|| invalid("native_api.residual_unknowns must be an array"))?;
            if unknowns.is_empty()
                || unknowns
                    .iter()
                    .any(|item| item.as_str().is_none_or(str::is_empty))
            {
                return Err(invalid("native_api.residual_unknowns must contain text"));
            }
        }
        Some(true) => validate_available(object)?,
        _ => return Err(invalid("native_api.available must be a boolean")),
    }
    Ok(value)
}

fn validate_available(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    for key in ["provenance", "signature_source", "calling_convention"] {
        require_text(object.get(key), &format!("native_api.{key}"))?;
    }
    validate_type(object.get("return_type"), "return_type", true)?;
    let parameters = object
        .get("parameters")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("native_api.parameters must be an array"))?;
    for parameter in parameters {
        validate_type(Some(parameter), "parameters", false)?;
    }
    let tables = object
        .get("jump_tables")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("native_api.jump_tables must be an array"))?;
    for table in tables {
        validate_jump_table(table)?;
    }
    let pseudocode = object
        .get("pseudocode")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("native_api.pseudocode must be an object"))?;
    if pseudocode.get("classification").and_then(Value::as_str)
        != Some("decompiler-generated-non-source")
        || pseudocode.get("compilable").and_then(Value::as_bool) != Some(false)
    {
        return Err(invalid("native_api pseudocode classification is invalid"));
    }
    validate_decompiler_artifacts(object.get("decompiler_artifacts"))?;
    strings_array(object.get("limitations"), "native_api.limitations")?;
    Ok(())
}

fn validate_type(value: Option<&Value>, label: &str, return_type: bool) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid(&format!("native_api.{label} must be an object")))?;
    let role = object.get("role").and_then(Value::as_str);
    if return_type && role != Some("return") || !return_type && role != Some("parameter") {
        return Err(invalid("native_api boundary type has an invalid role"));
    }
    require_text(object.get("data_type"), "native_api.data_type")?;
    require_text(object.get("confidence"), "native_api.confidence")?;
    if !matches!(
        object.get("confidence").and_then(Value::as_str),
        Some("low" | "medium" | "high")
    ) {
        return Err(invalid("native_api confidence is invalid"));
    }
    validate_type_identity(object, return_type)?;
    object
        .get("evidence")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or_else(|| invalid("native_api boundary evidence is required"))?;
    for evidence in object
        .get("evidence")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        validate_inference_evidence(evidence)?;
    }
    strings_array(
        object.get("decompiler_artifacts"),
        "native_api.decompiler_artifacts",
    )?;
    if object
        .get("decompiler_artifacts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|item| {
            !matches!(
                item.as_str(),
                Some(
                    "recovered-signature"
                        | "register-and-stack-variables"
                        | "compiler-generated-variable"
                )
            )
        })
    {
        return Err(invalid("native_api type decompiler artifact is invalid"));
    }
    Ok(())
}

fn validate_decompiler_artifacts(value: Option<&Value>) -> Result<(), Failure> {
    let label = "native_api.decompiler_artifacts";
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    if items.iter().any(|item| {
        !matches!(
            item.as_str(),
            Some(
                "recovered-signature"
                    | "register-and-stack-variables"
                    | "compiler-generated-control-flow"
                    | "pointer-arithmetic"
                    | "pseudocode"
            )
        )
    }) {
        return Err(invalid("native_api decompiler artifact is invalid"));
    }
    Ok(())
}

fn validate_type_identity(
    object: &serde_json::Map<String, Value>,
    return_type: bool,
) -> Result<(), Failure> {
    let ordinal = object.get("ordinal");
    let name = object.get("name");
    if return_type {
        if !ordinal.is_some_and(Value::is_null) || !name.is_some_and(Value::is_null) {
            return Err(invalid(
                "native_api return type ordinal and name must be null",
            ));
        }
    } else {
        let ordinal = ordinal
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("native_api parameter ordinal must be nonnegative"))?;
        if ordinal > i64::MAX as u64 {
            return Err(invalid("native_api parameter ordinal is out of range"));
        }
        let name = name.ok_or_else(|| invalid("native_api parameter name is required"))?;
        if !name.is_null() && name.as_str().is_none_or(str::is_empty) {
            return Err(invalid("native_api parameter name must be text or null"));
        }
    }
    let size = object
        .get("size_bytes")
        .ok_or_else(|| invalid("native_api size_bytes is required"))?;
    if !size.is_null() && size.as_u64().is_none() {
        return Err(invalid("native_api size_bytes must be nonnegative or null"));
    }
    let storage = object
        .get("storage")
        .ok_or_else(|| invalid("native_api storage is required"))?;
    if !storage.is_null() && storage.as_str().is_none_or(str::is_empty) {
        return Err(invalid("native_api storage must be text or null"));
    }
    Ok(())
}

fn validate_inference_evidence(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("native_api inference evidence must be an object"))?;
    if !matches!(
        object.get("kind").and_then(Value::as_str),
        Some(
            "signature-source"
                | "decompiler-type"
                | "type-lock"
                | "calling-convention"
                | "jump-table"
        )
    ) {
        return Err(invalid("native_api inference evidence kind is invalid"));
    }
    require_text(object.get("source"), "native_api inference evidence source")?;
    require_text(object.get("detail"), "native_api inference evidence detail")?;
    Ok(())
}

fn validate_jump_table(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("native_api jump table must be an object"))?;
    require_text(
        object.get("dispatch_address"),
        "jump table dispatch_address",
    )?;
    for key in ["data_sources", "mappings", "default_targets"] {
        object
            .get(key)
            .and_then(Value::as_array)
            .ok_or_else(|| invalid("native_api jump table collection must be an array"))?;
    }
    strings_array(object.get("limitations"), "jump table limitations")?;
    Ok(())
}

fn available_unknowns(boundary: &Value) -> Vec<String> {
    let mut unknowns = Vec::new();
    if let Some(tables) = boundary.get("jump_tables").and_then(Value::as_array) {
        for table in tables {
            let address = table
                .get("dispatch_address")
                .and_then(Value::as_str)
                .unwrap_or("<unknown>");
            if table
                .get("default_targets")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                unknowns.push(format!("Which default or out-of-range path, if any, belongs to the dispatch at {address}?"));
            }
            if table
                .get("mappings")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                unknowns.push(format!(
                    "Which case values and targets belong to the dispatch at {address}?"
                ));
            }
            if table
                .get("data_sources")
                .and_then(Value::as_array)
                .is_none_or(Vec::is_empty)
            {
                unknowns.push(format!(
                    "What backing data address produced the jump table dispatched at {address}?"
                ));
            }
            if table
                .get("data_sources")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items.iter().any(|item| {
                        item.get("entry_count").is_none_or(Value::is_null)
                            || item.get("entry_size_bytes").is_none_or(Value::is_null)
                    })
                })
            {
                unknowns.push(format!("What are the exact entry size and count for candidate jump-table data dispatched at {address}?"));
            }
            if table
                .get("mappings")
                .and_then(Value::as_array)
                .is_some_and(|items| {
                    items
                        .iter()
                        .any(|item| item.get("case_value").is_none_or(Value::is_null))
                })
            {
                unknowns.push(format!("Which source-level case values correspond to every target dispatched at {address}?"));
            }
        }
    }
    for value in std::iter::once(boundary.get("return_type")).chain(
        boundary
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(Some),
    ) {
        if value
            .and_then(|item| item.get("confidence"))
            .and_then(Value::as_str)
            == Some("low")
        {
            let role = value
                .and_then(|item| item.get("role"))
                .and_then(Value::as_str)
                .unwrap_or("boundary");
            let data_type = value
                .and_then(|item| item.get("data_type"))
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            unknowns.push(format!("Can the inferred {role} type {data_type} be confirmed with imported metadata or an ABI probe?"));
        }
    }
    unknowns.sort();
    unknowns.dedup();
    unknowns
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn strings_array(value: Option<&Value>, label: &str) -> Result<(), Failure> {
    let items = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    if items.iter().any(|item| item.as_str().is_none()) {
        return Err(invalid(&format!("{label} must contain strings")));
    }
    Ok(())
}

fn required_text(value: Option<&Value>, label: &str) -> Result<String, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| invalid(&format!("{label} must be non-empty text")))
}

fn require_text(value: Option<&Value>, label: &str) -> Result<(), Failure> {
    required_text(value, label).map(|_| ())
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide authenticated analyze_function Evidence and retry.".into(),
        BTreeMap::from([("operation".to_owned(), Detail::Text(OPERATION.to_owned()))]),
    )
}
