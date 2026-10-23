//! Provider-neutral validation and projection for ordered batch decompilation.
//!
//! A provider owns address resolution and decompiler execution.  This module
//! only validates the bounded result, checks that the provider preserved the
//! caller's selector order, and projects retained Evidence without rerunning
//! analysis or interpreting pseudocode.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "batch_decompile";

const MAX_ADDRESSES: usize = 64;
const MAX_ITEMS: usize = MAX_ADDRESSES;
const MAX_PSEUDOCODE_BYTES: usize = 512 * 1024;
const MAX_ERROR_MESSAGE_BYTES: usize = 4 * 1024;

const ERROR_CODES: &[&str] = &[
    "invalid_request",
    "access_denied",
    "artifact_changed",
    "unreadable_output",
    "capability_unavailable",
    "unsupported_target",
    "provider_unavailable",
    "provider_timeout",
    "resource_constraint",
    "cancelled",
    "artifact_integrity_mismatch",
    "artifact_operation_failed",
    "evidence_integrity_mismatch",
    "truncated",
    "process_capture_failed",
    "cleanup_incomplete",
    "revision_conflict",
    "configuration_invalid",
    "target_unavailable",
    "execution_failure",
];

const ERROR_CATEGORIES: &[&str] = &[
    "invalid_input",
    "unsupported_provider",
    "unsupported_target",
    "integrity_mismatch",
    "truncated",
    "cancelled",
    "timeout",
    "resource_constraint",
    "unavailable",
    "execution_failure",
];

const INPUT_FIELDS: &[&str] = &["addresses", "evidence", "result", "observations"];
const RESULT_FIELDS: &[&str] = &["items", "total", "succeeded", "failed", "durability"];

/// Validate the caller's ordered batch selectors and any retained carrier.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("batch_decompile input must be an object"))?;
    reject_fields(object, INPUT_FIELDS, "batch_decompile input")?;
    validate_addresses(object.get("addresses"))?;

    if let Some(evidence) = object.get("evidence") {
        validate_evidence(evidence)?;
    }
    if let Some(result) = object.get("result") {
        validate_result(result)?;
    }
    if let Some(observations) = object.get("observations") {
        validate_observations(observations)?;
    }

    Ok(())
}

/// Validate a provider result before an adapter wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    validate_selector_order(input, &result)?;
    Ok(result)
}

/// Project an already retained batch result without reinterpreting provider
/// facts or changing item order.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let result = selected_result(input)?;
    validate_selector_order(input, result)?;
    Ok(result.clone())
}

/// Alias used by retained-Evidence callers.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn selected_result(input: &Value) -> Result<&Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("batch_decompile input must be an object"))?;

    if let Some(result) = object.get("result") {
        return Ok(result);
    }
    if let Some(evidence) = object.get("evidence") {
        return evidence_result(evidence);
    }
    Err(invalid(
        "batch_decompile requires a retained result or Evidence",
    ))
}

fn validate_addresses(value: Option<&Value>) -> Result<(), Failure> {
    let Some(value) = value else {
        return Ok(());
    };
    let addresses = value
        .as_array()
        .ok_or_else(|| invalid("addresses must be an array"))?;
    if addresses.len() > MAX_ADDRESSES {
        return Err(resource("batch_decompile accepts at most 64 addresses"));
    }
    for address in addresses {
        if address.as_str().is_none() {
            return Err(invalid("addresses must contain strings"));
        }
    }
    Ok(())
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("batch_decompile Evidence must be an object"))?;
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid("batch_decompile Evidence must include evidence_id"));
    }
    if let Some(operation) = object.get("operation")
        && operation.as_str() != Some(OPERATION)
    {
        return Err(invalid("Evidence operation is not batch_decompile"));
    }
    validate_result(evidence_result(evidence)?)
}

fn evidence_result(evidence: &Value) -> Result<&Value, Failure> {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .ok_or_else(|| invalid("batch_decompile Evidence is missing normalized_result"))
}

fn validate_result(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("batch_decompile result must be an object"))?;
    reject_fields(object, RESULT_FIELDS, "batch_decompile result")?;

    let items = object
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("batch_decompile result items must be an array"))?;
    if items.len() > MAX_ITEMS {
        return Err(resource("batch_decompile result exceeds 64 items"));
    }
    for item in items {
        validate_item(item)?;
    }

    let total = nonnegative_count(object.get("total"), "total")?;
    let succeeded = nonnegative_count(object.get("succeeded"), "succeeded")?;
    let failed = nonnegative_count(object.get("failed"), "failed")?;
    let actual_succeeded = items
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) == Some("ok"))
        .count();
    if total != items.len()
        || succeeded != actual_succeeded
        || failed != items.len() - actual_succeeded
    {
        return Err(invalid(
            "batch counters must describe returned item statuses",
        ));
    }

    if let Some(durability) = object.get("durability") {
        validate_durability(durability, items)?;
    }
    Ok(())
}

fn validate_item(value: &Value) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("batch item must be an object"))?;
    let address = object
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("batch item address must be a string"))?;
    if address.len() > 4096 {
        return Err(resource("batch item address exceeds the output limit"));
    }

    match object.get("status").and_then(Value::as_str) {
        Some("ok") => {
            require_fields(object, &["address", "procedure", "status", "pseudocode"])?;
            let pseudocode = object
                .get("pseudocode")
                .and_then(Value::as_str)
                .filter(|text| !text.is_empty())
                .ok_or_else(|| invalid("successful batch item requires pseudocode"))?;
            if pseudocode.len() > MAX_PSEUDOCODE_BYTES {
                return Err(resource("pseudocode exceeds the 512 KiB output limit"));
            }
        }
        Some("error") => {
            require_fields(object, &["address", "procedure", "status", "error"])?;
            validate_error(object.get("error"))?;
        }
        _ => return Err(invalid("batch item status must be ok or error")),
    }
    validate_procedure(object.get("procedure"))
}

fn validate_procedure(value: Option<&Value>) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("batch item procedure must be an object"))?;
    match object.get("status").and_then(Value::as_str) {
        Some("resolved") => {
            require_fields(object, &["status", "address", "name"])?;
            if object
                .get("address")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                return Err(invalid("resolved procedure address must be non-empty"));
            }
            if object
                .get("name")
                .is_none_or(|name| name.is_null() || name.is_string())
                == false
            {
                return Err(invalid("resolved procedure name must be a string or null"));
            }
            if let Some(error) = object.get("name_error") {
                validate_error(Some(error))?;
            }
        }
        Some("unknown") => {
            require_fields(object, &["status", "error"])?;
            validate_error(object.get("error"))?;
        }
        _ => return Err(invalid("procedure status must be resolved or unknown")),
    }
    Ok(())
}

fn validate_error(value: Option<&Value>) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("analysis error must be an object"))?;
    for field in ["code", "category", "message", "retryable", "remediation"] {
        if !object.contains_key(field) {
            return Err(invalid(&format!("analysis error requires {field}")));
        }
    }
    if object
        .get("code")
        .and_then(Value::as_str)
        .is_none_or(|code| !ERROR_CODES.contains(&code))
        || object
            .get("category")
            .and_then(Value::as_str)
            .is_none_or(|category| !ERROR_CATEGORIES.contains(&category))
        || object
            .get("message")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object
            .get("message")
            .and_then(Value::as_str)
            .is_some_and(|message| message.len() > MAX_ERROR_MESSAGE_BYTES)
        || !object.get("retryable").is_some_and(Value::is_boolean)
    {
        return Err(invalid("analysis error contains invalid fields"));
    }

    validate_error_details(object)?;

    let remediation = object
        .get("remediation")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("analysis error remediation must be an object"))?;
    if remediation
        .get("action")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(invalid("analysis error remediation requires action"));
    }
    Ok(())
}

fn validate_error_details(object: &Map<String, Value>) -> Result<(), Failure> {
    if object.get("code").and_then(Value::as_str) != Some("artifact_integrity_mismatch") {
        return Ok(());
    }

    let details = object
        .get("details")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("artifact integrity errors require details"))?;
    let logical_path = details
        .get("logical_path")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("artifact integrity details require logical_path"))?;
    if logical_path.is_empty() {
        return Err(invalid(
            "artifact integrity details require a non-empty logical_path",
        ));
    }
    for field in ["declared_sha256", "calculated_sha256"] {
        if !details
            .get(field)
            .is_some_and(|value| value.is_null() || value.is_string())
        {
            return Err(invalid(&format!(
                "artifact integrity details require string-or-null {field}"
            )));
        }
    }
    if !details.get("unpacked").is_some_and(Value::is_boolean) {
        return Err(invalid(
            "artifact integrity details require boolean unpacked",
        ));
    }

    Ok(())
}

fn validate_durability(value: &Value, items: &[Value]) -> Result<(), Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("durability must be an object"))?;
    require_fields(object, &["confirmed_addresses", "unconfirmed_addresses"])?;
    let confirmed = address_list(object.get("confirmed_addresses"), "confirmed_addresses")?;
    let unconfirmed = address_list(object.get("unconfirmed_addresses"), "unconfirmed_addresses")?;
    let mut all = BTreeSet::new();
    for address in confirmed.iter().chain(unconfirmed.iter()) {
        if !all.insert(address.clone()) {
            return Err(invalid(
                "durability addresses must be unique and nonoverlapping",
            ));
        }
    }
    let resolved = items
        .iter()
        .filter_map(|item| item.get("procedure"))
        .filter_map(|procedure| {
            (procedure.get("status").and_then(Value::as_str) == Some("resolved"))
                .then(|| procedure.get("address").and_then(Value::as_str))
                .flatten()
        })
        .collect::<BTreeSet<_>>();
    if all
        .iter()
        .any(|address| !resolved.contains(address.as_str()))
    {
        return Err(invalid(
            "durability addresses must belong to resolved procedures",
        ));
    }
    for item in items {
        if item.get("status").and_then(Value::as_str) == Some("ok") {
            let address = item
                .get("procedure")
                .and_then(|procedure| procedure.get("address"))
                .and_then(Value::as_str);
            if address.is_none_or(|address| !all.contains(address)) {
                return Err(invalid(
                    "durability must classify every successful procedure",
                ));
            }
        }
    }
    Ok(())
}

fn validate_observations(value: &Value) -> Result<(), Failure> {
    let observations = value
        .as_array()
        .ok_or_else(|| invalid("observations must be an array"))?;
    if observations.len() > MAX_ITEMS {
        return Err(resource("observations exceed 64 records"));
    }
    for observation in observations {
        let object = observation
            .as_object()
            .ok_or_else(|| invalid("observation must be an object"))?;
        if object
            .get("evidence")
            .is_none_or(|evidence| !evidence.is_object())
        {
            return Err(invalid("observation requires Evidence"));
        }
    }
    Ok(())
}

fn validate_selector_order(input: &Value, result: &Value) -> Result<(), Failure> {
    let Some(addresses) = input.get("addresses").and_then(Value::as_array) else {
        return Ok(());
    };
    let items = result
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("batch result items must be an array"))?;
    if items.len() != addresses.len() {
        return Err(invalid("batch result must contain one item per selector"));
    }
    for (index, (selected, item)) in addresses.iter().zip(items).enumerate() {
        if item.get("address") != Some(selected) {
            return Err(invalid(&format!(
                "batch result item {index} does not preserve selector order"
            )));
        }
    }
    Ok(())
}

fn address_list(value: Option<&Value>, label: &str) -> Result<Vec<String>, Failure> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(&format!("{label} must be an array")))?;
    values
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|address| !address.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| invalid(&format!("{label} must contain non-empty strings")))
        })
        .collect()
}

fn nonnegative_count(value: Option<&Value>, label: &str) -> Result<usize, Failure> {
    value
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| invalid(&format!("{label} must be a non-negative integer")))
}

fn require_fields(object: &Map<String, Value>, fields: &[&str]) -> Result<(), Failure> {
    if let Some(field) = fields.iter().find(|field| !object.contains_key(**field)) {
        return Err(invalid(&format!("batch result requires {field}")));
    }
    Ok(())
}

fn reject_fields(
    object: &Map<String, Value>,
    allowed: &[&str],
    label: &str,
) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(invalid(&format!("unknown {label} field: {field}")));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        false,
        "Provide an ordered batch result with one validated item per selector.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn resource(message: &str) -> Failure {
    Failure::new_with_details(
        "resource_constraint",
        "resource_constraint",
        message.to_owned(),
        false,
        "Select fewer procedures or request a smaller result.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
