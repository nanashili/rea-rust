//! Projection of authenticated function Evidence into a callee inventory.
//!
//! Function analysis providers own call-graph discovery.  This module only
//! reads the retained dossier and carries its identities and coverage facts
//! into the `procedure_callees` result; it never resolves a procedure or
//! attaches to a provider database.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};

pub const OPERATION: &str = "procedure_callees";
const MAX_CALLEES: usize = 100_000;

/// Validate a caller-selected function Evidence projection request.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_callees input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("function"))
        .ok_or_else(|| invalid("function Evidence is required"))?;
    validate_function_evidence(evidence)?;

    if let Some(procedure) = object.get("procedure")
        && procedure.as_str().is_none()
    {
        return Err(invalid("procedure must be a string when supplied"));
    }
    Ok(())
}

/// Retain a provider result after validating its request and result shape.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if result.is_array() {
        validate_callee_array(&result)?;
    } else {
        validate_result(&result)?;
    }
    Ok(result)
}

/// Project the callee addresses from one authenticated function dossier.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_callees input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("function"))
        .ok_or_else(|| invalid("function Evidence is required"))?;
    let evidence_id = evidence_id(evidence)?.to_owned();
    let result = function_result(evidence)?;
    let dossier = result.get("dossier").unwrap_or(result);
    let procedure = procedure_identity(dossier, object.get("procedure"))?;
    let callees = extract_callees(result, dossier)?;
    let coverage = extract_coverage(result, dossier);
    let mut limitations = collect_strings(evidence.get("limitations"));
    limitations.extend(collect_strings(result.get("limitations")));
    if coverage.is_none() {
        limitations.push("Callee completeness was not reported by the source Evidence.".into());
    }
    limitations.sort();
    limitations.dedup();

    let status = match coverage
        .as_ref()
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
    {
        Some("complete") => "complete",
        Some("partial") | Some("truncated") => "partial",
        _ => "unknown",
    };
    let output = json!({
        "procedure": procedure,
        "callees": callees,
        "status": status,
        "relationship_coverage": coverage,
        "evidence_links": [evidence_id],
        "limitations": limitations,
    });
    validate_result(&output)?;
    Ok(output)
}

fn validate_function_evidence(evidence: &Value) -> Result<(), Failure> {
    if !evidence.is_object() {
        return Err(invalid("function Evidence must be an object"));
    }
    let operation = evidence.get("operation").and_then(Value::as_str);
    if operation != Some("analyze_function") && operation != Some(OPERATION) {
        return Err(invalid(
            "Evidence operation must be analyze_function or procedure_callees",
        ));
    }
    evidence_id(evidence)?;
    function_result(evidence)?;
    Ok(())
}

fn function_result(evidence: &Value) -> Result<&Value, Failure> {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .ok_or_else(|| invalid("function Evidence must include normalized_result or result"))
}

fn procedure_identity(dossier: &Value, selector: Option<&Value>) -> Result<Value, Failure> {
    if let Some(selector) = selector.and_then(Value::as_str) {
        return Ok(Value::String(selector.to_owned()));
    }
    let procedure = dossier
        .get("procedure")
        .or_else(|| dossier.get("function"))
        .ok_or_else(|| invalid("function dossier must include procedure identity"))?;
    if let Some(address) = procedure.get("address").and_then(Value::as_str) {
        return Ok(Value::String(address.to_owned()));
    }
    if let Some(name) = procedure.get("name").and_then(Value::as_str) {
        return Ok(Value::String(name.to_owned()));
    }
    Err(invalid("procedure identity must include address or name"))
}

fn extract_callees(result: &Value, dossier: &Value) -> Result<Vec<Value>, Failure> {
    let source = if result.is_array() {
        result
    } else {
        result
            .get("callees")
            .or_else(|| dossier.get("callees"))
            .ok_or_else(|| invalid("function Evidence must include callees"))?
    };
    let values = source
        .as_array()
        .ok_or_else(|| invalid("callees must be an array"))?;
    if values.len() > MAX_CALLEES {
        return Err(invalid("callee inventory exceeds the supported bound"));
    }

    let mut addresses = Vec::with_capacity(values.len());
    for value in values {
        let address = value
            .as_str()
            .or_else(|| value.get("address").and_then(Value::as_str))
            .filter(|address| !address.is_empty())
            .ok_or_else(|| invalid("callee entries must contain an address"))?;
        addresses.push(address.to_owned());
    }
    Ok(addresses.into_iter().map(Value::String).collect())
}

fn extract_coverage(result: &Value, dossier: &Value) -> Option<Value> {
    result
        .get("relationship_coverage")
        .or_else(|| dossier.get("relationship_coverage"))
        .or_else(|| result.get("coverage"))
        .cloned()
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("procedure_callees result must be an object"))?;
    let callees = object
        .get("callees")
        .ok_or_else(|| invalid("procedure_callees result must include a callees array"))?;
    validate_callee_array(callees)?;
    if object
        .get("evidence_links")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err(invalid(
            "procedure_callees result must include evidence_links",
        ));
    }
    Ok(())
}

fn validate_callee_array(value: &Value) -> Result<(), Failure> {
    let values = value
        .as_array()
        .ok_or_else(|| invalid("callees must be an array"))?;
    if values.len() > MAX_CALLEES {
        return Err(invalid("callee inventory exceeds the supported bound"));
    }
    for value in values {
        let address = value
            .as_str()
            .or_else(|| value.get("address").and_then(Value::as_str))
            .filter(|address| !address.is_empty());
        if address.is_none() {
            return Err(invalid("callee entries must contain an address"));
        }
    }
    Ok(())
}

fn evidence_id(value: &Value) -> Result<&str, Failure> {
    value
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("Evidence must include evidence_id"))
}

fn collect_strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated analyze_function Evidence containing callee observations.".into(),
        std::collections::BTreeMap::from([(
            String::from("operation"),
            Detail::Text(OPERATION.into()),
        )]),
    )
}
