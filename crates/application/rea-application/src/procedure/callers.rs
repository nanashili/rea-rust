//! Projection of direct callers from retained native relationship Evidence.
//!
//! Provider adapters own symbol resolution and reference discovery. This
//! module only selects facts already retained in Evidence, so missing or
//! incomplete relationship coverage remains visible to its caller.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "procedure_callers";
const MAX_CALLERS: usize = 100_000;

/// Validate a caller-selected function or relationship Evidence projection.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_callers input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("function"))
        .or_else(|| object.get("xrefs"))
        .ok_or_else(|| invalid("procedure callers Evidence is required"))?;
    validate_evidence(evidence)?;

    if let Some(procedure) = object.get("procedure")
        && procedure
            .as_str()
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(invalid(
            "procedure must be a non-empty string when supplied",
        ));
    }

    Ok(())
}

/// Validate a provider result before the runtime wraps it in Evidence.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_address_result(&result)?;
    Ok(result)
}

/// Project caller addresses and retained relationship facts from Evidence.
pub fn project(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure_callers input must be an object"))?;
    let evidence = caller_evidence(object)?;
    let evidence_id = evidence_id(evidence)?.to_owned();
    let result = evidence_result(evidence)?;
    let dossier = result.get("dossier").unwrap_or(result);
    let procedure = procedure_identity(dossier, object.get("procedure"))?;
    let callers = extract_callers(evidence, result, dossier)?;
    let coverage = extract_coverage(evidence, result, dossier);
    let mut limitations = collect_strings(evidence.get("limitations"));
    limitations.extend(collect_strings(result.get("limitations")));
    if coverage.is_none() {
        limitations.push("Caller completeness was not reported by the source Evidence.".into());
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
    let evidence_links = evidence_links(evidence, result, &evidence_id);
    let output = json!({
        "procedure": procedure,
        "callers": callers,
        "status": status,
        "relationship_coverage": coverage,
        "evidence_links": evidence_links,
        "limitations": limitations,
    });
    validate_projection(&output)?;
    Ok(output)
}

/// Alias for adapters that expose projections as inspection operations.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    project(input)
}

/// Alias for callers that use operation-oriented naming.
pub fn resolve(input: &Value) -> Result<Value, Failure> {
    project(input)
}

fn caller_evidence<'a>(object: &'a serde_json::Map<String, Value>) -> Result<&'a Value, Failure> {
    object
        .get("evidence")
        .or_else(|| object.get("function"))
        .or_else(|| object.get("xrefs"))
        .ok_or_else(|| invalid("procedure callers Evidence is required"))
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("procedure callers Evidence must be an object"))?;
    let operation = object.get("operation").and_then(Value::as_str);
    if !matches!(
        operation,
        Some("analyze_function")
            | Some("procedure_callers")
            | Some("xrefs")
            | Some("procedure_references")
    ) {
        return Err(invalid(
            "Evidence operation is not a caller relationship operation",
        ));
    }
    evidence_id(evidence)?;
    let result = evidence_result(evidence)?;
    if matches!(operation, Some("procedure_callers") | Some("xrefs")) {
        extract_xref_addresses(result)?;
    } else if operation == Some("procedure_references") {
        extract_reference_sources(result)?;
    } else {
        let dossier = result.get("dossier").unwrap_or(result);
        extract_dossier_callers(dossier)?;
    }
    Ok(())
}

fn evidence_id(value: &Value) -> Result<&str, Failure> {
    value
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("caller Evidence must include evidence_id"))
}

fn evidence_result(evidence: &Value) -> Result<&Value, Failure> {
    evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .ok_or_else(|| invalid("caller Evidence must include normalized_result or result"))
}

fn procedure_identity(dossier: &Value, selector: Option<&Value>) -> Result<Value, Failure> {
    if let Some(selector) = selector.and_then(Value::as_str) {
        return Ok(Value::String(selector.to_owned()));
    }
    let procedure = dossier
        .get("procedure")
        .or_else(|| dossier.get("function"))
        .ok_or_else(|| invalid("caller dossier must include procedure identity"))?;
    if let Some(address) = procedure.get("address").and_then(Value::as_str) {
        return Ok(Value::String(address.to_owned()));
    }
    if let Some(name) = procedure.get("name").and_then(Value::as_str) {
        return Ok(Value::String(name.to_owned()));
    }
    Err(invalid("procedure identity must include address or name"))
}

fn extract_callers(
    evidence: &Value,
    result: &Value,
    dossier: &Value,
) -> Result<Vec<Value>, Failure> {
    let operation = evidence.get("operation").and_then(Value::as_str);
    let addresses = match operation {
        Some("procedure_callers") | Some("xrefs") => extract_xref_addresses(result)?,
        Some("procedure_references") => extract_reference_sources(result)?,
        _ => extract_dossier_callers(dossier)?,
    };
    Ok(addresses.into_iter().map(Value::String).collect())
}

fn extract_dossier_callers(dossier: &Value) -> Result<Vec<String>, Failure> {
    let callers = dossier
        .get("callers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("caller dossier lacks callers"))?;
    let mut addresses = Vec::with_capacity(callers.len());
    for caller in callers {
        let address = caller
            .as_str()
            .or_else(|| caller.get("address").and_then(Value::as_str))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("caller identity lacks an address"))?;
        addresses.push(address.to_owned());
    }
    check_bound(addresses.len())?;
    Ok(addresses)
}

fn extract_xref_addresses(result: &Value) -> Result<Vec<String>, Failure> {
    let values = result
        .as_array()
        .or_else(|| result.get("xrefs").and_then(Value::as_array))
        .ok_or_else(|| invalid("xref Evidence lacks an xref array"))?;
    let mut addresses = Vec::with_capacity(values.len());
    for value in values {
        let address = value
            .as_str()
            .or_else(|| value.get("source_address").and_then(Value::as_str))
            .or_else(|| value.get("source").and_then(Value::as_str))
            .or_else(|| value.get("address").and_then(Value::as_str))
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("xref row lacks a source address"))?;
        addresses.push(address.to_owned());
    }
    check_bound(addresses.len())?;
    Ok(addresses)
}

fn extract_reference_sources(result: &Value) -> Result<Vec<String>, Failure> {
    let references = result
        .get("references")
        .and_then(Value::as_array)
        .or_else(|| result.as_array())
        .ok_or_else(|| invalid("procedure reference Evidence lacks references"))?;
    let mut addresses = Vec::with_capacity(references.len());
    for reference in references {
        let address = reference
            .get("source_address")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("procedure reference lacks a source address"))?;
        addresses.push(address.to_owned());
    }
    check_bound(addresses.len())?;
    Ok(addresses)
}

fn extract_coverage(evidence: &Value, result: &Value, dossier: &Value) -> Option<Value> {
    evidence
        .get("relationship_coverage")
        .or_else(|| result.get("relationship_coverage"))
        .or_else(|| dossier.get("relationship_coverage"))
        .or_else(|| result.get("coverage"))
        .cloned()
}

fn validate_address_result(result: &Value) -> Result<(), Failure> {
    if result.is_array() {
        extract_xref_addresses(result).map(|_| ())
    } else {
        let addresses = result
            .get("callers")
            .ok_or_else(|| invalid("procedure callers result must include callers"))?;
        extract_xref_addresses(addresses).map(|_| ())
    }
}

fn validate_projection(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("procedure callers projection must be an object"))?;
    extract_xref_addresses(
        object
            .get("callers")
            .ok_or_else(|| invalid("procedure callers projection lacks callers"))?,
    )?;
    if object
        .get("evidence_links")
        .and_then(Value::as_array)
        .is_none()
    {
        return Err(invalid("procedure callers projection lacks evidence_links"));
    }
    Ok(())
}

fn check_bound(count: usize) -> Result<(), Failure> {
    if count > MAX_CALLERS {
        return Err(invalid("caller inventory exceeds the supported bound"));
    }
    Ok(())
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

fn evidence_links(evidence: &Value, result: &Value, primary: &str) -> Vec<Value> {
    let mut links = BTreeSet::from([primary.to_owned()]);
    for source in [evidence.get("evidence_links"), result.get("evidence_links")]
        .into_iter()
        .flatten()
        .flat_map(|value| value.as_array().into_iter().flatten())
        .filter_map(Value::as_str)
    {
        links.insert(source.to_owned());
    }
    links.into_iter().map(Value::String).collect()
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated function or relationship Evidence and preserve caller coverage."
            .into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
