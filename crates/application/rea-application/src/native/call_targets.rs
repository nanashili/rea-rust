//! Static native call-target resolution over authenticated instruction facts.
//!
//! The Ghidra bridge owns instruction decoding and reference discovery.  This
//! boundary only interprets an already retained instruction observation.  A
//! reference is therefore reported as provider evidence and never as proof of
//! runtime control flow.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "resolve_native_call_targets";

const LIMITATION_STATIC: &str = "Targets are static provider call-reference observations; a resolved reference is not proof of runtime execution.";
const LIMITATION_MECHANISMS: &str = "Objective-C, Swift, vtable and closure mechanisms are not identified by this reference-only boundary.";

/// Validate the caller-selected Evidence and optional address selector.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native call-target input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("instruction"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("native instruction Evidence is required"))?;
    validate_evidence(evidence)?;

    if let Some(address) = object.get("address") {
        if address.as_str().is_none() {
            return Err(invalid("address must be a string when supplied"));
        }
    }
    Ok(())
}

/// Retain a provider-derived result after validating its request shape.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("native call-target result must be an object"));
    }
    validate_result_shape(&result)?;
    Ok(result)
}

/// Resolve static call references from one caller-supplied instruction Evidence.
pub fn resolve(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("native call-target input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("instruction"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("native instruction Evidence is required"))?;
    let instruction = instruction_result(evidence)?;
    let call_site = instruction
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("native instruction must include address"))?;
    if let Some(requested) = object.get("address").and_then(Value::as_str)
        && requested != call_site
    {
        return Err(invalid("address does not match the retained instruction"));
    }

    let procedure = instruction.get("procedure").cloned().unwrap_or(Value::Null);
    let decoded = instruction.get("status").and_then(Value::as_str) == Some("decoded");
    let flow = instruction
        .get("flow")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("native instruction must include flow facts"))?;
    let call = flow.get("kind").and_then(Value::as_str) == Some("call");
    let computed = flow
        .get("computed")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let references = instruction
        .get("references")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("native instruction references must be an array"))?;
    let grouped = group_call_references(references.as_slice());
    let ambiguous = grouped.len() > 1;
    let mut targets = Vec::with_capacity(grouped.len());
    for (address, references) in grouped {
        let procedure = procedure_for_target(&references);
        targets.push(json!({
            "address": address,
            "procedure": procedure,
            "status": if ambiguous { "candidate" } else if computed { "resolved-indirect" } else { "direct" },
            "basis": "provider-reference",
            "references": references,
        }));
    }

    let status = if !decoded {
        "unavailable"
    } else if !call {
        "not-call"
    } else if ambiguous {
        "ambiguous"
    } else if targets.is_empty() {
        "unresolved"
    } else if computed {
        "resolved-indirect"
    } else {
        "direct"
    };
    let mechanism = if !call {
        "unavailable"
    } else if computed {
        "computed"
    } else {
        "direct"
    };

    let result = json!({
        "call_site": call_site,
        "procedure": procedure,
        "status": status,
        "mechanism": mechanism,
        "targets": targets,
        "limitations": [LIMITATION_STATIC, LIMITATION_MECHANISMS],
    });
    validate_result_shape(&result)?;
    Ok(result)
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    if !evidence.is_object() {
        return Err(invalid("native instruction Evidence must be an object"));
    }
    if let Some(operation) = evidence.get("operation").and_then(Value::as_str)
        && operation != "inspect_native_instruction"
    {
        return Err(invalid(
            "Evidence operation is not inspect_native_instruction",
        ));
    }
    let _ = evidence_id(evidence)?;
    let _ = instruction_result(evidence)?;
    Ok(())
}

fn instruction_result(evidence: &Value) -> Result<&Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("instruction"))
        .unwrap_or(evidence);
    if !result.is_object() {
        return Err(invalid(
            "native instruction Evidence must contain an object result",
        ));
    }
    Ok(result)
}

fn group_call_references(references: &[Value]) -> BTreeMap<String, Vec<Value>> {
    let mut grouped = BTreeMap::new();
    for reference in references {
        if reference.get("call").and_then(Value::as_bool) != Some(true) {
            continue;
        }
        let Some(address) = reference.get("target_address").and_then(Value::as_str) else {
            continue;
        };
        grouped
            .entry(address.to_owned())
            .or_insert_with(Vec::new)
            .push(reference.clone());
    }
    grouped
}

fn procedure_for_target(references: &[Value]) -> Value {
    references
        .iter()
        .find_map(|reference| reference.get("target_procedure").cloned())
        .unwrap_or(Value::Null)
}

fn validate_result_shape(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("native call-target result must be an object"))?;
    for field in ["call_site", "status", "mechanism", "targets", "limitations"] {
        if !object.contains_key(field) {
            return Err(invalid(&format!("native call-target result lacks {field}")));
        }
    }
    if object.get("call_site").and_then(Value::as_str).is_none()
        || object
            .get("procedure")
            .is_some_and(|value| !value.is_null() && value.as_str().is_none())
    {
        return Err(invalid(
            "native call-target result has invalid procedure identity",
        ));
    }
    if object.get("targets").and_then(Value::as_array).is_none()
        || object
            .get("limitations")
            .and_then(Value::as_array)
            .is_none()
    {
        return Err(invalid("native call-target result has invalid collections"));
    }
    let statuses = [
        "direct",
        "resolved-indirect",
        "ambiguous",
        "unresolved",
        "not-call",
        "unavailable",
    ];
    if !object
        .get("status")
        .and_then(Value::as_str)
        .is_some_and(|status| statuses.contains(&status))
    {
        return Err(invalid("native call-target result has invalid status"));
    }
    let mechanisms = ["direct", "computed", "indirect", "unavailable"];
    if !object
        .get("mechanism")
        .and_then(Value::as_str)
        .is_some_and(|mechanism| mechanisms.contains(&mechanism))
    {
        return Err(invalid("native call-target result has invalid mechanism"));
    }
    let targets = object
        .get("targets")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("native call-target result has invalid targets"))?;
    for target in targets {
        let target = target
            .as_object()
            .ok_or_else(|| invalid("native call target must be an object"))?;
        if target.get("address").and_then(Value::as_str).is_none()
            || target.get("basis").and_then(Value::as_str) != Some("provider-reference")
            || !target
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| {
                    ["direct", "resolved-indirect", "candidate"].contains(&status)
                })
            || target.get("references").and_then(Value::as_array).is_none()
        {
            return Err(invalid("native call target has invalid provenance"));
        }
    }
    Ok(())
}

fn evidence_id(value: &Value) -> Result<&str, Failure> {
    value
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid("native instruction Evidence must include evidence_id"))
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated inspect_native_instruction Evidence and preserve static uncertainty.".into(),
        std::collections::BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}
