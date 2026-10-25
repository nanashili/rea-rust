//! Read-only projection of one provider procedure-information observation.
//!
//! The analysis provider owns function discovery and body recovery.  This
//! boundary validates and selects an already retained observation; it never
//! attaches to a database or infers facts from executable bytes.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "procedure_info";
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Validate a caller-selected procedure-info Evidence record.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure-info input must be an object"))?;
    reject_unknown_fields(
        object,
        &[
            "evidence",
            "procedure_info",
            "native_observation",
            "procedure",
        ],
        "procedure-info input",
    )?;

    let evidence = object
        .get("evidence")
        .or_else(|| object.get("procedure_info"))
        .or_else(|| object.get("native_observation"))
        .unwrap_or(input);
    validate_evidence(evidence)?;

    if let Some(selector) = object.get("procedure") {
        if !selector.is_string() && !selector.is_object() {
            return Err(invalid("procedure selector must be a string or object"));
        }
    }
    Ok(())
}

/// Validate and retain a provider result returned for the selected procedure.
pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    validate_result(&result)?;
    Ok(result)
}

/// Return the validated procedure information from caller-supplied Evidence.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input
        .as_object()
        .ok_or_else(|| invalid("procedure-info input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("procedure_info"))
        .or_else(|| object.get("native_observation"))
        .unwrap_or(input);
    let result = result_value(evidence)?.clone();
    if let Some(selector) = object.get("procedure") {
        validate_selector(&result, selector)?;
    }
    Ok(result)
}

fn validate_evidence(evidence: &Value) -> Result<(), Failure> {
    let object = evidence
        .as_object()
        .ok_or_else(|| invalid("procedure-info Evidence must be an object"))?;
    if let Some(operation) = object.get("operation") {
        if operation.as_str() != Some(OPERATION) {
            return Err(invalid("Evidence operation is not procedure_info"));
        }
    }
    if object
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        return Err(invalid("procedure-info Evidence must include evidence_id"));
    }
    validate_result(result_value(evidence)?)
}

fn result_value(evidence: &Value) -> Result<&Value, Failure> {
    let result = evidence
        .get("normalized_result")
        .or_else(|| evidence.get("result"))
        .or_else(|| evidence.get("value"))
        .unwrap_or(evidence);
    if !result.is_object() {
        return Err(invalid("procedure-info result must be an object"));
    }
    Ok(result)
}

fn validate_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("procedure-info result must be an object"))?;
    const RESULT_FIELDS: &[&str] = &[
        "name",
        "entrypoint",
        "basicblock_count",
        "length",
        "signature",
        "locals",
        "classification",
        "body",
    ];
    if object
        .keys()
        .any(|key| !RESULT_FIELDS.contains(&key.as_str()))
    {
        return Err(invalid("procedure-info result contains unknown fields"));
    }
    for key in RESULT_FIELDS {
        if !object.contains_key(*key) {
            return Err(invalid(&format!("procedure-info result lacks {key}")));
        }
    }
    if object
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || object
            .get("entrypoint")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        || object
            .get("basicblock_count")
            .and_then(Value::as_u64)
            .is_none_or(|count| count > MAX_SAFE_INTEGER)
        || object
            .get("length")
            .and_then(Value::as_u64)
            .is_none_or(|length| length > MAX_SAFE_INTEGER)
        || object
            .get("entrypoint")
            .and_then(Value::as_str)
            .and_then(parse_canonical_address)
            .is_none()
        || !nullable_string(object.get("signature"))
    {
        return Err(invalid("procedure-info identity or counts are invalid"));
    }
    match object.get("locals") {
        Some(Value::Null) => {}
        Some(Value::Array(locals)) => {
            if locals.len() > 200_000 {
                return Err(invalid("procedure-info locals exceed the resource limit"));
            }

            for local in locals {
                validate_local(local)?;
            }
        }
        _ => return Err(invalid("procedure-info locals must be an array or null")),
    }
    let external = validate_classification(object.get("classification"))?;
    validate_body(
        object.get("body"),
        object
            .get("entrypoint")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("procedure-info entrypoint is required"))?,
        object.get("length").and_then(Value::as_u64).unwrap_or(0),
        external,
    )
}

fn validate_local(local: &Value) -> Result<(), Failure> {
    let object = local
        .as_object()
        .ok_or_else(|| invalid("procedure-info local must be an object"))?;
    const LOCAL_FIELDS: &[&str] = &["description", "provenance", "name", "stack_displacement"];
    if object
        .keys()
        .any(|key| !LOCAL_FIELDS.contains(&key.as_str()))
        || object.get("description").and_then(Value::as_str).is_none()
        || object.get("provenance").and_then(Value::as_str) != Some("ghidra-function-database")
        || (object.contains_key("name") && !nullable_string(object.get("name")))
        || (object.contains_key("stack_displacement")
            && !object.get("stack_displacement").is_some_and(|v| {
                v.is_null()
                    || v.as_str()
                        .is_some_and(|s| !s.is_empty() && s.parse::<i128>().is_ok())
            }))
    {
        return Err(invalid("procedure-info local has invalid fields"));
    }
    Ok(())
}

fn validate_classification(value: Option<&Value>) -> Result<Option<bool>, Failure> {
    let Some(value) = value else {
        return Err(invalid("procedure-info classification is required"));
    };
    if value.is_null() {
        return Err(invalid("procedure-info classification must be an object"));
    }
    let object = value
        .as_object()
        .ok_or_else(|| invalid("procedure-info classification must be an object"))?;
    const CLASSIFICATION_FIELDS: &[&str] = &["external", "thunk", "thunk_target", "provenance"];
    if object
        .keys()
        .any(|key| !CLASSIFICATION_FIELDS.contains(&key.as_str()))
        || !object
            .get("external")
            .is_some_and(|value| value.is_null() || value.is_boolean())
        || !object
            .get("thunk")
            .is_some_and(|value| value.is_null() || value.is_boolean())
        || !object.get("thunk_target").is_some_and(|target| {
            target.is_null() || target.as_str().and_then(parse_canonical_address).is_some()
        })
        || !matches!(
            object.get("provenance").and_then(Value::as_str),
            Some("ghidra-function-manager") | Some("ghidra-rust-sleigh-cfg")
        )
    {
        return Err(invalid("procedure-info classification has invalid fields"));
    }
    Ok(object.get("external").and_then(Value::as_bool))
}

fn validate_body(
    value: Option<&Value>,
    entrypoint: &str,
    length: u64,
    external: Option<bool>,
) -> Result<(), Failure> {
    let object = value
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("procedure-info body must be an object"))?;
    let available = object
        .get("available")
        .and_then(Value::as_bool)
        .ok_or_else(|| invalid("procedure-info body.available must be boolean"))?;
    if !available {
        return Err(invalid(
            "procedure-info requires complete available body evidence",
        ));
    }
    const AVAILABLE_BODY_FIELDS: &[&str] = &[
        "available",
        "provenance",
        "ranges",
        "total_bytes",
        "span_bytes",
        "non_contiguous",
        "contains_entry",
    ];
    if object
        .keys()
        .any(|key| !AVAILABLE_BODY_FIELDS.contains(&key.as_str()))
    {
        return Err(invalid(
            "available procedure-info body contains unknown fields",
        ));
    }
    let ranges = object
        .get("ranges")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("available procedure-info body needs ranges"))?;
    let total = object
        .get("total_bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| invalid("procedure-info body.total_bytes must be nonnegative"))?;
    if total != length
        || !object
            .get("span_bytes")
            .is_some_and(|v| v.is_null() || v.as_u64().is_some())
        || !object.get("non_contiguous").is_some_and(Value::is_boolean)
        || !object.get("contains_entry").is_some_and(Value::is_boolean)
        || !matches!(
            object.get("provenance").and_then(Value::as_str),
            Some("ghidra-function-body-address-set") | Some("ghidra-rust-sleigh-cfg")
        )
    {
        return Err(invalid(
            "procedure-info body counts or metadata are invalid",
        ));
    }
    let mut total_from_ranges = 0_u128;
    let mut previous_space: Option<Option<&str>> = None;
    let mut previous_end = 0_u128;
    let mut first_start = 0_u128;
    let mut single_space = true;
    let mut closed_spaces: Vec<Option<&str>> = Vec::new();
    let mut entry_is_contained = false;

    for range in ranges {
        let range = range
            .as_object()
            .ok_or_else(|| invalid("procedure-info body range must be an object"))?;
        if range
            .keys()
            .any(|key| !["start", "end"].contains(&key.as_str()))
        {
            return Err(invalid("procedure-info body range endpoints are invalid"));
        }
        let start = range
            .get("start")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("procedure-info body range start is required"))?;
        let end = range
            .get("end")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("procedure-info body range end is required"))?;
        let (start_space, start_offset) = parse_canonical_address(start)
            .ok_or_else(|| invalid("procedure-info body range start is not canonical"))?;
        let (end_space, end_offset) = parse_canonical_address(end)
            .ok_or_else(|| invalid("procedure-info body range end is not canonical"))?;
        if start_space != end_space || end_offset < start_offset {
            return Err(invalid("procedure-info body range endpoints are invalid"));
        }
        if let Some(previous_space) = previous_space {
            if previous_space != start_space {
                if closed_spaces.contains(&start_space) {
                    return Err(invalid(
                        "procedure-info body ranges must keep address spaces ordered",
                    ));
                }
                closed_spaces.push(previous_space);
                single_space = false;
            }
            if previous_space == start_space && start_offset <= previous_end.saturating_add(1) {
                return Err(invalid(
                    "procedure-info body ranges must be ordered and disjoint",
                ));
            }
        } else {
            first_start = start_offset;
        }
        previous_space = Some(start_space);
        previous_end = end_offset;
        total_from_ranges = total_from_ranges
            .checked_add(end_offset - start_offset + 1)
            .ok_or_else(|| invalid("procedure-info body range size overflows"))?;
        if let Some((entry_space, entry_offset)) = parse_canonical_address(entrypoint) {
            entry_is_contained |= entry_space == start_space
                && entry_offset >= start_offset
                && entry_offset <= end_offset;
        }
    }
    let expected_span = if ranges.is_empty() {
        Some(0)
    } else if single_space {
        Some(u64::try_from(previous_end - first_start + 1).unwrap_or(u64::MAX))
    } else {
        None
    };
    let reported_span = object.get("span_bytes").and_then(|value| {
        if value.is_null() {
            Some(None)
        } else {
            value.as_u64().map(Some)
        }
    });
    if total_from_ranges != u128::from(total)
        || (ranges.len() > 1
            && !object
                .get("non_contiguous")
                .and_then(Value::as_bool)
                .unwrap_or(false))
        || (ranges.len() <= 1
            && object.get("non_contiguous").and_then(Value::as_bool) != Some(false))
        || reported_span != Some(expected_span)
        || object.get("contains_entry").and_then(Value::as_bool) != Some(entry_is_contained)
        || (external != Some(true) && !entry_is_contained)
    {
        return Err(invalid(
            "procedure-info body counts or entry membership disagree with ranges",
        ));
    }
    Ok(())
}

fn parse_canonical_address(value: &str) -> Option<(Option<&str>, u128)> {
    let (space, digits) = if let Some((space, offset)) = value.rsplit_once(':') {
        (Some(space), offset.strip_prefix("0x")?)
    } else {
        (None, value.strip_prefix("0x")?)
    };
    if let Some(space) = space {
        if !valid_address_space(space) {
            return None;
        }
    }
    // Provider output uses the canonical Ghidra spelling: a lowercase `0x`
    // prefix followed by lowercase hexadecimal digits.  Accepting uppercase
    // digits here would make retained Rust output broader than the TypeScript
    // canonical-address schema and would break exact selector identity.
    if digits.is_empty()
        || !digits
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character))
    {
        return None;
    }
    Some((space, u128::from_str_radix(digits, 16).ok()?))
}

fn valid_address_space(value: &str) -> bool {
    let mut characters = value.chars();
    while let Some(character) = characters.next() {
        if character.is_ascii_alphanumeric() || "._-~".contains(character) {
            continue;
        }
        if character != '%' {
            return false;
        }
        let Some(first) = characters.next() else {
            return false;
        };
        let Some(second) = characters.next() else {
            return false;
        };
        if !first.is_ascii_hexdigit()
            || !second.is_ascii_hexdigit()
            || (first.is_ascii_alphabetic() && !first.is_ascii_uppercase())
            || (second.is_ascii_alphabetic() && !second.is_ascii_uppercase())
        {
            return false;
        }
    }
    !value.is_empty()
}

fn validate_selector(result: &Value, selector: &Value) -> Result<(), Failure> {
    let object = selector.as_object();
    let matches = selector.as_str().is_some_and(|value| {
        result.get("name").and_then(Value::as_str) == Some(value)
            || result.get("entrypoint").and_then(Value::as_str) == Some(value)
    }) || object.is_some_and(|object| {
        object
            .keys()
            .all(|key| ["name", "address"].contains(&key.as_str()))
            && object
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(|name| !name.is_empty())
            && object
                .get("address")
                .and_then(Value::as_str)
                .is_some_and(|address| !address.is_empty())
            && object.get("name").and_then(Value::as_str)
                == result.get("name").and_then(Value::as_str)
            && object.get("address").and_then(Value::as_str)
                == result.get("entrypoint").and_then(Value::as_str)
    });
    if !matches {
        return Err(invalid(
            "retained procedure-info does not match procedure selector",
        ));
    }
    Ok(())
}

fn nullable_string(value: Option<&Value>) -> bool {
    value.is_some_and(|value| value.is_null() || value.as_str().is_some())
}

fn reject_unknown_fields(
    object: &serde_json::Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), Failure> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(invalid(&format!("{context} contains unknown fields")));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide authenticated procedure_info Evidence with complete body and classification facts.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::retain_result;
    use serde_json::json;

    #[test]
    fn accepts_rust_cfg_body_with_unknown_classification() {
        let input = json!({
            "evidence": {
            "evidence_id": "evidence-1",
            "operation": "procedure_info",
            "result": {
                "name": "main",
                "entrypoint": "0x1000",
                "basicblock_count": 1,
                "length": 4,
                "signature": null,
                "locals": null,
                "classification": {
                    "external": null,
                    "thunk": null,
                    "thunk_target": null,
                    "provenance": "ghidra-rust-sleigh-cfg"
                },
                "body": {
                    "available": true,
                    "provenance": "ghidra-rust-sleigh-cfg",
                    "ranges": [{"start": "0x1000", "end": "0x1003"}],
                    "total_bytes": 4,
                    "span_bytes": 4,
                    "non_contiguous": false,
                    "contains_entry": true
                }
            }
            }
        });
        assert!(retain_result(&input, input["evidence"]["result"].clone()).is_ok());
    }

    #[test]
    fn accepts_legacy_body_provenance() {
        let input = json!({
            "evidence": {
            "evidence_id": "evidence-1",
            "operation": "procedure_info",
            "result": {
                "name": "main",
                "entrypoint": "0x1000",
                "basicblock_count": 1,
                "length": 4,
                "signature": null,
                "locals": null,
                "classification": {
                    "external": false,
                    "thunk": false,
                    "thunk_target": null,
                    "provenance": "ghidra-function-manager"
                },
                "body": {
                    "available": true,
                    "provenance": "ghidra-function-body-address-set",
                    "ranges": [{"start": "0x1000", "end": "0x1003"}],
                    "total_bytes": 4,
                    "span_bytes": 4,
                    "non_contiguous": false,
                    "contains_entry": true
                }
            }
            }
        });

        assert!(retain_result(&input, input["evidence"]["result"].clone()).is_ok());
    }

    #[test]
    fn rejects_malformed_locals() {
        let input = json!({
            "evidence": {
            "evidence_id": "evidence-1",
            "operation": "procedure_info",
            "result": {
                "name": "main",
                "entrypoint": "0x1000",
                "basicblock_count": 1,
                "length": 4,
                "signature": null,
                "locals": "unknown",
                "classification": {
                    "external": null,
                    "thunk": null,
                    "thunk_target": null,
                    "provenance": "ghidra-rust-sleigh-cfg"
                },
                "body": {
                    "available": true,
                    "provenance": "ghidra-rust-sleigh-cfg",
                    "ranges": [{"start": "0x1000", "end": "0x1003"}],
                    "total_bytes": 4,
                    "span_bytes": 4,
                    "non_contiguous": false,
                    "contains_entry": true
                }
            }
            }
        });

        let error = retain_result(&input, input["evidence"]["result"].clone())
            .expect_err("malformed locals must be rejected");
        assert!(
            error
                .to_string()
                .contains("locals must be an array or null")
        );
    }
}
