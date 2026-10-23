//! Captured-only projection of one retained Android DEX method.
//!
//! The APK parser remains the owner of byte interpretation. This adapter only
//! selects facts already present in a retained package report and never reads
//! an APK or executes DEX code.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_android_method";

pub fn inspect(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("input must be an object"))?;
    reject_unknown(object)?;

    let report = resolve_report(object)?;
    let class_name = required_string(object, "class_name")?;
    let method_name = required_string(object, "method_name")?;
    let overload_index = optional_index(object)?;

    let dex = report
        .get("dex")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("retained package report must contain dex facts"))?;
    let mut matches = Vec::new();
    for facts in dex {
        let Some(classes) = facts.get("class_definitions").and_then(Value::as_array) else {
            continue;
        };
        for class in classes {
            let Some(descriptor) = class.get("descriptor").and_then(Value::as_str) else {
                continue;
            };
            if same_class(descriptor, class_name) {
                matches.push((facts, descriptor));
            }
        }
    }
    let (facts, descriptor) = match matches.as_slice() {
        [] => return Err(selection_failure(format!("Class {class_name} was not found."))),
        [single] => *single,
        _ => {
            return Err(selection_failure(format!(
                "Class {class_name} occurs in multiple DEX files."
            )))
        }
    };

    let methods = facts
        .get("methods")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("retained DEX facts must contain methods"))?;
    let candidates = methods
        .iter()
        .enumerate()
        .filter(|(_, method)| {
            method.get("class_descriptor").and_then(Value::as_str) == Some(descriptor)
                && method.get("name").and_then(Value::as_str) == Some(method_name)
        })
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err(selection_failure(format!(
            "Method {class_name}.{method_name} was not found."
        )));
    }
    if overload_index.is_none() && candidates.len() > 1 {
        return Err(selection_failure(format!(
            "Select one of {} matching method overloads.",
            candidates.len()
        )));
    }
    let selected_index = overload_index.unwrap_or(0);
    let Some((method_index, method)) = candidates.get(selected_index) else {
        return Err(selection_failure(format!(
            "Index {selected_index} is outside the {} matching overloads.",
            candidates.len()
        )));
    };

    let code = facts
        .get("code")
        .and_then(Value::as_array)
        .and_then(|code| {
            code.iter().find(|item| {
                item.get("method_index").and_then(Value::as_u64) == Some(*method_index as u64)
            })
        })
        .cloned();
    let code_item_offset = code
        .as_ref()
        .and_then(|item| item.get("code_offset"))
        .cloned()
        .unwrap_or(Value::Null);
    let annotations = facts
        .get("annotations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter(|item| item.get("owner").and_then(Value::as_str) == Some(descriptor))
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let call_sites = facts
        .get("call_sites")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let partial = facts.get("truncated").and_then(Value::as_bool).unwrap_or(false);
    let dex_entry = facts
        .get("entry")
        .cloned()
        .unwrap_or_else(|| Value::String(String::new()));
    let unknowns = if partial {
        vec![format!(
            "DEX {} method facts are truncated.",
            dex_entry.as_str().unwrap_or_default()
        )]
    } else {
        Vec::new()
    };
    let method = method_projection(method, selected_index);

    Ok(serde_json::json!({
        "class_name": class_name,
        "dex_entry": dex_entry,
        "dex_method_index": method_index,
        "method": method,
        "overload_index": selected_index,
        "overload_count": candidates.len(),
        "code": code,
        "annotations": annotations,
        "call_sites": call_sites,
        "code_item_offset": code_item_offset,
        "coverage": if partial { "partial" } else { "complete" },
        "unknowns": unknowns,
    }))
}

fn method_projection(method: &Value, overload_index: usize) -> Value {
    serde_json::json!({
        "name": method.get("name").cloned().unwrap_or(Value::Null),
        "reported_signature": method
            .get("descriptor")
            .cloned()
            .unwrap_or(Value::Null),
        "overload_index": overload_index,
        "is_constructor": method.get("name").and_then(Value::as_str) == Some("<init>"),
        "dex_descriptor": method
            .get("descriptor")
            .cloned()
            .unwrap_or(Value::Null),
    })
}

fn resolve_report<'a>(object: &'a Map<String, Value>) -> Result<&'a Value, Failure> {
    let source = object
        .get("report")
        .or_else(|| object.get("evidence"))
        .ok_or_else(|| invalid("retained Android package report is required"))?;
    let report = source
        .get("normalized_result")
        .or_else(|| source.get("result"))
        .unwrap_or(source);
    if report.is_object() {
        Ok(report)
    } else {
        Err(invalid("retained Android package report must be an object"))
    }
}

fn required_string<'a>(object: &'a Map<String, Value>, field: &str) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be a non-empty string")))
}

fn optional_index(object: &Map<String, Value>) -> Result<Option<usize>, Failure> {
    match object.get("overload_index") {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|index| usize::try_from(index).ok())
            .map(Some)
            .ok_or_else(|| invalid("overload_index must be a non-negative integer")),
    }
}

fn same_class(descriptor: &str, requested: &str) -> bool {
    descriptor == requested
        || descriptor
            .strip_prefix('L')
            .and_then(|value| value.strip_suffix(';'))
            .unwrap_or(descriptor)
            .replace('/', ".")
            == requested
}

fn reject_unknown(object: &Map<String, Value>) -> Result<(), Failure> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "report" | "evidence" | "class_name" | "method_name" | "overload_index"
        )
    }) {
        return Err(invalid("input contains an unknown field"));
    }
    Ok(())
}

fn selection_failure(message: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message,
        true,
        "Select one exact retained Android class and method overload and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("field", Detail::Text("method".into())),
        ]),
    )
}

fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Provide a bounded retained Android package report and method selector.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
