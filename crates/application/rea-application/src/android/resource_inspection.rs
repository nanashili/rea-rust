//! Projection of one Android resource from retained package Evidence.
//!
//! Package parsing and qualifier decoding remain owned by the Android package
//! provider. This boundary only validates a selector and filters retained
//! resource facts; it never opens an APK or contacts a device.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_android_resource";
const MAX_MATCHES: usize = 200_000;
const MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

const SELECTOR_FIELDS: &[&str] = &[
    "resource_id",
    "package_id",
    "type_id",
    "entry_index",
    "name",
    "locale",
    "region",
    "density",
    "sdk",
    "orientation",
];

/// Validate a retained-report selector. The report itself is checked when it
/// is resolved so callers can pass either direct reports or Evidence.
pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("Android resource inspection input must be an object"))?;
    for key in object.keys() {
        if !SELECTOR_FIELDS.contains(&key.as_str())
            && !matches!(key.as_str(), "evidence" | "report")
        {
            return Err(invalid(
                "Android resource inspection input contains an unknown field",
            ));
        }
    }
    validate_selector(object)?;
    let _ = resolve_report(object)?;
    Ok(())
}

/// Project a caller-selected resource from an already retained package report.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;
    let object = input.as_object().expect("validated input object");
    let report = resolve_report(object)?;
    let source = object.get("report").or_else(|| object.get("evidence"));
    let selector = selector_view(object);
    let matches = retained_matches(report)?;
    let selected = matches
        .into_iter()
        .filter(|candidate| matches_candidate(candidate, &selector, report))
        .map(|candidate| project_candidate(candidate, report))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        return Err(invalid(
            "No retained Android resource matched the exact selector",
        ));
    }
    if selector.get("name").is_some() && selected.len() > 1 {
        return Err(invalid(
            "The symbolic resource name is ambiguous across retained resource packages or configurations",
        ));
    }
    if selected.len() > MAX_MATCHES {
        return Err(invalid(
            "retained Android resource matches exceed the bounded result limit",
        ));
    }
    let coverage = coverage_for(report, &selected);
    let result = json!({
        "selector": selector,
        "matches": selected,
        "coverage": coverage,
        "provenance": provenance_for(source, report),
        "limitations": limitations_for(source, report),
        "unknowns": [
            "Only retained package facts are examined; omitted configurations remain unknown.",
            "Resource runtime resolution and device-specific overlays are unavailable."
        ],
        "unsupported": [
            "runtime_resource_resolution",
            "device_specific_overlay_resolution"
        ]
    });
    admitted_output(&result)?;
    Ok(result)
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    admitted_output(&result)?;
    if !result.is_object() {
        return Err(invalid(
            "Android resource inspection result must be an object",
        ));
    }
    Ok(result)
}

fn validate_selector(object: &Map<String, Value>) -> Result<(), Failure> {
    for field in ["resource_id", "name", "locale", "region"] {
        if let Some(value) = object.get(field) {
            if value.as_str().is_none_or(str::is_empty) {
                return Err(invalid(&format!("{field} must be a non-empty string")));
            }
        }
    }
    for field in ["package_id", "type_id", "entry_index"] {
        if let Some(value) = object.get(field) {
            if value
                .as_u64()
                .is_none_or(|number| number > u64::from(u32::MAX))
            {
                return Err(invalid(&format!("{field} must be a non-negative integer")));
            }
        }
    }
    validate_bounded_integer(object, "density", u64::from(u16::MAX))?;
    validate_bounded_integer(object, "sdk", u64::from(u16::MAX))?;
    validate_bounded_integer(object, "orientation", u64::from(u8::MAX))?;
    if object.get("resource_id").is_none()
        && object.get("name").is_none()
        && object.get("package_id").is_none()
        && object.get("type_id").is_none()
        && object.get("entry_index").is_none()
    {
        return Err(invalid("a resource identity selector is required"));
    }
    Ok(())
}

fn resolve_report<'a>(object: &'a Map<String, Value>) -> Result<&'a Value, Failure> {
    let source = object
        .get("report")
        .or_else(|| object.get("evidence"))
        .ok_or_else(|| {
            invalid("Android resource inspection requires retained package report Evidence")
        })?;
    let report = source
        .get("normalized_result")
        .or_else(|| source.get("result"))
        .unwrap_or(source);
    if !report.is_object() {
        return Err(invalid("retained Android package report must be an object"));
    }
    if report.get("matches").is_none()
        && report.get("resource_entries").is_none()
        && report.get("resources").is_none()
    {
        return Err(invalid(
            "retained Android package report has no resource facts",
        ));
    }
    Ok(report)
}

fn retained_matches<'a>(report: &'a Value) -> Result<Vec<&'a Value>, Failure> {
    let values = report
        .get("matches")
        .or_else(|| report.get("resources"))
        .or_else(|| report.get("resource_entries"))
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("retained resource facts must be an array"))?;
    if values.len() > MAX_MATCHES {
        return Err(invalid(
            "retained resource facts exceed the bounded result limit",
        ));
    }
    Ok(values.iter().collect())
}

fn validate_bounded_integer(
    object: &Map<String, Value>,
    field: &str,
    maximum: u64,
) -> Result<(), Failure> {
    if let Some(value) = object.get(field) {
        if value.as_u64().is_none_or(|number| number > maximum) {
            return Err(invalid(&format!(
                "{field} must be an integer between 0 and {maximum}"
            )));
        }
    }
    Ok(())
}

fn selector_view(object: &Map<String, Value>) -> Map<String, Value> {
    SELECTOR_FIELDS
        .iter()
        .filter_map(|field| {
            object
                .get(*field)
                .map(|value| ((*field).to_owned(), value.clone()))
        })
        .collect()
}

fn matches_candidate(candidate: &Value, selector: &Map<String, Value>, report: &Value) -> bool {
    let entry = candidate.get("entry").unwrap_or(candidate);
    if let Some(expected) = selector.get("resource_id").and_then(Value::as_str) {
        let Some(actual) = entry.get("resource_id").and_then(Value::as_str) else {
            return false;
        };
        if !resource_ids_match(actual, expected) {
            return false;
        }
    }
    if let Some(expected) = selector.get("name").and_then(Value::as_str) {
        let normalized = expected.strip_prefix('@').unwrap_or(expected);
        let name_matches = ["key_name", "qualified_name"]
            .iter()
            .filter_map(|field| entry.get(*field).and_then(Value::as_str))
            .any(|actual| actual == expected || actual == normalized);
        if !name_matches {
            return false;
        }
    }
    if let Some(resource_id) = entry.get("resource_id").and_then(Value::as_str) {
        if let Some((package, kind, index)) = parse_resource_id(resource_id) {
            if !numeric_selector(selector, "package_id", package)
                || !numeric_selector(selector, "type_id", kind)
                || !numeric_selector(selector, "entry_index", index)
            {
                return false;
            }
        } else if ["package_id", "type_id", "entry_index"]
            .iter()
            .any(|field| selector.contains_key(*field))
        {
            return false;
        }
    }
    let configuration_matches = |configuration: &Value| {
        [
            ("locale", "locale"),
            ("region", "region"),
            ("density", "density"),
            ("sdk", "sdk"),
            ("orientation", "orientation"),
        ]
        .iter()
        .all(|(field, source_field)| {
            selector.get(*field).map_or(true, |expected| {
                configuration.get(*source_field) == Some(expected)
            })
        })
    };
    let entry_configuration_matches = entry
        .get("configuration")
        .or_else(|| entry.get("configuration_facts"))
        .is_some_and(|configuration| configuration_matches(configuration));
    if selector.keys().any(|key| {
        matches!(
            key.as_str(),
            "locale" | "region" | "density" | "sdk" | "orientation"
        )
    }) {
        let variant_configuration_matches =
            variants_for(candidate, report).into_iter().any(|variant| {
                variant
                    .get("configuration_facts")
                    .or_else(|| variant.get("configuration"))
                    .is_some_and(|configuration| configuration_matches(configuration))
            });
        entry_configuration_matches || variant_configuration_matches
    } else {
        true
    }
}

fn variants_for<'a>(candidate: &'a Value, report: &'a Value) -> Vec<&'a Value> {
    if let Some(variants) = candidate.get("variants").and_then(Value::as_array) {
        return variants.iter().collect();
    }
    let Some(resource_id) = candidate
        .get("entry")
        .unwrap_or(candidate)
        .get("resource_id")
        .and_then(Value::as_str)
    else {
        return Vec::new();
    };
    report
        .get("resource_variants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|variant| variant.get("resource_id").and_then(Value::as_str) == Some(resource_id))
        .collect()
}

fn project_candidate(candidate: &Value, report: &Value) -> Value {
    if candidate.get("variants").is_some() {
        return candidate.clone();
    }
    let variants = variants_for(candidate, report);
    if variants.is_empty() {
        return candidate.clone();
    }
    let Some(object) = candidate.as_object() else {
        return candidate.clone();
    };
    let mut projected = object.clone();
    projected.insert(
        "variants".to_owned(),
        Value::Array(variants.into_iter().cloned().collect()),
    );
    Value::Object(projected)
}

fn numeric_selector(selector: &Map<String, Value>, field: &str, actual: u32) -> bool {
    selector.get(field).map_or(true, |expected| {
        expected.as_u64() == Some(u64::from(actual))
    })
}

fn parse_resource_id(value: &str) -> Option<(u32, u32, u32)> {
    let value = value.strip_prefix('@').unwrap_or(value);
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))?;
    if value.len() != 8 {
        return None;
    }
    let number = u32::from_str_radix(value, 16).ok()?;
    Some((number >> 24, (number >> 16) & 0xff, number & 0xffff))
}

fn resource_ids_match(actual: &str, expected: &str) -> bool {
    actual == expected
        || parse_resource_id(actual).is_some()
            && parse_resource_id(actual) == parse_resource_id(expected)
}

fn coverage_for(report: &Value, matches: &[Value]) -> &'static str {
    if report.get("coverage").and_then(Value::as_str) == Some("partial")
        || matches.iter().any(resource_has_partial_coverage)
    {
        "partial"
    } else {
        "complete"
    }
}

fn resource_has_partial_coverage(resource: &Value) -> bool {
    let entry = resource.get("entry").unwrap_or(resource);
    entry_has_partial_coverage(entry)
        || resource
            .get("variants")
            .and_then(Value::as_array)
            .is_some_and(|variants| variants.iter().any(variant_has_partial_coverage))
}

fn entry_has_partial_coverage(entry: &Value) -> bool {
    entry.get("issue").is_some_and(is_present)
        || entry.get("mapping_issue").is_some_and(is_present)
        || entry
            .get("complex_values")
            .and_then(Value::as_array)
            .is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.get("issue").is_some_and(is_present))
            })
}

fn variant_has_partial_coverage(variant: &Value) -> bool {
    variant.get("value_issue").is_some_and(is_present)
        || variant.get("mapping_issue").is_some_and(is_present)
}

fn is_present(value: &Value) -> bool {
    !value.is_null()
}

fn provenance_for(source: Option<&Value>, report: &Value) -> Value {
    let source = source.and_then(Value::as_object);
    let report = report.as_object();
    let mut provenance = Map::new();
    for field in [
        "evidence_id",
        "operation",
        "subject",
        "provider",
        "locations",
        "source",
    ] {
        if let Some(value) = source
            .and_then(|object| object.get(field))
            .or_else(|| report.and_then(|object| object.get(field)))
        {
            provenance.insert(field.to_owned(), value.clone());
        }
    }
    Value::Object(provenance)
}

fn limitations_for(source: Option<&Value>, report: &Value) -> Value {
    source
        .and_then(|value| value.get("limitations"))
        .or_else(|| report.get("limitations"))
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()))
}

fn admitted_output(value: &Value) -> Result<(), Failure> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| invalid("resource result could not be serialized"))?;
    if bytes.len() > MAX_OUTPUT_BYTES {
        return Err(invalid("resource result exceeds the 8 MiB output limit"));
    }
    Ok(())
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a retained Android package report and an exact resource selector.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
