//! Bounded views over retained `analyze_function` Evidence.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "analyze_function";

/// Project one native function facet without rerunning the provider analysis.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent_raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&parent_raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "Native function views require analyze_function Evidence.",
        ));
    }

    let normalized: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&format!("function result is invalid JSON: {error}")))?;
    let dossier = normalized.get("dossier").unwrap_or(&normalized);
    let artifact = artifact_from_subject(&record)?;
    let requested = RequestedFacet::parse(view)?;
    let shared = shared_fields(&record, dossier, artifact);

    let body = match requested {
        RequestedFacet::Singleton { facet, offset } => {
            if offset != 0 {
                return Err(invalid("Singleton native facets require offset 0."));
            }
            singleton_facet(dossier, &facet, shared, view)
        }
        RequestedFacet::Pseudocode { offset, limit } => {
            pseudocode_page(dossier, offset, limit, shared, view)
        }
        RequestedFacet::Rows {
            facet,
            offset,
            limit,
        } => rows_page(dossier, &facet, offset, limit, shared, view),
    }?;

    create_view_evidence(&record, view, body)
}

#[derive(Clone)]
enum RequestedFacet {
    Singleton {
        facet: String,
        offset: usize,
    },
    Pseudocode {
        offset: usize,
        limit: usize,
    },
    Rows {
        facet: String,
        offset: usize,
        limit: usize,
    },
}

impl RequestedFacet {
    fn parse(view: &Value) -> Result<Self, Failure> {
        if view.get("kind").and_then(Value::as_str) != Some("native") {
            return Err(invalid("analyze_function Evidence requires a native view."));
        }
        let facet = view
            .get("facet")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("Native function view facet is required."))?;
        let offset = parse_bound(view, "offset", 0)?;
        let limit = parse_bound(view, "limit", 64)?;
        if limit == 0 {
            return Err(invalid("Native function view limit must be positive."));
        }

        if matches!(facet, "procedure" | "native_api" | "value_flow_summary") {
            return Ok(Self::Singleton {
                facet: facet.to_owned(),
                offset,
            });
        }
        if facet == "pseudocode" {
            return Ok(Self::Pseudocode { offset, limit });
        }
        if native_facet(facet).is_some() {
            return Ok(Self::Rows {
                facet: facet.to_owned(),
                offset,
                limit,
            });
        }
        Err(invalid("Unknown native function facet."))
    }
}

fn parse_bound(view: &Value, field: &str, default: u64) -> Result<usize, Failure> {
    let value = view.get(field).and_then(Value::as_u64).unwrap_or(default);
    usize::try_from(value).map_err(|_| invalid(&format!("Native function {field} is too large.")))
}

fn artifact_from_subject(record: &EvidenceRecord) -> Result<Value, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&format!("function subject is invalid: {error}")))?;
    let path = subject
        .get("local_path")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("Native function Evidence requires an artifact-bound subject."))?;
    let sha256 = subject
        .get("digest")
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid("Native function Evidence requires an artifact digest."))?;
    Ok(json!({"path": path, "sha256": sha256}))
}

fn shared_fields(record: &EvidenceRecord, dossier: &Value, artifact: Value) -> Value {
    let flow = dossier.get("native_value_flow");
    let api = dossier.get("native_api");
    let mut limitations = BTreeSet::new();
    let recorded_limitations = record_limitations(record);
    extend_strings(&mut limitations, recorded_limitations.as_ref());
    extend_strings(&mut limitations, dossier.get("limitations"));
    if let Some(flow) = flow.filter(|value| value.get("available") == Some(&Value::Bool(true))) {
        extend_strings(&mut limitations, flow.get("limitations"));
    }
    if let Some(api) = api.filter(|value| value.get("available") == Some(&Value::Bool(true))) {
        extend_strings(&mut limitations, api.get("limitations"));
    }

    let mut unknowns = Vec::new();
    match flow {
        None | Some(Value::Null) => unknowns.push("native_value_flow was not recorded".to_owned()),
        Some(value) if value.get("available") == Some(&Value::Bool(false)) => {
            unknowns.push(format!(
                "native_value_flow unavailable: {}",
                value["reason"].as_str().unwrap_or("unknown reason")
            ))
        }
        Some(value) if value["truncated"] == Value::Bool(true) => unknowns
            .push("native_value_flow is truncated; omitted observations remain unknown".to_owned()),
        _ => {}
    }
    match api {
        None | Some(Value::Null) => unknowns.push("native_api was not recorded".to_owned()),
        Some(value) if value.get("available") == Some(&Value::Bool(false)) => {
            unknowns.push(format!(
                "native_api unavailable: {}",
                value["reason"].as_str().unwrap_or("unknown reason")
            ));
            if let Some(residual) = value.get("residual_unknowns") {
                unknowns.extend(
                    residual
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned),
                );
            }
        }
        _ => {}
    }

    json!({
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": PARENT_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "procedure_address": dossier["procedure"]["address"],
        "artifact": artifact,
        "limitations": limitations.into_iter().collect::<Vec<_>>(),
        "unknowns": unique_strings(unknowns),
    })
}

fn record_limitations(record: &EvidenceRecord) -> Option<Value> {
    serde_json::from_str::<Value>(record.raw().get())
        .ok()
        .and_then(|value| value.get("limitations").cloned())
}

fn singleton_facet(
    dossier: &Value,
    facet: &str,
    mut shared: Value,
    view: &Value,
) -> Result<Value, Failure> {
    let availability = availability(dossier, facet);
    if let Some(reason) = unavailable_reason(availability) {
        append_unknown(&mut shared, reason.clone());
        return Ok(singleton(
            view,
            shared,
            json!({"available":false,"reason":reason}),
        ));
    }
    let item = match facet {
        "procedure" => dossier["procedure"].clone(),
        "native_api" => dossier
            .get("native_api")
            .cloned()
            .unwrap_or_else(|| json!({"available":false,"reason":"not recorded"})),
        "value_flow_summary" => value_flow_summary(dossier),
        _ => return Err(invalid("Unknown singleton native facet.")),
    };
    Ok(singleton(view, shared, item))
}

fn value_flow_summary(dossier: &Value) -> Value {
    let Some(flow) = dossier.get("native_value_flow") else {
        return json!({"available":false,"reason":"not recorded"});
    };
    if flow.get("available") != Some(&Value::Bool(true)) {
        return json!({"available":false,"reason":flow["reason"]});
    }
    json!({
        "available": true,
        "provenance": flow["provenance"],
        "truncated": flow["truncated"],
        "omitted_operations_lower_bound": flow["omitted_operations_lower_bound"],
        "known_omitted_inputs": flow["known_omitted_inputs"],
        "known_omitted_edges": flow["known_omitted_edges"],
        "operations": array_len(flow, "operations"),
        "def_use": array_len(flow, "def_use"),
        "effects": array_len(flow, "effects"),
        "parameters": array_len(flow, "parameters"),
        "parameter_uses": array_len(flow, "parameter_uses"),
    })
}

fn pseudocode_page(
    dossier: &Value,
    offset: usize,
    limit: usize,
    shared: Value,
    view: &Value,
) -> Result<Value, Failure> {
    let text = dossier["pseudocode"]
        .as_str()
        .ok_or_else(|| invalid("Native function pseudocode is missing."))?;
    let (item, examined) = utf16_page(text, offset, limit)?;
    let mut output = json!({
        "kind":"native",
        "view":view,
        "item":{"text":item,"unit":"utf16-code-units"},
        "coverage":page_coverage(offset, examined, text.encode_utf16().count()),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn rows_page(
    dossier: &Value,
    facet: &str,
    offset: usize,
    limit: usize,
    mut shared: Value,
    view: &Value,
) -> Result<Value, Failure> {
    let availability = availability(dossier, facet);
    if let Some(reason) = unavailable_reason(availability) {
        append_unknown(&mut shared, reason.clone());
        return Ok(singleton(
            view,
            shared,
            json!({"available":false,"reason":reason}),
        ));
    }
    let Some(rows) = native_rows(dossier, facet) else {
        let reason = if facet.starts_with("value_flow_") {
            dossier["native_value_flow"]["reason"]
                .as_str()
                .unwrap_or("not recorded")
        } else {
            "not recorded"
        };
        return Ok(singleton(
            view,
            shared,
            json!({"available":false,"reason":reason}),
        ));
    };
    let item = rows
        .iter()
        .skip(offset)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let mut output = json!({
        "kind":"native",
        "view":view,
        "item":item,
        "coverage":page_coverage(offset, item.len(), rows.len()),
    });
    merge_shared(&mut output, shared);
    Ok(output)
}

fn native_rows<'a>(dossier: &'a Value, facet: &str) -> Option<&'a Vec<Value>> {
    let key = native_facet(facet)?;
    let value = if key.starts_with("value_flow_") {
        dossier
            .get("native_value_flow")?
            .get(key.strip_prefix("value_flow_")?)?
    } else {
        dossier.get(key)?
    };
    value.as_array()
}

fn native_facet(facet: &str) -> Option<&'static str> {
    Some(match facet {
        "assembly" => "assembly",
        "basic_blocks" => "basic_blocks",
        "comments" => "comments",
        "callers" => "callers",
        "callees" => "callees",
        "incoming_references" => "incoming_references",
        "outgoing_references" => "outgoing_references",
        "unresolved_calls" => "unresolved_calls",
        "referenced_strings" => "referenced_strings",
        "referenced_names" => "referenced_names",
        "swift_string_literals" => "swift_string_literals",
        "swift_string_literal_omissions" => "swift_string_literal_omissions",
        "value_flow_operations" => "value_flow_operations",
        "value_flow_def_use" => "value_flow_def_use",
        "value_flow_effects" => "value_flow_effects",
        "value_flow_parameters" => "value_flow_parameters",
        "value_flow_parameter_uses" => "value_flow_parameter_uses",
        _ => return None,
    })
}

fn availability<'a>(dossier: &'a Value, facet: &str) -> Option<&'a Value> {
    let key = match facet {
        "incoming_references" | "outgoing_references" => "references",
        "referenced_strings" | "referenced_names" => "strings_names",
        "basic_blocks" => "cfg",
        value => value,
    };
    dossier.get("facet_availability")?.get(key)
}

fn unavailable_reason(availability: Option<&Value>) -> Option<String> {
    availability
        .filter(|value| value.get("available") == Some(&Value::Bool(false)))
        .map(|value| value["reason"].as_str().unwrap_or("unavailable").to_owned())
}

fn singleton(view: &Value, shared: Value, item: Value) -> Value {
    let mut output = json!({
        "kind":"native",
        "view":view,
        "item":item,
        "coverage":complete_coverage(1),
    });
    merge_shared(&mut output, shared);
    output
}

fn create_view_evidence(
    record: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let subject: Value = serde_json::from_str(record.subject().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let unsigned = json!({
        "subject": subject,
        "provider": {"id":"analysis-view","name":"REA retained analysis view","version":"1"},
        "analysis_profile": null,
        "predicate_type":"rea.analysis-view",
        "operation":OPERATION,
        "parameters":{"parent_evidence_id":record.evidence_id(),"view":view},
        "raw_result":null,
        "normalized_result":body,
        "confidence":"derived",
        "authority":authority,
        "environment":null,
        "limitations":[],
        "relationship_coverage":null,
        "locations":[],
        "evidence_links":[record.evidence_id()]
    });
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}

fn utf16_page(text: &str, offset: usize, limit: usize) -> Result<(String, usize), Failure> {
    let units = text.encode_utf16().collect::<Vec<_>>();
    let start = offset.min(units.len());
    if start > 0
        && start < units.len()
        && is_high_surrogate(units[start - 1])
        && is_low_surrogate(units[start])
    {
        return Err(invalid("Pseudocode offset splits a UTF-16 surrogate pair."));
    }
    let mut end = start.saturating_add(limit).min(units.len());
    if end > start
        && end < units.len()
        && is_high_surrogate(units[end - 1])
        && is_low_surrogate(units[end])
    {
        end -= 1;
    }
    if end == start && start < units.len() {
        return Err(invalid(
            "Increase pseudocode limit to include the next complete Unicode character.",
        ));
    }
    String::from_utf16(&units[start..end])
        .map(|value| (value, end - start))
        .map_err(|_| invalid("Pseudocode page contains invalid UTF-16."))
}

fn is_high_surrogate(unit: u16) -> bool {
    (0xd800..=0xdbff).contains(&unit)
}

fn is_low_surrogate(unit: u16) -> bool {
    (0xdc00..=0xdfff).contains(&unit)
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({
        "status": if examined == 0 { "empty" } else { "page" },
        "examined": examined,
        "total": total,
        "next_offset": if exhausted { Value::Null } else { json!(offset + examined) },
        "exhausted": exhausted,
    })
}

fn complete_coverage(total: usize) -> Value {
    json!({"status":"complete-within-view","examined":total,"total":total,"next_offset":null,"exhausted":true})
}

fn merge_shared(output: &mut Value, shared: Value) {
    if let (Some(output), Some(shared)) = (output.as_object_mut(), shared.as_object()) {
        output.extend(shared.clone());
    }
}

fn append_unknown(shared: &mut Value, reason: String) {
    let mut values = shared["unknowns"].as_array().cloned().unwrap_or_default();
    values.push(Value::String(reason));
    shared["unknowns"] = Value::Array(unique_values(values));
}

fn extend_strings(target: &mut BTreeSet<String>, value: Option<&Value>) {
    if let Some(values) = value.and_then(Value::as_array) {
        target.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
}

fn unique_strings(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn unique_values(values: Vec<Value>) -> Vec<Value> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.to_string()))
        .collect()
}

fn array_len(value: &Value, key: &str) -> Value {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(Value::Null, |items| json!(items.len()))
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Select compatible retained Evidence and retry.".into(),
        BTreeMap::from([
            ("operation".to_owned(), Detail::Text(OPERATION.into())),
            ("reason".to_owned(), Detail::Text(message.into())),
        ]),
    )
}
