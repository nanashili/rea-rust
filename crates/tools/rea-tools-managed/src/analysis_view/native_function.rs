//! Views over retained `analyze_function` Evidence.
//!
//! Compatibility owner: `src/domain/analysisView/nativeFunctionView.ts`.
use crate::common::json::{self, unique_sorted};
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, text_page, view_error,
    view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};

/// Resolve the availability key for a facet (`availabilityKeys`).
fn availability_key(facet: &str) -> &str {
    match facet {
        "incoming_references" | "outgoing_references" => "references",
        "referenced_strings" | "referenced_names" => "strings_names",
        "basic_blocks" => "cfg",
        other => other,
    }
}

/// `parentFields`: shared identity, limitations and unknowns.
fn parent_fields(
    parent: &Parent<'_>,
    dossier: &Value,
    artifact: (&str, &str),
) -> (Vec<String>, Vec<String>) {
    let flow = dossier.get("native_value_flow").unwrap_or(&Value::Null);
    let api = dossier.get("native_api").unwrap_or(&Value::Null);
    let mut unknowns: Vec<String> = Vec::new();
    if flow.is_null() {
        unknowns.push("native_value_flow was not recorded".to_owned());
    } else if flow.get("available").and_then(Value::as_bool) != Some(true) {
        unknowns.push(format!(
            "native_value_flow unavailable: {}",
            flow.get("reason").and_then(Value::as_str).unwrap_or("")
        ));
    } else if flow.get("truncated").and_then(Value::as_bool) == Some(true) {
        unknowns
            .push("native_value_flow is truncated; omitted observations remain unknown".to_owned());
    }
    if api.is_null() {
        unknowns.push("native_api was not recorded".to_owned());
    } else if api.get("available").and_then(Value::as_bool) != Some(true) {
        unknowns.push(format!(
            "native_api unavailable: {}",
            api.get("reason").and_then(Value::as_str).unwrap_or("")
        ));
        unknowns.extend(json::strings(
            api.get("residual_unknowns").unwrap_or(&Value::Null),
        ));
    }

    let _ = artifact;
    let mut limits: Vec<String> = parent.limitations.clone();
    limits.extend(json::strings(
        dossier.get("limitations").unwrap_or(&Value::Null),
    ));
    if flow.is_object() {
        limits.extend(json::strings(
            flow.get("limitations").unwrap_or(&Value::Null),
        ));
    }
    if api.get("available").and_then(Value::as_bool) == Some(true) {
        limits.extend(json::strings(
            api.get("limitations").unwrap_or(&Value::Null),
        ));
    }
    (unique_sorted(limits), unique_sorted(unknowns))
}

/// Resolve the row collection for a non-singleton facet (`nativeRows`).
fn native_rows(dossier: &Value, facet: &str) -> Option<Vec<Value>> {
    let flow = dossier.get("native_value_flow").unwrap_or(&Value::Null);
    let flow = if flow.get("available").and_then(Value::as_bool) == Some(true) {
        Some(flow)
    } else {
        None
    };
    let direct = |key: &str| {
        dossier
            .get(key)
            .and_then(Value::as_array)
            .map(|rows| rows.to_vec())
    };
    match facet {
        "assembly" => direct("assembly"),
        "basic_blocks" => direct("basic_blocks"),
        "comments" => direct("comments"),
        "callers" => direct("callers"),
        "callees" => direct("callees"),
        "incoming_references" => direct("incoming_references"),
        "outgoing_references" => direct("outgoing_references"),
        "unresolved_calls" => direct("unresolved_calls"),
        "referenced_strings" => direct("referenced_strings"),
        "referenced_names" => direct("referenced_names"),
        "swift_string_literals" => direct("swift_string_literals"),
        "swift_string_literal_omissions" => direct("swift_string_literal_omissions"),
        "value_flow_operations" => flow
            .and_then(|f| f.get("operations"))
            .and_then(Value::as_array)
            .map(|r| r.to_vec()),
        "value_flow_def_use" => flow
            .and_then(|f| f.get("def_use"))
            .and_then(Value::as_array)
            .map(|r| r.to_vec()),
        "value_flow_effects" => flow
            .and_then(|f| f.get("effects"))
            .and_then(Value::as_array)
            .map(|r| r.to_vec()),
        "value_flow_parameters" => flow
            .and_then(|f| f.get("parameters"))
            .and_then(Value::as_array)
            .map(|r| r.to_vec()),
        "value_flow_parameter_uses" => flow
            .and_then(|f| f.get("parameter_uses"))
            .and_then(Value::as_array)
            .map(|r| r.to_vec()),
        _ => None,
    }
}

/// `projectNativeFunctionView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    // The dispatcher parses the dossier before the projector checks the view.
    let dossier = parent.parse_result("analyze_function")?;
    if view_kind(view) != "native" {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "analyze_function Evidence requires a native view.",
        ));
    }

    let Some((artifact_path, artifact_sha256)) = parent.artifact() else {
        return Err(view_error(
            &["source", "subject"],
            "invalid_value",
            "Native function Evidence requires an artifact-bound subject.",
        ));
    };
    let (limitations, mut unknowns) =
        parent_fields(parent, &dossier, (artifact_path, artifact_sha256));

    let facet = json::str_at(view, "facet").unwrap_or_default();
    let availability = dossier
        .get("facet_availability")
        .and_then(|table| table.get(availability_key(facet)))
        .cloned()
        .unwrap_or(Value::Null);
    let availability_unavailable =
        availability.get("available").and_then(Value::as_bool) == Some(false);
    if availability_unavailable {
        let mut combined = unknowns.clone();
        combined.push(
            availability
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        );
        unknowns = unique_sorted(combined);
    }

    let procedure_address = dossier
        .get("procedure")
        .and_then(|procedure| procedure.get("address"))
        .cloned()
        .unwrap_or(Value::Null);
    let artifact = json!({ "path": artifact_path, "sha256": artifact_sha256 });
    // `...common` fields follow the item/coverage in TS spread order.
    let append_common = |map: &mut Map<String, Value>| {
        map.insert("parent_evidence_id".into(), json!(parent.evidence_id));
        map.insert("parent_operation".into(), json!("analyze_function"));
        map.insert("parent_digest".into(), json!(parent.digest()));
        map.insert("procedure_address".into(), json!(procedure_address));
        map.insert("artifact".into(), artifact.clone());
        map.insert("limitations".into(), json!(limitations));
        map.insert("unknowns".into(), json!(unknowns));
    };
    let singleton = |item: Value, map_common: &dyn Fn(&mut Map<String, Value>)| -> Value {
        let mut out = Map::new();
        out.insert("kind".into(), json!("native"));
        out.insert("view".into(), view.clone());
        out.insert("item".into(), item);
        out.insert("coverage".into(), complete_within_view(1, 1));
        map_common(&mut out);
        Value::Object(out)
    };

    if availability_unavailable {
        return Ok(singleton(availability, &append_common));
    }

    let (offset, limit) = offset_limit(view);
    let flow = dossier.get("native_value_flow").unwrap_or(&Value::Null);

    if facet == "procedure" || facet == "native_api" || facet == "value_flow_summary" {
        if offset != 0 {
            return Err(view_error(
                &["view"],
                "invalid_value",
                "Singleton native facets require offset 0.",
            ));
        }
        if facet == "procedure" {
            let procedure = dossier.get("procedure").cloned().unwrap_or(Value::Null);
            return Ok(singleton(procedure, &append_common));
        }
        if facet == "native_api" {
            let api = dossier.get("native_api").cloned().unwrap_or(Value::Null);
            let item = if api.is_null() {
                json!({ "available": false, "reason": "not recorded" })
            } else {
                api
            };
            return Ok(singleton(item, &append_common));
        }
        let status = if flow.is_null() {
            json!({ "available": false, "reason": "not recorded" })
        } else if flow.get("available").and_then(Value::as_bool) != Some(true) {
            json!({ "available": false, "reason": flow.get("reason").cloned().unwrap_or(Value::Null) })
        } else {
            json!({
                "available": true,
                "provenance": flow.get("provenance").cloned().unwrap_or(Value::Null),
                "truncated": flow.get("truncated").cloned().unwrap_or(Value::Null),
                "omitted_operations_lower_bound": flow.get("omitted_operations_lower_bound").cloned().unwrap_or(Value::Null),
                "known_omitted_inputs": flow.get("known_omitted_inputs").cloned().unwrap_or(Value::Null),
                "known_omitted_edges": flow.get("known_omitted_edges").cloned().unwrap_or(Value::Null),
                "operations": json::array_at(flow, "operations").len(),
                "def_use": json::array_at(flow, "def_use").len(),
                "effects": json::array_at(flow, "effects").len(),
                "parameters": json::array_at(flow, "parameters").len(),
                "parameter_uses": json::array_at(flow, "parameter_uses").len(),
            })
        };
        return Ok(singleton(status, &append_common));
    }

    if facet == "pseudocode" {
        let body = dossier
            .get("pseudocode")
            .and_then(Value::as_str)
            .unwrap_or("");
        let (item, coverage) = text_page(body, offset, limit, "Pseudocode")?;
        let mut out = Map::new();
        out.insert("kind".into(), json!("native"));
        out.insert("view".into(), view.clone());
        out.insert("item".into(), item);
        out.insert("coverage".into(), coverage);
        append_common(&mut out);
        return Ok(Value::Object(out));
    }

    let Some(rows) = native_rows(&dossier, facet) else {
        let value_flow_failed = facet.starts_with("value_flow_")
            && flow.get("available").and_then(Value::as_bool) == Some(false);
        let reason = if value_flow_failed {
            flow.get("reason")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned()
        } else {
            "not recorded".to_owned()
        };
        return Ok(singleton(
            json!({ "available": false, "reason": reason }),
            &append_common,
        ));
    };

    let items = page(&rows, offset, limit);
    let examined = items.len();
    let mut out = Map::new();
    out.insert("kind".into(), json!("native"));
    out.insert("view".into(), view.clone());
    out.insert("item".into(), Value::Array(items));
    out.insert(
        "coverage".into(),
        page_coverage(offset, examined, rows.len()),
    );
    append_common(&mut out);
    Ok(Value::Object(out))
}
