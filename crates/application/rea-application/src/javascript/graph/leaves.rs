//! Pure domain leaves the graph projections read: semantic coverage and
//! resource-limit classifications, execution-limit projection, semantic slot
//! inventories and export return-shape projection.

use super::super::semantic::value_types::JsString;
use super::evidence::{limit, partial_coverage};
use super::json::{Json, Obj};

/// `semanticCoverageResourceLimits`.
pub fn semantic_resource_limits(coverage: &Json) -> Vec<String> {
    coverage
        .at("resourceLimits")
        .arr()
        .iter()
        .map(|value| value.str().to_owned())
        .collect()
}

/// `semanticResourceLimitReason`.
pub fn semantic_resource_limit_reason(limit: &str) -> &'static str {
    match limit {
        "primitive-candidates" => "Primitive candidate budget exceeded (maximum 256 alternatives).",
        "primitive-bytes" => {
            "Primitive string-byte budget exceeded (maximum 1048576 estimated JSON bytes)."
        }
        "expression-depth" => {
            "Semantic expression depth budget exceeded (maximum 256 nested expressions)."
        }
        _ => {
            "Getter expansion was conservatively bounded (maximum 512 scheduled states or a growing receiver cycle)."
        }
    }
}

/// `semanticResourceLimitCoverage`.
pub fn semantic_resource_limit_coverage(limits: &[String]) -> Vec<Json> {
    limits
        .iter()
        .map(|resource| {
            let (value, unit) = match resource.as_str() {
                "primitive-candidates" => (256.0, "items"),
                "primitive-bytes" => (1_048_576.0, "bytes"),
                "expression-depth" => (256.0, "depth"),
                _ => (512.0, "items"),
            };
            limit(
                &format!("javascript_semantic_{}", resource.replace('-', "_")),
                value,
                unit,
            )
        })
        .collect()
}

/// `RETURNED_REFERENCE_WIDENING_LIMITATION`.
pub const RETURNED_REFERENCE_WIDENING_LIMITATION: &str = "Local returned-reference projections were conservatively widened; effects include additional source-local candidates.";

/// `javaScriptAnalysisCoverageLimits`.
pub fn analysis_coverage_limits(limits: &Json) -> Vec<Json> {
    let mut result = Vec::new();
    for key in [
        "worker_heap_limit_bytes",
        "worker_process_memory_limit_bytes",
        "worker_timeout_ms",
        "parent_result_budget_bytes",
        "parent_available_result_budget_bytes",
        "semantic_result_budget_bytes",
        "transfer_record_bytes",
        "transfer_file_bytes",
    ] {
        let Some(value) = limits.get(key).and_then(Json::as_f64) else {
            continue;
        };
        if value.fract() != 0.0 || !(0.0..=9_007_199_254_740_991.0).contains(&value) {
            continue;
        }
        result.push(limit(
            &format!("javascript_analysis_{key}"),
            value,
            if key.ends_with("_ms") {
                "milliseconds"
            } else {
                "bytes"
            },
        ));
    }
    result
}

/// `semanticPropertyPointer`.
pub fn property_pointer(path: &[String]) -> String {
    path.iter()
        .map(|key| format!("/{}", key.replace('~', "~0").replace('/', "~1")))
        .collect()
}

/// Encode a semantic property path without decoding JavaScript UTF-16 text.
pub fn property_pointer_js(path: &[JsString]) -> JsString {
    let mut pointer = JsString::from("");
    for key in path {
        pointer.extend(&JsString::from("/"));
        for unit in key.units() {
            match *unit {
                0x7e => pointer.extend(&JsString::from("~0")),
                0x2f => pointer.extend(&JsString::from("~1")),
                unit => pointer.extend(&JsString::from_utf16(vec![unit])),
            }
        }
    }
    pointer
}

/// `semanticContainer`: slot inventory and coverage of an object or array value.
pub struct Container<'a> {
    /// Slots in producer order.
    pub slots: &'a [Json],
    /// `{ status, omitted }` coverage.
    pub coverage: Json,
}

/// `semanticContainer`.
pub fn container(value: &Json) -> Option<Container<'_>> {
    let (slots, unknown, omitted) = match value.at("status").str() {
        "object" => ("properties", "unknownProperties", "omittedProperties"),
        "array" => ("items", "unknownItems", "omittedItems"),
        _ => return None,
    };
    let coverage = if value.at(unknown).as_bool() == Some(true) {
        Obj::new()
            .with("status", "partial")
            .with("omitted", value.at(omitted).clone())
    } else {
        Obj::new().with("status", "complete").with("omitted", 0.0)
    };
    Some(Container {
        slots: value.at(slots).arr(),
        coverage: coverage.into(),
    })
}

/// `semanticSlotAtPath`.
pub fn slot_at_path(value: &Json, path: &[JsString]) -> Json {
    let leaf = path.last().cloned().unwrap_or_default();
    let mut current: Json = Obj::new()
        .with("name", "")
        .with("presence", "present")
        .with("value", value.clone())
        .into();
    for (index, name) in path.iter().enumerate() {
        let current_value = current.at("value").clone();
        let inventory = container(&current_value);
        if current.at("presence").str() != "present" || inventory.is_none() {
            let reason = if let Some(reason) = current_value.get("reason") {
                let mut unknown = current_value.obj();
                unknown.set(
                    "reason",
                    format!(
                        "{} Cannot continue {} through receiver {}.",
                        reason.str(),
                        property_pointer_js(path),
                        property_pointer_js(&path[..index])
                    ),
                );
                unknown
            } else {
                Obj::new().with("status", "unknown").with(
                    "reason",
                    format!(
                        "Cannot resolve {} through {} receiver {}.",
                        property_pointer_js(path),
                        current_value.at("status").str(),
                        property_pointer_js(&path[..index])
                    ),
                )
            };
            return Obj::new()
                .with("name", leaf)
                .with("presence", "unknown-coverage")
                .with("value", reason)
                .into();
        }
        let Some(inventory) = inventory else { break };
        if current_value.at("status").str() == "array" && name == "length" {
            current = Obj::new()
                .with("name", name)
                .with("presence", "present")
                .with(
                    "value",
                    Obj::new().with("status", "unknown").with(
                        "reason",
                        "Array length is present but its value is not retained.",
                    ),
                )
                .into();
            continue;
        }
        let observed = inventory
            .slots
            .iter()
            .find(|slot| slot.at("name").text() == name)
            .cloned();
        current = observed.unwrap_or_else(|| {
            Obj::new()
                .with("name", name)
                .with(
                    "presence",
                    if inventory.coverage.at("status").str() == "complete" {
                        "absent"
                    } else {
                        "unknown-coverage"
                    },
                )
                .with(
                    "value",
                    Obj::new()
                        .with("status", "unknown")
                        .with("reason", format!("Own property {name} was not observed.")),
                )
                .into()
        });
    }
    current
}

/// `flattenSemanticReturnValue`.
fn flatten_return_value(value: &Json) -> (Vec<Json>, Vec<Json>) {
    let mut fields = Vec::new();
    let mut coverage = Vec::new();
    flatten_value(
        value,
        &JsString::from(""),
        &mut fields,
        &mut coverage,
        "present",
    );
    fields.sort_by(|left, right| {
        left.at("path")
            .text()
            .compare_code_points(right.at("path").text())
    });
    coverage.sort_by(|left, right| {
        left.at("path")
            .text()
            .compare_code_points(right.at("path").text())
    });
    (fields, coverage)
}

fn field(path: &JsString, presence: &str, state: &str, value: Json, reason: Json) -> Json {
    Obj::new()
        .with("path", Json::String(path.clone()))
        .with("presence", presence)
        .with("state", state)
        .with("value", value)
        .with("reason", reason)
        .into()
}

fn flatten_value(
    value: &Json,
    path: &JsString,
    fields: &mut Vec<Json>,
    coverage: &mut Vec<Json>,
    presence: &str,
) {
    if presence != "present" {
        let reason = value
            .get("reason")
            .cloned()
            .unwrap_or_else(|| Json::from("Property presence is uncertain."));
        fields.push(field(path, presence, "unknown", Json::Null, reason));
        return;
    }
    match value.at("status").str() {
        "literal" => {
            fields.push(field(
                path,
                presence,
                "literal",
                value.at("value").clone(),
                Json::Null,
            ));
            return;
        }
        "union" => {
            fields.push(field(
                path,
                presence,
                "union",
                value.at("values").clone(),
                Json::Null,
            ));
            return;
        }
        _ => {}
    }
    if let Some(reason) = value.get("reason") {
        fields.push(field(path, presence, "unknown", Json::Null, reason.clone()));
        return;
    }
    let Some(inventory) = container(value) else {
        return;
    };
    let mut entry = Obj::new().with("path", Json::String(path.clone()));
    if let Some(object) = inventory.coverage.as_obj() {
        entry.extend_from(object);
    }
    coverage.push(entry.into());
    for slot in inventory.slots {
        let name = slot.at("name").text().clone();
        let child = path.concat(&property_pointer_js(&[name]));
        flatten_value(
            slot.at("value"),
            &child,
            fields,
            coverage,
            slot.at("presence").str(),
        );
    }
}

/// `projectJavaScriptExportReturnShapes`: `(properties, range, coverage, limitations)`.
pub fn export_return_shapes(
    ir: &Json,
    link: &Json,
    module_path: &JsString,
    base_coverage: &Json,
) -> Option<(Obj, Json, Json, Vec<JsString>)> {
    let callable_id = link.at("callableId").as_js_string()?;
    let exported = link.at("exportedName").as_js_string()?;
    let callable = ir
        .at("callables")
        .arr()
        .iter()
        .find(|callable| callable.at("callableId").as_js_string() == Some(&callable_id))?;
    let shapes: Vec<Json> = callable
        .at("returnSites")
        .arr()
        .iter()
        .map(|site| {
            let (fields, property_coverage) = flatten_return_value(site.at("value"));
            Obj::new()
                .with("source_range", site.at("location").clone())
                .with("value_status", site.at("value").at("status").clone())
                .with("fields", Json::Array(fields))
                .with("property_coverage", Json::Array(property_coverage))
                .into()
        })
        .collect();
    let return_coverage = callable.at("returnCoverage");
    let semantic_omitted = return_coverage.at("omittedCount").as_f64();
    let complete = base_coverage.at("status").str() == "complete"
        && return_coverage.at("status").str() == "complete";
    let limits = base_coverage.at("limits").arr().to_vec();
    let coverage = if complete {
        base_coverage.clone()
    } else {
        partial_coverage(limits, semantic_omitted)
    };
    let mut limitations: Vec<JsString> = ir
        .at("limitations")
        .arr()
        .iter()
        .map(|value| value.text().clone())
        .collect();
    limitations.push(JsString::from(
        "Return shapes are inferred from inert syntax and do not prove runtime behavior.",
    ));
    if callable.at("returnSites").arr().is_empty() {
        limitations.push(JsString::from(
            "No direct return value was retained; runtime return behavior remains unknown.",
        ));
    }
    let retained = shapes.len();
    let properties = Obj::new()
        .with("semantic_role", "export-return-shapes")
        .with("module_path", Json::String(module_path.clone()))
        .with("exported_name", Json::String(exported.clone()))
        .with("callable_id", callable.at("callableId").clone())
        .with("callable_kind", callable.at("kind").clone())
        .with("static_return_shapes", Json::Array(shapes))
        .with(
            "return_shape_coverage",
            Obj::new()
                .with("status", return_coverage.at("status").clone())
                .with("retained_return_sites", retained)
                .with("omitted_return_sites", semantic_omitted)
                .with("omitted_fields", 0.0)
                .with("omitted_property_coverage", 0.0)
                .with("projection_complete", true),
        );
    Some((
        properties,
        callable.at("location").clone(),
        coverage,
        limitations,
    ))
}

#[cfg(test)]
mod tests {
    use super::property_pointer_js;
    use crate::javascript::semantic::value_types::JsString;

    #[test]
    fn property_pointer_js_preserves_unpaired_units_and_escapes_delimiters() {
        let path = vec![JsString::from_utf16(vec![0xd800, 0x2f, 0x7e])];

        assert_eq!(
            property_pointer_js(&path).units(),
            &[0x2f, 0xd800, 0x7e, 0x31, 0x7e, 0x30]
        );
    }
}
