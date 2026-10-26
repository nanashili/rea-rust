//! Pure domain leaves the graph projections read: semantic coverage and
//! resource-limit classifications, execution-limit projection, semantic slot
//! inventories and export return-shape projection.

use super::super::semantic::value_types::{
    Coverage, JsString, Property, SemanticValue, SlotPresence,
};
use super::direct_serializer::JsonConversion;
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

#[derive(Clone, Copy)]
pub(crate) enum ValueRef<'a> {
    Json(&'a Json),
    Typed(&'a SemanticValue),
}

enum ContainerSlots<'a> {
    Json(&'a [Json]),
    Typed(&'a [Property]),
}

struct ContainerRef<'a> {
    slots: ContainerSlots<'a>,
    coverage: Json,
}

/// A property selected from a semantic value without copying its subtree.
pub(crate) enum SlotFact<'a> {
    Root(&'a Json),
    Observed(&'a Json),
    TypedRoot(&'a SemanticValue),
    TypedObserved(&'a Property),
    Synthetic {
        name: JsString,
        presence: &'static str,
        value: Json,
    },
}

impl SlotFact<'_> {
    pub(crate) fn name(&self) -> JsString {
        match self {
            Self::Root(_) => JsString::from(""),
            Self::Observed(property) => property.at("name").text().clone(),
            Self::TypedRoot(_) => JsString::from(""),
            Self::TypedObserved(property) => property.name.clone(),
            Self::Synthetic { name, .. } => name.clone(),
        }
    }

    pub(crate) fn presence(&self) -> &str {
        match self {
            Self::Root(_) => "present",
            Self::Observed(property) => property.at("presence").str(),
            Self::TypedRoot(_) => "present",
            Self::TypedObserved(property) => typed_presence(property.presence),
            Self::Synthetic { presence, .. } => presence,
        }
    }

    pub(crate) fn raw_name(&self) -> Json {
        match self {
            Self::Root(_) => Json::String(JsString::from("")),
            Self::Observed(property) => property.at("name").clone(),
            Self::TypedRoot(_) => Json::String(JsString::from("")),
            Self::TypedObserved(property) => Json::String(property.name.clone()),
            Self::Synthetic { name, .. } => Json::String(name.clone()),
        }
    }

    pub(crate) fn raw_presence(&self) -> Json {
        match self {
            Self::Root(_) => Json::String(JsString::from("present")),
            Self::Observed(property) => property.at("presence").clone(),
            Self::TypedRoot(_) => Json::String(JsString::from("present")),
            Self::TypedObserved(property) => {
                Json::String(JsString::from(typed_presence(property.presence)))
            }
            Self::Synthetic { presence, .. } => Json::String(JsString::from(*presence)),
        }
    }

    pub(crate) fn value_status(&self) -> Json {
        self.value_ref().status()
    }

    pub(crate) fn value_coverage(&self) -> Json {
        self.value_ref().coverage()
    }

    pub(crate) fn is_container(&self) -> bool {
        self.value_ref().is_container()
    }

    fn value_ref(&self) -> ValueRef<'_> {
        match self {
            Self::Root(value) => ValueRef::Json(value),
            Self::Observed(property) => ValueRef::Json(property.at("value")),
            Self::TypedRoot(value) => ValueRef::Typed(value),
            Self::TypedObserved(property) => ValueRef::Typed(&property.value),
            Self::Synthetic { value, .. } => ValueRef::Json(value),
        }
    }
}

impl ValueRef<'_> {
    fn status(self) -> Json {
        match self {
            Self::Json(value) => value.at("status").clone(),
            Self::Typed(value) => semantic_status(value),
        }
    }

    fn coverage(self) -> Json {
        match self {
            Self::Json(value) => {
                container(value).map_or(Json::Null, |inventory| inventory.coverage)
            }
            Self::Typed(value) => typed_container_coverage(value),
        }
    }

    fn is_container(self) -> bool {
        match self {
            Self::Json(value) => matches!(value.at("status").str(), "object" | "array"),
            Self::Typed(value) => matches!(
                value,
                SemanticValue::Object { .. } | SemanticValue::Array { .. }
            ),
        }
    }
}

fn semantic_status(value: &SemanticValue) -> Json {
    Json::String(JsString::from(match value {
        SemanticValue::Literal { .. } => "literal",
        SemanticValue::Union { .. } => "union",
        SemanticValue::Object { .. } => "object",
        SemanticValue::Array { .. } => "array",
        SemanticValue::Unknown { .. } => "unknown",
        SemanticValue::Ambiguous { .. } => "ambiguous",
        SemanticValue::Cycle { .. } => "cycle",
    }))
}

fn typed_presence(presence: SlotPresence) -> &'static str {
    match presence {
        SlotPresence::Present => "present",
        SlotPresence::Absent => "absent",
        SlotPresence::UnknownCoverage => "unknown-coverage",
    }
}

fn typed_container_coverage(value: &SemanticValue) -> Json {
    let coverage = match value {
        SemanticValue::Object { coverage, .. } | SemanticValue::Array { coverage, .. } => coverage,
        _ => return Json::Null,
    };
    let (unknown, omitted) = match coverage {
        Coverage::Exact => (false, Some(0usize)),
        Coverage::Unknown { omitted } => (true, *omitted),
    };
    Obj::new()
        .with_static("status", if unknown { "partial" } else { "complete" })
        .with_static(
            "omitted",
            omitted.map_or(Json::Null, |count| Json::from(count as f64)),
        )
        .into()
}

fn container_ref(value: ValueRef<'_>) -> Option<ContainerRef<'_>> {
    match value {
        ValueRef::Json(value) => {
            let inventory = container(value)?;
            Some(ContainerRef {
                slots: ContainerSlots::Json(inventory.slots),
                coverage: inventory.coverage,
            })
        }
        ValueRef::Typed(value) => match value {
            SemanticValue::Object { properties, .. } => Some(ContainerRef {
                slots: ContainerSlots::Typed(properties.as_slice()),
                coverage: typed_container_coverage(value),
            }),
            SemanticValue::Array { items, .. } => Some(ContainerRef {
                slots: ContainerSlots::Typed(items.as_slice()),
                coverage: typed_container_coverage(value),
            }),
            _ => None,
        },
    }
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
            .with_static("status", "partial")
            .with_static("omitted", value.at(omitted).clone())
    } else {
        Obj::new()
            .with_static("status", "complete")
            .with_static("omitted", 0.0)
    };
    Some(Container {
        slots: value.at(slots).arr(),
        coverage: coverage.into(),
    })
}

/// Select a property using the same rules for serialized and typed values.
pub(crate) fn slot_at_value<'a>(value: ValueRef<'a>, path: &[JsString]) -> SlotFact<'a> {
    let leaf = path.last().cloned().unwrap_or_default();
    if path.is_empty() {
        return match value {
            ValueRef::Json(value) => SlotFact::Root(value),
            ValueRef::Typed(value) => SlotFact::TypedRoot(value),
        };
    }

    let mut current = value;
    for (index, name) in path.iter().enumerate() {
        let Some(inventory) = container_ref(current) else {
            return SlotFact::Synthetic {
                name: leaf,
                presence: "unknown-coverage",
                value: continued_path_unknown(path, index, &value_metadata_json(current)),
            };
        };

        if is_array(current) && name == "length" {
            let length_value: Json = Obj::new()
                .with_static("status", "unknown")
                .with_static(
                    "reason",
                    "Array length is present but its value is not retained.",
                )
                .into();
            if index + 1 == path.len() {
                return SlotFact::Synthetic {
                    name: name.clone(),
                    presence: "present",
                    value: length_value,
                };
            }
            return SlotFact::Synthetic {
                name: leaf,
                presence: "unknown-coverage",
                value: continued_path_unknown(path, index + 1, &length_value),
            };
        }

        let observed = match inventory.slots {
            ContainerSlots::Json(slots) => slots
                .iter()
                .find(|slot| slot.at("name").text() == name)
                .map(SlotFact::Observed),
            ContainerSlots::Typed(slots) => slots
                .iter()
                .find(|slot| slot.name == name)
                .map(SlotFact::TypedObserved),
        };
        let Some(observed) = observed else {
            let presence = if inventory.coverage.at("status").str() == "complete" {
                "absent"
            } else {
                "unknown-coverage"
            };
            let missing_value: Json = Obj::new()
                .with_static("status", "unknown")
                .with_static("reason", format!("Own property {name} was not observed."))
                .into();
            if index + 1 == path.len() {
                return SlotFact::Synthetic {
                    name: leaf,
                    presence,
                    value: missing_value,
                };
            }
            return SlotFact::Synthetic {
                name: leaf,
                presence: "unknown-coverage",
                value: continued_path_unknown(path, index + 1, &missing_value),
            };
        };

        if index + 1 == path.len() {
            return observed;
        }

        if observed.presence() != "present" {
            return SlotFact::Synthetic {
                name: leaf,
                presence: "unknown-coverage",
                value: continued_path_unknown(
                    path,
                    index + 1,
                    &value_metadata_json(
                        observed
                            .borrowed_value()
                            .expect("observed slot has a value"),
                    ),
                ),
            };
        }

        current = observed
            .borrowed_value()
            .expect("present observed slot has a value");
    }

    unreachable!("a non-empty path must return a slot fact")
}

fn is_array(value: ValueRef<'_>) -> bool {
    match value {
        ValueRef::Json(value) => value.at("status").str() == "array",
        ValueRef::Typed(SemanticValue::Array { .. }) => true,
        ValueRef::Typed(_) => false,
    }
}

impl<'a> SlotFact<'a> {
    fn borrowed_value(&self) -> Option<ValueRef<'a>> {
        match self {
            Self::Root(value) => Some(ValueRef::Json(value)),
            Self::Observed(property) => Some(ValueRef::Json(property.at("value"))),
            Self::TypedRoot(value) => Some(ValueRef::Typed(value)),
            Self::TypedObserved(property) => Some(ValueRef::Typed(&property.value)),
            Self::Synthetic { .. } => None,
        }
    }
}

fn value_metadata_json(value: ValueRef<'_>) -> Json {
    match value {
        ValueRef::Json(value) => value.clone(),
        ValueRef::Typed(
            value @ (SemanticValue::Unknown { .. }
            | SemanticValue::Ambiguous { .. }
            | SemanticValue::Cycle { .. }),
        ) => JsonConversion::default()
            .serialize(value)
            .expect("opaque semantic values must serialize"),
        ValueRef::Typed(value) => Obj::new()
            .with_static("status", semantic_status(value))
            .into(),
    }
}

fn continued_path_unknown(path: &[JsString], receiver_index: usize, value: &Json) -> Json {
    if let Some(reason) = value.get("reason") {
        let mut unknown = value.obj();
        unknown.set(
            "reason",
            format!(
                "{} Cannot continue {} through receiver {}.",
                reason.str(),
                property_pointer_js(path),
                property_pointer_js(&path[..receiver_index])
            ),
        );
        return unknown.into();
    }

    Obj::new()
        .with_static("status", "unknown")
        .with_static(
            "reason",
            format!(
                "Cannot resolve {} through {} receiver {}.",
                property_pointer_js(path),
                value.at("status").str(),
                property_pointer_js(&path[..receiver_index])
            ),
        )
        .into()
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
        .with_static("path", Json::String(path.clone()))
        .with_static("presence", presence)
        .with_static("state", state)
        .with_static("value", value)
        .with_static("reason", reason)
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
    let mut entry = Obj::new().with_static("path", Json::String(path.clone()));
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
                .with_static("source_range", site.at("location").clone())
                .with_static("value_status", site.at("value").at("status").clone())
                .with_static("fields", Json::array(fields))
                .with_static("property_coverage", Json::array(property_coverage))
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
        .with_static("semantic_role", "export-return-shapes")
        .with_static("module_path", Json::String(module_path.clone()))
        .with_static("exported_name", Json::String(exported.clone()))
        .with_static("callable_id", callable.at("callableId").clone())
        .with_static("callable_kind", callable.at("kind").clone())
        .with_static("static_return_shapes", Json::array(shapes))
        .with_static(
            "return_shape_coverage",
            Obj::new()
                .with_static("status", return_coverage.at("status").clone())
                .with_static("retained_return_sites", retained)
                .with_static("omitted_return_sites", semantic_omitted)
                .with_static("omitted_fields", 0.0)
                .with_static("omitted_property_coverage", 0.0)
                .with_static("projection_complete", true),
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
    use super::{Json, Obj, ValueRef, property_pointer_js, slot_at_value, value_metadata_json};
    use crate::javascript::graph::direct_serializer::JsonConversion;
    use crate::javascript::semantic::value_types::JsString;
    use crate::javascript::semantic::value_types::{
        Coverage, Primitive, Property, PropertySlots, ResourceLimit, SemanticValue, SlotPresence,
    };

    #[test]
    fn property_pointer_js_preserves_unpaired_units_and_escapes_delimiters() {
        let path = vec![JsString::from_utf16(vec![0xd800, 0x2f, 0x7e])];

        assert_eq!(
            property_pointer_js(&path).units(),
            &[0x2f, 0xd800, 0x7e, 0x31, 0x7e, 0x30]
        );
    }

    #[test]
    fn slot_lookup_preserves_nested_and_missing_slot_semantics() {
        let value: Json = Obj::new()
            .with_static("status", "object")
            .with_static(
                "properties",
                Json::array(vec![
                    Obj::new()
                        .with_static("name", "items")
                        .with_static("presence", "present")
                        .with_static(
                            "value",
                            Obj::new()
                                .with_static("status", "array")
                                .with_static(
                                    "items",
                                    Json::array(vec![
                                        Obj::new()
                                            .with_static("name", "0")
                                            .with_static("presence", "present")
                                            .with_static(
                                                "value",
                                                Obj::new()
                                                    .with_static("status", "literal")
                                                    .with_static("value", 7.0),
                                            )
                                            .into(),
                                    ]),
                                )
                                .with_static("unknownItems", false)
                                .with_static("omittedItems", 0.0),
                        )
                        .into(),
                ]),
            )
            .with_static("unknownProperties", false)
            .with_static("omittedProperties", 0.0)
            .into();

        let observed = slot_at_value(ValueRef::Json(&value), &["items".into(), "0".into()]);
        assert_eq!(observed.name(), "0");
        assert_eq!(observed.presence(), "present");
        assert_eq!(observed.value_status().str(), "literal");

        let missing = slot_at_value(ValueRef::Json(&value), &["items".into(), "9".into()]);
        assert_eq!(missing.name(), "9");
        assert_eq!(missing.presence(), "absent");
        assert_eq!(missing.value_status().str(), "unknown");

        let length = slot_at_value(ValueRef::Json(&value), &["items".into(), "length".into()]);
        assert_eq!(length.presence(), "present");
        assert_eq!(length.value_status().str(), "unknown");
    }

    #[test]
    fn typed_and_json_slot_selection_preserve_metadata_and_first_duplicate() {
        let duplicate_name = JsString::from_utf16(vec![0xd800, 0x2f]);
        let value = SemanticValue::Object {
            properties: PropertySlots::from(vec![
                Property {
                    name: duplicate_name.clone(),
                    value: SemanticValue::Literal {
                        value: Primitive::Number(1.0),
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: duplicate_name.clone(),
                    value: SemanticValue::Literal {
                        value: Primitive::Number(2.0),
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: "arr".into(),
                    value: SemanticValue::Array {
                        items: PropertySlots::from(vec![Property {
                            name: "0".into(),
                            value: SemanticValue::Unknown {
                                reason: "opaque item".into(),
                                resource_limit: None,
                            },
                            presence: SlotPresence::Present,
                        }]),
                        coverage: Coverage::Unknown { omitted: Some(3) },
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: "opaque".into(),
                    value: SemanticValue::Unknown {
                        reason: "opaque receiver".into(),
                        resource_limit: Some(ResourceLimit::PrimitiveCandidates),
                    },
                    presence: SlotPresence::Present,
                },
                Property {
                    name: "uncertain".into(),
                    value: SemanticValue::Literal {
                        value: Primitive::Boolean(true),
                    },
                    presence: SlotPresence::UnknownCoverage,
                },
            ]),
            coverage: Coverage::Exact,
        };
        let full = JsonConversion::default().serialize(&value).unwrap();

        for path in [
            vec![duplicate_name.clone()],
            vec!["arr".into(), "length".into()],
            vec!["arr".into(), "9".into()],
            vec!["arr".into(), "9".into(), "leaf".into()],
            vec!["opaque".into(), "leaf".into()],
            vec!["uncertain".into(), "leaf".into()],
        ] {
            let expected = slot_at_value(ValueRef::Json(&full), &path);
            let actual = slot_at_value(ValueRef::Typed(&value), &path);

            assert_eq!(actual.name(), expected.name());
            assert_eq!(actual.raw_name(), expected.raw_name());
            assert_eq!(actual.presence(), expected.presence());
            assert_eq!(actual.raw_presence(), expected.raw_presence());
            assert_eq!(actual.value_status(), expected.value_status());
            assert_eq!(actual.value_coverage(), expected.value_coverage());
            let actual_metadata = value_metadata_json(actual.value_ref());
            let expected_metadata = value_metadata_json(expected.value_ref());
            assert_eq!(actual_metadata.at("reason"), expected_metadata.at("reason"));
            assert_eq!(
                actual_metadata.at("resourceLimit"),
                expected_metadata.at("resourceLimit")
            );
            assert_eq!(actual.is_container(), expected.is_container());
        }

        let duplicate = slot_at_value(ValueRef::Typed(&value), &[duplicate_name]);
        let ValueRef::Typed(selected) = duplicate.borrowed_value().unwrap() else {
            panic!("typed selector returned JSON");
        };
        let SemanticValue::Literal {
            value: Primitive::Number(number),
        } = selected
        else {
            panic!("duplicate selector did not return first literal");
        };
        assert_eq!(*number, 1.0);
    }
}
