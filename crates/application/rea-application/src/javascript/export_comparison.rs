//! Contract boundary for exact JavaScript export-shape comparisons.

use rea_core::{
    canonical_json,
    failure::{Detail, Failure},
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "compare_javascript_export_shapes";

pub fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("export comparison input must be an object"))?;
    let left = object
        .get("left")
        .ok_or_else(|| invalid("left Evidence is required"))?;
    let right = object
        .get("right")
        .ok_or_else(|| invalid("right Evidence is required"))?;
    let left_id = evidence_id(left, "left")?;
    let right_id = evidence_id(right, "right")?;
    if left_id == right_id {
        return Err(invalid("left and right Evidence must be distinct"));
    }
    for field in [
        "left_module_path",
        "right_module_path",
        "left_export_name",
        "right_export_name",
    ] {
        if object.get(field).and_then(Value::as_str).is_none() {
            return Err(invalid(&format!("{field} must be a string")));
        }
    }
    Ok(())
}

pub fn retain_result(input: &Value, result: Value) -> Result<Value, Failure> {
    validate_input(input)?;
    if !result.is_object() {
        return Err(invalid("export comparison result must be an object"));
    }
    Ok(result)
}

/// Compare caller-selected, already-retained static export shapes.
///
/// The producer consumes the normalized shape projections supplied by the
/// authenticated adapter. It never executes JavaScript or invents a match for
/// an unresolved selector. Each side may contain `shapes` and an optional
/// `selection`; this keeps unresolved exports explicit in the result.
pub fn compare_javascript_export_shapes(input: &Value) -> Result<Value, Failure> {
    validate_input(input)?;

    let object = input
        .as_object()
        .ok_or_else(|| invalid("export comparison input must be an object"))?;
    let left = object
        .get("left")
        .ok_or_else(|| invalid("left Evidence is required"))?;
    let right = object
        .get("right")
        .ok_or_else(|| invalid("right Evidence is required"))?;
    let evidence_links = vec![
        Value::String(evidence_id(left, "left")?.to_owned()),
        Value::String(evidence_id(right, "right")?.to_owned()),
    ];

    let left_selection = selection_result(left, input, "left");
    let right_selection = selection_result(right, input, "right");
    let left_shapes = retained_shapes_for_selection(left, &left_selection);
    let right_shapes = retained_shapes_for_selection(right, &right_selection);
    let pairing = pair_shapes(&left_shapes, &right_shapes);
    let changes = build_changes(
        &left_shapes,
        &right_shapes,
        &left_selection,
        &right_selection,
        &pairing,
        &evidence_links,
    );
    let mut changes = changes;
    changes.sort_by_key(canonical_value_key);

    let summary = summary(&changes);
    let semantic = serde_json::json!({
        "left": left_selection,
        "right": right_selection,
        "property_inventories": inventories(&left_shapes, &right_shapes, &pairing),
        "summary": summary,
        "changes": changes,
        "coverage": coverage(
            left,
            right,
            &left_selection,
            &right_selection,
            &left_shapes,
            &right_shapes,
            &pairing,
            &changes,
        ),
        "evidence_links": evidence_links,
        "limitations": [
            "Return shapes are inferred from inert syntax and do not prove runtime behavior.",
            "Return variants are paired only by unique exact literal discriminants, never by source order.",
            "Dynamic values, incomplete object coverage, and ambiguous variants remain unknown.",
            "This static comparison cannot establish runtime semantics; run behavioral probes directly against the relevant application versions when that evidence is required."
        ]
    });
    let comparison_id = format!("jesc_{}", digest(&semantic)?);
    let mut result = semantic;
    result["comparison_id"] = Value::String(comparison_id);
    Ok(result)
}

fn retained_shapes(side: &Value) -> Vec<Value> {
    side.get("shapes")
        .or_else(|| side.get("static_return_shapes"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn retained_shapes_for_selection(side: &Value, selection: &Value) -> Vec<Value> {
    let direct = retained_shapes(side);
    if !direct.is_empty() {
        return direct;
    }

    let Some(node_id) = selection.get("selected_node_id").and_then(Value::as_str) else {
        return Vec::new();
    };
    let graph = graph_value(side);
    let Some(nodes) = graph.get("nodes").and_then(Value::as_array) else {
        return Vec::new();
    };
    nodes
        .iter()
        .find(|node| node.get("node_id").and_then(Value::as_str) == Some(node_id))
        .and_then(|node| node.get("observations"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|observation| {
            let properties = observation.get("properties")?;
            if properties.get("semantic_role").and_then(Value::as_str)
                != Some("export-return-shapes")
            {
                return None;
            }
            properties
                .get("static_return_shapes")
                .and_then(Value::as_array)
                .cloned()
        })
        .unwrap_or_default()
}

fn selection_result(side: &Value, input: &Value, name: &str) -> Value {
    if let Some(selection) = side.get("selection") {
        return selection.clone();
    }
    let object = input.as_object();
    let module_path = object
        .and_then(|value| value.get(&format!("{name}_module_path")))
        .cloned()
        .unwrap_or(Value::Null);
    let export_name = object
        .and_then(|value| value.get(&format!("{name}_export_name")))
        .cloned()
        .unwrap_or(Value::Null);
    let graph = graph_value(side);
    let candidates = export_candidates(&graph);
    let exact = candidates
        .iter()
        .filter(|candidate| {
            candidate.1 == module_path.as_str().unwrap_or_default()
                && candidate.2 == export_name.as_str().unwrap_or_default()
        })
        .collect::<Vec<_>>();
    let status = if exact.is_empty() {
        "missing"
    } else if exact.len() > 1 {
        "ambiguous"
    } else if !exact[0].3 {
        "unavailable"
    } else if return_shapes_for(
        &graph,
        exact[0].0.as_str(),
        module_path.as_str().unwrap_or_default(),
        export_name.as_str().unwrap_or_default(),
    )
    .is_none()
    {
        "unavailable"
    } else {
        "selected"
    };
    let selected_node_id = if status == "selected" || status == "unavailable" {
        exact
            .first()
            .map(|candidate| Value::String(candidate.0.to_owned()))
            .unwrap_or(Value::Null)
    } else {
        Value::Null
    };
    let diagnostic_candidates = if exact.is_empty() {
        let matching = candidates
            .iter()
            .filter(|candidate| {
                candidate.1 == module_path.as_str().unwrap_or_default()
                    || candidate.2 == export_name.as_str().unwrap_or_default()
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            candidates.iter().collect()
        } else {
            matching
        }
    } else {
        exact.clone()
    };
    let candidate_values = diagnostic_candidates
        .iter()
        .map(|(node_id, module, export, _)| {
            serde_json::json!({
                "node_id": node_id,
                "module_path": module,
                "export_name": export,
                "matches_requested_module": module == module_path.as_str().unwrap_or_default(),
                "matches_requested_export": export == export_name.as_str().unwrap_or_default()
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "evidence_id": side.get("evidence_id").cloned().unwrap_or(Value::Null),
        "graph_id": graph.get("graph_id").cloned().unwrap_or(Value::Null),
        "requested_module_path": module_path,
        "requested_export_name": export_name,
        "candidates": candidate_values,
        "omitted_candidates": 0,
        "status": status,
        "selected_node_id": selected_node_id
    })
}

fn graph_value(side: &Value) -> Value {
    let normalized = side.get("normalized_result").unwrap_or(side);
    normalized
        .get("graph")
        .cloned()
        .unwrap_or_else(|| normalized.clone())
}

fn export_candidates(graph: &Value) -> Vec<(String, String, String, bool)> {
    let mut candidates = BTreeMap::<String, (String, String, String, bool)>::new();
    for node in graph
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(node_id) = node.get("node_id").and_then(Value::as_str) else {
            continue;
        };
        for observation in node
            .get("observations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let properties = observation.get("properties").unwrap_or(&Value::Null);
            if properties.get("semantic_role").and_then(Value::as_str) != Some("export-binding") {
                continue;
            }
            let (Some(module), Some(export)) = (
                properties.get("module_path").and_then(Value::as_str),
                properties.get("exported_name").and_then(Value::as_str),
            ) else {
                continue;
            };
            let key = format!("{node_id}\0{module}\0{export}");
            let trusted = observation.get("evidence").is_some_and(|e| {
                e.get("authority").and_then(Value::as_str) == Some("ast-static-analysis")
                    && e.get("state").and_then(Value::as_str) == Some("observed")
                    && e.get("extractor")
                        .and_then(|x| x.get("operation"))
                        .and_then(Value::as_str)
                        == Some("recover-module-export")
            });
            candidates
                .entry(key)
                .and_modify(|entry| entry.3 |= trusted)
                .or_insert((
                    node_id.to_owned(),
                    module.to_owned(),
                    export.to_owned(),
                    trusted,
                ));
        }
    }
    let mut output = candidates.into_values().collect::<Vec<_>>();
    output.sort_by(|left, right| {
        (left.1.as_str(), left.2.as_str(), left.0.as_str()).cmp(&(
            right.1.as_str(),
            right.2.as_str(),
            right.0.as_str(),
        ))
    });
    output
}

fn return_shapes_for(
    graph: &Value,
    node_id: &str,
    module: &str,
    export: &str,
) -> Option<Vec<Value>> {
    graph
        .get("nodes")
        .and_then(Value::as_array)?
        .iter()
        .find(|node| node.get("node_id").and_then(Value::as_str) == Some(node_id))?
        .get("observations")
        .and_then(Value::as_array)?
        .iter()
        .find_map(|observation| {
            let properties = observation.get("properties")?;
            (properties.get("semantic_role").and_then(Value::as_str)
                == Some("export-return-shapes")
                && properties.get("module_path").and_then(Value::as_str) == Some(module)
                && properties.get("exported_name").and_then(Value::as_str) == Some(export)
                && observation.get("evidence").is_some_and(|evidence| {
                    evidence.get("authority").and_then(Value::as_str)
                        == Some("static-relationship-inference")
                        && evidence.get("state").and_then(Value::as_str) == Some("inferred")
                        && evidence
                            .get("extractor")
                            .and_then(|extractor| extractor.get("operation"))
                            .and_then(Value::as_str)
                            == Some("recover-export-return-shapes")
                }))
            .then(|| {
                properties
                    .get("static_return_shapes")
                    .and_then(Value::as_array)
                    .cloned()
            })
            .flatten()
        })
}

fn build_changes(
    left: &[Value],
    right: &[Value],
    left_selection: &Value,
    right_selection: &Value,
    pairing: &[(usize, usize, Value)],
    evidence_links: &[Value],
) -> Vec<Value> {
    if !is_selected(left_selection) || !is_selected(right_selection) {
        return vec![unknown_change(
            "Both selectors must resolve one exact export with trusted static return shapes before comparison.",
            evidence_links,
        )];
    }
    if left.is_empty() && right.is_empty() {
        return vec![unknown_change(
            "At least one selected export has no retained direct return shape.",
            evidence_links,
        )];
    }

    let paired_left: BTreeSet<usize> = pairing.iter().map(|(index, _, _)| *index).collect();
    let paired_right: BTreeSet<usize> = pairing.iter().map(|(_, index, _)| *index).collect();
    let mut changes = Vec::new();
    for (left_index, right_index, discriminant) in pairing {
        if let (Some(left_shape), Some(right_shape)) =
            (left.get(*left_index), right.get(*right_index))
        {
            changes.extend(diff_shape(
                left_shape,
                right_shape,
                &discriminant,
                evidence_links,
            ));
        }
    }
    for (index, shape) in left.iter().enumerate() {
        if !paired_left.contains(&index) {
            changes.push(unpaired_change("left", shape, evidence_links));
        }
    }
    for (index, shape) in right.iter().enumerate() {
        if !paired_right.contains(&index) {
            changes.push(unpaired_change("right", shape, evidence_links));
        }
    }
    changes
}

fn is_selected(selection: &Value) -> bool {
    selection.get("status").and_then(Value::as_str) == Some("selected")
}

fn pair_shapes(left: &[Value], right: &[Value]) -> Vec<(usize, usize, Value)> {
    let left_keys = discriminants(left);
    let right_keys = discriminants(right);
    let mut pairs = Vec::new();
    for (key, left_occurrences) in &left_keys {
        let Some(right_occurrences) = right_keys.get(key) else {
            continue;
        };
        if left_occurrences.len() != 1 || right_occurrences.len() != 1 {
            continue;
        }
        let (left_index, discriminant) = &left_occurrences[0];
        let (right_index, _) = &right_occurrences[0];
        pairs.push((*left_index, *right_index, discriminant.clone()));
    }
    pairs.sort_by_key(|(_, _, discriminant)| canonical_value_key(discriminant));
    pairs
}

fn discriminants(shapes: &[Value]) -> BTreeMap<String, Vec<(usize, Value)>> {
    let mut output: BTreeMap<String, Vec<(usize, Value)>> = BTreeMap::new();
    for (index, shape) in shapes.iter().enumerate() {
        let Some(fields) = shape.get("fields").and_then(Value::as_array) else {
            continue;
        };
        for field in fields {
            if field.get("presence").and_then(Value::as_str) != Some("present")
                || field.get("state").and_then(Value::as_str) != Some("literal")
            {
                continue;
            }
            let Some(path) = field.get("path").and_then(Value::as_str) else {
                continue;
            };
            let Some(value) = field.get("value") else {
                continue;
            };
            let discriminant = serde_json::json!({"path": path, "value": value});
            output
                .entry(canonical_value_key(&discriminant))
                .or_default()
                .push((index, discriminant));
        }
    }
    output
}

fn diff_shape(left: &Value, right: &Value, discriminant: &Value, links: &[Value]) -> Vec<Value> {
    let left_fields = fields_by_path(left);
    let right_fields = fields_by_path(right);
    let mut paths = BTreeSet::new();
    paths.extend(left_fields.keys().cloned());
    paths.extend(right_fields.keys().cloned());
    let mut changes = Vec::new();
    for path in paths {
        let left_field = left_fields.get(&path);
        let right_field = right_fields.get(&path);
        let left_presence = field_presence(left, left_field, &path);
        let right_presence = field_presence(right, right_field, &path);
        let status = if left_presence == "unknown-coverage" || right_presence == "unknown-coverage"
        {
            Some("unknown")
        } else if left_presence == "absent" && right_presence == "absent" {
            None
        } else if left_presence == "absent" {
            Some("added")
        } else if right_presence == "absent" {
            Some("removed")
        } else if left_field == right_field {
            None
        } else if field_state(left_field) == Some("unknown")
            || field_state(right_field) == Some("unknown")
        {
            Some("unknown")
        } else {
            Some("changed")
        };
        if let Some(status) = status {
            changes.push(change(
                status,
                &path,
                Some(discriminant),
                left_presence,
                right_presence,
                value_availability(left_field),
                value_availability(right_field),
                source_range(left),
                source_range(right),
                links,
                status == "unknown",
            ));
        }
    }
    changes
}

fn fields_by_path(shape: &Value) -> BTreeMap<String, Value> {
    shape
        .get("fields")
        .and_then(Value::as_array)
        .map(|fields| {
            fields
                .iter()
                .filter_map(|field| {
                    field
                        .get("path")
                        .and_then(Value::as_str)
                        .map(|path| (path.to_owned(), field.clone()))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn field_presence(shape: &Value, field: Option<&Value>, path: &str) -> &'static str {
    if let Some(presence) = field
        .and_then(|value| value.get("presence"))
        .and_then(Value::as_str)
    {
        return match presence {
            "present" => "present",
            "absent" => "absent",
            "unknown-coverage" => "unknown-coverage",
            _ => "unknown-coverage",
        };
    }
    let parent = path.rsplit_once('/').map(|(parent, _)| parent);
    if parent.is_some_and(|parent| {
        shape
            .get("property_coverage")
            .and_then(Value::as_array)
            .is_some_and(|coverage| {
                coverage.iter().any(|entry| {
                    entry.get("path").and_then(Value::as_str) == Some(parent)
                        && entry.get("status").and_then(Value::as_str) == Some("complete")
                })
            })
    }) {
        "absent"
    } else {
        "unknown-coverage"
    }
}

fn field_state(field: Option<&Value>) -> Option<&str> {
    field
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
}

fn value_availability(field: Option<&Value>) -> Value {
    let Some(field) = field else {
        return serde_json::json!({"availability": "absent"});
    };
    match field_state(Some(field)) {
        Some("literal") => {
            serde_json::json!({"availability": "literal", "value": field.get("value").cloned().unwrap_or(Value::Null)})
        }
        Some("union") => {
            serde_json::json!({"availability": "union", "values": field.get("value").cloned().unwrap_or_else(|| Value::Array(Vec::new()))})
        }
        _ => {
            serde_json::json!({"availability": "unknown", "reason": field.get("reason").and_then(Value::as_str).unwrap_or("Static field value is unknown.")})
        }
    }
}

fn source_range(shape: &Value) -> Value {
    shape.get("source_range").cloned().unwrap_or(Value::Null)
}

fn unpaired_change(side: &str, shape: &Value, links: &[Value]) -> Value {
    let left = if side == "left" {
        serde_json::json!({"availability": "unknown", "reason": "Left return variant has no unique exact cross-version pairing."})
    } else {
        serde_json::json!({"availability": "unknown", "reason": "No left return variant was uniquely paired with this right variant."})
    };
    let right = if side == "right" {
        serde_json::json!({"availability": "unknown", "reason": "Right return variant has no unique exact cross-version pairing."})
    } else {
        serde_json::json!({"availability": "unknown", "reason": "No right return variant was uniquely paired with this left variant."})
    };
    change(
        "unknown",
        "",
        None,
        "unknown-coverage",
        "unknown-coverage",
        left,
        right,
        if side == "left" {
            source_range(shape)
        } else {
            Value::Null
        },
        if side == "right" {
            source_range(shape)
        } else {
            Value::Null
        },
        links,
        true,
    )
}

fn unknown_change(reason: &str, links: &[Value]) -> Value {
    change(
        "unknown",
        "",
        None,
        "unknown-coverage",
        "unknown-coverage",
        serde_json::json!({"availability": "unknown", "reason": reason}),
        serde_json::json!({"availability": "unknown", "reason": reason}),
        Value::Null,
        Value::Null,
        links,
        true,
    )
}

fn change(
    status: &str,
    path: &str,
    discriminant: Option<&Value>,
    left_presence: &str,
    right_presence: &str,
    left: Value,
    right: Value,
    left_range: Value,
    right_range: Value,
    links: &[Value],
    unknown: bool,
) -> Value {
    let limitations = if unknown {
        vec![Value::String(
            "The static value or relevant parent-property coverage is incomplete.".to_owned(),
        )]
    } else {
        Vec::new()
    };
    let semantic = serde_json::json!({"status": status, "path": path, "discriminant": discriminant.cloned().unwrap_or(Value::Null), "presence": {"left": left_presence, "right": right_presence}, "left": left, "right": right, "left_source_range": left_range, "right_source_range": right_range, "evidence_links": links, "limitations": limitations});
    let id = format!(
        "jesc_change_{}",
        digest(&semantic).unwrap_or_else(|_| "invalid".to_owned())
    );
    let mut result = semantic;
    result["change_id"] = Value::String(id);
    result
}

fn inventories(left: &[Value], right: &[Value], pairing: &[(usize, usize, Value)]) -> Vec<Value> {
    let left_pairs: BTreeMap<usize, &Value> = pairing
        .iter()
        .map(|(left_index, _, discriminant)| (*left_index, discriminant))
        .collect();
    let right_pairs: BTreeMap<usize, &Value> = pairing
        .iter()
        .map(|(_, right_index, discriminant)| (*right_index, discriminant))
        .collect();
    left.iter()
        .enumerate()
        .map(|(index, shape)| inventory("left", index, shape, left_pairs.get(&index).copied()))
        .chain(right.iter().enumerate().map(|(index, shape)| {
            inventory("right", index, shape, right_pairs.get(&index).copied())
        }))
        .collect()
}

fn inventory(side: &str, index: usize, shape: &Value, discriminant: Option<&Value>) -> Value {
    serde_json::json!({
        "side": side,
        "variant_index": index,
        "discriminant": discriminant.cloned().unwrap_or(Value::Null),
        "paired": discriminant.is_some(),
        "source_range": source_range(shape),
        "properties": inventory_properties(shape),
        "property_coverage": shape
            .get("property_coverage")
            .and_then(Value::as_array)
            .map(|entries| entries.iter().map(|entry| serde_json::json!({
                "path": entry.get("path").cloned().unwrap_or(Value::Null),
                "status": entry.get("status").cloned().unwrap_or(Value::Null)
            })).collect::<Vec<_>>())
            .unwrap_or_default()
    })
}

fn inventory_properties(shape: &Value) -> Vec<String> {
    let mut properties = BTreeSet::new();
    for field in shape
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if field_presence(
            shape,
            Some(field),
            field
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        ) == "present"
            && field
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| !path.is_empty())
        {
            if let Some(path) = field.get("path").and_then(Value::as_str) {
                properties.insert(path.to_owned());
            }
        }
    }
    for coverage in shape
        .get("property_coverage")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(path) = coverage
            .get("path")
            .and_then(Value::as_str)
            .filter(|path| !path.is_empty())
        {
            properties.insert(path.to_owned());
        }
    }
    properties.into_iter().collect()
}

fn summary(changes: &[Value]) -> Value {
    let count = |status: &str| {
        changes
            .iter()
            .filter(|change| change.get("status").and_then(Value::as_str) == Some(status))
            .count()
    };
    serde_json::json!({"added": count("added"), "removed": count("removed"), "changed": count("changed"), "unknown": count("unknown")})
}

fn coverage(
    left_side: &Value,
    right_side: &Value,
    left_selection: &Value,
    right_selection: &Value,
    left: &[Value],
    right: &[Value],
    pairing: &[(usize, usize, Value)],
    changes: &[Value],
) -> Value {
    let left_graph_status = graph_status(left_side);
    let right_graph_status = graph_status(right_side);
    let omitted_candidates =
        omitted_candidates(left_selection).saturating_add(omitted_candidates(right_selection));
    let left_source = return_shape_coverage(left_side, left_selection);
    let right_source = return_shape_coverage(right_side, right_selection);
    let truncated = omitted_candidates > 0
        || source_is_truncated(&left_source)
        || source_is_truncated(&right_source);
    let partial = left_selection.get("status").and_then(Value::as_str) != Some("selected")
        || right_selection.get("status").and_then(Value::as_str) != Some("selected")
        || left_graph_status != "complete"
        || right_graph_status != "complete"
        || has_partial_property_coverage(left)
        || has_partial_property_coverage(right)
        || pairing.len() < left.len()
        || pairing.len() < right.len()
        || changes
            .iter()
            .any(|change| change.get("status").and_then(Value::as_str) == Some("unknown"));
    serde_json::json!({
        "status": if truncated { "truncated" } else if partial { "partial" } else { "complete-within-inputs" },
        "left_graph_status": left_graph_status,
        "right_graph_status": right_graph_status,
        "paired_variants": pairing.len(),
        "unpaired_left_variants": left.len().saturating_sub(pairing.iter().filter(|(index, _, _)| *index < left.len()).count()),
        "unpaired_right_variants": right.len().saturating_sub(pairing.iter().filter(|(_, index, _)| *index < right.len()).count()),
        "omitted_left_variants": 0,
        "omitted_right_variants": 0,
        "left_source_omitted_variants": source_count(&left_source, "omitted_return_sites"),
        "right_source_omitted_variants": source_count(&right_source, "omitted_return_sites"),
        "left_omitted_fields": source_count(&left_source, "omitted_fields").unwrap_or(0),
        "right_omitted_fields": source_count(&right_source, "omitted_fields").unwrap_or(0),
        "left_omitted_property_coverage": source_count(&left_source, "omitted_property_coverage").unwrap_or(0),
        "right_omitted_property_coverage": source_count(&right_source, "omitted_property_coverage").unwrap_or(0),
        "omitted_candidates": omitted_candidates,
        "omitted_changes": 0
    })
}

fn graph_status(side: &Value) -> &'static str {
    let graph = graph_value(side);
    match graph
        .get("coverage")
        .and_then(|coverage| coverage.get("status"))
        .and_then(Value::as_str)
    {
        Some("complete") => "complete",
        Some("partial") => "partial",
        Some("unknown") => "unknown",
        Some("unavailable") => "unavailable",
        _ => "complete",
    }
}

fn omitted_candidates(selection: &Value) -> usize {
    selection
        .get("omitted_candidates")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize
}

fn return_shape_coverage(side: &Value, selection: &Value) -> Value {
    let Some(node_id) = selection.get("selected_node_id").and_then(Value::as_str) else {
        return Value::Null;
    };
    graph_value(side)
        .get("nodes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|node| node.get("node_id").and_then(Value::as_str) == Some(node_id))
        .and_then(|node| node.get("observations"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find_map(|observation| {
            let properties = observation.get("properties")?;
            (properties.get("semantic_role").and_then(Value::as_str)
                == Some("export-return-shapes"))
            .then(|| {
                properties
                    .get("return_shape_coverage")
                    .cloned()
                    .unwrap_or(Value::Null)
            })
        })
        .unwrap_or(Value::Null)
}

fn source_count(source: &Value, field: &str) -> Option<usize> {
    source
        .get(field)
        .and_then(Value::as_u64)
        .map(|value| value as usize)
}

fn source_is_truncated(source: &Value) -> bool {
    source.get("status").and_then(Value::as_str) == Some("truncated")
        || source.get("projection_complete").and_then(Value::as_bool) == Some(false)
        || source_count(source, "omitted_fields").unwrap_or(0) > 0
        || source_count(source, "omitted_property_coverage").unwrap_or(0) > 0
}

fn has_partial_property_coverage(shapes: &[Value]) -> bool {
    shapes.iter().any(|shape| {
        shape
            .get("property_coverage")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|entry| entry.get("status").and_then(Value::as_str) == Some("partial"))
            || shape
                .get("fields")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|field| {
                    field_presence(
                        shape,
                        Some(field),
                        field
                            .get("path")
                            .and_then(Value::as_str)
                            .unwrap_or_default(),
                    ) == "unknown-coverage"
                })
    })
}

fn canonical_value_key(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_string())
}

fn digest(value: &Value) -> Result<String, Failure> {
    canonical_json::digest(value).map_err(|error| invalid(&error.to_string()))
}

fn evidence_id<'a>(value: &'a Value, side: &str) -> Result<&'a str, Failure> {
    value
        .get("evidence_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| invalid(&format!("{side} Evidence must include evidence_id")))
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide two distinct authenticated JavaScript graph Evidence records and selectors."
            .into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Value {
        serde_json::json!({
            "left": {"evidence_id": "ev_left"},
            "right": {"evidence_id": "ev_right"},
            "left_module_path": "main.js",
            "left_export_name": "default",
            "right_module_path": "main.js",
            "right_export_name": "default"
        })
    }

    #[test]
    fn accepts_distinct_evidence_and_selectors() {
        validate_input(&input()).expect("valid comparison input");
        assert_eq!(
            retain_result(&input(), serde_json::json!({"changes": []})).expect("result retained")
                ["changes"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );
    }

    #[test]
    fn rejects_same_evidence_identity() {
        let mut duplicate = input();
        duplicate["right"]["evidence_id"] = serde_json::json!("ev_left");
        assert!(validate_input(&duplicate).is_err());
    }

    fn shape(value: Value) -> Value {
        serde_json::json!({
            "source_range": {"start": {"line": 1, "column": 0}, "end": {"line": 1, "column": 4}},
            "fields": [
                {"path": "/kind", "presence": "present", "state": "literal", "value": "item", "reason": null},
                value
            ],
            "property_coverage": []
        })
    }

    fn comparison_input(left_shapes: Vec<Value>, right_shapes: Vec<Value>) -> Value {
        serde_json::json!({
            "left": {"evidence_id": "ev_left", "selection": {"status": "selected"}, "shapes": left_shapes},
            "right": {"evidence_id": "ev_right", "selection": {"status": "selected"}, "shapes": right_shapes},
            "left_module_path": "main.js",
            "left_export_name": "default",
            "right_module_path": "main.js",
            "right_export_name": "default"
        })
    }

    #[test]
    fn compares_added_removed_changed_and_unknown_exports() {
        let left = vec![shape(serde_json::json!({
            "path": "/value", "presence": "present", "state": "literal", "value": 1, "reason": null
        }))];
        let right = vec![shape(serde_json::json!({
            "path": "/value", "presence": "present", "state": "literal", "value": 2, "reason": null
        }))];
        let changed = compare_javascript_export_shapes(&comparison_input(left, right))
            .expect("changed shape comparison");
        assert_eq!(changed["summary"]["changed"], 1);
        assert_eq!(
            changed["evidence_links"],
            serde_json::json!(["ev_left", "ev_right"])
        );

        let added = compare_javascript_export_shapes(&comparison_input(
            vec![shape(serde_json::json!({
                "path": "/value", "presence": "absent", "state": "unknown", "value": null, "reason": "not present"
            }))],
            vec![shape(serde_json::json!({
                "path": "/value", "presence": "present", "state": "literal", "value": 2, "reason": null
            }))],
        ))
        .expect("added shape comparison");
        assert_eq!(added["summary"]["added"], 1);

        let removed = compare_javascript_export_shapes(&comparison_input(
            vec![shape(serde_json::json!({
                "path": "/value", "presence": "present", "state": "literal", "value": 2, "reason": null
            }))],
            vec![shape(serde_json::json!({
                "path": "/value", "presence": "absent", "state": "unknown", "value": null, "reason": "not present"
            }))],
        ))
        .expect("removed shape comparison");
        assert_eq!(removed["summary"]["removed"], 1);

        let unknown = compare_javascript_export_shapes(&comparison_input(
            vec![shape(serde_json::json!({
                "path": "/value", "presence": "present", "state": "unknown", "value": null, "reason": "dynamic"
            }))],
            vec![shape(serde_json::json!({
                "path": "/value", "presence": "present", "state": "literal", "value": 2, "reason": null
            }))],
        ))
        .expect("unknown shape comparison");
        assert_eq!(unknown["summary"]["unknown"], 1);
    }
}
