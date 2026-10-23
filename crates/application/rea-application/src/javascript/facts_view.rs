//! Projection of caller-selected JavaScript observation properties.
//!
//! The facts view reads retained graph nodes only.  It does not resolve paths,
//! merge observations, or infer values that the producer did not retain.

use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// A bounded page of retained JavaScript observation facts.
#[derive(Debug, PartialEq)]
pub struct FactPage {
    pub rows: Vec<Value>,
    pub total: usize,
    pub offset: usize,
}

/// Project exact JavaScript facts from the retained application graph.
pub fn project(nodes: &[Value], view: &Value) -> Result<FactPage, String> {
    let (offset, limit) = page_arguments(view)?;
    let filters = FactFilters::from_view(view);
    let property_keys = requested_property_keys(view);
    let include_available_property_keys = view
        .get("include_available_property_keys")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    if filters.matches_nothing() {
        return Ok(FactPage {
            rows: Vec::new(),
            total: 0,
            offset,
        });
    }

    let mut rows = Vec::new();
    let mut total = 0;

    for node in nodes {
        if !filters.matches_node(node) {
            continue;
        }

        for observation in observations(node) {
            if !filters.matches_observation(observation) {
                continue;
            }

            if total >= offset && rows.len() < limit {
                rows.push(fact_row(
                    node,
                    observation,
                    &property_keys,
                    include_available_property_keys,
                ));
            }

            total += 1;
        }
    }

    Ok(FactPage {
        rows,
        total,
        offset,
    })
}

struct FactFilters {
    paths: Option<BTreeSet<String>>,
    kinds: Option<BTreeSet<String>>,
}

impl FactFilters {
    fn from_view(view: &Value) -> Self {
        let where_object = view.get("where").and_then(Value::as_object);

        Self {
            paths: string_set(where_object.and_then(|value| value.get("paths"))),
            kinds: string_set(where_object.and_then(|value| value.get("kinds"))),
        }
    }

    fn matches_nothing(&self) -> bool {
        self.paths.as_ref().is_some_and(BTreeSet::is_empty)
            || self.kinds.as_ref().is_some_and(BTreeSet::is_empty)
    }

    fn matches_node(&self, node: &Value) -> bool {
        self.kinds.as_ref().is_none_or(|kinds| {
            node.get("kind")
                .and_then(Value::as_str)
                .is_some_and(|kind| kinds.contains(kind))
        })
    }

    fn matches_observation(&self, observation: &Value) -> bool {
        self.paths.as_ref().is_none_or(|paths| {
            observation_path(observation).is_some_and(|path| paths.contains(path))
        })
    }
}

fn page_arguments(view: &Value) -> Result<(usize, usize), String> {
    let offset = parse_usize(view, "offset", 0)?;
    let limit = parse_usize(view, "limit", 64)?;

    if limit == 0 {
        return Err("JavaScript facts view limit must be positive.".to_owned());
    }

    Ok((offset, limit))
}

fn parse_usize(view: &Value, field: &str, default: u64) -> Result<usize, String> {
    let value = view.get(field).and_then(Value::as_u64).unwrap_or(default);
    usize::try_from(value).map_err(|_| format!("JavaScript facts view {field} is too large."))
}

fn string_set(value: Option<&Value>) -> Option<BTreeSet<String>> {
    value.map(|value| {
        value
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn requested_property_keys(view: &Value) -> Vec<String> {
    let mut keys = Vec::new();

    for key in view
        .get("property_keys")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !keys.iter().any(|existing| existing == key) {
            keys.push(key.to_owned());
        }
    }

    keys
}

fn observations(node: &Value) -> impl Iterator<Item = &Value> {
    node.get("observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
}

fn fact_row(
    node: &Value,
    observation: &Value,
    property_keys: &[String],
    include_available_property_keys: bool,
) -> Value {
    let properties = selected_properties(observation, property_keys);
    let mut row = Map::new();
    row.insert("node_id".to_owned(), member_or_null(node, "node_id"));
    row.insert("kind".to_owned(), member_or_null(node, "kind"));
    row.insert("identity".to_owned(), member_or_null(node, "identity"));
    row.insert(
        "observation_id".to_owned(),
        member_or_null(observation, "observation_id"),
    );
    row.insert(
        "source_map_reference".to_owned(),
        member_or_null(observation, "source_map_reference"),
    );
    row.insert("properties".to_owned(), Value::Object(properties));
    row.insert(
        "evidence".to_owned(),
        member_or_null(observation, "evidence"),
    );

    if include_available_property_keys {
        row.insert(
            "available_property_keys".to_owned(),
            Value::Array(available_property_keys(observation)),
        );
    }

    Value::Object(row)
}

fn member_or_null(value: &Value, member: &str) -> Value {
    value.get(member).cloned().unwrap_or(Value::Null)
}

fn selected_properties(observation: &Value, property_keys: &[String]) -> Map<String, Value> {
    let Some(properties) = observation.get("properties").and_then(Value::as_object) else {
        return Map::new();
    };

    property_keys
        .iter()
        .filter_map(|key| {
            properties
                .get(key)
                .cloned()
                .map(|value| (key.clone(), value))
        })
        .collect()
}

fn available_property_keys(observation: &Value) -> Vec<Value> {
    let mut keys = observation
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| properties.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    keys.sort();
    keys.into_iter().map(Value::String).collect()
}

/// Return only the exact retained artifact path or source-range source string.
fn observation_path(observation: &Value) -> Option<&str> {
    let location = observation.get("evidence")?.get("location")?;
    if location.get("available").and_then(Value::as_bool) != Some(true) {
        return None;
    }

    let value = location.get("value")?;
    match value.get("kind").and_then(Value::as_str) {
        Some("artifact-path") => value.get("path").and_then(Value::as_str),
        Some("source-range") => value.get("source").and_then(Value::as_str),
        _ => None,
    }
}
