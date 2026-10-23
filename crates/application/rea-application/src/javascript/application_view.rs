//! Projection of retained JavaScript application Evidence.
//!
//! This module deliberately reads only the authenticated normalized result of
//! the parent Evidence.  It does not reopen the artifact or reconstruct a
//! graph while answering a view request.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const PARENT_OPERATION: &str = "analyze_javascript_application";
const MODULE_KINDS: [&str; 3] = ["javascript-asset", "javascript-module", "source-module"];
const MESSAGE_LIMIT: usize = 256 * 1024;

pub fn project(parent: &Value, view: &Value) -> Result<Value, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
    if !record.operation_matches(PARENT_OPERATION) {
        return Err(invalid(
            "JavaScript application view requires analyze_javascript_application Evidence.",
        ));
    }

    let report: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "JavaScript application normalized result is invalid: {error}"
            ))
        })?;
    let graph = report
        .get("graph")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("JavaScript application result has no graph."))?;
    let nodes = graph
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("JavaScript application graph has no nodes."))?;
    let shared = shared_fields(&record, &report, graph);
    let kind = view
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| incompatible("JavaScript application Evidence supports summary, module item/page, javascript, and javascript-facts views."))?;

    match kind {
        "summary" => Ok(summary(view, &report, graph, nodes, shared)),
        "javascript" => javascript_page(view, nodes, shared),
        "javascript-facts" => javascript_facts(view, nodes, shared),
        "item" => module_item_view(view, nodes, shared),
        "page" => module_page_view(view, nodes, shared),
        _ => Err(incompatible(
            "JavaScript application Evidence supports summary, module item/page, javascript, and javascript-facts views.",
        )),
    }
}

fn summary(
    view: &Value,
    report: &Value,
    graph: &Map<String, Value>,
    nodes: &[Value],
    mut shared: Value,
) -> Value {
    let module_count = nodes.iter().filter(|node| is_module(node)).count();
    let semantic_coverage = report
        .get("semantic_graph")
        .and_then(|value| value.get("coverage"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut semantic = semantic_coverage;
    if let Some(families) = semantic.get_mut("families").and_then(Value::as_array_mut) {
        for family in families {
            if let Some(object) = family.as_object_mut() {
                let unknown_count = object
                    .get("unknown_ids")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len);
                object.remove("unknown_ids");
                object.insert("unknown_count".into(), json!(unknown_count));
            }
        }
    }
    let coverage = json!({
        "application": graph.get("coverage").cloned().unwrap_or(Value::Null),
        "semantic": semantic,
        "application_unknowns": nodes.iter().filter(|node| node.get("kind").and_then(Value::as_str) == Some("unknown")).count(),
        "semantic_unknowns": report.get("semantic_graph").and_then(|value| value.get("unknowns")).and_then(Value::as_array).map_or(0, Vec::len),
    });
    let body = json!({
        "kind": "summary",
        "view": view,
        "summary": {
            "input_path": report.get("input_path").cloned().unwrap_or(Value::Null),
            "format": report.get("format").cloned().unwrap_or(Value::Null),
            "root_artifact_sha256": report.get("root_artifact_sha256").cloned().unwrap_or(Value::Null),
            "source_selection": report.get("source_selection").cloned().unwrap_or(Value::Null),
            "statistics": report.get("statistics").cloned().unwrap_or(Value::Null),
            "electron": report.get("summary").cloned().unwrap_or(Value::Null),
            "coverage": coverage,
            "limitation_count": report.get("limitations").and_then(Value::as_array).map_or(0, Vec::len),
        },
        "coverage": complete_coverage(module_count, nodes.len()),
    });
    shared
        .as_object_mut()
        .expect("shared fields are an object")
        .extend(body.as_object().expect("summary is an object").clone());
    shared
}

fn javascript_page(view: &Value, nodes: &[Value], mut shared: Value) -> Result<Value, Failure> {
    let (offset, limit) = page_arguments(view)?;
    let entries = module_page(nodes, offset, limit, view.get("where"));
    let rows = entries
        .items
        .iter()
        .map(module_reference)
        .collect::<Vec<_>>();
    let body = json!({"kind":"javascript","view":view,"rows":rows,"source_coverage":source_coverage(nodes),"coverage":page_coverage(offset, entries.items.len(), entries.total)});
    shared
        .as_object_mut()
        .expect("shared fields are an object")
        .extend(
            body.as_object()
                .expect("javascript page is an object")
                .clone(),
        );
    Ok(shared)
}

fn module_page_view(view: &Value, nodes: &[Value], mut shared: Value) -> Result<Value, Failure> {
    if view.get("collection").and_then(Value::as_str) != Some("modules") {
        return Err(incompatible(
            "Section and symbol collections apply to inspect_binary_layout Evidence.",
        ));
    }
    let (offset, limit) = page_arguments(view)?;
    let entries = module_page(nodes, offset, limit, view.get("where"));
    let items = entries
        .items
        .iter()
        .map(|entry| {
            json!({
                "node_id": entry.node_id(), "kind": entry.kind(), "path": entry.path(),
            })
        })
        .collect::<Vec<_>>();
    let body = json!({"kind":"page","view":view,"items":items,"coverage":page_coverage(offset, entries.items.len(), entries.total)});
    shared
        .as_object_mut()
        .expect("shared fields are an object")
        .extend(body.as_object().expect("module page is an object").clone());
    Ok(shared)
}

fn module_item_view(view: &Value, nodes: &[Value], mut shared: Value) -> Result<Value, Failure> {
    if view.get("collection").and_then(Value::as_str) != Some("modules") {
        return Err(incompatible(
            "Section and symbol collections apply to inspect_binary_layout Evidence.",
        ));
    }
    let entries = module_page(nodes, 0, usize::MAX, None).items;
    let selector = view
        .get("selector")
        .ok_or_else(|| incompatible("Module items are selected by exact path or node_id."))?;
    let matches = entries
        .iter()
        .filter(|entry| selector_matches(entry, selector))
        .collect::<Vec<_>>();
    let selected = if let Some(node_id) = selector.get("node_id").and_then(Value::as_str) {
        matches.first().ok_or_else(|| invalid(&format!("No module has node_id {node_id:?}. Page the modules collection to inspect available identities.")))?
    } else if let Some(path) = selector.get("path").and_then(Value::as_str) {
        match matches.as_slice() {
            [] => {
                return Err(invalid(&format!(
                    "No module has path {path:?}. Page the modules collection to inspect exact paths and node_id values."
                )));
            }
            [entry] => entry,
            many => {
                return Err(invalid(&format!(
                    "Multiple modules have path {path:?}; select one by node_id. Matches: {}",
                    many.iter()
                        .map(|entry| entry.node_id())
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
        }
    } else {
        return Err(incompatible(
            "Module items are selected by exact path or node_id.",
        ));
    };
    let body = json!({"kind":"item","view":view,"item":module_item(selected),"coverage":complete_coverage(1, entries.len())});
    shared
        .as_object_mut()
        .expect("shared fields are an object")
        .extend(body.as_object().expect("module item is an object").clone());
    Ok(shared)
}

fn javascript_facts(view: &Value, nodes: &[Value], mut shared: Value) -> Result<Value, Failure> {
    let facts =
        crate::javascript::facts_view::project(nodes, view).map_err(|message| invalid(&message))?;
    let examined = facts.rows.len();
    let body = json!({
        "kind":"javascript-facts",
        "view":view,
        "rows":facts.rows,
        "source_coverage":source_coverage(nodes),
        "coverage":page_coverage(facts.offset, examined, facts.total)
    });
    shared
        .as_object_mut()
        .expect("shared fields are an object")
        .extend(body.as_object().expect("facts view is an object").clone());
    Ok(shared)
}

#[derive(Clone)]
struct Entry {
    node: Value,
    path: Option<String>,
}
impl Entry {
    fn node_id(&self) -> &str {
        self.node
            .get("node_id")
            .and_then(Value::as_str)
            .unwrap_or("")
    }
    fn kind(&self) -> &str {
        self.node.get("kind").and_then(Value::as_str).unwrap_or("")
    }
    fn path(&self) -> Option<&str> {
        self.path.as_deref()
    }
}
struct Page {
    items: Vec<Entry>,
    total: usize,
}

fn module_page(nodes: &[Value], offset: usize, limit: usize, where_value: Option<&Value>) -> Page {
    let where_object = where_value.and_then(Value::as_object);
    let where_kind = where_object
        .and_then(|value| value.get("kind"))
        .and_then(Value::as_str);
    let where_path = where_object
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str);
    let mut items = Vec::new();
    let mut total = 0;
    for node in nodes.iter().filter(|node| is_module(node)) {
        let entry = Entry {
            path: module_path(node),
            node: node.clone(),
        };
        if where_kind.is_some_and(|kind| entry.kind() != kind)
            || where_path.is_some_and(|path| entry.path() != Some(path))
        {
            continue;
        }
        if total >= offset && items.len() < limit {
            items.push(entry);
        }
        total += 1;
    }
    Page { items, total }
}

fn module_item(entry: &Entry) -> Value {
    let node = &entry.node;
    let observations = node
        .get("observations")
        .cloned()
        .unwrap_or_else(|| json!([]));
    json!({"node_id":node.get("node_id"),"kind":node.get("kind"),"path":entry.path(),"identity":node.get("identity"),"hashes":node_hashes(node),"exports":export_names(node),"source_ranges":source_ranges(node),"observations":observations})
}

fn module_reference(entry: &Entry) -> Value {
    let observations = entry
        .node
        .get("observations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut basis = BTreeSet::new();
    let mut ranges = 0;
    for observation in &observations {
        if observation
            .get("evidence")
            .and_then(|e| e.get("location"))
            .and_then(source_range)
            .is_some()
        {
            ranges += 1;
        }
        if let Some(evidence) = observation.get("evidence").and_then(Value::as_object) {
            basis.insert(format!(
                "{}:{}:{}",
                evidence
                    .get("authority")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                evidence.get("state").and_then(Value::as_str).unwrap_or(""),
                evidence
                    .get("confidence")
                    .and_then(Value::as_str)
                    .unwrap_or("")
            ));
        }
    }
    let basis = basis.into_iter().map(|value| { let mut parts = value.splitn(3, ':'); json!({"authority":parts.next().unwrap_or(""),"state":parts.next().unwrap_or(""),"confidence":parts.next().unwrap_or("")}) }).collect::<Vec<_>>();
    json!({"node_id":entry.node.get("node_id"),"kind":entry.node.get("kind"),"path":entry.path(),"identity":entry.node.get("identity"),"retained_source_range_count":ranges,"basis":basis})
}

fn shared_fields(record: &EvidenceRecord, report: &Value, graph: &Map<String, Value>) -> Value {
    let parent_id = record.evidence_id();
    let mut limitations = strings(report.get("limitations"));
    limitations.extend(strings(graph.get("limitations")));
    limitations.extend(strings(
        report
            .get("semantic_graph")
            .and_then(|value| value.get("limitations")),
    ));
    let mut unknowns = coverage_unknowns(report, graph);
    unknowns.extend(limitations.clone());
    json!({"parent_evidence_id":parent_id,"parent_operation":PARENT_OPERATION,"parent_digest":parent_id.strip_prefix("ev_").unwrap_or(parent_id),"artifact":{"path":report.get("input_path"),"sha256":report.get("root_artifact_sha256")},"limitations":bounded_messages(limitations, parent_id),"unknowns":bounded_messages(unknowns, parent_id)})
}

fn source_coverage(nodes: &[Value]) -> Value {
    let application_unknown_count = nodes
        .iter()
        .filter(|node| node.get("kind").and_then(Value::as_str) == Some("unknown"))
        .count();
    json!({"application":Value::Null,"semantic":Value::Null,"application_unknown_count":application_unknown_count,"semantic_unknown_count":0})
}

fn coverage_unknowns(report: &Value, graph: &Map<String, Value>) -> Vec<String> {
    let mut unknowns = Vec::new();
    if graph
        .get("coverage")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        != Some("complete")
    {
        unknowns.push(format!(
            "graph.coverage.status is {}",
            graph
                .get("coverage")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }
    if report
        .get("semantic_graph")
        .and_then(|value| value.get("coverage"))
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        != Some("complete")
    {
        unknowns.push(format!(
            "semantic_graph.coverage.status is {}",
            report
                .get("semantic_graph")
                .and_then(|value| value.get("coverage"))
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }
    unknowns
}

fn is_module(node: &Value) -> bool {
    node.get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| MODULE_KINDS.contains(&kind))
}
fn selector_matches(entry: &Entry, selector: &Value) -> bool {
    selector
        .get("node_id")
        .and_then(Value::as_str)
        .is_some_and(|id| entry.node_id() == id)
        || selector
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(|path| entry.path() == Some(path))
}
fn module_path(node: &Value) -> Option<String> {
    let identity = node.get("identity")?;
    match identity.get("strategy").and_then(Value::as_str) {
        Some("canonical-path") => identity
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned),
        Some("source-map-original") => identity
            .get("original_source")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => node
            .get("observations")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find_map(observation_path)
            .map(str::to_owned),
    }
}
fn observation_path(observation: &Value) -> Option<&str> {
    observation
        .get("properties")
        .and_then(|value| value.get("path"))
        .and_then(Value::as_str)
        .or_else(|| {
            observation
                .get("evidence")
                .and_then(|value| value.get("location"))
                .and_then(|location| location.get("value"))
                .and_then(|value| value.get("path"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            observation
                .get("evidence")
                .and_then(|value| value.get("location"))
                .and_then(source_range)
        })
}
fn source_range(location: &Value) -> Option<&str> {
    (location.get("available").and_then(Value::as_bool) == Some(true)
        && location
            .get("value")
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str)
            == Some("source-range"))
    .then(|| {
        location
            .get("value")
            .and_then(|value| value.get("source"))
            .and_then(Value::as_str)
    })
    .flatten()
}
fn source_ranges(node: &Value) -> Vec<Value> {
    node.get("observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|observation| {
            observation
                .get("evidence")
                .and_then(|evidence| evidence.get("location"))
                .filter(|location| source_range(location).is_some())
                .and_then(|location| location.get("value"))
                .cloned()
        })
        .collect()
}
fn export_names(node: &Value) -> Vec<String> {
    let mut names = BTreeSet::new();
    for observation in node
        .get("observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let values = observation
            .get("properties")
            .and_then(|properties| {
                properties
                    .get("export_names")
                    .or_else(|| properties.get("exports"))
            })
            .and_then(Value::as_array);
        for value in values.into_iter().flatten().filter_map(Value::as_str) {
            names.insert(value.to_owned());
        }
    }
    names.into_iter().collect()
}
fn node_hashes(node: &Value) -> Vec<String> {
    let mut hashes = BTreeSet::new();
    if let Some(identity) = node.get("identity") {
        for key in [
            "sha256",
            "artifact_sha256",
            "source_map_sha256",
            "source_sha256",
        ] {
            if let Some(value) = identity.get(key).and_then(Value::as_str) {
                hashes.insert(value.to_owned());
            }
        }
    }
    for observation in node
        .get("observations")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        for key in [
            "sha256",
            "container_sha256",
            "entry_sha256",
            "source_sha256",
        ] {
            if let Some(value) = observation
                .get("properties")
                .and_then(|properties| properties.get(key))
                .and_then(Value::as_str)
                .filter(|value| {
                    value.len() == 64
                        && value
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
            {
                hashes.insert(value.to_owned());
            }
        }
    }
    hashes.into_iter().collect()
}
fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}
fn bounded_messages(mut values: Vec<String>, parent_id: &str) -> Vec<String> {
    values.sort();
    values.dedup();
    if values
        .iter()
        .map(|value| value.len() * 18 + 6)
        .sum::<usize>()
        <= MESSAGE_LIMIT
    {
        return values;
    }
    let notice = format!(
        "additional messages omitted from this view; consult source parent Evidence {parent_id} for the complete list."
    );
    let mut retained = Vec::new();
    let mut used = notice.len() * 18 + 6;
    for value in values {
        let cost = value.len() * 18 + 6;
        if used + cost > MESSAGE_LIMIT {
            break;
        }
        used += cost;
        retained.push(value);
    }
    retained.push(notice);
    retained
}
fn page_arguments(view: &Value) -> Result<(usize, usize), Failure> {
    let offset = view.get("offset").and_then(Value::as_u64).unwrap_or(0) as usize;
    let limit = view.get("limit").and_then(Value::as_u64).unwrap_or(64) as usize;
    if limit == 0 {
        return Err(invalid("View limit must be positive."));
    }
    Ok((offset, limit))
}
fn complete_coverage(examined: usize, total: usize) -> Value {
    json!({"status":"complete-within-view","examined":examined,"total":total,"next_offset":null,"exhausted":true})
}
fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}
fn incompatible(message: &str) -> Failure {
    invalid(message)
}
fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the retained Evidence view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
