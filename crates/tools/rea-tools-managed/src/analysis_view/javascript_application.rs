//! Views over retained `analyze_javascript_application` Evidence.
//!
//! Compatibility owners: `src/domain/analysisView/javascriptApplicationView.ts`,
//! `javascriptModuleReferences.ts`, `javascriptFactsView.ts`,
//! `javascriptApplicationCoverage.ts`, and the JavaScript parent admission in
//! `src/domain/analysisView/analysisView.ts`
//! (`parseJavaScriptParent` ->
//! `src/domain/javascript/javascriptApplicationAnalysis.ts`).
use crate::common::json;
use crate::common::schema::{self, Issue, IssueKind};
use crate::common::view::input_error as view_input_error;
use crate::common::view::{
    Parent, bounded_view_messages, complete_within_view, offset_limit, page_coverage, view_error,
    view_kind,
};
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

const OPERATION: &str = "inspect_analysis_view";

/// `jsIncompatible`: one `["view"]` invalid_value issue.
fn js_incompatible(detail: &str) -> AnalysisError {
    view_error(&["view"], "invalid_value", detail.to_owned())
}

/// `projectJavaScriptApplicationView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if kind != "summary"
        && kind != "item"
        && kind != "page"
        && kind != "javascript"
        && kind != "javascript-facts"
    {
        return Err(js_incompatible(
            "JavaScript application Evidence supports summary, module item/page, typed module references or selected JavaScript facts.",
        ));
    }
    // `parseJavaScriptParent`: structural validation via the owning tool's
    // result contract, then the cross-graph binding refinements.
    let analysis = parse_java_script_parent(parent)?;

    let source_coverage = source_coverage(&analysis);
    let shared = parent_fields(parent, &analysis, &source_coverage);

    let graph = analysis.get("graph").unwrap_or(&Value::Null);
    let nodes = json::array_at(graph, "nodes");

    match kind {
        "javascript-facts" => {
            let (rows, total) = project_java_script_facts(nodes, view);
            let rows_len = rows.len();
            let mut out = shared;
            out.insert("kind".into(), json!("javascript-facts"));
            out.insert("view".into(), view.clone());
            out.insert("rows".into(), Value::Array(rows));
            out.insert("source_coverage".into(), source_coverage);
            out.insert(
                "coverage".into(),
                page_coverage(offset(view), rows_len, total),
            );
            Ok(Value::Object(out))
        }
        "javascript" => {
            let (entries, total) = module_page(nodes, view);
            let rows: Vec<Value> = entries.iter().map(module_reference).collect();
            let rows_len = rows.len();
            let mut out = shared;
            out.insert("kind".into(), json!("javascript"));
            out.insert("view".into(), view.clone());
            out.insert("rows".into(), Value::Array(rows));
            out.insert("source_coverage".into(), source_coverage);
            out.insert(
                "coverage".into(),
                page_coverage(offset(view), rows_len, total),
            );
            Ok(Value::Object(out))
        }
        "summary" => {
            let module_count = nodes.iter().filter(|node| is_module_node(node)).count();
            let summary = summary_object(&analysis, graph, &source_coverage);
            // Spread order: { kind, view, summary, coverage, ...shared }.
            let mut out = Map::new();
            out.insert("kind".into(), json!("summary"));
            out.insert("view".into(), view.clone());
            out.insert("summary".into(), summary);
            out.insert(
                "coverage".into(),
                complete_within_view(module_count, nodes.len()),
            );
            for (key, value) in shared {
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
        "item" => {
            if json::str_at(view, "collection") != Some("modules") {
                return Err(js_incompatible(
                    "Section and symbol collections apply to inspect_binary_layout Evidence.",
                ));
            }
            let modules: Vec<ModuleEntry> = module_entries(nodes).collect();
            let selected = select_module(&modules, view)?;
            let item = module_item(selected);
            let mut out = Map::new();
            out.insert("kind".into(), json!("item"));
            out.insert("view".into(), view.clone());
            out.insert("item".into(), item);
            out.insert("coverage".into(), complete_within_view(1, modules.len()));
            for (key, value) in shared {
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
        // "page"
        _ => {
            if kind != "page" || json::str_at(view, "collection") != Some("modules") {
                return Err(js_incompatible(
                    "Section and symbol collections apply to inspect_binary_layout Evidence.",
                ));
            }
            let (entries, total) = module_page(nodes, view);
            let items: Vec<Value> = entries
                .iter()
                .map(|entry| {
                    json!({
                        "node_id": entry.node.get("node_id").cloned().unwrap_or(Value::Null),
                        "kind": entry.node.get("kind").cloned().unwrap_or(Value::Null),
                        "path": path_value(&entry.path),
                    })
                })
                .collect();
            let items_len = items.len();
            let mut out = Map::new();
            out.insert("kind".into(), json!("page"));
            out.insert("view".into(), view.clone());
            out.insert("items".into(), Value::Array(items));
            out.insert(
                "coverage".into(),
                page_coverage(offset(view), items_len, total),
            );
            for (key, value) in shared {
                out.insert(key, value);
            }
            Ok(Value::Object(out))
        }
    }
}

fn offset(view: &Value) -> usize {
    offset_limit(view).0
}

fn path_value(path: &Option<String>) -> Value {
    match path {
        Some(text) => Value::String(text.clone()),
        None => Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Parent admission: structural parse + binding refinements.
// ---------------------------------------------------------------------------

/// `parseJavaScriptParent`: parse the parent with the owning tool's result
/// contract, then run `checkApplicationBindingsSteps`. Issues are prefixed
/// `["source","normalized_result",...]`.
fn parse_java_script_parent(parent: &Parent<'_>) -> Result<std::sync::Arc<Value>, AnalysisError> {
    parent.cached("analyze_javascript_application", || {
        let result = crate::common::view::parse_owned_result(
            "analyze_javascript_application",
            parent.normalized_result,
        )?;
        let issues = check_application_bindings(&result);
        if !issues.is_empty() {
            let issues = schema::prefix_issues(issues, &["source", "normalized_result"]);
            let input = json!({ "source": { "normalized_result": parent.normalized_result } });
            return Err(schema::input_error_from_issues(
                OPERATION,
                &issues,
                &input,
                Vec::new(),
            ));
        }
        Ok(result)
    })
}

/// `checkApplicationBindingsSteps`: custom cross-graph binding issues.
fn check_application_bindings(result: &Value) -> Vec<Issue> {
    let mut issues = Vec::new();
    let graph = result.get("graph").unwrap_or(&Value::Null);
    let semantic = result.get("semantic_graph").unwrap_or(&Value::Null);
    let custom = |path: Vec<Value>, message: &str| Issue {
        path,
        kind: IssueKind::Custom {
            message: message.to_owned(),
        },
        aborts: false,
    };
    if semantic.get("application_graph_id") != graph.get("graph_id") {
        issues.push(custom(
            vec![json!("semantic_graph"), json!("application_graph_id")],
            "Semantic graph must commit the containing application graph",
        ));
    }
    if semantic.get("root_artifact_sha256") != result.get("root_artifact_sha256") {
        issues.push(custom(
            vec![json!("semantic_graph"), json!("root_artifact_sha256")],
            "Semantic graph must commit the containing root artifact",
        ));
    }
    let mut application_node_ids: BTreeSet<&str> = BTreeSet::new();
    for node in json::array_at(graph, "nodes") {
        if let Some(id) = node.get("node_id").and_then(Value::as_str) {
            application_node_ids.insert(id);
        }
    }
    for (node_index, node) in json::array_at(semantic, "nodes").iter().enumerate() {
        for (identifier_index, identifier) in node
            .get("application_node_ids")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            let present = identifier
                .as_str()
                .is_some_and(|id| application_node_ids.contains(id));
            if !present {
                issues.push(custom(
                    vec![
                        json!("semantic_graph"),
                        json!("nodes"),
                        json!(node_index),
                        json!("application_node_ids"),
                        json!(identifier_index),
                    ],
                    "Semantic node references an absent application node",
                ));
            }
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// Module helpers.
// ---------------------------------------------------------------------------

struct ModuleEntry<'a> {
    node: &'a Value,
    path: Option<String>,
}

fn is_module_node(node: &Value) -> bool {
    matches!(
        node.get("kind").and_then(Value::as_str),
        Some("javascript-asset" | "javascript-module" | "source-module")
    )
}

/// `moduleEntries`: module-kind nodes paired with their path semantics.
fn module_entries<'a>(nodes: &'a [Value]) -> impl Iterator<Item = ModuleEntry<'a>> {
    nodes
        .iter()
        .filter(|node| is_module_node(node))
        .map(|node| ModuleEntry {
            node,
            path: javascript_module_path(node),
        })
}

/// `javascriptModulePath`: exact module path or source-map reference.
fn javascript_module_path(node: &Value) -> Option<String> {
    let identity = node.get("identity").unwrap_or(&Value::Null);
    match identity.get("strategy").and_then(Value::as_str) {
        Some("canonical-path") => {
            return identity
                .get("path")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        Some("source-map-original") => {
            return identity
                .get("original_source")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        _ => {}
    }
    for observation in json::array_at(node, "observations") {
        let properties = observation.get("properties").unwrap_or(&Value::Null);
        if let Some(path) = properties.get("path").and_then(Value::as_str) {
            return Some(path.to_owned());
        }
        let location = observation
            .get("evidence")
            .and_then(|evidence| evidence.get("location"))
            .unwrap_or(&Value::Null);
        if location.get("available").and_then(Value::as_bool) == Some(true) {
            let value = location.get("value").unwrap_or(&Value::Null);
            match value.get("kind").and_then(Value::as_str) {
                Some("artifact-path") => {
                    if let Some(path) = value.get("path").and_then(Value::as_str) {
                        return Some(path.to_owned());
                    }
                }
                Some("source-range") => {
                    if let Some(source) = value.get("source").and_then(Value::as_str) {
                        return Some(source.to_owned());
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// `modulePage`: scan retained order once, materialize the matching page.
fn module_page<'a>(nodes: &'a [Value], view: &Value) -> (Vec<ModuleEntry<'a>>, usize) {
    let (offset, limit) = offset_limit(view);
    let where_clause = view.get("where");
    let want_kind = where_clause
        .and_then(|value| value.get("kind"))
        .and_then(Value::as_str);
    // `where.path` may be an explicit null (matches null paths) or omitted.
    let path_filter = where_clause
        .and_then(Value::as_object)
        .filter(|map| map.contains_key("path"))
        .map(|map| map.get("path").and_then(Value::as_str).map(str::to_owned));

    let mut entries = Vec::new();
    let mut total = 0usize;
    for entry in module_entries(nodes) {
        if let Some(kind) = want_kind
            && entry.node.get("kind").and_then(Value::as_str) != Some(kind)
        {
            continue;
        }
        if let Some(path) = &path_filter
            && &entry.path != path
        {
            continue;
        }
        if total >= offset && entries.len() < limit {
            entries.push(entry);
        }
        total += 1;
    }
    (entries, total)
}

fn export_names(node: &Value) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    for observation in json::array_at(node, "observations") {
        let properties = observation.get("properties").unwrap_or(&Value::Null);
        let value = properties
            .get("export_names")
            .or_else(|| properties.get("exports"));
        let Some(Value::Array(items)) = value else {
            continue;
        };
        for entry in items {
            if let Some(text) = entry.as_str()
                && seen.insert(text.to_owned())
            {
                names.push(text.to_owned());
            }
        }
    }
    names
}

fn node_hashes(node: &Value) -> Vec<String> {
    let mut hashes: Vec<String> = Vec::new();
    let mut seen = BTreeSet::new();
    let add = |value: &str, hashes: &mut Vec<String>, seen: &mut BTreeSet<String>| {
        if seen.insert(value.to_owned()) {
            hashes.push(value.to_owned());
        }
    };
    let identity = node.get("identity").unwrap_or(&Value::Null);
    match identity.get("strategy").and_then(Value::as_str) {
        Some("content-digest") => {
            if let Some(sha) = identity.get("sha256").and_then(Value::as_str) {
                add(sha, &mut hashes, &mut seen);
            }
        }
        Some("canonical-path") => {
            if let Some(sha) = identity.get("artifact_sha256").and_then(Value::as_str) {
                add(sha, &mut hashes, &mut seen);
            }
        }
        Some("source-map-original") => {
            if let Some(sha) = identity.get("source_map_sha256").and_then(Value::as_str) {
                add(sha, &mut hashes, &mut seen);
            }
            if let Some(sha) = identity.get("source_sha256").and_then(Value::as_str) {
                add(sha, &mut hashes, &mut seen);
            }
        }
        _ => {}
    }
    for observation in json::array_at(node, "observations") {
        let properties = observation.get("properties").unwrap_or(&Value::Null);
        for key in [
            "sha256",
            "container_sha256",
            "entry_sha256",
            "source_sha256",
        ] {
            if let Some(value) = properties.get(key).and_then(Value::as_str)
                && is_sha256(value)
            {
                add(value, &mut hashes, &mut seen);
            }
        }
    }
    hashes
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn source_ranges(node: &Value) -> Vec<Value> {
    let mut ranges = Vec::new();
    for observation in json::array_at(node, "observations") {
        let location = observation
            .get("evidence")
            .and_then(|evidence| evidence.get("location"))
            .unwrap_or(&Value::Null);
        if location.get("available").and_then(Value::as_bool) == Some(true) {
            let value = location.get("value").unwrap_or(&Value::Null);
            if value.get("kind").and_then(Value::as_str) == Some("source-range") {
                ranges.push(value.clone());
            }
        }
    }
    ranges
}

/// `moduleItem`.
fn module_item(node: &Value) -> Value {
    let observations: Vec<Value> = json::array_at(node, "observations")
        .iter()
        .map(|observation| {
            let evidence = observation.get("evidence").cloned().unwrap_or(Value::Null);
            json!({
                "observation_id": observation.get("observation_id").cloned().unwrap_or(Value::Null),
                "label": observation.get("label").cloned().unwrap_or(Value::Null),
                "properties": observation.get("properties").cloned().unwrap_or(Value::Null),
                "evidence": evidence,
            })
        })
        .collect();
    json!({
        "node_id": node.get("node_id").cloned().unwrap_or(Value::Null),
        "kind": node.get("kind").cloned().unwrap_or(Value::Null),
        "path": path_value(&javascript_module_path(node)),
        "identity": node.get("identity").cloned().unwrap_or(Value::Null),
        "hashes": node_hashes(node),
        "exports": export_names(node),
        "source_ranges": source_ranges(node),
        "observations": observations,
    })
}

/// `moduleReference`: unique support states, no promotion of mixed facts.
fn module_reference(entry: &ModuleEntry<'_>) -> Value {
    let node = entry.node;
    let mut ranges = 0u64;
    let mut support_keys: Vec<String> = Vec::new();
    let mut support: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    for observation in json::array_at(node, "observations") {
        let evidence = observation.get("evidence").unwrap_or(&Value::Null);
        let location = evidence.get("location").unwrap_or(&Value::Null);
        if location.get("available").and_then(Value::as_bool) == Some(true)
            && location
                .get("value")
                .and_then(|value| value.get("kind"))
                .and_then(Value::as_str)
                == Some("source-range")
        {
            ranges += 1;
        }
        let authority = evidence.get("authority").cloned().unwrap_or(Value::Null);
        let state = evidence.get("state").cloned().unwrap_or(Value::Null);
        let confidence = evidence.get("confidence").cloned().unwrap_or(Value::Null);
        let key = format!(
            "{}:{}:{}",
            authority.as_str().unwrap_or_default(),
            state.as_str().unwrap_or_default(),
            confidence.as_str().unwrap_or_default()
        );
        if !support.contains_key(&key) {
            support_keys.push(key.clone());
        }
        support.insert(
            key,
            json!({ "authority": authority, "state": state, "confidence": confidence }),
        );
    }
    let basis: Vec<Value> = support_keys
        .into_iter()
        .map(|key| support.remove(&key).unwrap_or(Value::Null))
        .collect();
    json!({
        "node_id": node.get("node_id").cloned().unwrap_or(Value::Null),
        "kind": node.get("kind").cloned().unwrap_or(Value::Null),
        "path": path_value(&entry.path),
        "identity": node.get("identity").cloned().unwrap_or(Value::Null),
        "retained_source_range_count": ranges,
        "basis": basis,
    })
}

/// `selectModule`: exact path or node_id selection.
fn select_module<'a>(
    modules: &'a [ModuleEntry<'a>],
    view: &Value,
) -> Result<&'a Value, AnalysisError> {
    let selector = view.get("selector").unwrap_or(&Value::Null);
    if let Some(node_id) = selector.get("node_id") {
        let matches: Vec<&ModuleEntry<'_>> = modules
            .iter()
            .filter(|entry| entry.node.get("node_id") == Some(node_id))
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0].node);
        }
        return Err(view_error(
            &["view", "selector", "node_id"],
            "invalid_value",
            format!(
                "No module has node_id {}. Page the modules collection to inspect available identities.",
                json_stringify(node_id)
            ),
        ));
    }
    if selector
        .as_object()
        .is_some_and(|map| map.contains_key("path"))
    {
        let selector_path = selector
            .get("path")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let matches: Vec<&ModuleEntry<'_>> = modules
            .iter()
            .filter(|entry| entry.path == selector_path)
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0].node);
        }
        let rendered = json_stringify(selector.get("path").unwrap_or(&Value::Null));
        if matches.is_empty() {
            return Err(view_error(
                &["view", "selector", "path"],
                "invalid_value",
                format!(
                    "No module has path {rendered}. Page the modules collection to inspect exact paths and node_id values."
                ),
            ));
        }
        let expected: Vec<Value> = matches
            .iter()
            .map(|entry| json!({ "node_id": entry.node.get("node_id").cloned().unwrap_or(Value::Null) }))
            .collect();
        let mut issue = crate::common::view::issue(
            &["view", "selector", "path"],
            "invalid_value",
            format!("Multiple modules have path {rendered}; select one by node_id."),
        );
        issue.expected = Some(Value::Array(expected));
        return Err(view_input_error(vec![issue]));
    }
    Err(js_incompatible(
        "Module items are selected by exact path or node_id.",
    ))
}

/// `JSON.stringify(value)` of a JSON value (matches TS error message rendering).
fn json_stringify(value: &Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".to_owned())
}

// ---------------------------------------------------------------------------
// Facts view (`projectJavaScriptFacts`).
// ---------------------------------------------------------------------------

fn project_java_script_facts(nodes: &[Value], view: &Value) -> (Vec<Value>, usize) {
    let (offset, limit) = offset_limit(view);
    let where_object = view.get("where").and_then(Value::as_object);
    // `view.where.paths`: `undefined` -> None, `[]` -> Some(empty).
    let paths: Option<BTreeSet<String>> =
        where_object
            .filter(|map| map.contains_key("paths"))
            .map(|map| {
                map.get("paths")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default()
            });
    let kinds: Option<BTreeSet<String>> =
        where_object
            .filter(|map| map.contains_key("kinds"))
            .map(|map| {
                map.get("kinds")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default()
            });

    if paths.as_ref().is_some_and(BTreeSet::is_empty)
        || kinds.as_ref().is_some_and(BTreeSet::is_empty)
    {
        return (Vec::new(), 0);
    }

    // `[...new Set(view.property_keys)]`: unique, insertion order.
    let mut keys: Vec<String> = Vec::new();
    let mut key_seen = BTreeSet::new();
    for key in json::array_at(view, "property_keys") {
        if let Some(text) = key.as_str()
            && key_seen.insert(text.to_owned())
        {
            keys.push(text.to_owned());
        }
    }
    let include_available = view
        .get("include_available_property_keys")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut rows = Vec::new();
    let mut total = 0usize;
    for node in nodes {
        let node_kind = node.get("kind").and_then(Value::as_str).unwrap_or_default();
        if let Some(kinds) = &kinds
            && !kinds.contains(node_kind)
        {
            continue;
        }
        for observation in json::array_at(node, "observations") {
            if let Some(paths) = &paths {
                match observation_path(observation) {
                    Some(path) if paths.contains(&path) => {}
                    _ => continue,
                }
            }
            total += 1;
            if total <= offset || rows.len() >= limit {
                continue;
            }
            rows.push(fact_row(node, observation, &keys, include_available));
        }
    }
    (rows, total)
}

fn observation_path(observation: &Value) -> Option<String> {
    let location = observation
        .get("evidence")
        .and_then(|evidence| evidence.get("location"))
        .unwrap_or(&Value::Null);
    if location.get("available").and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let value = location.get("value").unwrap_or(&Value::Null);
    match value.get("kind").and_then(Value::as_str) {
        Some("artifact-path") => value.get("path").and_then(Value::as_str).map(str::to_owned),
        Some("source-range") => value
            .get("source")
            .and_then(Value::as_str)
            .map(str::to_owned),
        _ => None,
    }
}

fn fact_row(node: &Value, observation: &Value, keys: &[String], include_available: bool) -> Value {
    let mut row = Map::new();
    row.insert(
        "node_id".into(),
        node.get("node_id").cloned().unwrap_or(Value::Null),
    );
    row.insert(
        "kind".into(),
        node.get("kind").cloned().unwrap_or(Value::Null),
    );
    row.insert(
        "identity".into(),
        node.get("identity").cloned().unwrap_or(Value::Null),
    );
    row.insert(
        "observation_id".into(),
        observation
            .get("observation_id")
            .cloned()
            .unwrap_or(Value::Null),
    );
    row.insert(
        "source_map_reference".into(),
        observation
            .get("source_map_reference")
            .cloned()
            .unwrap_or(Value::Null),
    );
    let properties = observation.get("properties").unwrap_or(&Value::Null);
    if include_available {
        // `Object.keys(properties).sort()` (default UTF-16 order).
        let mut available: Vec<String> = properties
            .as_object()
            .map(|map| map.keys().cloned().collect())
            .unwrap_or_default();
        available.sort_by(|left, right| json::cmp_utf16(left, right));
        row.insert("available_property_keys".into(), json!(available));
    }
    // `keys.flatMap(key => value !== undefined && Object.hasOwn(props, key) ? [[key, value]] : [])`:
    // present (own) keys only; a retained null is present, so it is kept.
    let mut selected = Map::new();
    if let Some(object) = properties.as_object() {
        for key in keys {
            if let Some(value) = object.get(key) {
                selected.insert(key.clone(), value.clone());
            }
        }
    }
    row.insert("properties".into(), Value::Object(selected));
    row.insert(
        "evidence".into(),
        observation.get("evidence").cloned().unwrap_or(Value::Null),
    );
    Value::Object(row)
}

// ---------------------------------------------------------------------------
// Coverage (`javascriptApplicationSourceCoverage`).
// ---------------------------------------------------------------------------

fn source_coverage(analysis: &Value) -> Value {
    let graph = analysis.get("graph").unwrap_or(&Value::Null);
    let semantic = analysis.get("semantic_graph").unwrap_or(&Value::Null);
    // `const { families, ...semantic } = analysis.semantic_graph.coverage`.
    let semantic_coverage = json::without(
        semantic.get("coverage").unwrap_or(&Value::Null),
        &["families"],
    );
    let application_unknowns = json::array_at(graph, "nodes")
        .iter()
        .filter(|node| node.get("kind").and_then(Value::as_str) == Some("unknown"))
        .count();
    let semantic_unknowns = semantic
        .get("unknowns")
        .and_then(Value::as_array)
        .map(Vec::len)
        .unwrap_or(0);

    let mut out = Map::new();
    // `source_selection` is `exactOptional`: present only if the parsed key exists.
    if analysis
        .as_object()
        .is_some_and(|map| map.contains_key("source_selection"))
    {
        out.insert(
            "source_selection".into(),
            analysis
                .get("source_selection")
                .cloned()
                .unwrap_or(Value::Null),
        );
    }
    out.insert(
        "application".into(),
        graph.get("coverage").cloned().unwrap_or(Value::Null),
    );
    out.insert("semantic".into(), Value::Object(semantic_coverage));
    out.insert(
        "application_unknown_count".into(),
        json!(application_unknowns),
    );
    out.insert("semantic_unknown_count".into(), json!(semantic_unknowns));
    Value::Object(out)
}

fn coverage_unknowns(coverage: &Value) -> Vec<String> {
    let mut unknowns = Vec::new();
    let application_status = coverage
        .get("application")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if application_status != "complete" {
        unknowns.push(format!("graph.coverage.status is {application_status}"));
    }
    let semantic_status = coverage
        .get("semantic")
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if semantic_status != "complete" {
        unknowns.push(format!(
            "semantic_graph.coverage.status is {semantic_status}"
        ));
    }
    let application_unknowns = coverage
        .get("application_unknown_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if application_unknowns > 0 {
        unknowns.push(format!(
            "{application_unknowns} application graph unknowns remain in the parent Evidence."
        ));
    }
    let semantic_unknowns = coverage
        .get("semantic_unknown_count")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if semantic_unknowns > 0 {
        unknowns.push(format!(
            "{semantic_unknowns} semantic graph unknowns remain in the parent Evidence."
        ));
    }
    unknowns
}

// ---------------------------------------------------------------------------
// Shared parent fields and summary.
// ---------------------------------------------------------------------------

fn analysis_limitations(analysis: &Value) -> Vec<String> {
    let graph = analysis.get("graph").unwrap_or(&Value::Null);
    let semantic = analysis.get("semantic_graph").unwrap_or(&Value::Null);
    let mut limitations = json::strings(analysis.get("limitations").unwrap_or(&Value::Null));
    limitations.extend(json::strings(
        graph.get("limitations").unwrap_or(&Value::Null),
    ));
    limitations.extend(json::strings(
        semantic.get("limitations").unwrap_or(&Value::Null),
    ));
    limitations
}

/// `parentFields`: shared view envelope returned by every JavaScript view.
fn parent_fields(
    parent: &Parent<'_>,
    analysis: &Value,
    source_coverage: &Value,
) -> Map<String, Value> {
    let limitations = analysis_limitations(analysis);
    let mut combined = parent.limitations.clone();
    combined.extend(limitations.iter().cloned());

    let mut out = Map::new();
    out.insert("parent_evidence_id".into(), json!(parent.evidence_id));
    out.insert(
        "parent_operation".into(),
        json!("analyze_javascript_application"),
    );
    out.insert("parent_digest".into(), json!(parent.digest()));
    out.insert(
        "artifact".into(),
        json!({
            "path": analysis.get("input_path").cloned().unwrap_or(Value::Null),
            "sha256": analysis.get("root_artifact_sha256").cloned().unwrap_or(Value::Null),
        }),
    );
    out.insert(
        "limitations".into(),
        json!(bounded_view_messages(
            &combined,
            parent.evidence_id,
            "limitations",
            &[]
        )),
    );
    out.insert(
        "unknowns".into(),
        json!(bounded_view_messages(
            &limitations,
            parent.evidence_id,
            "unknowns",
            &coverage_unknowns(source_coverage),
        )),
    );
    out
}

/// `summary` body for the JavaScript summary view.
fn summary_object(analysis: &Value, graph: &Value, source_coverage: &Value) -> Value {
    let semantic = analysis.get("semantic_graph").unwrap_or(&Value::Null);
    let semantic_coverage = semantic.get("coverage").unwrap_or(&Value::Null);
    // semantic coverage with families mapped to unknown_count.
    let mut semantic_summary = semantic_coverage.as_object().cloned().unwrap_or_default();
    let families: Vec<Value> = json::array_at(semantic_coverage, "families")
        .iter()
        .map(|family| {
            let mut mapped = json::without(family, &["unknown_ids"]);
            let count = family
                .get("unknown_ids")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0);
            mapped.insert("unknown_count".into(), json!(count));
            Value::Object(mapped)
        })
        .collect();
    semantic_summary.insert("families".into(), Value::Array(families));

    let coverage = json!({
        "application": graph.get("coverage").cloned().unwrap_or(Value::Null),
        "semantic": Value::Object(semantic_summary),
        "application_unknowns": source_coverage.get("application_unknown_count").cloned().unwrap_or(json!(0)),
        "semantic_unknowns": source_coverage.get("semantic_unknown_count").cloned().unwrap_or(json!(0)),
    });

    let mut summary = Map::new();
    summary.insert(
        "input_path".into(),
        analysis.get("input_path").cloned().unwrap_or(Value::Null),
    );
    summary.insert(
        "format".into(),
        analysis.get("format").cloned().unwrap_or(Value::Null),
    );
    summary.insert(
        "root_artifact_sha256".into(),
        analysis
            .get("root_artifact_sha256")
            .cloned()
            .unwrap_or(Value::Null),
    );
    if analysis
        .as_object()
        .is_some_and(|map| map.contains_key("source_selection"))
    {
        summary.insert(
            "source_selection".into(),
            analysis
                .get("source_selection")
                .cloned()
                .unwrap_or(Value::Null),
        );
    }
    summary.insert(
        "statistics".into(),
        analysis.get("statistics").cloned().unwrap_or(Value::Null),
    );
    summary.insert(
        "electron".into(),
        analysis.get("summary").cloned().unwrap_or(Value::Null),
    );
    summary.insert("coverage".into(), coverage);
    summary.insert(
        "limitation_count".into(),
        json!(
            analysis
                .get("limitations")
                .and_then(Value::as_array)
                .map(Vec::len)
                .unwrap_or(0)
        ),
    );
    Value::Object(summary)
}
