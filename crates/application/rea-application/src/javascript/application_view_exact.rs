//! Exact retained JavaScript application views.
//!
//! This projector is deliberately separate from the legacy `Value` projector.
//! A JavaScript graph is allowed to contain an unpaired UTF-16 code unit in a
//! path, label, or object key.  Converting such a graph through
//! `serde_json::Value` either rejects it or replaces the source identity.  The
//! graph `Json` representation keeps those units and therefore owns this
//! projection boundary.

use crate::javascript::graph::json::{self, Json, Obj};
use crate::javascript::semantic::value_types::JsString;
use rea_core::analysis_error::{AnalysisError, InputIssue};
use rea_core::evidence::record::EvidenceRecord;
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::BTreeSet;

const OPERATION: &str = "inspect_analysis_view";

/// Project a retained JavaScript application record without decoding it into
/// `serde_json::Value`.
///
/// The record is the complete authenticated Evidence object.  Its
/// `normalized_result` is the only producer-owned graph used below; all other
/// parent fields are copied from the record exactly.
pub fn project_exact(record: &Json, view: &Json) -> Result<Json, AnalysisError> {
    let kind = text(view.get("kind"));
    let analysis = record
        .get("normalized_result")
        .ok_or_else(|| invalid("retained Evidence is missing normalized_result"))?;
    let graph = analysis.at("graph");
    let nodes = graph.at("nodes").arr();
    let coverage = source_coverage(analysis);
    let shared = parent_fields(record, analysis, &coverage);

    match kind {
        Some("summary") => {
            let mut output = Obj::new()
                .with("kind", "summary")
                .with("view", view)
                .with("summary", summary_object(analysis, graph, &coverage))
                .with(
                    "coverage",
                    complete_within_view(module_count(nodes), nodes.len()),
                );
            output.extend_from(&shared);
            Ok(output.into())
        }
        Some("javascript") => {
            let (entries, total) = module_page(nodes, &view);
            let rows = entries
                .into_iter()
                .map(module_reference)
                .collect::<Vec<_>>();
            let mut output = shared;
            output.set("kind", "javascript");
            output.set("view", view);
            output.set("rows", Json::array(rows.clone()));
            output.set("source_coverage", coverage);
            output.set("coverage", page_coverage(&view, rows.len(), total));
            Ok(output.into())
        }
        Some("javascript-facts") => {
            let (rows, total) = facts(nodes, &view);
            let mut output = shared;
            output.set("kind", "javascript-facts");
            output.set("view", view);
            output.set("rows", Json::array(rows.clone()));
            output.set("source_coverage", coverage);
            output.set("coverage", page_coverage(&view, rows.len(), total));
            Ok(output.into())
        }
        Some("item") => {
            require_modules(&view)?;
            let modules = module_entries(nodes);
            let selected = select_module(&modules, &view)?;
            let mut output = Obj::new()
                .with("kind", "item")
                .with("view", view)
                .with("item", module_item(selected))
                .with("coverage", complete_within_view(1, modules.len()));
            output.extend_from(&shared);
            Ok(output.into())
        }
        Some("page") => {
            require_modules(&view)?;
            let (entries, total) = module_page(nodes, &view);
            let items = entries
                .into_iter()
                .map(|entry| {
                    Obj::new()
                        .with("node_id", entry.node.at("node_id"))
                        .with("kind", entry.node.at("kind"))
                        .with("path", entry.path)
                        .into()
                })
                .collect::<Vec<_>>();
            let mut output = Obj::new()
                .with("kind", "page")
                .with("view", view)
                .with("items", Json::array(items.clone()))
                .with("coverage", page_coverage(&view, items.len(), total));
            output.extend_from(&shared);
            Ok(output.into())
        }
        _ => Err(invalid(
            "JavaScript application Evidence supports summary, module item/page, typed module references or selected JavaScript facts.",
        )),
    }
}

/// Project and authenticate one retained JavaScript view without a Value
/// round-trip. This is the application-owned raw boundary used by MCP and
/// other adapters; the returned record retains exact graph strings.
pub fn project_raw(record: &Json, view: &Json) -> Result<EvidenceRecord, AnalysisError> {
    let result = project_exact(record, view)?;
    validate_subject_artifact_binding(record, &result)?;
    let result = attach_view_digest(result)?;
    let unsigned = build_view_evidence(record, view, result);

    seal_view_evidence(unsigned)
}

fn validate_subject_artifact_binding(record: &Json, result: &Json) -> Result<(), AnalysisError> {
    let expected = record
        .get("subject")
        .and_then(|subject| subject.get("digest"))
        .and_then(|digest| digest.get("sha256"))
        .and_then(Json::as_str);
    let actual = result
        .get("artifact")
        .and_then(|artifact| artifact.get("sha256"))
        .and_then(Json::as_str);
    if expected.is_some() && expected != actual {
        return Err(AnalysisError::evidence_integrity(
            "Parent subject SHA-256 differs from analysis artifact SHA-256.",
        ));
    }
    Ok(())
}

fn attach_view_digest(mut result: Json) -> Result<Json, AnalysisError> {
    let view_digest = result.digest();
    let Json::Object(output) = &mut result else {
        return Err(AnalysisError::output(
            OPERATION,
            "Analysis view projection is not an object.",
        ));
    };
    output.set("view_digest", view_digest);
    Ok(result)
}

fn build_view_evidence(record: &Json, view: &Json, result: Json) -> Json {
    let subject = record.get("subject").cloned().unwrap_or(Json::Null);
    let confidence = view_confidence(&result);
    let limitations = view_limitations(&result);
    let locations = view_locations(&result);
    Obj::new()
        .with("subject", subject)
        .with(
            "provider",
            Obj::new()
                .with("id", "rea-analysis-view")
                .with("name", "REA analysis view projection")
                .with("version", "1"),
        )
        .with("analysis_profile", Json::Null)
        .with("predicate_type", "rea.analysis-view")
        .with("operation", OPERATION)
        .with(
            "parameters",
            Obj::new()
                .with("parent_evidence_id", record.at("evidence_id"))
                .with("view", view.clone()),
        )
        .with("raw_result", Json::Null)
        .with("normalized_result", result)
        .with("confidence", confidence)
        .with("authority", record.at("authority"))
        .with("environment", Json::Null)
        .with("limitations", limitations)
        .with("relationship_coverage", Json::Null)
        .with("locations", locations)
        .with(
            "evidence_links",
            Json::array(vec![record.at("evidence_id").clone()]),
        )
        .into()
}

fn view_limitations(result: &Json) -> Json {
    result
        .get("limitations")
        .cloned()
        .unwrap_or_else(|| Json::array(Vec::new()))
}

fn view_locations(result: &Json) -> Json {
    result
        .get("artifact")
        .and_then(|artifact| artifact.get("path"))
        .filter(|path| path.as_js_string().is_some_and(|path| !path.is_empty()))
        .map(|path| {
            Json::array(vec![
                Obj::new()
                    .with("kind", "artifact-path")
                    .with("path", path.clone())
                    .into(),
            ])
        })
        .unwrap_or_else(|| Json::array(Vec::new()))
}

fn view_confidence(result: &Json) -> &'static str {
    if result
        .get("templated_groups")
        .and_then(Json::as_f64)
        .is_some_and(|count| count > 0.0)
    {
        "inferred"
    } else {
        "derived"
    }
}

fn seal_view_evidence(unsigned: Json) -> Result<EvidenceRecord, AnalysisError> {
    let raw = RawValue::from_string(Json::from(unsigned).stringify())
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))?;
    EvidenceRecord::create_unsigned(&raw)
        .map_err(|error| AnalysisError::evidence_integrity(error.to_string()))
}

/// Project and seal a JavaScript application view while retaining exact graph
/// strings. This is the raw Evidence boundary used by tool adapters; it
/// avoids converting the parent through `serde_json::Value`.
pub fn project_exact_evidence(
    parent: &EvidenceRecord,
    view: &Json,
) -> Result<Box<RawValue>, AnalysisError> {
    let record = json::parse(parent.raw().get()).map_err(|error| {
        AnalysisError::evidence_integrity(format!(
            "Authenticated JavaScript Evidence is not valid exact JSON: {error}"
        ))
    })?;
    let projected = project_raw(&record, view)?;
    RawValue::from_string(projected.raw().get().to_owned()).map_err(|error| {
        AnalysisError::evidence_integrity(format!(
            "JavaScript analysis view Evidence could not be retained: {error}"
        ))
    })
}

fn invalid(message: &str) -> AnalysisError {
    AnalysisError::input(
        OPERATION,
        vec![InputIssue::new(&["view"], "invalid_value", message)],
    )
}

fn text(value: Option<&Json>) -> Option<&str> {
    value.and_then(Json::as_str)
}

fn owned(value: Option<&Json>) -> Json {
    value.cloned().unwrap_or(Json::Null)
}

fn require_modules(view: &Json) -> Result<(), AnalysisError> {
    if text(view.get("collection")) == Some("modules") {
        Ok(())
    } else {
        Err(invalid(
            "Section and symbol collections apply to inspect_binary_layout Evidence.",
        ))
    }
}

fn module_count(nodes: &[Json]) -> usize {
    nodes.iter().filter(|node| is_module_node(node)).count()
}

fn is_module_node(node: &Json) -> bool {
    matches!(
        text(node.get("kind")),
        Some("javascript-asset" | "javascript-module" | "source-module")
    )
}

#[derive(Clone)]
struct ModuleEntry<'a> {
    node: &'a Json,
    path: Option<JsString>,
}

fn module_entries(nodes: &[Json]) -> Vec<ModuleEntry<'_>> {
    nodes
        .iter()
        .filter(|node| is_module_node(node))
        .map(|node| ModuleEntry {
            node,
            path: module_path(node),
        })
        .collect()
}

fn module_path(node: &Json) -> Option<JsString> {
    let identity = node.at("identity");
    match text(identity.get("strategy")) {
        Some("canonical-path") => identity.get("path").and_then(Json::as_js_string).cloned(),
        Some("source-map-original") => identity
            .get("original_source")
            .and_then(Json::as_js_string)
            .cloned(),
        _ => node
            .at("observations")
            .arr()
            .iter()
            .find_map(module_observation_path),
    }
}

fn module_observation_path(observation: &Json) -> Option<JsString> {
    let properties = observation.at("properties");
    if let Some(path) = properties.get("path").and_then(Json::as_js_string) {
        return Some(path.clone());
    }
    observation_path(observation)
}

fn observation_path(observation: &Json) -> Option<JsString> {
    let location = observation.at("evidence").at("location");
    if location.at("available").as_bool() != Some(true) {
        return None;
    }
    let value = location.at("value");
    match text(value.get("kind")) {
        Some("artifact-path") | Some("source-range") => value
            .get("path")
            .or_else(|| value.get("source"))
            .and_then(Json::as_js_string)
            .cloned(),
        _ => None,
    }
}

fn module_page<'a>(nodes: &'a [Json], view: &Json) -> (Vec<ModuleEntry<'a>>, usize) {
    let (offset, limit) = offset_limit(view);
    let clause = view.get("where");
    let want_kind = clause.and_then(|value| text(value.get("kind")));
    let path_filter = clause
        .and_then(|value| value.as_obj())
        .and_then(|object| object.get("path"))
        .map(|value| value.as_js_string().cloned());
    let mut entries = Vec::new();
    let mut total = 0;
    for entry in module_entries(nodes) {
        if want_kind.is_some_and(|kind| text(entry.node.get("kind")) != Some(kind))
            || path_filter.as_ref().is_some_and(|path| &entry.path != path)
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

fn select_module<'a>(modules: &[ModuleEntry<'a>], view: &Json) -> Result<&'a Json, AnalysisError> {
    let selector = view.at("selector");
    if let Some(node_id) = selector.get("node_id") {
        let matches = modules
            .iter()
            .filter(|entry| entry.node.get("node_id") == Some(node_id))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [entry] => Ok(entry.node),
            _ => Err(invalid("No module has the requested node_id.")),
        };
    }
    if selector.as_obj().is_some_and(|object| object.has("path")) {
        let Some(path) = selector.get("path").and_then(Json::as_js_string).cloned() else {
            return Err(invalid(
                "Module items are selected by an exact string path or node_id.",
            ));
        };
        let matches = modules
            .iter()
            .filter(|entry| entry.path.as_ref() == Some(&path))
            .collect::<Vec<_>>();
        return match matches.as_slice() {
            [entry] => Ok(entry.node),
            [] => Err(invalid("No module has the requested path.")),
            _ => Err(ambiguous_module_path(&path, &matches)),
        };
    }
    Err(invalid(
        "Module items are selected by exact path or node_id.",
    ))
}

fn ambiguous_module_path(path: &JsString, matches: &[&ModuleEntry<'_>]) -> AnalysisError {
    let expected = matches
        .iter()
        .filter_map(|entry| entry.node.get("node_id").and_then(Json::as_str))
        .map(|node_id| {
            let mut object = serde_json::Map::new();
            object.insert("node_id".to_owned(), Value::String(node_id.to_owned()));
            Value::Object(object)
        })
        .collect();
    AnalysisError::input(
        OPERATION,
        vec![InputIssue {
            path: vec![
                Value::String("view".to_owned()),
                Value::String("selector".to_owned()),
                Value::String("path".to_owned()),
            ],
            reason: "invalid_value",
            message: Some(format!(
                "Multiple modules have path {}; select one by node_id.",
                Json::String(path.clone()).stringify()
            )),
            expected: Some(Value::Array(expected)),
            minimum: None,
            maximum: None,
        }],
    )
}

fn module_item(node: &Json) -> Json {
    let observations: Vec<Json> = node
        .at("observations")
        .arr()
        .iter()
        .map(|observation| {
            Obj::new()
                .with("observation_id", observation.at("observation_id"))
                .with("label", observation.at("label"))
                .with("properties", observation.at("properties"))
                .with("evidence", observation.at("evidence"))
                .into()
        })
        .collect();
    Obj::new()
        .with("node_id", node.at("node_id"))
        .with("kind", node.at("kind"))
        .with("path", module_path(node))
        .with("identity", node.at("identity"))
        .with("hashes", Json::array(node_hashes(node)))
        .with("exports", Json::array(export_names(node)))
        .with("source_ranges", Json::array(source_ranges(node)))
        .with("observations", Json::array(observations))
        .into()
}

fn export_names(node: &Json) -> Vec<Json> {
    let mut values = Vec::new();
    for observation in node.at("observations").arr() {
        let properties = observation.at("properties");
        let Some(entries) = properties
            .get("export_names")
            .or_else(|| properties.get("exports"))
            .map(Json::arr)
        else {
            continue;
        };
        for value in entries {
            if value.as_js_string().is_some() && !values.iter().any(|existing| existing == value) {
                values.push(value.clone());
            }
        }
    }
    values
}

fn node_hashes(node: &Json) -> Vec<Json> {
    let mut values: Vec<Json> = Vec::new();
    let mut add = |value: &Json| {
        if let Some(text) = value.as_str()
            && is_sha256(text)
            && !values
                .iter()
                .any(|existing| existing.as_str() == Some(text))
        {
            values.push(value.clone());
        }
    };
    let identity = node.at("identity");
    match text(identity.get("strategy")) {
        Some("content-digest") => add(identity.get("sha256").unwrap_or(&Json::Null)),
        Some("canonical-path") => add(identity.get("artifact_sha256").unwrap_or(&Json::Null)),
        Some("source-map-original") => {
            add(identity.get("source_map_sha256").unwrap_or(&Json::Null));
            add(identity.get("source_sha256").unwrap_or(&Json::Null));
        }
        _ => {}
    }
    for observation in node.at("observations").arr() {
        for key in [
            "sha256",
            "container_sha256",
            "entry_sha256",
            "source_sha256",
        ] {
            add(observation.at("properties").get(key).unwrap_or(&Json::Null));
        }
    }
    values
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn source_ranges(node: &Json) -> Vec<Json> {
    node.at("observations")
        .arr()
        .iter()
        .filter_map(|observation| {
            let location = observation.at("evidence").at("location");
            (location.at("available").as_bool() == Some(true)
                && text(location.at("value").get("kind")) == Some("source-range"))
            .then(|| location.at("value").clone())
        })
        .collect()
}

fn module_reference(entry: ModuleEntry<'_>) -> Json {
    let node = entry.node;
    let mut ranges = 0usize;
    let mut support = Vec::new();
    for observation in node.at("observations").arr() {
        let evidence = observation.at("evidence");
        let location = evidence.at("location");
        if location.at("available").as_bool() == Some(true)
            && text(location.at("value").get("kind")) == Some("source-range")
        {
            ranges += 1;
        }
        let authority = evidence.at("authority");
        let state = evidence.at("state");
        let confidence = evidence.at("confidence");
        let duplicate = support.iter().any(|existing: &Json| {
            existing.at("authority") == authority
                && existing.at("state") == state
                && existing.at("confidence") == confidence
        });
        if !duplicate {
            support.push(
                Obj::new()
                    .with("authority", authority)
                    .with("state", state)
                    .with("confidence", confidence)
                    .into(),
            );
        }
    }
    Obj::new()
        .with("node_id", node.at("node_id"))
        .with("kind", node.at("kind"))
        .with("path", entry.path)
        .with("identity", node.at("identity"))
        .with("retained_source_range_count", ranges)
        .with("basis", Json::array(support))
        .into()
}

fn facts(nodes: &[Json], view: &Json) -> (Vec<Json>, usize) {
    let (offset, limit) = offset_limit(view);
    let clause = view.get("where");
    let paths = js_string_set(clause.and_then(|value| value.get("paths")));
    let kinds = js_string_set(clause.and_then(|value| value.get("kinds")));
    let mut keys = Vec::<JsString>::new();
    let mut seen = BTreeSet::new();
    for value in view.at("property_keys").arr() {
        if let Some(key) = value.as_js_string()
            && seen.insert(key.clone())
        {
            keys.push(key.clone());
        }
    }
    let include_available = view
        .at("include_available_property_keys")
        .as_bool()
        .unwrap_or(false);
    let mut rows = Vec::new();
    let mut total = 0;
    for node in nodes {
        if kinds.as_ref().is_some_and(|set| {
            !node
                .at("kind")
                .as_js_string()
                .is_some_and(|kind| set.contains(kind))
        }) {
            continue;
        }
        for observation in node.at("observations").arr() {
            if paths.as_ref().is_some_and(|set| {
                !observation_path(observation).is_some_and(|path| set.contains(&path))
            }) {
                continue;
            }
            if total >= offset && rows.len() < limit {
                rows.push(fact_row(node, observation, &keys, include_available));
            }
            total += 1;
        }
    }
    (rows, total)
}

fn js_string_set(value: Option<&Json>) -> Option<BTreeSet<JsString>> {
    value.map(|value| {
        value
            .arr()
            .iter()
            .filter_map(Json::as_js_string)
            .cloned()
            .collect()
    })
}

fn fact_row(node: &Json, observation: &Json, keys: &[JsString], include_available: bool) -> Json {
    let properties = observation.at("properties");
    let mut output = Obj::new()
        .with("node_id", node.at("node_id"))
        .with("kind", node.at("kind"))
        .with("identity", node.at("identity"))
        .with("observation_id", observation.at("observation_id"))
        .with(
            "source_map_reference",
            observation.at("source_map_reference"),
        );
    if include_available {
        let mut available = properties
            .as_obj()
            .map(|object| {
                object
                    .iter()
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        available.sort_by(json::compare_utf16);
        output.set(
            "available_property_keys",
            Json::array(available.into_iter().map(Json::from).collect()),
        );
    }
    let mut selected = Obj::new();
    for key in keys {
        if let Some(value) = properties.get_js_string(key) {
            selected.set(key.clone(), value.clone());
        }
    }
    output.set("properties", selected);
    output.set("evidence", observation.at("evidence"));
    output.into()
}

fn offset_limit(view: &Json) -> (usize, usize) {
    let offset = view
        .at("offset")
        .as_f64()
        .and_then(|value| usize::try_from(value as u64).ok())
        .unwrap_or(0);
    let limit = view
        .at("limit")
        .as_f64()
        .and_then(|value| usize::try_from(value as u64).ok())
        .unwrap_or(64);
    (offset, limit)
}

fn page_coverage(view: &Json, returned: usize, total: usize) -> Json {
    let offset = offset_limit(view).0;
    let exhausted = offset >= total || offset + returned >= total;
    Obj::new()
        .with("status", if returned == 0 { "empty" } else { "page" })
        .with("examined", returned)
        .with("total", total)
        .with(
            "next_offset",
            if exhausted {
                Json::Null
            } else {
                Json::from(offset + returned)
            },
        )
        .with("exhausted", exhausted)
        .into()
}

fn complete_within_view(examined: usize, total: usize) -> Json {
    Obj::new()
        .with("status", "complete-within-view")
        .with("examined", examined)
        .with("total", total)
        .with("next_offset", Json::Null)
        .with("exhausted", true)
        .into()
}

fn source_coverage(analysis: &Json) -> Json {
    let graph = analysis.at("graph");
    let semantic = analysis.at("semantic_graph");
    let mut semantic_coverage = semantic.at("coverage").obj();
    semantic_coverage.remove("families");
    let application_unknowns = graph
        .at("nodes")
        .arr()
        .iter()
        .filter(|node| text(node.get("kind")) == Some("unknown"))
        .count();
    let semantic_unknowns = semantic.at("unknowns").arr().len();
    let mut result = Obj::new();
    if analysis.get("source_selection").is_some() {
        result.set("source_selection", owned(analysis.get("source_selection")));
    }
    result.set("application", owned(graph.get("coverage")));
    result.set("semantic", semantic_coverage);
    result.set("application_unknown_count", application_unknowns);
    result.set("semantic_unknown_count", semantic_unknowns);
    result.into()
}

fn parent_fields(record: &Json, analysis: &Json, coverage: &Json) -> Obj {
    let graph = analysis.at("graph");
    let semantic = analysis.at("semantic_graph");
    let mut limitations = strings(record.get("limitations"));
    limitations.extend(strings(analysis.get("limitations")));
    limitations.extend(strings(graph.get("limitations")));
    limitations.extend(strings(semantic.get("limitations")));
    unique_sort_strings(&mut limitations);
    let mut unknowns = limitations.clone();
    unknowns.extend(coverage_unknowns(coverage));
    unique_sort_strings(&mut unknowns);
    Obj::new()
        .with("parent_evidence_id", record.at("evidence_id"))
        .with("parent_operation", "analyze_javascript_application")
        .with("parent_digest", parent_digest(record))
        .with(
            "artifact",
            Obj::new()
                .with("path", owned(analysis.get("input_path")))
                .with("sha256", owned(analysis.get("root_artifact_sha256"))),
        )
        .with("limitations", Json::array(limitations.clone()))
        .with("unknowns", Json::array(unknowns))
        .into()
}

/// The published view contract defines `parent_digest` as the parent Evidence
/// identifier without its transport prefix.  The raw Evidence record does
/// not carry a top-level `digest` object; its digest is represented by the
/// authenticated `evidence_id`.  Keep this conversion in the exact JSON
/// boundary so it cannot accidentally become a non-string graph value.
fn parent_digest(record: &Json) -> Json {
    let Some(evidence_id) = record.at("evidence_id").as_js_string() else {
        return Json::String(JsString::from(""));
    };

    Json::String(
        evidence_id
            .strip_prefix("ev_")
            .unwrap_or_else(|| evidence_id.clone()),
    )
}

fn unique_sort_strings(values: &mut Vec<Json>) {
    values.retain(|value| value.as_js_string().is_some());
    values.sort_by(|left, right| {
        json::compare_utf16(
            left.as_js_string().expect("filtered string"),
            right.as_js_string().expect("filtered string"),
        )
    });
    values.dedup_by(|left, right| left == right);
}

fn strings(value: Option<&Json>) -> Vec<Json> {
    value
        .map(|value| {
            value
                .arr()
                .iter()
                .filter(|item| item.as_js_string().is_some())
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

fn coverage_unknowns(coverage: &Json) -> Vec<Json> {
    let mut unknowns = Vec::new();
    let application_status = text(coverage.at("application").get("status")).unwrap_or_default();
    if application_status != "complete" {
        unknowns.push(Json::from(format!(
            "graph.coverage.status is {application_status}"
        )));
    }
    let semantic_status = text(coverage.at("semantic").get("status")).unwrap_or_default();
    if semantic_status != "complete" {
        unknowns.push(Json::from(format!(
            "semantic_graph.coverage.status is {semantic_status}"
        )));
    }
    let application_unknowns = coverage
        .at("application_unknown_count")
        .as_f64()
        .unwrap_or(0.0) as usize;
    if application_unknowns > 0 {
        unknowns.push(Json::from(format!(
            "{application_unknowns} application graph unknowns remain in the parent Evidence."
        )));
    }
    let semantic_unknowns = coverage
        .at("semantic_unknown_count")
        .as_f64()
        .unwrap_or(0.0) as usize;
    if semantic_unknowns > 0 {
        unknowns.push(Json::from(format!(
            "{semantic_unknowns} semantic graph unknowns remain in the parent Evidence."
        )));
    }
    unknowns
}

fn summary_object(analysis: &Json, graph: &Json, coverage: &Json) -> Json {
    let semantic_coverage = analysis.at("semantic_graph").at("coverage");
    let mut semantic = semantic_coverage.obj();
    let families = semantic_coverage
        .at("families")
        .arr()
        .iter()
        .map(|family| {
            let mut mapped = family.obj();
            let unknown_count = mapped
                .remove("unknown_ids")
                .map(|value| value.arr().len())
                .unwrap_or(0);
            mapped.set("unknown_count", unknown_count);
            mapped.into()
        })
        .collect::<Vec<_>>();
    semantic.set("families", Json::array(families));
    let mut result = Obj::new()
        .with("input_path", owned(analysis.get("input_path")))
        .with("format", owned(analysis.get("format")))
        .with(
            "root_artifact_sha256",
            owned(analysis.get("root_artifact_sha256")),
        );
    if analysis.get("source_selection").is_some() {
        result.set("source_selection", owned(analysis.get("source_selection")));
    }
    result.set("statistics", owned(analysis.get("statistics")));
    result.set("electron", owned(analysis.get("summary")));
    result.set(
        "coverage",
        Obj::new()
            .with("application", owned(graph.get("coverage")))
            .with("semantic", semantic)
            .with(
                "application_unknowns",
                owned(coverage.get("application_unknown_count")),
            )
            .with(
                "semantic_unknowns",
                owned(coverage.get("semantic_unknown_count")),
            ),
    );
    result.set("limitation_count", analysis.at("limitations").arr().len());
    result.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retained_record(path: JsString, properties: Obj) -> Json {
        let observation = Obj::new()
            .with("observation_id", "obs_exact")
            .with("label", JsString::from_utf16([0xd800]))
            .with("properties", properties)
            .with(
                "evidence",
                Obj::new()
                    .with("authority", "static-relationship-inference")
                    .with("state", "observed")
                    .with("confidence", "derived")
                    .with(
                        "location",
                        Obj::new().with("available", true).with(
                            "value",
                            Obj::new()
                                .with("kind", "artifact-path")
                                .with("path", path.clone()),
                        ),
                    ),
            );
        let node = Obj::new()
            .with("node_id", "node_exact")
            .with("kind", "javascript-module")
            .with(
                "identity",
                Obj::new()
                    .with("strategy", "canonical-path")
                    .with("path", path),
            )
            .with("observations", Json::array(vec![observation.into()]));
        let graph = Obj::new()
            .with("nodes", Json::array(vec![node.into()]))
            .with("coverage", Obj::new().with("status", "complete"))
            .with("limitations", Json::array(Vec::new()));
        Obj::new()
            .with("evidence_id", "ev_exact")
            .with(
                "digest",
                Obj::new().with(
                    "sha256",
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                ),
            )
            .with(
                "normalized_result",
                Obj::new()
                    .with("input_path", "fixture.js")
                    .with("format", "file")
                    .with(
                        "root_artifact_sha256",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .with("limitations", Json::array(Vec::new()))
                    .with("graph", graph)
                    .with(
                        "semantic_graph",
                        Obj::new()
                            .with("coverage", Obj::new())
                            .with("unknowns", Json::array(Vec::new())),
                    ),
            )
            .into()
    }

    #[test]
    fn module_path_and_label_keep_unpaired_utf16_units() {
        let path = JsString::from_utf16([b'a' as u16, 0xd800, b'/' as u16, b'b' as u16]);
        let record = retained_record(path.clone(), Obj::new());
        let view = Obj::new()
            .with("kind", "item")
            .with("collection", "modules")
            .with("selector", Obj::new().with("path", path));
        let view: Json = view.into();
        let result = project_exact(&record, &view).expect("exact view");
        let item = result.at("item");
        assert_eq!(
            item.at("path").as_js_string().expect("path").units(),
            &[b'a' as u16, 0xd800, b'/' as u16, b'b' as u16]
        );
        assert_eq!(
            item.at("observations")
                .arr()
                .first()
                .expect("observation")
                .at("label")
                .as_js_string()
                .expect("label")
                .units(),
            &[0xd800]
        );
    }

    #[test]
    fn facts_selects_exact_surrogate_property_key_without_collision() {
        let key = JsString::from_utf16([b'x' as u16, 0xd800]);
        let record = retained_record(
            JsString::from("fixture.js"),
            Obj::new()
                .with(key.clone(), "exact")
                .with("x�", "different"),
        );
        let view = Obj::new()
            .with("kind", "javascript-facts")
            .with("property_keys", Json::array(vec![key.into()]))
            .with("limit", 10usize);
        let view: Json = view.into();
        let result = project_exact(&record, &view).expect("exact facts");
        let properties = result
            .at("rows")
            .arr()
            .first()
            .expect("row")
            .at("properties");
        assert_eq!(
            properties
                .get_js_string(&JsString::from_utf16([b'x' as u16, 0xd800]))
                .and_then(Json::as_str),
            Some("exact")
        );
        assert!(properties.get("x�").is_none());
    }

    #[test]
    fn every_view_kind_keeps_exact_path_and_pagination_identity() {
        let path = JsString::from_utf16([b'm' as u16, 0xd800, b'/' as u16, b'n' as u16]);
        let key = JsString::from_utf16([b'k' as u16, 0xdc00]);
        let record = retained_record(path.clone(), Obj::new().with(key.clone(), "value"));
        let views: Vec<Json> = vec![
            Obj::new().with("kind", "summary").into(),
            Obj::new()
                .with("kind", "javascript")
                .with("where", Obj::new().with("path", path.clone()))
                .with("offset", 0usize)
                .with("limit", 1usize)
                .into(),
            Obj::new()
                .with("kind", "page")
                .with("collection", "modules")
                .with("where", Obj::new().with("path", path.clone()))
                .with("offset", 0usize)
                .with("limit", 1usize)
                .into(),
            Obj::new()
                .with("kind", "item")
                .with("collection", "modules")
                .with("selector", Obj::new().with("path", path.clone()))
                .into(),
            Obj::new()
                .with("kind", "javascript-facts")
                .with(
                    "where",
                    Obj::new().with("paths", Json::array(vec![path.into()])),
                )
                .with("property_keys", Json::array(vec![key.into()]))
                .with("offset", 0usize)
                .with("limit", 1usize)
                .into(),
        ];

        for view in views {
            let result = project_exact(&record, &view).expect("exact view");
            assert_eq!(result.at("view"), &view);
        }
    }
}
