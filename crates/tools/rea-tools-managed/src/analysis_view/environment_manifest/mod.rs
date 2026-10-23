//! `environment-manifest` views over retained HAR captures and browser scenarios.
//!
//! Compatibility owners: `src/domain/analysisView/environmentManifestView.ts`,
//! `EnvironmentManifestAccumulator.ts`, `environmentManifestRules.ts`,
//! `scenarioCaptureRecords.ts` and `src/domain/jsonShape.ts`
//! (`parseJsonObject`, `jsonValueType`). Templates are inferences from recorded
//! request lines.
mod rules;
mod scenario;

use super::web_network::budget::Budget;
use super::web_network::capture::admit_har_capture_parent;
use super::web_network::ordering::{compare, composite_key};
use super::web_network::routes::{
    ENTRY_BYTES, GROUP_BYTES, Line, RECORD_SCRATCH_BYTES, RequestLine, RouteTemplate,
    SEGMENT_BYTES, media_type_essence, number, read_query_parameter_names,
    read_recorded_request_line, route_part_count, scan_route_template, sorted_numbers, text_bytes,
    text_bytes_of,
};
use crate::common::json::{js_len, unique_sorted};
use crate::common::view::{Parent, complete_within_view, view_error};
use rea_core::analysis_error::AnalysisError;
use rules::{
    Part, SIBLING_VARIANCE_SEGMENT_LIMIT, ToolGroup, ToolNameRegistry, apply_template_rules,
    compare_tools, parameter_names, path_template, tool_name,
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeSet, HashMap, HashSet};

const SUBJECT: &str = "Environment-manifest";
/// Quotes, separators and brackets a four-part composite key adds.
const KEY_OVERHEAD_CHARS: usize = 32;
const WRITE_METHODS: [&str; 3] = ["POST", "PUT", "PATCH"];
const ASSET_ESSENCES: [&str; 7] = [
    "text/html",
    "application/xhtml+xml",
    "text/css",
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "application/wasm",
];
const ASSET_PREFIXES: [&str; 4] = ["image/", "font/", "audio/", "video/"];
const ASSET_EXTENSIONS: [&str; 17] = [
    "js", "mjs", "css", "map", "htm", "html", "png", "jpg", "jpeg", "gif", "svg", "webp", "ico",
    "woff", "woff2", "ttf", "otf",
];

/// Admit the complete inline envelope before it is authenticated; returns the
/// retained reservation the projection continues from.
pub fn admit_inline(view: &Value, evidence: &Value) -> Result<usize, AnalysisError> {
    let _ = view;
    let mut budget = Budget::new(SUBJECT);
    budget.admit_inline_evidence(evidence)?;
    Ok(budget.retained())
}

/// The `template_rules` uniqueness refinement of the view request.
pub fn refine_request(view: &Value) -> Result<(), AnalysisError> {
    let Some(rules) = view.get("template_rules").and_then(Value::as_array) else {
        return Ok(());
    };
    let unique: HashSet<String> = rules.iter().map(Value::to_string).collect();
    if unique.len() == rules.len() {
        return Ok(());
    }
    Err(view_error(
        &["view", "template_rules"],
        "invalid_value",
        "template_rules must not repeat a rule",
    ))
}

/// `isJson`: `application/json` or `application/*+json`.
fn is_json(essence: Option<&str>) -> bool {
    essence.is_some_and(|essence| {
        essence == "application/json"
            || (essence.starts_with("application/") && essence.ends_with("+json"))
    })
}

/// `isJsonLike`.
fn is_json_like(essence: Option<&str>) -> bool {
    is_json(essence) || matches!(essence, Some("text/plain" | "text/markdown"))
}

fn is_api_path(path: &str) -> bool {
    path.starts_with("/api/") || path.starts_with("/apis/")
}

fn asset_path(template: &str) -> bool {
    template.rsplit_once('.').is_some_and(|(_, extension)| {
        ASSET_EXTENSIONS
            .iter()
            .any(|known| known.eq_ignore_ascii_case(extension))
    })
}

/// `environmentName`: kebab-case host (with port) of the primary origin.
fn environment_name(origin: &str) -> String {
    let Ok(url) = url::Url::parse(origin) else {
        return String::new();
    };
    let host = match (url.host_str(), url.port()) {
        (Some(host), Some(port)) => format!("{host}:{port}"),
        (Some(host), None) => host.to_owned(),
        _ => String::new(),
    };
    let mut output = String::new();
    let mut separator = false;
    for character in host.to_lowercase().chars() {
        if character.is_ascii_lowercase() || character.is_ascii_digit() {
            output.push(character);
            separator = false;
        } else if !separator {
            output.push('-');
            separator = true;
        }
    }
    let output = output.strip_prefix('-').unwrap_or(&output);
    output.strip_suffix('-').unwrap_or(output).to_owned()
}

/// `jsonValueType`.
fn json_value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Array(_) => "array",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Object(_) => "object",
    }
}

/// ECMAScript array-index property keys enumerate first, ascending.
fn array_index(key: &str) -> Option<u64> {
    if key.is_empty()
        || (key.len() > 1 && key.starts_with('0'))
        || !key.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    key.parse::<u64>()
        .ok()
        .filter(|index| *index < 4_294_967_295)
}

/// `Object.entries(JSON.parse(text))` key order for a parsed object.
fn entries_in_property_order(object: &Map<String, Value>) -> Vec<(&String, &Value)> {
    let mut indexed: Vec<(u64, &String, &Value)> = Vec::new();
    let mut named: Vec<(&String, &Value)> = Vec::new();
    for (key, value) in object {
        match array_index(key) {
            Some(index) => indexed.push((index, key, value)),
            None => named.push((key, value)),
        }
    }
    indexed.sort_by_key(|(index, _, _)| *index);
    indexed
        .into_iter()
        .map(|(_, key, value)| (key, value))
        .chain(named)
        .collect()
}

struct RecordLine {
    ordinal: Value,
    method: String,
    path: String,
    status: Option<f64>,
    content_type: Option<String>,
}

struct GroupState {
    tool: ToolGroup,
    api_path: bool,
    json_like: bool,
}

#[derive(Default, Clone, Copy)]
struct OriginStats {
    records: usize,
    json_like: usize,
}

/// `EnvironmentManifestAccumulator`.
struct Accumulator {
    budget: Budget,
    include_query: bool,
    rules: HashSet<String>,
    groups: Vec<GroupState>,
    group_index: HashMap<String, usize>,
    records: Vec<RecordLine>,
    origins: Vec<(String, OriginStats)>,
    origin_index: HashMap<String, usize>,
    unrepresented: usize,
    unrepresentable_body_key: bool,
}

impl Accumulator {
    fn add(&mut self, record: &Value) -> Result<(), AnalysisError> {
        self.budget.add_limitations(crate::common::json::strings(
            record.get("limitations").unwrap_or(&Value::Null),
        ))?;
        let result = self.add_line(record);
        self.budget.release_temporary();
        result
    }

    fn add_line(&mut self, record: &Value) -> Result<(), AnalysisError> {
        let reported = record.get("reported").unwrap_or(&Value::Null);
        let budget = &mut self.budget;
        let line = match read_recorded_request_line(reported, self.include_query, &mut |bytes| {
            budget.temporary(bytes)
        }) {
            None => return Err(self.budget.over_budget()),
            Some(RequestLine::Excluded(_)) => {
                self.unrepresented += 1;
                return Ok(());
            }
            Some(RequestLine::Line(line)) => line,
        };
        let budget = &mut self.budget;
        let Some(route) = scan_route_template(&line.path, &mut |bytes| budget.temporary(bytes))
        else {
            return Err(self.budget.over_budget());
        };
        let budget = &mut self.budget;
        let Some(query_names) =
            read_query_parameter_names(line.query.as_deref(), &mut |bytes| budget.temporary(bytes))
        else {
            return Err(self.budget.over_budget());
        };
        let key_length = js_len(&line.method)
            + js_len(&line.origin)
            + js_len(&route.template)
            + js_len(&route.rules)
            + KEY_OVERHEAD_CHARS;
        if !self.budget.temporary(text_bytes(key_length)) {
            return Err(self.budget.over_budget());
        }
        let key = composite_key(&[
            json!(line.method),
            json!(line.origin),
            json!(route.template),
            json!(route.rules),
        ]);
        let group = self.group_index.get(&key).copied();
        let body_shape = if group.is_none() && WRITE_METHODS.contains(&line.method.as_str()) {
            self.body_shape(reported)?
        } else {
            None
        };
        let ordinal = record.get("ordinal").cloned().unwrap_or(Value::Null);
        self.append(ordinal, line, route, query_names, key, group, body_shape)
    }

    /// `#bodyShape`: top-level key types of the first recorded JSON request body.
    fn body_shape(&mut self, reported: &Value) -> Result<Option<Value>, AnalysisError> {
        let body = reported
            .as_object()
            .and_then(|reported| reported.get("request"))
            .and_then(Value::as_object)
            .and_then(|request| request.get("postData"));
        let (Some(text), Some(mime_type)) = (
            body.and_then(|body| body.get("text"))
                .and_then(Value::as_str),
            body.and_then(|body| body.get("mimeType"))
                .and_then(Value::as_str),
        ) else {
            return Ok(None);
        };
        if !self.budget.temporary(text_bytes_of(mime_type)) {
            return Err(self.budget.over_budget());
        }
        if !is_json(media_type_essence(mime_type).as_deref()) {
            return Ok(None);
        }
        if !self
            .budget
            .temporary(RECORD_SCRATCH_BYTES + text_bytes_of(text) * 3)
        {
            return Err(self.budget.over_budget());
        }
        let Ok(Value::Object(root)) = serde_json::from_str::<Value>(text) else {
            return Ok(None);
        };
        let mut properties = Map::new();
        for (name, value) in entries_in_property_order(&root) {
            if name == "__proto__" {
                self.unrepresentable_body_key = true;
            } else {
                properties.insert(name.clone(), json!(json_value_type(value)));
            }
        }
        Ok(Some(json!({ "type": "object", "properties": properties })))
    }

    #[allow(clippy::too_many_arguments)]
    fn append(
        &mut self,
        ordinal: Value,
        line: Line,
        route: RouteTemplate,
        query_names: Option<BTreeSet<String>>,
        key: String,
        group: Option<usize>,
        body_shape: Option<Value>,
    ) -> Result<(), AnalysisError> {
        let mime = media_type_essence(&line.raw_mime);
        let existing = group.map(|index| &self.groups[index].tool);
        let mut bytes = ENTRY_BYTES * 2 + text_bytes_of(&line.path) + text_bytes_of(&line.method);
        let origin = self.origin_index.get(&line.origin).copied();
        if origin.is_none() {
            bytes += ENTRY_BYTES * 2 + text_bytes_of(&line.origin);
        }
        match existing {
            None => {
                bytes += GROUP_BYTES
                    + text_bytes_of(&key)
                    + text_bytes_of(&line.method)
                    + text_bytes_of(&line.origin)
                    + text_bytes_of(&route.template) * 2
                    + text_bytes_of(&route.rules);
                bytes += ENTRY_BYTES * 4 * route_part_count(&route.template);
                for segment in &route.segments {
                    bytes += SEGMENT_BYTES + ENTRY_BYTES + text_bytes_of(&segment.value);
                }
                if let Some(Value::Object(properties)) = body_shape
                    .as_ref()
                    .and_then(|shape| shape.get("properties"))
                {
                    for name in properties.keys() {
                        bytes += ENTRY_BYTES + text_bytes_of(name);
                    }
                }
            }
            Some(tool) => {
                for segment in &route.segments {
                    if let Some(Part::Param { values, .. }) = tool.parts.get(segment.segment_index)
                        && !values.contains(&segment.value)
                    {
                        bytes += ENTRY_BYTES + text_bytes_of(&segment.value);
                    }
                }
            }
        }
        if let Some(status) = line.status
            && !existing.is_some_and(|tool| tool.statuses.contains(&status))
        {
            bytes += ENTRY_BYTES;
        }
        if let Some(mime) = &mime
            && !existing.is_some_and(|tool| tool.content_types.contains(mime))
        {
            bytes += ENTRY_BYTES + text_bytes_of(mime);
        }
        for name in query_names.iter().flatten() {
            if !existing.is_some_and(|tool| tool.query_names.contains(name)) {
                bytes += ENTRY_BYTES + text_bytes_of(name);
            }
        }
        if !self.budget.retain(bytes) {
            return Err(self.budget.over_budget());
        }
        let position = self.records.len();
        self.records.push(RecordLine {
            ordinal,
            method: line.method.clone(),
            path: line.path.clone(),
            status: line.status,
            content_type: mime.clone(),
        });
        let json_like = is_json_like(mime.as_deref());
        let origin_at = match origin {
            Some(at) => at,
            None => {
                self.origins
                    .push((line.origin.clone(), OriginStats::default()));
                self.origin_index
                    .insert(line.origin.clone(), self.origins.len() - 1);
                self.origins.len() - 1
            }
        };
        let stats = &mut self.origins[origin_at].1;
        stats.records += 1;
        if json_like {
            stats.json_like += 1;
        }
        let index = match group {
            Some(index) => {
                for segment in &route.segments {
                    if let Some(Part::Param { values, .. }) =
                        self.groups[index].tool.parts.get_mut(segment.segment_index)
                    {
                        values.insert(segment.value.clone());
                    }
                }
                index
            }
            None => {
                let by_index: HashMap<usize, &super::web_network::routes::RouteSegment> = route
                    .segments
                    .iter()
                    .map(|segment| (segment.segment_index, segment))
                    .collect();
                let parts = route.template[1.min(route.template.len())..]
                    .split('/')
                    .enumerate()
                    .map(|(index, text)| match by_index.get(&index) {
                        None => Part::Literal(text.to_owned()),
                        Some(segment) => Part::Param {
                            rule: segment.rule,
                            values: BTreeSet::from([segment.value.clone()]),
                        },
                    })
                    .collect();
                self.groups.push(GroupState {
                    tool: ToolGroup {
                        method: line.method.clone(),
                        origin: line.origin.clone(),
                        api_surface_template: route.template.clone(),
                        parts,
                        positions: Vec::new(),
                        statuses: Vec::new(),
                        content_types: BTreeSet::new(),
                        query_names: BTreeSet::new(),
                        body_shape,
                    },
                    api_path: is_api_path(&route.template),
                    json_like: false,
                });
                self.group_index.insert(key, self.groups.len() - 1);
                self.groups.len() - 1
            }
        };
        let state = &mut self.groups[index];
        state.tool.positions.push(position);
        state.json_like |= json_like;
        if let Some(status) = line.status
            && !state.tool.statuses.contains(&status)
        {
            state.tool.statuses.push(status);
        }
        if let Some(mime) = mime {
            state.tool.content_types.insert(mime);
        }
        for name in query_names.into_iter().flatten() {
            state.tool.query_names.insert(name);
        }
        Ok(())
    }

    /// `#primaryOrigin`.
    fn primary_origin(&self) -> Option<String> {
        let mut best: Option<(&str, OriginStats)> = None;
        for (origin, stats) in &self.origins {
            let better = match best {
                None => true,
                Some((best_origin, best_stats)) => {
                    stats.json_like > best_stats.json_like
                        || (stats.json_like == best_stats.json_like
                            && (stats.records > best_stats.records
                                || (stats.records == best_stats.records
                                    && compare(origin, best_origin) == std::cmp::Ordering::Less)))
                }
            };
            if better {
                best = Some((origin, *stats));
            }
        }
        best.map(|(origin, _)| origin.to_owned())
    }

    fn is_asset(state: &GroupState) -> bool {
        state.tool.content_types.iter().any(|essence| {
            ASSET_ESSENCES.contains(&essence.as_str())
                || ASSET_PREFIXES
                    .iter()
                    .any(|prefix| essence.starts_with(prefix))
        }) || asset_path(&state.tool.api_surface_template)
    }

    /// `#tools`.
    fn tools(&self, groups: Vec<ToolGroup>) -> Vec<Value> {
        let mut registry = ToolNameRegistry::default();
        let mut named: Vec<(ToolGroup, Vec<String>, String)> =
            apply_template_rules(groups, &self.rules)
                .into_iter()
                .map(|group| {
                    let names = parameter_names(&group.parts);
                    let template = path_template(&group.parts, &names);
                    (group, names, template)
                })
                .collect();
        named.sort_by(|left, right| {
            compare_tools((&left.2, &left.0.method), (&right.2, &right.0.method))
        });
        named
            .into_iter()
            .map(|(group, names, template)| {
                let name = tool_name(&group.method, &group.parts, &names, &mut registry);
                let mut next = 0;
                let params: Vec<Value> = group
                    .parts
                    .iter()
                    .enumerate()
                    .filter_map(|(index, part)| {
                        let Part::Param { rule, values } = part else {
                            return None;
                        };
                        let name = names.get(next).cloned().unwrap_or_default();
                        next += 1;
                        Some(json!({
                            "index": index,
                            "name": name,
                            "rule": rule,
                            "basis": "inferred",
                            "observed_values": values.iter().collect::<Vec<_>>(),
                        }))
                    })
                    .collect();
                let mut tool = Map::new();
                tool.insert("name".into(), json!(name));
                tool.insert("method".into(), json!(group.method));
                tool.insert("path_template".into(), json!(template));
                tool.insert(
                    "api_surface_template".into(),
                    json!(group.api_surface_template),
                );
                tool.insert("params".into(), Value::Array(params));
                tool.insert(
                    "query_parameter_names".into(),
                    json!(group.query_names.iter().collect::<Vec<_>>()),
                );
                tool.insert(
                    "body_shape".into(),
                    group.body_shape.clone().unwrap_or(Value::Null),
                );
                tool.insert(
                    "statuses".into(),
                    Value::Array(sorted_numbers(group.statuses.iter().copied())),
                );
                tool.insert(
                    "content_types".into(),
                    json!(group.content_types.iter().collect::<Vec<_>>()),
                );
                tool.insert(
                    "record_ordinals".into(),
                    Value::Array(
                        group
                            .positions
                            .iter()
                            .map(|position| self.records[*position].ordinal.clone())
                            .collect(),
                    ),
                );
                Value::Object(tool)
            })
            .collect()
    }

    /// `finish`: the complete deterministic manifest.
    fn finish(mut self) -> Result<Map<String, Value>, AnalysisError> {
        let primary = self.primary_origin();
        let mut tool_groups: Vec<ToolGroup> = Vec::new();
        let mut exclusions: Vec<(Value, bool)> = Vec::new();
        let mut exclusion_index: HashMap<String, usize> = HashMap::new();
        let mut beyond_limit = false;
        for state in &self.groups {
            let reason = if Some(&state.tool.origin) != primary.as_ref() {
                Some("other-origin")
            } else if state.api_path || state.json_like {
                None
            } else if Self::is_asset(state) {
                Some("ui-page-or-asset")
            } else {
                Some("non-json")
            };
            let Some(reason) = reason else {
                beyond_limit |= state.tool.parts.len() > SIBLING_VARIANCE_SEGMENT_LIMIT;
                tool_groups.push(state.tool.clone());
                continue;
            };
            let exclusion = json!({
                "method": state.tool.method,
                "origin": state.tool.origin,
                "path_template": state.tool.api_surface_template,
                "reason": reason,
            });
            let key = composite_key(&[
                json!(state.tool.method),
                json!(state.tool.origin),
                json!(state.tool.api_surface_template),
                json!(reason),
            ]);
            let templated = state
                .tool
                .parts
                .iter()
                .any(|part| matches!(part, Part::Param { .. }));
            match exclusion_index.get(&key) {
                Some(at) => {
                    exclusions[*at] = (exclusion, exclusions[*at].1 || templated);
                }
                None => {
                    exclusion_index.insert(key, exclusions.len());
                    exclusions.push((exclusion, templated));
                }
            }
        }
        let tools = self.tools(tool_groups);
        let mut cited: Vec<Value> = Vec::new();
        let mut cited_seen: HashSet<String> = HashSet::new();
        for tool in &tools {
            for ordinal in tool
                .get("record_ordinals")
                .and_then(Value::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default()
            {
                if cited_seen.insert(ordinal.to_string()) {
                    cited.push(ordinal.clone());
                }
            }
        }
        let positions: HashMap<String, usize> = self
            .records
            .iter()
            .enumerate()
            .map(|(position, record)| (record.ordinal.to_string(), position))
            .collect();
        let field = |exclusion: &Value, key: &str| {
            exclusion
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        exclusions.sort_by(|(left, _), (right, _)| {
            compare(&field(left, "origin"), &field(right, "origin"))
                .then_with(|| {
                    compare(
                        &field(left, "path_template"),
                        &field(right, "path_template"),
                    )
                })
                .then_with(|| compare(&field(left, "method"), &field(right, "method")))
                .then_with(|| compare(&field(left, "reason"), &field(right, "reason")))
        });
        let mut limitations = Vec::new();
        if tools
            .iter()
            .any(|tool| tool.get("body_shape").is_some_and(|shape| !shape.is_null()))
        {
            limitations.push(
                "Body shapes list top-level JSON key types from one recorded request each; they do not establish required fields or a complete schema.".to_owned(),
            );
        }
        if self.unrepresentable_body_key {
            limitations.push(
                "A top-level __proto__ key in a recorded JSON body is omitted from body_shape; it cannot be an own property of the published object.".to_owned(),
            );
        }
        if self.rules.contains("sibling-variance") && beyond_limit {
            limitations.push(format!(
                "Routes with more than {SIBLING_VARIANCE_SEGMENT_LIMIT} segments are not compared by sibling-variance; they keep their grouped templates."
            ));
        }
        if self.unrepresented > 0 {
            limitations.push(format!(
                "{} retained records without a usable request line are not represented in the manifest.",
                self.unrepresented
            ));
        }
        if primary.is_none() {
            limitations.push(
                "No retained record had a parseable origin; the manifest names no primary origin."
                    .to_owned(),
            );
        }
        self.budget.add_limitations(limitations)?;
        cited.sort_by_key(|ordinal| {
            positions
                .get(&ordinal.to_string())
                .copied()
                .unwrap_or(usize::MAX)
        });
        let records: Vec<Value> = cited
            .iter()
            .filter_map(|ordinal| positions.get(&ordinal.to_string()))
            .map(|position| {
                let record = &self.records[*position];
                json!({
                    "ordinal": record.ordinal,
                    "method": record.method,
                    "path": record.path,
                    "status": record.status.map_or(Value::Null, number),
                    "content_type": record.content_type,
                })
            })
            .collect();
        let templated_groups = tools
            .iter()
            .filter(|tool| {
                tool.get("params")
                    .and_then(Value::as_array)
                    .is_some_and(|params| !params.is_empty())
            })
            .count()
            + exclusions
                .iter()
                .filter(|(_, templated)| *templated)
                .count();
        let tool_count = tools.len();
        let mut out = Map::new();
        out.insert("origin".into(), json!(primary.clone().unwrap_or_default()));
        out.insert(
            "name".into(),
            json!(primary.as_deref().map(environment_name).unwrap_or_default()),
        );
        out.insert("tools".into(), Value::Array(tools));
        out.insert("records".into(), Value::Array(records));
        out.insert(
            "excluded".into(),
            Value::Array(
                exclusions
                    .into_iter()
                    .map(|(exclusion, _)| exclusion)
                    .collect(),
            ),
        );
        out.insert(
            "unknowns".into(),
            json!([
                {
                    "kind": "authorization-model",
                    "statement": "Authorization headers and cookies are structurally excluded from captures; the manifest states no authorization model.",
                },
                {
                    "kind": "response-semantics",
                    "statement": "Recorded statuses and bodies are retained only as pointers to parent records; the manifest states no response semantics.",
                },
                {
                    "kind": "state-transition",
                    "statement": "Recorded exchanges are independent observations; the manifest states no ordering, side effects or state transitions between tools.",
                },
            ]),
        );
        out.insert("templated_groups".into(), json!(templated_groups));
        out.insert(
            "coverage".into(),
            complete_within_view(tool_count, tool_count),
        );
        out.insert(
            "limitations".into(),
            json!(self.budget.sorted_limitations()),
        );
        Ok(out)
    }
}

/// The records a manifest projects from, for either parent kind.
struct CaptureParent {
    operation: &'static str,
    records: Vec<Value>,
    total_records: f64,
    limitations: Vec<String>,
    artifact: Value,
}

/// `admitCaptureParent`.
fn admit_capture_parent(
    parent: &Parent<'_>,
    budget: &mut Budget,
) -> Result<CaptureParent, AnalysisError> {
    if parent.operation == "capture_browser_scenario" {
        let scenario = scenario::admit_scenario_capture_parent(parent, budget)?;
        return Ok(CaptureParent {
            operation: "capture_browser_scenario",
            total_records: scenario.total_records as f64,
            records: scenario.records,
            limitations: scenario.limitations,
            artifact: json!({ "path": "", "sha256": null }),
        });
    }
    let capture = admit_har_capture_parent(parent, "environment-manifest", budget)?;
    let artifact = capture.get("artifact").unwrap_or(&Value::Null);
    Ok(CaptureParent {
        operation: "inspect_web_network_capture",
        records: capture
            .get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        total_records: capture
            .get("total_records")
            .and_then(Value::as_f64)
            .unwrap_or(0.0),
        limitations: crate::common::json::strings(
            capture.get("limitations").unwrap_or(&Value::Null),
        ),
        artifact: json!({
            "path": artifact.get("path").cloned().unwrap_or(Value::Null),
            "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
        }),
    })
}

/// `projectEnvironmentManifestView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let include_query = view
        .get("include_query_parameter_names")
        .and_then(Value::as_bool)
        != Some(false);
    let template_rules: Vec<String> =
        crate::common::json::strings(view.get("template_rules").unwrap_or(&Value::Null));
    let mut budget = Budget::new(SUBJECT);
    if !budget.retain(parent.admitted_bytes) {
        return Err(budget.over_budget());
    }
    let capture = admit_capture_parent(parent, &mut budget)?;
    let mut limitations = parent.limitations.clone();
    limitations.extend(capture.limitations.iter().cloned());
    limitations.push(
        "Tool templates, parameters and names are inferences from recorded request lines; they do not establish handler identity, URL-space schemas or causality.".into(),
    );
    if include_query {
        limitations.push(
            "Observed query parameter names do not establish required parameters, value types or a complete API schema.".into(),
        );
    }
    if !template_rules.is_empty() {
        limitations.push(format!(
            "Opt-in template rules {} merge recorded literals by shape; merged parameters may conflate distinct resources.",
            unique_sorted(template_rules.iter().cloned()).join(", ")
        ));
    }
    if (capture.records.len() as f64) < capture.total_records {
        limitations.push(
            "Parent contains an ordinal subset; the manifest covers only retained records.".into(),
        );
    }
    budget.add_limitations(limitations)?;
    let mut accumulator = Accumulator {
        budget,
        include_query,
        rules: template_rules.into_iter().collect(),
        groups: Vec::new(),
        group_index: HashMap::new(),
        records: Vec::new(),
        origins: Vec::new(),
        origin_index: HashMap::new(),
        unrepresented: 0,
        unrepresentable_body_key: false,
    };
    for record in &capture.records {
        accumulator.add(record)?;
    }
    let manifest = accumulator.finish()?;
    let mut out = Map::new();
    out.insert("kind".into(), json!("environment-manifest"));
    out.insert("view".into(), view.clone());
    out.insert("parent_evidence_id".into(), json!(parent.evidence_id));
    out.insert("parent_operation".into(), json!(capture.operation));
    out.insert("parent_digest".into(), json!(parent.digest()));
    out.insert("artifact".into(), capture.artifact);
    out.extend(manifest);
    Ok(Value::Object(out))
}
