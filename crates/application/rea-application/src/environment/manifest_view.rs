//! Offline environment-manifest projection over retained network Evidence.
//!
//! The manifest is derived only from retained request lines.  Route templates,
//! parameter names and the primary origin are projections of those observations.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const HAR_OPERATION: &str = "inspect_web_network_capture";
const SCENARIO_OPERATION: &str = "capture_browser_scenario";
const ROUTE_RULES: [&str; 4] = ["numeric", "uuid", "hex", "iso-date"];
const TEMPLATE_RULES: [&str; 3] = ["after-uid-literal", "opaque-token", "sibling-variance"];
const STOP_WORDS: [&str; 12] = [
    "search", "settings", "errors", "list", "members", "versions", "health", "merged", "usage",
    "checks", "dto", "markdown",
];

pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;
    let request = parse_view(view)?;
    if !matches!(record.operation_matches(HAR_OPERATION), true)
        && !record.operation_matches(SCENARIO_OPERATION)
    {
        return Err(unsupported(
            &record,
            "environment-manifest requires web capture or browser scenario Evidence.",
        ));
    }
    if record.operation_matches(HAR_OPERATION) {
        let capture: Value = serde_json::from_str(record.normalized_result().get())
            .map_err(|error| invalid(&error.to_string()))?;
        validate_har(&capture)?;
        let records = capture["records"].as_array().expect("validated records");
        let total = capture["total_records"]
            .as_u64()
            .expect("validated total_records") as usize;
        return project_records(
            &record,
            view,
            &request,
            records,
            total,
            capture["artifact"].clone(),
        );
    }
    let scenario: Value = serde_json::from_str(record.normalized_result().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let records = scenario_records(&scenario)?;
    let total = records.len();
    project_records(
        &record,
        view,
        &request,
        &records,
        total,
        json!({"path":"", "sha256":null}),
    )
}

struct ViewRequest {
    rules: BTreeSet<String>,
    include_query: bool,
}

fn parse_view(view: &Value) -> Result<ViewRequest, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("environment-manifest view must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "kind" | "template_rules" | "include_query_parameter_names"
        ) {
            return Err(invalid(
                "environment-manifest view contains an unknown field",
            ));
        }
    }
    if object.get("kind").and_then(Value::as_str) != Some("environment-manifest") {
        return Err(invalid("view kind must be environment-manifest"));
    }
    let mut rules = BTreeSet::new();
    if let Some(value) = object.get("template_rules") {
        let values = value
            .as_array()
            .ok_or_else(|| invalid("template_rules must be an array"))?;
        for rule in values {
            let rule = rule
                .as_str()
                .ok_or_else(|| invalid("template_rules must contain strings"))?;
            if !TEMPLATE_RULES.contains(&rule) || !rules.insert(rule.into()) {
                return Err(invalid(
                    "template_rules must contain unique supported rules",
                ));
            }
        }
    }
    let include_query = object
        .get("include_query_parameter_names")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid("include_query_parameter_names must be boolean"))
        })
        .transpose()?
        .unwrap_or(true);
    Ok(ViewRequest {
        rules,
        include_query,
    })
}

fn validate_har(capture: &Value) -> Result<(), Failure> {
    if capture.get("format").and_then(Value::as_str) != Some("har") {
        return Err(unsupported_value(
            "environment-manifest supports HAR captures only",
        ));
    }
    if capture.get("artifact").and_then(Value::as_object).is_none()
        || capture["artifact"]
            .get("path")
            .and_then(Value::as_str)
            .is_none()
        || !capture["artifact"].get("sha256").is_some()
    {
        return Err(invalid("web capture artifact is missing"));
    }
    if capture.get("records").and_then(Value::as_array).is_none()
        || capture
            .get("total_records")
            .and_then(Value::as_u64)
            .is_none()
    {
        return Err(invalid("web capture records are missing"));
    }
    Ok(())
}

fn scenario_records(scenario: &Value) -> Result<Vec<Value>, Failure> {
    if let Some(records) = scenario.get("records").and_then(Value::as_array) {
        return Ok(records.clone());
    }
    let items = scenario
        .get("events")
        .and_then(|events| events.get("items"))
        .and_then(Value::as_array)
        .ok_or_else(|| unsupported_value("browser scenario has no retained network events"))?;
    let mut output = Vec::new();
    for (ordinal, item) in items.iter().enumerate() {
        if item.get("kind").and_then(Value::as_str) != Some("request") {
            continue;
        }
        let request = json!({"method": item.get("method").cloned().unwrap_or(Value::Null), "url": item.get("url").cloned().unwrap_or(Value::Null)});
        output
            .push(json!({"ordinal": ordinal, "reported": {"request": request}, "limitations": []}));
    }
    Ok(output)
}

fn project_records(
    record: &EvidenceRecord,
    view: &Value,
    request: &ViewRequest,
    records: &[Value],
    total: usize,
    artifact: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let mut accumulator = ManifestAccumulator::new(request.include_query, request.rules.clone());
    let mut limitations = BTreeSet::new();
    if request.include_query {
        limitations.insert("Observed query parameter names do not establish required parameters, value types or a complete API schema.".into());
    }
    limitations.insert("Tool templates, parameters and names are inferences from recorded request lines; they do not establish handler identity, URL-space schemas or causality.".into());
    if records.len() < total {
        limitations.insert(
            "Parent contains an ordinal subset; the manifest covers only retained records.".into(),
        );
    }
    for item in records {
        accumulator.add(item, &mut limitations)?;
    }
    let mut body = accumulator.finish(total, limitations);
    body["kind"] = Value::String("environment-manifest".into());
    body["view"] = view.clone();
    body["parent_evidence_id"] = Value::String(record.evidence_id().into());
    body["parent_operation"] = Value::String(if record.operation_matches(HAR_OPERATION) {
        HAR_OPERATION.into()
    } else {
        SCENARIO_OPERATION.into()
    });
    body["parent_digest"] = Value::String(
        record
            .evidence_id()
            .strip_prefix("ev_")
            .unwrap_or(record.evidence_id())
            .into(),
    );
    body["artifact"] = json!({"path": artifact.get("path").and_then(Value::as_str).unwrap_or(""), "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null)});
    create_view_evidence(record, view, body)
}

struct ManifestAccumulator {
    include_query: bool,
    rules: BTreeSet<String>,
    groups: BTreeMap<String, Group>,
    records: Vec<RecordLine>,
    origins: BTreeMap<String, OriginStats>,
    unrepresented: usize,
}
struct OriginStats {
    records: usize,
    json_like: usize,
}
struct Group {
    method: String,
    origin: String,
    template: String,
    parts: Vec<Part>,
    positions: Vec<usize>,
    statuses: BTreeSet<i64>,
    content_types: BTreeSet<String>,
    query_names: BTreeSet<String>,
    body_shape: Option<Value>,
    json_like: bool,
}
#[derive(Clone)]
enum Part {
    Literal(String),
    Parameter {
        rule: String,
        values: BTreeSet<String>,
    },
}
struct RecordLine {
    ordinal: u64,
    method: String,
    path: String,
    status: Option<i64>,
    content_type: Option<String>,
}

impl ManifestAccumulator {
    fn new(include_query: bool, rules: BTreeSet<String>) -> Self {
        Self {
            include_query,
            rules,
            groups: BTreeMap::new(),
            records: Vec::new(),
            origins: BTreeMap::new(),
            unrepresented: 0,
        }
    }
    fn add(&mut self, record: &Value, limitations: &mut BTreeSet<String>) -> Result<(), Failure> {
        let ordinal = record
            .get("ordinal")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("capture record ordinal is missing"))?;
        let reported = record.get("reported").unwrap_or(&Value::Null);
        let request = match reported.get("request").and_then(Value::as_object) {
            Some(value) => value,
            None => {
                self.unrepresented += 1;
                return Ok(());
            }
        };
        let url = match request.get("url") {
            Some(Value::String(value)) => value,
            Some(Value::Null) => {
                self.unrepresented += 1;
                return Ok(());
            }
            _ => {
                self.unrepresented += 1;
                return Ok(());
            }
        };
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("capture request method is unavailable"))?
            .to_owned();
        let (origin, path, query) = parse_url(url).ok_or_else(|| {
            self.unrepresented += 1;
            invalid("capture request URL is unparseable")
        })?;
        let (template, parts) = route_template(&path);
        let response = reported.get("response").and_then(Value::as_object);
        let status = response
            .and_then(|value| value.get("status"))
            .and_then(Value::as_i64)
            .filter(|value| *value != 0);
        let mime = response
            .and_then(|value| value.get("content"))
            .and_then(|value| value.get("mimeType"))
            .and_then(Value::as_str)
            .and_then(media_type_essence);
        let query_names = if self.include_query {
            query.map(query_parameter_names).unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let key = format!("{method}\u{1f}{origin}\u{1f}{template}");
        let body_shape = if self.groups.contains_key(&key)
            || !matches!(method.as_str(), "POST" | "PUT" | "PATCH")
        {
            None
        } else {
            request_body_shape(request)
        };
        let position = self.records.len();
        self.records.push(RecordLine {
            ordinal,
            method: method.clone(),
            path: path.clone(),
            status,
            content_type: mime.clone(),
        });
        let stats = self.origins.entry(origin.clone()).or_insert(OriginStats {
            records: 0,
            json_like: 0,
        });
        stats.records += 1;
        if is_json_like(mime.as_deref()) {
            stats.json_like += 1;
        }
        let group = self.groups.entry(key).or_insert_with(|| Group {
            method,
            origin,
            template: template.clone(),
            parts: parts.clone(),
            positions: Vec::new(),
            statuses: BTreeSet::new(),
            content_types: BTreeSet::new(),
            query_names: BTreeSet::new(),
            body_shape,
            json_like: false,
        });
        for (index, part) in parts.iter().enumerate() {
            if let (Part::Parameter { values, .. }, Some(Part::Parameter { values: next, .. })) =
                (&mut group.parts[index], parts.get(index))
            {
                for value in next {
                    values.insert(value.clone());
                }
            }
        }
        group.positions.push(position);
        group.json_like |= is_json_like(mime.as_deref());
        if let Some(value) = status {
            group.statuses.insert(value);
        }
        if let Some(value) = mime {
            group.content_types.insert(value);
        }
        group.query_names.extend(query_names);
        let _ = limitations;
        Ok(())
    }
    fn finish(self, total: usize, mut limitations: BTreeSet<String>) -> Value {
        if self.unrepresented > 0 {
            limitations.insert(format!("{} retained records without a usable request line are not represented in the manifest.", self.unrepresented));
        }
        let primary = self
            .origins
            .iter()
            .max_by(|(left, a), (right, b)| {
                a.json_like
                    .cmp(&b.json_like)
                    .then(a.records.cmp(&b.records))
                    .then_with(|| right.cmp(left))
            })
            .map(|(origin, _)| origin.clone());
        if primary.is_none() {
            limitations.insert(
                "No retained record had a parseable origin; the manifest names no primary origin."
                    .into(),
            );
        }
        let mut tools = Vec::new();
        let mut excluded = Vec::new();
        let mut cited = BTreeSet::new();
        let mut templated = 0;
        for group in self.groups.values() {
            let parts = apply_rules(group.parts.clone(), &self.rules);
            let is_tool = Some(&group.origin) == primary.as_ref()
                && (group.template.starts_with("/api/")
                    || group.template.starts_with("/apis/")
                    || group.json_like);
            if is_tool {
                let tool = tool_value(group, parts, &self.records);
                for ordinal in tool["record_ordinals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_u64)
                {
                    cited.insert(ordinal);
                }
                if tool["params"].as_array().is_some_and(|p| !p.is_empty()) {
                    templated += 1;
                }
                tools.push(tool);
            } else {
                let reason = if Some(&group.origin) != primary.as_ref() {
                    "other-origin"
                } else if is_asset(group) {
                    "ui-page-or-asset"
                } else {
                    "non-json"
                };
                if parts
                    .iter()
                    .any(|part| matches!(part, Part::Parameter { .. }))
                {
                    templated += 1;
                }
                excluded.push(json!({"method":group.method,"origin":group.origin,"path_template":group.template,"reason":reason}));
            }
        }
        tools.sort_by(|a, b| {
            a["path_template"]
                .as_str()
                .cmp(&b["path_template"].as_str())
                .then(a["method"].as_str().cmp(&b["method"].as_str()))
        });
        excluded.sort_by(|a, b| {
            a["origin"]
                .as_str()
                .cmp(&b["origin"].as_str())
                .then(
                    a["path_template"]
                        .as_str()
                        .cmp(&b["path_template"].as_str()),
                )
                .then(a["method"].as_str().cmp(&b["method"].as_str()))
        });
        let records = self.records.iter().filter(|line| cited.contains(&line.ordinal)).map(|line| json!({"ordinal":line.ordinal,"method":line.method,"path":line.path,"status":line.status,"content_type":line.content_type})).collect::<Vec<_>>();
        let name = primary.as_deref().map(environment_name).unwrap_or_default();
        json!({"origin":primary.unwrap_or_default(),"name":name,"tools":tools,"records":records,"excluded":excluded,"unknowns":[{"kind":"authorization-model","statement":"Authorization headers and cookies are structurally excluded from captures; the manifest states no authorization model."},{"kind":"response-semantics","statement":"Recorded statuses and bodies are retained only as pointers to parent records; the manifest states no response semantics."},{"kind":"state-transition","statement":"Recorded exchanges are independent observations; the manifest states no ordering, side effects or state transitions between tools."}],"templated_groups":templated,"coverage":{"status":"complete-within-view","examined":tools.len(),"total":tools.len(),"next_offset":Value::Null,"exhausted":true},"limitations":limitations.into_iter().collect::<Vec<_>>()})
    }
}

fn route_template(path: &str) -> (String, Vec<Part>) {
    let mut rendered = Vec::new();
    let mut parts = Vec::new();
    for segment in path.trim_start_matches('/').split('/') {
        if let Some(rule) = segment_rule(segment) {
            rendered.push(format!("{{{rule}}}"));
            parts.push(Part::Parameter {
                rule: rule.into(),
                values: BTreeSet::from([segment.into()]),
            });
        } else {
            rendered.push(segment.into());
            parts.push(Part::Literal(segment.into()));
        }
    }
    (format!("/{}", rendered.join("/")), parts)
}
fn apply_rules(mut parts: Vec<Part>, rules: &BTreeSet<String>) -> Vec<Part> {
    if rules.contains("after-uid-literal") {
        for index in 1..parts.len() {
            if matches!((&parts[index-1], &parts[index]), (Part::Literal(previous), Part::Literal(current)) if previous == "uid" && !STOP_WORDS.iter().any(|word| *word == current.as_str()))
            {
                let current = match &parts[index] {
                    Part::Literal(value) => value.clone(),
                    _ => String::new(),
                };
                parts[index] = Part::Parameter {
                    rule: "after-uid-literal".into(),
                    values: BTreeSet::from([current]),
                };
            }
        }
    }
    if rules.contains("opaque-token") {
        for part in &mut parts {
            if let Part::Literal(value) = part {
                if opaque_token(value) && !value.starts_with('v') {
                    *part = Part::Parameter {
                        rule: "opaque-token".into(),
                        values: BTreeSet::from([value.clone()]),
                    };
                }
            }
        }
    }
    parts
}
fn tool_value(group: &Group, parts: Vec<Part>, records: &[RecordLine]) -> Value {
    let mut names = Vec::new();
    let mut used = BTreeMap::new();
    for (index, part) in parts.iter().enumerate() {
        if let Part::Parameter { rule, .. } = part {
            let base = parameter_base(&parts, index, rule);
            let count = used.entry(base.clone()).or_insert(0);
            *count += 1;
            names.push((
                index,
                if *count == 1 {
                    base
                } else {
                    format!("{}_{}", base, count)
                },
            ));
        }
    }
    let mut next = 0;
    let path = format!(
        "/{}",
        parts
            .iter()
            .map(|part| match part {
                Part::Literal(value) => value.clone(),
                Part::Parameter { rule, .. } => {
                    let name = names
                        .get(next)
                        .map(|(_, value)| value.clone())
                        .unwrap_or_default();
                    next += 1;
                    if ROUTE_RULES.contains(&rule.as_str()) {
                        format!("{{{rule}}}")
                    } else {
                        format!("{{{name}}}")
                    }
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    );
    let params = names.iter().map(|(index, name)| { let Part::Parameter { rule, values } = &parts[*index] else { unreachable!() }; json!({"index":index,"name":name,"rule":rule,"basis":"inferred","observed_values":values}) }).collect::<Vec<_>>();
    let name = tool_name(&group.method, &parts, &names);
    json!({"name":name,"method":group.method,"path_template":path,"api_surface_template":group.template,"params":params,"query_parameter_names":group.query_names,"body_shape":group.body_shape,"statuses":group.statuses,"content_types":group.content_types,"record_ordinals":group.positions.iter().map(|position| records[*position].ordinal).collect::<Vec<_>>()})
}
fn parameter_base(parts: &[Part], index: usize, rule: &str) -> String {
    match rule {
        "numeric" => "id".to_owned(),
        "uuid" => "uuid".to_owned(),
        "hex" => "hash".to_owned(),
        "iso-date" => "date".to_owned(),
        "after-uid-literal" | "opaque-token" => "uid".to_owned(),
        "sibling-variance" => parts
            .get(index.saturating_sub(1))
            .and_then(|part| match part {
                Part::Literal(value) => Some(format!("{}_id", value.trim_end_matches('s'))),
                _ => None,
            })
            .unwrap_or_else(|| "id".to_owned()),
        _ => "id".to_owned(),
    }
}
fn tool_name(method: &str, parts: &[Part], names: &[(usize, String)]) -> String {
    let mut values = vec![method.to_ascii_lowercase()];
    for part in parts {
        if let Part::Literal(value) = part {
            if !value.is_empty()
                && !matches!(value.as_str(), "api" | "apis" | "namespaces" | "default")
            {
                values.push(value.split('.').next().unwrap_or(value).into());
            }
        }
    }
    if !names.is_empty() {
        values.push("by".into());
        values.extend(names.iter().map(|(_, name)| name.clone()));
    }
    let mut name = sanitize(&values.join("_"));
    if name.is_empty() {
        name = "tool".into();
    }
    name.truncate(60);
    name
}
fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() {
                char.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}
fn request_body_shape(request: &Map<String, Value>) -> Option<Value> {
    let body = request.get("postData")?.as_object()?;
    if !body
        .get("mimeType")
        .and_then(Value::as_str)
        .and_then(media_type_essence)
        .is_some_and(|mime| is_json(mime.as_str()))
    {
        return None;
    }
    let text = body.get("text")?.as_str()?;
    let object = serde_json::from_str::<Value>(text)
        .ok()?
        .as_object()?
        .clone();
    let properties = object
        .into_iter()
        .filter_map(|(key, value)| (!key.eq("__proto__")).then(|| (key, json!(json_type(&value)))))
        .collect::<Map<_, _>>();
    Some(json!({"type":"object","properties":properties}))
}
fn json_type(value: &Value) -> &'static str {
    match value {
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "boolean",
        Value::Object(_) => "object",
        Value::Array(_) => "array",
        Value::Null => "null",
    }
}
fn is_asset(group: &Group) -> bool {
    group.content_types.iter().any(|mime| {
        mime == "text/html"
            || mime == "text/css"
            || mime.starts_with("image/")
            || mime.starts_with("font/")
            || mime.starts_with("audio/")
            || mime.starts_with("video/")
    }) || group
        .template
        .split('/')
        .last()
        .is_some_and(|part| part.contains('.'))
}
fn is_json(mime: &str) -> bool {
    mime == "application/json" || (mime.starts_with("application/") && mime.ends_with("+json"))
}
fn is_json_like(mime: Option<&str>) -> bool {
    mime.is_some_and(|value| is_json(value) || matches!(value, "text/plain" | "text/markdown"))
}
fn opaque_token(value: &str) -> bool {
    value.len() >= 12
        && value.chars().all(|char| char.is_ascii_alphanumeric())
        && value.chars().any(|char| char.is_ascii_digit())
        && value.chars().any(|char| char.is_ascii_lowercase())
}
fn segment_rule(value: &str) -> Option<&'static str> {
    if !value.is_empty() && value.chars().all(|char| char.is_ascii_digit()) {
        Some("numeric")
    } else if value.len() == 36
        && [8, 13, 18, 23]
            .iter()
            .all(|index| value.as_bytes().get(*index) == Some(&b'-'))
        && value
            .chars()
            .enumerate()
            .all(|(index, char)| [8, 13, 18, 23].contains(&index) || char.is_ascii_hexdigit())
    {
        Some("uuid")
    } else if value.len() >= 32 && value.chars().all(|char| char.is_ascii_hexdigit()) {
        Some("hex")
    } else if value.len() == 10
        && value.as_bytes().get(4) == Some(&b'-')
        && value.as_bytes().get(7) == Some(&b'-')
        && value
            .chars()
            .enumerate()
            .all(|(index, char)| [4, 7].contains(&index) || char.is_ascii_digit())
    {
        Some("iso-date")
    } else {
        None
    }
}
fn parse_url(value: &str) -> Option<(String, String, Option<&str>)> {
    let scheme = value.find("://")?;
    let authority_end = value[scheme + 3..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |index| scheme + 3 + index);
    let origin = &value[..authority_end];
    if origin.is_empty() {
        return None;
    }
    let rest = &value[authority_end..];
    let fragment = rest.find('#').unwrap_or(rest.len());
    let without_fragment = &rest[..fragment];
    let query_index = without_fragment.find('?');
    let path_end = query_index.unwrap_or(without_fragment.len());
    let path = if path_end == 0 {
        "/"
    } else {
        &without_fragment[..path_end]
    };
    Some((
        origin.into(),
        path.into(),
        query_index.map(|index| &without_fragment[index + 1..]),
    ))
}
fn query_parameter_names(query: &str) -> BTreeSet<String> {
    query
        .split('&')
        .filter_map(|pair| {
            pair.split_once('=')
                .or(Some((pair, "")))
                .map(|(name, _)| percent_decode(name))
        })
        .filter(|name| !name.is_empty())
        .collect()
}
fn percent_decode(value: &str) -> String {
    let mut output = String::new();
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'+' {
            output.push(' ');
            index += 1;
        } else if index + 2 < bytes.len() && bytes[index] == b'%' {
            if let Ok(byte) = u8::from_str_radix(&value[index + 1..index + 3], 16) {
                output.push(byte as char);
                index += 3;
            } else {
                output.push('%');
                index += 1;
            }
        } else {
            output.push(bytes[index] as char);
            index += 1;
        }
    }
    output
}
fn media_type_essence(value: &str) -> Option<String> {
    let value = value.split(';').next()?.trim();
    (!value.is_empty()
        && value.contains('/')
        && value
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(char)))
    .then(|| value.to_ascii_lowercase())
}
fn environment_name(origin: &str) -> String {
    let name = origin
        .split("//")
        .nth(1)
        .unwrap_or(origin)
        .to_ascii_lowercase()
        .chars()
        .map(|char| {
            if char.is_ascii_alphanumeric() {
                char
            } else {
                '-'
            }
        })
        .collect::<String>();
    name.trim_matches('-').to_owned()
}
fn extend_strings(_target: &mut BTreeSet<String>, _value: Option<&Value>) {}
fn create_view_evidence(
    record: &EvidenceRecord,
    view: &Value,
    body: Value,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let authority: Value = serde_json::from_str(record.authority().get())
        .map_err(|error| invalid(&error.to_string()))?;
    let unsigned = json!({"subject":null,"provider":{"id":"analysis-view","name":"REA retained analysis view","version":"1"},"analysis_profile":null,"predicate_type":"rea.analysis-view","operation":OPERATION,"parameters":{"parent_evidence_id":record.evidence_id(),"view":view},"raw_result":null,"normalized_result":body,"confidence":"derived","authority":authority,"environment":null,"limitations":[],"relationship_coverage":null,"locations":[],"evidence_links":[record.evidence_id()]});
    let raw =
        serde_json::value::to_raw_value(&unsigned).map_err(|error| invalid(&error.to_string()))?;
    let derived =
        EvidenceRecord::create_unsigned(&raw).map_err(|error| invalid(&error.to_string()))?;
    serde_json::value::RawValue::from_string(derived.raw().get().to_owned())
        .map_err(|error| invalid(&error.to_string()))
}
fn unsupported(record: &EvidenceRecord, message: &str) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        message.into(),
        false,
        "Select compatible retained Evidence and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("evidence_id", Detail::Text(record.evidence_id().into())),
        ]),
    )
}
fn unsupported_value(message: &str) -> Failure {
    Failure::new(
        "unsupported_target",
        "unsupported_target",
        message.into(),
        false,
        "Select compatible retained Evidence and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
fn invalid(message: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        message.into(),
        false,
        "Correct the retained Evidence or view and retry.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("reason", Detail::Text(message.into())),
        ]),
    )
}
