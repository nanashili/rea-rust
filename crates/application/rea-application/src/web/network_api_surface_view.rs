//! Offline API-surface projection over retained web-network Evidence.
//!
//! The projection intentionally reads only the retained request lines. It does
//! not contact recorded destinations or infer handler identity from a route.

use rea_core::{
    evidence::record::EvidenceRecord,
    failure::{Detail, Failure},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub const OPERATION: &str = "inspect_analysis_view";
const CAPTURE_OPERATION: &str = "inspect_web_network_capture";
const ROUTE_RULES: [&str; 4] = ["numeric", "uuid", "hex", "iso-date"];

/// Project a retained HAR capture into a deterministic, paged API surface.
pub fn project(parent: &Value, view: &Value) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let raw =
        serde_json::value::to_raw_value(parent).map_err(|error| invalid(&error.to_string()))?;
    let record = EvidenceRecord::parse(&raw).map_err(|error| invalid(&error.to_string()))?;

    if !record.operation_matches(CAPTURE_OPERATION) {
        return Err(unsupported(
            &record,
            "api-surface requires inspect_web_network_capture Evidence.",
        ));
    }

    let request = parse_view(view)?;
    let capture: Value =
        serde_json::from_str(record.normalized_result().get()).map_err(|error| {
            invalid(&format!(
                "web network capture result is invalid JSON: {error}"
            ))
        })?;
    validate_capture(&capture)?;

    let mut accumulator = SurfaceAccumulator::new(request.include_query_parameter_names);
    let mut limitations = BTreeSet::new();
    extend_strings(&mut limitations, parent.get("limitations"));
    extend_strings(&mut limitations, capture.get("limitations"));
    limitations.insert(
        "Grouping does not establish handler identity, URL-space schemas or causality.".into(),
    );
    if request.include_query_parameter_names {
        limitations.insert("Observed query parameter names do not establish required parameters, value types or a complete API schema.".into());
    }

    let records = capture["records"].as_array().expect("validated records");
    let total_records = capture["total_records"]
        .as_u64()
        .expect("validated total_records") as usize;
    if records.len() < total_records {
        limitations.insert(
            "Parent contains an ordinal subset; the surface covers only retained records.".into(),
        );
    }
    for record in records {
        accumulator.add(record)?;
    }

    let page = accumulator.page(request.offset, request.limit);
    let artifact = capture["artifact"].clone();
    let mut body = json!({
        "kind": "api-surface",
        "view": view,
        "parent_evidence_id": record.evidence_id(),
        "parent_operation": CAPTURE_OPERATION,
        "parent_digest": record.evidence_id().strip_prefix("ev_").unwrap_or(record.evidence_id()),
        "artifact": {"path": artifact["path"], "sha256": artifact["sha256"]},
        "records": {"examined": records.len(), "total": total_records, "excluded": page["excluded_records"].as_array().map_or(0, Vec::len)},
        "limitations": limitations.into_iter().collect::<Vec<_>>(),
    });
    body.as_object_mut()
        .expect("object literal")
        .extend(page.as_object().expect("page object").clone());
    create_view_evidence(&record, view, body)
}

struct ViewRequest {
    offset: usize,
    limit: usize,
    include_query_parameter_names: bool,
}

fn parse_view(view: &Value) -> Result<ViewRequest, Failure> {
    let object = view
        .as_object()
        .ok_or_else(|| invalid("api-surface view must be an object"))?;
    for key in object.keys() {
        if !matches!(
            key.as_str(),
            "kind" | "offset" | "limit" | "include_query_parameter_names"
        ) {
            return Err(invalid("api-surface view contains an unknown field"));
        }
    }
    if object.get("kind").and_then(Value::as_str) != Some("api-surface") {
        return Err(invalid("view kind must be api-surface"));
    }
    let offset = object
        .get("offset")
        .map(parse_nonnegative)
        .transpose()?
        .unwrap_or(0);
    let limit = object
        .get("limit")
        .map(parse_positive)
        .transpose()?
        .unwrap_or(50);
    let include = object
        .get("include_query_parameter_names")
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| invalid("include_query_parameter_names must be boolean"))
        })
        .transpose()?
        .unwrap_or(false);
    Ok(ViewRequest {
        offset,
        limit,
        include_query_parameter_names: include,
    })
}

fn parse_nonnegative(value: &Value) -> Result<usize, Failure> {
    value
        .as_u64()
        .map(|value| value as usize)
        .ok_or_else(|| invalid("offset must be a non-negative integer"))
}

fn parse_positive(value: &Value) -> Result<usize, Failure> {
    let value = parse_nonnegative(value)?;
    if value == 0 {
        return Err(invalid("limit must be positive"));
    }
    Ok(value)
}

fn validate_capture(capture: &Value) -> Result<(), Failure> {
    if capture.get("format").and_then(Value::as_str) != Some("har") {
        return Err(invalid("api-surface does not support non-HAR captures"));
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

struct SurfaceAccumulator {
    include_query: bool,
    groups: BTreeMap<(String, String, String, String), Group>,
    excluded: Vec<Value>,
    unavailable_response: bool,
}

struct Group {
    method: String,
    origin: String,
    template: String,
    segments: Vec<Segment>,
    ordinals: Vec<u64>,
    statuses: BTreeSet<i64>,
    content_types: BTreeSet<String>,
    query_names: Option<BTreeMap<String, Vec<u64>>>,
}

struct Segment {
    index: usize,
    rule: &'static str,
    values: BTreeSet<String>,
}

impl SurfaceAccumulator {
    fn new(include_query: bool) -> Self {
        Self {
            include_query,
            groups: BTreeMap::new(),
            excluded: Vec::new(),
            unavailable_response: false,
        }
    }

    fn add(&mut self, record: &Value) -> Result<(), Failure> {
        let ordinal = record
            .get("ordinal")
            .and_then(Value::as_u64)
            .ok_or_else(|| invalid("capture record ordinal is missing"))?;
        let reported = record
            .get("reported")
            .ok_or_else(|| invalid("capture record reported value is missing"))?;
        let request = match reported.get("request").and_then(Value::as_object) {
            Some(request) => request,
            None => return self.exclude(ordinal, "request-unavailable"),
        };
        let url = match request.get("url") {
            Some(Value::Null) => return self.exclude(ordinal, "url-redacted"),
            Some(Value::String(url)) => url,
            Some(_) => return self.exclude(ordinal, "url-unparseable"),
            None => return self.exclude(ordinal, "request-unavailable"),
        };
        let method = match request
            .get("method")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        {
            Some(value) => value.to_owned(),
            None => return self.exclude(ordinal, "method-unavailable"),
        };
        let (origin, path, query) = match parse_url(url) {
            Some(parsed) => parsed,
            None => return self.exclude(ordinal, "url-unparseable"),
        };
        let (template, segments, rules) = route_template(&path);
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
        if status.is_none() || mime.is_none() {
            self.unavailable_response = true;
        }
        let query_names = if self.include_query {
            query.map(|value| query_parameter_names(value))
        } else {
            None
        };
        let key = (origin.clone(), template.clone(), method.clone(), rules);
        let group = self.groups.entry(key).or_insert_with(|| Group {
            method,
            origin,
            template,
            segments,
            ordinals: Vec::new(),
            statuses: BTreeSet::new(),
            content_types: BTreeSet::new(),
            query_names: self.include_query.then(BTreeMap::new),
        });
        for (index, segment) in group.segments.iter_mut().enumerate() {
            if let Some(value) = path_segment_value(&path, index, &segment.rule) {
                segment.values.insert(value);
            }
        }
        group.ordinals.push(ordinal);
        if let Some(status) = status {
            group.statuses.insert(status);
        }
        if let Some(mime) = mime {
            group.content_types.insert(mime);
        }
        if let Some(names) = query_names {
            if let Some(query_names) = group.query_names.as_mut() {
                for name in names {
                    query_names.entry(name).or_default().push(ordinal);
                }
            }
        }
        Ok(())
    }

    fn exclude(&mut self, ordinal: u64, reason: &str) -> Result<(), Failure> {
        self.excluded
            .push(json!({"ordinal": ordinal, "reason": reason}));
        Ok(())
    }

    fn page(&self, offset: usize, limit: usize) -> Value {
        let groups = self
            .groups
            .values()
            .skip(offset)
            .take(limit)
            .map(group_value)
            .collect::<Vec<_>>();
        let total = self.groups.len();
        json!({
            "coverage": page_coverage(offset, groups.len(), total),
            "groups": groups,
            "templated_groups": self.groups.values().filter(|group| !group.segments.is_empty()).count(),
            "excluded_records": self.excluded,
            "unknowns": if self.unavailable_response { vec!["Some retained records have unavailable status or content type values."] } else { Vec::<&str>::new() },
        })
    }
}

fn group_value(group: &Group) -> Value {
    let segments = group.segments.iter().map(|segment| json!({"segment_index":segment.index,"rule":segment.rule,"basis":"inferred","observed_values":segment.values})).collect::<Vec<_>>();
    let mut flags = Vec::new();
    if group.ordinals.len() == 1 {
        flags.push("single-sample");
    }
    if group.statuses.len() > 1 {
        flags.push("mixed-statuses");
    }
    if group.content_types.len() > 1 {
        flags.push("mixed-content-types");
    }
    let mut value = json!({"method":group.method,"origin":group.origin,"path_template":group.template,"templated_segments":segments,"record_ordinals":group.ordinals,"statuses":group.statuses,"content_types":group.content_types,"flags":flags});
    if let Some(query_names) = &group.query_names {
        value["query_parameter_names"] = json!(
            query_names
                .iter()
                .map(|(name, ordinals)| json!({"name":name,"record_ordinals":ordinals}))
                .collect::<Vec<_>>()
        );
    }
    value
}

fn route_template(path: &str) -> (String, Vec<Segment>, String) {
    let mut segments = Vec::new();
    let mut parts = Vec::new();
    let mut rules = String::new();
    for (index, value) in path.split('/').skip(1).enumerate() {
        let rule = segment_rule(value);
        if let Some(rule) = rule {
            segments.push(Segment {
                index,
                rule,
                values: BTreeSet::from([value.to_owned()]),
            });
            parts.push(format!("{{{rule}}}"));
            rules.push_str(&format!("{index}:{rule};"));
        } else {
            parts.push(value.to_owned());
        }
    }
    (format!("/{}", parts.join("/")), segments, rules)
}

fn path_segment_value(path: &str, index: usize, rule: &str) -> Option<String> {
    let value = path.split('/').skip(1).nth(index)?;
    (segment_rule(value) == Some(rule)).then(|| value.to_owned())
}

fn segment_rule(value: &str) -> Option<&'static str> {
    if !value.is_empty() && value.chars().all(|char| char.is_ascii_digit()) {
        return Some("numeric");
    }
    if value.len() == 36
        && value.as_bytes()[8] == b'-'
        && value.as_bytes()[13] == b'-'
        && value.as_bytes()[18] == b'-'
        && value.as_bytes()[23] == b'-'
        && value
            .chars()
            .enumerate()
            .all(|(index, char)| [8, 13, 18, 23].contains(&index) || char.is_ascii_hexdigit())
    {
        return Some("uuid");
    }
    if value.len() >= 32 && value.chars().all(|char| char.is_ascii_hexdigit()) {
        return Some("hex");
    }
    if value.len() == 10
        && value.as_bytes()[4] == b'-'
        && value.as_bytes()[7] == b'-'
        && value
            .chars()
            .enumerate()
            .all(|(index, char)| [4, 7].contains(&index) || char.is_ascii_digit())
    {
        return Some("iso-date");
    }
    None
}

fn parse_url(value: &str) -> Option<(String, String, Option<&str>)> {
    let scheme_end = value.find("://")?;
    let authority_end = value[scheme_end + 3..]
        .find(['/', '?', '#'])
        .map_or(value.len(), |index| scheme_end + 3 + index);
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
    let query = query_index.map(|index| &without_fragment[index + 1..]);
    Some((origin.to_owned(), path.to_owned(), query))
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
    let essence = value.split(';').next()?.trim_matches([' ', '\t']);
    if essence.contains('/')
        && essence
            .chars()
            .all(|char| char.is_ascii_alphanumeric() || "!#$%&'*+.^_`|~-".contains(char))
    {
        Some(essence.to_ascii_lowercase())
    } else {
        None
    }
}

fn page_coverage(offset: usize, examined: usize, total: usize) -> Value {
    let exhausted = offset >= total || offset.saturating_add(examined) >= total;
    json!({"status":if examined == 0 {"empty"} else {"page"},"examined":examined,"total":total,"next_offset":if exhausted {Value::Null} else {json!(offset + examined)},"exhausted":exhausted})
}

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
            ("operation".into(), Detail::Text(OPERATION.into())),
            (
                "evidence_id".into(),
                Detail::Text(record.evidence_id().into()),
            ),
        ]),
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
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(message.into())),
        ]),
    )
}

fn extend_strings(target: &mut BTreeSet<String>, value: Option<&Value>) {
    if let Some(values) = value.and_then(Value::as_array) {
        target.extend(values.iter().filter_map(Value::as_str).map(str::to_owned));
    }
}
