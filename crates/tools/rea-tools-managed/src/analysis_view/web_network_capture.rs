//! Views over retained `inspect_web_network_capture` Evidence.
//!
//! Compatibility owners: `src/domain/analysisView/webNetworkCaptureView.ts`
//! and `src/domain/analysisView/qlogCaptureView.ts`. Pages select immutable
//! retained facts; no capture file, provider or network is consulted.
use super::web_network::capture::{self, CAPTURE_OPERATION};
use crate::common::json::{js_len, sha256_hex, without};
use crate::common::schema;
use crate::common::view::{
    Parent, complete_within_view, offset_limit, page, page_coverage, view_error, view_kind,
};
use base64::Engine;
use rea_core::analysis_error::AnalysisError;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};

const RECORD_SCOPE: &str = "Capture record pages cover the records selected into the parent Evidence, in that selected order; total_records counts the original decoded capture.";
const PREVIEW_SCOPE: &str = "Preview selects recorded headline fields and byte descriptors; headers, XML, bodies, message data and other fields remain in complete record pages. Missing preview fields do not establish their absence from the producer record.";
const QLOG_SCOPE: &str = "Qlog fact pages retain all-recorded-events-before-selection scope. Exhausting a page does not establish network completeness, body recovery, retransmission or actual loss.";

/// `projectWebNetworkCaptureView`.
pub fn project(parent: &Parent<'_>, view: &Value) -> Result<Value, AnalysisError> {
    let kind = view_kind(view);
    if !matches!(kind, "summary" | "capture" | "qlog") {
        return Err(view_error(
            &["view"],
            "invalid_value",
            "Historical captures support summary, capture record pages, qlog fact pages and admitted api-surface or environment-manifest views.",
        ));
    }
    let report = parse_capture_parent(parent)?;
    let artifact = report.get("artifact").cloned().unwrap_or(Value::Null);
    let digest_excluded = artifact.get("sha256").is_none_or(Value::is_null);

    let mut limitations: Vec<String> = Vec::new();
    for limitation in parent
        .limitations
        .iter()
        .cloned()
        .chain(crate::common::json::strings(
            report.get("limitations").unwrap_or(&Value::Null),
        ))
        .chain(std::iter::once(RECORD_SCOPE.to_owned()))
    {
        if !limitations.contains(&limitation) {
            limitations.push(limitation);
        }
    }
    let mut unknowns = vec![
        "Historical records do not establish live runtime attribution or deployment authenticity."
            .to_owned(),
    ];
    if digest_excluded {
        unknowns.push("The explicitly excluded artifact digest remains unknown.".to_owned());
    }
    let records = report
        .get("records")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let format = report
        .get("format")
        .and_then(Value::as_str)
        .unwrap_or_default();

    let mut out = Map::new();
    out.insert("kind".into(), json!(kind));
    out.insert("view".into(), view.clone());
    out.insert("parent_evidence_id".into(), json!(parent.evidence_id));
    out.insert("parent_operation".into(), json!(CAPTURE_OPERATION));
    out.insert("parent_digest".into(), json!(parent.digest()));
    out.insert(
        "artifact".into(),
        json!({
            "path": artifact.get("path").cloned().unwrap_or(Value::Null),
            "sha256": artifact.get("sha256").cloned().unwrap_or(Value::Null),
        }),
    );
    out.insert("limitations".into(), json!(limitations));
    out.insert("unknowns".into(), json!(unknowns));

    match kind {
        "summary" => {
            let mut summary = Map::new();
            summary.insert("artifact".into(), artifact.clone());
            summary.insert(
                "decoder".into(),
                report.get("decoder").cloned().unwrap_or(Value::Null),
            );
            summary.insert("format".into(), json!(format));
            summary.insert(
                "total_records".into(),
                report.get("total_records").cloned().unwrap_or(Value::Null),
            );
            summary.insert("retained_records".into(), json!(records.len()));
            summary.insert(
                "runtime_attribution".into(),
                report
                    .get("runtime_attribution")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            if format == "qlog" {
                summary.insert(
                    "qlog".into(),
                    summarize_qlog(report.get("qlog").unwrap_or(&Value::Null)),
                );
            }
            out.insert("summary".into(), Value::Object(summary));
            out.insert(
                "coverage".into(),
                complete_within_view(records.len(), records.len()),
            );
        }
        "qlog" => {
            if format != "qlog" {
                return Err(view_error(
                    &["view", "kind"],
                    "invalid_value",
                    "Qlog fact views require retained qlog Evidence.",
                ));
            }
            let (context, page, coverage) =
                project_qlog_page(report.get("qlog").unwrap_or(&Value::Null), view)?;
            out.insert("context".into(), context);
            out.insert("page".into(), page);
            out.insert("coverage".into(), coverage);
            limitations.push(QLOG_SCOPE.to_owned());
            out.insert("limitations".into(), json!(limitations));
        }
        _ => {
            let (offset, limit) = offset_limit(view);
            let selected = page(records, offset, limit);
            let complete = view.get("detail").and_then(Value::as_str) == Some("complete");
            let items: Vec<Value> = if complete {
                selected.clone()
            } else {
                selected
                    .iter()
                    .map(|record| preview(record, format))
                    .collect()
            };
            out.insert("items".into(), Value::Array(items));
            out.insert(
                "coverage".into(),
                page_coverage(offset, selected.len(), records.len()),
            );
            if !complete {
                limitations.push(PREVIEW_SCOPE.to_owned());
            }
            out.insert("limitations".into(), json!(limitations));
        }
    }
    Ok(Value::Object(out))
}

/// `parseCaptureParent`: authenticate the retained report and its subject.
fn parse_capture_parent(parent: &Parent<'_>) -> Result<std::sync::Arc<Value>, AnalysisError> {
    let report = capture::parse_capture(parent)?.map_err(|issues| {
        let issues = schema::prefix_issues(issues, &["source", "normalized_result"]);
        let input = json!({ "source": { "normalized_result": parent.normalized_result } });
        schema::input_error_from_issues(crate::common::view::OPERATION, &issues, &input, Vec::new())
    })?;
    let artifact = report.get("artifact").unwrap_or(&Value::Null);
    if !artifact.get("sha256").is_none_or(Value::is_null)
        && !capture::subject_identifies(parent, artifact)
    {
        return Err(capture::subject_error());
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Qlog facts (`qlogCaptureView.ts`).
// ---------------------------------------------------------------------------

fn len_at(value: &Value, key: &str) -> usize {
    value.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

/// `summarizeQlogCapture`.
fn summarize_qlog(qlog: &Value) -> Value {
    let traces = array(qlog, "traces");
    let mut summary = without(qlog, &["traces"]);
    summary.insert("trace_count".into(), json!(traces.len()));
    summary.insert(
        "retained_stream_count".into(),
        json!(
            traces
                .iter()
                .map(|trace| len_at(trace, "streams"))
                .sum::<usize>()
        ),
    );
    summary.insert(
        "loss_declaration_count".into(),
        json!(
            traces
                .iter()
                .map(|trace| len_at(trace, "loss_declarations"))
                .sum::<usize>()
        ),
    );
    summary.insert(
        "incomplete_fact_record_count".into(),
        json!(
            traces
                .iter()
                .map(|trace| len_at(trace, "incomplete_fact_records"))
                .sum::<usize>()
        ),
    );
    Value::Object(summary)
}

/// `summarizeTrace`.
fn summarize_trace(trace: &Value) -> Value {
    let mut summary = without(
        trace,
        &["streams", "loss_declarations", "incomplete_fact_records"],
    );
    summary.insert("stream_count".into(), json!(len_at(trace, "streams")));
    summary.insert(
        "loss_declaration_count".into(),
        json!(len_at(trace, "loss_declarations")),
    );
    summary.insert(
        "incomplete_fact_record_count".into(),
        json!(len_at(trace, "incomplete_fact_records")),
    );
    Value::Object(summary)
}

/// `summarizeStream`.
fn summarize_stream(stream: &Value) -> Value {
    let mut summary = without(
        stream,
        &["contributions", "covered_ranges", "reported_final_sizes"],
    );
    summary.insert(
        "contribution_count".into(),
        json!(len_at(stream, "contributions")),
    );
    summary.insert(
        "covered_range_count".into(),
        json!(len_at(stream, "covered_ranges")),
    );
    summary.insert(
        "reported_final_size_count".into(),
        json!(len_at(stream, "reported_final_sizes")),
    );
    Value::Object(summary)
}

/// ECMAScript `===` for JSON values selected by a request (numbers by value).
fn same(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (Some(Value::Number(left)), Some(Value::Number(right))) => left.as_f64() == right.as_f64(),
        (left, right) => left == right,
    }
}

/// `projectQlogCapturePage`: context, page and coverage.
fn project_qlog_page(qlog: &Value, view: &Value) -> Result<(Value, Value, Value), AnalysisError> {
    let (offset, limit) = offset_limit(view);
    let facet = view
        .get("facet")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let invalid = |field: &str, message: &str| {
        crate::common::view::input_error(vec![rea_core::analysis_error::InputIssue::new(
            &["view", field],
            "invalid_value",
            message,
        )])
    };
    let traces = array(qlog, "traces");
    let (items, total): (Vec<Value>, usize) = if facet == "traces" {
        (
            page(traces, offset, limit)
                .iter()
                .map(summarize_trace)
                .collect(),
            traces.len(),
        )
    } else {
        let matches: Vec<&Value> = traces
            .iter()
            .filter(|trace| same(trace.get("trace_index"), view.get("trace_index")))
            .collect();
        let [trace] = matches.as_slice() else {
            return Err(invalid(
                "trace_index",
                "Select one unambiguous retained trace index.",
            ));
        };
        match facet {
            "streams" => {
                let streams = array(trace, "streams");
                (
                    page(streams, offset, limit)
                        .iter()
                        .map(summarize_stream)
                        .collect(),
                    streams.len(),
                )
            }
            "loss-declarations" => {
                let rows = array(trace, "loss_declarations");
                (page(rows, offset, limit), rows.len())
            }
            "incomplete-records" => {
                let rows = array(trace, "incomplete_fact_records");
                (page(rows, offset, limit), rows.len())
            }
            _ => {
                let streams: Vec<&Value> = array(trace, "streams")
                    .iter()
                    .filter(|stream| {
                        same(stream.get("stream_id"), view.get("stream_id"))
                            && same(stream.get("direction"), view.get("direction"))
                    })
                    .collect();
                let [stream] = streams.as_slice() else {
                    return Err(invalid(
                        "stream_id",
                        "Select one unambiguous retained stream ID and direction within the trace.",
                    ));
                };
                let key = match facet {
                    "contributions" => "contributions",
                    "ranges" => "covered_ranges",
                    _ => "reported_final_sizes",
                };
                let rows = array(stream, key);
                (page(rows, offset, limit), rows.len())
            }
        }
    };
    let examined = items.len();
    let context = Value::Object(without(qlog, &["traces"]));
    Ok((
        context,
        json!({ "facet": facet, "items": items }),
        page_coverage(offset, examined, total),
    ))
}

// ---------------------------------------------------------------------------
// Record previews.
// ---------------------------------------------------------------------------

const HEADLINE_FIELDS: [&str; 7] = [
    "method",
    "url",
    "httpVersion",
    "http_version",
    "status",
    "statusText",
    "reason",
];
const MITMPROXY_PATH_MAX_LENGTH: usize = 2 * 1024;

fn mitmproxy_headline_fields(key: &str) -> &'static [&'static str] {
    match key {
        "request" => &["scheme", "host", "port", "authority", "path"],
        "response" => &["status_code"],
        _ => &[],
    }
}

/// `integerIn(value, min, max)`.
fn integer_in(value: &Value, min: f64, max: f64) -> bool {
    value
        .as_f64()
        .is_some_and(|number| number.fract() == 0.0 && number >= min && number <= max)
}

/// `hasControl`: a C0 code unit, DEL or (optionally) a space.
fn has_control(value: &str, include_space: bool) -> bool {
    value.chars().any(|character| {
        (character as u32) < 0x20 || character == '\u{7f}' || (include_space && character == ' ')
    })
}

/// `hostLike` (lone surrogates cannot occur in parsed transport strings).
fn host_like(value: &Value, max_length: usize) -> bool {
    value.as_str().is_some_and(|text| {
        js_len(text) <= max_length && !has_control(text, true) && !text.contains(['@', '/', '\\'])
    })
}

/// `headlineShape`.
fn headline_shape(field: &str, value: &Value) -> bool {
    match field {
        "scheme" => value.as_str().is_some_and(|text| {
            let bytes = text.as_bytes();
            !bytes.is_empty()
                && bytes.len() <= 32
                && bytes[0].is_ascii_alphabetic()
                && bytes[1..]
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'.' | b'-'))
        }),
        "host" => host_like(value, 255),
        "authority" => host_like(value, 262),
        "port" => integer_in(value, 0.0, 65_535.0),
        "status_code" => integer_in(value, 100.0, 999.0),
        "path" => value.as_str().is_some_and(|text| {
            js_len(text) <= MITMPROXY_PATH_MAX_LENGTH
                && !has_control(text, false)
                && !text.contains('@')
                && (text == "*"
                    || (text.starts_with('/')
                        && !text.starts_with("//")
                        && !text.starts_with("/\\")))
        }),
        _ => false,
    }
}

/// ECMAScript `String(number)` for the integer slots admitted by the shape check.
fn number_text(value: &Value) -> Option<String> {
    let number = value.as_f64()?;
    Some(if number.fract() == 0.0 && number.abs() < 1e21 {
        format!("{}", number as i64)
    } else {
        value.to_string()
    })
}

/// `describesText`: retained producer bytes that are exactly the text's UTF-8.
fn describes_text(descriptor: &Value, text: &str) -> bool {
    let field = |key: &str| descriptor.get(key);
    field("representation").and_then(Value::as_str) == Some("producer-bytes")
        && field("state").and_then(Value::as_str) == Some("retained")
        && field("bytes").and_then(Value::as_f64) == Some(text.len() as f64)
        && field("content_base64").and_then(Value::as_str)
            == Some(
                base64::engine::general_purpose::STANDARD
                    .encode(text.as_bytes())
                    .as_str(),
            )
        && field("sha256").and_then(Value::as_str) == Some(sha256_hex(text.as_bytes()).as_str())
}

/// `representationMatches`.
fn representation_matches(
    field: &str,
    value: &Value,
    sidecars: &[&Value],
    bytes: &[&Value],
) -> bool {
    if matches!(field, "port" | "status_code") {
        return bytes.is_empty()
            && value.is_number()
            && sidecars.len() == 1
            && sidecars[0].get("producer_type").and_then(Value::as_str) == Some("integer")
            && sidecars[0]
                .get("literal")
                .and_then(Value::as_str)
                .map(str::to_owned)
                == number_text(value);
    }
    if !sidecars.is_empty() || bytes.len() > 1 {
        return false;
    }
    match bytes.first() {
        None => true,
        Some(descriptor) => value
            .as_str()
            .is_some_and(|text| describes_text(descriptor, text)),
    }
}

/// `FacetIndex`: a record's facet coordinates, indexed once.
struct FacetIndex<'a> {
    sidecars: HashMap<&'a str, Vec<&'a Value>>,
    bytes: HashMap<&'a str, Vec<&'a Value>>,
    containers: HashSet<String>,
    withheld: HashSet<String>,
    omitted_names: HashSet<String>,
}

impl FacetIndex<'_> {
    fn scalar(&self, pointer: &str) -> bool {
        self.sidecars.contains_key(pointer) || self.bytes.contains_key(pointer)
    }

    /// `usableScalar`.
    fn usable_scalar(&self, pointer: &str) -> bool {
        !self.omitted_names.contains(pointer)
            && !self.containers.contains(pointer)
            && !self.withheld.contains(pointer)
            && !ancestors_of(pointer)
                .iter()
                .any(|ancestor| self.withheld.contains(*ancestor) || self.scalar(ancestor))
    }

    /// `mitmproxyHeadline`.
    fn headline(&self, pointer: &str, field: &str, value: &Value) -> bool {
        self.usable_scalar(pointer)
            && headline_shape(field, value)
            && representation_matches(
                field,
                value,
                self.sidecars
                    .get(pointer)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
                self.bytes
                    .get(pointer)
                    .map(Vec::as_slice)
                    .unwrap_or_default(),
            )
    }
}

/// `ancestorsOf`: strict ancestors of a JSON pointer, from the root down.
fn ancestors_of(pointer: &str) -> Vec<&str> {
    pointer
        .match_indices('/')
        .map(|(at, _)| &pointer[..at])
        .collect()
}

/// `addAncestors`: add strict ancestors, stopping at one already present.
fn add_ancestors(pointer: &str, into: &mut HashSet<String>) {
    for (at, _) in pointer.rmatch_indices('/') {
        let ancestor = &pointer[..at];
        if into.contains(ancestor) {
            return;
        }
        into.insert(ancestor.to_owned());
    }
}

fn pointer_of(value: &Value) -> &str {
    value
        .get("pointer")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// `indexFacets`.
fn index_facets(record: &Value) -> FacetIndex<'_> {
    let mut index = FacetIndex {
        sidecars: HashMap::new(),
        bytes: HashMap::new(),
        containers: HashSet::new(),
        withheld: HashSet::new(),
        omitted_names: HashSet::new(),
    };
    for literal in array(record, "numeric_literals") {
        add_ancestors(pointer_of(literal), &mut index.containers);
        index
            .sidecars
            .entry(pointer_of(literal))
            .or_default()
            .push(literal);
    }
    for field in array(record, "binary_fields") {
        let pointer = pointer_of(field);
        add_ancestors(pointer, &mut index.containers);
        if field.get("state").and_then(Value::as_str) == Some("redacted") {
            index.withheld.insert(pointer.to_owned());
        }
        index.bytes.entry(pointer).or_default().push(field);
    }
    for redaction in array(record, "redactions") {
        let pointer = pointer_of(redaction);
        add_ancestors(pointer, &mut index.containers);
        if redaction.get("scope").is_some() {
            index.omitted_names.insert(pointer.to_owned());
        } else {
            index.withheld.insert(pointer.to_owned());
        }
    }
    index
}

/// `selectHeadlines`.
fn select_headlines(
    fields: &Map<String, Value>,
    key: &str,
    facets: Option<&FacetIndex<'_>>,
    selected_pointers: &mut HashSet<String>,
) -> Value {
    let mut selected = Map::new();
    let candidates = HEADLINE_FIELDS.iter().map(|field| (*field, None)).chain(
        facets
            .map(|_| mitmproxy_headline_fields(key))
            .unwrap_or_default()
            .iter()
            .map(|field| (*field, facets)),
    );
    for (field, index) in candidates {
        let Some(value) = fields.get(field) else {
            continue;
        };
        let pointer = format!("/{key}/{field}");
        if let Some(index) = index
            && !index.headline(&pointer, field, value)
        {
            continue;
        }
        selected.insert(field.to_owned(), value.clone());
        selected_pointers.insert(pointer);
    }
    Value::Object(selected)
}

/// `preview`: select parsed producer facts without reinterpreting payload bytes.
fn preview(record: &Value, format: &str) -> Value {
    let Some(mut output) = record.as_object().cloned() else {
        return record.clone();
    };
    let source = record.get("reported").and_then(Value::as_object);
    let mut selected_pointers = HashSet::new();
    if let Some(source) = source {
        let index = (format == "mitmproxy"
            && source.get("type").and_then(Value::as_str) == Some("http"))
        .then(|| index_facets(record));
        let facets = index
            .as_ref()
            .filter(|index| index.usable_scalar("/type") && !index.scalar("/type"));
        let mut reported = Map::new();
        for key in ["session_id", "name", "time", "startedDateTime", "type"] {
            if let Some(value) = source.get(key) {
                reported.insert(key.into(), value.clone());
                selected_pointers.insert(format!("/{key}"));
            }
        }
        for key in ["request", "response"] {
            let Some(value) = source.get(key) else {
                continue;
            };
            match value.as_object() {
                None => {
                    reported.insert(key.into(), value.clone());
                }
                Some(fields) => {
                    let headlines = select_headlines(fields, key, facets, &mut selected_pointers);
                    reported.insert(key.into(), headlines);
                }
            }
        }
        output.insert("reported".into(), Value::Object(reported));
        let literals: Vec<Value> = array(record, "numeric_literals")
            .iter()
            .filter(|literal| selected_pointers.contains(pointer_of(literal)))
            .cloned()
            .collect();
        output.insert("numeric_literals".into(), Value::Array(literals));
    }
    let fields: Vec<Value> = array(record, "binary_fields")
        .iter()
        .map(|field| Value::Object(without(field, &["content_base64"])))
        .collect();
    output.insert("binary_fields".into(), Value::Array(fields));
    Value::Object(output)
}
