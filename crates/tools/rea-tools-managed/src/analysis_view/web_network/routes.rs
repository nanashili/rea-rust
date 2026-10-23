//! Route templates and recorded request lines shared by grouping views.
//!
//! Compatibility owner: `src/domain/analysisView/webNetworkRouteTemplates.ts`.
use super::url::{parse_recorded_transport_url, query_parameter_names};
use crate::common::json::js_len;
use serde_json::Value;
use std::collections::BTreeSet;

/// `ROUTE_RULES`.
pub const ROUTE_RULES: [&str; 4] = ["numeric", "uuid", "hex", "iso-date"];

// Conservative representation allowances shared with the original accounting.
pub const GROUP_BYTES: usize = 2048;
pub const SEGMENT_BYTES: usize = 1024;
pub const ENTRY_BYTES: usize = 128;
pub const RECORD_SCRATCH_BYTES: usize = 512;
pub const CAPTURE_CONTAINER_BYTES: usize = 512;
const SEGMENT_SCRATCH_BYTES: usize = 512;

/// `textBytes(length)` for a UTF-16 length.
pub fn text_bytes(length: usize) -> usize {
    32 + length * 14
}

/// `textBytes(text.length)`.
pub fn text_bytes_of(text: &str) -> usize {
    text_bytes(js_len(text))
}

/// One templated segment of a recorded path.
#[derive(Clone)]
pub struct RouteSegment {
    pub segment_index: usize,
    pub rule: &'static str,
    pub value: String,
}

/// `RouteTemplate`.
pub struct RouteTemplate {
    pub template: String,
    pub rules: String,
    pub segments: Vec<RouteSegment>,
}

/// Why a retained record cannot join a grouping view.
pub enum RequestLine {
    Excluded(&'static str),
    Line(Line),
}

/// One retained request line.
pub struct Line {
    pub method: String,
    pub origin: String,
    pub path: String,
    pub query: Option<String>,
    /// Non-zero numeric status, when recorded.
    pub status: Option<f64>,
    pub raw_mime: String,
}

fn is_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&byte)
}

/// `mediaTypeEssence`: lowercase `type/subtype` without parameters.
pub fn media_type_essence(reported: &str) -> Option<String> {
    let end = reported.find(';').unwrap_or(reported.len());
    let essence = reported[..end].trim_matches([' ', '\t']);
    let (kind, subtype) = essence.split_once('/')?;
    if kind.is_empty()
        || subtype.is_empty()
        || !kind.bytes().all(is_token)
        || !subtype.bytes().all(is_token)
    {
        return None;
    }
    Some(essence.to_ascii_lowercase())
}

/// `routePartCount`: one more than the template's separators.
pub fn route_part_count(template: &str) -> usize {
    1 + template.bytes().filter(|byte| *byte == b'/').count()
}

fn all_digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn all_hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_uuid(value: &str) -> bool {
    let groups: Vec<&str> = value.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .zip([8, 4, 4, 4, 12])
            .all(|(group, length)| group.len() == length && all_hex(group))
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

/// `YYYY-MM-DD` naming an existing proleptic-Gregorian UTC date.
fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let (Ok(year), Ok(month), Ok(day)) = (
        value[..4].parse::<u32>(),
        value[5..7].parse::<u32>(),
        value[8..].parse::<u32>(),
    ) else {
        return false;
    };
    if !all_digits(&value[..4]) || !all_digits(&value[5..7]) || !all_digits(&value[8..]) {
        return false;
    }
    (1..=12).contains(&month) && day >= 1 && day <= days_in_month(year, month)
}

/// `segmentRule`: the first exact format rule a segment satisfies.
pub fn segment_rule(value: &str) -> Option<&'static str> {
    if all_digits(value) {
        return Some("numeric");
    }
    if is_uuid(value) {
        return Some("uuid");
    }
    if value.len() >= 32 && all_hex(value) {
        return Some("hex");
    }
    if is_iso_date(value) {
        return Some("iso-date");
    }
    None
}

/// `scanRouteTemplate`; `None` when the temporary budget is exhausted.
pub fn scan_route_template(
    path: &str,
    temporary: &mut dyn FnMut(usize) -> bool,
) -> Option<RouteTemplate> {
    let mut segments = Vec::new();
    let mut template = String::new();
    let mut rules = String::new();
    let mut template_length = js_len(path) as i64;
    let mut rules_length = 0usize;
    let mut copied = 0usize;
    let mut index = 0usize;
    let mut start = 1usize.min(path.len());
    loop {
        let slash = path[start..].find('/').map(|at| at + start);
        let end = slash.unwrap_or(path.len());
        let value = &path[start..end];
        if let Some(rule) = segment_rule(value) {
            if !temporary(SEGMENT_SCRATCH_BYTES) {
                return None;
            }
            let placeholder = format!("{{{rule}}}");
            let identity = format!("{index}:{rule};");
            segments.push(RouteSegment {
                segment_index: index,
                rule,
                value: value.to_owned(),
            });
            template.push_str(&path[copied..start]);
            template.push_str(&placeholder);
            rules.push_str(&identity);
            template_length += placeholder.len() as i64 - js_len(value) as i64;
            rules_length += identity.len();
            copied = end;
        }
        match slash {
            None => break,
            Some(slash) => {
                start = slash + 1;
                index += 1;
            }
        }
    }
    if segments.is_empty() {
        return Some(RouteTemplate {
            template: path.to_owned(),
            rules: String::new(),
            segments,
        });
    }
    if !temporary(text_bytes(template_length.max(0) as usize) + text_bytes(rules_length)) {
        return None;
    }
    template.push_str(&path[copied..]);
    Some(RouteTemplate {
        template,
        rules,
        segments,
    })
}

fn object(value: &Value) -> Option<&serde_json::Map<String, Value>> {
    value.as_object()
}

/// `readRecordedRequestLine`; `None` when the temporary budget is exhausted.
pub fn read_recorded_request_line(
    reported: &Value,
    include_query: bool,
    temporary: &mut dyn FnMut(usize) -> bool,
) -> Option<RequestLine> {
    let Some(request) = object(reported)
        .and_then(|reported| reported.get("request"))
        .and_then(object)
    else {
        return Some(RequestLine::Excluded("request-unavailable"));
    };
    let url = match request.get("url") {
        Some(Value::Null) => return Some(RequestLine::Excluded("url-redacted")),
        Some(Value::String(url)) => url,
        _ => return Some(RequestLine::Excluded("url-unparseable")),
    };
    if !temporary(RECORD_SCRATCH_BYTES + text_bytes_of(url)) {
        return None;
    }
    let parsed = parse_recorded_transport_url(url, include_query);
    let Some(origin) = parsed.origin else {
        return Some(RequestLine::Excluded("url-unparseable"));
    };
    let method = match request.get("method") {
        Some(Value::String(method)) if !method.is_empty() => method.clone(),
        _ => return Some(RequestLine::Excluded("method-unavailable")),
    };
    let Some(path) = parsed.path else {
        return Some(RequestLine::Excluded("url-unparseable"));
    };
    let response = object(reported)
        .and_then(|reported| reported.get("response"))
        .and_then(object);
    let status = response.and_then(|response| response.get("status"));
    let mime = response
        .and_then(|response| response.get("content"))
        .and_then(object)
        .and_then(|content| content.get("mimeType"));
    let raw_mime = mime.and_then(Value::as_str).unwrap_or_default().to_owned();
    if !temporary(text_bytes_of(&raw_mime)) {
        return None;
    }
    Some(RequestLine::Line(Line {
        method,
        origin,
        path,
        query: parsed.query,
        status: status
            .and_then(Value::as_f64)
            .filter(|status| *status != 0.0),
        raw_mime,
    }))
}

/// `readQueryParameterNames`: `Some(None)` without a selected query, `None`
/// when the temporary budget is exhausted.
pub fn read_query_parameter_names(
    query: Option<&str>,
    temporary: &mut dyn FnMut(usize) -> bool,
) -> Option<Option<BTreeSet<String>>> {
    let Some(query) = query else {
        return Some(None);
    };
    let pairs = usize::from(js_len(query) > 1) + query.bytes().filter(|byte| *byte == b'&').count();
    if !temporary(RECORD_SCRATCH_BYTES + text_bytes_of(query) + pairs * ENTRY_BYTES * 4) {
        return None;
    }
    Some(Some(query_parameter_names(query).into_iter().collect()))
}

/// A JSON number for a recorded numeric value, integral values as integers.
pub fn number(value: f64) -> Value {
    if value.fract() == 0.0 && value.abs() < 9_007_199_254_740_992.0 {
        Value::from(value as i64)
    } else {
        serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)
    }
}

/// Numeric ascending order (`(a, b) => a - b`).
pub fn sorted_numbers(values: impl IntoIterator<Item = f64>) -> Vec<Value> {
    let mut numbers: Vec<f64> = Vec::new();
    for value in values {
        if !numbers.contains(&value) {
            numbers.push(value);
        }
    }
    numbers.sort_by(|left, right| left.total_cmp(right));
    numbers.into_iter().map(number).collect()
}
