//! Untrusted CDP value readers: `src/browser/CdpCaptureValues.ts`,
//! `CdpCaptureEventHelpers.ts` (`isMainFrameNavigation`) and the frame-tree
//! readers of `CdpCaptureDocuments.ts` (`walkFrameTrees`, `captureFrames`,
//! `mainFrameUrl`).
use super::completeness::Completeness;
use crate::cdp::urls::{self, SanitizedUrl};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub(crate) type Record = Map<String, Value>;

pub(crate) fn record(value: Option<&Value>) -> Option<&Record> {
    value.and_then(Value::as_object)
}

pub(crate) fn string(value: Option<&Value>) -> Option<&str> {
    value.and_then(Value::as_str)
}

/// `numberValue`: a finite JSON number.
pub(crate) fn number(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(Value::as_f64)
        .filter(|number| number.is_finite())
}

/// A JavaScript number as `JSON.stringify` would emit it: integral values
/// within the safe range serialize without a fraction.
pub(crate) fn js_number(value: f64) -> Value {
    const SAFE: f64 = 9_007_199_254_740_991.0;
    if value.fract() == 0.0 && value.abs() <= SAFE {
        return Value::from(value as i64);
    }
    serde_json::Number::from_f64(value).map_or(Value::Null, Value::Number)
}

/// Re-emit every JSON number the way JavaScript serializes it.
pub(crate) fn js_json(value: &Value) -> Value {
    match value {
        Value::Number(number) if number.is_f64() => number.as_f64().map_or(Value::Null, js_number),
        Value::Array(items) => Value::Array(items.iter().map(js_json).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), js_json(item)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `integerOrNull`.
pub(crate) fn integer_or_null(value: Option<&Value>) -> Value {
    number(value).map_or(Value::Null, |number| js_number(number.trunc().max(0.0)))
}

/// `isHttpUrl`.
pub(crate) fn is_http_url(value: Option<&str>) -> bool {
    value
        .and_then(urls::parse)
        .is_some_and(|url| matches!(url.scheme(), "http" | "https"))
}

/// `allowedSanitizedUrl`.
pub(crate) fn allowed_sanitized_url(
    value: Option<&str>,
    origins: &BTreeSet<String>,
) -> Option<SanitizedUrl> {
    let sanitized = urls::sanitize_browser_url(value?);
    sanitized
        .origin
        .as_ref()
        .is_some_and(|origin| origins.contains(origin))
        .then_some(sanitized)
}

/// `exclusionReasonForUrl`.
pub(crate) fn exclusion_reason_for_url(value: Option<&str>) -> &'static str {
    match value {
        None | Some("") => "unattributed_origin",
        Some(text) if is_http_url(Some(text)) => "disallowed_origin",
        Some(_) => "unsupported_url",
    }
}

/// `requiredRecord` + `mainFrameUrl`. `Err` is the producer's
/// `protocol_error`.
pub(crate) fn main_frame_url(result: &Value) -> Result<Option<String>, ()> {
    let root = result.as_object().ok_or(())?;
    Ok(string(
        record(record(root.get("frameTree")).and_then(|tree| tree.get("frame")))
            .and_then(|frame| frame.get("url")),
    )
    .map(str::to_owned))
}

/// The root frame tree of a `Page.getFrameTree` result.
pub(crate) fn frame_tree_root(result: &Value) -> Option<&Record> {
    record(result.get("frameTree"))
}

/// `walkFrameTrees`: preorder, children in declaration order. A malformed
/// child list or child reports `None` (unknown omitted count).
pub(crate) fn walk_frame_trees<'a>(
    root: &'a Record,
    on_malformed: &mut dyn FnMut(Option<u64>),
) -> Vec<&'a Record> {
    let mut pending = vec![root];
    let mut visited = Vec::new();
    while let Some(tree) = pending.pop() {
        let raw = tree.get("childFrames");
        let children: Vec<&Record> = match raw {
            None => Vec::new(),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|child| {
                    let parsed = child.as_object();
                    if parsed.is_none() {
                        on_malformed(None);
                    }
                    parsed
                })
                .collect(),
            Some(_) => {
                on_malformed(None);
                Vec::new()
            }
        };
        pending.extend(children.into_iter().rev());
        visited.push(tree);
    }
    visited
}

/// One normalized frame of `captureFrames`.
pub(crate) struct Frame {
    pub frame_id: String,
    pub parent_frame_id: Option<String>,
    pub url: String,
    pub origin: String,
}

/// `captureFrames`.
pub(crate) fn capture_frames(
    result: &Value,
    origins: &BTreeSet<String>,
    maximum: Option<usize>,
    mut completeness: Option<&mut Completeness>,
) -> Vec<Frame> {
    let Some(root) = frame_tree_root(result) else {
        if let Some(completeness) = completeness.as_deref_mut() {
            completeness.exclude("frames", "invalid_protocol_value");
        }
        return Vec::new();
    };
    let mut omitted: Vec<Option<u64>> = Vec::new();
    let trees = walk_frame_trees(root, &mut |count| omitted.push(count));
    if let Some(completeness) = completeness.as_deref_mut() {
        for count in omitted {
            completeness.exclude_count("frames", "invalid_protocol_value", count);
        }
    }
    let mut items = Vec::new();
    for tree in trees {
        let frame = record(tree.get("frame"));
        let frame_id = string(frame.and_then(|frame| frame.get("id")));
        let sanitized =
            allowed_sanitized_url(string(frame.and_then(|frame| frame.get("url"))), origins);
        let (Some(frame), Some(frame_id)) = (frame, frame_id) else {
            if let Some(completeness) = completeness.as_deref_mut() {
                completeness.exclude("frames", "invalid_protocol_value");
            }
            continue;
        };
        let Some(SanitizedUrl {
            url,
            origin: Some(origin),
        }) = sanitized
        else {
            if let Some(completeness) = completeness.as_deref_mut() {
                completeness.exclude("frames", exclusion_reason_for_url(string(frame.get("url"))));
            }
            continue;
        };
        if maximum.is_some_and(|maximum| items.len() >= maximum) {
            continue;
        }
        let parent = string(frame.get("parentId"));
        if (!std::ptr::eq(tree, root) || frame.contains_key("parentId"))
            && parent.is_none_or(str::is_empty)
        {
            if let Some(completeness) = completeness.as_deref_mut() {
                completeness.exclude("frames", "invalid_protocol_value");
            }
        }
        items.push(Frame {
            frame_id: frame_id.to_owned(),
            parent_frame_id: parent.map(str::to_owned),
            url,
            origin,
        });
    }
    items
}

/// One validated CDP event envelope (`CdpEvent`).
pub(crate) struct Event {
    pub method: String,
    pub params: Value,
    pub session_id: Option<String>,
}

/// `isMainFrameNavigation`.
pub(crate) fn is_main_frame_navigation(event: &Event, main_frame_id: &str) -> bool {
    let Some(params) = event.params.as_object() else {
        return false;
    };
    let frame_id = match event.method.as_str() {
        "Page.frameNavigated" => {
            string(record(params.get("frame")).and_then(|frame| frame.get("id")))
        }
        "Page.frameRequestedNavigation" | "Page.navigatedWithinDocument" => {
            string(params.get("frameId"))
        }
        _ => None,
    };
    frame_id == Some(main_frame_id)
}
