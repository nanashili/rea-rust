//! Network dimension for passive browser-capture comparison.
use super::captures::{Change, Dimension};
use serde_json::Value;

pub(super) fn network_dimension(before: &Value, after: &Value) -> Dimension {
    let before_complete = complete(before);
    let after_complete = complete(after);
    let before_items = items(before);
    let after_items = items(after);
    let mut changes = Vec::new();
    for item in &before_items {
        let key = identity(item);
        if !after_items
            .iter()
            .any(|candidate| identity(candidate) == key)
        {
            changes.push(Change {
                identity: key,
                change: "removed",
            });
        }
    }
    for item in &after_items {
        let key = identity(item);
        if !before_items
            .iter()
            .any(|candidate| identity(candidate) == key)
        {
            changes.push(Change {
                identity: key,
                change: "added",
            });
        }
    }
    if !before_complete || !after_complete {
        return Dimension {
            status: if changes.is_empty() {
                "unknown"
            } else {
                "changed"
            },
            changes,
            reason: Some("Network activity was incomplete in at least one observation.".to_owned()),
        };
    }
    Dimension {
        status: if changes.is_empty() {
            "unchanged"
        } else {
            "changed"
        },
        changes,
        reason: None,
    }
}

fn items(value: &Value) -> Vec<Value> {
    value
        .get("network")
        .and_then(|network| network.get("requests"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}
fn identity(value: &Value) -> String {
    value
        .get("request_key")
        .or_else(|| value.get("url"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}
fn complete(value: &Value) -> bool {
    value
        .get("capture_completeness")
        .and_then(|c| c.get("network"))
        .and_then(Value::as_str)
        .map(|s| s == "complete")
        .unwrap_or(false)
        || value
            .get("completeness")
            .and_then(|c| c.get("network"))
            .and_then(Value::as_str)
            .map(|s| s == "complete")
            .unwrap_or(false)
}
