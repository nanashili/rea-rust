//! Explicit trace languages over process-capture observations.
pub mod eval;
mod json;
pub mod spec;

use self::json::{array, boolean, field};
use serde_json::Value;

fn number(value: &Value, key: &str) -> f64 {
    field(value, key)
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN)
}

fn retention_omitted(value: &Value) -> bool {
    number(value, "observed_frames") > number(value, "retained_frames")
}

fn filesystem_truncated(value: &Value) -> bool {
    boolean(value, "enumeration_truncated") == Some(true)
        || !array(value, "enumeration_omissions").is_empty()
        || !array(value, "hash_omissions").is_empty()
}

pub(crate) fn source_truncated(capture: &Value, source: &str) -> bool {
    let details = &capture["truncation_details"];
    match source {
        "terminal_raw" => retention_omitted(&details["raw_terminal"]),
        "terminal_rendered" => {
            retention_omitted(&details["raw_terminal"])
                || retention_omitted(&details["rendered_terminal"])
        }
        "filesystem" => {
            filesystem_truncated(&details["filesystem_before"])
                || filesystem_truncated(&details["filesystem_after"])
        }
        "process" => boolean(&details["process"], "sampling_partial") == Some(true),
        _ => false,
    }
}
