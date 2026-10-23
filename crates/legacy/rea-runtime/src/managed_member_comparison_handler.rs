//! Runtime boundary for comparing managed artifacts selected by path.
//!
//! The application comparison owner creates artifact-bound member Evidence
//! from each stable byte snapshot. This adapter owns only input selection and
//! stable file admission; retained Evidence continues through the existing
//! managed workflow dispatcher.

use rea_application::managed::member_comparison as managed_member_comparison;
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::{fs::stable_file, fs::unix_file::UnixFiles};
use rea_rust_analysis::managed;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path, sync::Arc};

pub const OPERATION: &str = "compare_managed_members";

/// Compare two caller-selected managed artifacts, or replay two retained
/// `inspect_managed_members` Evidence records when the request supplies them.
pub fn inspect(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid_input("input must be an object"))?;

    if object.contains_key("left_path") || object.contains_key("right_path") {
        return inspect_paths(object, cancellation);
    }

    managed_member_comparison::compare(input).map_err(|reason| workflow_failure(&reason))
}

fn inspect_paths(
    object: &serde_json::Map<String, Value>,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    reject_unknown_path_fields(object)?;

    let left_path = required_path(object, "left_path")?;
    let right_path = required_path(object, "right_path")?;

    let access = Arc::new(UnixFiles);
    let left = read_snapshot(access.clone(), left_path, "left", cancellation)?;
    let right = read_snapshot(access, right_path, "right", cancellation)?;

    managed_member_comparison::compare_captured(left_path, &left.bytes, right_path, &right.bytes)
        .map_err(|reason| workflow_failure(&reason))
}

fn reject_unknown_path_fields(object: &serde_json::Map<String, Value>) -> Result<(), Failure> {
    if let Some(field) = object
        .keys()
        .find(|field| !matches!(field.as_str(), "left_path" | "right_path"))
    {
        return Err(invalid_input(&format!(
            "path comparison contains unknown field: {field}"
        )));
    }

    Ok(())
}

fn required_path<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a str, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty() && !path.contains('\0'))
        .ok_or_else(|| invalid_input(&format!("{field} must be a non-empty NUL-free path")))
}

fn read_snapshot(
    access: Arc<UnixFiles>,
    path: &str,
    side: &str,
    cancellation: &Cancellation,
) -> Result<stable_file::Snapshot, Failure> {
    stable_file::read(
        access,
        Path::new(path),
        managed::MAX_INPUT_BYTES,
        cancellation,
    )
    .map_err(|failure| snapshot_failure(side, path, &failure))
}

fn snapshot_failure(
    side: &str,
    path: &str,
    failure: &stable_file::ReadFailure<UnixFiles>,
) -> Failure {
    let reason = failure
        .primary
        .as_ref()
        .map(|issue| format!("{issue:?}"))
        .unwrap_or_else(|| "stable managed artifact read failed".into());

    Failure::new(
        "execution_failed",
        "execution_failed",
        "Managed member comparison could not read a stable artifact.".into(),
        true,
        "Retry after both selected artifacts are stable and readable.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("side".into(), Detail::Text(side.into())),
            ("path".into(), Detail::Text(path.into())),
            ("reason".into(), Detail::Text(reason)),
        ]),
    )
}

fn invalid_input(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Managed member comparison input is invalid.".into(),
        false,
        "Provide left_path and right_path, or two retained inspect_managed_members Evidence records.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}

fn workflow_failure(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "Managed member comparison input is invalid.".into(),
        false,
        "Provide two distinct inspect_managed_members Evidence records or stable artifact paths."
            .into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
