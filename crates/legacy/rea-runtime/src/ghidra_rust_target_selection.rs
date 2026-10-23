//! Resolve the caller-selected artifact used by live Rust Ghidra sessions.

use crate::batch_decompile_runtime_handlers::{GhidraRustTarget, OPERATION};
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, value::RawValue};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const READ_BUFFER_BYTES: usize = 1024 * 1024;

/// Resolve a retained subject into the exact identity selected by the caller.
pub fn resolve(current_target: Option<&RawValue>) -> Result<GhidraRustTarget, Failure> {
    let raw_target =
        current_target.ok_or_else(|| unavailable("No target is currently selected."))?;
    let subject: Value = serde_json::from_str(raw_target.get()).map_err(|error| {
        state_error(&format!(
            "Stored selected target could not be decoded: {error}"
        ))
    })?;
    let object = subject
        .as_object()
        .ok_or_else(|| state_error("Stored selected target is not an object."))?;

    let path = selected_path(object)?;
    let expected_sha256 = selected_digest(object)?;
    let observed_sha256 = digest_file(Path::new(path))
        .map_err(|error| unavailable(&format!("The selected target could not be read: {error}")))?;

    if observed_sha256 != expected_sha256 {
        return Err(integrity_failure(
            "The selected target changed after it was admitted.",
            expected_sha256,
            &observed_sha256,
        ));
    }

    Ok(GhidraRustTarget {
        path: path.to_owned(),
        sha256: expected_sha256.to_owned(),
    })
}

fn selected_path<'a>(object: &'a serde_json::Map<String, Value>) -> Result<&'a str, Failure> {
    let path = object
        .get("local_path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| state_error("Stored target has no local path."))?;

    if path.contains('\0') || !Path::new(path).is_absolute() {
        return Err(state_error(
            "Stored target local path is not absolute and NUL-free.",
        ));
    }

    Ok(path)
}

fn selected_digest<'a>(object: &'a serde_json::Map<String, Value>) -> Result<&'a str, Failure> {
    object
        .get("digest")
        .and_then(Value::as_object)
        .and_then(|digest| digest.get("sha256"))
        .and_then(Value::as_str)
        .filter(|digest| rea_core::evidence::is_sha256(digest))
        .ok_or_else(|| state_error("Stored target has no valid lowercase SHA-256 digest."))
}

fn digest_file(path: &Path) -> io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; READ_BUFFER_BYTES];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn unavailable(message: &str) -> Failure {
    Failure::new(
        "target_unavailable",
        "unavailable",
        message.to_owned(),
        false,
        "Inspect a target in the current native session, then retry.".into(),
        operation_details(),
    )
}

fn state_error(message: &str) -> Failure {
    Failure::new(
        "internal_state_error",
        "internal",
        message.to_owned(),
        false,
        "Restart the native REA process and inspect the target again.".into(),
        operation_details(),
    )
}

fn integrity_failure(message: &str, expected_sha256: &str, observed_sha256: &str) -> Failure {
    Failure::new(
        "target_changed",
        "integrity",
        message.to_owned(),
        false,
        "Restore the selected target or inspect it again before retrying.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(OPERATION.into())),
            ("expected_sha256", Detail::Text(expected_sha256.into())),
            ("observed_sha256", Detail::Text(observed_sha256.into())),
        ]),
    )
}

fn operation_details() -> BTreeMap<&'static str, Detail> {
    BTreeMap::from([("operation", Detail::Text(OPERATION.into()))])
}
