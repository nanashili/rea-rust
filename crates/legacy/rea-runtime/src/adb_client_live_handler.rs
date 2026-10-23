//! Live, read-only inspection of the caller-selected ADB client.
//!
//! The handler owns the short-lived `adb version` child through the host
//! launcher and hands its bounded output to the application parser. It never
//! contacts a device or starts the ADB server.

use std::{collections::BTreeMap, path::PathBuf, thread, time::Duration};

use rea_application::adb;
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::{
    process::launcher::{ChildLaunchSpec, OwnedChildProcess},
    process::windows::job::WindowsJobLimits,
};
use serde_json::Value;

const MAX_OUTPUT_BYTES: usize = 64 * 1024;

/// Public operation handled by this live adapter.
pub const OPERATION: &str = "inspect_adb_client";

/// Return whether the live adapter owns the named operation.
pub fn supports(operation: &str) -> bool {
    operation == OPERATION
}

/// Dispatch the live ADB client operation.
///
/// The caller supplies the cancellation token used by the host-owned child.
/// Keeping this dispatch boundary separate from the offline ADB dispatcher
/// prevents a retained JSON observation from accidentally gaining process
/// execution authority.
pub fn dispatch(
    operation: &str,
    input: &Value,
    cancellation: &Cancellation,
) -> Result<Value, Failure> {
    if !supports(operation) {
        return Err(invalid("unsupported live ADB client operation"));
    }

    inspect(input, cancellation)
}

pub fn inspect(input: &Value, cancellation: &Cancellation) -> Result<Value, Failure> {
    let (binary_path, path_source) = parse_selection(input)?;
    ensure_active(cancellation)?;

    let mut child = OwnedChildProcess::launch(ChildLaunchSpec {
        executable: PathBuf::from(&binary_path),
        arguments: ChildLaunchSpec::arguments(["version"]),
        working_directory: None,
        protocol_stdin: false,
        limits: WindowsJobLimits {
            memory_bytes: None,
            cpu_seconds: None,
        },
    })
    .map_err(|error| launch_failure(error.message))?;

    let completion = loop {
        ensure_active_or_cancel(&mut child, cancellation)?;
        if let Some(exit) = child
            .try_wait()
            .map_err(|error| launch_failure(error.message))?
        {
            break exit;
        }
        thread::sleep(Duration::from_millis(5));
    };
    let output = child
        .drain_output()
        .map_err(|error| launch_failure(error.message))?;
    if completion.code != 0 {
        return Err(Failure::new(
            "provider_failure",
            "provider_execution",
            format!("adb version exited with status {}", completion.code),
            false,
            "Select a working adb client and retry the read-only version probe.".into(),
            BTreeMap::from([("operation", Detail::Text("inspect_adb_client".into()))]),
        ));
    }
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::new(
            "resource_constraint",
            "resource_constraint",
            "adb version output exceeds the 64 KiB bound.".into(),
            false,
            "Use a bounded adb version probe output.".into(),
            BTreeMap::from([("operation", Detail::Text("inspect_adb_client".into()))]),
        ));
    }

    let result = adb::client::inspect(
        adb::client::Selection {
            binary_path,
            path_source,
        },
        adb::client::ProbeOutput {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
    )?;
    serde_json::to_value(result).map_err(|_| invalid("ADB client result is not serializable"))
}

fn parse_selection(input: &Value) -> Result<(String, adb::client::PathSource), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("ADB client input must be an object"))?;
    let selection = object
        .get("selection")
        .and_then(Value::as_object)
        .unwrap_or(object);
    let binary_path = selection
        .get("binary_path")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| invalid("binary_path is required"))?;
    let path_source = match selection
        .get("path_source")
        .and_then(Value::as_str)
        .unwrap_or("path")
    {
        "path" => adb::client::PathSource::Path,
        "environment" => adb::client::PathSource::Environment,
        _ => return Err(invalid("path_source must be path or environment")),
    };
    Ok((binary_path.to_owned(), path_source))
}

fn ensure_active(cancellation: &Cancellation) -> Result<(), Failure> {
    if cancellation.reason().is_some() {
        Err(cancelled(cancellation))
    } else {
        Ok(())
    }
}

fn ensure_active_or_cancel(
    child: &mut OwnedChildProcess,
    cancellation: &Cancellation,
) -> Result<(), Failure> {
    if cancellation.reason().is_some() {
        child
            .cancel(130)
            .map_err(|error| launch_failure(error.message))?;
        return Err(cancelled(cancellation));
    }
    Ok(())
}

fn cancelled(cancellation: &Cancellation) -> Failure {
    Failure::new(
        "cancelled",
        "cancelled",
        cancellation.reason().unwrap_or("request cancelled").into(),
        true,
        "Retry the ADB client inspection.".into(),
        BTreeMap::from([("operation", Detail::Text("inspect_adb_client".into()))]),
    )
}

fn launch_failure(reason: String) -> Failure {
    Failure::new(
        "provider_unavailable",
        "provider_unavailable",
        reason,
        false,
        "Select an executable ADB client.".into(),
        BTreeMap::from([("operation", Detail::Text("inspect_adb_client".into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a caller-selected ADB client.".into(),
        BTreeMap::from([("operation", Detail::Text("inspect_adb_client".into()))]),
    )
}
