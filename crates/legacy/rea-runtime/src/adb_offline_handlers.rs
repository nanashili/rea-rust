//! Offline-only dispatch for captured ADB observations.
//!
//! This adapter deliberately has no process, device, or host-filesystem
//! authority.  The caller supplies the captured output or retained Evidence;
//! application producers validate and project those facts here.

use rea_application::adb;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// ADB observations accepted by this offline adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdbOfflineOperation {
    InspectClient,
    ListDevices,
    InspectDevice,
    ListPackages,
    ReadLogcat,
    InspectPackage,
    PullPackage,
    PullFile,
    CaptureScreen,
    ListProcesses,
    ListDirectory,
    ListFeatures,
    ListServices,
    InspectDisplay,
    InspectWindow,
    ReadSetting,
    CollectBugreport,
    ResolvePackages,
}

impl AdbOfflineOperation {
    /// Parse a public operation name. Mutating ADB operations are intentionally
    /// absent and therefore fail closed as unknown operations.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "inspect_adb_client" => Ok(Self::InspectClient),
            "list_adb_devices" => Ok(Self::ListDevices),
            "inspect_adb_device" => Ok(Self::InspectDevice),
            "list_adb_packages" => Ok(Self::ListPackages),
            "read_adb_logcat" => Ok(Self::ReadLogcat),
            "inspect_adb_package" => Ok(Self::InspectPackage),
            "pull_adb_package" => Ok(Self::PullPackage),
            "pull_adb_file" => Ok(Self::PullFile),
            "capture_adb_screen" => Ok(Self::CaptureScreen),
            "list_adb_processes" => Ok(Self::ListProcesses),
            "list_adb_directory" => Ok(Self::ListDirectory),
            "list_adb_features" => Ok(Self::ListFeatures),
            "list_adb_services" => Ok(Self::ListServices),
            "inspect_adb_display" => Ok(Self::InspectDisplay),
            "inspect_adb_window" => Ok(Self::InspectWindow),
            "read_adb_setting" => Ok(Self::ReadSetting),
            "collect_adb_bugreport" => Ok(Self::CollectBugreport),
            "resolve_adb_packages" => Ok(Self::ResolvePackages),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::InspectClient => "inspect_adb_client",
            Self::ListDevices => "list_adb_devices",
            Self::InspectDevice => "inspect_adb_device",
            Self::ListPackages => "list_adb_packages",
            Self::ReadLogcat => "read_adb_logcat",
            Self::InspectPackage => "inspect_adb_package",
            Self::PullPackage => "pull_adb_package",
            Self::PullFile => "pull_adb_file",
            Self::CaptureScreen => "capture_adb_screen",
            Self::ListProcesses => "list_adb_processes",
            Self::ListDirectory => "list_adb_directory",
            Self::ListFeatures => "list_adb_features",
            Self::ListServices => "list_adb_services",
            Self::InspectDisplay => "inspect_adb_display",
            Self::InspectWindow => "inspect_adb_window",
            Self::ReadSetting => "read_adb_setting",
            Self::CollectBugreport => "collect_adb_bugreport",
            Self::ResolvePackages => "resolve_adb_packages",
        }
    }
}

/// Dispatch one captured ADB observation without invoking ADB or accessing a
/// device or host path.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = AdbOfflineOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed operation.
pub fn dispatch_typed(operation: AdbOfflineOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        AdbOfflineOperation::InspectClient => inspect_client(input),
        AdbOfflineOperation::ListDevices => list_devices(input),
        AdbOfflineOperation::InspectDevice => adb::device_inspection::inspect_value(input),
        AdbOfflineOperation::ListPackages => adb::packages::inspect_value(input),
        AdbOfflineOperation::ReadLogcat => adb::logcat::inspect_value(input),
        AdbOfflineOperation::InspectPackage => inspect_package(input),
        AdbOfflineOperation::PullPackage => adb::package_pull::inspect_value(input),
        AdbOfflineOperation::PullFile => adb::file_pull::project(input),
        AdbOfflineOperation::CaptureScreen => adb::screen_capture::normalize_value(input),
        AdbOfflineOperation::ListProcesses => adb::processes::list_value(input),
        AdbOfflineOperation::ListDirectory => adb::directory::inspect(input),
        AdbOfflineOperation::ListFeatures => {
            adb::capability_inventory::inspect_features_value(input)
        }
        AdbOfflineOperation::ListServices => {
            adb::capability_inventory::inspect_services_value(input)
        }
        AdbOfflineOperation::InspectDisplay => adb::display::inspect_display_value(input),
        AdbOfflineOperation::InspectWindow => adb::display::inspect_window_value(input),
        AdbOfflineOperation::ReadSetting => adb::setting::inspect_value(input),
        AdbOfflineOperation::CollectBugreport => adb::bugreport::inspect_value(input),
        AdbOfflineOperation::ResolvePackages => adb::package_resolution::resolve_value(input),
    }
}

/// Project a caller-supplied `adb version` banner. The application parser
/// enforces the bounded banner, selected binary identity, and protocol shape;
/// this wrapper adds no process or filesystem behavior.
pub fn inspect_client(input: &Value) -> Result<Value, Failure> {
    adb::client::inspect_value(input)
}

/// Inspect-package's typed joiner requires Rust-owned APK report values. A
/// captured JSON result is still safely reusable when its fixed ADB projection
/// is validated at this boundary; no package bytes are opened here.
fn inspect_package(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("inspect_adb_package input must be an object"))?;
    let result = object
        .get("result")
        .or_else(|| object.get("projection"))
        .unwrap_or(input);
    let result_object = result
        .as_object()
        .ok_or_else(|| invalid("inspect_adb_package captured projection must be an object"))?;
    for field in ["client", "serial", "package_name", "coverage"] {
        if !result_object.contains_key(field) {
            return Err(invalid(&format!(
                "inspect_adb_package result requires {field}"
            )));
        }
    }
    Ok(result.clone())
}

fn list_devices(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("list_adb_devices input must be an object"))?;
    let client = object
        .get("client")
        .ok_or_else(|| invalid("list_adb_devices client is required"))?;
    let client_object = client
        .as_object()
        .ok_or_else(|| invalid("ADB client identity must be an object"))?;
    let binary_path = required_string(client_object, "binary_path")?;
    let path_source = match required_string(client_object, "path_source")?.as_str() {
        "environment" => adb::client::PathSource::Environment,
        "path" => adb::client::PathSource::Path,
        _ => return Err(invalid("ADB client path_source is invalid")),
    };
    let client = adb::client::ClientIdentity {
        binary_path,
        path_source,
        version: optional_string(client_object, "version")?,
        installed_path: optional_string(client_object, "installed_path")?,
    };
    let probe = object
        .get("probe")
        .cloned()
        .ok_or_else(|| invalid("list_adb_devices probe is required"))?;
    let probe =
        serde_json::from_value(probe).map_err(|_| invalid("list_adb_devices probe is invalid"))?;
    serde_json::to_value(adb::devices::list(client, probe)?)
        .map_err(|_| invalid("result is not serializable"))
}

fn required_string(object: &Map<String, Value>, field: &str) -> Result<String, Failure> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| invalid(&format!("{field} is required")))
}

fn optional_string(object: &Map<String, Value>, field: &str) -> Result<Option<String>, Failure> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.is_empty() => Ok(Some(value.clone())),
        Some(_) => Err(invalid(&format!(
            "{field} must be a non-empty string or null"
        ))),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("ADB operation is not an offline observation: {name}"),
        false,
        "Select a supported captured ADB observation.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide bounded caller-supplied ADB output or Evidence.".into(),
        BTreeMap::from([("operation", Detail::Text("adb_offline_handlers".into()))]),
    )
}
