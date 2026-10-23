//! Typed dispatch for read-only ADB application producers.
//!
//! This layer accepts already-captured adapter input. It does not own process
//! execution, device leases, filesystem publication, or cancellation; those
//! remain host responsibilities. The dispatcher only selects a producer and
//! preserves its tagged boundary failures.

use rea_application::adb;
use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// Read-only operations whose captured inputs can be handled by the native
/// application producers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadOnlyAdbOperation {
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

impl ReadOnlyAdbOperation {
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

/// Dispatch one captured read-only ADB operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = ReadOnlyAdbOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch using a previously parsed operation name.
pub fn dispatch_typed(operation: ReadOnlyAdbOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        ReadOnlyAdbOperation::InspectClient => adb::client::inspect_value(input),
        ReadOnlyAdbOperation::ListDevices => dispatch_devices(input),
        ReadOnlyAdbOperation::InspectDevice => adb::device_inspection::inspect_value(input),
        ReadOnlyAdbOperation::ListPackages => adb::packages::inspect_value(input),
        ReadOnlyAdbOperation::ReadLogcat => adb::logcat::inspect_value(input),
        ReadOnlyAdbOperation::InspectPackage => unsupported(
            operation,
            "inspect_adb_package requires typed APK Evidence and is not a JSON capture handler",
        ),
        ReadOnlyAdbOperation::PullPackage => adb::package_pull::inspect_value(input),
        ReadOnlyAdbOperation::PullFile => adb::file_pull::project(input),
        ReadOnlyAdbOperation::CaptureScreen => adb::screen_capture::normalize_value(input),
        ReadOnlyAdbOperation::ListProcesses => adb::processes::list_value(input),
        ReadOnlyAdbOperation::ListDirectory => adb::directory::inspect(input),
        ReadOnlyAdbOperation::ListFeatures => {
            adb::capability_inventory::inspect_features_value(input)
        }
        ReadOnlyAdbOperation::ListServices => {
            adb::capability_inventory::inspect_services_value(input)
        }
        ReadOnlyAdbOperation::InspectDisplay => adb::display::inspect_display_value(input),
        ReadOnlyAdbOperation::InspectWindow => adb::display::inspect_window_value(input),
        ReadOnlyAdbOperation::ReadSetting => adb::setting::inspect_value(input),
        ReadOnlyAdbOperation::CollectBugreport => adb::bugreport::inspect_value(input),
        ReadOnlyAdbOperation::ResolvePackages => adb::package_resolution::resolve_value(input),
    }
}

fn dispatch_devices(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("list_adb_devices input must be an object"))?;
    let client = decode_client(
        object
            .get("client")
            .ok_or_else(|| invalid("list_adb_devices client is required"))?,
    )?;
    let output = serde_json::from_value(
        object
            .get("probe")
            .cloned()
            .ok_or_else(|| invalid("list_adb_devices probe is required"))?,
    )
    .map_err(|_| invalid("list_adb_devices probe is invalid"))?;

    serde_json::to_value(adb::devices::list(client, output)?)
        .map_err(|_| invalid("list_adb_devices result is not serializable"))
}

fn decode_client(value: &Value) -> Result<adb::client::ClientIdentity, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("ADB client identity must be an object"))?;
    let binary_path = required_string(object, "binary_path")?;
    let path_source = match required_string(object, "path_source")?.as_str() {
        "environment" => adb::client::PathSource::Environment,
        "path" => adb::client::PathSource::Path,
        _ => return Err(invalid("ADB client path_source is invalid")),
    };
    let version = optional_string(object, "version")?;
    let installed_path = optional_string(object, "installed_path")?;

    Ok(adb::client::ClientIdentity {
        binary_path,
        path_source,
        version,
        installed_path,
    })
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

fn unsupported(operation: ReadOnlyAdbOperation, reason: &str) -> Result<Value, Failure> {
    Err(Failure::new(
        "unsupported_request",
        "unsupported_request",
        reason.into(),
        false,
        "Supply the typed Evidence required by this application producer.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    ))
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("ADB operation is not read-only or is unknown: {name}"),
        false,
        "Select one of the supported read-only ADB operations.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide a bounded captured ADB operation input.".into(),
        BTreeMap::from([("operation", Detail::Text("adb_handlers".into()))]),
    )
}
