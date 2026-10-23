//! Offline browser and Electron evidence projections.
//!
//! This adapter deliberately has no transport, filesystem, process, or
//! JavaScript authority. Callers must supply a retained snapshot or capture;
//! the adapter only validates the envelope and returns the supplied facts.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OfflineOperation {
    ListBrowserTargets,
    ListElectronTargets,
    InspectElectronFuses,
    InspectElectronPage,
    ReconcileElectron,
    CaptureBrowserScenario,
    CaptureElectronScenario,
}

impl OfflineOperation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "list_browser_targets" => Ok(Self::ListBrowserTargets),
            "list_electron_targets" | "offline_list_electron_targets" => {
                Ok(Self::ListElectronTargets)
            }
            "inspect_electron_fuses" => Ok(Self::InspectElectronFuses),
            "inspect_electron_page" | "offline_inspect_electron_page" => {
                Ok(Self::InspectElectronPage)
            }
            "reconcile_electron" => Ok(Self::ReconcileElectron),
            "capture_browser_scenario" => Ok(Self::CaptureBrowserScenario),
            "capture_electron_scenario" => Ok(Self::CaptureElectronScenario),
            _ => Err(invalid(
                name,
                "operation is not an offline browser/Electron operation",
            )),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::ListBrowserTargets => "list_browser_targets",
            Self::ListElectronTargets => "offline_list_electron_targets",
            Self::InspectElectronFuses => "inspect_electron_fuses",
            Self::InspectElectronPage => "offline_inspect_electron_page",
            Self::ReconcileElectron => "reconcile_electron",
            Self::CaptureBrowserScenario => "capture_browser_scenario",
            Self::CaptureElectronScenario => "capture_electron_scenario",
        }
    }
}

/// Dispatch an operation using only caller-supplied retained evidence.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = OfflineOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

pub fn dispatch_typed(operation: OfflineOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        OfflineOperation::ListBrowserTargets | OfflineOperation::ListElectronTargets => {
            project_snapshot(operation, input)
        }
        OfflineOperation::InspectElectronFuses | OfflineOperation::InspectElectronPage => {
            project_capture(operation, input)
        }
        OfflineOperation::CaptureBrowserScenario | OfflineOperation::CaptureElectronScenario => {
            project_capture(operation, input)
        }
        OfflineOperation::ReconcileElectron => reconcile(input),
    }
}

fn project_snapshot(operation: OfflineOperation, input: &Value) -> Result<Value, Failure> {
    let object = object_input(operation, input)?;
    require_only(object, &["snapshot"], operation)?;
    object_value(object, "snapshot", operation)
}

fn project_capture(operation: OfflineOperation, input: &Value) -> Result<Value, Failure> {
    let object = object_input(operation, input)?;
    require_only(object, &["capture"], operation)?;
    object_value(object, "capture", operation)
}

fn reconcile(input: &Value) -> Result<Value, Failure> {
    let operation = OfflineOperation::ReconcileElectron;
    let object = object_input(operation, input)?;
    require_only(object, &["static_evidence", "runtime_evidence"], operation)?;
    let static_evidence = array_value(object, "static_evidence", operation)?;
    let runtime_evidence = array_value(object, "runtime_evidence", operation)?;
    if static_evidence.is_empty() || runtime_evidence.is_empty() {
        return Err(invalid(
            operation.name(),
            "static_evidence and runtime_evidence must both contain at least one record",
        ));
    }

    Ok(serde_json::json!({
        "static_evidence": static_evidence,
        "runtime_evidence": runtime_evidence,
    }))
}

fn object_input<'a>(
    operation: OfflineOperation,
    input: &'a Value,
) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| invalid(operation.name(), "offline input must be an object"))
}

fn require_only(
    object: &Map<String, Value>,
    fields: &[&str],
    operation: OfflineOperation,
) -> Result<(), Failure> {
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err(invalid(
            operation.name(),
            "offline input must contain exactly the retained evidence fields",
        ));
    }
    Ok(())
}

fn object_value(
    object: &Map<String, Value>,
    field: &str,
    operation: OfflineOperation,
) -> Result<Value, Failure> {
    object
        .get(field)
        .filter(|value| value.is_object())
        .cloned()
        .ok_or_else(|| invalid(operation.name(), &format!("{field} must be an object")))
}

fn array_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    operation: OfflineOperation,
) -> Result<&'a Vec<Value>, Failure> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| invalid(operation.name(), &format!("{field} must be an array")))
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide an explicit retained browser or Electron capture; live targets are unsupported by this adapter."
            .into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}
