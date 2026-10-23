//! Offline dispatch for static artifact format inspection.
//!
//! The application crate owns byte parsing, stable reads, Evidence identity,
//! source locations, and parser limitations. This adapter only validates the
//! public operation and input shape before selecting that owner. It never
//! opens a provider database, launches a target, or writes a caller-selected
//! output file.

use rea_application::{
    apple::plist::PlistInspection,
    binary::go::GoInspection,
    binary::layout::BinaryLayoutInspection,
    binary::macho::MachoInspection,
    binary::pe_resources::PeResourcesInspection,
    binary::pe_target::PeTargetInspection,
    binary::rust::RustInspection,
    evm::interface::{self as evm_interface, EvmEncoding},
    inputs, wasm,
};
use rea_core::{
    cancellation::Cancellation,
    failure::{Detail, Failure},
};
use rea_host::fs::unix_file::UnixFiles;
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

/// Static format operations that can be delegated to the application layer
/// without granting target or provider authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaticFormatOperation {
    GoBinary,
    RustBinary,
    Macho,
    PeResources,
    PeTarget,
    EvmInterface,
    BinaryLayout,
    Plist,
    WasmArtifact,
    SqliteDatabase,
}

impl StaticFormatOperation {
    /// Parse one public operation name and fail closed for every other tool.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "inspect_go_binary" => Ok(Self::GoBinary),
            "inspect_rust_binary" => Ok(Self::RustBinary),
            "inspect_macho" => Ok(Self::Macho),
            "inspect_pe_resources" => Ok(Self::PeResources),
            "inspect_pe_target" => Ok(Self::PeTarget),
            "inspect_evm_interface" => Ok(Self::EvmInterface),
            "inspect_binary_layout" => Ok(Self::BinaryLayout),
            "inspect_plist" => Ok(Self::Plist),
            "inspect_wasm_artifact" => Ok(Self::WasmArtifact),
            "inspect_sqlite_database" => Ok(Self::SqliteDatabase),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the canonical operation name used by contracts and Evidence.
    pub const fn name(self) -> &'static str {
        match self {
            Self::GoBinary => "inspect_go_binary",
            Self::RustBinary => "inspect_rust_binary",
            Self::Macho => "inspect_macho",
            Self::PeResources => "inspect_pe_resources",
            Self::PeTarget => "inspect_pe_target",
            Self::EvmInterface => "inspect_evm_interface",
            Self::BinaryLayout => "inspect_binary_layout",
            Self::Plist => "inspect_plist",
            Self::WasmArtifact => "inspect_wasm_artifact",
            Self::SqliteDatabase => "inspect_sqlite_database",
        }
    }
}

/// Inspect one explicit local artifact using the shared application producer.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = StaticFormatOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already parsed operation without provider or target access.
pub fn dispatch_typed(operation: StaticFormatOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        StaticFormatOperation::GoBinary => inspect_go(input),
        StaticFormatOperation::RustBinary => inspect_rust(input),
        StaticFormatOperation::Macho => inspect_macho(input),
        StaticFormatOperation::PeResources => inspect_pe_resources(input),
        StaticFormatOperation::PeTarget => inspect_pe_target(input),
        StaticFormatOperation::EvmInterface => inspect_evm(input),
        StaticFormatOperation::BinaryLayout => inspect_binary_layout(input),
        StaticFormatOperation::Plist => inspect_plist(input),
        StaticFormatOperation::WasmArtifact => inspect_wasm(input),
        StaticFormatOperation::SqliteDatabase => Err(unsupported(operation)),
    }
}

/// Dispatch the WASM operation through its own input boundary.  The producer
/// accepts only caller-supplied bytes or authenticated Evidence; it never
/// acquires a path, launches a decoder, or executes the module.
fn inspect_wasm(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, StaticFormatOperation::WasmArtifact)?;
    let allowed = ["path", "bytes_base64", "sha256", "evidence"];
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(input_failure(
            StaticFormatOperation::WasmArtifact,
            format!("unexpected WASM inspection field: {field}"),
        ));
    }

    if object.contains_key("evidence") {
        if object.len() != 1 || !object["evidence"].is_object() {
            return Err(input_failure(
                StaticFormatOperation::WasmArtifact,
                "Evidence input must contain only a non-empty evidence object".into(),
            ));
        }
    } else if !(object.contains_key("path") && object.contains_key("bytes_base64")) {
        return Err(input_failure(
            StaticFormatOperation::WasmArtifact,
            "Byte input requires path and bytes_base64".into(),
        ));
    }

    wasm::offline::dispatch(input.clone())
}

fn inspect_go(input: &Value) -> Result<Value, Failure> {
    let path = inspection_path(input, StaticFormatOperation::GoBinary)?;
    let cancellation = Cancellation::default();
    let mut inspection = GoInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::GoBinary,
        inspection.inspect(
            &path,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_rust(input: &Value) -> Result<Value, Failure> {
    let path = inspection_path(input, StaticFormatOperation::RustBinary)?;
    let cancellation = Cancellation::default();
    let mut inspection = RustInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::RustBinary,
        inspection.inspect(
            &path,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_macho(input: &Value) -> Result<Value, Failure> {
    let path = inspection_path(input, StaticFormatOperation::Macho)?;
    let cancellation = Cancellation::default();
    let mut inspection = MachoInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::Macho,
        inspection.inspect(
            &path,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_pe_target(input: &Value) -> Result<Value, Failure> {
    let path = inspection_path(input, StaticFormatOperation::PeTarget)?;
    let cancellation = Cancellation::default();
    let mut inspection = PeTargetInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::PeTarget,
        inspection.inspect(
            &path,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_binary_layout(input: &Value) -> Result<Value, Failure> {
    let path = inspection_path(input, StaticFormatOperation::BinaryLayout)?;
    let cancellation = Cancellation::default();
    let mut inspection = BinaryLayoutInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::BinaryLayout,
        inspection.inspect(
            &path,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_plist(input: &Value) -> Result<Value, Failure> {
    let path = inspection_path(input, StaticFormatOperation::Plist)?;
    let cancellation = Cancellation::default();
    let mut inspection = PlistInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::Plist,
        inspection.inspect(
            &path,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_pe_resources(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, StaticFormatOperation::PeResources)?;
    let request = inputs::pe_resources(object)
        .map_err(|error| input_failure(StaticFormatOperation::PeResources, error.to_string()))?;
    let cancellation = Cancellation::default();
    let mut inspection = PeResourcesInspection::new(Arc::new(UnixFiles));
    finish_inspection(
        StaticFormatOperation::PeResources,
        inspection.inspect(
            request,
            &cancellation,
            rea_application::artifacts::inspection::Completion::OneShot,
        ),
        inspection.close(),
    )
}

fn inspect_evm(input: &Value) -> Result<Value, Failure> {
    let object = input_object(input, StaticFormatOperation::EvmInterface)?;
    let path = required_path(object, StaticFormatOperation::EvmInterface)?;
    let encoding = match object
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("raw")
    {
        "raw" => EvmEncoding::Raw,
        "hex" => EvmEncoding::Hex,
        value => {
            return Err(input_failure(
                StaticFormatOperation::EvmInterface,
                format!("encoding must be raw or hex, got {value}"),
            ));
        }
    };
    let evidence = evm_interface::inspect_evidence(
        Arc::new(UnixFiles),
        &path,
        encoding,
        &Cancellation::default(),
    )?;
    serialize(StaticFormatOperation::EvmInterface, &evidence)
}

fn inspection_path(input: &Value, operation: StaticFormatOperation) -> Result<String, Failure> {
    let object = input_object(input, operation)?;
    required_path(object, operation)
}

fn input_object<'a>(
    input: &'a Value,
    operation: StaticFormatOperation,
) -> Result<&'a Map<String, Value>, Failure> {
    input
        .as_object()
        .ok_or_else(|| input_failure(operation, "input must be an object".into()))
}

fn required_path(
    object: &Map<String, Value>,
    operation: StaticFormatOperation,
) -> Result<String, Failure> {
    object
        .get("path")
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| input_failure(operation, "path must be a non-empty string".into()))
}

fn finish_inspection<T: serde::Serialize>(
    operation: StaticFormatOperation,
    result: Result<T, Failure>,
    close: Result<(), Failure>,
) -> Result<Value, Failure> {
    let value = result?;
    close?;
    serialize(operation, &value)
}

fn serialize<T: serde::Serialize>(
    operation: StaticFormatOperation,
    value: &T,
) -> Result<Value, Failure> {
    serde_json::to_value(value).map_err(|error| {
        Failure::new(
            "execution_failure",
            "analysis_output",
            error.to_string(),
            false,
            "Review the serialized application Evidence.".into(),
            BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
        )
    })
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Static format operation is unknown: {name}"),
        false,
        "Select a supported static format operation.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn input_failure(operation: StaticFormatOperation, reason: String) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason,
        false,
        "Provide one explicit local artifact path and retry.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.name().into()))]),
    )
}

fn unsupported(operation: StaticFormatOperation) -> Failure {
    Failure::new(
        "unsupported_request",
        "unsupported_request",
        format!(
            "{} is not available in the no-side-effect offline adapter",
            operation.name()
        ),
        false,
        "Use the owning artifact workflow when its external tool or snapshot lifecycle is authorized.".into(),
        BTreeMap::from([
            (
                "operation",
                Detail::Text(operation.name().into()),
            ),
            (
                "authority",
                Detail::Text("offline_static_only".into()),
            ),
        ]),
    )
}
