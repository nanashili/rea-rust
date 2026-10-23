//! Runtime dispatch for retained native procedure observations.
//!
//! This adapter is deliberately provider-free.  It accepts caller-supplied
//! Evidence, delegates shape validation and projection to the application
//! producers, and never opens a binary, provider session, or database.

use rea_application::{native::function_instruction_read, procedure};
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Read-only procedure operations supported by retained Evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProcedureOperation {
    ProcedureAddress,
    ProcedureAssembly,
    ProcedureCallees,
    ProcedureCallers,
    ProcedureInfo,
    ProcedureReferences,
    ProcedurePseudoCode,
    ReadFunctionInstructions,
    ResolveContainingProcedure,
}

impl NativeProcedureOperation {
    /// Parse the public operation name used by MCP and CLI callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "procedure_address" => Ok(Self::ProcedureAddress),
            "procedure_assembly" => Ok(Self::ProcedureAssembly),
            "procedure_callees" => Ok(Self::ProcedureCallees),
            "procedure_callers" => Ok(Self::ProcedureCallers),
            "procedure_info" => Ok(Self::ProcedureInfo),
            "procedure_references" => Ok(Self::ProcedureReferences),
            "procedure_pseudo_code" => Ok(Self::ProcedurePseudoCode),
            "read_function_instructions" => Ok(Self::ReadFunctionInstructions),
            "resolve_containing_procedure" => Ok(Self::ResolveContainingProcedure),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProcedureAddress => "procedure_address",
            Self::ProcedureAssembly => "procedure_assembly",
            Self::ProcedureCallees => "procedure_callees",
            Self::ProcedureCallers => "procedure_callers",
            Self::ProcedureInfo => "procedure_info",
            Self::ProcedureReferences => "procedure_references",
            Self::ProcedurePseudoCode => "procedure_pseudo_code",
            Self::ReadFunctionInstructions => "read_function_instructions",
            Self::ResolveContainingProcedure => "resolve_containing_procedure",
        }
    }
}

/// Dispatch one retained native procedure operation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = NativeProcedureOperation::parse(operation)?;
    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without reopening provider state.
pub fn dispatch_typed(
    operation: NativeProcedureOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        NativeProcedureOperation::ProcedureAddress => procedure::address::inspect(input),
        NativeProcedureOperation::ProcedureAssembly => procedure::assembly::inspect(input),
        NativeProcedureOperation::ProcedureCallees => procedure::callees::project(input),
        NativeProcedureOperation::ProcedureCallers => procedure::callers::project(input),
        NativeProcedureOperation::ProcedureInfo => procedure::info::inspect(input),
        NativeProcedureOperation::ProcedureReferences => procedure::references::project(input),
        NativeProcedureOperation::ProcedurePseudoCode => procedure::pseudo_code::inspect(input),
        NativeProcedureOperation::ReadFunctionInstructions => {
            function_instruction_read::read(input)
        }
        NativeProcedureOperation::ResolveContainingProcedure => resolve_containing_procedure(input),
    }
}

fn resolve_containing_procedure(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("resolve_containing_procedure input must be an object"))?;
    let evidence = object
        .get("evidence")
        .or_else(|| object.get("containing_procedure"))
        .or_else(|| object.get("native_observation"))
        .ok_or_else(|| invalid("containing-procedure Evidence is required"))?;
    let evidence_object = evidence
        .as_object()
        .ok_or_else(|| invalid("containing-procedure Evidence must be an object"))?;
    require_text(evidence_object.get("evidence_id"), "evidence_id")?;

    let result = evidence_object
        .get("normalized_result")
        .or_else(|| evidence_object.get("result"))
        .or_else(|| evidence_object.get("value"))
        .ok_or_else(|| invalid("containing-procedure Evidence is missing its result"))?;
    validate_containing_result(result)?;

    if let Some(address) = object.get("address") {
        let requested = require_text(Some(address), "address")?;
        let retained = result
            .get("query_address")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("containing-procedure result lacks query_address"))?;
        if requested != retained {
            return Err(invalid(
                "address does not match retained containment Evidence",
            ));
        }
    }

    Ok(result.clone())
}

fn validate_containing_result(result: &Value) -> Result<(), Failure> {
    let object = result
        .as_object()
        .ok_or_else(|| invalid("containing-procedure result must be an object"))?;
    require_text(object.get("query_address"), "query_address")?;
    if !object.get("found").is_some_and(Value::is_boolean) {
        return Err(invalid("containing-procedure result.found must be boolean"));
    }
    match object.get("found").and_then(Value::as_bool) {
        Some(true) if object.get("procedure").is_none_or(Value::is_null) => {
            Err(invalid("found containment result must include procedure"))
        }
        Some(false)
            if object
                .get("procedure")
                .is_some_and(|value| !value.is_null()) =>
        {
            Err(invalid(
                "unresolved containment result must have null procedure",
            ))
        }
        _ => Ok(()),
    }
}

fn require_text<'a>(value: Option<&'a Value>, field: &str) -> Result<&'a str, Failure> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or_else(|| invalid(&format!("{field} must be non-empty text")))
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("native procedure operation is unknown: {name}"),
        false,
        "Select a supported retained native procedure operation.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide caller-supplied retained native procedure Evidence and retry.".into(),
        BTreeMap::new(),
    )
}
