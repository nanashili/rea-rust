//! Typed dispatch for offline native analysis inventory projections.
//!
//! The provider owns discovery, decoding, and Evidence creation. This adapter
//! only routes already-captured JSON into the application projections. It does
//! not open a provider database, read target bytes, or reinterpret missing
//! facts as negative findings.

use rea_application::{
    native::bookmark_inventory, native::document_inventory, native::name_inventory,
    native::search_strings, native::segment_inventory, native::string_inventory, procedure,
};
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Inventory operations that can be projected from captured observations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnalysisInventoryOperation {
    ListBookmarks,
    ListDocuments,
    ListNames,
    ListProcedures,
    ListSegments,
    ListStrings,
    SearchProcedures,
    SearchStrings,
}

impl AnalysisInventoryOperation {
    /// Parse the public operation name used by CLI and MCP callers.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            bookmark_inventory::OPERATION => Ok(Self::ListBookmarks),
            document_inventory::OPERATION => Ok(Self::ListDocuments),
            name_inventory::OPERATION => Ok(Self::ListNames),
            procedure::list::OPERATION => Ok(Self::ListProcedures),
            segment_inventory::OPERATION => Ok(Self::ListSegments),
            string_inventory::OPERATION => Ok(Self::ListStrings),
            procedure::search::OPERATION => Ok(Self::SearchProcedures),
            search_strings::OPERATION => Ok(Self::SearchStrings),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ListBookmarks => bookmark_inventory::OPERATION,
            Self::ListDocuments => document_inventory::OPERATION,
            Self::ListNames => name_inventory::OPERATION,
            Self::ListProcedures => procedure::list::OPERATION,
            Self::ListSegments => segment_inventory::OPERATION,
            Self::ListStrings => string_inventory::OPERATION,
            Self::SearchProcedures => procedure::search::OPERATION,
            Self::SearchStrings => search_strings::OPERATION,
        }
    }
}

/// Dispatch one inventory operation using retained, provider-produced input.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = AnalysisInventoryOperation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch an already-parsed operation without reparsing its name.
pub fn dispatch_typed(
    operation: AnalysisInventoryOperation,
    input: &Value,
) -> Result<Value, Failure> {
    match operation {
        AnalysisInventoryOperation::ListBookmarks => bookmark_inventory::inspect(input),
        AnalysisInventoryOperation::ListDocuments => document_inventory::inspect(input),
        AnalysisInventoryOperation::ListNames => name_inventory::list_names(input),
        AnalysisInventoryOperation::ListProcedures => procedure::list::inspect(input),
        AnalysisInventoryOperation::ListSegments => segment_inventory::inspect(input),
        AnalysisInventoryOperation::ListStrings => string_inventory::inspect(input),
        AnalysisInventoryOperation::SearchProcedures => procedure::search::search(input),
        AnalysisInventoryOperation::SearchStrings => search_strings::search(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        format!("Analysis inventory operation is unknown: {name}"),
        false,
        "Select one of the supported offline inventory operations.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(name.into()))]),
    )
}
