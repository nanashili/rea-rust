//! Public read-only adapters for the four native analysis operations whose
//! stable results are shared with the TypeScript contracts.
//!
//! Provider access and Evidence retention remain outside this adapter.  Each
//! branch delegates parsing to the application owner, then selects only the
//! public result fields required by its contract.

use rea_application::{
    native, native::bookmark_inventory, native::document_inventory, native::navigation_context,
};
use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    ListBookmarks,
    ListDocuments,
    GetNavigationContext,
    AddressName,
}

impl Operation {
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            "list_bookmarks" => Ok(Self::ListBookmarks),
            "list_documents" => Ok(Self::ListDocuments),
            "get_navigation_context" => Ok(Self::GetNavigationContext),
            "address_name" => Ok(Self::AddressName),
            _ => Err(unknown_operation(name)),
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::ListBookmarks => "list_bookmarks",
            Self::ListDocuments => "list_documents",
            Self::GetNavigationContext => "get_navigation_context",
            Self::AddressName => "address_name",
        }
    }
}

pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    dispatch_typed(Operation::parse(operation)?, &input)
}

pub fn dispatch_typed(operation: Operation, input: &Value) -> Result<Value, Failure> {
    match operation {
        Operation::ListBookmarks => bookmark_inventory::project(input),
        Operation::ListDocuments => document_inventory::list(input),
        Operation::GetNavigationContext => project_navigation_context(input),
        Operation::AddressName => native::annotation_inspection::project(input),
    }
}

fn project_navigation_context(input: &Value) -> Result<Value, Failure> {
    let projected = navigation_context::project_value(input)?;
    let object = projected
        .as_object()
        .ok_or_else(|| invalid("navigation context projection must be an object"))?;
    let document = object
        .get("document")
        .cloned()
        .ok_or_else(|| invalid("navigation context projection omitted document"))?;
    let address = object
        .get("address")
        .cloned()
        .ok_or_else(|| invalid("navigation context projection omitted address"))?;
    let procedure = object
        .get("procedure")
        .cloned()
        .ok_or_else(|| invalid("navigation context projection omitted procedure"))?;

    Ok(json!({
        "result": {
            "document": document,
            "address": address,
            "procedure": procedure,
        }
    }))
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Public native analysis operation is unknown: {name}"),
        false,
        "Select one of the four supported public native analysis operations.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.into(),
        false,
        "Provide retained native analysis observations and retry.".into(),
        BTreeMap::from([("operation", Detail::Text("get_navigation_context".into()))]),
    )
}
