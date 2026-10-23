//! Typed dispatch for offline native byte observations.
//!
//! The provider adapter owns target loading and address normalization.  This
//! layer accepts only the resulting caller-supplied blocks or mappings and
//! delegates their interpretation to the shared application producers.  It
//! never opens a provider database, reads a target, or creates Evidence.

use rea_application::{native::address_file_offset, native::byte_search, native::raw_byte_read};
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Offline byte observations supported by the runtime boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BytesOperation {
    ReadBytes,
    SearchBytes,
    AddressToFileOffset,
}

impl BytesOperation {
    /// Parse a public operation name into the corresponding offline handler.
    pub fn parse(name: &str) -> Result<Self, Failure> {
        match name {
            raw_byte_read::OPERATION => Ok(Self::ReadBytes),
            byte_search::OPERATION => Ok(Self::SearchBytes),
            address_file_offset::OPERATION => Ok(Self::AddressToFileOffset),
            _ => Err(unknown_operation(name)),
        }
    }

    /// Return the stable public operation name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::ReadBytes => raw_byte_read::OPERATION,
            Self::SearchBytes => byte_search::OPERATION,
            Self::AddressToFileOffset => address_file_offset::OPERATION,
        }
    }
}

/// Dispatch one offline byte observation by its public operation name.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    let operation = BytesOperation::parse(operation)?;

    dispatch_typed(operation, &input)
}

/// Dispatch one already-parsed operation without contacting a provider.
pub fn dispatch_typed(operation: BytesOperation, input: &Value) -> Result<Value, Failure> {
    match operation {
        BytesOperation::ReadBytes => raw_byte_read::read(input),
        BytesOperation::SearchBytes => byte_search::search(input),
        BytesOperation::AddressToFileOffset => address_file_offset::project(input),
    }
}

fn unknown_operation(name: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Offline byte operation is unknown: {name}"),
        false,
        "Select one of the supported offline byte observations.".into(),
        BTreeMap::from([("operation", Detail::Text(name.into()))]),
    )
}
