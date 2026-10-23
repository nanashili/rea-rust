//! Runtime boundary for direct native xref requests.
//!
//! Direct xref discovery requires a live provider session.  The retained
//! relationship projections have different contracts and must not be used as
//! an unannounced substitute, so this adapter validates the public request and
//! fails closed until a provider-backed implementation is available.

use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "xrefs";

/// Validate the official request shape, then report the missing authority.
pub fn dispatch(input: Value) -> Result<Value, Failure> {
    validate_input(&input)?;
    Err(unsupported(
        "direct xref discovery requires an analysis provider",
    ))
}

fn validate_input(input: &Value) -> Result<(), Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("xrefs input must be an object"))?;
    for key in object.keys() {
        if key != "document" && key != "address" {
            return Err(invalid(&format!("unknown xrefs input field: {key}")));
        }
    }

    if let Some(document) = object.get("document")
        && document.as_str().is_none()
        && !document.is_null()
    {
        return Err(invalid("document must be a string or null"));
    }
    if let Some(address) = object.get("address")
        && address.as_str().is_none()
        && !address.is_null()
    {
        return Err(invalid("address must be a string or null"));
    }
    Ok(())
}

fn invalid(message: &str) -> Failure {
    Failure::new_with_details(
        "invalid_request",
        "invalid_input",
        message.to_owned(),
        false,
        "Provide an optional document and address with a supported provider.".into(),
        BTreeMap::from([(String::from("operation"), Detail::Text(OPERATION.into()))]),
    )
}

fn unsupported(message: &str) -> Failure {
    Failure::new_with_details(
        "unsupported_request",
        "unsupported_request",
        message.to_owned(),
        false,
        "Select an available analysis provider for direct xref discovery.".into(),
        BTreeMap::from([
            (String::from("operation"), Detail::Text(OPERATION.into())),
            (
                String::from("authority"),
                Detail::Text(String::from("provider_required")),
            ),
        ]),
    )
}
