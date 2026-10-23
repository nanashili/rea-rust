//! Public offline handler for `inspect_jeb_client`.
//!
//! The caller supplies the endpoint selection and a previously captured
//! `get_client_information` response.  The handler never contacts or starts
//! JEB; the existing application producer owns validation and failure
//! projection.

use crate::jeb;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_jeb_client";

/// Project caller-captured JEB client information without live I/O.
pub fn inspect_jeb_client(input: &Value) -> Result<Value, Failure> {
    let object = input
        .as_object()
        .ok_or_else(|| invalid("inspect_jeb_client input must be an object"))?;
    if object.keys().any(|key| key != "selection" && key != "client_information") {
        return Err(invalid(
            "inspect_jeb_client accepts endpoint selection and captured client information only",
        ));
    }
    jeb::client::inspect_value(input)
}

fn invalid(reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide a caller-selected endpoint and captured JEB client information.".into(),
        BTreeMap::from([("operation", Detail::Text(OPERATION.into()))]),
    )
}
