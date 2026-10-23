//! Public, offline `inspect_nib_archive` application handler.
//!
//! Acquisition is deliberately outside this handler.  Callers provide
//! archive bytes, an already decoded report, or retained Evidence; the NIB
//! producer performs only serialized archive decoding and never instantiates
//! archived classes.

use crate::interface_builder::nib_archive;
use rea_core::{
    failure::{Detail, Failure},
    json_output,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = "inspect_nib_archive";
const MAX_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

/// Handle one caller-supplied NIB archive observation.
///
/// The existing NIB producer owns byte decoding and report extraction.  This
/// unique public entry point owns the application output bound and keeps the
/// accepted sources explicit: bytes, a decoded report, or retained Evidence.
pub fn inspect_nib_archive(input: &Value) -> Result<Value, Failure> {
    let result = nib_archive::inspect(input)?;
    json_output::admitted_length(&result, MAX_OUTPUT_BYTES).map_err(|error| {
        let reason = match error {
            json_output::Error::Limit { maximum } => {
                format!("serialized NIB archive result exceeds {maximum} bytes")
            }
            json_output::Error::Encoding(error) => {
                format!("serialized NIB archive result is invalid: {error}")
            }
        };
        Failure::new(
            "resource_limit",
            "resource_limit",
            "NIB archive inspection exceeded its output bound.".into(),
            false,
            "Provide a smaller archive report or request a narrower projection.".into(),
            BTreeMap::from([
                ("operation", Detail::Text(OPERATION.into())),
                ("reason", Detail::Text(reason)),
            ]),
        )
    })?;
    Ok(result)
}

/// Short adapter-friendly alias for callers that dispatch by module handler.
pub fn inspect(input: &Value) -> Result<Value, Failure> {
    inspect_nib_archive(input)
}
