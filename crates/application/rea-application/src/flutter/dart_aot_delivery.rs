//! Delivery selection for Dart AOT inspection results.
//!
//! The Dart AOT reader always produces the complete observation.  This module
//! owns the caller's delivery choice and projects the complete Evidence into
//! the authenticated summary view when requested.  It does not reopen the
//! APK, rerun the ELF reader, or reinterpret the retained result.

use rea_core::failure::{Detail, Failure};
use serde_json::{Value, json};
use std::collections::BTreeMap;

use crate::{flutter::dart_aot, flutter::dart_aot_view};

pub const OPERATION: &str = dart_aot::OPERATION;

/// Select complete or summary delivery for one already-computed Dart AOT result.
///
/// Summary delivery uses the same authenticated analysis-view projection as
/// `inspect_analysis_view`, with the complete parent Evidence retained in the
/// returned view's evidence link.  Complete delivery returns the reader's
/// original Evidence without cloning or reshaping it.
pub fn select(
    complete: &serde_json::value::RawValue,
    detail: Option<&str>,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    match detail.unwrap_or("complete") {
        "complete" => {
            serde_json::value::RawValue::from_string(complete.get().to_owned()).map_err(|error| {
                delivery_failure(format!("Unable to retain complete result: {error}"))
            })
        }
        "summary" => project_summary(complete),
        _ => Err(delivery_failure(
            "Dart AOT detail must be complete or summary".to_owned(),
        )),
    }
}

fn project_summary(
    complete: &serde_json::value::RawValue,
) -> Result<Box<serde_json::value::RawValue>, Failure> {
    let parent: Value = serde_json::from_str(complete.get()).map_err(|error| {
        delivery_failure(format!("Complete Dart AOT Evidence is invalid: {error}"))
    })?;
    dart_aot_view::project(&parent, &json!({"kind": "summary"}))
}

fn delivery_failure(reason: String) -> Failure {
    Failure::new(
        "execution_failure",
        "analysis_output",
        reason.clone(),
        false,
        "Review the Dart AOT delivery selection and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("reason".into(), Detail::Text(reason)),
        ]),
    )
}
