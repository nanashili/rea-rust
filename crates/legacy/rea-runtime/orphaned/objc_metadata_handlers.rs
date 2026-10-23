//! Offline adapters for Objective-C class and protocol discovery.
//!
//! The application producer owns name classification. This boundary only
//! selects the operation and admits caller-supplied static observations or
//! retained Evidence; it never opens a target, invokes a provider, or runs a
//! runtime query.

use rea_application::native::objc_metadata;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

/// Dispatch one Objective-C metadata projection.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    validate_operation(operation, &input)?;

    match operation {
        objc_metadata::CLASSES_OPERATION => objc_metadata::classes(&input),
        objc_metadata::PROTOCOLS_OPERATION => objc_metadata::protocols(&input),
        _ => Err(unknown_operation(operation)),
    }
}

/// Dispatch a previously selected operation without changing its authority.
pub fn dispatch_typed(operation: &str, input: &Value) -> Result<Value, Failure> {
    validate_operation(operation, input)?;

    match operation {
        objc_metadata::CLASSES_OPERATION => objc_metadata::classes(input),
        objc_metadata::PROTOCOLS_OPERATION => objc_metadata::protocols(input),
        _ => Err(unknown_operation(operation)),
    }
}

fn validate_operation(operation: &str, input: &Value) -> Result<(), Failure> {
    match operation {
        objc_metadata::CLASSES_OPERATION | objc_metadata::PROTOCOLS_OPERATION => {}
        _ => return Err(unknown_operation(operation)),
    }

    let object = input
        .as_object()
        .ok_or_else(|| invalid(operation, "Objective-C metadata input must be an object"))?;
    if object.contains_key("pattern")
        && operation == objc_metadata::PROTOCOLS_OPERATION
    {
        return Err(invalid(
            operation,
            "get_objc_protocols does not accept a pattern",
        ));
    }
    let has_names = object.contains_key("names");
    let has_evidence = object.contains_key("evidence");
    if has_names == has_evidence {
        return Err(invalid(
            operation,
            "provide exactly one of names or retained Evidence",
        ));
    }
    objc_metadata::validate_input(input, operation)
}

fn unknown_operation(operation: &str) -> Failure {
    invalid(operation, "unsupported Objective-C metadata operation")
}

fn invalid(operation: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        reason.to_owned(),
        false,
        "Provide retained Objective-C name Evidence or a caller-supplied static capture.".into(),
        BTreeMap::from([
            ("operation", Detail::Text(operation.into())),
            ("authority", Detail::Text("offline_capture_only".into())),
        ]),
    )
}
