//! Captured-Evidence-only runtime adapter for `observe_native_ui`.
//!
//! The macOS provider owns live-window capture. This adapter accepts only a
//! retained Evidence record and delegates deterministic validation to the
//! application projection; it never opens, observes, or mutates a UI.

use rea_application::native;
use rea_core::failure::{Detail, Failure};
use serde_json::Value;
use std::collections::BTreeMap;

pub const OPERATION: &str = native::ui_observation::OPERATION;

/// Dispatch one retained native UI observation.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(Failure::new(
            "invalid_request",
            "invalid_input",
            format!("unknown native UI observation operation: {operation}"),
            false,
            "Select observe_native_ui.".into(),
            BTreeMap::from([("operation", Detail::Text(operation.into()))]),
        ));
    }

    native::ui_observation::observe(&input)
}
