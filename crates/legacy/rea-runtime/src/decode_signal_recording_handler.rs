//! Isolated adapter for the public `decode_signal_recording` contract.
//!
//! The application workflow owns validation, paging, Evidence construction,
//! and source identity.  This module deliberately does not open the selected
//! path or launch sigrok.  A host adapter may call [`decode_signal_recording`]
//! after it has supplied a stable private-copy [`Snapshot`] and a
//! [`DecoderRunner`] that implements the TypeScript provider's Linux
//! `sigrok-cli`/`prlimit` authority.  Until that host boundary exists, the
//! JSON dispatch entrypoint remains fail-closed.

use rea_application::signals::recording::{self as signal_recording, DecoderRunner, Selection};
use rea_core::failure::{Detail, Failure};
use rea_host::fs::stable_file::Snapshot;
use serde_json::Value;
use std::collections::BTreeMap;

/// Stable public operation name for this isolated adapter.
pub const OPERATION: &str = signal_recording::OPERATION;

/// Run the application-owned projection with an already-admitted source and
/// an already-authorized host runner.
///
/// The caller retains ownership of the runner and snapshot.  In particular,
/// this function preserves the caller-selected path and snapshot digest from
/// the application result and never substitutes a path read by the adapter.
pub fn decode_signal_recording<R: DecoderRunner>(
    selection: Selection,
    snapshot: Snapshot,
    runner: &mut R,
) -> Result<Value, Failure> {
    signal_recording::decode_signal_recording(selection, snapshot, runner).map(|evidence| {
        serde_json::to_value(evidence.as_ref())
            .expect("application Evidence projection must serialize")
    })
}

/// JSON dispatch is intentionally unavailable until the exact host execution
/// boundary is registered.  Accepting a path-shaped request here would imply
/// filesystem and process authority that this runtime module does not own.
pub fn dispatch(operation: &str, input: Value) -> Result<Value, Failure> {
    if operation != OPERATION {
        return Err(unknown_operation(operation));
    }

    signal_recording::project_captured(&input)
}

fn unknown_operation(operation: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        format!("Signal recording operation is unknown: {operation}"),
        false,
        "Select decode_signal_recording.".into(),
        BTreeMap::from([("operation", Detail::Text(operation.into()))]),
    )
}
