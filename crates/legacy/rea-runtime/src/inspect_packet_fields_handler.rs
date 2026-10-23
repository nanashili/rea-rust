//! Public runtime handler for `inspect_packet_fields`.
//!
//! The application producer owns TShark supervision, glossary parsing, field
//! selection, coverage accounting, and Evidence construction.  This adapter
//! only supplies the runtime cancellation boundary and converts the producer's
//! retained Evidence value to the JSON value expected by the MCP transport.

use rea_application::pcap::packet_fields;
use rea_core::cancellation::Cancellation;
use rea_core::failure::Failure;
use serde_json::Value;

/// Execute packet-field discovery with the caller's exact selection object.
///
/// The input is passed through unchanged so defaults, protocol filters,
/// literal queries, and paging remain owned by `packet_fields`.  The returned
/// value is the complete Evidence envelope produced by that application
/// boundary, including the normalized catalog, source/tool identity,
/// diagnostics, and coverage window.
pub fn inspect_packet_fields(input: &Value) -> Result<Value, Failure> {
    let cancellation = Cancellation::default();
    let evidence = packet_fields::inspect(input, &cancellation)?;

    serde_json::from_str(evidence.get()).map_err(|error| {
        Failure::new(
            "integrity_failure",
            "integrity_failure",
            format!("Packet-field Evidence was not valid JSON: {error}"),
            false,
            "Retry packet-field discovery with a valid producer result.".into(),
            Default::default(),
        )
    })
}
