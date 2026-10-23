//! Capability facts for the opt-in Rust Ghidra worker.
//!
//! Capability claims are derived from the commands attested by the worker's
//! `info` response.  This keeps the host from advertising document or UI
//! operations that the JSON-lines worker does not implement.

use std::collections::BTreeSet;

use crate::ghidra_rust::protocol::WorkerInfo;

pub const PROVIDER_ID: &str = "ghidra-rust";
pub const PROVIDER_NAME: &str = "Ghidra Rust";
pub const PROVIDER_VERSION: &str = "worker-protocol-2";

const LIMITATIONS: &[&str] = &[
    "Functions come from the saved inventory or initial loader symbols and entry/function-start metadata; no function discovery is performed.",
    "This provider has no Java analyzers, Objective-C or Swift analysis, or type editor.",
    "Procedure search matches literal saved-inventory names only.",
    "Segment entries describe object-file sections; memory permissions are unavailable.",
    "Worker commands are attested by info: open, segments, functions, resolve_functions, batch_decompile, batch_decompile_inventory, checkpoint and close. REA resolves selectors against the frozen inventory and routes pseudocode through batch_decompile.",
    "Experimental local adapter; provider registration and distribution require a maintainer scope decision.",
    "The worker has an operation deadline and bounded output. Optional REA_GHIDRA_RUST_MEMORY_MIB supervision samples the exact worker process RSS on macOS/Linux and stops the owned process group when its threshold is reached or monitoring fails. This is not a kernel memory ceiling or a process-family memory limit; memory may overshoot between samples or during termination, and shared pages may be counted in RSS.",
    "RSS supervision samples at one-second intervals after each completed observation, with a one-second observation deadline. Scheduling and cleanup can delay termination. Termination preserves completed durable checkpoints; the current native call cannot safely checkpoint before it is stopped.",
    "The local prototype requires REA_GHIDRA_RUST_ENABLED=true. Public batches use sequential 64-procedure native chunks, a 16 MiB selector/inventory budget and a 32 MiB normalized output budget.",
    "Progress delivery is best-effort and coalesced. Worker replies and shutdown never wait for a stalled callback. A callback already in flight cannot be cancelled by the reporter interface.",
];

/// Operations that can be projected from the worker's currently attested
/// command set.  Document operations are local session projections, so they
/// remain available without a worker command.
pub const OPERATIONS: &[&str] = &[
    "list_segments",
    "list_procedures",
    "search_procedures",
    "batch_decompile",
    "procedure_pseudo_code",
    "procedure_address",
    "address_name",
    "list_documents",
    "current_document",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Capability {
    pub operation: String,
    pub available: bool,
    pub reason: Option<String>,
    pub cache_policy: &'static str,
    pub mutates_artifact: bool,
    pub launches_process: bool,
    pub may_show_ui: bool,
    pub may_access_network: bool,
    pub may_write_filesystem: bool,
    pub changes_permissions: bool,
    pub requires_root: bool,
    pub limitations: &'static [&'static str],
}

/// Build capability records from the worker's attested command names.
pub fn capabilities_for_worker(info: &WorkerInfo) -> Vec<Capability> {
    let commands = info.capabilities.iter().map(String::as_str).collect();
    OPERATIONS
        .iter()
        .map(|operation| capability_for_operation(operation, &commands))
        .collect()
}

fn capability_for_operation(operation: &str, commands: &BTreeSet<&str>) -> Capability {
    let required = required_commands(operation);
    let available = required.iter().all(|command| commands.contains(command));
    let reason = (!available).then(|| {
        format!(
            "The worker did not attest the command set required for {operation}."
        )
    });

    Capability {
        operation: operation.to_owned(),
        available,
        reason,
        cache_policy: "live",
        mutates_artifact: false,
        launches_process: true,
        may_show_ui: false,
        may_access_network: false,
        may_write_filesystem: true,
        changes_permissions: false,
        requires_root: false,
        limitations: LIMITATIONS,
    }
}

fn required_commands(operation: &str) -> &'static [&'static str] {
    match operation {
        "list_segments" => &["segments"],
        "list_procedures" => &["functions"],
        "search_procedures" => &["resolve_functions"],
        "batch_decompile" | "procedure_pseudo_code" => &["batch_decompile"],
        "procedure_address" | "address_name" => &["resolve_functions"],
        _ => &[],
    }
}

