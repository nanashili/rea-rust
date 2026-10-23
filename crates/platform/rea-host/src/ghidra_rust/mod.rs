//! Ghidra Rust worker client: protocol frames, batch planning and the owned worker process.
//!
//! Used by the legacy `rea-runtime`; the workspace provider is `rea-provider-ghidra`.

pub mod batch;
pub mod batch_items;
pub mod batch_plan;
pub mod batch_reply;
pub mod client;
pub mod frames;
pub mod operations;
pub mod protocol;
pub mod provider;
pub mod transport_policy;
pub mod worker_error;
