//! Resource-policy facts shared by the Rust Ghidra provider.
//!
//! The policy describes optional sampled RSS supervision.  It deliberately
//! does not claim a kernel allocation limit: the worker process remains the
//! owner of its resource lifecycle, while REA records the observation policy.

use serde_json::{json, Value};

pub const GHIDRA_RUST_MEMORY_SAMPLE_INTERVAL_MS: u64 = 1_000;
pub const GHIDRA_RUST_MEMORY_SAMPLE_TIMEOUT_MS: u64 = 1_000;
pub const GHIDRA_RUST_MIB: u64 = 1_024 * 1_024;

/// Maximum positive MiB value representable by the TypeScript safe integer
/// policy after conversion from bytes.
pub const GHIDRA_RUST_MAX_MEMORY_MIB: u64 = 8_589_934_591;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GhidraRustMemoryPolicy {
    pub memory_limit_mib: Option<u64>,
}

impl GhidraRustMemoryPolicy {
    pub fn new(memory_limit_mib: Option<u64>) -> Self {
        Self { memory_limit_mib }
    }

    pub fn memory_supervision(&self) -> &'static str {
        match self.memory_limit_mib {
            Some(_) => "sampled_worker_rss",
            None => "disabled",
        }
    }

    /// Render the stable field names used by the TypeScript profile and
    /// diagnostics contracts.
    pub fn as_json(&self) -> Value {
        json!({
            "memory_enforcement": "unavailable",
            "memory_supervision": self.memory_supervision(),
            "memory_limit_mib": self.memory_limit_mib,
            "memory_limit_scope": "worker_process_only",
            "memory_sample_interval_ms": GHIDRA_RUST_MEMORY_SAMPLE_INTERVAL_MS,
            "memory_sample_timeout_ms": GHIDRA_RUST_MEMORY_SAMPLE_TIMEOUT_MS,
            "memory_hard_limit": false,
        })
    }
}

/// Construct the optional sampled-memory policy without performing probing or
/// claiming that the limit is enforceable by the host kernel.
pub fn ghidra_rust_memory_policy(memory_limit_mib: Option<u64>) -> Value {
    GhidraRustMemoryPolicy::new(memory_limit_mib).as_json()
}
