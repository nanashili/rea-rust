//! Verified Wakaru release pin, resource bounds and public limitations.
//!
//! Compatibility owner: `src/javascript/recovery/WakaruRelease.ts`.

/// Unchanged upstream source pin; executed bytes are identified separately.
pub const WAKARU_RELEASE_VERSION: &str = "1.14.0";
pub const WAKARU_RELEASE_REVISION: &str = "8219bf5016a063d7fb215101a8c45d5959ec733f";

/// Releases the report parser accepts (`^1.13.0`); `1.13.0` is the first
/// release this adapter verified.
pub const WAKARU_ACCEPTED_RANGE: &str = "^1.13.0";

/// Catalog identity for the verified Wakaru release. Evidence replaces the
/// version with the observed banner.
pub const WAKARU_PROVIDER_ID: &str = "wakaru";
pub const WAKARU_PROVIDER_NAME: &str = "Wakaru";

/// Catalog identity version, used only when no banner was admitted (an
/// unreachable state on the success path, since admission always sets one).
pub const WAKARU_PROVIDER_VERSION_PLACEHOLDER: &str = WAKARU_RELEASE_VERSION;

/// Per-operation resource bounds for the verified Linux adapter.
pub struct RecoveryLimits {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub output_entries: u64,
    pub report_bytes: u64,
    pub address_space_bytes: u64,
    pub timeout_ms: u64,
}

pub const RECOVERY_LIMITS: RecoveryLimits = RecoveryLimits {
    input_bytes: 64 * 1024 * 1024,
    output_bytes: 128 * 1024 * 1024,
    output_entries: 10000,
    report_bytes: 8 * 1024 * 1024,
    address_space_bytes: 1024 * 1024 * 1024,
    timeout_ms: 120000,
};

/// Public limitations for transformations and extraction provenance.
pub const RECOVERY_LIMITATIONS: [&str; 5] = [
    "Recovered sources are derived artifacts; original variable names and runtime equivalence are not established.",
    "Extraction ranges refer to half-open UTF-8 byte offsets in the original input, not rewritten line positions or whole-bundle coverage.",
    "Emitted source maps are preserved as reported by the engine; their mapping accuracy is not independently established.",
    "Inspection mode may produce non-executable regions. No input or recovered application code is executed.",
    "Linux adapter: one worker, 1 GiB address-space ceiling, 120-second deadline, 64 MiB total input, 128 MiB output, 10000 output entries and 8 MiB per diagnostic/report stream. Resource limits are per operation, not aggregate host containment.",
];
