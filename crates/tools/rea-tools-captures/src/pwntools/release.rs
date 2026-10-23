//! Verified-unchanged upstream profile, budgets and reserved exit statuses.
//!
//! Compatibility owner: `src/native/pwntools/PwntoolsRelease.ts`.
use rea_core::evidence::envelope::EvidenceProvider;

/// `PWNTOOLS_PROVIDER_IDENTITY`.
pub const PROVIDER_ID: &str = "pwntools-elf";
pub const PROVIDER_NAME: &str = "REA pwntools ELF adapter";
pub const PROVIDER_VERSION: &str = "pwntools@4.15.0;pyelftools@0.33;unicorn@2.1.2";

/// Evidence provider identity for both adapters.
pub fn provider() -> EvidenceProvider {
    EvidenceProvider::new(
        PROVIDER_ID,
        PROVIDER_NAME,
        Some(PROVIDER_VERSION.to_owned()),
    )
}

/// `PWNTOOLS_MEMORY_FAILURE_EXIT`.
pub const MEMORY_FAILURE_EXIT: i64 = 75;
/// `PWNTOOLS_FILE_SIZE_FAILURE_EXIT`.
pub const FILE_SIZE_FAILURE_EXIT: i64 = 76;

/// `PWNTOOLS_LIMITS`.
pub const INPUT_BYTES: u64 = 32 * 1024 * 1024;
pub const OUTPUT_BYTES: u64 = 64 * 1024 * 1024;
pub const DIAGNOSTIC_BYTES: usize = 1024 * 1024;
pub const TIMEOUT_MS: u64 = 30_000;
pub const ADDRESS_SPACE_BYTES: u64 = 3 * 1024 * 1024 * 1024;
pub const CPU_SECONDS: u64 = 30;

/// Maximum caller-supplied override, from `PwntoolsInputLimit.ts`.
pub const MAXIMUM_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

/// The caller-supplied host requirement text (`HOST_REQUIREMENT`).
pub const HOST_REQUIREMENT: &str =
    "The initial real-verified pwntools artifact profile supports Linux x64 only.";
