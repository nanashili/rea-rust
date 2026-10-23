//! Audited firmware engine releases, catalog identities and resource policy.
//!
//! Compatibility owner: `src/firmware/FirmwareRelease.ts`.
/// One audited upstream release line.
pub struct Release {
    pub version: &'static str,
}
/// `FIRMWARE_RELEASES.binwalk`.
pub const BINWALK_RELEASE: Release = Release { version: "3.1.0" };
/// `FIRMWARE_RELEASES.unblob`.
pub const UNBLOB_RELEASE: Release = Release { version: "26.6.4" };
/// Catalog identity for the verified Binwalk release.
pub const BINWALK_PROVIDER_ID: &str = "binwalk";
pub const BINWALK_PROVIDER_NAME: &str = "Binwalk";
/// Catalog identity for explicit firmware extraction.
pub const UNBLOB_PROVIDER_ID: &str = "unblob";
pub const UNBLOB_PROVIDER_NAME: &str = "Unblob";
/// `FIRMWARE_LIMITS`. Resource policy, not a claim of aggregate containment.
pub struct FirmwareLimits {
    pub input_bytes: u64,
    pub report_bytes: u64,
    pub diagnostic_bytes: usize,
    pub address_space_bytes: u64,
    pub timeout_ms: u64,
}
/// `FIRMWARE_LIMITS`.
pub const FIRMWARE_LIMITS: FirmwareLimits = FirmwareLimits {
    input_bytes: 128 * 1024 * 1024,
    report_bytes: 8 * 1024 * 1024,
    diagnostic_bytes: 8 * 1024 * 1024,
    address_space_bytes: 1024 * 1024 * 1024,
    timeout_ms: 120_000,
};
