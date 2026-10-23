//! Aggregate decompression ceiling for one archive-backed artifact operation.
//!
//! Compatibility owner: `src/domain/artifactDecompressionBudget.ts`.

/// Allow a whole archive to expand by this factor before refusal.
pub const ARTIFACT_DECOMPRESSION_RATIO: u64 = 500;
/// Smallest aggregate budget granted to any archive.
pub const MINIMUM_ARTIFACT_DECOMPRESSION_BYTES: u64 = 256 * 1024 * 1024;

/// Largest total decompressed bytes allowed for an archive of this size.
pub fn artifact_decompression_budget_bytes(compressed_bytes: u64) -> u64 {
    MINIMUM_ARTIFACT_DECOMPRESSION_BYTES
        .max(compressed_bytes.saturating_mul(ARTIFACT_DECOMPRESSION_RATIO))
}
