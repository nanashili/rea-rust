//! macOS child-container readers for the artifact graph (read-only DMG mounts
//! and universal Mach-O slices).
//!
//! Both implement the shared `crate::artifact_reader::ArtifactReader` contract.
#[cfg(feature = "family-artifacts")]
pub(crate) mod dmg;
pub(crate) mod macho_slice;
