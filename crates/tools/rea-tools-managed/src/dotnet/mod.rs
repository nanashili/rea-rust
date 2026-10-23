//! Managed PE/CLI metadata and CIL parsing from local bytes.
//!
//! Pure byte-parsing port of `src/dotnet/**` (every non-test module except
//! `ManagedSnapshot` and `ManagedStaticProvider*`, which `managed_tools`
//! owns). The three public functions mirror `inspectManagedArtifactBytes`,
//! `inspectManagedMembersBytes` and `inspectManagedNativeBoundariesBytes`:
//! each returns exactly the JSON object the TypeScript returns, with the same
//! keys, key order, values and limitations.
//!
//! This module reads no files and touches no session; `bytes` is the complete
//! artifact and `target` supplies only `path` and `sha256` (all the TS uses).
//! A failure that escapes an inspector is a [`ReadError`]: a bounded
//! `ManagedReaderFailure` issue, or any other thrown failure.

mod artifact_inspector;
mod boundary_helpers;
mod boundary_inspector;
mod budget;
mod bytes;
mod exception_validation;
mod failure;
mod heaps;
mod instruction_decoder;
mod inventory;
mod inventory_rows;
mod layout;
mod member_core;
mod member_inspector;
mod member_ownership;
mod member_pointers;
mod member_rows;
mod method_body;
mod method_specs;
mod pe_machine;
mod pe_reader;
mod row_sizes;
mod type_member_lists;
mod type_name_digests;
mod type_names;
mod type_nesting;
mod type_references;
mod user_strings;

pub use failure::{ReadError, ReadResult};
use serde_json::Value;

/// The artifact identity the inspectors project. Only `path` and `sha256` are
/// used, matching the TS `BinaryTarget` fields the parser reads.
pub struct Target<'a> {
    pub path: &'a str,
    pub sha256: &'a str,
}

/// Inspect PE/CLI identity directly from local bytes without CLR loading.
///
/// Port of `inspectManagedArtifactBytes(bytes, target)`.
pub fn inspect_managed_artifact_bytes(bytes: &[u8], target: &Target<'_>) -> ReadResult<Value> {
    artifact_inspector::inspect_managed_artifact_bytes(bytes, target)
}

/// Inspect metadata members and method bodies without loading target code.
///
/// Port of `inspectManagedMembersBytes(bytes, target, { typeNames })`. The TS
/// also accepts `methodOffset`, `methodLimit` and `userStrings`; the public
/// surface fixes them to their defaults (`0`, `MAX_SAFE_INTEGER`, `true`), the
/// values the provider glue passes for this entry point.
pub fn inspect_managed_members_bytes(
    bytes: &[u8],
    target: &Target<'_>,
    type_names: Option<&[String]>,
) -> ReadResult<Value> {
    member_inspector::inspect_managed_members_bytes(bytes, target, type_names)
}

/// Inspect managed/native boundary declarations from PE metadata.
///
/// Port of `inspectManagedNativeBoundariesBytes(bytes, target)`.
pub fn inspect_managed_native_boundaries_bytes(
    bytes: &[u8],
    target: &Target<'_>,
) -> ReadResult<Value> {
    boundary_inspector::inspect_managed_native_boundaries_bytes(bytes, target)
}
