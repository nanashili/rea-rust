//! Analysis-snapshot domain, bounded cache, and snapshot files.
//!
//! Compatibility owners: `src/domain/analysisSnapshot.ts`,
//! `src/application/binary/AnalysisSnapshotCache.ts`,
//! `src/application/binary/AnalysisSnapshotFiles.ts` and their domain
//! dependencies. The binary session (the orchestrator) wires this module in:
//! it owns the active target/profile and the session Evidence ledger, and
//! supplies the evidence bundle filtered by [`evidence_bundle_for_target`].
#![allow(dead_code)]

mod cache;
mod canonical;
mod domain;
mod evidence;
mod files;
mod model;

use rea_analysis::CapabilityDescriptor;
use serde_json::{Map, Value};

pub(crate) use cache::SnapshotCache;
pub(crate) use domain::{analysis_profiles_equal, target_identity_matches};
pub(crate) use evidence::evidence_bundle_for_target;
pub(crate) use files::{SnapshotFiles, read_analysis_snapshot};
pub(crate) use model::{AnalysisSnapshot, snapshot_matches_binding};

/// Stateful operations depend on provider UI state and are never cached (TS
/// `STATEFUL_OPERATIONS`).
fn is_stateful_operation(operation: &str) -> bool {
    matches!(
        operation,
        "health"
            | "current_address"
            | "current_procedure"
            | "current_document"
            | "goto_address"
            | "list_documents"
    )
}

/// Operations that require a `document` parameter to be cacheable (TS
/// `DOCUMENT_SCOPED_OPERATIONS`): every catalog tool with kind `official-proxy`
/// except `current_document` and `list_documents`.
fn is_document_scoped_operation(operation: &str) -> bool {
    rea_mcp::catalog().tools.iter().any(|tool| {
        tool.kind == "official-proxy"
            && tool.name != "current_document"
            && tool.name != "list_documents"
            && tool.name == operation
    })
}

/// Operations whose cursor default requires an `address` parameter (TS
/// `CURSOR_DEFAULT_OPERATIONS`).
fn is_cursor_default_operation(operation: &str) -> bool {
    matches!(
        operation,
        "address_name" | "comment" | "inline_comment" | "next_address" | "prev_address" | "xrefs"
    )
}

/// Whether an operation is immutable and independent of provider UI state (TS
/// `isSnapshotCacheable`).
pub(crate) fn is_snapshot_cacheable(
    operation: &str,
    descriptor: Option<&CapabilityDescriptor>,
    parameters: &Map<String, Value>,
) -> bool {
    if is_stateful_operation(operation) {
        return false;
    }
    if is_document_scoped_operation(operation)
        && !parameters.get("document").is_some_and(Value::is_string)
    {
        return false;
    }
    if is_cursor_default_operation(operation)
        && !parameters.get("address").is_some_and(Value::is_string)
    {
        return false;
    }
    let Some(descriptor) = descriptor else {
        return false;
    };
    if descriptor.effects.mutates_artifact {
        return false;
    }
    let cache_policy = descriptor.cache_policy.as_deref();
    if cache_policy == Some("live") {
        return false;
    }
    if cache_policy != Some("snapshot") && descriptor.effects.may_write_filesystem {
        return false;
    }
    !descriptor.effects.changes_permissions
}
