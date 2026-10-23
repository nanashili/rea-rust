//! Canonical caller-facing error projection contract.
//!
//! Compatibility owner: `analysisErrorProjectionSchema` (`contracts/errorSchemas.ts`).
use crate::zod::{
    Field, Schema, boolean, discriminated, enumeration, field, literal_str, nullable, optional,
    record, strict, string, string_min, unknown,
};
use std::sync::OnceLock;

const CATEGORIES: &[&str] = &[
    "invalid_input",
    "unsupported_provider",
    "unsupported_target",
    "integrity_mismatch",
    "truncated",
    "cancelled",
    "timeout",
    "resource_constraint",
    "unavailable",
    "execution_failure",
];

const GENERIC_CODES: &[&str] = &[
    "invalid_request",
    "access_denied",
    "artifact_changed",
    "unreadable_output",
    "capability_unavailable",
    "unsupported_target",
    "provider_unavailable",
    "provider_timeout",
    "resource_constraint",
    "cancelled",
];

const TRAILING_GENERIC_CODES: &[&str] = &[
    "artifact_operation_failed",
    "evidence_integrity_mismatch",
    "truncated",
    "process_capture_failed",
    "cleanup_incomplete",
    "revision_conflict",
    "configuration_invalid",
    "target_unavailable",
    "execution_failure",
];

fn common(code: &'static str) -> Vec<Field> {
    vec![
        field("code", literal_str(code)),
        field("category", enumeration(CATEGORIES)),
        field("message", string_min(1)),
        field("retryable", boolean()),
        field("remediation", strict(vec![field("action", string_min(1))])),
    ]
}

fn generic(code: &'static str) -> Schema {
    let mut fields = common(code);
    fields.push(optional("details", record(unknown())));
    strict(fields)
}

fn build() -> Schema {
    let mut options = GENERIC_CODES
        .iter()
        .map(|code| generic(code))
        .collect::<Vec<_>>();
    let mut integrity = common("artifact_integrity_mismatch");
    integrity.push(field(
        "details",
        strict(vec![
            field("logical_path", string()),
            field("declared_sha256", nullable(string())),
            field("calculated_sha256", nullable(string())),
            field("unpacked", boolean()),
        ]),
    ));
    options.push(strict(integrity));
    options.extend(TRAILING_GENERIC_CODES.iter().map(|code| generic(code)));
    discriminated("code", options)
}

/// `analysisErrorProjectionSchema` (built once).
pub fn analysis_error_projection() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(build)
}
