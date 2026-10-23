//! Ported comparison-result schema subsets consumed by the investigation
//! tools. These mirror only the parts of `functionComparisonSchemas.ts`,
//! `artifactComparison.ts`, `process/processComparison.ts` and
//! `process/processTraceEvaluation.ts` the investigation workflows parse.
//!
//! The capture/artifact families own the full producer schemas; a parallel
//! port places them elsewhere. These private copies validate supplied Evidence
//! `normalized_result` payloads with the same shapes and refinements.
#![allow(dead_code)]

use crate::zod::{
    Schema, array, array_min, boolean, defaulted, enumeration, field, int_min, nonnegative_int,
    nullable, number, object, optional, refine, strict, string, string_matching, string_min, union,
    zero,
};
use serde_json::{Value, json};

/// `prefixedDigestSchema("ev")` predicate.
fn ev_id(value: &str) -> bool {
    super::is_prefixed_digest(value, "ev")
}
/// `prefixedDigestSchema("agm")`.
fn agm_id(value: &str) -> bool {
    super::is_prefixed_digest(value, "agm")
}
/// Bare lowercase sha256.
fn sha256(value: &str) -> bool {
    crate::zod::is_lower_sha256(value)
}
/// `occ_<64 hex>`.
fn occ_id(value: &str) -> bool {
    value.strip_prefix("occ_").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}
/// `art_<64 hex>`.
fn art_id(value: &str) -> bool {
    value.strip_prefix("art_").is_some_and(|hex| {
        hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn ev_id_schema() -> Schema {
    string_matching(|value| ev_id(value))
}
fn digest_schema() -> Schema {
    string_matching(|value| sha256(value))
}

// ---------------------------------------------------------------------------
// process comparison (process/processComparison.ts)

/// Ordered dimensions contributing to the overall process status.
pub(crate) const PROCESS_COMPARISON_DIMENSIONS: [&str; 5] =
    ["terminal", "interaction", "exit", "filesystem", "process"];

/// `comparisonStatusSchema` enum.
pub(crate) const COMPARISON_STATUSES: [&str; 7] = [
    "unchanged",
    "added",
    "removed",
    "changed",
    "truncated",
    "unknown",
    "contradiction",
];

fn comparison_status() -> Schema {
    enumeration(&COMPARISON_STATUSES)
}

/// `deriveProcessComparisonStatus(dimensions)`.
pub(crate) fn derive_process_comparison_status(dimensions: &[&str]) -> &'static str {
    if dimensions.contains(&"truncated") {
        return "truncated";
    }
    if dimensions
        .iter()
        .any(|status| matches!(*status, "changed" | "added" | "removed"))
    {
        return "changed";
    }
    if dimensions.contains(&"unknown") {
        "unknown"
    } else {
        "unchanged"
    }
}

/// `processTraceComparisonResultSchema` (strict object). The side and
/// diagnostic shapes mirror `processTraceEvaluation.ts`.
fn process_trace_comparison_result() -> Schema {
    // sideResultSchema / diagnosticSchema reference matched-event records whose
    // internal shape is owned by the trace family; validate them as JSON values
    // so a present trace is accepted structurally without re-deriving it.
    let side = object(vec![
        field("status", enumeration(&["pass", "fail", "unknown"])),
        field("matched_variant", nullable(string())),
        field("satisfied_constraints", array(crate::zod::unknown())),
        field("raw_trace", array(crate::zod::unknown())),
    ]);
    let diagnostic = object(vec![
        field("kind", string()),
        field("message", string()),
        field("event_ids", array(string())),
        field("locations", array(crate::zod::unknown())),
    ]);
    strict(vec![
        field(
            "verdict",
            enumeration(&["equivalent", "different", "nonconforming", "unknown"]),
        ),
        field("left", side.clone()),
        field("right", side),
        field("diagnostic", nullable(diagnostic)),
    ])
}

/// `processCaptureComparisonSchema` with its status/dimension refinement.
pub(crate) fn process_capture_comparison() -> Schema {
    let first_divergence = crate::zod::discriminated(
        "status",
        vec![
            object(vec![field("status", crate::zod::literal_str("none"))]),
            object(vec![
                field("status", crate::zod::literal_str("unknown")),
                field("reason", string()),
            ]),
            object(vec![
                field("status", crate::zod::literal_str("found")),
                field(
                    "dimension",
                    enumeration(&["terminal", "interaction", "exit", "filesystem", "process"]),
                ),
                field("index", nonnegative_int()),
                field("left_at_ms", nullable(nonnegative_int())),
                field("right_at_ms", nullable(nonnegative_int())),
                field("left", nullable(crate::zod::unknown())),
                field("right", nullable(crate::zod::unknown())),
            ]),
        ],
    );
    let base = object(vec![
        field("status", comparison_status()),
        field("terminal", comparison_status()),
        field("interaction", comparison_status()),
        field("exit", comparison_status()),
        field("filesystem", comparison_status()),
        field("process", comparison_status()),
        field("first_divergence", first_divergence),
        optional("trace", process_trace_comparison_result()),
        field("limitations", array(string())),
    ]);
    refine(base, |value| {
        let dimensions: Vec<&str> = PROCESS_COMPARISON_DIMENSIONS
            .iter()
            .map(|dimension| {
                value
                    .get(dimension)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
            })
            .collect();
        let expected = derive_process_comparison_status(&dimensions);
        if value.get("status").and_then(Value::as_str) == Some(expected) {
            Ok(())
        } else {
            Err("Process comparison status contradicts its dimensions".to_owned())
        }
    })
}

// ---------------------------------------------------------------------------
// function comparison (functionComparisonSchemas.ts + functionComparisonResults.ts)

pub(crate) const FUNCTION_DIMENSION_NAMES: [&str; 8] = [
    "identity",
    "pseudocode",
    "assembly",
    "comments",
    "calls",
    "references",
    "strings_names",
    "cfg",
];

fn text_delta() -> Schema {
    object(vec![
        field("added_lines", nonnegative_int()),
        field("removed_lines", nonnegative_int()),
        field("hunks", nonnegative_int()),
    ])
}

fn function_dimension_context() -> Vec<crate::zod::Field> {
    vec![
        field("dimension", enumeration(&FUNCTION_DIMENSION_NAMES)),
        field("left_count", nullable(nonnegative_int())),
        field("right_count", nullable(nonnegative_int())),
        field("evidence_links", array_min(ev_id_schema(), 2)),
        field("limitations", array(string())),
    ]
}

fn function_dimension() -> Schema {
    let mut unchanged = function_dimension_context();
    unchanged.extend([
        field("status", crate::zod::literal_str("unchanged")),
        field("left_digest", digest_schema()),
        field("right_digest", digest_schema()),
        field("text_delta", nullable(text_delta())),
        field(
            "conclusion_kind",
            crate::zod::literal_str("derived_relationship"),
        ),
    ]);
    let mut changed = function_dimension_context();
    changed.extend([
        field("status", crate::zod::literal_str("changed")),
        field("left_digest", digest_schema()),
        field("right_digest", digest_schema()),
        field("text_delta", nullable(text_delta())),
        field(
            "conclusion_kind",
            enumeration(&["derived_relationship", "contradiction"]),
        ),
    ]);
    let mut unknown = function_dimension_context();
    unknown.extend([
        field("status", crate::zod::literal_str("unknown")),
        field("left_digest", crate::zod::null()),
        field("right_digest", crate::zod::null()),
        field("text_delta", crate::zod::null()),
        field(
            "conclusion_kind",
            crate::zod::literal_str("unresolved_branch"),
        ),
    ]);
    union(vec![object(unchanged), object(changed), object(unknown)])
}

fn function_match() -> Schema {
    union(vec![
        object(vec![
            field("status", crate::zod::literal_str("matched")),
            field("method", crate::zod::literal_str("symbol")),
            field("left_name", string()),
            field("right_name", string()),
        ]),
        object(vec![
            field("status", enumeration(&["mismatched", "ambiguous"])),
            field("method", crate::zod::literal_str("explicit")),
            field("left_name", string()),
            field("right_name", string()),
        ]),
    ])
}

/// `overallStatus(dimensions, match)`.
fn function_overall_status(dimensions: &[Value], match_status: &str) -> &'static str {
    if match_status == "mismatched" {
        return "changed";
    }
    if match_status == "ambiguous" {
        return "unknown";
    }
    if dimensions
        .iter()
        .any(|dimension| dimension.get("status").and_then(Value::as_str) == Some("changed"))
    {
        return "changed";
    }
    if dimensions
        .iter()
        .any(|dimension| dimension.get("status").and_then(Value::as_str) == Some("unknown"))
    {
        return "unknown";
    }
    "unchanged"
}

/// `functionComparisonResultSchema`.
pub(crate) fn function_comparison_result() -> Schema {
    let base = object(vec![
        field("status", enumeration(&["unchanged", "changed", "unknown"])),
        field("function_match", function_match()),
        field("left_subject_sha256", digest_schema()),
        field("right_subject_sha256", digest_schema()),
        field(
            "summary",
            object(vec![
                field("unchanged", nonnegative_int()),
                field("changed", nonnegative_int()),
                field("unknown", nonnegative_int()),
            ]),
        ),
        field(
            "dimensions",
            crate::zod::array_range(function_dimension(), 8, 8),
        ),
        field("changes", array(function_dimension())),
        field("limitations", array(string())),
    ]);
    refine(base, |value| {
        let dimensions = value
            .get("dimensions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let match_status = value
            .pointer("/function_match/status")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let expected = function_overall_status(&dimensions, match_status);
        if value.get("status").and_then(Value::as_str) == Some(expected) {
            Ok(())
        } else {
            Err(
                "Function comparison status contradicts its dimensions or function match."
                    .to_owned(),
            )
        }
    })
}

// ---------------------------------------------------------------------------
// artifact comparison (artifactComparison.ts)

const ARTIFACT_CHANGE_KINDS: [&str; 5] =
    ["added", "removed", "changed", "unknown", "contradiction"];
const ARTIFACT_DIMENSIONS: [&str; 9] = [
    "content",
    "kind",
    "format",
    "size",
    "executable",
    "relations",
    "metadata",
    "availability",
    "integrity",
];

fn artifact_change() -> Schema {
    object(vec![
        field("classification", enumeration(&ARTIFACT_CHANGE_KINDS)),
        field("logical_path", string_min(1)),
        field(
            "dimensions",
            array_min(enumeration(&ARTIFACT_DIMENSIONS), 1),
        ),
        field(
            "left_occurrence_id",
            nullable(string_matching(|v| occ_id(v))),
        ),
        field(
            "right_occurrence_id",
            nullable(string_matching(|v| occ_id(v))),
        ),
        field("left_artifact_id", nullable(string_matching(|v| art_id(v)))),
        field(
            "right_artifact_id",
            nullable(string_matching(|v| art_id(v))),
        ),
        field("evidence_links", array_min(ev_id_schema(), 2)),
    ])
}

/// `artifactComparisonResultSchema`.
pub(crate) fn artifact_comparison_result() -> Schema {
    object(vec![
        field("status", comparison_status()),
        field("left_manifest_id", string_matching(|v| agm_id(v))),
        field("right_manifest_id", string_matching(|v| agm_id(v))),
        field(
            "summary",
            object(vec![
                field("unchanged", nonnegative_int()),
                field("added", nonnegative_int()),
                field("removed", nonnegative_int()),
                field("changed", nonnegative_int()),
                field("unknown", nonnegative_int()),
                defaulted("contradiction", nonnegative_int(), zero),
            ]),
        ),
        field("changes", array(artifact_change())),
        field("limitations", array(string())),
    ])
}

/// Parse `schema` and format the first issue as the `describeValidationFailure`
/// text used by `AnalysisInputError` (no "(N more issues)" suffix; see report).
pub(crate) fn parse_or_describe(schema: &Schema, value: &Value) -> Result<Value, String> {
    schema.parse(value).map_err(|issue| {
        let location = if issue.path.is_empty() {
            "the document root".to_owned()
        } else {
            issue.path.join(".")
        };
        format!("at {location}: {}", issue.message)
    })
}

/// Re-export used by other submodules for unused-import hygiene.
pub(crate) fn _touch() -> Value {
    let _ = (boolean(), number(), int_min(0));
    json!(null)
}
