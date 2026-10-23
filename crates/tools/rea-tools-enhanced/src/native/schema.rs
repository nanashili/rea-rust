//! Trace-specific output contracts shared by the native value-flow and
//! UI-action workflows.
//!
//! Compatibility owners: `nativeValueTraceSchema`
//! (`domain/native/nativeValueTrace.ts`), `nativeCallTargetsSchema` and its
//! `reference` (`domain/native/nativeInstruction.ts`),
//! `nativeInvestigationGraphSchema` / `nativeInvestigationTraceSchema`
//! (`domain/native/nativeInvestigationGraph.ts`),
//! `interfaceBuilderAnalysisSchema` (`domain/apple/interfaceBuilderGraph.ts`)
//! and the native metadata location/evidence contracts
//! (`domain/native/objcSwiftMetadata.ts`).
use crate::domain::dossier::{native_call_classification, native_pcode_operation, reference_kind};
use crate::zod::{
    Schema, array, array_min, array_range, boolean, defaulted, discriminated, enumeration, field,
    int, is_lower_sha256, literal_str, nonnegative_int, null, null_value, nullable, object,
    optional, record, strict, string, string_matching, string_min, unknown,
};
use serde_json::Value;
use std::sync::OnceLock;

fn null_default() -> Value {
    null_value()
}

/// The `reference` object from `nativeInstruction.ts`.
pub fn native_instruction_reference() -> Schema {
    strict(vec![
        field("target_address", string()),
        field("type", string()),
        field("call", boolean()),
        field("jump", boolean()),
        field("indirect", boolean()),
        field("computed", boolean()),
        field("operand_index", int()),
        optional("source_address", nullable(string_min(1))),
        optional("data", nullable(boolean())),
        optional("read", nullable(boolean())),
        optional("write", nullable(boolean())),
        optional("primary", nullable(boolean())),
        optional("provenance", nullable(string_min(1))),
        optional("source", nullable(string_min(1))),
    ])
}

/// `nativeCallTargetsSchema`.
pub fn native_call_targets() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        strict(vec![
            field("call_site", string()),
            field("procedure", nullable(string())),
            field(
                "status",
                enumeration(&[
                    "direct",
                    "resolved-indirect",
                    "ambiguous",
                    "unresolved",
                    "not-call",
                    "unavailable",
                ]),
            ),
            field(
                "mechanism",
                enumeration(&["direct", "computed", "indirect", "unavailable"]),
            ),
            field(
                "targets",
                array(strict(vec![
                    field("address", string()),
                    field("procedure", nullable(string())),
                    field(
                        "status",
                        enumeration(&["direct", "resolved-indirect", "candidate"]),
                    ),
                    field("basis", literal_str("provider-reference")),
                    field("references", array(native_instruction_reference())),
                ])),
            ),
            field("limitations", array(string())),
        ])
    })
}

/// `nativeValueTraceSchema`.
pub fn native_value_trace() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        strict(vec![
            field("seed", string()),
            field("target_sha256", string()),
            field(
                "nodes",
                array(strict(vec![
                    field("id", string()),
                    field("procedure", string()),
                    field("evidence_id", string()),
                    field("kind", enumeration(&["operation", "parameter"])),
                    field("operation", nullable(native_pcode_operation())),
                    field(
                        "parameter",
                        nullable(strict(vec![
                            field("ordinal", nonnegative_int()),
                            field("name", string()),
                            field("data_type", string()),
                        ])),
                    ),
                ])),
            ),
            field(
                "edges",
                array(strict(vec![
                    field("source", string()),
                    field("target", string()),
                    field("input_index", nullable(nonnegative_int())),
                    field(
                        "kind",
                        enumeration(&[
                            "def-use",
                            "call",
                            "parameter-use",
                            "argument-binding",
                            "return-binding",
                        ]),
                    ),
                    field(
                        "status",
                        enumeration(&["derived", "direct", "resolved-indirect", "candidate"]),
                    ),
                    field("evidence_id", string()),
                ])),
            ),
            field(
                "procedures",
                array(strict(vec![
                    field("address", string()),
                    field("depth", nonnegative_int()),
                    field("evidence_id", string()),
                    field("provider", string()),
                    field("analysis_profile_digest", nullable(string())),
                ])),
            ),
            field(
                "unknowns",
                array(strict(vec![
                    field("procedure", string()),
                    field("address", nullable(string())),
                    field("reason", string()),
                ])),
            ),
            field("total_nodes", nonnegative_int()),
            field("total_edges", nonnegative_int()),
            field("decompilations", nonnegative_int()),
            field("next_offset", nullable(nonnegative_int())),
            field("truncated", boolean()),
            field("limitations", array(string())),
        ])
    })
}

/// `nativeCallReferenceSchema` (classification extended with endpoints), used
/// by native metadata evidence.
fn native_call_reference_for_evidence() -> Schema {
    strict(vec![
        field(
            "classification",
            enumeration(&["none", "unknown", "direct", "objective_c"]),
        ),
        field("provider_type", int()),
        field("provenance", string_min(1)),
        field("source_address", string()),
        field("target_address", string()),
    ])
}

/// `providerSchema` (evidence provider identity used inside UI evidence).
fn provider_schema() -> Schema {
    strict(vec![
        field("id", string_min(1)),
        field("name", string_min(1)),
        field("version", nullable(string())),
    ])
}

/// `nativeMetadataLocationSchema`.
pub fn native_metadata_location() -> Schema {
    strict(vec![
        field("address", nullable(string())),
        field("file_offset", nullable(nonnegative_int())),
    ])
}

/// `nativeMetadataEvidenceSchema`.
pub fn native_metadata_evidence() -> Schema {
    strict(vec![
        field(
            "kind",
            enumeration(&[
                "binary_metadata",
                "interface_builder_resource",
                "symbol",
                "reference",
                "decompiler",
            ]),
        ),
        field("description", string_min(1)),
        optional("provider", provider_schema()),
        field("location", native_metadata_location()),
        optional("reported_address", string()),
        optional("call_reference", native_call_reference_for_evidence()),
        defaulted("artifact_path", nullable(string_min(1)), null_default),
        defaulted(
            "artifact_sha256",
            nullable(string_matching(is_lower_sha256)),
            null_default,
        ),
    ])
}

fn node_kind() -> Schema {
    enumeration(&[
        "storyboard",
        "scene",
        "view_controller",
        "view",
        "control",
        "constraint",
        "layout_guide",
        "resource",
        "placeholder",
        "external_object",
        "outlet",
        "action",
        "segue",
        "objc_class",
        "objc_selector",
        "swift_declaration",
        "swift_requirement",
        "dispatch_table",
        "dispatch_slot",
        "thunk",
        "function",
        "state_value",
        "global_value",
        "field",
        "branch_condition",
        "sink",
        "unknown",
    ])
}

fn relation() -> Schema {
    enumeration(&[
        "contains",
        "outlet_to",
        "target_action",
        "segue_to",
        "objc_dispatch",
        "swift_witness_dispatch",
        "swift_vtable_dispatch",
        "thunk_to",
        "direct_call",
        "indirect_call",
        "provider_call",
        "reads",
        "writes",
        "flows_to",
        "controls",
    ])
}

/// `nativeInvestigationNodeSchema`.
pub fn investigation_node() -> Schema {
    strict(vec![
        field("id", string_min(1)),
        field("kind", node_kind()),
        field("name", string_min(1)),
        field("location", nullable(native_metadata_location())),
        field("attributes", record(unknown())),
        field("evidence", array(native_metadata_evidence())),
    ])
}

/// `nativeInvestigationEdgeSchema` (discriminated by `resolution`).
pub fn investigation_edge() -> Schema {
    discriminated(
        "resolution",
        vec![
            strict(vec![
                field("id", string_min(1)),
                field("from", string_min(1)),
                field("to", string_min(1)),
                field("relation", relation()),
                field(
                    "resolution",
                    enumeration(&["observed", "inferred", "resolved", "ambiguous"]),
                ),
                field("evidence", array_min(native_metadata_evidence(), 1)),
                field("limitations", array(string())),
            ]),
            strict(vec![
                field("id", string_min(1)),
                field("from", string_min(1)),
                field("to", null()),
                field("relation", relation()),
                field("resolution", literal_str("unresolved")),
                field("reason", string_min(1)),
                field("evidence", array(native_metadata_evidence())),
                field("limitations", array(string())),
            ]),
        ],
    )
}

/// `nativeInvestigationCoverageSchema`.
pub fn investigation_coverage() -> Schema {
    strict(vec![
        field("facet", string_min(1)),
        field(
            "status",
            enumeration(&["complete", "partial", "unsupported", "not_requested"]),
        ),
        field("reason", nullable(string())),
        field("examined", nonnegative_int()),
        field("omitted", nonnegative_int()),
    ])
}

fn investigation_provider() -> Schema {
    strict(vec![
        field("id", string_min(1)),
        field("version", nullable(string())),
        field("tool_version", string_min(1)),
    ])
}

/// `nativeInvestigationGraphSchema`.
pub fn investigation_graph() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        strict(vec![
            field("target_sha256", string_matching(is_lower_sha256)),
            field("provider", investigation_provider()),
            field("nodes", array(investigation_node())),
            field("edges", array(investigation_edge())),
            field("coverage", array(investigation_coverage())),
            field("truncated", boolean()),
        ])
    })
}

/// `nativeInvestigationTraceSchema`.
pub fn investigation_trace() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        strict(vec![
            field("target_sha256", string_matching(is_lower_sha256)),
            field("provider", investigation_provider()),
            field("start", string_min(1)),
            field("direction", enumeration(&["forward", "backward"])),
            field("nodes", array(investigation_node())),
            field("edges", array(investigation_edge())),
            field("unresolved", array(investigation_edge())),
            field("reached_depth", nonnegative_int()),
            field("truncated", boolean()),
            field("reason", nullable(string())),
            field("coverage", array(investigation_coverage())),
            field("limitations", array(string_min(1))),
        ])
    })
}

/// `interfaceBuilderDocumentSchema`.
fn interface_builder_document() -> Schema {
    strict(vec![
        field("relative_path", string_min(1)),
        field("archive_sha256", string_matching(is_lower_sha256)),
        field("document_kind", enumeration(&["nib", "storyboard_scene"])),
        field("object_count", nonnegative_int()),
        field("connection_count", nonnegative_int()),
        field("hierarchy_complete", boolean()),
    ])
}

/// `interfaceBuilderAnalysisSchema`.
pub fn interface_builder_analysis() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        strict(vec![
            field("target_sha256", string_matching(is_lower_sha256)),
            field(
                "documents",
                array_range(interface_builder_document(), 0, 64),
            ),
            field("graph", investigation_graph().clone()),
            field("limitations", array(string())),
        ])
    })
}

/// `referencesSchema` from `NativeCallRoutes.ts` (`z.object`, strips unknowns).
pub fn native_call_routes_references() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        object(vec![
            field("reference_kinds_available", boolean()),
            field(
                "references",
                array(object(vec![
                    field("source_address", string()),
                    field("target_address", string()),
                    field(
                        "target_procedure",
                        nullable(object(vec![field("address", string())])),
                    ),
                    field("kind", reference_kind()),
                    optional("call", native_call_classification()),
                ])),
            ),
            field(
                "unresolved_calls",
                array(object(vec![
                    field("address", string()),
                    field("reason", string()),
                ])),
            ),
        ])
    })
}
