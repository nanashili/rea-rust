//! Provider-neutral function dossier contract.
//!
//! Compatibility owners: `functionDossierSchema` and its parts in
//! `domain/hopperValues.ts`, `nativeApiBoundarySchema` /
//! `nativeApiInspectionResultSchema` (`domain/native/nativeApiBoundary.ts`),
//! `nativeValueFlowSchema` (`domain/native/nativeValueFlow.ts`) and
//! `nativeCallClassificationSchema` (`domain/native/nativeCallReference.ts`).
use super::address::coordinate;
use crate::zod::{
    MAX_SAFE_INTEGER, ObjectSchema, Schema, UnknownKeys, array, array_min, array_range, boolean,
    discriminated, enumeration, field, from_shape, int, int_min, int_range, integer, literal_bool,
    literal_str, nonnegative_int, null, nullable, object, optional, refine, strict, string,
    string_matching, string_min, tuple,
};
use num_bigint::BigInt;
use serde_json::Value;
use std::sync::OnceLock;

const MAX_SAFE: i64 = MAX_SAFE_INTEGER as i64;

fn is_decimal_displacement(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_lower_hex(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// `unavailableAnalysisFactSchema`.
pub fn unavailable_fact() -> Schema {
    strict(vec![
        field("available", literal_bool(false)),
        field("reason", string()),
    ])
}

/// `analysisStringSchema` shape (strips unknown keys).
pub fn analysis_string_shape() -> ObjectSchema {
    let Schema::Object(shape) = object(vec![
        field("address", string()),
        field("value", string()),
        optional("provider_value", string()),
        optional("decoding", unavailable_fact()),
        optional(
            "string",
            object(vec![
                field("encoding", string_min(1)),
                optional("encoding_status", enumeration(&["observed", "inferred"])),
                field(
                    "termination",
                    enumeration(&["missing", "present_or_not_required"]),
                ),
                field("byte_length", int_min(0)),
            ]),
        ),
    ]) else {
        unreachable!("object schema")
    };
    (*shape).clone()
}

fn body_ranges_agree(body: &Value) -> Result<(), String> {
    let ranges = body["ranges"].as_array().cloned().unwrap_or_default();
    let mut total = BigInt::from(0);
    let mut bounds: Vec<(Option<String>, BigInt, BigInt)> = Vec::new();
    let mut closed: Vec<Option<String>> = Vec::new();
    let mut previous_space: Option<Option<String>> = None;
    for range in &ranges {
        let start = range["start"].as_str().and_then(coordinate);
        let end = range["end"].as_str().and_then(coordinate);
        let (Some(start), Some(end)) = (start, end) else {
            return Err("Function body range has invalid inclusive endpoints".into());
        };
        if start.space != end.space || end.offset < start.offset {
            return Err("Function body range has invalid inclusive endpoints".into());
        }
        if let Some(previous) = &previous_space
            && *previous != start.space
            && !closed.contains(previous)
        {
            closed.push(previous.clone());
        }
        let previous = bounds
            .iter()
            .position(|(space, _, _)| *space == start.space);
        let overlapping =
            previous.is_some_and(|index| start.offset <= &bounds[index].2 + BigInt::from(1));
        if closed.contains(&start.space) || overlapping {
            return Err(
                "Function body ranges must be ordered, disjoint and maximal within each address space".into(),
            );
        }
        total += &end.offset - &start.offset + BigInt::from(1);
        match previous {
            Some(index) => bounds[index].2 = end.offset.clone(),
            None => bounds.push((
                start.space.clone(),
                start.offset.clone(),
                end.offset.clone(),
            )),
        }
        previous_space = Some(start.space);
    }
    let span = match bounds.len() {
        0 => Some(BigInt::from(0)),
        1 => Some(&bounds[0].2 - &bounds[0].1 + BigInt::from(1)),
        _ => None,
    };
    let reported_span = integer(&body["span_bytes"]).map(BigInt::from);
    let reported_total = integer(&body["total_bytes"]).map(BigInt::from);
    if reported_total != Some(total)
        || span != reported_span
        || body["non_contiguous"].as_bool() != Some(ranges.len() > 1)
    {
        return Err(
            "Function body counts, enclosing span or contiguity disagree with inclusive ranges"
                .into(),
        );
    }
    Ok(())
}

/// `functionBodySchema`.
pub fn function_body() -> Schema {
    discriminated(
        "available",
        vec![
            unavailable_fact(),
            refine(
                strict(vec![
                    field("available", literal_bool(true)),
                    field("provenance", string_min(1)),
                    field(
                        "ranges",
                        array(strict(vec![
                            field("start", string()),
                            field("end", string()),
                        ])),
                    ),
                    field("total_bytes", int_range(0, MAX_SAFE)),
                    field("span_bytes", nullable(int_range(0, MAX_SAFE))),
                    field("non_contiguous", boolean()),
                    field("contains_entry", boolean()),
                ]),
                body_ranges_agree,
            ),
        ],
    )
}

/// `functionBodyEntryAgrees`.
pub fn function_body_entry_agrees(body: &Value, address: &str) -> bool {
    if body["available"] != Value::Bool(true) {
        return true;
    }
    let Some(entry) = coordinate(address) else {
        return false;
    };
    let contains = body["ranges"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|range| {
            let start = range["start"].as_str().and_then(coordinate);
            let end = range["end"].as_str().and_then(coordinate);
            match (start, end) {
                (Some(start), Some(end)) => {
                    start.space == entry.space
                        && entry.offset >= start.offset
                        && entry.offset <= end.offset
                }
                _ => false,
            }
        });
    body["contains_entry"].as_bool() == Some(contains)
}

/// `procedureClassificationSchema`.
pub fn procedure_classification() -> Schema {
    strict(vec![
        field("external", boolean()),
        field("thunk", boolean()),
        field("thunk_target", nullable(string())),
        field("provenance", string_min(1)),
    ])
}

fn identity_entry_agrees(identity: &Value) -> Result<(), String> {
    let address = identity["address"].as_str().unwrap_or_default();
    if function_body_entry_agrees(&identity["body"], address) {
        Ok(())
    } else {
        Err("Function body entry membership disagrees with procedure identity".into())
    }
}

/// `procedureIdentitySchema` shape (strict, without its refinement).
pub fn procedure_identity_shape() -> ObjectSchema {
    ObjectSchema {
        fields: vec![
            field("address", string()),
            field("name", string()),
            field("classification", nullable(procedure_classification())),
            field("body", function_body()),
        ],
        unknown: UnknownKeys::Strict,
    }
}

/// `procedureIdentitySchema`.
pub fn procedure_identity() -> Schema {
    refine(
        from_shape(procedure_identity_shape()),
        identity_entry_agrees,
    )
}

/// `localVariableSchema`.
pub fn local_variable() -> Schema {
    strict(vec![
        field("description", string()),
        field("provenance", string_min(1)),
        optional("name", nullable(string())),
        optional(
            "stack_displacement",
            nullable(string_matching(is_decimal_displacement)),
        ),
    ])
}

/// `referenceKindSchema`.
pub fn reference_kind() -> Schema {
    discriminated(
        "available",
        vec![
            unavailable_fact(),
            strict(vec![
                field("available", literal_bool(true)),
                field("provenance", string_min(1)),
                field("type", string()),
                field("flow", boolean()),
                field("call", boolean()),
                field("jump", boolean()),
                field("data", boolean()),
                field("read", boolean()),
                field("write", boolean()),
                field("indirect", boolean()),
                field("computed", boolean()),
                field("conditional", boolean()),
                field("terminal", boolean()),
                field("primary", boolean()),
                field("operand_index", int()),
                field("external", boolean()),
            ]),
        ],
    )
}

/// `unresolvedCallSchema`.
pub fn unresolved_call() -> Schema {
    strict(vec![field("address", string()), field("reason", string())])
}

/// `nativeCallClassificationSchema`.
pub fn native_call_classification() -> Schema {
    strict(native_call_classification_fields())
}

/// Fields of `nativeCallClassificationSchema` (for `nativeCallReferenceSchema`).
pub fn native_call_classification_fields() -> Vec<crate::zod::Field> {
    vec![
        field(
            "classification",
            enumeration(&["none", "unknown", "direct", "objective_c"]),
        ),
        field("provider_type", int()),
        field("provenance", string_min(1)),
    ]
}

/// `nativeCallReferenceSchema` (classification extended with endpoints).
pub fn native_call_reference() -> Schema {
    let mut fields = native_call_classification_fields();
    fields.push(field("source_address", string()));
    fields.push(field("target_address", string()));
    strict(fields)
}

fn word_pair() -> Schema {
    tuple(vec![string(), string()])
}

/// `swiftStringLiteralSchema`.
pub fn swift_string_literal() -> Schema {
    let variant = |representation: &'static str, address: Schema| {
        strict(vec![
            field("source_address", string()),
            field("value", string()),
            field("registers", word_pair()),
            field("words", word_pair()),
            field("representation", literal_str(representation)),
            field("address", address),
        ])
    };
    discriminated(
        "representation",
        vec![variant("small", null()), variant("large", string())],
    )
}

/// `swiftStringLiteralOmissionSchema`.
pub fn swift_string_literal_omission() -> Schema {
    let variant = |representation: &'static str, address: Schema| {
        strict(vec![
            field("source_address", string()),
            field("byte_length", int_range(0, MAX_SAFE)),
            field("reason", enumeration(&["capacity", "unresolved_jump"])),
            field("registers", word_pair()),
            field("words", word_pair()),
            field("representation", literal_str(representation)),
            field("address", address),
        ])
    };
    discriminated(
        "representation",
        vec![variant("small", null()), variant("large", string())],
    )
}

/// `referenceEdgeSchema`.
pub fn reference_edge() -> Schema {
    strict(vec![
        field("source_address", string()),
        field("target_address", string()),
        field("source_procedure", nullable(procedure_identity())),
        field("target_procedure", nullable(procedure_identity())),
        field("kind", reference_kind()),
        optional("call", native_call_classification()),
    ])
}

fn facet_availability() -> Schema {
    discriminated(
        "available",
        vec![
            strict(vec![field("available", literal_bool(true))]),
            strict(vec![
                field("available", literal_bool(false)),
                field("reason", string_min(1)),
            ]),
        ],
    )
}

fn inference_confidence() -> Schema {
    enumeration(&["low", "medium", "high"])
}

fn inference_evidence() -> Schema {
    strict(vec![
        field(
            "kind",
            enumeration(&[
                "signature-source",
                "decompiler-type",
                "type-lock",
                "calling-convention",
                "jump-table",
            ]),
        ),
        field("source", string_min(1)),
        field("detail", string_min(1)),
    ])
}

fn boundary_type(role: &'static str) -> Schema {
    let (ordinal, name) = if role == "return" {
        (null(), null())
    } else {
        (int_min(0), nullable(string_min(1)))
    };
    strict(vec![
        field("ordinal", ordinal),
        field("name", name),
        field("data_type", string_min(1)),
        field("size_bytes", nullable(int_min(0))),
        field("storage", nullable(string_min(1))),
        field("confidence", inference_confidence()),
        field("evidence", array_min(inference_evidence(), 1)),
        field(
            "decompiler_artifacts",
            array(enumeration(&[
                "recovered-signature",
                "register-or-stack-storage",
                "compiler-generated-variable",
            ])),
        ),
        field("role", literal_str(role)),
    ])
}

fn jump_table() -> Schema {
    strict(vec![
        field("dispatch_address", string_min(1)),
        field(
            "data_sources",
            array(strict(vec![
                field("address", string_min(1)),
                field(
                    "provenance",
                    enumeration(&[
                        "ghidra-decompiler-load-table",
                        "ghidra-dispatch-block-data-reference",
                        "ghidra-aarch64-byte-table",
                        "ghidra-aarch64-halfword-table",
                    ]),
                ),
                field("entry_size_bytes", nullable(int_min(1))),
                field("entry_count", nullable(int_min(0))),
                field("confidence", inference_confidence()),
                field("evidence", array_min(inference_evidence(), 1)),
            ])),
        ),
        field(
            "mappings",
            array(strict(vec![
                field("case_value", nullable(int())),
                field("target_address", string_min(1)),
                field("confidence", inference_confidence()),
                field("evidence", array_min(inference_evidence(), 1)),
            ])),
        ),
        field(
            "default_targets",
            array(strict(vec![
                field("target_address", string_min(1)),
                field("confidence", inference_confidence()),
                field("evidence", array_min(inference_evidence(), 1)),
            ])),
        ),
        field("limitations", array(string())),
    ])
}

/// `nativeApiBoundarySchema`.
pub fn native_api_boundary() -> Schema {
    discriminated(
        "available",
        vec![
            strict(vec![
                field("available", literal_bool(false)),
                field("reason", string_min(1)),
                field("residual_unknowns", array_min(string_min(1), 1)),
            ]),
            strict(vec![
                field("available", literal_bool(true)),
                field("provenance", string_min(1)),
                field("signature_source", string_min(1)),
                field("calling_convention", string_min(1)),
                field("return_type", boundary_type("return")),
                field("parameters", array(boundary_type("parameter"))),
                field("jump_tables", array(jump_table())),
                field(
                    "pseudocode",
                    strict(vec![
                        field(
                            "classification",
                            literal_str("decompiler-generated-non-source"),
                        ),
                        field("compilable", literal_bool(false)),
                    ]),
                ),
                field(
                    "decompiler_artifacts",
                    array(enumeration(&[
                        "recovered-signature",
                        "register-and-stack-variables",
                        "compiler-generated-control-flow",
                        "pointer-arithmetic",
                        "pseudocode",
                    ])),
                ),
                field("limitations", array(string())),
            ]),
        ],
    )
}

/// `nativeApiInspectionResultSchema`.
pub fn native_api_inspection_result() -> Schema {
    strict(vec![
        field(
            "procedure",
            strict(vec![
                field("address", string_min(1)),
                field("name", string_min(1)),
            ]),
        ),
        field("boundary", native_api_boundary()),
        field(
            "substeps",
            array_range(
                strict(vec![
                    field(
                        "operation",
                        enumeration(&[
                            "analyze_function",
                            "project_native_api_boundary",
                            "preserve_residual_unknowns",
                        ]),
                    ),
                    field("status", enumeration(&["completed", "unsupported"])),
                    field("observations", array(string_min(1))),
                ]),
                3,
                3,
            ),
        ),
        field("unsupported_branches", array(string_min(1))),
        field("residual_unknowns", array(string_min(1))),
    ])
}

/// `nativeVarnodeSchema`.
pub fn native_varnode() -> Schema {
    strict(vec![
        field(
            "kind",
            enumeration(&["constant", "address", "register", "unique", "other"]),
        ),
        field("size_bytes", nonnegative_int()),
        field("location", nullable(string())),
        field("constant_hex", nullable(string_matching(is_lower_hex))),
    ])
}

/// `nativePcodeOperationSchema`.
pub fn native_pcode_operation() -> Schema {
    strict(vec![
        field("id", string_min(1)),
        field("address", string_min(1)),
        field("sequence", nonnegative_int()),
        field("opcode", string_min(1)),
        field("is_dead", boolean()),
        field(
            "block_membership",
            enumeration(&["member", "detached", "unavailable"]),
        ),
        field("inputs", array(native_varnode())),
        field("output", nullable(native_varnode())),
    ])
}

/// `nativePcodeDefUseSchema`.
pub fn native_pcode_def_use() -> Schema {
    strict(vec![
        field("definition", string_min(1)),
        field("use", string_min(1)),
        field("input_index", nonnegative_int()),
    ])
}

/// `nativePcodeEffectSchema`.
pub fn native_pcode_effect() -> Schema {
    strict(vec![
        field("operation", string_min(1)),
        field(
            "kind",
            enumeration(&[
                "memory_read",
                "memory_write",
                "conditional_branch",
                "indirect_branch",
                "direct_call",
                "indirect_call",
            ]),
        ),
        field("operand_input", nullable(nonnegative_int())),
        field("value_input", nullable(nonnegative_int())),
    ])
}

/// `nativeValueFlowSchema`.
pub fn native_value_flow() -> Schema {
    discriminated(
        "available",
        vec![
            strict(vec![
                field("available", literal_bool(true)),
                field("provenance", literal_str("ghidra-high-pcode")),
                field("operations", array(native_pcode_operation())),
                field("def_use", array(native_pcode_def_use())),
                field("effects", array(native_pcode_effect())),
                field(
                    "parameters",
                    array(strict(vec![
                        field("ordinal", nonnegative_int()),
                        field("name", string()),
                        field("data_type", string()),
                    ])),
                ),
                field(
                    "parameter_uses",
                    array(strict(vec![
                        field("ordinal", nonnegative_int()),
                        field("use", string()),
                        field("input_index", nonnegative_int()),
                    ])),
                ),
                field("truncated", boolean()),
                field("omitted_operations_lower_bound", nonnegative_int()),
                field("known_omitted_inputs", nonnegative_int()),
                field("known_omitted_edges", nonnegative_int()),
                field("limitations", array(string_min(1))),
            ]),
            strict(vec![
                field("available", literal_bool(false)),
                field("reason", string_min(1)),
                field("limitations", array(string_min(1))),
            ]),
        ],
    )
}

fn build_function_dossier() -> Schema {
    let mut procedure = procedure_identity_shape().extended(vec![
        field("signature", nullable(string())),
        field("locals", array(local_variable())),
    ]);
    procedure.unknown = UnknownKeys::Strict;
    let referenced_string =
        analysis_string_shape().extended(vec![field("source_address", string())]);
    let facet = facet_availability;
    strict(vec![
        field(
            "procedure",
            refine(from_shape(procedure), identity_entry_agrees),
        ),
        field("pseudocode", string()),
        field("assembly", array(string())),
        field(
            "comments",
            array(strict(vec![
                field("address", string()),
                field("kind", enumeration(&["comment", "inline"])),
                field("text", string()),
            ])),
        ),
        field("callers", array(procedure_identity())),
        field("callees", array(procedure_identity())),
        field("incoming_references", array(reference_edge())),
        field("outgoing_references", array(reference_edge())),
        optional("unresolved_calls", array(unresolved_call())),
        field("referenced_strings", array(from_shape(referenced_string))),
        field(
            "referenced_names",
            array(strict(vec![
                field("address", string()),
                field("value", string()),
                field("source_address", string()),
            ])),
        ),
        optional("swift_string_literals", array(swift_string_literal())),
        optional(
            "swift_string_literal_omissions",
            array(swift_string_literal_omission()),
        ),
        field(
            "basic_blocks",
            array(strict(vec![
                field("start", string()),
                field("end", string()),
                field("successors", array(string())),
            ])),
        ),
        field("native_api", nullable(native_api_boundary())),
        field("native_value_flow", nullable(native_value_flow())),
        optional(
            "facet_availability",
            strict(vec![
                optional("pseudocode", facet()),
                optional("assembly", facet()),
                optional("comments", facet()),
                optional("callers", facet()),
                optional("callees", facet()),
                optional("references", facet()),
                optional("strings_names", facet()),
                optional("cfg", facet()),
            ]),
        ),
        field("limitations", array(string())),
    ])
}

/// `functionDossierSchema` (built once).
pub fn function_dossier() -> &'static Schema {
    static SCHEMA: OnceLock<Schema> = OnceLock::new();
    SCHEMA.get_or_init(build_function_dossier)
}

/// `parseFunctionDossier`: the strictly parsed dossier, or the original
/// output failure.
pub fn parse_function_dossier(
    value: &Value,
) -> Result<Value, rea_core::analysis_error::AnalysisError> {
    function_dossier().parse(value).map_err(|_| {
        rea_core::analysis_error::AnalysisError::output(
            "analyze_function",
            "provider output did not match the dossier contract",
        )
    })
}
