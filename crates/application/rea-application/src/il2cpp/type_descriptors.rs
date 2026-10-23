//! Projection of already decoded IL2CPP type-descriptor rows.
//!
//! A metadata reader owns binary layout and string decoding.  This boundary
//! only classifies explicit descriptor facts and checks references supplied by
//! that reader; absent facts remain unresolved instead of being inferred.

use rea_core::failure::{Detail, Failure};
use serde_json::{Map, Value};
use std::collections::BTreeMap;

pub const OPERATION: &str = "project_il2cpp_type_descriptors";
const MAX_ROWS: usize = 200_000;
const MAX_ARGUMENTS: usize = 200_000;

/// Project normalized descriptor rows into stable, reference-preserving facts.
pub fn project(input: &Value) -> Result<Value, Failure> {
    let root = input
        .as_object()
        .ok_or_else(|| invalid("input", "Expected an object"))?;
    let metadata = root
        .get("metadata")
        .and_then(Value::as_object)
        .unwrap_or(root);
    let rows = find_rows(metadata)?;
    let identities = DescriptorIdentities::build(rows);
    let cyclic = find_cyclic_rows(rows, &identities)?;

    let mut descriptors = Vec::with_capacity(rows.len());
    let mut diagnostics = Vec::new();
    let mut resolved = 0usize;
    let mut unresolved = 0usize;

    for (row, source) in rows.iter().enumerate() {
        let object = source
            .as_object()
            .ok_or_else(|| invalid_row(row, "Expected an object"))?;
        let kind = classify_kind(object);
        let (mut resolution, references, details) = project_kind(
            object,
            &kind,
            row,
            rows.len(),
            &identities,
            &mut diagnostics,
        )?;
        if cyclic[row] && resolution == "resolved" {
            diagnostics.push(diagnostic(
                "cyclic_type_reference",
                row,
                "Descriptor references form a cycle",
            ));
            resolution = "unresolved";
        }
        if identities.is_ambiguous(row) {
            diagnostics.push(diagnostic(
                "conflicting_descriptor_identity",
                row,
                "Descriptor identity aliases disagree",
            ));
            resolution = "unresolved";
        }
        if resolution == "resolved" {
            resolved += 1;
        } else {
            unresolved += 1;
        }

        descriptors.push(serde_json::json!({
            "source_index": row,
            "source": source,
            "source_identity": identities.source_identity(row),
            "kind": kind,
            "resolution": resolution,
            "references": references,
            "details": details,
        }));
    }

    let status = if diagnostics.is_empty() && unresolved == 0 {
        "complete"
    } else {
        "partial"
    };
    Ok(serde_json::json!({
        "status": status,
        "descriptors": descriptors,
        "diagnostics": diagnostics,
        "coverage": {
            "descriptors": rows.len(),
            "resolved": resolved,
            "unresolved": unresolved,
        }
    }))
}

fn find_rows<'a>(object: &'a Map<String, Value>) -> Result<&'a [Value], Failure> {
    let value = [
        "type_descriptors",
        "typeDescriptors",
        "typespecs",
        "type_specs",
        "descriptors",
    ]
    .iter()
    .find_map(|key| object.get(*key))
    .ok_or_else(|| invalid("type_descriptors", "Expected a descriptor array"))?;
    let rows = value
        .as_array()
        .ok_or_else(|| invalid("type_descriptors", "Expected an array"))?;
    if rows.len() > MAX_ROWS {
        return Err(invalid(
            "type_descriptors",
            "Collection exceeds the IL2CPP descriptor row limit",
        ));
    }
    Ok(rows)
}

fn classify_kind(object: &Map<String, Value>) -> String {
    let value = [
        "kind",
        "type_kind",
        "typeKind",
        "element_type",
        "elementType",
    ]
    .iter()
    .find_map(|key| object.get(*key));
    match value {
        Some(Value::String(kind)) => normalize_kind(kind),
        Some(Value::Number(number)) => normalize_element_type(number),
        Some(Value::Null) | None => "unknown".to_owned(),
        Some(_) => "unknown".to_owned(),
    }
}

/// Normalize the numeric ElementType values used by IL2CPP metadata before
/// classification. Primitive descriptors carry no metadata-row reference;
/// retaining their decoded identity lets signature consumers resolve them
/// without guessing from an absent type index. Unknown numeric values remain
/// explicit and unresolved.
fn normalize_element_type(number: &serde_json::Number) -> String {
    match number.as_u64() {
        Some(0x01) => "primitive_void".to_owned(),
        Some(0x02) => "primitive_boolean".to_owned(),
        Some(0x03) => "primitive_char".to_owned(),
        Some(0x04) => "primitive_i1".to_owned(),
        Some(0x05) => "primitive_u1".to_owned(),
        Some(0x06) => "primitive_i2".to_owned(),
        Some(0x07) => "primitive_u2".to_owned(),
        Some(0x08) => "primitive_i4".to_owned(),
        Some(0x09) => "primitive_u4".to_owned(),
        Some(0x0a) => "primitive_i8".to_owned(),
        Some(0x0b) => "primitive_u8".to_owned(),
        Some(0x0c) => "primitive_r4".to_owned(),
        Some(0x0d) => "primitive_r8".to_owned(),
        Some(0x0e) => "primitive_string".to_owned(),
        Some(0x18) => "primitive_native_int".to_owned(),
        Some(0x19) => "primitive_native_uint".to_owned(),
        Some(0x1c) => "primitive_object".to_owned(),
        Some(0x0f) => "pointer".to_owned(),
        Some(0x10) => "byref".to_owned(),
        Some(0x11) => "value".to_owned(),
        Some(0x12) => "class".to_owned(),
        Some(0x13) => "generic_parameter".to_owned(),
        Some(0x14 | 0x1d) => "array".to_owned(),
        Some(0x15) => "generic_instantiation".to_owned(),
        // VAR (0x13) addresses a declaring type parameter; MVAR (0x1e)
        // addresses a method parameter. Keep the distinction in the stable
        // kind so consumers do not have to reinterpret the original byte.
        Some(0x1e) => "method_generic_parameter".to_owned(),
        Some(value) => format!("encoded_{value}"),
        None => "unknown".to_owned(),
    }
}

fn normalize_kind(kind: &str) -> String {
    let normalized = kind.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    match normalized.as_str() {
        "class" | "class_type" | "reference" => "class".to_owned(),
        "value" | "valuetype" | "value_type" | "struct" => "value".to_owned(),
        "array" | "szarray" => "array".to_owned(),
        "byref" | "by_reference" | "ref" => "byref".to_owned(),
        "pointer" | "ptr" => "pointer".to_owned(),
        "generic_parameter" | "genericparam" | "generic_parameter_type" | "var" => {
            "generic_parameter".to_owned()
        }
        "method_generic_parameter" | "method_genericparam" | "mvar" => {
            "method_generic_parameter".to_owned()
        }
        "generic_instantiation" | "generic_instance" | "genericinst" => {
            "generic_instantiation".to_owned()
        }
        "primitive_void"
        | "primitive_boolean"
        | "primitive_char"
        | "primitive_i1"
        | "primitive_u1"
        | "primitive_i2"
        | "primitive_u2"
        | "primitive_i4"
        | "primitive_u4"
        | "primitive_i8"
        | "primitive_u8"
        | "primitive_r4"
        | "primitive_r8"
        | "primitive_string"
        | "primitive_native_int"
        | "primitive_native_uint"
        | "primitive_object" => normalized,
        "unknown" => "unknown".to_owned(),
        _ => format!("unknown:{normalized}"),
    }
}

fn project_kind(
    object: &Map<String, Value>,
    kind: &str,
    row: usize,
    row_count: usize,
    identities: &DescriptorIdentities,
    diagnostics: &mut Vec<Value>,
) -> Result<(&'static str, Value, Value), Failure> {
    match kind {
        "primitive_void"
        | "primitive_boolean"
        | "primitive_char"
        | "primitive_i1"
        | "primitive_u1"
        | "primitive_i2"
        | "primitive_u2"
        | "primitive_i4"
        | "primitive_u4"
        | "primitive_i8"
        | "primitive_u8"
        | "primitive_r4"
        | "primitive_r8"
        | "primitive_string"
        | "primitive_native_int"
        | "primitive_native_uint"
        | "primitive_object" => Ok((
            "resolved",
            Value::Null,
            serde_json::json!({"primitive": kind.strip_prefix("primitive_").unwrap_or(kind)}),
        )),
        "class" | "value" => {
            let reference = reference(
                object,
                &[
                    "type_index",
                    "typeIndex",
                    "class_index",
                    "classIndex",
                    "type_definition_index",
                ],
            );
            if !valid_reference(reference, row_count, row, identities, diagnostics) {
                diagnostics.push(diagnostic(
                    "missing_type_reference",
                    row,
                    "Class/value descriptor has no explicit type reference",
                ));
                return Ok((
                    "unresolved",
                    reference_with_evidence("type_index", reference, row_count, identities),
                    serde_json::json!({"reason": "missing_type_reference"}),
                ));
            }
            Ok((
                "resolved",
                reference_with_evidence("type_index", reference, row_count, identities),
                Value::Null,
            ))
        }
        "array" => {
            let element = reference(
                object,
                &[
                    "element_type_index",
                    "elementTypeIndex",
                    "element_index",
                    "elementIndex",
                    "type_index",
                ],
            );
            let rank = object
                .get("rank")
                .or_else(|| object.get("array_rank"))
                .and_then(Value::as_u64)
                .or_else(|| single_dimension_array_rank(object));
            let element_valid = valid_reference(element, row_count, row, identities, diagnostics);
            if !element_valid || rank.is_none() || rank == Some(0) {
                diagnostics.push(diagnostic(
                    "incomplete_array",
                    row,
                    "Array descriptor needs a positive rank and element reference",
                ));
                return Ok((
                    "unresolved",
                    reference_with_evidence("element_type_index", element, row_count, identities),
                    serde_json::json!({"rank": rank}),
                ));
            }
            Ok((
                "resolved",
                reference_with_evidence("element_type_index", element, row_count, identities),
                serde_json::json!({"rank": rank}),
            ))
        }
        "byref" | "pointer" => {
            let element = reference(
                object,
                &[
                    "element_type_index",
                    "elementTypeIndex",
                    "element_index",
                    "elementIndex",
                    "type_index",
                ],
            );
            if !valid_reference(element, row_count, row, identities, diagnostics) {
                diagnostics.push(diagnostic(
                    "missing_element_reference",
                    row,
                    "Byref/pointer descriptor has no element reference",
                ));
                return Ok((
                    "unresolved",
                    reference_with_evidence("element_type_index", element, row_count, identities),
                    Value::Null,
                ));
            }
            Ok((
                "resolved",
                reference_with_evidence("element_type_index", element, row_count, identities),
                Value::Null,
            ))
        }
        "generic_parameter" | "method_generic_parameter" => {
            let index = object
                .get("generic_parameter_index")
                .or_else(|| object.get("parameter_index"))
                .or_else(|| object.get("index"));
            if !index.is_some_and(|value| reference_from_value(value).is_some()) {
                diagnostics.push(diagnostic(
                    "missing_generic_index",
                    row,
                    "Generic parameter descriptor has no non-negative index",
                ));
                return Ok(("unresolved", Value::Null, Value::Null));
            }
            Ok((
                "resolved",
                serde_json::json!({
                    "generic_parameter_index": index,
                    "method": kind == "method_generic_parameter"
                        || object
                            .get("method")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                }),
                Value::Null,
            ))
        }
        "generic_instantiation" => {
            let arguments_value = object
                .get("arguments")
                .or_else(|| object.get("generic_arguments"))
                .or_else(|| object.get("type_arguments"));
            let Some(arguments_value) = arguments_value else {
                diagnostics.push(diagnostic(
                    "missing_generic_arguments",
                    row,
                    "Generic instantiation descriptor has no explicit arguments",
                ));
                return Ok(("unresolved", Value::Null, Value::Null));
            };
            let arguments = arguments_value.as_array().ok_or_else(|| {
                invalid_row(row, "Generic instantiation arguments must be an array")
            })?;
            if arguments.len() > MAX_ARGUMENTS {
                return Err(invalid_row(row, "Generic argument collection is too large"));
            }
            let valid = arguments
                .iter()
                .enumerate()
                .all(|(argument_index, argument)| {
                    let reference = reference_from_value(argument);
                    if reference.is_none() {
                        diagnostics.push(diagnostic(
                            "unresolved_generic_argument",
                            row,
                            &format!(
                                "Generic argument {argument_index} has no explicit type reference"
                            ),
                        ));
                        return false;
                    }
                    valid_reference(reference, row_count, row, identities, diagnostics)
                });
            if !valid {
                diagnostics.push(diagnostic(
                    "unresolved_generic_argument",
                    row,
                    "One or more generic arguments lacks an explicit reference",
                ));
            }
            Ok((
                if valid { "resolved" } else { "unresolved" },
                generic_arguments_with_evidence(arguments, row_count, identities),
                Value::Null,
            ))
        }
        _ => {
            diagnostics.push(diagnostic(
                "unknown_descriptor_kind",
                row,
                "Descriptor kind is unknown or encoded without a decoder",
            ));
            Ok(("unresolved", Value::Null, Value::Null))
        }
    }
}

fn reference(object: &Map<String, Value>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| object.get(*key).and_then(reference_from_value))
}

/// `SZARRAY` carries its one-dimensional rank in the element-type tag, so a
/// decoder is not required to repeat it in a separate `rank` field.  Keep the
/// source tag as provenance while supplying the fact needed by the stable
/// array projection.
fn single_dimension_array_rank(object: &Map<String, Value>) -> Option<u64> {
    let element_type = ["element_type", "elementType"]
        .iter()
        .find_map(|key| object.get(*key));
    let is_szarray = match element_type {
        Some(Value::Number(value)) => value.as_u64() == Some(0x1d),
        Some(Value::String(value)) => value.trim().eq_ignore_ascii_case("szarray"),
        _ => false,
    };
    is_szarray.then_some(1)
}

fn reference_with_evidence(
    field: &str,
    reference: Option<u64>,
    row_count: usize,
    identities: &DescriptorIdentities,
) -> Value {
    let mut fields = Map::new();
    fields.insert(field.to_owned(), reference.map_or(Value::Null, Value::from));
    fields.extend(identities.reference_evidence(reference, row_count));
    Value::Object(fields)
}

fn generic_arguments_with_evidence(
    arguments: &[Value],
    row_count: usize,
    identities: &DescriptorIdentities,
) -> Value {
    let argument_identities = arguments
        .iter()
        .map(|argument| identities.reference_evidence(reference_from_value(argument), row_count))
        .map(Value::Object)
        .collect::<Vec<_>>();

    serde_json::json!({
        "arguments": arguments,
        "argument_identities": argument_identities,
    })
}

/// Resolves descriptor references against explicit metadata identities when a
/// capture provides them. Positional fallback is retained only for legacy
/// rows without any identity claims; duplicate identities stay ambiguous.
struct DescriptorIdentities {
    rows_by_identity: BTreeMap<u64, Vec<usize>>,
    identities_by_row: Vec<BTreeMap<String, u64>>,
    ambiguous_rows: Vec<bool>,
    has_explicit_identity: bool,
}

impl DescriptorIdentities {
    fn build(rows: &[Value]) -> Self {
        let mut rows_by_identity = BTreeMap::new();
        let mut identities_by_row = vec![BTreeMap::new(); rows.len()];
        let mut ambiguous_rows = vec![false; rows.len()];
        let mut has_explicit_identity = false;

        for (row, value) in rows.iter().enumerate() {
            let Some(object) = value.as_object() else {
                continue;
            };
            for key in [
                "metadata_index",
                "metadataIndex",
                "descriptor_index",
                "descriptorIndex",
                "type_descriptor_index",
                "typeDescriptorIndex",
                "index",
            ] {
                let Some(identity) = object.get(key).and_then(reference_from_value) else {
                    continue;
                };
                has_explicit_identity = true;
                if identities_by_row[row]
                    .values()
                    .any(|selected| *selected != identity)
                {
                    ambiguous_rows[row] = true;
                }
                identities_by_row[row].insert(key.to_owned(), identity);
                rows_by_identity
                    .entry(identity)
                    .or_insert_with(Vec::new)
                    .push(row);
            }
        }

        for rows in rows_by_identity.values_mut() {
            rows.sort_unstable();
            rows.dedup();
        }

        Self {
            rows_by_identity,
            identities_by_row,
            ambiguous_rows,
            has_explicit_identity,
        }
    }

    fn is_ambiguous(&self, row: usize) -> bool {
        self.ambiguous_rows.get(row).copied().unwrap_or(false)
    }

    fn source_identity(&self, row: usize) -> Value {
        self.identities_by_row
            .get(row)
            .filter(|identities| !identities.is_empty())
            .map_or(Value::Null, |identities| {
                Value::Object(
                    identities
                        .iter()
                        .map(|(key, value)| (key.clone(), Value::from(*value)))
                        .collect(),
                )
            })
    }

    fn resolve(&self, reference: u64, row_count: usize) -> ReferenceResolution {
        if self.has_explicit_identity {
            return match self.rows_by_identity.get(&reference) {
                Some(rows) => match rows.as_slice() {
                    [row] if !self.is_ambiguous(*row) => ReferenceResolution::Resolved(*row),
                    [_] => ReferenceResolution::Ambiguous,
                    [] => ReferenceResolution::Missing,
                    _ => ReferenceResolution::Ambiguous,
                },
                // Once any descriptor supplies an explicit identity, an
                // unmatched reference cannot safely fall back to the row's
                // position. The TypeScript decoder treats each collection
                // index as a fact of that decoder's output; mixing that
                // positional convention with caller-supplied identities
                // would select a definition by incidental array order.
                None => ReferenceResolution::Missing,
            };
        }

        usize::try_from(reference)
            .ok()
            .filter(|row| *row < row_count)
            .map_or(ReferenceResolution::Missing, ReferenceResolution::Resolved)
    }

    fn reference_evidence(&self, reference: Option<u64>, row_count: usize) -> Map<String, Value> {
        let mut evidence = Map::new();
        let Some(reference) = reference else {
            evidence.insert("identity_status".into(), Value::String("absent".into()));
            evidence.insert("resolved_source_index".into(), Value::Null);
            return evidence;
        };

        match self.resolve(reference, row_count) {
            ReferenceResolution::Resolved(row) => {
                evidence.insert("identity_status".into(), Value::String("resolved".into()));
                evidence.insert("resolved_source_index".into(), Value::from(row));
                evidence.insert("source_identity".into(), self.source_identity(row));
                evidence.insert(
                    "resolution_basis".into(),
                    Value::String(
                        if self.has_explicit_identity {
                            "explicit_identity"
                        } else {
                            "positional_index"
                        }
                        .into(),
                    ),
                );
            }
            ReferenceResolution::Ambiguous => {
                evidence.insert("identity_status".into(), Value::String("ambiguous".into()));
                evidence.insert("resolved_source_index".into(), Value::Null);
            }
            ReferenceResolution::Missing => {
                evidence.insert("identity_status".into(), Value::String("missing".into()));
                evidence.insert("resolved_source_index".into(), Value::Null);
            }
        }
        evidence
    }
}

enum ReferenceResolution {
    Resolved(usize),
    Ambiguous,
    Missing,
}

fn valid_reference(
    reference: Option<u64>,
    row_count: usize,
    row: usize,
    identities: &DescriptorIdentities,
    diagnostics: &mut Vec<Value>,
) -> bool {
    let Some(reference) = reference else {
        return false;
    };

    match identities.resolve(reference, row_count) {
        ReferenceResolution::Resolved(_) => true,
        ReferenceResolution::Ambiguous => {
            diagnostics.push(diagnostic(
                "ambiguous_type_reference",
                row,
                &format!("Type descriptor reference {reference} matches multiple rows"),
            ));
            false
        }
        ReferenceResolution::Missing => {
            diagnostics.push(diagnostic(
                "invalid_type_reference",
                row,
                &format!("Type descriptor reference {reference} is outside the descriptor table"),
            ));
            false
        }
    }
}

fn reference_from_value(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(parse_index))
        .or_else(|| {
            value.as_object().and_then(|object| {
                ["type_index", "typeIndex", "index", "metadata_index"]
                    .iter()
                    .find_map(|key| object.get(*key).and_then(reference_from_value))
            })
        })
}

fn parse_index(value: &str) -> Option<u64> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    let (digits, radix) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or((value, 10), |digits| (digits, 16));
    u64::from_str_radix(digits, radix).ok()
}

fn find_cyclic_rows(
    rows: &[Value],
    identities: &DescriptorIdentities,
) -> Result<Vec<bool>, Failure> {
    let mut graph = Vec::with_capacity(rows.len());
    for (row, source) in rows.iter().enumerate() {
        let object = source
            .as_object()
            .ok_or_else(|| invalid_row(row, "Expected an object"))?;
        let kind = classify_kind(object);
        graph.push(dependencies(object, &kind, rows.len(), identities));
    }

    let mut cyclic = vec![false; rows.len()];
    let mut state = vec![VisitState::Unvisited; rows.len()];
    let mut stack = Vec::new();
    let mut positions = vec![None; rows.len()];

    for start in 0..rows.len() {
        if state[start] != VisitState::Unvisited {
            continue;
        }

        state[start] = VisitState::Visiting;
        positions[start] = Some(stack.len());
        stack.push((start, 0));

        while !stack.is_empty() {
            let frame = stack.len() - 1;
            let node = stack[frame].0;
            if stack[frame].1 == graph[node].len() {
                let finished = node;
                stack.pop();
                positions[finished] = None;
                state[finished] = VisitState::Visited;
                continue;
            }

            let dependency = graph[node][stack[frame].1];
            stack[frame].1 += 1;
            match state[dependency] {
                VisitState::Unvisited => {
                    state[dependency] = VisitState::Visiting;
                    positions[dependency] = Some(stack.len());
                    stack.push((dependency, 0));
                }
                VisitState::Visiting => {
                    if let Some(position) = positions[dependency] {
                        for (cycle_node, _) in stack.iter().skip(position) {
                            cyclic[*cycle_node] = true;
                        }
                    }
                }
                VisitState::Visited => {}
            }
        }
    }

    Ok(cyclic)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Unvisited,
    Visiting,
    Visited,
}

fn dependencies(
    object: &Map<String, Value>,
    kind: &str,
    row_count: usize,
    identities: &DescriptorIdentities,
) -> Vec<usize> {
    let mut references = Vec::new();
    match kind {
        "class" | "value" => {
            if let Some(reference) = reference(
                object,
                &[
                    "type_index",
                    "typeIndex",
                    "class_index",
                    "classIndex",
                    "type_definition_index",
                ],
            ) {
                references.push(reference);
            }
        }
        "array" | "byref" | "pointer" => {
            if let Some(reference) = reference(
                object,
                &[
                    "element_type_index",
                    "elementTypeIndex",
                    "element_index",
                    "elementIndex",
                    "type_index",
                ],
            ) {
                references.push(reference);
            }
        }
        "generic_instantiation" => {
            let arguments = object
                .get("arguments")
                .or_else(|| object.get("generic_arguments"))
                .or_else(|| object.get("type_arguments"));
            if let Some(arguments) = arguments.and_then(Value::as_array) {
                references.extend(arguments.iter().filter_map(reference_from_value));
            }
        }
        _ => {}
    }

    references
        .into_iter()
        .filter_map(|reference| match identities.resolve(reference, row_count) {
            ReferenceResolution::Resolved(row) => Some(row),
            ReferenceResolution::Ambiguous | ReferenceResolution::Missing => None,
        })
        .collect()
}

fn diagnostic(kind: &str, row: usize, message: &str) -> Value {
    serde_json::json!({"kind": kind, "row": row, "message": message})
}

fn invalid_row(row: usize, reason: &str) -> Failure {
    invalid(&format!("type_descriptors[{row}]"), reason)
}

fn invalid(field: &str, reason: &str) -> Failure {
    Failure::new(
        "invalid_request",
        "invalid_input",
        "IL2CPP type descriptor input is invalid.".into(),
        false,
        "Supply normalized IL2CPP type descriptor rows and retry.".into(),
        BTreeMap::from([
            ("operation".into(), Detail::Text(OPERATION.into())),
            ("field".into(), Detail::Text(field.into())),
            ("reason".into(), Detail::Text(reason.into())),
        ]),
    )
}
